"""Bounded authenticated delegation records; observer never launches a job."""

import ast
import hashlib
import json
import os
from pathlib import Path
import stat

COMMON = {"id", "kind", "nonce", "pid", "token", "identity"}
FIELDS = {
    "argv",
    "cwd",
    "env",
    "owner_id",
    "worker_environment",
    "request",
    "request_path",
    "request_sha256",
    "source_sha256",
    "AST_sha256",
    "executor",
    "custody_root_id",
    "requesting_case",
    "requesting_class",
}


def check_snapshot(host, snapshot):
    manifest = host.manifest
    if set(snapshot) != FIELDS:
        raise RuntimeError("custody_snapshot_schema_refused")
    root = Path(snapshot["cwd"])
    if (
        not root.is_absolute()
        or root.resolve() != root
        or not root.is_relative_to(manifest["owned_root"])
    ):
        raise RuntimeError("custody_owned_root_refused")
    run = snapshot["request"]
    if (
        set(run) != {"run_id", "generation"}
        or type(run["generation"]) is not int
        or run["generation"] < 1
    ):
        raise RuntimeError("custody_request_schema_refused")
    path = root / ".unrest/runs" / run["run_id"].removeprefix("run:") / "request.json"
    if str(path) != snapshot["request_path"] or path.resolve() != path:
        raise RuntimeError("custody_request_path_refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != host.root["uid"]
            or info.st_size > 65536
        ):
            raise RuntimeError("custody_request_carrier_refused")
        data = os.read(fd, 65537)
    finally:
        os.close(fd)
    durable = json.loads(data)
    if hashlib.sha256(data).hexdigest() != snapshot["request_sha256"] or any(
        durable[k] != run[k] for k in run
    ):
        raise RuntimeError("custody_stale_request_refused")
    source = Path(manifest["checkout"]) / "src/unrest_harness/run_control.py"
    source_bytes = source.read_bytes()
    call = next(
        n for n in ast.walk(ast.parse(source_bytes)) if isinstance(n, ast.Call) and n.lineno == 1147
    )
    if (
        hashlib.sha256(source_bytes).hexdigest() != snapshot["source_sha256"]
        or snapshot["source_sha256"]
        != manifest["product_pins"]["src/unrest_harness/run_control.py"]
        or snapshot["AST_sha256"]
        != hashlib.sha256(ast.dump(call, include_attributes=False).encode()).hexdigest()
    ):
        raise RuntimeError("custody_source_pin_refused")
    argv = snapshot["argv"]
    if (
        snapshot["executor"]
        not in ("executor_fixture:execute", "unrest_harness.runtime_executor:execute")
        or argv
        != [
            argv[0],
            "-m",
            "unrest_harness.run_worker",
            "--project-root",
            str(root),
            "--run-id",
            run["run_id"],
            "--executor",
            snapshot["executor"],
            "--custody-root-id",
            snapshot["custody_root_id"],
            "--generation",
            str(run["generation"]),
        ]
        or argv[0] not in manifest["runtime"]["paths"]
    ):
        raise RuntimeError("custody_vector_refused")
    environment = {
        "LANG": "C.UTF-8",
        "PATH": os.defpath,
        "PYTHONPATH": str(source.parent.parent),
        **snapshot["worker_environment"],
    }
    if environment != snapshot["env"]:
        raise RuntimeError("custody_environment_refused")
    if snapshot["requesting_case"] != manifest["source_case"]:
        raise RuntimeError("custody_case_refused")


def role(events, request):
    ready = [
        e
        for e in events
        if e["kind"] == "ready"
        and e["token"] == request["token"]
        and e["owner_pid"] == request["pid"]
    ]
    if len(ready) != 1:
        raise RuntimeError("custody_READY_refused")
    return ready[0]["class"]


def handle(host, request, events):
    kind = request["kind"]
    schemas = {
        "custody_submit": {"snapshot", "attestation"},
        "custody_peer": {"peer", "claim"},
        "custody_owner": set(),
        "custody_poll": set(),
        "custody_spawned": {"job_id", "child"},
        "custody_close": set(),
        "custody_signal": {"child", "signal"},
        "custody_cancel": {"child"},
    }
    if kind not in schemas or set(request) != COMMON | schemas[kind]:
        raise RuntimeError("custody_frame_schema_refused")
    if not hasattr(host, "custody"):
        host.custody = {"jobs": {}, "keys": set(), "closing": False, "owner": None, "peers": {}}
    state = host.custody
    if kind == "custody_submit" and state["closing"]:
        raise RuntimeError("custody_late_or_foreign_requester")
    caller = role(events, request)
    custodians = [
        pid
        for pid, row in host.registered.items()
        if any(
            e["kind"] == "ready"
            and e["token"] == row["token"]
            and e["class"] == "restart-custodian"
            and e["owner_pid"] == pid
            for e in events
        )
    ]
    if len(custodians) != 1:
        raise RuntimeError("custody_unique_live_owner_required")
    custodian = custodians[0]
    host.authenticate(
        {
            "nonce": request["nonce"],
            "pid": custodian,
            "token": host.registered[custodian]["token"],
            "identity": host.registered[custodian]["identity"],
        },
        events,
    )
    if host.registered[custodian]["identity"]["ppid"] != host.child.pid:
        raise RuntimeError("custody_root_ancestry_refused")
    state["owner"] = custodian
    if kind == "custody_owner":
        if (
            caller not in ("composed-http-role:orchestrator", "restart-control-frontend")
            or state["closing"]
        ):
            raise RuntimeError("custody_late_or_foreign_requester")
        return {"identity": host.registered[custodian]["identity"]}
    if kind == "custody_peer":
        if request["pid"] != custodian or set(request["peer"]) != {"pid", "uid", "gid"}:
            raise RuntimeError("custody_peer_owner_refused")
        claim = request["claim"]
        if (
            set(claim) != {"challenge", "nonce", "pid", "token", "identity", "snapshot_sha256"}
            or claim["pid"] != request["peer"]["pid"]
            or request["peer"]["uid"] != host.root["uid"]
        ):
            raise RuntimeError("custody_peer_claim_refused")
        host.authenticate(claim, events)
        if (
            claim["challenge"] in state["peers"]
            or len(claim["challenge"]) != 32
            or len(state["peers"]) >= 16
        ):
            raise RuntimeError("custody_peer_replay_or_limit")
        state["peers"][claim["challenge"]] = {
            "claim": claim,
            "peer": request["peer"],
            "used": False,
        }
        return {"attestation": claim["challenge"]}
    if kind == "custody_submit":
        if (
            caller not in ("composed-http-role:orchestrator", "restart-control-frontend")
            or state["closing"]
        ):
            raise RuntimeError("custody_late_or_foreign_requester")
        snapshot = request["snapshot"]
        check_snapshot(host, snapshot)
        if snapshot["requesting_class"] != caller:
            raise RuntimeError("custody_requester_role_refused")
        jobs = state["jobs"]
        key = (snapshot["cwd"], snapshot["request"]["run_id"], snapshot["request"]["generation"])
        if request["id"] not in jobs:
            peer = state["peers"].get(request["attestation"])
            snapshot_pin = hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()
            if (
                peer is None
                or peer["used"]
                or peer["claim"]["pid"] != request["pid"]
                or peer["claim"]["snapshot_sha256"] != snapshot_pin
            ):
                raise RuntimeError("custody_missing_kernel_peer_binding")
            peer["used"] = True
            if key in state["keys"] or len(jobs) >= 16:
                raise RuntimeError("custody_replay_or_limit_refused")
            state["keys"].add(key)
            jobs[request["id"]] = {
                "id": request["id"],
                "snapshot": snapshot,
                "requester": request["pid"],
                "phase": "queued",
            }
        job = jobs[request["id"]]
        if (
            job["snapshot"] != snapshot
            or job["requester"] != request["pid"]
            or job["phase"] == "delivered"
        ):
            raise RuntimeError("custody_replayed_frame")
        if job["phase"] != "spawned":
            return {"pending": True}
        job["phase"] = "delivered"
        return {
            "custodian": custodian,
            "child": job["child"],
            "child_token": job["child_token"],
            "real_spawn_READY": True,
            "terminal_wait": False,
        }
    if kind == "custody_close":
        if request["pid"] != host.child.pid or state["closing"]:
            raise RuntimeError("custody_close_authority_refused")
        state["closing"] = True
        return {"closing": True}
    if kind == "custody_poll":
        if request["pid"] != custodian:
            raise RuntimeError("custody_poll_foreign")
        queued = [j for j in state["jobs"].values() if j["phase"] == "queued"]
        job = queued[0] if queued else None
        if job:
            check_snapshot(host, job["snapshot"])
            host.authenticate(
                {
                    "nonce": request["nonce"],
                    "pid": job["requester"],
                    "token": host.registered[job["requester"]]["token"],
                    "identity": host.registered[job["requester"]]["identity"],
                },
                events,
            )
            job["phase"] = "executing"
        return {"job": job, "closing": state["closing"]}
    if kind == "custody_spawned":
        job = state["jobs"].get(request["job_id"])
        if request["pid"] != custodian or job is None or job["phase"] != "executing":
            raise RuntimeError("custody_unbound_spawn_receipt")
        child = request["child"]
        registered = next(
            (
                e
                for e in events
                if e["kind"] == "registered"
                and e["pid"] == child
                and e["owner_pid"] == custodian
                and e["class"] == "source-run-worker"
            ),
            None,
        )
        if (
            registered is None
            or child not in host.registered
            or not any(
                e["kind"] == "ready"
                and e["owner_pid"] == child
                and e["token"] == registered["token"]
                for e in events
            )
        ):
            return {"pending": True}
        identity = host.registered[child]["identity"]
        host.authenticate(
            {
                "nonce": request["nonce"],
                "pid": child,
                "token": registered["token"],
                "identity": identity,
            },
            events,
        )
        if identity["ppid"] != custodian or identity["pgid"] != child:
            raise RuntimeError("custody_actual_parent_group_refused")
        job.update(phase="spawned", child=child, child_token=registered["token"])
        return {"recorded": True, "identity": identity}
    if kind in ("custody_signal", "custody_cancel"):
        if request["pid"] != custodian or kind != "custody_signal" or request["signal"] != 15:
            raise RuntimeError("custody_signal_authority_refused")
        child = request["child"]
        registered = host.registered.get(child)
        if registered is None or registered["identity"]["ppid"] != custodian:
            raise RuntimeError("custody_signal_foreign_child")
        host.authenticate(
            {
                "nonce": request["nonce"],
                "pid": child,
                "token": registered["token"],
                "identity": registered["identity"],
            },
            events,
        )
        return {"signal": 15, "identity": registered["identity"]}
    raise RuntimeError("custody_unknown_operation")
