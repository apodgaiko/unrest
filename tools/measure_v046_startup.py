"""Provider-free MCP startup ruler. Requires independently reviewed case oracles.

Every launch is reserved in a fsynced, flock-protected campaign ledger BEFORE
spawn. Interrupted reservations remain consumed. Never use a production home.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import ExitStack
import fcntl
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import shutil
import signal
import statistics
import subprocess
import tempfile
import time
from typing import Any, TypeVar

ROLES = ("orchestrator", "worker", "validator", "terminal-reviewer")
HOMES = ("empty", "seeded", "held-out-populated")
T = TypeVar("T")
SHUTDOWN_TIMEOUT = 5.0

BASELINE = "5a3d568aa881c746432b7034597bbb8a1ffe025f"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root: Path) -> dict[str, str]:
    if root.is_symlink() or any(p.is_symlink() for p in root.rglob("*")):
        raise ValueError("fixture/package inventory cannot follow symlinks")
    return {
        str(p.relative_to(root)): digest(p)
        for p in sorted(root.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def case_matrix() -> list[dict[str, str]]:
    return [
        dict(zip(("role", "home", "install", "load"), values, strict=True),
             id="/".join(values))
        for values in itertools.product(ROLES, HOMES, ("editable", "wheel"),
                                        ("isolated", "concurrent-4"))
    ]


def statistics_ms(values: list[float]) -> dict[str, float]:
    if not values or any(not math.isfinite(x) or x < 0 for x in values):
        raise ValueError("finite nonnegative observations required")
    ordered = sorted(values)
    median = statistics.median(values)
    return {"median": median, "p95": ordered[math.ceil(.95 * len(values)) - 1],
            "min": min(values), "max": max(values),
            "mad": statistics.median(abs(x - median) for x in values)}


def calibrate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result = {}
    expected = {c["id"] for c in case_matrix() if c["load"] == "isolated"}
    if {r["case_id"] for r in rows} != expected:
        raise ValueError("calibration requires all 24 isolated cases")
    for case_id in sorted(expected):
        samples = [r for r in rows if r["case_id"] == case_id]
        if len(samples) < 10 or any(r["status"] != "ok" for r in samples):
            raise ValueError("ten successful samples per case required; retain failures")
        discovery = statistics_ms([r["discovery_ms"] for r in samples])
        call = statistics_ms([r["first_call_ms"] for r in samples])
        result[case_id] = {"discovery": discovery, "first_call": call,
                           "noise_ms": max(3 * discovery["mad"], 5),
                           "p95_budget_ms": discovery["p95"] + max(3 * discovery["mad"], 10),
                           "first_call_tolerance_ms": max(3 * call["mad"], 5)}
    return result


def ledger_event(path: Path, event: dict[str, Any]) -> int:
    launches = event.get("launches", 0)
    if type(launches) is not int or launches < 0:
        raise ValueError("launch count must be a nonnegative integer")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.seek(0)
        previous = [json.loads(line) for line in stream if line.strip()]
        count = sum(e.get("launches", 0) for e in previous)
        if count + event.get("launches", 0) > 2300:
            raise ValueError("campaign launch ceiling exhausted")
        if event.get("kind") == "external" and any(
            e.get("source") == event.get("source") for e in previous
        ):
            raise ValueError("external lane already accounted")
        number = len(previous) + 1
        stream.write(json.dumps(dict(event, sequence=number), sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        return number


def environment(root: Path, role: str) -> dict[str, str]:
    # Allowlist avoids inheriting provider credentials, PYTHONPATH or mission authority.
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT") if k in os.environ}
    env.update(HOME=str(root / "user"), UNREST_HOME=str(root / "home"),
               UNREST_PROJECTS_DIR=str(root / "home" / "projects"),
               UNREST_NODE_ID="startup-probe", UNREST_NODE_TYPE=(
                   "validate" if role == "validator" else "work"),
               UNREST_HANDOFF_PATH=str(root / "handoff.json"),
               UNREST_TERMINAL_REVIEW_PATH=str(root / "terminal-review.json"),
               PYTHONDONTWRITEBYTECODE="1")
    return env


# External instrumentation only: baseline/candidate product bytes stay untouched.
CHILD = r'''
import json, pathlib, sys, time
start = time.monotonic_ns()
import unrest_harness.server as server
phases = {"import_ms": (time.monotonic_ns()-start)/1e6}
def wrap(owner, name):
    original = getattr(owner, name)
    def timed(*args, **kwargs):
        start = time.monotonic_ns()
        try: return original(*args, **kwargs)
        finally: phases[name+"_ms"] = (time.monotonic_ns()-start)/1e6
    setattr(owner, name, timed)
wrap(server.HarnessConfig, "discover")
wrap(server.HarnessConfig, "validate_capability_support")
for name in ("create_orchestrator_server", "create_worker_server",
             "create_validator_server", "create_terminal_reviewer_server"):
    wrap(server, name)
try: server.main()
finally: pathlib.Path("phases.json").write_text(json.dumps(phases, sort_keys=True))
'''


def package_identity(python: Path) -> dict[str, Any]:
    code = '''import hashlib, importlib.metadata as m, json, pathlib, platform
import unrest_harness
root = pathlib.Path(unrest_harness.__file__).parent
print(json.dumps({"python":platform.python_version(), "package_path":str(root),
"dependencies":dict(sorted((d.metadata["Name"],d.version) for d in m.distributions())),
"package_files":{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
for p in sorted(root.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}}))'''
    with tempfile.TemporaryDirectory(prefix="unrest046-identity-") as directory:
        completed = subprocess.run([str(python), "-I", "-c", code], cwd=directory,
                                   env=environment(Path(directory), "worker"),
                                   capture_output=True, text=True, check=True)
    return json.loads(completed.stdout)


async def rpc(proc: asyncio.subprocess.Process, message: dict[str, Any],
              timeout: float = 10) -> Any:
    assert proc.stdin and proc.stdout
    async with asyncio.timeout(timeout):
        proc.stdin.write((json.dumps(dict(jsonrpc="2.0", **message)) + "\n").encode())
        await proc.stdin.drain()
        if "id" not in message:
            return None
        while True:
            line = await proc.stdout.readline()
            if not line:
                raise RuntimeError("server exited before reply")
            response = json.loads(line)
            if response.get("id") == message["id"]:
                if "error" in response:
                    raise RuntimeError("JSON-RPC error")
                return response["result"]


async def discover(proc: asyncio.subprocess.Process, timeout: float = 10) -> Any:
    async with asyncio.timeout(timeout):
        await rpc(proc, {"method": "notifications/initialized"})
        return await rpc(proc, {"id": 2, "method": "tools/list", "params": {}})


def approved_fixture(manifest: dict[str, Any], case: dict[str, str]) -> Path | None:
    spec = manifest["fixtures"][case["home"]]
    if case["home"] == "held-out-populated":
        approval = Path(manifest["heldout_approval"])
        if not approval.is_file():
            raise ValueError("parent heldout/APPROVED.json missing")
        # Exact approval digest is provided by the parent after review, never guessed.
        if digest(approval) != manifest["heldout_approval_sha256"]:
            raise ValueError("heldout approval identity mismatch")
    if spec is None:
        if case["home"] != "empty":
            raise ValueError("missing populated fixture")
        return None
    fixture = Path(spec["path"])
    if "materializer" in spec:
        for key in ("materializer", "manifest", "oracle"):
            if digest(Path(spec[key]["path"])) != spec[key]["sha256"]:
                raise ValueError("heldout artifact identity mismatch")
        return fixture
    if inventory(fixture) != spec["files"]:
        raise ValueError("fixture bytes differ from frozen inventory")
    return fixture


def verify_projects(home: Path, projects: list[dict[str, Any]]) -> None:
    for project in projects:
        runtime = home / "projects" / project["project_id"] / ".unrest-runtime"
        mission = runtime / "missions" / "mission-001"
        state = json.loads((runtime / "state.json").read_text())["state"]
        tasks = json.loads((mission / "task-state.json").read_text())["tasks"]
        contracts = json.loads((mission / "contract-state.json").read_text())["items"]
        expected = project["expected"]
        if (state != expected["state"]
                or {k: v["status"] for k, v in tasks.items()} != expected["tasks"]
                or {k: v["status"] for k, v in contracts.items()}
                != dict.fromkeys(project["targets"], expected["contract"])):
            raise ValueError("independent project state oracle mismatch")


def prepare(python: Path, case: dict[str, str], manifest: dict[str, Any],
            directory: Path) -> dict[str, Any]:
    """Finish all synchronous setup before any peer receives a spawn timestamp."""
    fixture = approved_fixture(manifest, case)
    root = directory / "case"
    spec = manifest["fixtures"][case["home"]]
    if spec and "materializer" in spec:
        subprocess.run([str(python), "-I", spec["materializer"]["path"],
                        "--source", str(fixture), "--manifest", spec["manifest"]["path"],
                        "--destination", str(root)], check=True, capture_output=True,
                       cwd=directory, env=environment(Path(directory), case["role"]))
    else:
        root.mkdir()
    (root / "user").mkdir(exist_ok=True)
    if fixture and not (spec and "materializer" in spec):
        shutil.copytree(fixture, root / "home")
        # Synthetic fixtures embed absolute project/workspace paths. Rebase only
        # the declared fixture root, before taking the preservation snapshot.
        for copied in sorted((root / "home").rglob("*")):
            if copied.is_file():
                data = copied.read_bytes()
                copied.write_bytes(data.replace(str(manifest["fixtures"][case["home"]].get(
                    "relocation_root", fixture.parent)).encode(), str(root).encode()))
        (root / "workspace").mkdir(exist_ok=True)
    elif not fixture:
        (root / "home").mkdir()
    # Orchestrator requires a preseeded disposable project, even for empty home.
    setup = manifest.get("setup")
    if setup and case["home"] != "held-out-populated":
        script = Path(setup["path"])
        if digest(script) != setup["sha256"]:
            raise ValueError("fixture setup helper identity mismatch")
        subprocess.run([str(python), str(script), "--home", str(root / "home"),
                        "--probe-only"], cwd=root, env=environment(root, case["role"]),
                       check=True, capture_output=True)
    (root / "probes").mkdir(exist_ok=True)
    oracle = manifest["oracles"][case["role"]]
    if case["home"] == "held-out-populated":
        oracle = {**oracle, **manifest["heldout_oracles"][case["role"]]}
    if "heldout_approval" in manifest:
        approval_path = Path(manifest["heldout_approval"])
        if digest(approval_path) != manifest["heldout_approval_sha256"]:
            raise ValueError("heldout approval identity mismatch")
        approval = json.loads(approval_path.read_text())
        response_path = approval_path.parent / "first-call-oracle.json"
        if digest(response_path) != approval["artifact_sha256"]["first-call-oracle.json"]:
            raise ValueError("independent response oracle identity mismatch")
        independent = json.loads(response_path.read_text())[case["role"]]
        subset = independent["expected_response_subset"]
        if case["role"] == "orchestrator" and case["home"] != "held-out-populated":
            subset = {"projectId": oracle["arguments"]["project_id"],
                      "state": {"state": oracle["state"]}}
        oracle = {**oracle, "expected_response_subset": subset}
    env = environment(root, case["role"])
    if oracle.get("output"):
        env["UNREST_TERMINAL_REVIEW_PATH" if case["role"] == "terminal-reviewer"
            else "UNREST_HANDOFF_PATH"] = str(root / oracle["output"])
    if spec and "oracle" in spec:
        verify_projects(root / "home", json.loads(
            Path(spec["oracle"]["path"]).read_text())["projects"])
    before = inventory(root / "home")
    return {"root": root, "oracle": oracle, "env": env, "before": before}


def subset_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and subset_matches(actual[key], value)
            for key, value in expected.items())
    return type(actual) is type(expected) and actual == expected


def verify_response(result: dict[str, Any], oracle: dict[str, Any]) -> None:
    expected = oracle.get("expected_response_subset")
    if expected is None:
        # Accepted first-call contract, independent of the observed handoff.
        expected = ({"recorded": True} if oracle.get("handoff") is not None else {
            "projectId": oracle["arguments"]["project_id"],
            "state": {"state": oracle["state"]}})
    if not subset_matches(result.get("structuredContent"), expected):
        raise ValueError("first call response differs from independent oracle")


def verify_preservation(root: Path, before: dict[str, str], role: str) -> list[str]:
    after = inventory(root / "home")
    permitted = ({".unrest-runtime/runs/admission.lock", ".unrest/foundation/custody-root.json"}
                 if role == "orchestrator" else set())
    return sorted(k for k in before.keys() | after.keys()
                  if before.get(k) != after.get(k) and (k in before or k not in permitted))


def reserve(python: Path, case: dict[str, str], manifest: dict[str, Any],
            ledger: Path, diagnostic: bool) -> dict[str, Any]:
    sequence = ledger_event(ledger, {"kind": "launch", "launches": 1,
                                    "case_id": case["id"], "diagnostic": diagnostic,
                                    "python": str(python),
                                    "helper_sha256": digest(Path(__file__)),
                                    "manifest_sha256": hashlib.sha256(json.dumps(
                                        manifest, sort_keys=True).encode()).hexdigest()})
    row: dict[str, Any] = {"case_id": case["id"], "reservation": sequence,
                           "status": "failed", "events_ns": {},
                           "cache": "uncontrolled/warm-after-first"}
    return row


async def owned_wait(task: asyncio.Future[T], *, cancel: bool = False) -> T:
    """Keep ownership until completion, even if the caller is cancelled again."""
    cancellation = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            if cancellation is None:
                cancellation = exc
                if cancel:
                    task.cancel()
        except Exception:
            break
    if cancellation is not None:
        # Retrieve failures too; cancellation remains the caller's outcome.
        if not task.cancelled():
            task.exception()
        raise cancellation
    return task.result()


async def receive(python: Path, case: dict[str, str], prepared: dict[str, Any],
                  row: dict[str, Any], stderr: Any) -> None:
    root, oracle, env = (prepared[k] for k in ("root", "oracle", "env"))
    row["events_ns"]["spawn"] = time.monotonic_ns()
    async def spawn() -> asyncio.subprocess.Process:
        proc = await asyncio.create_subprocess_exec(
            str(python), "-I", "-c", CHILD, "--mode", case["role"],
            cwd=root, env=env, stderr=stderr,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            start_new_session=True, limit=16 * 1024 * 1024)
        prepared["proc"] = proc
        return proc

    # Registration must finish before cancellation can unwind to shutdown.
    proc = await owned_wait(asyncio.create_task(spawn()))
    await rpc(proc, {"id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "unrest046-ruler", "version": "1"}}})
    row["events_ns"]["initialize"] = time.monotonic_ns()
    prepared["catalog"] = await discover(proc)
    row["events_ns"]["tools_list"] = time.monotonic_ns()
    prepared["result"] = await rpc(proc, {"id": 3, "method": "tools/call", "params": {
        "name": oracle["tool"], "arguments": oracle["arguments"]}})
    row["events_ns"]["first_call"] = time.monotonic_ns()


def verify_first(case: dict[str, str], prepared: dict[str, Any],
                 row: dict[str, Any], diagnostic: bool) -> None:
    root, oracle, before = (prepared[k] for k in ("root", "oracle", "before"))
    catalog, result = prepared["catalog"], prepared["result"]
    if oracle.get("catalog") is None and diagnostic:
        row["unreviewed_catalog"] = catalog
    elif catalog != oracle["catalog"]:
        raise ValueError("role catalog mismatch")
    if result.get("isError"):
        raise ValueError("first tool call failed")
    verify_response(result, oracle)
    expected = oracle.get("handoff")
    if expected is not None:
        output = root / oracle["output"]
        if not output.exists() or json.loads(output.read_text()) != expected:
            raise ValueError("handoff differs from independent oracle")
    else:
        structured = result.get("structuredContent", {})
        row["response_keys"] = sorted(structured)
        row["response_state"] = structured.get("state", {}).get("state")
        if (structured.get("state", {}).get("state") != oracle["state"]
                or structured.get("projectId") != oracle["arguments"]["project_id"]):
            raise ValueError("unexpected disposable probe state")
    changed = verify_preservation(root, before, case["role"])
    if changed:
        row["changed_fixture_paths"] = changed
        raise ValueError("first call mutated seeded home")
    row["status"] = "ok"


def record_error(row: dict[str, Any], exc: BaseException) -> None:
    row["status"] = "failed"
    # Error class only: exceptions may contain private server output.
    row["error_type"] = type(exc).__name__
    safe_errors = {"role catalog mismatch", "first tool call failed",
                   "first call response differs from independent oracle",
                   "handoff differs from independent oracle",
                   "unexpected disposable probe state", "first call mutated seeded home",
                   "server exited before reply", "JSON-RPC error"}
    if str(exc) in safe_errors:
        row["error_code"] = str(exc)


async def shutdown(prepared: dict[str, Any], row: dict[str, Any]) -> None:
    await owned_wait(asyncio.create_task(_shutdown(prepared, row)))


async def _shutdown(prepared: dict[str, Any], row: dict[str, Any]) -> None:
    proc = prepared.get("proc")
    row["events_ns"]["shutdown_start"] = time.monotonic_ns()
    if proc:
        assert proc.stdin
        try:
            proc.stdin.close()
            await asyncio.wait_for(proc.wait(), SHUTDOWN_TIMEOUT)
        except Exception as exc:
            record_error(row, exc)
            if isinstance(exc, TimeoutError):
                row["shutdown_timeout"] = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # Reap has its own bound; failure leaves cleanup unconfirmed.
            await asyncio.wait_for(proc.wait(), SHUTDOWN_TIMEOUT)
        row["exit_code"] = proc.returncode
        if proc.returncode != 0:
            row["status"] = "failed"
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            pass
        else:
            row["status"] = "failed"
            row["process_leak"] = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            async with asyncio.timeout(SHUTDOWN_TIMEOUT):
                while True:
                    try:
                        os.killpg(proc.pid, 0)
                    except ProcessLookupError:
                        break
                    await asyncio.sleep(.01)
    prepared["cleanup_complete"] = True
    row["events_ns"]["exit"] = time.monotonic_ns()


def finish(case: dict[str, str], prepared: dict[str, Any], row: dict[str, Any]) -> None:
    root, oracle, before = (prepared[k] for k in ("root", "oracle", "before"))
    stderr_path = root / "stderr"
    try:
        changed = verify_preservation(root, before, case["role"])
        if changed:
            row["changed_fixture_paths"] = changed
            raise ValueError("shutdown mutated seeded home")
        if oracle.get("handoff") is not None:
            if json.loads((root / oracle["output"]).read_text()) != oracle["handoff"]:
                raise ValueError("shutdown mutated handoff")
        row["post_exit_preserved"] = True
    except Exception as exc:
        row["status"] = "failed"
        row["post_exit_preserved"] = False
        row["preservation_error_type"] = type(exc).__name__
    events = row["events_ns"]
    row["client_phases_ms"] = {
        name: (events[end] - events[start]) / 1e6
        for name, start, end in (
            ("initialize", "spawn", "initialize"),
            ("tools_list", "initialize", "tools_list"),
            ("first_call", "tools_list", "first_call"),
            ("shutdown", "shutdown_start", "exit"))
        if start in events and end in events}
    if "tools_list" in events:
        row["discovery_ms"] = (events["tools_list"] - events["spawn"]) / 1e6
    if "first_call" in events:
        row["first_call_ms"] = (events["first_call"] - events["tools_list"]) / 1e6
    if (root / "phases.json").exists():
        row["server_phases_ms"] = json.loads((root / "phases.json").read_text())
    row["stderr_sha256"] = digest(stderr_path) if stderr_path.exists() else None


async def measure_batch(python: Path, prepared: list[tuple[dict[str, str], dict[str, Any]]],
                        manifest: dict[str, Any], ledger: Path,
                        diagnostic: bool = False) -> list[dict[str, Any]]:
    # Barriers exclude all filesystem work from reply and shutdown deadlines.
    # A partial reservation failure consumes its prefix without spawning children.
    rows = [reserve(python, case, manifest, ledger, diagnostic) for case, _ in prepared]
    with ExitStack() as stack:
        streams = [stack.enter_context((item["root"] / "stderr").open("wb"))
                   for _, item in prepared]
        try:
            results = await owned_wait(asyncio.gather(*(receive(python, case, item, row, stream)
                for (case, item), row, stream in zip(prepared, rows, streams, strict=True)),
                return_exceptions=True), cancel=True)
            for (case, item), row, result in zip(prepared, rows, results, strict=True):
                try:
                    if isinstance(result, BaseException):
                        raise result
                    verify_first(case, item, row, diagnostic)
                except Exception as exc:
                    record_error(row, exc)
        finally:
            # Drain every cleanup before inspecting or persisting any result.
            results = await owned_wait(asyncio.gather(*(shutdown(item, row)
                for (_, item), row in zip(prepared, rows, strict=True)),
                return_exceptions=True))
            for row, result in zip(rows, results, strict=True):
                if isinstance(result, BaseException):
                    record_error(row, result)
    for (case, item), row in zip(prepared, rows, strict=True):
        try:
            if not item.get("cleanup_complete"):
                raise RuntimeError("child cleanup unconfirmed; root retained")
            finish(case, item, row)
        except Exception as exc:
            record_error(row, exc)
        ledger_event(ledger, {"kind": "result", "launches": 0, **row})
    return rows


async def measure(python: Path, case: dict[str, str], manifest: dict[str, Any],
                  ledger: Path, prepared: dict[str, Any],
                  diagnostic: bool = False) -> dict[str, Any]:
    return (await measure_batch(python, [(case, prepared)], manifest, ledger, diagnostic))[0]


def remove_root(directory: Path, prepared: dict[str, Any]) -> None:
    # A failed reap/group check must never erase a possibly live child's home.
    if "proc" not in prepared or prepared.get("cleanup_complete"):
        shutil.rmtree(directory)


async def run(args: argparse.Namespace) -> int:
    manifest = json.loads(args.case_manifest.read_text())
    if manifest["cases"] != case_matrix():
        raise ValueError("full immutable Cartesian case matrix required")
    if not args.diagnostic:
        # Entire pilot waits for heldout approval, including empty/seeded cases.
        approved_fixture(manifest, next(c for c in manifest["cases"]
                                        if c["home"] == "held-out-populated"))
    identity = package_identity(args.python)
    rows: list[dict[str, Any]] = []
    cases = [c for c in manifest["cases"] if c["install"] == args.install
             and c["load"] == args.load and (not args.case or c["id"] == args.case)]
    scheduled = cases * args.samples
    width = 4 if args.load == "concurrent-4" else 1
    if len(scheduled) % width:
        raise ValueError("total concurrent launches must divide by four; no padding")
    for start in range(0, len(scheduled), width):
        with ExitStack() as stack:
            prepared = []
            for case in scheduled[start:start + width]:
                directory = Path(tempfile.mkdtemp(prefix="unrest046-startup-"))
                item: dict[str, Any] = {}
                stack.callback(remove_root, directory, item)
                item.update(prepare(args.python, case, manifest, directory))
                prepared.append((case, item))
            batch = await measure_batch(args.python, prepared, manifest, args.ledger,
                                        args.diagnostic)
        rows.extend(batch)
        write_json(args.output, {"identity": identity, "manifest_sha256": digest(
            args.case_manifest), "helper_sha256": digest(Path(__file__)), "samples": rows})
        if any(r["status"] != "ok" for r in batch):
            return 1
    if not rows:
        raise ValueError("no matching case")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--case-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--install", choices=("editable", "wheel"), required=True)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--case")
    parser.add_argument("--load", choices=("isolated", "concurrent-4"), default="isolated")
    parser.add_argument("--diagnostic", action="store_true")
    args = parser.parse_args()
    if not args.python.is_absolute() or args.samples < 1:
        parser.error("absolute interpreter and positive sample count required")
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
