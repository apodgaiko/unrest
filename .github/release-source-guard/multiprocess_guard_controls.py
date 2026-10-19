"""New ownership methods under real inherited guard, READY and kernel tracing."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import sysconfig
from types import SimpleNamespace

SUPPORT = Path(__file__).resolve().parent
REPOSITORY = SUPPORT.parent.parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def child(path):
    manifest = json.loads(Path(path).read_bytes())
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    endpoint = load("endpoint", SUPPORT / "finite/endpoint.py")
    endpoint.early(manifest["endpoint"])
    guard = load("runtime_guard", SUPPORT / "finite/runtime_guard.py")
    endpoint.attach(guard)
    guard.install(path, sha(path))
    guard.require_ready("root")
    sys.path.insert(0, str(REPOSITORY))
    import pytest

    class Plugin:
        def pytest_runtest_setup(self, item):
            guard._STATE["case"] = item.nodeid

        def pytest_collection_finish(self, session):
            names = [item.nodeid for item in session.items]
            assert len(names) == 31
            (Path(manifest["owned_root"]) / "collection.json").write_text(json.dumps(names))

        def pytest_runtest_logreport(self, report):
            guard.append(
                {
                    "kind": "test_outcome",
                    "nodeid": report.nodeid,
                    "phase": report.when,
                    "outcome": report.outcome,
                }
            )

    status = int(
        pytest.main(
            [
                "-q",
                "-p",
                "no:cacheprovider",
                "--basetemp=" + manifest["owned_root"] + "/pytest",
                "--junitxml=" + manifest["owned_root"] + "/ownership.xml",
                "tests/test_multiprocess_resource_ownership.py",
                "tests/test_session_resource_ownership.py",
            ],
            plugins=[Plugin()],
        )
    )
    summary = guard.observe_summary(path)
    summary.update(original_pytest_exit_code=status, original_source_cases_executed=False)
    (Path(manifest["owned_root"]) / "summary.json").write_text(json.dumps(summary, sort_keys=True))
    assert summary["ready"] and not endpoint.STATE["poison"]
    return status


def run(root):
    assert sys.platform == "linux" and os.getuid() == 20000
    assert os.statvfs(REPOSITORY).f_flag & os.ST_RDONLY
    root.mkdir(mode=0o700)
    (root / "home").mkdir(mode=0o700)
    (root / "events").mkdir(mode=0o700)
    control = root / "control"
    control.mkdir(mode=0o700)
    module = root / "profile_gate.so"
    compiler = Path("/usr/bin/gcc").resolve(strict=True)
    compilation = subprocess.run(
        [
            str(compiler),
            "-shared",
            "-fPIC",
            "-O2",
            "-I" + sysconfig.get_path("include"),
            str(SUPPORT / "profile_gate.c"),
            "-o",
            str(module),
        ],
        capture_output=True,
    )
    (root / "compiler.stdout").write_bytes(compilation.stdout)
    (root / "compiler.stderr").write_bytes(compilation.stderr)
    assert compilation.returncode == 0
    finite = SUPPORT / "finite"
    template = json.loads((finite / "source-template.json").read_bytes())
    manifest = {
        **template,
        "checkout": str(REPOSITORY),
        "owned_root": str(root),
        "events": str(root / "events"),
        "guard": str(finite / "runtime_guard.py"),
        "guard_sha256": sha(finite / "runtime_guard.py"),
        "registry": {"path": str(finite / "registry.py"), "sha256": sha(finite / "registry.py")},
        "direct_support": {
            "path": str(finite / "direct_routes.py"),
            "files": {str(p): sha(p) for p in sorted(finite.glob("*.py"))},
        },
        "runtime": {
            "paths": [sys.executable],
            "realpath": str(Path(sys.executable).resolve()),
            "sha256": sha(sys.executable),
        },
        "product_pins": {
            str(p.relative_to(REPOSITORY)): sha(p)
            for folder in ("src", "tests", "tools")
            for p in sorted((REPOSITORY / folder).rglob("*.py"))
        },
        "http_source": str(REPOSITORY / "tests/test_server.py"),
        "native_sysctl_offsets": {"system": "Linux", "abi": "proc-stat-start-ticks"},
        "linux_profile_gate": {
            "path": str(module),
            "sha256": sha(module),
            "source_sha256": sha(SUPPORT / "profile_gate.c"),
        },
    }
    manifest["endpoint"] = {
        "responses": str(control),
        "nonce": os.urandom(32).hex(),
        "socket": str(control / "receipt.sock"),
        "observer_pid": os.getpid(),
        "observer_uid": os.getuid(),
        "sha256": sha(finite / "endpoint.py"),
    }
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest, sort_keys=True))
    host = load("control_linux_supervisor", SUPPORT / "linux_supervisor.py")
    trace_module = load("linux_trace", SUPPORT / "linux_trace.py")
    start_read, start_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(start_write)
            output = os.open(root / "stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            errors = os.open(root / "stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.dup2(output, 1)
            os.dup2(errors, 2)
            os.close(output)
            os.close(errors)
            os.chdir(REPOSITORY)
            trace_module.install_observation_filter()
            if os.read(start_read, 1) != b"1":
                os._exit(126)
            os.close(start_read)
            os.execve(
                sys.executable,
                [sys.executable, "-B", str(Path(__file__).resolve()), "--child", str(path)],
                {
                    "HOME": str(root / "home"),
                    "PATH": "/usr/bin:/bin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "LC_ALL": "C.UTF-8",
                    "LANG": "C.UTF-8",
                },
            )
        finally:
            os._exit(127)
    os.close(start_read)
    supervisor = host.Supervisor(
        {"manifest": str(path), "pins": {str(path): sha(path)}, "endpoint": manifest["endpoint"]},
        SimpleNamespace(pid=pid),
    )
    info = os.fstat(supervisor.channel.fileno())
    (control / "HOST-FDS.json").write_text(
        json.dumps(
            {
                "nonce": manifest["endpoint"]["nonce"],
                "objects": [
                    {"device": info.st_dev, "inode": info.st_ino, "type": stat.S_IFMT(info.st_mode)}
                ],
            }
        )
    )
    vector = [sys.executable, "-B", str(Path(__file__).resolve()), "--child", str(path)]
    environment = {
        "HOME": str(root / "home"),
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    }
    consumed = set()
    accepted = []

    def resolve(child_pid, exe, argv, env, cwd):
        parent = trace_module._observation.process_identity(child_pid)["ppid"]
        supervisor.refresh()
        if parent not in supervisor.registered:
            return False
        events = supervisor.events()
        candidates = [
            row
            for row in events
            if row["kind"] == "actual_launch_binding"
            and row["owner_pid"] == parent
            and row["token"] not in consumed
            and row["transformed_argv_sha256"]
            == hashlib.sha256(json.dumps(argv).encode()).hexdigest()
            and row["environment_sha256"]
            == hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest()
            and row["cwd"] == cwd
        ]
        if len(candidates) != 1:
            return False
        selected = candidates[0]
        if (
            exe != sys.executable
            or sha(exe) != manifest["runtime"]["sha256"]
            or argv[-2] != "-c"
            or sha_bytes(argv[-1].encode()) != selected["bootstrap_sha256"]
        ):
            return False
        registration = [
            row for row in events if row["kind"] == "admitted" and row["token"] == selected["token"]
        ]
        if len(registration) != 1 or registration[0]["class"] not in {
            "source-multiprocess-tracker",
            "source-multiprocess-spawn",
        }:
            return False
        for item in selected["multiprocess_descriptors"]:
            info = Path("/proc/" + str(child_pid) + "/fd/" + str(item["fd"])).stat()
            if (info.st_dev, info.st_ino, info.st_mode, info.st_uid) != tuple(
                item[k] for k in ("device", "inode", "mode", "uid")
            ):
                return False
        writer = selected["multiprocess_fifo_pair"][1]
        info = Path("/proc/" + str(parent) + "/fd/" + str(writer["fd"])).stat()
        if (info.st_dev, info.st_ino, info.st_mode) != (
            writer["device"],
            writer["inode"],
            writer["mode"],
        ):
            return False
        consumed.add(selected["token"])
        accepted.append(
            {
                "pid": child_pid,
                "parent": parent,
                "declaration": selected,
                "registration": registration[0],
            }
        )
        return True

    def attached():
        os.write(start_write, b"1")
        os.close(start_write)

    def tick(trace):
        supervisor.tick()

    try:
        proof = trace_module.OwnedTrace(
            pid,
            [
                {
                    "pid": pid,
                    "path": sys.executable,
                    "argv": vector,
                    "environment": environment,
                    "cwd": str(REPOSITORY),
                    "sha256": sha(sys.executable),
                }
            ],
            timeout=180,
            on_tick=tick,
            resolve_exec=resolve,
            seize=True,
            on_attached=attached,
            selective=True,
        ).run()
        supervisor.tick()
        (root / "kernel.json").write_text(json.dumps(proof, sort_keys=True))
        (root / "accepted.json").write_text(json.dumps(accepted, sort_keys=True))
        (root / "receipts.json").write_text(json.dumps(supervisor.receipts, sort_keys=True))
        result = {
            "root_wait_raw": proof["root_parent_wait_raw"],
            "kernel_poison": proof["poison"],
            "supervisor_poison": supervisor.poisoned,
            "accepted": len(accepted),
            "new_methods_only": True,
            "source_read_only": True,
            "uid": os.getuid(),
            "guard_sha256": manifest["guard_sha256"],
            "collection_sha256": sha(root / "collection.json")
            if (root / "collection.json").exists()
            else None,
        }
        (root / "proof.json").write_text(json.dumps(result, sort_keys=True))
        print(json.dumps(result, sort_keys=True))
        assert (
            proof["root_parent_wait_raw"] == 0 and not proof["poison"] and not supervisor.poisoned
        )
        waits = [row for row in proof["records"] if row["kind"] == "original_parent_wait4"]
        assert len(accepted) > 0
        for child_record in accepted:
            rows = [
                row
                for row in waits
                if row["parent"] == child_record["parent"] and row["child"] == child_record["pid"]
            ]
            assert len(rows) == 1
    finally:
        supervisor.close()


def sha_bytes(body):
    return hashlib.sha256(body).hexdigest()


if __name__ == "__main__":
    if len(sys.argv) == 3:
        assert sys.argv[1] == "--child"
        raise SystemExit(child(sys.argv[2]))
    if len(sys.argv) == 2:
        run(Path(sys.argv[1]))
    else:
        raise SystemExit(2)
