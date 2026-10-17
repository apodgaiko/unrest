"""Prepare and observe an inactive disposable desktop MCP registration.

Run with the candidate interpreter and -I. This external observer is not shipped
in the package and does not install or activate a desktop configuration.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any
import uuid


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def save(path: Path, value: Any) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def isolate(root: Path) -> None:
    os.environ.clear()
    os.environ.update(HOME=str(root / "user"), PATH="/usr/bin:/bin",
                      LANG="C.UTF-8", UNREST_HOME=str(root / "home"),
                      UNREST_PROJECTS_DIR=str(root / "home/projects"),
                      PYTHONDONTWRITEBYTECODE="1")
    sys.dont_write_bytecode = True
    os.chdir(root)


def package_identity() -> dict[str, Any]:
    import unrest_harness

    package = Path(unrest_harness.__file__).resolve().parent
    files = {str(p.relative_to(package)): sha(p.read_bytes())
             for p in sorted(package.rglob("*"))
             if p.is_file() and "__pycache__" not in p.parts}
    return {"path": str(package), "files": files, "sha256": sha(canonical(files)),
            "version": importlib.metadata.version("unrest-harness"),
            "dependencies": dict(sorted((d.metadata["Name"], d.version)
                                        for d in importlib.metadata.distributions()))}


def prepare(root: Path, candidate_manifest: Path) -> dict[str, Any]:
    # Never reuse an existing fixture or silently point at an ordinary home.
    manifest_bytes = candidate_manifest.read_bytes()
    json.loads(manifest_bytes)
    root.mkdir(mode=0o700)
    for name in ("user", "home", "workspace", "observations"):
        (root / name).mkdir(mode=0o700)
    isolate(root)
    from unrest_harness.config import HarnessConfig
    from unrest_harness.controller import ProjectController
    from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer

    config = HarnessConfig.discover()
    config.validate_capability_support()
    project_id = "desktop-probe-" + uuid.uuid4().hex
    from unrest_harness.models import TerminalReviewHandoff

    def refuse_dispatch(request: Any) -> Any:
        raise RuntimeError("desktop fixture preparation cannot dispatch")

    controller = ProjectController(config, MockDispatcher(refuse_dispatch),
                                   MockTerminalReviewer(TerminalReviewHandoff(
                                       done=False, report="fixture only")))
    controller.store.generate_project_id = lambda brief: project_id  # type: ignore[method-assign]
    controller.start_project("Disposable desktop discovery fixture", str(root / "workspace"))
    script = Path(__file__).resolve()
    registration = {"command": sys.executable,
                    "args": ["-I", str(script), "serve", "--root", str(root)]}
    name = "unrest-candidate-" + project_id.removeprefix("desktop-probe-")
    setup = {"schema": 1, "project_id": project_id, "role": "orchestrator",
             "root": str(root), "interpreter": sys.executable,
             "interpreter_realpath": str(Path(sys.executable).resolve()),
             "interpreter_sha256": sha(Path(sys.executable).read_bytes()),
             "launcher": str(script), "launcher_sha256": sha(script.read_bytes()),
             "candidate_manifest_sha256": sha(manifest_bytes),
             "package": package_identity(), "registration_name": name,
             "registration": registration,
             "policy": {str(p.relative_to(config.bundled_dir)): sha(p.read_bytes())
                        for p in sorted(config.bundled_dir.rglob("*")) if p.is_file()},
             "config": {"harness_home": str(config.harness_home),
                        "projects_dir": str(config.projects_dir),
                        "capability_profile": config.capability_profile,
                        "capability_policy_version": config.capability_policy_version},
             "certification": "unverified; validator must bind to certified artifact"}
    (root / "candidate-manifest.json").write_bytes(manifest_bytes)
    save(root / "setup.json", setup)
    save(root / "registration.json", {"mcpServers": {name: registration}})
    save(root / "call.json", {"name": "inspect_project", "arguments": {"project_id": project_id}})
    return setup


class ResponseObserver:
    """Forward exact wire bytes; persist only matching disposable result hashes."""

    def __init__(self, raw: Any, project_id: str, observation: Path) -> None:
        self.raw = raw
        self.project_id = project_id
        self.observation = observation
        self.pending = b""
        self.sequence = 0

    def write(self, data: bytes) -> int:
        # Observe only after the underlying write succeeds. No payload is retained
        # on disk, including unrelated calls a client might issue accidentally.
        count = self.raw.write(data)
        self.pending += data[:count]
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            try:
                message = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if not isinstance(message, dict):
                continue
            result = message.get("result")
            content = result.get("structuredContent") if isinstance(result, dict) else None
            if isinstance(content, dict) and content.get("projectId") == self.project_id:
                self.sequence += 1
                save(self.observation / f"response-{self.sequence:04d}.json", {
                    "pid": os.getpid(), "monotonic_ns": time.monotonic_ns(),
                    "project_id": self.project_id,
                    "result_sha256": sha(canonical(result)),
                    "structured_content_sha256": sha(canonical(content)),
                    "wire_sha256": sha(line + b"\n")})
        if len(self.pending) > 16 * 1024 * 1024:
            raise ValueError("observer line limit exceeded")
        return int(count)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.raw, name)


class ObservedStdout:
    def __init__(self, original: Any, observer: ResponseObserver) -> None:
        self.original = original
        self.buffer = observer

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)


def serve(root: Path) -> None:
    setup = json.loads((root / "setup.json").read_text())
    if root != Path(setup["root"]):
        raise ValueError("fixture root mismatch")
    isolate(root)
    actual = package_identity()
    if (actual != setup["package"] or sys.executable != setup["interpreter"]
            or sha(Path(sys.executable).read_bytes()) != setup["interpreter_sha256"]
            or sha(Path(__file__).read_bytes()) != setup["launcher_sha256"]
            or sha((root / "candidate-manifest.json").read_bytes())
            != setup["candidate_manifest_sha256"]
            or json.loads((root / "registration.json").read_text()) != {
                "mcpServers": {setup["registration_name"]: setup["registration"]}}):
        raise ValueError("prepared candidate identity changed; prepare a new fixture")
    from unrest_harness import server
    from unrest_harness.config import HarnessConfig

    config = HarnessConfig.discover()
    config.validate_capability_support()
    if {"harness_home": str(config.harness_home), "projects_dir": str(config.projects_dir),
        "capability_profile": config.capability_profile,
        "capability_policy_version": config.capability_policy_version} != setup["config"]:
        raise ValueError("prepared configuration changed")
    observation = root / "observations" / uuid.uuid4().hex
    observation.mkdir(mode=0o700)
    started = subprocess.run(["/bin/ps", "-p", str(os.getpid()), "-o", "lstart="],
                             check=True, capture_output=True, text=True, timeout=2).stdout.strip()
    if not started:
        raise ValueError("responding process start unavailable")
    save(observation / "process.json", {
        "pid": os.getpid(), "process_start": started, "observed_ns": time.time_ns(),
        "interpreter": sys.executable, "sys_path": sys.path,
        "server_module": server.__file__, "package_sha256": actual["sha256"],
        "setup_sha256": sha((root / "setup.json").read_bytes()),
        "registration_sha256": sha((root / "registration.json").read_bytes()),
        "candidate_manifest_sha256": setup["candidate_manifest_sha256"],
        "project_id": setup["project_id"], "role": setup["role"],
        "policy_sha256": sha(canonical(setup["policy"])),
        "config_sha256": sha(canonical(setup["config"]))})
    original = sys.stdout
    sys.stdout = ObservedStdout(original, ResponseObserver(
        original.buffer, setup["project_id"], observation))  # type: ignore[assignment]
    sys.argv = ["unrest-server", "--mode", "orchestrator"]
    try:
        server.main()
    finally:
        sys.stdout = original
        save(observation / "exit.json", {"pid": os.getpid(), "observed_ns": time.time_ns()})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "serve"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.action == "prepare":
        if args.candidate_manifest is None:
            parser.error("prepare requires --candidate-manifest")
        setup = prepare(root, args.candidate_manifest.resolve())
        print(json.dumps({"root": str(root), "registration": setup["registration_name"],
                          "project_id": setup["project_id"]}, sort_keys=True))
    else:
        serve(root)


if __name__ == "__main__":
    main()
