"""Coordinate synthetic compartment readiness without exposing runner authority.

Product source is deliberately absent. A successful probe is not source readiness
and cannot be used by a release-checkpoint receipt or deduplication decision.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import traceback
import uuid

BASE = "python@sha256:9a4a5ceafb4ddd7468a09ade0049463a7bd1acbefda52adee748544110fd032d"
SUPPORT = Path(__file__).resolve().parent
REPOSITORY = SUPPORT.parent.parent
PACKAGES = {"pytest", "iniconfig", "packaging", "pluggy", "pygments"}
TMPFS = {
    "/work": "rw,nosuid,nodev,size=128m,uid=20000,gid=20000,mode=0711",
    "/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777",
    "/records": "rw,nosuid,nodev,noexec,size=32m,uid=20001,gid=20001,mode=0700",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv: list[str], log: Path) -> subprocess.CompletedProcess[bytes]:
    with log.open("ab") as output:
        return subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, check=False)


def validate_container(value: dict, public_support: Path) -> None:
    host = value["HostConfig"]
    expected = {
        "Privileged": False, "ReadonlyRootfs": True, "NetworkMode": "none",
        "IpcMode": "private", "PidMode": "", "CgroupnsMode": "private",
        "PidsLimit": 128, "Memory": 1073741824,
    }
    if any(host.get(key) != wanted for key, wanted in expected.items()):
        raise RuntimeError("compartment scope/privilege configuration drift")
    # Docker inspect canonicalizes CLI capability names with the CAP_ prefix.
    capabilities = host["CapAdd"]
    if host["CapDrop"] != ["ALL"] or len(capabilities) != 5 or {
        value.removeprefix("CAP_") for value in capabilities
    } != {"SETUID", "SETGID", "SETPCAP", "SYS_PTRACE", "DAC_READ_SEARCH"}:
        raise RuntimeError("bootstrap capability drift")
    if host["SecurityOpt"] != ["no-new-privileges"]:
        raise RuntimeError("compartment security option drift")
    if host["Tmpfs"] != TMPFS:
        raise RuntimeError("writable root inventory drift")
    mounts = value["Mounts"]
    if len(mounts) != 1 or not all((
        mounts[0]["Type"] == "bind", mounts[0]["Source"] == str(public_support),
        mounts[0]["Destination"] == "/guard", mounts[0]["RW"] is False,
    )):
        raise RuntimeError("public support mount inventory drift")
    if value["Config"]["OpenStdin"] or value["Config"]["Entrypoint"] != [
        "/usr/local/bin/python",
    ] or value["Config"]["Cmd"] != ["-B", "/guard/compartment_probe.py"]:
        raise RuntimeError("finite synthetic entry point drift")


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    root.mkdir(mode=0o700)
    raw = root / "raw"
    raw.mkdir(mode=0o700)
    log = raw / "coordinator.log"
    import importlib.util
    spec = importlib.util.spec_from_file_location("environment", SUPPORT / "environment.py")
    assert spec is not None and spec.loader is not None
    environment = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(environment)
    if environment.BASE != BASE:
        raise RuntimeError("environment base identity drift")
    inputs = {"uv_bootstrap_sha256": environment.UV_SHA256,
              "uv_lock_sha256": sha(REPOSITORY / "uv.lock")}
    image = ""
    try:
        image = environment.build(root / "build", REPOSITORY, log)
        inputs["image_id"] = image
        exit_code = 0
    except Exception:
        with log.open("a") as output:
            traceback.print_exc(file=output)
        exit_code = 125
    container = "source-observer-probe-" + uuid.uuid4().hex
    if exit_code == 0:
        argv = [
            "docker", "create", "--name", container, "--read-only", "--network=none",
            "--ipc=private", "--cgroupns=private", "--cap-drop=ALL",
            "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=SETPCAP",
            "--cap-add=SYS_PTRACE",
            "--cap-add=DAC_READ_SEARCH",
            "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=1g",
            *["--tmpfs=" + path + ":" + options for path, options in TMPFS.items()],
            "--mount=type=bind,src=" + str(SUPPORT) + ",dst=/guard,readonly",
            "--entrypoint=/usr/local/bin/python", image,
            "-B", "/guard/compartment_probe.py",
        ]
        try:
            result = run(argv, log)
            if result.returncode:
                raise RuntimeError("compartment creation failed")
            inspected = subprocess.check_output(["docker", "inspect", container])
            (raw / "container-inspect.json").write_bytes(inspected)
            validate_container(json.loads(inspected)[0], SUPPORT)
            result = run(["docker", "start", "--attach", container], log)
            # Inspect real exit state; docker start --attach need not return it.
            state = subprocess.check_output([
                "docker", "inspect", "--format={{json .State}}", container,
            ])
            state_value = json.loads(state)
            if state_value["Running"] or state_value["OOMKilled"]:
                raise RuntimeError("compartment did not settle normally")
            exit_code = state_value["ExitCode"]
            # The fixed evidence envelope remains in the private coordinator log.
            (raw / "container-state.json").write_bytes(state)
        except Exception:
            with log.open("a") as output:
                traceback.print_exc(file=output)
            exit_code = 125
        finally:
            run(["docker", "rm", "--force", container], log)
    safe_identity = {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "head_sha": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA"),
        "base_oci": BASE, "uv_lock_sha256": sha(REPOSITORY / "uv.lock"),
        "support": {str(p.relative_to(SUPPORT)): sha(p) for p in sorted(SUPPORT.rglob("*"))
                    if p.is_file() and p.suffix in {".py", ".json", ".pem", ".c"}},
        "synthetic_dependencies": inputs, "synthetic_exit_code": exit_code,
        "source_checkpoint_ready": False, "selected_carrier": None,
        "original_source_cases_executed": 0,
    }
    (raw / "provenance.json").write_text(json.dumps(safe_identity, sort_keys=True, indent=2))
    archive = root / "raw.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        for path in sorted(raw.iterdir()):
            if not path.is_file() or path.is_symlink():
                raise RuntimeError("nonregular private evidence member")
            output.add(path, arcname=path.name, recursive=False)
    encrypted = root / "evidence.cms"
    result = run([
        "openssl", "cms", "-encrypt", "-binary", "-aes-256-cbc", "-outform", "DER",
        "-in", str(archive), "-out", str(encrypted),
        str(SUPPORT / "evidence-recipient.pem"),
    ], root / "encryption.log")
    if result.returncode:
        raise RuntimeError("private evidence encryption failed")
    safe_identity["ciphertext_sha256"] = sha(encrypted)
    safe_identity["plaintext_archive_sha256"] = sha(archive)
    (root / "safe-provenance.json").write_text(
        json.dumps(safe_identity, sort_keys=True, indent=2) + "\n"
    )
    shutil.rmtree(raw)
    archive.unlink()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
