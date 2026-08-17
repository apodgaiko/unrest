#!/usr/bin/env python3
"""Exercise deterministic ``unrest init`` output through a console script."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path


def _inventory(root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in (root, *sorted(root.rglob("*"))):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            kind = "directory"
            payload = b""
        elif stat.S_ISREG(info.st_mode):
            kind = "file"
            payload = path.read_bytes()
        elif stat.S_ISLNK(info.st_mode):
            kind = "symlink"
            payload = os.fsencode(os.readlink(path))
        else:
            kind = "other"
            payload = b""
        entries.append(
            {
                "path": str(path.relative_to(root)),
                "kind": kind,
                "mode": stat.S_IMODE(info.st_mode),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return entries


def _inventory_hash(inventory: list[dict[str, object]]) -> str:
    payload = json.dumps(
        inventory,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _config_path(boundary: Path, scope: str, agent: str) -> Path:
    if scope == "project":
        return boundary / (".mcp.json" if agent == "claude" else ".codex/config.toml")
    return boundary / (".claude.json" if agent == "claude" else ".codex/config.toml")


def _run(command: Path, arguments: list[str], cwd: Path, env: dict[str, str]) -> dict[str, object]:
    completed = subprocess.run(
        [str(command), *arguments],
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", errors="replace"),
        "stderr": completed.stderr.decode("utf-8", errors="replace"),
        "stdout_base64": base64.b64encode(completed.stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(completed.stderr).decode("ascii"),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def _assert_same_result(first: dict[str, object], second: dict[str, object]) -> None:
    for field in ("exit_code", "stdout_base64", "stderr_base64"):
        if first[field] != second[field]:
            raise RuntimeError(f"repeated init {field} differs")


def _authoritative_prompt(command: Path) -> bytes:
    first_line = command.read_text(encoding="utf-8").splitlines()[0]
    if not first_line.startswith("#!"):
        raise RuntimeError(f"console script has no interpreter shebang: {command}")
    interpreter = first_line[2:]
    completed = subprocess.run(
        [
            interpreter,
            "-c",
            (
                "from unrest_harness.config import HarnessConfig; "
                "p=HarnessConfig.discover().bundled_dir/'prompts'/'orchestrator'/"
                "'system_prompt.md'; import sys; sys.stdout.buffer.write(p.read_bytes())"
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"cannot load installed authoritative prompt: {completed.stderr.decode()}"
        )
    return completed.stdout


def check_init_output_stability(command: Path) -> dict[str, object]:
    resolved_command = command.resolve(strict=True)
    authoritative_prompt = _authoritative_prompt(resolved_command)
    cells: list[dict[str, object]] = []
    invalid_inputs: list[dict[str, object]] = []
    unsafe_controls: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="unrest-init-output-") as temporary:
        root = Path(temporary)
        for scope in ("project", "user"):
            for agent in ("claude", "codex"):
                for root_state in ("absent", "existing"):
                    cell = root / f"{scope}-{agent}-{root_state}"
                    home = cell / "home"
                    workspace = cell / "workspace"
                    unrest_home = cell / "unrest-home"
                    home.mkdir(parents=True)
                    workspace.mkdir()
                    unrest_home.mkdir()
                    boundary = workspace if scope == "project" else home
                    managed_root = boundary / f".{agent}"
                    if root_state == "existing":
                        sentinel = managed_root / "unrelated" / "keep.bin"
                        sentinel.parent.mkdir(parents=True)
                        sentinel.write_bytes(b"unrelated\x00configuration\n")
                        sentinel.chmod(0o600)
                    arguments = ["init", "--agent", agent]
                    if scope == "project":
                        arguments.extend(["--workspace-dir", str(workspace)])
                    else:
                        arguments.extend(["--scope", "user"])
                    env = {
                        "HOME": str(home),
                        "PATH": os.environ.get("PATH", ""),
                        **(
                            {"PYTHONPATH": os.environ["PYTHONPATH"]}
                            if os.environ.get("PYTHONPATH")
                            else {}
                        ),
                        "PYTHONUTF8": "1",
                        "UNREST_HOME": str(unrest_home),
                    }
                    first = _run(resolved_command, arguments, workspace, env)
                    first_inventory = _inventory(cell)
                    first_inventory_hash = _inventory_hash(first_inventory)
                    config_path = _config_path(boundary, scope, agent)
                    if first["exit_code"] != 0 or not config_path.is_file():
                        raise RuntimeError(
                            f"first init failed for {scope}/{agent}/{root_state}: {first}"
                        )
                    first_config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest()
                    second = _run(resolved_command, arguments, workspace, env)
                    second_inventory = _inventory(cell)
                    second_inventory_hash = _inventory_hash(second_inventory)
                    second_config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest()
                    third = _run(resolved_command, arguments, workspace, env)
                    _assert_same_result(second, third)
                    if first_inventory_hash != second_inventory_hash:
                        raise RuntimeError(
                            f"repeated init inventory differs for {scope}/{agent}/{root_state}"
                        )
                    if first_config_hash != second_config_hash:
                        raise RuntimeError(
                            f"repeated init config differs for {scope}/{agent}/{root_state}"
                        )
                    if "created=1 repaired=0 verified=0" not in str(first["stdout"]):
                        raise RuntimeError(
                            f"prompt create message failed for {scope}/{agent}/{root_state}"
                        )
                    if "created=0 repaired=0 verified=1" not in str(second["stdout"]):
                        raise RuntimeError(
                            f"prompt verify message failed for {scope}/{agent}/{root_state}"
                        )

                    prompt = boundary / f".{agent}" / "orchestrator_prompt.md"
                    prompt.write_bytes(b"corrupted installed prompt\n")
                    corrupt_sha256 = hashlib.sha256(prompt.read_bytes()).hexdigest()
                    repaired = _run(resolved_command, arguments, workspace, env)
                    if repaired["exit_code"] != 0 or "created=0 repaired=1 verified=0" not in str(
                        repaired["stdout"]
                    ):
                        raise RuntimeError(
                            f"prompt repair message failed for {scope}/{agent}/{root_state}"
                        )
                    if prompt.read_bytes() != authoritative_prompt:
                        raise RuntimeError(
                            f"prompt bytes were not repaired for {scope}/{agent}/{root_state}"
                        )
                    if stat.S_IMODE(prompt.stat().st_mode) != 0o644:
                        raise RuntimeError(
                            f"prompt mode was not repaired for {scope}/{agent}/{root_state}"
                        )

                    prompt.write_bytes(authoritative_prompt[: max(1, len(authoritative_prompt) // 3)])
                    truncated_sha256 = hashlib.sha256(prompt.read_bytes()).hexdigest()
                    truncated_repair = _run(resolved_command, arguments, workspace, env)
                    if "created=0 repaired=1 verified=0" not in str(
                        truncated_repair["stdout"]
                    ) or prompt.read_bytes() != authoritative_prompt:
                        raise RuntimeError(
                            f"truncated prompt was not repaired for {scope}/{agent}/{root_state}"
                        )

                    prompt.chmod(0o600)
                    wrong_mode_repair = _run(resolved_command, arguments, workspace, env)
                    if "created=0 repaired=1 verified=0" not in str(
                        wrong_mode_repair["stdout"]
                    ) or stat.S_IMODE(prompt.stat().st_mode) != 0o644:
                        raise RuntimeError(
                            f"wrong prompt mode was not repaired for {scope}/{agent}/{root_state}"
                        )
                    repaired_verify = _run(resolved_command, arguments, workspace, env)
                    repaired_repeat = _run(resolved_command, arguments, workspace, env)
                    _assert_same_result(repaired_verify, repaired_repeat)
                    cells.append(
                        {
                            "scope": scope,
                            "agent": agent,
                            "root_state": root_state,
                            "create_result": first,
                            "verify_result": second,
                            "repair_result": repaired,
                            "truncated_repair_result": truncated_repair,
                            "wrong_mode_repair_result": wrong_mode_repair,
                            "repaired_verify_result": repaired_verify,
                            "corrupt_prompt_sha256": corrupt_sha256,
                            "truncated_prompt_sha256": truncated_sha256,
                            "repaired_prompt_sha256": hashlib.sha256(
                                prompt.read_bytes()
                            ).hexdigest(),
                            "repaired_prompt_mode": stat.S_IMODE(prompt.stat().st_mode),
                            "authoritative_prompt_sha256": hashlib.sha256(
                                authoritative_prompt
                            ).hexdigest(),
                            "inventory": first_inventory,
                            "inventory_sha256": first_inventory_hash,
                            "config_sha256": first_config_hash,
                        }
                    )

        for scope in ("project", "user"):
            for agent in ("claude", "codex"):
                for unsafe_kind in ("symlink", "directory"):
                    cell = root / f"unsafe-{scope}-{agent}-{unsafe_kind}"
                    home = cell / "home"
                    workspace = cell / "workspace"
                    unrest_home = cell / "unrest-home"
                    home.mkdir(parents=True)
                    workspace.mkdir()
                    unrest_home.mkdir()
                    boundary = workspace if scope == "project" else home
                    arguments = ["init", "--agent", agent]
                    if scope == "project":
                        arguments.extend(["--workspace-dir", str(workspace)])
                    else:
                        arguments.extend(["--scope", "user"])
                    env = {
                        "HOME": str(home),
                        "PATH": os.environ.get("PATH", ""),
                        **(
                            {"PYTHONPATH": os.environ["PYTHONPATH"]}
                            if os.environ.get("PYTHONPATH")
                            else {}
                        ),
                        "PYTHONUTF8": "1",
                        "UNREST_HOME": str(unrest_home),
                    }
                    baseline = _run(resolved_command, arguments, workspace, env)
                    if baseline["exit_code"] != 0:
                        raise RuntimeError(f"unsafe-control baseline failed: {baseline}")
                    prompt = boundary / f".{agent}" / "orchestrator_prompt.md"
                    prompt.unlink()
                    outside = cell / "outside-prompt.md"
                    outside.write_bytes(b"outside sentinel\n")
                    if unsafe_kind == "symlink":
                        prompt.symlink_to(outside)
                    else:
                        prompt.mkdir()
                    before = _inventory(cell)
                    result = _run(resolved_command, arguments, workspace, env)
                    after = _inventory(cell)
                    if result["exit_code"] == 0 or after != before:
                        raise RuntimeError(
                            f"unsafe prompt target was accepted or mutated: "
                            f"{scope}/{agent}/{unsafe_kind}"
                        )
                    unsafe_controls.append(
                        {
                            "scope": scope,
                            "agent": agent,
                            "unsafe_kind": unsafe_kind,
                            "result": result,
                            "inventory_sha256": _inventory_hash(before),
                        }
                    )

        invalid_home = root / "invalid" / "home"
        invalid_workspace = root / "invalid" / "workspace"
        invalid_home.mkdir(parents=True)
        invalid_workspace.mkdir()
        invalid_env = {
            "HOME": str(invalid_home),
            "PATH": os.environ.get("PATH", ""),
            **(
                {"PYTHONPATH": os.environ["PYTHONPATH"]}
                if os.environ.get("PYTHONPATH")
                else {}
            ),
            "PYTHONUTF8": "1",
            "UNREST_HOME": str(root / "invalid" / "unrest-home"),
        }
        for arguments in (
            ["init", "--agent", "unknown"],
            ["init", "--scope", "user", "--workspace-dir", str(invalid_workspace)],
        ):
            first = _run(resolved_command, arguments, invalid_workspace, invalid_env)
            second = _run(resolved_command, arguments, invalid_workspace, invalid_env)
            _assert_same_result(first, second)
            if first["exit_code"] == 0 or "Error:" not in str(first["stderr"]):
                raise RuntimeError(f"invalid init was not an explicit error: {first}")
            invalid_inputs.append({"arguments": arguments, "result": first})

    return {
        "console_script": str(resolved_command),
        "cells": cells,
        "invalid_inputs": invalid_inputs,
        "unsafe_controls": unsafe_controls,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("console_script", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = check_init_output_stability(arguments.console_script)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.write_text(rendered, encoding="utf-8")
        print(
            f"init output stability verified: {len(result['cells'])} cells; "
            f"evidence={arguments.output}"
        )


if __name__ == "__main__":
    main()
