from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
import traceback
from pathlib import Path

import pytest

from unrest_harness.acp_runner import (
    LaunchError,
    LaunchPlan,
    build_launch_plan,
    preflight_launch,
    spawn_launch,
)


def _executable(path: Path, *, target: Path | None = None) -> Path:
    if target is not None:
        path.symlink_to(target)
    else:
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o700)
    return path


def _plan(
    command: str,
    cwd: Path,
    *,
    path: str | None,
    extra: dict[str, str] | None = None,
) -> LaunchPlan:
    environment = dict(extra or {})
    if path is not None:
        environment["PATH"] = path
    return build_launch_plan(command, cwd=cwd, environment=environment)


def _category(plan: LaunchPlan) -> str:
    with pytest.raises(LaunchError) as caught:
        preflight_launch(plan)
    return caught.value.category


def test_plan_parses_once_and_is_deeply_immutable(tmp_path: Path) -> None:
    source = {"PATH": "tools", "TOKEN": "before"}
    plan = build_launch_plan(
        "adapter 'quoted argument' --flag",
        cwd=tmp_path,
        environment=source,
    )
    source["PATH"] = "mutated"
    source["TOKEN"] = "after"

    assert plan.argv == ("adapter", "quoted argument", "--flag")
    assert plan.cwd == str(tmp_path)
    assert plan.path == "tools"
    assert dict(plan.environment) == {"PATH": "tools", "TOKEN": "before"}
    with pytest.raises(TypeError):
        plan.environment["PATH"] = "nope"  # type: ignore[index]
    with pytest.raises((AttributeError, TypeError)):
        plan.argv = ("changed",)  # type: ignore[misc]


@pytest.mark.parametrize("command", ["", " \t\n", "adapter 'unterminated", "''"])
def test_invalid_command_families_are_one_category(
    command: str, tmp_path: Path
) -> None:
    with pytest.raises(LaunchError) as caught:
        build_launch_plan(command, cwd=tmp_path, environment={})
    assert caught.value.category == "invalid_command"


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("missing", "missing"),
        ("directory", "directory"),
        ("non_executable", "not_executable"),
    ],
)
@pytest.mark.parametrize("direct", [False, True], ids=["bare", "direct"])
def test_local_rejection_categories(
    tmp_path: Path, fixture: str, expected: str, direct: bool
) -> None:
    candidate = tmp_path / "adapter"
    if fixture == "directory":
        candidate.mkdir()
        candidate.chmod(0o700)
    elif fixture == "non_executable":
        candidate.write_text("not executable", encoding="utf-8")
        candidate.chmod(0o600)
    argv0 = "./adapter" if direct else "adapter"
    path = None if direct else str(tmp_path)
    assert _category(_plan(argv0, tmp_path, path=path)) == expected


@pytest.mark.parametrize("obstruction", ["directory", "non_executable"])
def test_bare_path_skips_obstruction_for_later_executable(
    tmp_path: Path, obstruction: str
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    blocked = first / "adapter"
    if obstruction == "directory":
        blocked.mkdir()
    else:
        blocked.write_text("blocked", encoding="utf-8")
        blocked.chmod(0o600)
    _executable(second / "adapter")
    plan = _plan(
        "adapter",
        tmp_path,
        path=os.pathsep.join((str(first), str(second))),
    )
    preflight_launch(plan)


@pytest.mark.parametrize("entry", ["tools", ""])
@pytest.mark.asyncio
async def test_relative_and_empty_path_entries_use_launch_cwd(
    tmp_path: Path, entry: str
) -> None:
    directory = tmp_path / entry if entry else tmp_path
    directory.mkdir(exist_ok=True)
    _executable(directory / "adapter")
    plan = _plan("adapter", tmp_path, path=entry)
    preflight_launch(plan)
    process = await spawn_launch(
        plan,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=64 * 1024,
    )
    _, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode(errors="replace")


def test_absent_path_has_no_host_or_default_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = tmp_path / "host"
    host.mkdir()
    _executable(host / "adapter")
    monkeypatch.setenv("PATH", f"{host}{os.pathsep}{os.defpath}")

    plan = _plan("adapter", tmp_path, path=None)
    assert plan.path is None
    assert _category(plan) == "missing"


def test_bare_path_order_ignores_host_decoy(tmp_path: Path) -> None:
    selected = tmp_path / "selected"
    decoy = tmp_path / "decoy"
    selected.mkdir()
    decoy.mkdir()
    _executable(selected / "adapter")
    _executable(decoy / "adapter")
    plan = _plan("adapter", tmp_path, path=str(selected))
    preflight_launch(plan)
    assert str(decoy) not in plan.path


@pytest.mark.parametrize("argv0", ["./adapter", "nested/../adapter"])
def test_direct_relative_launcher_uses_launch_cwd(
    tmp_path: Path, argv0: str
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    _executable(tmp_path / "adapter")
    preflight_launch(_plan(argv0, tmp_path, path="/does/not/matter"))


def test_direct_absolute_launcher_ignores_path(tmp_path: Path) -> None:
    launcher = _executable(tmp_path / "adapter")
    preflight_launch(_plan(str(launcher), tmp_path, path="/does/not/exist"))


def test_direct_tilde_is_literal_and_not_expanded(tmp_path: Path) -> None:
    home_launcher = tmp_path / "home" / "adapter"
    home_launcher.parent.mkdir()
    _executable(home_launcher)
    plan = _plan("~/adapter", tmp_path, path=str(home_launcher.parent))
    assert _category(plan) == "missing"


@pytest.mark.asyncio
@pytest.mark.parametrize("direct_form", ["relative", "absolute"])
async def test_real_direct_launch_preserves_original_argv0(
    tmp_path: Path, direct_form: str
) -> None:
    launcher = tmp_path / "adapter"
    launcher.write_text('#!/bin/sh\nprintf "%s" "$0" > "$1"\n', encoding="utf-8")
    launcher.chmod(0o700)
    output = tmp_path / "argv0.txt"
    argv0 = "./adapter" if direct_form == "relative" else str(launcher)
    plan = _plan(
        f"{argv0} {output}",
        tmp_path,
        path=str(tmp_path / "decoy"),
    )
    preflight_launch(plan)
    process = await spawn_launch(
        plan,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=64 * 1024,
    )
    _, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode(errors="replace")
    assert output.read_text(encoding="utf-8") == argv0
    assert plan.argv[0] == argv0


@pytest.mark.asyncio
async def test_real_bare_launch_uses_later_valid_path_candidate(
    tmp_path: Path,
) -> None:
    blocked_dir = tmp_path / "blocked"
    selected_dir = tmp_path / "selected"
    blocked_dir.mkdir()
    selected_dir.mkdir()
    (blocked_dir / "adapter").mkdir()
    output = tmp_path / "selected.txt"
    launcher = selected_dir / "adapter"
    launcher.write_text('#!/bin/sh\nprintf selected > "$1"\n', encoding="utf-8")
    launcher.chmod(0o700)
    plan = _plan(
        f"adapter {output}",
        tmp_path,
        path=os.pathsep.join((str(blocked_dir), str(selected_dir))),
    )
    preflight_launch(plan)
    process = await spawn_launch(
        plan,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=64 * 1024,
    )
    _, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode(errors="replace")
    assert output.read_text(encoding="utf-8") == "selected"


def test_diagnostics_are_deterministic_bounded_and_value_safe(tmp_path: Path) -> None:
    canary = "CANARY-" + secrets.token_hex(24)
    command = f"{canary}/missing --token {canary}"
    rendered: list[str] = []
    for _ in range(2):
        try:
            plan = build_launch_plan(
                command,
                cwd=tmp_path / canary,
                environment={"PATH": canary, "SECRET": canary},
            )
            preflight_launch(plan)
        except LaunchError as exc:
            assert exc.__cause__ is None
            assert exc.__context__ is None
            rendered.extend((str(exc), repr(exc), traceback.format_exc()))
    assert rendered[0] == rendered[3]
    assert all(len(value.encode("utf-8")) <= 160 for value in rendered[0::3])
    assert all(canary not in value for value in rendered)


@pytest.mark.asyncio
async def test_real_spawn_preserves_exact_plan_fields(tmp_path: Path) -> None:
    _executable(tmp_path / "adapter", target=Path(sys.executable))
    output = tmp_path / "capture.json"
    code = (
        "import json,os,sys,pathlib;"
        "pathlib.Path(sys.argv[1]).write_text(json.dumps({"
        "'argv':sys.argv[2:],'cwd':os.getcwd(),'path':os.environ.get('PATH'),"
        "'marker':os.environ.get('MARKER')}))"
    )
    plan = _plan(
        f"adapter -c {json.dumps(code)} {output} 'quoted argument'",
        tmp_path,
        path=str(tmp_path),
        extra={"MARKER": "exact"},
    )
    preflight_launch(plan)
    process = await spawn_launch(
        plan,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=64 * 1024,
    )
    _, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode(errors="replace")
    captured = json.loads(output.read_text(encoding="utf-8"))
    assert captured == {
        "argv": ["quoted argument"],
        "cwd": str(tmp_path),
        "marker": "exact",
        "path": str(tmp_path),
    }
    assert plan.argv[0] == "adapter"


@pytest.mark.asyncio
async def test_direct_plan_copies_mutable_inputs_before_real_spawn(
    tmp_path: Path,
) -> None:
    selected = tmp_path / "selected"
    decoy = tmp_path / "decoy"
    selected.mkdir()
    decoy.mkdir()
    output = tmp_path / "selected.txt"
    for directory, marker in ((selected, "selected"), (decoy, "decoy")):
        launcher = directory / "adapter"
        launcher.write_text(
            f'#!/bin/sh\nprintf "{marker}" > "$1"\n',
            encoding="utf-8",
        )
        launcher.chmod(0o700)

    caller_argv = ["adapter", str(output)]
    caller_environment = {"PATH": str(selected), "MARKER": "before"}
    plan = LaunchPlan(
        argv=caller_argv,  # type: ignore[arg-type]
        cwd=str(tmp_path),
        environment=caller_environment,
        path=str(selected),
    )
    preflight_launch(plan)

    caller_argv[0] = "missing"
    caller_environment["PATH"] = str(decoy)
    caller_environment["MARKER"] = "after"

    assert plan.argv == ("adapter", str(output))
    assert plan.path == str(selected)
    assert dict(plan.environment) == {
        "PATH": str(selected),
        "MARKER": "before",
    }
    with pytest.raises(TypeError):
        plan.environment["PATH"] = str(decoy)  # type: ignore[index]

    process = await spawn_launch(
        plan,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=64 * 1024,
    )
    _, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode(errors="replace")
    assert output.read_text(encoding="utf-8") == "selected"


@pytest.mark.parametrize(
    ("argv", "cwd", "environment", "path"),
    [
        ([], "/launch", {}, None),
        ([""], "/launch", {}, None),
        ("adapter", "/launch", {}, None),
        (["adapter", 1], "/launch", {}, None),
        (["adapter"], Path("/launch"), {}, None),
        (["adapter"], "/launch", {1: "value"}, None),
        (["adapter"], "/launch", {"KEY": 1}, None),
        (
            ["adapter"],
            "/launch",
            {"PATH": "DIRECT-CONSTRUCTOR-CANARY"},
            "mismatch-DIRECT-CONSTRUCTOR-CANARY",
        ),
    ],
)
def test_direct_plan_rejects_invalid_shapes_value_safely(
    argv: object,
    cwd: object,
    environment: object,
    path: object,
) -> None:
    canary = "DIRECT-CONSTRUCTOR-CANARY"
    with pytest.raises(LaunchError) as caught:
        LaunchPlan(
            argv=argv,  # type: ignore[arg-type]
            cwd=cwd,  # type: ignore[arg-type]
            environment=environment,  # type: ignore[arg-type]
            path=path,  # type: ignore[arg-type]
        )
    error = caught.value
    assert error.category == "invalid_command"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert all(
        canary not in rendered
        for rendered in (
            str(error),
            repr(error),
            "".join(traceback.format_exception(error)),
        )
    )


def _unencodable_fs_string() -> str:
    value = "\ud800"
    try:
        os.fsencode(value)
    except UnicodeError:
        return value
    pytest.skip("host filesystem encoding accepts the unpaired surrogate")


@pytest.mark.parametrize(
    "field",
    ["argv0", "later_argv", "cwd", "env_key", "env_value", "path"],
)
@pytest.mark.parametrize("malformation", ["nul", "unencodable"])
def test_plan_rejects_every_malformed_os_bound_string_before_preflight(
    field: str,
    malformation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = "CANARY\0VALUE" if malformation == "nul" else _unencodable_fs_string()
    argv = ["adapter", "argument"]
    cwd = "/launch"
    environment = {"PATH": "/bin", "KEY": "value"}
    path = "/bin"
    if field == "argv0":
        argv[0] = malformed
    elif field == "later_argv":
        argv[1] = malformed
    elif field == "cwd":
        cwd = malformed
    elif field == "env_key":
        environment[malformed] = environment.pop("KEY")
    elif field == "env_value":
        environment["KEY"] = malformed
    else:
        environment["PATH"] = malformed
        path = malformed

    probed = False

    def forbidden_probe(candidate: Path) -> str | None:
        nonlocal probed
        probed = True
        raise AssertionError("filesystem probing must not be reached")

    monkeypatch.setattr(
        "unrest_harness.acp_runner._launch_candidate_category",
        forbidden_probe,
    )
    with pytest.raises(LaunchError) as caught:
        plan = LaunchPlan(
            argv=argv,  # type: ignore[arg-type]
            cwd=cwd,
            environment=environment,
            path=path,
        )
        preflight_launch(plan)

    error = caught.value
    assert error.category == "invalid_command"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "CANARY" not in str(error)
    assert probed is False


def test_plan_preserves_platform_surrogateescape_strings() -> None:
    surrogateescaped = os.fsdecode(b"\xff")
    if "\udc80" > surrogateescaped or surrogateescaped > "\udcff":
        pytest.skip("host filesystem encoding does not use surrogateescape here")

    plan = LaunchPlan(
        argv=("adapter", surrogateescaped),
        cwd="/launch",
        environment={"PATH": "/bin", "VALUE": surrogateescaped},
        path="/bin",
    )

    assert plan.argv[1] == surrogateescaped
    assert plan.environment["VALUE"] == surrogateescaped


@pytest.mark.parametrize("illegal_name", ["=", "CANARY=KEY", "=CANARY"])
def test_plan_rejects_environment_names_containing_equals_before_preflight(
    illegal_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probed = False

    def forbidden_probe(candidate: Path) -> str | None:
        nonlocal probed
        probed = True
        raise AssertionError("filesystem probing must not be reached")

    monkeypatch.setattr(
        "unrest_harness.acp_runner._launch_candidate_category",
        forbidden_probe,
    )
    with pytest.raises(LaunchError) as caught:
        plan = LaunchPlan(
            argv=("adapter",),
            cwd="/launch",
            environment={"PATH": "/bin", illegal_name: "CANARY-VALUE"},
            path="/bin",
        )
        preflight_launch(plan)

    error = caught.value
    assert error.category == "invalid_command"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "CANARY" not in str(error)
    assert probed is False


@pytest.mark.asyncio
async def test_plan_preserves_legal_empty_environment_name_and_equals_value(
    tmp_path: Path,
) -> None:
    plan = build_launch_plan(
        "/usr/bin/true",
        cwd=tmp_path,
        environment={"": "empty-name", "VALUE": "before=after"},
    )
    preflight_launch(plan)

    process = await spawn_launch(
        plan,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=64 * 1024,
    )

    assert await process.wait() == 0
    assert dict(plan.environment) == {"": "empty-name", "VALUE": "before=after"}


@pytest.mark.asyncio
async def test_spawn_does_not_mask_unrelated_programmer_value_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = build_launch_plan("/usr/bin/true", cwd=tmp_path, environment={})
    preflight_launch(plan)

    async def invalid_internal_spawn(*args, **kwargs):
        raise ValueError("invalid internal stream limit")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", invalid_internal_spawn)

    with pytest.raises(ValueError, match="invalid internal stream limit"):
        await spawn_launch(
            plan,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=0,
        )


@pytest.mark.asyncio
async def test_real_invalid_format_is_distinct_safe_startup_failure(
    tmp_path: Path,
) -> None:
    launcher = tmp_path / "invalid-format"
    launcher.write_bytes(b"this is executable but has no executable format\n")
    launcher.chmod(0o700)
    plan = _plan("./invalid-format", tmp_path, path=None)
    preflight_launch(plan)

    with pytest.raises(LaunchError) as caught:
        await spawn_launch(
            plan,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=64 * 1024,
        )
    error = caught.value
    assert error.category == "startup_failed"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "invalid-format" not in str(error)
    assert len(str(error).encode("utf-8")) <= 160
