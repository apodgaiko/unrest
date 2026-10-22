"""Small pure-compilation reproduction; never launch Git or a test backend."""

from __future__ import annotations

import __future__
import hashlib
from pathlib import Path

import pytest
from finite import git_routes

SUPPORT = Path(__file__).parent
ROOT = SUPPORT.parent.parent
CARRIERS = tuple(
    SUPPORT / "finite" / n
    for n in (
        "binding_routes.py",
        "orders_git.py",
        "crash_route.py",
        "source_git.py",
        "cleanup_routes.py",
        "historical_git.py",
        "candidate_git.py",
    )
) + (ROOT / "src/unrest_harness/experimental_candidate.py",)


def test_repeated_original_git_carriers_compile_once_but_read_every_time():
    state = {}
    for _ in range(10):
        for path in CARRIERS:
            body = path.read_bytes()
            pin = hashlib.sha256(body).hexdigest()
            code = git_routes.current_code(path, pin, state, inherit=False)
            assert code == compile(body, str(path), "exec", dont_inherit=True)
    assert state["git_current_code_metrics"] == {"reads": 80, "compiles": 8}
    assert len(state["git_compiled_current_code"]) == 8


def test_cached_code_never_reuses_resolver_globals(tmp_path):
    path = tmp_path / "source.py"
    path.write_text("values = []\nvalues.append(1)\n")
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    state = {}
    first, second = {}, {}
    exec(git_routes.current_code(path, pin, state), first)
    first["values"].append("foreign")
    exec(git_routes.current_code(path, pin, state), second)
    assert first["values"] == [1, "foreign"] and second["values"] == [1]


@pytest.mark.parametrize(
    "change", ["bytes", "new-pin", "identity", "symlink", "hardlink", "missing"]
)
def test_cached_compilation_refuses_every_current_carrier_drift(tmp_path, change):
    path = tmp_path / "source.py"
    path.write_text("value = 1\n")
    state = {}
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    git_routes.current_code(path, pin, state)
    if change == "bytes":
        path.write_text("value = 2\n")
    elif change == "new-pin":
        path.write_text("value = 2\n")
        pin = hashlib.sha256(path.read_bytes()).hexdigest()
    elif change == "identity":
        other = tmp_path / "replacement"
        other.write_bytes(path.read_bytes())
        other.replace(path)
    elif change == "symlink":
        original = tmp_path / "original"
        path.rename(original)
        path.symlink_to(original)
    elif change == "hardlink":
        (tmp_path / "other").hardlink_to(path)
    else:
        path.unlink()
    with pytest.raises((OSError, RuntimeError)):
        git_routes.current_code(path, pin, state)


def test_compilation_flags_and_pure_code_identity_stay_distinct(tmp_path):
    path = tmp_path / "source.py"
    path.write_text("def value(x: int) -> int:\n    return x\n")
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    state = {}
    plain = git_routes.current_code(path, pin, state, inherit=False)
    inherited = git_routes.current_code(path, pin, state)
    expected = git_routes.current_code.__code__.co_flags & __future__.annotations.compiler_flag
    assert plain == compile(path.read_bytes(), str(path), "exec", dont_inherit=True)
    assert inherited == compile(
        path.read_bytes(), str(path), "exec", flags=expected, dont_inherit=True
    )
