"""Strict worker generation admission for RunControl.worker_start."""
from __future__ import annotations

from enum import IntEnum
import hashlib
import importlib
from pathlib import Path
import sys

import pytest

from unrest_harness.run_control import RunControl, RunControlError
from tests.test_run_control import _EXECUTOR_SOURCE, _start_args


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "executor_fixture.py").write_text(_EXECUTOR_SOURCE, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop("executor_fixture", None)
    importlib.invalidate_caches()
    return tmp_path


class _GenerationInt(int):
    pass


class _GenerationEnum(IntEnum):
    FIRST = 1


def _queued_run(project: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[RunControl, str]:
    control = RunControl(project, executor_ref="executor_fixture:execute", recover=False)
    # No worker is launched; the test drives worker_start directly.
    monkeypatch.setattr(control, "_spawn", lambda request: None)
    run = control.submit_run("start_project", _start_args(project), "idem:generation")
    assert control.inspect_run(run.run_id).state == "queued"
    return control, run.run_id


def _state_tree(project: Path) -> dict[str, str]:
    tree: dict[str, str] = {}
    for root in (project / ".unrest", project / ".unrest-runtime"):
        for path in sorted(root.rglob("*")):
            relative = str(path.relative_to(project))
            if path.is_symlink():
                tree[relative] = "link:" + str(path.readlink())
            elif path.is_dir():
                tree[relative] = "dir"
            else:
                tree[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return tree


def _assert_unmutated(
    control: RunControl, run_id: str, project: Path, before: dict[str, str]
) -> None:
    assert _state_tree(project) == before
    assert control.inspect_run(run_id).state == "queued"
    assert control._load_worker_cursor(run_id) is None
    assert not list((project / ".unrest-runtime/runs").glob("*.worker.json"))


@pytest.mark.parametrize(
    "generation",
    [
        True,
        False,
        1.0,
        "1",
        None,
        _GenerationInt(1),
        _GenerationEnum.FIRST,
        0,
        -1,
    ],
    ids=["true", "false", "float", "str", "none", "int-subclass", "int-enum", "zero", "negative"],
)
def test_worker_start_refuses_non_native_or_nonpositive_generation_before_mutation(
    project: Path, monkeypatch: pytest.MonkeyPatch, generation: object
) -> None:
    control, run_id = _queued_run(project, monkeypatch)
    before = _state_tree(project)
    with pytest.raises(RunControlError) as refused:
        control.worker_start(run_id, pid=12345, pgid=12345, generation=generation)  # type: ignore[arg-type]
    assert refused.value.code == "invalid_argument"
    _assert_unmutated(control, run_id, project, before)
    # The refusal leaves the admitted run startable by its real generation.
    assert control.worker_start(run_id, pid=12345, pgid=12345, generation=1)
    assert control.inspect_run(run_id).state == "running"
    cursor = control._load_worker_cursor(run_id)
    assert cursor is not None and type(cursor["generation"]) is int and cursor["generation"] == 1


def test_worker_start_mismatched_positive_generation_is_stale_without_mutation(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control, run_id = _queued_run(project, monkeypatch)
    before = _state_tree(project)
    with pytest.raises(RunControlError) as refused:
        control.worker_start(run_id, pid=12345, pgid=12345, generation=2)
    assert refused.value.code == "stale"
    _assert_unmutated(control, run_id, project, before)
