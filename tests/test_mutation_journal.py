"""Crash-boundary and async-concurrency tests for public mutation custody."""
from __future__ import annotations

import asyncio
import fcntl
import json
from pathlib import Path
import subprocess
import sys

import pytest

from unrest_harness.mutation_journal import DurableMutationJournal, MutationJournalError


class _FaultOnce:
    def __init__(self, boundary: str) -> None:
        self.boundary = boundary
        self.triggered = False

    def __call__(self, boundary: str) -> None:
        if boundary == self.boundary and not self.triggered:
            self.triggered = True
            raise RuntimeError("injected crash")


def _execute(journal: DurableMutationJournal, effect, reconcile=lambda _: None):
    return journal.execute(
        operation="integrate_workspace",
        resource_key="lease:test",
        idempotency_key="idempotency:test",
        request={"idempotency_key": "idempotency:test", "workspace_id": "lease:test"},
        effect=effect,
        reconcile=reconcile,
    )


def _record(root: Path) -> dict[str, object]:
    paths = list((root / ".unrest" / "foundation" / "public-mutations").glob("*.json"))
    assert len(paths) == 1
    return json.loads(paths[0].read_text())


def _record_path(root: Path) -> Path:
    paths = list((root / ".unrest" / "foundation" / "public-mutations").glob("*.json"))
    assert len(paths) == 1
    return paths[0]


def test_prepared_crash_is_safe_to_stage_and_apply_once(tmp_path: Path) -> None:
    fault = _FaultOnce("prepared")
    with pytest.raises(RuntimeError, match="injected crash"):
        _execute(
            DurableMutationJournal(tmp_path, fault=fault),
            lambda _: {"outcome": "applied"},
        )
    assert _record(tmp_path)["state"] == "prepared"
    calls = 0

    def effect(_: str):
        nonlocal calls
        calls += 1
        return {"outcome": "applied"}

    assert _execute(DurableMutationJournal(tmp_path), effect) == {"outcome": "applied"}
    assert calls == 1
    assert _record(tmp_path)["state"] == "completed"


def test_stage_is_replayed_safely_after_crash_before_claim(tmp_path: Path) -> None:
    staged: set[str] = set()

    def stage(fingerprint: str) -> None:
        staged.add(fingerprint)

    journal = DurableMutationJournal(tmp_path, fault=_FaultOnce("staged"))
    with pytest.raises(RuntimeError, match="injected crash"):
        journal.execute(
            operation="integrate_workspace",
            resource_key="lease:test",
            idempotency_key="idempotency:test",
            request={"workspace_id": "lease:test"},
            stage=stage,
            effect=lambda _: {"outcome": "applied"},
            reconcile=lambda _: None,
        )
    assert _record(tmp_path)["state"] == "staged"
    result = DurableMutationJournal(tmp_path).execute(
        operation="integrate_workspace",
        resource_key="lease:test",
        idempotency_key="idempotency:test",
        request={"workspace_id": "lease:test"},
        stage=stage,
        effect=lambda _: {"outcome": "applied"},
        reconcile=lambda _: None,
    )
    assert result == {"outcome": "applied"}
    assert len(staged) == 1


def test_effect_crash_reconciles_without_reexecution(tmp_path: Path) -> None:
    external = tmp_path / "external-effect.json"

    def effect(_: str):
        external.write_text('{"outcome":"applied"}\n')
        return {"outcome": "applied"}

    with pytest.raises(RuntimeError, match="injected crash"):
        _execute(
            DurableMutationJournal(tmp_path, fault=_FaultOnce("effect_applied")),
            effect,
        )
    assert _record(tmp_path)["state"] == "applying"

    def forbidden(_: str):
        raise AssertionError("effect was blindly re-executed")

    result = _execute(
        DurableMutationJournal(tmp_path),
        forbidden,
        reconcile=lambda _: json.loads(external.read_text()),
    )
    assert result == {"outcome": "applied"}
    assert _record(tmp_path)["state"] == "completed"


def test_effect_complete_crash_finishes_without_effect_or_reconcile(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="injected crash"):
        _execute(
            DurableMutationJournal(tmp_path, fault=_FaultOnce("effect_complete")),
            lambda _: {"outcome": "applied"},
        )
    assert _record(tmp_path)["state"] == "effect_complete"
    result = _execute(
        DurableMutationJournal(tmp_path),
        lambda _: pytest.fail("effect repeated"),
        reconcile=lambda _: pytest.fail("completed effect reconciled"),
    )
    assert result == {"outcome": "applied"}
    assert _record(tmp_path)["state"] == "completed"


def test_live_foreign_owner_is_busy_and_record_is_unchanged(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="injected crash"):
        _execute(
            DurableMutationJournal(tmp_path, fault=_FaultOnce("effect_applied")),
            lambda _: {"outcome": "applied"},
        )
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        path = _record_path(tmp_path)
        record = _record(tmp_path)
        record["owner_pid"] = child.pid
        path.write_text(
            json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        before = path.read_bytes()
        reconciled = False

        def reconcile(_: str):
            nonlocal reconciled
            reconciled = True
            return {"outcome": "applied"}

        with pytest.raises(MutationJournalError, match="busy"):
            _execute(DurableMutationJournal(tmp_path), pytest.fail, reconcile=reconcile)
        assert not reconciled
        assert path.read_bytes() == before
    finally:
        child.terminate()
        child.wait(timeout=5)


@pytest.mark.asyncio
async def test_async_effect_holds_no_blocking_flock_and_same_process_waits(
    tmp_path: Path,
) -> None:
    journal = DurableMutationJournal(tmp_path)
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def effect(_: str):
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return {"outcome": "applied"}

    async def run():
        return await journal.execute_async(
            operation="evaluate_candidate",
            resource_key="campaign:test\0candidate:test",
            idempotency_key="evaluation:test",
            request={"campaign_id": "campaign:test", "candidate_id": "candidate:test"},
            effect=effect,
            reconcile=lambda _: None,
        )

    first = asyncio.create_task(run())
    await entered.wait()
    lock_paths = list(
        (tmp_path / ".unrest-runtime" / "foundation" / "public-mutations").glob("*.lock")
    )
    assert len(lock_paths) == 1
    with lock_paths[0].open("a+b") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    second = asyncio.create_task(run())
    await asyncio.sleep(0)
    assert not second.done()
    release.set()
    assert await first == {"outcome": "applied"}
    assert await second == {"outcome": "applied"}
    assert calls == 1
