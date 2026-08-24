from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import sys
import time

import pytest

from unrest_harness.run_control import RUN_OPERATIONS, RunControl, RunControlError
from unrest_harness.foundation_store import CustodyActor


_EXECUTOR_SOURCE = '''
from pathlib import Path
import os
import subprocess
import sys
import time

def execute(operation, arguments, context):
    counter = Path.cwd() / "effect-count.log"
    descriptor = os.open(counter, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, (operation + "\\n").encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    mode = arguments.get("brief", "success")
    if mode == "slow":
        while True:
            time.sleep(0.05)
    if mode == "crash":
        os._exit(17)
    if mode == "descendant":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.35)"])
        context.register_descendant(child.pid)
    project_id = arguments.get("project_id") or "created-project"
    return {
        "dag": None,
        "harnessRoot": str(Path.cwd() / ".unrest"),
        "projectId": project_id,
        "projectRoot": str(Path.cwd()),
        "state": {"state": "done"},
    }
'''


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "executor_fixture.py").write_text(_EXECUTOR_SOURCE, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop("executor_fixture", None)
    importlib.invalidate_caches()
    return tmp_path


def _control(
    project: Path,
    *,
    owner_id: str | None = None,
    recover: bool = True,
) -> RunControl:
    return RunControl(
        project,
        executor_ref="executor_fixture:execute",
        owner_id=owner_id,
        recover=recover,
    )


def _start_args(project: Path, mode: str = "success") -> dict[str, object]:
    workspace = project / "workspace"
    workspace.mkdir(exist_ok=True)
    return {"brief": mode, "workspace_dir": str(workspace)}


def _wait_for_state(
    control: RunControl,
    run_id: str,
    states: set[str],
    *,
    timeout: float = 5,
):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        summary = control.inspect_run(run_id)
        if summary.state in states:
            return summary
        time.sleep(0.01)
    raise AssertionError(f"run did not reach {states}: {control.inspect_run(run_id)}")


def test_exact_six_operations_and_closed_argument_schemas(project: Path) -> None:
    assert RUN_OPERATIONS == {
        "abort_project",
        "advance_project",
        "decide_attention",
        "end_mission",
        "start_project",
        "submit_plan",
    }
    control = _control(project)
    with pytest.raises(RunControlError) as unknown:
        control.submit_run("inspect_run", {}, "idem:unknown")
    assert unknown.value.code == "invalid_argument"
    with pytest.raises(RunControlError) as extra:
        control.submit_run("start_project", {**_start_args(project), "extra": "private"}, "idem:extra")
    assert extra.value.as_envelope() == {
        "error": {
            "code": "invalid_argument",
            "message": "arguments do not match the operation schema",
        }
    }
    assert "private" not in str(extra.value)


def test_admission_returns_quickly_and_terminal_run_has_identity_receipt_and_custody(
    project: Path,
) -> None:
    control = _control(project)
    started = time.monotonic()
    queued = control.submit_run("start_project", _start_args(project), "idem:success")
    elapsed = time.monotonic() - started
    assert elapsed < 1
    assert queued.state == "queued"
    terminal = control.attach_run(queued.run_id, timeout_seconds=5)
    assert terminal.state == "succeeded"
    assert terminal.result is not None and terminal.result["projectId"] == "created-project"
    assert terminal.receipt_id is not None
    token = queued.run_id.removeprefix("run:")
    request = json.loads((project / f".unrest/runs/{token}/request.json").read_text())
    assert request["run_identity_digest"].startswith("sha256:")
    assert request["control_identity_digest"].startswith("sha256:")
    receipt_files = list((project / ".unrest/foundation/receipts/run_receipt.v1").glob("*.json"))
    assert len(receipt_files) == 1
    assert control.foundation.has_local_custody("sha256:" + receipt_files[0].stem)
    assert not list((project / ".unrest/runs").glob("**/*.worker.json"))
    assert (project / ".unrest-runtime/runs").is_dir()


def test_two_servers_share_idempotency_and_reject_competing_resource(project: Path) -> None:
    first = _control(project, owner_id="server:first")
    second = _control(project, owner_id="server:second")
    run = first.submit_run("start_project", _start_args(project, "slow"), "idem:shared")
    _wait_for_state(first, run.run_id, {"running"})
    duplicate = second.submit_run("start_project", _start_args(project, "slow"), "idem:shared")
    assert duplicate.run_id == run.run_id
    assert (project / "effect-count.log").read_text().splitlines() == ["start_project"]
    with pytest.raises(RunControlError) as busy:
        second.submit_run("start_project", _start_args(project, "success"), "idem:competitor")
    assert busy.value.code == "busy"
    with pytest.raises(RunControlError) as conflict:
        second.submit_run(
            "start_project",
            {**_start_args(project, "slow"), "worker_model": "different"},
            "idem:shared",
        )
    assert conflict.value.code == "conflict"
    second.cancel_run(run.run_id, "test cancellation", "cancel:shared")
    assert second.attach_run(run.run_id, timeout_seconds=5).state == "cancelled"


def test_cancel_is_idempotent_records_boundaries_and_releases_resource(project: Path) -> None:
    control = _control(project)
    run = control.submit_run("start_project", _start_args(project, "slow"), "idem:cancel")
    _wait_for_state(control, run.run_id, {"running"})
    token = run.run_id.removeprefix("run:")
    cursor_path = project / ".unrest-runtime/runs" / (
        __import__("hashlib").sha256(run.run_id.encode()).hexdigest() + ".worker.json"
    )
    assert json.loads(cursor_path.read_text())["run_id"] == run.run_id
    first = control.cancel_run(run.run_id, "operator requested", "cancel:one")
    assert first.state in {"cancel_requested", "draining", "cancelled"}
    terminal = control.attach_run(run.run_id, timeout_seconds=5)
    assert terminal.state == "cancelled"
    assert control.cancel_run(run.run_id, "operator requested", "cancel:one") == terminal
    successor = control.submit_run("start_project", _start_args(project), "idem:after-cancel")
    assert control.attach_run(successor.run_id, timeout_seconds=5).state == "succeeded"
    events = [
        json.loads(path.read_text())["state"]
        for path in sorted((project / f".unrest/runs/{token}/events").glob("*.json"))
    ]
    assert events[0] == "queued"
    assert "running" in events
    assert "cancel_requested" in events
    assert "draining" in events
    assert events[-1] == "cancelled"


def test_cancel_before_dispatch_never_invokes_executor(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = _control(project, recover=False)
    monkeypatch.setattr(control, "_spawn", lambda request: None)
    run = control.submit_run("start_project", _start_args(project), "idem:cancel-queued")
    assert run.state == "queued"
    cancelled = control.cancel_run(run.run_id, "cancel before dispatch", "cancel:queued")
    assert cancelled.state == "cancelled"
    assert not (project / "effect-count.log").exists()


def test_restart_reattaches_live_worker_and_never_repeats_effect(project: Path) -> None:
    original = _control(project, owner_id="server:original")
    run = original.submit_run("start_project", _start_args(project, "descendant"), "idem:restart")
    _wait_for_state(original, run.run_id, {"running"})
    restarted = _control(project, owner_id="server:restarted")
    assert restarted.inspect_run(run.run_id).run_id == run.run_id
    with pytest.raises(RunControlError) as busy:
        restarted.submit_run("start_project", _start_args(project), "idem:during-restart")
    assert busy.value.code == "busy"
    terminal = restarted.attach_run(run.run_id, timeout_seconds=5)
    assert terminal.state == "succeeded"
    assert (project / "effect-count.log").read_text().splitlines() == ["start_project"]


def test_orphan_becomes_attention_and_retry_does_not_replay_old_effect(project: Path) -> None:
    original = _control(project, owner_id="server:original")
    run = original.submit_run("start_project", _start_args(project, "crash"), "idem:crash")
    _wait_for_state(original, run.run_id, {"running"})
    cursor_name = __import__("hashlib").sha256(run.run_id.encode()).hexdigest() + ".worker.json"
    cursor_path = project / ".unrest-runtime/runs" / cursor_name
    assert json.loads(cursor_path.read_text())["run_id"] == run.run_id
    time.sleep(0.1)
    cursor_path.unlink(missing_ok=True)
    restarted = _control(project, owner_id="server:restarted")
    attention = restarted.inspect_run(run.run_id)
    assert attention.state == "attention"
    assert attention.error == {
        "error": {
            "code": "internal_error",
            "message": "worker ownership could not be recovered",
        }
    }
    assert (project / "effect-count.log").read_text().splitlines() == ["start_project"]
    retry = restarted.submit_run("start_project", _start_args(project), "idem:retry")
    assert restarted.attach_run(retry.run_id, timeout_seconds=5).state == "succeeded"
    assert (project / "effect-count.log").read_text().splitlines() == [
        "start_project",
        "start_project",
    ]


def test_recovery_finishes_durable_effect_without_dispatch(project: Path) -> None:
    control = _control(project, recover=False)
    run = control.submit_run("start_project", _start_args(project, "slow"), "idem:phase")
    _wait_for_state(control, run.run_id, {"running"})
    cursor_name = __import__("hashlib").sha256(run.run_id.encode()).hexdigest() + ".worker.json"
    cursor_path = project / ".unrest-runtime/runs" / cursor_name
    cursor = json.loads(cursor_path.read_text())
    os.killpg(cursor["pgid"], 9)
    time.sleep(0.1)
    cursor_path.unlink(missing_ok=True)
    result = {
        "dag": None,
        "harnessRoot": str(project / ".unrest"),
        "projectId": "recovered",
        "projectRoot": str(project),
        "state": {"state": "done"},
    }
    control.worker_effect_complete(run.run_id, result)
    restarted = _control(project)
    terminal = restarted.inspect_run(run.run_id)
    assert terminal.state == "succeeded"
    assert terminal.result == result
    assert (project / "effect-count.log").read_text().splitlines() == ["start_project"]


def test_receipt_append_recovery_is_byte_idempotent(project: Path) -> None:
    control = _control(project, recover=False)
    run = control.submit_run("start_project", _start_args(project, "slow"), "idem:receipt-crash")
    _wait_for_state(control, run.run_id, {"running"})
    cursor_name = __import__("hashlib").sha256(run.run_id.encode()).hexdigest() + ".worker.json"
    cursor_path = project / ".unrest-runtime/runs" / cursor_name
    cursor = json.loads(cursor_path.read_text())
    os.killpg(cursor["pgid"], 9)
    time.sleep(0.1)
    cursor_path.unlink(missing_ok=True)
    result = {
        "dag": None,
        "harnessRoot": str(project / ".unrest"),
        "projectId": "receipt-recovery",
        "projectRoot": str(project),
        "state": {"state": "done"},
    }
    control.worker_effect_complete(run.run_id, result)
    control.worker_report_complete(run.run_id)
    request = control._load_request(run.run_id)
    receipt = control._construct_run_receipt(request, "succeeded")
    control.foundation.append_receipt(
        receipt,
        custodian=CustodyActor(
            actor_id="provider_configuration:run-lifecycle-authority",
            authority_class="run_lifecycle_authority",
            decision_ref="decision:issue:run_receipt.v1",
        ),
    )
    custody_before = control.foundation.verify_custody_chain()
    restarted = _control(project)
    assert restarted.inspect_run(run.run_id).state == "succeeded"
    assert restarted.foundation.verify_custody_chain() == custody_before


def test_hash_chain_tamper_fails_closed_without_leaking_record(project: Path) -> None:
    control = _control(project)
    run = control.submit_run("start_project", _start_args(project), "idem:tamper")
    control.attach_run(run.run_id, timeout_seconds=5)
    token = run.run_id.removeprefix("run:")
    event_path = sorted((project / f".unrest/runs/{token}/events").glob("*.json"))[0]
    event_path.write_text('{"brief":"TOP-SECRET"}\n', encoding="utf-8")
    with pytest.raises(RunControlError) as caught:
        control.inspect_run(run.run_id)
    assert caught.value.code == "integrity_error"
    assert "TOP-SECRET" not in str(caught.value)
