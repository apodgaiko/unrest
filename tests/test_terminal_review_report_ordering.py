"""Crash diagnostics survive a separate finalization failure."""
from __future__ import annotations

import multiprocessing
import time

import pytest

from tests.multiprocess_lifetime import SpawnResources

from unrest_harness import supervision as s
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import MockDispatcher
from unrest_harness.models import TerminalReviewHandoff
from unrest_harness.project_lock import project_access_guard
from unrest_harness.storage import ProjectStore
from tests.test_supervision_finalization import _hold_snapshot, _prepare


@pytest.mark.parametrize('failure', ['held_snapshot', 'path_fault', 'storage_fault'])
def test_crash_report_survives_finalization_refusal(tmp_path, monkeypatch, failure):
    with SpawnResources() as ownership:
        store, _, binding = _prepare(tmp_path, 'terminal_reviewer')
        owned = {}
        diagnostic = 'controlled original reviewer diagnostic'
        fault = OSError('supplemental finalization storage fault')

        class Reviewer:
            def review(self, project_id, mission_id, attempt):
                snapshot = s.load_snapshot(store, project_id, mission_id, attempt)
                owned.update(snapshot=snapshot, attempt=attempt)
                if failure == 'held_snapshot':
                    ctx = ownership.context(multiprocessing.get_context('spawn'))
                    pipe, child = ctx.Pipe()
                    proc = ctx.Process(target=_hold_snapshot, args=(
                        str(store.config.harness_home), snapshot.model_dump(), child))
                    proc.start()
                    child.close()
                    owned.update(proc=proc, pipe=pipe)
                    assert pipe.poll(10) and pipe.recv() == 'owned'
                elif failure == 'path_fault':
                    def refuse(*args, **kwargs):
                        raise s.SupervisionSnapshotError('supplemental snapshot path fault')
                    monkeypatch.setattr(s, '_snapshot_lock', refuse)
                else:
                    def refuse_write(*args, **kwargs):
                        raise fault
                    monkeypatch.setattr(s, 'atomic_write_json', refuse_write)
                owned['start'] = time.monotonic()
                raise RuntimeError(diagnostic)

        co = MissionCoordinator(store, binding.project_id, MockDispatcher(lambda request: None), Reviewer())
        try:
            expected = (s.SupervisionSteeringError if failure == 'held_snapshot'
                        else s.SupervisionSnapshotError if failure == 'path_fault' else OSError)
            with project_access_guard(store, binding.project_id), pytest.raises(expected) as caught:
                co.close_mission(binding.mission_id)
            if failure == 'held_snapshot':
                assert caught.value.code == 'project_busy'
                assert 4.9 <= time.monotonic() - owned['start'] < 7
                assert owned['proc'].is_alive()
            elif failure == 'storage_fault':
                assert caught.value is fault
            else:
                assert str(caught.value) == 'supplemental snapshot path fault'
            fresh = ProjectStore(store.config)
            assert fresh.load_state(binding.project_id).state == 'mission_running'
            assert not (fresh.mission_dir(binding.project_id, binding.mission_id) / 'closeout.md').exists()
            assert s.load_snapshot(fresh, binding.project_id, binding.mission_id,
                                   owned['attempt']) == owned['snapshot']
            with s._supervision_transaction(fresh, binding.project_id, binding.mission_id):
                pass
            expected_report = TerminalReviewHandoff(done=False, report=(
                'Terminal reviewer runtime failure; mission artifacts were '
                'preserved and closure can be retried after resolving this '
                f'attention item.\n\nError: {diagnostic}'))
            assert fresh.read_terminal_review(binding.project_id, binding.mission_id,
                                              owned['attempt']) == expected_report
            assert diagnostic in fresh.terminal_review_report_path(
                binding.project_id, binding.mission_id, owned['attempt']).read_text()
        finally:
            if 'proc' in owned:
                owned['pipe'].send('release')
                owned['proc'].join(10)
                if owned['proc'].is_alive():
                    owned['proc'].kill()
                    owned['proc'].join(10)
                assert owned['proc'].exitcode == 0
                owned['pipe'].close()


def test_recovered_stop_keeps_original_crash_report(tmp_path):
    from tests.test_supervision import STEERING_TARGETS, _request

    store, _, binding = _prepare(tmp_path, 'terminal_reviewer')
    attempts = []

    class Reviewer:
        def review(self, project_id, mission_id, attempt):
            attempts.append(attempt)
            snapshot = s.load_snapshot(store, project_id, mission_id, attempt)
            checkpoint = snapshot.model_copy(update={'checkpoint_sequence': 1,
                'phase': 'waiting_at_checkpoint', 'supervision_status': 'waiting'})
            bound = s.report_supervision_checkpoint(store, checkpoint,
                assigned_target_ids=STEERING_TARGETS, project_guard=False)

            def fault(label):
                if label == 'after_receipt_fsync:stop_requested':
                    raise RuntimeError('receipt interruption')
            with pytest.raises(RuntimeError, match='receipt interruption'):
                s.steer_attempt(store, _request(bound, 'stop_for_attention'),
                                project_guard=False, fault=fault)
            raise RuntimeError('original stopped reviewer crash')

    co = MissionCoordinator(store, binding.project_id, MockDispatcher(lambda request: None), Reviewer())
    with project_access_guard(store, binding.project_id):
        result = co.close_mission(binding.mission_id)
    assert result.detail == 'terminal_review_stop'
    fresh = ProjectStore(store.config)
    report = fresh.read_terminal_review(binding.project_id, binding.mission_id, attempts[0])
    assert not report.done
    assert report.report.endswith('Error: original stopped reviewer crash')
    assert 'stopped cooperatively' in fresh.load_attention(binding.project_id)[0].report
    assert not (fresh.mission_dir(binding.project_id, binding.mission_id) / 'closeout.md').exists()
