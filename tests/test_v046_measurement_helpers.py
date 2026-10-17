"""Ruler correctness without scored launches or provider access."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("startup_ruler", ROOT / "tools/measure_v046_startup.py")
assert SPEC and SPEC.loader
ruler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ruler)


def test_matrix_has_all_48_unique_cases():
    cases = ruler.case_matrix()
    assert len(cases) == len({c["id"] for c in cases}) == 48
    assert sum(c["load"] == "isolated" for c in cases) == 24
    assert sum(c["home"] == "held-out-populated" for c in cases) == 16


def test_nearest_rank_and_noise_floors():
    assert ruler.statistics_ms(list(range(1, 21))) == {
        "median": 10.5, "p95": 19, "min": 1, "max": 20, "mad": 5}
    rows = [dict(case_id=c["id"], status="ok", discovery_ms=100, first_call_ms=2)
            for c in ruler.case_matrix() if c["load"] == "isolated" for _ in range(10)]
    calibration = ruler.calibrate(rows)
    assert len(calibration) == 24
    for case in calibration.values():
        assert case["noise_ms"] == 5
        assert case["p95_budget_ms"] == 110
        assert case["first_call_tolerance_ms"] == 5
    rows[0]["status"] = "failed"
    with pytest.raises(ValueError, match="retain failures"):
        ruler.calibrate(rows)
    with pytest.raises(ValueError, match="24 isolated"):
        ruler.calibrate(rows[10:])


@pytest.mark.parametrize("values", [[], [-1], [float("nan")], [float("inf")]])
def test_invalid_latency_rejected(values):
    with pytest.raises(ValueError):
        ruler.statistics_ms(values)


def test_ledger_reserves_atomically_and_retains_crashed_reservations(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ruler.ledger_event(ledger, {"kind": "external", "source": "fixture", "launches": 2290})
    with pytest.raises(ValueError, match="already accounted"):
        ruler.ledger_event(ledger, {"kind": "external", "source": "fixture", "launches": 0})
    def reserve(_):
        try:
            return ruler.ledger_event(ledger, {"kind": "launch", "launches": 1})
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(reserve, range(16)))
    assert sum(result is not None for result in results) == 10
    events = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert sum(e["launches"] for e in events) == 2300
    assert [e["sequence"] for e in events] == list(range(1, 12))
    ruler.ledger_event(ledger, {"kind": "result", "launches": 0, "status": "failed"})
    with pytest.raises(ValueError, match="ceiling"):
        ruler.ledger_event(ledger, {"kind": "launch", "launches": 1})


def test_environment_has_no_inherited_mission_or_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("UNREST_NODE_ASSIGNMENT", "private")
    monkeypatch.setenv("UNREST_PROJECT_ID", "production")
    monkeypatch.setenv("OPENAI_API_KEY", "private")
    monkeypatch.setenv("PYTHONPATH", "foreign")
    env = ruler.environment(tmp_path, "validator")
    assert not {"UNREST_NODE_ASSIGNMENT", "UNREST_PROJECT_ID", "OPENAI_API_KEY",
                "PYTHONPATH"} & env.keys()
    assert env["UNREST_NODE_TYPE"] == "validate"
    assert env["HOME"] == str(tmp_path / "user")


def test_approval_and_fixture_bytes_fail_closed(tmp_path):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "state").write_text("synthetic")
    approval = tmp_path / "APPROVED.json"
    manifest = {"fixtures": {"held-out-populated": {
        "path": str(fixture), "files": ruler.inventory(fixture)}},
        "heldout_approval": str(approval), "heldout_approval_sha256": None}
    case = {"home": "held-out-populated"}
    with pytest.raises(ValueError, match="APPROVED"):
        ruler.approved_fixture(manifest, case)
    approval.write_text("reviewed")
    with pytest.raises(ValueError, match="identity"):
        ruler.approved_fixture(manifest, case)
    manifest["heldout_approval_sha256"] = ruler.digest(approval)
    assert ruler.approved_fixture(manifest, case) == fixture
    (fixture / "state").write_text("tampered")
    with pytest.raises(ValueError, match="fixture bytes"):
        ruler.approved_fixture(manifest, case)


def test_four_arm_simulation_uses_independent_terminal_counts(tmp_path):
    import subprocess
    import sys
    result = subprocess.run([
        sys.executable, str(ROOT / "tools/measure_v046_flow.py"),
        "--case-manifest", str(ROOT / "tests/fixtures/v046_measurement/flow-cases.json"),
        "--mode", "simulated", "--output", str(tmp_path / "flow.json"),
    ], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    data = json.loads((tmp_path / "flow.json").read_text())
    assert data["live_benefit"] == "unmeasured"
    assert {row["arm"] for row in data["samples"]} == {
        "barrier/fresh", "barrier/reuse", "streaming/fresh", "streaming/reuse"}
    assert all(row["oracle_ok"] and row["fresh_gate_completion"] is None
               for row in data["samples"])
    assert any(row["halt"] == "budget" for row in data["samples"])


@pytest.mark.parametrize("launches", [-1, 1.5, True])
def test_ledger_cannot_refund_or_forge_launch_counts(tmp_path, launches):
    with pytest.raises(ValueError, match="nonnegative integer"):
        ruler.ledger_event(tmp_path / "ledger", {"launches": launches})


def test_fixture_inventory_rejects_symlinks(tmp_path):
    (tmp_path / "link").symlink_to(ROOT / "pyproject.toml")
    with pytest.raises(ValueError, match="symlinks"):
        ruler.inventory(tmp_path)


def test_project_oracle_checks_targets_and_terminal_state(tmp_path):
    runtime = tmp_path / "projects" / "synthetic" / ".unrest-runtime"
    mission = runtime / "missions" / "mission-001"
    mission.mkdir(parents=True)
    (runtime / "state.json").write_text('{"state":"done"}')
    (mission / "task-state.json").write_text('{"tasks":{"w":{"status":"cleared"}}}')
    (mission / "contract-state.json").write_text('{"items":{"T":{"status":"passed"}}}')
    projects = [{"project_id": "synthetic", "targets": ["T"], "expected": {
        "state": "done", "tasks": {"w": "cleared"}, "contract": "passed"}}]
    ruler.verify_projects(tmp_path, projects)
    (mission / "contract-state.json").write_text('{"items":{}}')
    with pytest.raises(ValueError, match="oracle mismatch"):
        ruler.verify_projects(tmp_path, projects)


@pytest.mark.parametrize("message", [{"id": 1, "method": "initialize"},
                                     {"method": "notifications/initialized"}])
@pytest.mark.parametrize("blocked", ["drain", "read"])
def test_rpc_deadline_includes_drain_and_read(message, blocked):
    import asyncio
    from types import SimpleNamespace
    if blocked == "read" and "id" not in message:
        return  # Notifications have no response phase.
    async def stall():
        await asyncio.Event().wait()
    async def immediate():
        return None
    proc = SimpleNamespace(stdin=SimpleNamespace(write=lambda _: None,
                                                 drain=stall if blocked == "drain" else immediate),
                           stdout=SimpleNamespace(readline=stall))
    async def check():
        with pytest.raises(TimeoutError):
            await ruler.rpc(proc, message, timeout=.01)
    asyncio.run(check())


def test_discovery_notification_and_list_share_one_deadline(monkeypatch):
    import asyncio
    seen = []
    async def slow_rpc(proc, message):
        seen.append(message["method"])
        await asyncio.sleep(.02)
    monkeypatch.setattr(ruler, "rpc", slow_rpc)
    async def check():
        with pytest.raises(TimeoutError):
            await ruler.discover(None, timeout=.03)
    asyncio.run(check())
    assert seen == ["notifications/initialized", "tools/list"]


def test_drain_and_read_share_one_deadline():
    import asyncio
    from types import SimpleNamespace
    seen = []
    async def drain():
        await asyncio.sleep(.02)
    async def read():
        seen.append("read")
        await asyncio.sleep(.02)
        return b'{"id":1,"result":{}}\n'
    proc = SimpleNamespace(stdin=SimpleNamespace(write=lambda _: None, drain=drain),
                           stdout=SimpleNamespace(readline=read))
    async def check():
        with pytest.raises(TimeoutError):
            await ruler.rpc(proc, {"id": 1}, timeout=.03)
    asyncio.run(check())
    assert seen == ["read"]


@pytest.mark.parametrize("role", ruler.ROLES)
@pytest.mark.parametrize("fault", [None, "false_response", "shutdown_home", "shutdown_handoff", "cleanup_home"])
def test_real_measure_path_with_local_transport_controls(tmp_path, monkeypatch, role, fault):
    """No subprocess: run the actual measurement, preservation and ledger path."""
    import asyncio
    from types import SimpleNamespace
    root = tmp_path / "case"
    (root / "home").mkdir(parents=True)
    (root / "home" / "state").write_text("original")
    handoff = {"done": True}
    oracle = {"catalog": {"tools": []}, "tool": "probe", "arguments": {"project_id": "probe"},
              "state": "done", "handoff": None if role == "orchestrator" else handoff,
              "output": "handoff.json"}
    prepared = {"root": root, "oracle": oracle, "env": {},
                "before": ruler.inventory(root / "home")}
    async def wait():
        if fault == "shutdown_home":
            (root / "home" / "state").write_text("shutdown mutation")
        if fault == "shutdown_handoff" and role != "orchestrator":
            (root / "handoff.json").write_text('{}')
        return 0
    proc = SimpleNamespace(stdin=SimpleNamespace(close=lambda: None), wait=wait,
                           returncode=0, pid=123)
    async def spawn(*args, **kwargs):
        return proc
    async def rpc(proc, message, **kwargs):
        if message["method"] == "tools/list":
            return oracle["catalog"]
        if message["method"] == "tools/call":
            (root / "handoff.json").write_text(json.dumps(handoff))
            response = ({"projectId": "probe", "state": {"state": "done"}}
                        if role == "orchestrator" else {"recorded": True})
            if fault == "false_response":
                response = {"recorded": False, "projectId": "wrong", "state": {"state": "done"}}
            return {"structuredContent": response}
        return {}
    def no_group(pid, signal):
        if fault == "cleanup_home":
            if (root / "home" / "state").read_text() == "cleanup mutation":
                raise ProcessLookupError
            if signal:
                (root / "home" / "state").write_text("cleanup mutation")
            return
        raise ProcessLookupError
    monkeypatch.setattr(ruler.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(ruler, "rpc", rpc)
    monkeypatch.setattr(ruler.os, "killpg", no_group)
    case = {"id": "local-control", "role": role}
    row = asyncio.run(ruler.measure(Path("/unused"), case, {}, tmp_path / "ledger", prepared))
    failed = fault is not None and not (fault == "shutdown_handoff" and role == "orchestrator")
    assert row["status"] == ("failed" if failed else "ok")
    assert row["events_ns"]["first_call"] <= row["events_ns"]["exit"]
    if fault == "false_response":
        assert json.loads((root / "handoff.json").read_text()) == handoff
        assert row["error_code"] == "first call response differs from independent oracle"
    if fault in ("shutdown_home", "cleanup_home"):
        assert row["changed_fixture_paths"] == ["state"]
        assert row["post_exit_preserved"] is False
    assert json.loads((tmp_path / "ledger").read_text().splitlines()[-1])["status"] == row["status"]


def test_all_slow_fixture_preparations_finish_before_any_concurrent_spawn(tmp_path, monkeypatch):
    import argparse
    import asyncio
    import time
    prepared = []
    started = []
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"cases": ruler.case_matrix()}))
    def prepare(python, case, manifest, directory):
        assert not started
        time.sleep(.01)  # Represents synchronous materializer/copy/oracle work.
        prepared.append(case["id"])
        return {"root": directory}
    async def measure_batch(python, batch, manifest, ledger, diagnostic):
        assert len(prepared) == 4
        started.extend(case["id"] for case, _ in batch)
        await asyncio.sleep(.001)
        return [{"status": "ok"} for _ in batch]
    monkeypatch.setattr(ruler, "prepare", prepare)
    monkeypatch.setattr(ruler, "measure_batch", measure_batch)
    monkeypatch.setattr(ruler, "package_identity", lambda _: {})
    args = argparse.Namespace(case_manifest=manifest_path, diagnostic=True, python=Path('/unused'),
                              install="editable", load="concurrent-4", samples=4,
                              case="worker/empty/editable/concurrent-4", ledger=tmp_path / "ledger",
                              output=tmp_path / "output")
    assert asyncio.run(ruler.run(args)) == 0
    assert len(started) == 4
    assert not (tmp_path / "ledger").exists()


@pytest.mark.parametrize("actual", [False, None, 1, "true"])
def test_recorded_response_is_strict_boolean(actual):
    with pytest.raises(ValueError, match="response differs"):
        ruler.verify_response({"structuredContent": {"recorded": actual}}, {"handoff": {}})


def flow_module():
    spec = importlib.util.spec_from_file_location("flow_ruler", ROOT / "tools/measure_v046_flow.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("fault", ["transition", "candidate", "target", "authority", "session",
                                   "integration", "final_gate", "history", "turn_candidate", "terminal_authority"])
def test_independent_flow_oracle_rejects_semantic_mutation(fault):
    flow = flow_module()
    manifest = json.loads((ROOT / "tests/fixtures/v046_measurement/flow-cases.json").read_text())
    case = manifest["cases"][2]  # Straggler rotation; no simultaneous completions.
    orders = ()
    while True:
        try:
            row = flow.simulate(case, True, True, manifest["base"], orders)
            break
        except flow.MoreOrders as exc:
            orders += (exc.due,)
    assert flow.verify_trace(row, case, manifest)
    if fault == "transition":
        row["transitions"][0]["next_phase"] = "passed"
    if fault == "candidate":
        row["projection"]["lanes"][0]["candidate"] = 99
    if fault == "target":
        row["events"][0]["targets"] = ["VAL-FOREIGN"]
    if fault == "authority":
        row["transitions"][0]["leases"] = []
    if fault == "session":
        row["events"][0]["session"] = "foreign"
    if fault == "integration":
        row["projection"]["integration"].reverse()
    if fault == "final_gate":
        row["projection"]["final_gate"] = "passed"
    if fault == "history":
        row["projection"]["lanes"][0]["history"] = []
    if fault == "turn_candidate":
        row["projection"]["lanes"][0]["turns"][1]["candidate"] = 99
    if fault == "terminal_authority":
        row["terminal_authority"][0]["leases"] = ["still-authorized"]
    assert not flow.verify_trace(row, case, manifest)


@pytest.mark.parametrize("fault", ["bytes", "missing", "extra", "symlink"])
def test_independent_flow_fixture_oracle_rejects_bad_files(tmp_path, fault):
    import shutil
    flow = flow_module()
    manifest = json.loads((ROOT / "tests/fixtures/v046_measurement/flow-cases.json").read_text())
    shutil.copytree(ROOT / "tests/fixtures/v046_measurement/flow-files/final", tmp_path / "final")
    root = tmp_path / "final"
    flow.verify_fixture_files(root, manifest, "final")
    if fault == "bytes":
        (root / "lane_a.txt").write_text("wrong\n")
    if fault == "missing":
        (root / "lane_a.txt").unlink()
    if fault == "extra":
        (root / "foreign").write_text("unexpected")
    if fault == "symlink":
        (root / "lane_a.txt").unlink()
        (root / "lane_a.txt").symlink_to(root / "lane_b.txt")
    with pytest.raises(ValueError, match="independent oracle"):
        flow.verify_fixture_files(root, manifest, "final")


@pytest.mark.parametrize("fault", [None, "deadline", "verification", "artifact", "spawn",
                                   "shutdown", "close", "wait", "persistence"])
def test_batch_barriers_exclude_slow_work_from_peer_deadlines(tmp_path, monkeypatch, fault):
    import asyncio
    import time
    from types import SimpleNamespace

    batch, processes, observations = [], {}, {}
    for index in range(4):
        root = tmp_path / str(index)
        (root / "home").mkdir(parents=True)
        (root / "handoff.json").write_text('{"done": true}')
        batch.append(({"id": str(index), "role": "worker"}, {
            "root": root, "oracle": {"catalog": {"tools": []}, "tool": "probe",
                "arguments": {}, "handoff": {"done": True}, "output": "handoff.json"},
            "env": {}, "before": {}}))
    original_rpc, original_ledger = ruler.rpc, ruler.ledger_event
    original_verify, original_digest = ruler.verify_preservation, ruler.digest
    reservations, results = [], []

    def ledger(path, event):
        if event["kind"] == "launch":
            assert not processes
            reservations.append(event["case_id"])
        else:
            assert all(p.exited for p in processes.values())
            results.append(event["case_id"])
        time.sleep(.04)
        if fault == "persistence" and event["kind"] == "result":
            raise OSError("controlled persistence failure")
        return original_ledger(path, event)

    def verify(root, before, role):
        # Every reply or deadline has been observed before even the first scan.
        assert len(observations) == (3 if fault == "spawn" else 4)
        assert not any(p.closed for p in processes.values()) or all(
            p.exited for p in processes.values())
        time.sleep(.04)
        if fault == "verification" and root.name == "0":
            raise ValueError("controlled verification failure")
        return original_verify(root, before, role)

    def digest(path):
        if path.name == "stderr":
            assert all(p.exited for p in processes.values())
            time.sleep(.04)
            if fault == "artifact" and path.parent.name == "0":
                raise OSError("controlled artifact failure")
        return original_digest(path)

    async def spawn(*args, **kwargs):
        assert reservations == ["0", "1", "2", "3"]
        index = kwargs["cwd"].name
        if fault == "spawn" and index == "0":
            raise OSError("controlled spawn failure")
        reader = asyncio.StreamReader()
        proc = SimpleNamespace(pid=100 + int(index), returncode=None, closed=False,
                               exited=False, stdout=reader, waits=0)
        async def drain():
            await asyncio.sleep(0)
        def write(data):
            request = json.loads(data)
            if "id" not in request:
                return
            if fault == "deadline" and index == "3" and request["id"] == 3:
                return
            result = {1: {}, 2: {"tools": []},
                      3: {"structuredContent": {"recorded": True}}}[request["id"]]
            asyncio.get_running_loop().call_later(.002 * (int(index) + 1),
                reader.feed_data, (json.dumps({"id": request["id"], "result": result}) + '\n').encode())
        def close():
            proc.closed = True
            if fault == "close" and index == "0":
                raise OSError("controlled close failure")
        async def wait():
            proc.waits += 1
            if fault == "wait" and index == "0" and proc.waits == 1:
                raise OSError("controlled wait failure")
            if fault == "shutdown" and index == "0" and proc.waits == 1:
                raise TimeoutError
            await asyncio.sleep(.005 * (int(index) + 1))
            proc.exited, proc.returncode = True, 0
            return 0
        proc.stdin = SimpleNamespace(write=write, drain=drain, close=close)
        proc.wait = wait
        processes[index] = proc
        return proc

    async def rpc(proc, message, **kwargs):
        start = time.monotonic()
        try:
            return await original_rpc(proc, message, timeout=.05)
        finally:
            if message.get("id") == 3:
                observations[str(proc.pid - 100)] = time.monotonic() - start

    def killpg(pid, sig):
        if sig:
            return
        raise ProcessLookupError
    monkeypatch.setattr(ruler, "ledger_event", ledger)
    monkeypatch.setattr(ruler, "verify_preservation", verify)
    monkeypatch.setattr(ruler, "digest", digest)
    monkeypatch.setattr(ruler, "rpc", rpc)
    monkeypatch.setattr(ruler.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(ruler.os, "killpg", killpg)
    if fault == "persistence":
        with pytest.raises(OSError):
            asyncio.run(ruler.measure_batch(Path('/unused'), batch, {}, tmp_path / 'ledger'))
    else:
        rows = asyncio.run(ruler.measure_batch(Path('/unused'), batch, {}, tmp_path / 'ledger'))
        assert len(rows) == 4
        assert sum(row["status"] == "failed" for row in rows) == (fault is not None)
        assert len(results) == 4
        if fault == "deadline":
            assert rows[3]["error_type"] == "TimeoutError"
        for row in rows:
            if "first_call" in row["events_ns"]:
                assert row["events_ns"]["shutdown_start"] > row["events_ns"]["first_call"]
                assert row["client_phases_ms"]["shutdown"] < 100
    assert all(p.exited for p in processes.values())
    assert all(elapsed < .1 for elapsed in observations.values())
    events = [json.loads(line) for line in (tmp_path / 'ledger').read_text().splitlines()]
    assert sum(event["launches"] for event in events) == 4


def test_partial_batch_reservation_failure_never_spawns_or_refunds(tmp_path, monkeypatch):
    import asyncio
    ledger = tmp_path / "ledger"
    ruler.ledger_event(ledger, {"launches": 2298})
    async def forbidden(*args, **kwargs):
        pytest.fail("partial reservation must not spawn")
    monkeypatch.setattr(ruler.asyncio, "create_subprocess_exec", forbidden)
    batch = [({"id": str(i), "role": "worker"}, {}) for i in range(4)]
    with pytest.raises(ValueError, match="ceiling"):
        asyncio.run(ruler.measure_batch(Path('/unused'), batch, {}, ledger))
    assert sum(json.loads(line)["launches"] for line in ledger.read_text().splitlines()) == 2300


def test_cancelled_batch_cleans_up_without_refunding(tmp_path, monkeypatch):
    import asyncio
    from types import SimpleNamespace
    root = tmp_path / 'case'
    root.mkdir()
    closed = []
    async def check():
        started = asyncio.Event()
        async def spawn(*args, **kwargs):
            async def wait():
                await asyncio.sleep(.001)
                closed.append('exit')
                return 0
            return SimpleNamespace(stdin=SimpleNamespace(close=lambda: closed.append('close')),
                                   wait=wait, pid=123, returncode=0)
        async def stall(*args, **kwargs):
            started.set()
            await asyncio.Event().wait()
        def no_group(*args):
            raise ProcessLookupError
        monkeypatch.setattr(ruler.asyncio, 'create_subprocess_exec', spawn)
        monkeypatch.setattr(ruler, 'rpc', stall)
        monkeypatch.setattr(ruler.os, 'killpg', no_group)
        task = asyncio.create_task(ruler.measure_batch(Path('/unused'), [
            ({'id': 'cancel', 'role': 'worker'}, {'root': root, 'oracle': {}, 'env': {}})],
            {}, tmp_path / 'ledger'))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(check())
    assert closed == ['close', 'exit']
    events = [json.loads(line) for line in (tmp_path / 'ledger').read_text().splitlines()]
    assert sum(e['launches'] for e in events) == 1


@pytest.mark.parametrize('phase', ['spawn', 'rpc', 'normal', 'forced', 'error', 'group'])
@pytest.mark.parametrize('repeated', [False, True])
def test_run_cancellation_owns_cleanup_and_roots(tmp_path, monkeypatch, phase, repeated):
    import argparse
    import asyncio
    from types import SimpleNamespace

    case = next(c for c in ruler.case_matrix() if c['role'] == 'worker'
                and c['home'] == 'empty' and c['install'] == 'editable'
                and c['load'] == 'isolated')
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps({'cases': ruler.case_matrix()}))
    ledger = tmp_path / 'ledger'
    roots, waits, signals = [], [], []
    original_prepare = ruler.prepare

    def prepare(python, case, manifest, directory):
        roots.append(directory)
        return original_prepare(python, case, {'fixtures': {'empty': None}, 'oracles': {
            'worker': {'catalog': {'tools': []}, 'tool': 'probe', 'arguments': {},
                       'expected_response_subset': {'recorded': True},
                       'handoff': {'done': True}, 'output': 'handoff.json'}}}, directory)

    async def check():
        reached, release = asyncio.Event(), asyncio.Event()
        proc = SimpleNamespace(pid=123, returncode=None)
        group_alive = True

        async def barrier():
            reached.set()
            await release.wait()
            assert roots[0].exists()

        async def spawn(*args, **kwargs):
            if phase == 'spawn':
                await barrier()
            return proc

        async def rpc(proc, message, **kwargs):
            if phase == 'rpc':
                reached.set()
                await asyncio.Event().wait()
            if message.get('id') == 3:
                (roots[0] / 'case/handoff.json').write_text('{"done": true}')
                return {'structuredContent': {'recorded': True}}
            return {'tools': []} if message.get('id') == 2 else {}

        def close():
            if phase == 'error':
                raise OSError('controlled close failure')

        async def wait():
            nonlocal group_alive
            waits.append('started')
            try:
                if phase == 'forced' and len(waits) == 1:
                    raise TimeoutError
                if phase in ('normal', 'forced', 'error'):
                    await barrier()
                proc.returncode = 0
                if phase != 'group':
                    group_alive = False
                waits.append('completed')
                return 0
            except asyncio.CancelledError:
                waits.append('cancelled')
                raise

        def killpg(pid, sig):
            nonlocal group_alive
            assert roots[0].exists()
            signals.append(sig)
            if not group_alive:
                raise ProcessLookupError
            if phase == 'group' and sig:
                reached.set()
            if phase == 'group' and release.is_set():
                group_alive = False
                raise ProcessLookupError

        proc.stdin = SimpleNamespace(close=close)
        proc.wait = wait
        monkeypatch.setattr(ruler, 'prepare', prepare)
        monkeypatch.setattr(ruler, 'package_identity', lambda _: {})
        monkeypatch.setattr(ruler, 'rpc', rpc)
        monkeypatch.setattr(ruler.asyncio, 'create_subprocess_exec', spawn)
        monkeypatch.setattr(ruler.os, 'killpg', killpg)
        args = argparse.Namespace(case_manifest=manifest, diagnostic=True, python=Path('/unused'),
            install='editable', load='isolated', case=case['id'], samples=1,
            ledger=ledger, output=tmp_path / 'output')
        task = asyncio.create_task(ruler.run(args))
        await asyncio.wait_for(reached.wait(), 1)
        task.cancel()
        await asyncio.sleep(.001)
        if phase != 'rpc':
            assert not task.done()
            assert roots[0].exists()
            if repeated:
                for _ in range(3):
                    task.cancel()
                    await asyncio.sleep(.001)
                    assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 1)
        assert proc.returncode == 0
        assert not group_alive
        assert waits[-1] == 'completed'
        assert 'cancelled' not in waits
        assert 0 in signals
        if phase in ('forced', 'error', 'group'):
            assert ruler.signal.SIGKILL in signals
        assert not roots[0].exists()
        assert not [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    asyncio.run(check())
    events = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert sum(e['launches'] for e in events) == 1
    assert events[0]['kind'] == 'launch'


@pytest.mark.parametrize('failure', ['reap', 'group'])
def test_unconfirmed_shutdown_is_bounded_and_retains_root(tmp_path, monkeypatch, failure):
    import asyncio
    from types import SimpleNamespace

    directory = tmp_path / 'owned'
    directory.mkdir()
    row = {'status': 'ok', 'events_ns': {}}
    calls = []
    async def wait():
        calls.append('wait')
        if failure == 'reap':
            if len(calls) == 1:
                raise TimeoutError
            await asyncio.Event().wait()
        return 0
    proc = SimpleNamespace(stdin=SimpleNamespace(close=lambda: None), wait=wait,
                           pid=123, returncode=0 if failure == 'group' else None)
    item = {'proc': proc}
    monkeypatch.setattr(ruler, 'SHUTDOWN_TIMEOUT', .02)
    monkeypatch.setattr(ruler.os, 'killpg', lambda *args: None)
    async def check():
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(ruler.shutdown(item, row), .5)
        assert not [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    asyncio.run(check())
    ruler.remove_root(directory, item)
    assert directory.exists()
    assert not item.get('cleanup_complete')
