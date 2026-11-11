"""Governed S1 transport witness over in-process fake ACP streams (VAL-37..44, VAL-41b).

SAFE-INPROC-PIPE: the "process" is an in-process object whose stdout is an
``asyncio.StreamReader`` and whose stdin is either a pipe-backed
``asyncio.StreamWriter`` or a scripted fake writer. Nothing is launched.
"""
from __future__ import annotations

import asyncio
import gc
import itertools
import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from tests.governed_s1_support import governed_project
from unrest_harness import acp_runner
from unrest_harness import governed_admission as ga
from unrest_harness import governed_records as gr
from unrest_harness.acp_runner import ACPClient, ACPError, GovernedWitnessUnavailable
from unrest_harness.models import Task

STAGE_NAMES = ("prepared", "not_submitted", "write_completed", "write_error", "response",
               "local_failure")
PARAMS = {"prompt": [{"type": "text", "text": "hello"}], "sessionId": "s-1"}


class FakeWriter:
    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.closing = False
        self.on_drain: Callable[[], Any] | None = None
        self.pending_at_write: list[int] = []
        self.client: ACPClient | None = None

    def write(self, data: bytes) -> None:
        if self.client is not None:
            self.pending_at_write.extend(self.client._pending)
        self.writes.append(data)

    async def drain(self) -> None:
        if self.on_drain is not None:
            result = self.on_drain()
            if asyncio.iscoroutine(result):
                await result

    def is_closing(self) -> bool:
        return self.closing


def _bound(tmp_path: Path, attempt: str = "2000-01-01T00-00-00Z-0001",
           inventory: dict[str, str] | None = None) -> tuple[Any, gr.GovernedBound]:
    controller, project_id, mid = governed_project(tmp_path)
    c = gr.classify(controller.store, project_id, mid)
    task = Task(id="w0", type="work", body="do", targets=["VAL-A"], skill="s")
    templates = ga.bind_tasks(c, [task], controller.dispatcher)
    assert isinstance(templates, dict)
    template = templates["w0"]
    assert isinstance(template, gr.GovernedTemplate)
    scope = gr.ExecutionScope(anchor=controller.store.unrest_dir(project_id),
                              project_id=project_id, mission_id=mid,
                              admission_id=template.admission_id, attempt_id=attempt,
                              node_id="w0", inventory=inventory or {})
    gr.open_scope(controller.store, scope)
    return controller, gr.GovernedBound(template=template, scope=scope)


def _stages(bound: gr.GovernedBound) -> dict[str, list[str]]:
    scope = bound.scope
    base = scope.anchor.joinpath(*scope.components(), "submissions")
    return {wid: sorted(p.name.removesuffix(".json") for p in (base / wid).iterdir())
            for wid in scope.witness_ids}


def _letters(names: list[str]) -> set[str]:
    return {gr.STAGE_LETTER[name] for name in names}


def _client(writer: Any, terminal_environment: dict[str, str] | None = None,
            wire: dict[str, str] | None = None) -> tuple[ACPClient, asyncio.StreamReader]:
    stdout = asyncio.StreamReader()
    process = SimpleNamespace(stdin=writer, stdout=stdout)
    client = ACPClient(process, "/nonexistent", None,  # type: ignore[arg-type]
                       terminal_environment or {}, wire_credentials=wire)
    if isinstance(writer, FakeWriter):
        writer.client = client
    return client, stdout


def _respond(stdout: asyncio.StreamReader, rid: Any, *, error: bool = False) -> None:
    frame: dict[str, Any] = {"jsonrpc": "2.0", "id": rid}
    frame["error" if error else "result"] = {"code": 1} if error else {"ok": True}
    stdout.feed_data(json.dumps(frame).encode() + b"\n")


def _assert_clean(client: ACPClient) -> None:
    assert client._pending == {} and client._witnessed_rids == set()
    assert client._correlated == {}


def _run(coro_factory: Callable[[], Any]) -> tuple[Any, list[dict[str, Any]]]:
    unretrieved: list[dict[str, Any]] = []

    async def main() -> Any:
        asyncio.get_running_loop().set_exception_handler(
            lambda loop, ctx: unretrieved.append(ctx))
        try:
            return await coro_factory()
        finally:
            gc.collect()
            await asyncio.sleep(0)

    result = asyncio.run(main())
    gc.collect()
    return result, unretrieved


# VAL-37 ----------------------------------------------------------------------


def test_val37_fenced_scope_writes_nothing(tmp_path):
    _, bound = _bound(tmp_path)
    bound.scope.fenced = True
    writer = FakeWriter()

    async def go():
        client, stdout = _client(writer)
        await client.start()
        with pytest.raises(GovernedWitnessUnavailable):
            await client.send_prepared(PARAMS, bound, "initial")
        _assert_clean(client)
        stdout.feed_eof()

    _, unretrieved = _run(go)
    assert writer.writes == [] and bound.scope.witness_ids == []
    assert unretrieved == []


# VAL-38 ----------------------------------------------------------------------


def test_val38_bytes_equal_legacy_write_over_os_pipe(tmp_path):
    _, bound = _bound(tmp_path)
    secret = {"OPENAI_API_KEY": "sk-redact-me-0123456789"}
    params = {"prompt": [{"type": "text", "text": "use sk-redact-me-0123456789"}],
              "sessionId": "s-1"}

    async def capture(governed: bool) -> bytes:
        read_fd, write_fd = os.pipe()
        loop = asyncio.get_running_loop()
        pipe = os.fdopen(write_fd, "wb", buffering=0)
        transport, protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, pipe)
        writer = asyncio.StreamWriter(transport, protocol, None, loop)
        client, stdout = _client(writer, terminal_environment=secret)
        await client.start()
        if governed:
            task = asyncio.create_task(client.send_prepared(params, bound, "initial"))
        else:
            task = asyncio.create_task(client.send_request("session/prompt", params))
        await asyncio.sleep(0.05)
        _respond(stdout, 1)
        await task
        _assert_clean(client)
        stdout.feed_eof()
        transport.close()
        await asyncio.sleep(0)
        data = b""
        while chunk := os.read(read_fd, 65536):
            data += chunk
        os.close(read_fd)
        return data

    async def go():
        return await capture(True), await capture(False)

    (governed, legacy), unretrieved = _run(go)
    assert governed == legacy and governed.count(b"\n") == 1
    assert b"sk-redact-me" not in governed
    assert unretrieved == []


def test_val38_single_write_and_pending_before_write(tmp_path):
    _, bound = _bound(tmp_path)
    writer = FakeWriter()

    async def go():
        client, stdout = _client(writer)
        await client.start()
        task = asyncio.create_task(client.send_prepared(PARAMS, bound, "initial"))
        await asyncio.sleep(0.01)
        _respond(stdout, 1)
        assert await task == {"ok": True}
        stdout.feed_eof()

    _run(go)
    assert len(writer.writes) == 1 and writer.pending_at_write == [1]


# sha256 of ACPClient.send_request + "\n\n" + ACPClient._write source at 79dd57d.
LEGACY_TRANSPORT_SHA = "5e8de442f998fa623d4ee5d86d7ece1d9dd5fca511c6b8705ac677a3bda9d393"


def test_val38_legacy_send_request_and_write_unchanged():
    import ast
    import hashlib

    source = Path(acp_runner.__file__).read_text()
    tree = ast.parse(source)
    client_class = next(node for node in tree.body
                        if isinstance(node, ast.ClassDef) and node.name == "ACPClient")
    bodies = {node.name: ast.get_source_segment(source, node)
              for node in client_class.body
              if isinstance(node, ast.AsyncFunctionDef) and node.name in ("send_request",
                                                                          "_write")}
    joined = "\n\n".join(bodies[name] or "" for name in ("send_request", "_write"))
    assert hashlib.sha256(joined.encode()).hexdigest() == LEGACY_TRANSPORT_SHA


# VAL-39 ----------------------------------------------------------------------


def test_val39_prepared_failure_writes_nothing(tmp_path, monkeypatch):
    _, bound = _bound(tmp_path)
    writer = FakeWriter()
    real = acp_runner.publish_witness_stage

    def fail_prepared(scope, wid, stage, record, inventories):
        if stage == "prepared":
            raise OSError("disk")
        return real(scope, wid, stage, record, inventories)

    monkeypatch.setattr(acp_runner, "publish_witness_stage", fail_prepared)

    async def go():
        client, stdout = _client(writer)
        await client.start()
        with pytest.raises(GovernedWitnessUnavailable):
            await client.send_prepared(PARAMS, bound, "initial")
        _assert_clean(client)
        stdout.feed_eof()

    _run(go)
    assert writer.writes == []
    (wid,) = bound.scope.witness_ids
    assert _stages(bound) == {wid: []}
    assert gr.classify_witness([]) == "unknown"


# VAL-40 ----------------------------------------------------------------------


@pytest.mark.parametrize("point", ["buffer", "fenced", "fifth", "prepared", "drain",
                                   "cancel_drain", "cancel_await"])
def test_val40_failure_points_leave_no_state(tmp_path, monkeypatch, point):
    _, bound = _bound(tmp_path)
    writer = FakeWriter()
    if point == "buffer":
        monkeypatch.setattr(acp_runner, "_redact_json_value",
                            lambda *a: (_ for _ in ()).throw(ValueError("buffer")))
    elif point == "fenced":
        bound.scope.fenced = True
    elif point == "fifth":
        bound.scope.witness_ids.extend(["a" * 32, "b" * 32, "c" * 32, "d" * 32])
    elif point == "prepared":
        monkeypatch.setattr(acp_runner, "publish_witness_stage",
                            lambda *a: (_ for _ in ()).throw(OSError("p")))
    elif point == "drain":
        writer.on_drain = lambda: (_ for _ in ()).throw(BrokenPipeError())

    async def go():
        client, stdout = _client(writer)
        await client.start()
        if point == "cancel_drain":
            blocker = asyncio.Event()
            writer.on_drain = blocker.wait
        task = asyncio.create_task(client.send_prepared(PARAMS, bound, "initial"))
        if point in ("cancel_drain", "cancel_await"):
            await asyncio.sleep(0.02)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises((ACPError, ValueError, OSError)):
                await task
        _assert_clean(client)
        stdout.feed_eof()
        await asyncio.sleep(0)

    _, unretrieved = _run(go)
    assert not [ctx for ctx in unretrieved if "never retrieved" in str(ctx.get("message"))]


# VAL-41 ----------------------------------------------------------------------


def _scenario(tmp_path, monkeypatch, name: str):
    _, bound = _bound(tmp_path)
    writer = FakeWriter()
    raised: dict[str, BaseException] = {}
    real_publish = acp_runner.publish_witness_stage

    async def go():
        client, stdout = _client(writer)
        await client.start()
        if name == "response_during_drain":
            writer.on_drain = lambda: _respond(stdout, 1)
        elif name == "w_publish_fails":
            monkeypatch.setattr(acp_runner, "publish_witness_stage",
                                lambda scope, wid, stage, record, inv: (
                                    (_ for _ in ()).throw(OSError("w"))
                                    if stage == "write_completed"
                                    else real_publish(scope, wid, stage, record, inv)))
            writer.on_drain = lambda: _respond(stdout, 1)
        elif name == "correlated_then_drain_fails":
            original = BrokenPipeError("drain")
            raised["original"] = original

            async def respond_then_fail():
                _respond(stdout, 1)
                await asyncio.sleep(0.01)
                raise original

            writer.on_drain = respond_then_fail
        elif name == "eof":
            writer.on_drain = None
        elif name == "error_frame":
            writer.on_drain = lambda: _respond(stdout, 1, error=True)
        elif name == "float_id":
            writer.on_drain = lambda: _respond(stdout, 1.0)
        elif name == "closed_stdin":
            writer.closing = True
        elif name == "drain_fails":
            writer.on_drain = lambda: (_ for _ in ()).throw(ConnectionResetError())
        task = asyncio.create_task(client.send_prepared(PARAMS, bound, "initial"))
        if name == "eof":
            await asyncio.sleep(0.02)
            _respond(stdout, 99)  # unknown id: ignored
            stdout.feed_eof()
        try:
            result = await task
        except BaseException as exc:  # noqa: BLE001
            raised["got"] = exc
            result = None
        if name == "late_after_cancel":
            pass
        _assert_clean(client)
        if not stdout.at_eof():
            stdout.feed_eof()
        await asyncio.sleep(0)
        return result

    result, unretrieved = _run(go)
    assert unretrieved == []
    ((wid, names),) = _stages(bound).items()
    return bound, wid, names, raised, result


@pytest.mark.parametrize(("name", "expected", "outcome"), [
    ("response_during_drain", {"P", "W", "R"}, "response_observed"),
    ("w_publish_fails", {"P", "R"}, "response_observed"),
    ("correlated_then_drain_fails", {"P", "E", "R"}, "response_observed"),
    ("eof", {"P", "W", "L"}, "transport_write_completed"),
    ("error_frame", {"P", "W", "R"}, "response_observed"),
    ("float_id", {"P", "W", "R"}, "response_observed"),
    ("closed_stdin", {"P", "N"}, "not_submitted"),
    ("drain_fails", {"P", "E"}, "unknown"),
])
def test_val41_observation_sets(tmp_path, monkeypatch, name, expected, outcome):
    bound, wid, names, raised, result = _scenario(tmp_path, monkeypatch, name)
    assert _letters(names) == expected
    assert gr.classify_witness(names) == outcome
    if name == "correlated_then_drain_fails":
        assert raised["got"] is raised["original"]
    if name == "error_frame":
        assert isinstance(raised["got"], ACPError)
        stages = gr.read_witness_stages(SimpleNamespace(unrest_dir=lambda pid: bound.scope.anchor),
                                        bound.scope.project_id, bound.scope.mission_id,
                                        bound.scope.attempt_id, wid, ["response"])
        assert stages["response"]["response_class"] == "error"  # type: ignore[index]
    if name == "eof":
        assert sorted(names) == ["local_failure", "prepared", "write_completed"]
    if name in ("response_during_drain", "float_id", "w_publish_fails"):
        assert result == {"ok": True}


def test_val41_failed_e_publication_keeps_original_exception(tmp_path, monkeypatch):
    _, bound = _bound(tmp_path)
    writer = FakeWriter()
    original = BrokenPipeError("drain")
    real = acp_runner.publish_witness_stage
    monkeypatch.setattr(acp_runner, "publish_witness_stage",
                        lambda scope, wid, stage, record, inv: (
                            (_ for _ in ()).throw(OSError("e"))
                            if stage in ("write_error", "response")
                            else real(scope, wid, stage, record, inv)))

    async def go():
        client, stdout = _client(writer)
        await client.start()
        writer.on_drain = lambda: (_ for _ in ()).throw(original)
        with pytest.raises(BrokenPipeError) as caught:
            await client.send_prepared(PARAMS, bound, "initial")
        assert caught.value is original
        _assert_clean(client)
        stdout.feed_eof()

    _run(go)


def test_val41_late_frame_after_cancel_ignored(tmp_path):
    _, bound = _bound(tmp_path)
    writer = FakeWriter()

    async def go():
        client, stdout = _client(writer)
        await client.start()
        task = asyncio.create_task(client.send_prepared(PARAMS, bound, "initial"))
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        _respond(stdout, 1)
        await asyncio.sleep(0.02)
        _assert_clean(client)
        stdout.feed_eof()

    _run(go)
    ((_, names),) = _stages(bound).items()
    assert _letters(names) == {"P", "W", "L"}


SYNTHETIC_EXPECTED = {
    "stage_without_prepared": 31, "conflicting_stages": 22, "unknown": 5,
    "not_submitted": 1, "response_observed": 3, "transport_write_completed": 2,
}


def _oracle(letters: frozenset[str]) -> str:
    """Independent restatement of the ordered procedure (amendment §4)."""
    if letters and "P" not in letters:
        return "stage_without_prepared"
    if "P" in letters and (("N" in letters and letters & {"W", "E", "R", "L"})
                           or {"W", "E"} <= letters or {"R", "L"} <= letters):
        return "conflicting_stages"
    table = {
        frozenset(): "unknown", frozenset("P"): "unknown", frozenset("PE"): "unknown",
        frozenset("PL"): "unknown", frozenset("PEL"): "unknown",
        frozenset("PN"): "not_submitted",
        frozenset("PR"): "response_observed", frozenset("PWR"): "response_observed",
        frozenset("PER"): "response_observed",
        frozenset("PW"): "transport_write_completed",
        frozenset("PWL"): "transport_write_completed",
    }
    return table[letters]


def test_val41b_all_64_subsets_synthetic():
    """SYNTHETIC: classifier over stage-name sets, not observed transport runs."""
    counts: dict[str, int] = {}
    by_letter = {gr.STAGE_LETTER[name]: name for name in STAGE_NAMES}
    for size in range(7):
        for combo in itertools.combinations("PNWERL", size):
            names = [by_letter[letter] for letter in combo]
            got = gr.classify_witness(names)
            reason = gr.witness_unavailable_reason(names)
            final = reason if got == "unavailable" else got
            assert final == _oracle(frozenset(combo)), combo
            counts[final] = counts.get(final, 0) + 1
    assert counts == SYNTHETIC_EXPECTED and sum(counts.values()) == 64


# VAL-42 ----------------------------------------------------------------------


def test_val42_publications_in_loop_thread_without_executor(tmp_path, monkeypatch):
    _, bound = _bound(tmp_path)
    writer = FakeWriter()
    threads: list[int] = []
    real = acp_runner.publish_witness_stage

    def spy(*args):
        threads.append(threading.get_ident())
        return real(*args)

    monkeypatch.setattr(acp_runner, "publish_witness_stage", spy)
    monkeypatch.setattr(asyncio, "to_thread",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("to_thread")))
    loop_thread: list[int] = []

    async def go():
        loop = asyncio.get_running_loop()
        loop_thread.append(threading.get_ident())
        loop.run_in_executor = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore[method-assign]
            AssertionError("executor"))
        client, stdout = _client(writer)
        await client.start()
        writer.on_drain = lambda: _respond(stdout, 1)
        await client.send_prepared(PARAMS, bound, "initial")
        stdout.feed_eof()

    _run(go)
    assert len(threads) == 3 and set(threads) == set(loop_thread)


# VAL-43 / VAL-44 -------------------------------------------------------------


def test_val43_continuation_has_no_criteria_same_scope(tmp_path):
    _, bound = _bound(tmp_path)
    writer = FakeWriter()

    async def go():
        client, stdout = _client(writer)
        await client.start()
        writer.on_drain = lambda: _respond(stdout, client._request_id)
        await client.send_prepared(PARAMS, bound, "initial")
        await client.send_prepared(PARAMS, bound, "continuation")
        stdout.feed_eof()

    _run(go)
    stores = SimpleNamespace(unrest_dir=lambda pid: bound.scope.anchor)
    records = [gr.read_witness_stages(stores, bound.scope.project_id, bound.scope.mission_id,
                                      bound.scope.attempt_id, wid, ["prepared"])["prepared"]
               for wid in bound.scope.witness_ids]
    assert [r["input_kind"] for r in records] == ["initial", "continuation"]  # type: ignore[index]
    assert records[0]["criteria"] and records[1]["criteria"] == []  # type: ignore[index]


def test_val44_fifth_witness_refused(tmp_path):
    _, bound = _bound(tmp_path)
    writer = FakeWriter()

    async def go():
        client, stdout = _client(writer)
        await client.start()
        writer.on_drain = lambda: _respond(stdout, client._request_id)
        for _ in range(4):
            await client.send_prepared(PARAMS, bound, "continuation")
        with pytest.raises(GovernedWitnessUnavailable):
            await client.send_prepared(PARAMS, bound, "continuation")
        _assert_clean(client)
        stdout.feed_eof()

    _run(go)
    assert len(writer.writes) == 4 and len(bound.scope.witness_ids) == 4
    gr.close_scope(bound.scope, effect_started=True, outcome="completed")
    c = gr.classify(SimpleNamespace(unrest_dir=lambda pid: bound.scope.anchor,  # type: ignore[arg-type]
                                    unrest_runtime_dir=lambda pid: bound.scope.anchor),
                    bound.scope.project_id, bound.scope.mission_id)
    assert c.executions_status == "ok"


def test_val36_witness_guard_uses_three_inventories(tmp_path, monkeypatch):
    _, bound = _bound(tmp_path, inventory={"STORE": "store-secret-012345"})
    writer = FakeWriter()
    seen: list[tuple[Any, ...]] = []
    real_guard = gr.guard
    monkeypatch.setattr(gr, "guard", lambda data, inv: seen.append(tuple(inv))
                        or real_guard(data, inv))

    async def go():
        client, stdout = _client(writer, terminal_environment={"OPENAI_API_KEY": "sk-c-01234567"},
                                 wire={"WIRE": "wire-secret-0123"})
        await client.start()
        writer.on_drain = lambda: _respond(stdout, 1)
        await client.send_prepared(PARAMS, bound, "initial")
        stdout.feed_eof()

    _run(go)
    assert seen and all(len(item) == 3 for item in seen)
    assert seen[0][0] == {"STORE": "store-secret-012345"} and seen[0][2] == {
        "WIRE": "wire-secret-0123"}


def test_val43_both_governed_prompt_sites_use_send_prepared():
    """Static structure only (not runtime evidence): both session/prompt sites in the
    runner choose ``send_prepared`` for GovernedBound and raw ``send_request`` otherwise."""
    import ast

    tree = ast.parse(Path(acp_runner.__file__).read_text(encoding="utf-8"))
    sites = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.IfExp) and isinstance(node.test, ast.Call)
                and isinstance(node.test.func, ast.Name) and node.test.func.id == "isinstance"
                and isinstance(node.test.args[1], ast.Name)
                and node.test.args[1].id == "GovernedBound"):
            continue
        body, orelse = node.body, node.orelse
        assert isinstance(body, ast.Call) and isinstance(body.func, ast.Attribute)
        assert isinstance(orelse, ast.Call) and isinstance(orelse.func, ast.Attribute)
        assert orelse.func.attr == "send_request"
        assert isinstance(orelse.args[0], ast.Constant)
        assert orelse.args[0].value == "session/prompt"
        sites.append((body.func.attr, body.args[2].value))  # type: ignore[attr-defined]
    assert sorted(sites) == [("send_prepared", "continuation"), ("send_prepared", "initial")]
