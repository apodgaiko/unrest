"""Controlled readiness only. No host human, genuine provider or model calls."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
from types import SimpleNamespace

from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
import pytest

import unrest_harness.approval_recovery as recovery
import unrest_harness.acp_runner as acp
from unrest_harness.approval_native import (
    ApprovalUnavailable,
    NativeBinding,
    human_display,
    native_event,
)
from unrest_harness.approval_relay import Routing, read_frame, write_frame
from unrest_harness.acp_runner import ACPNodeRunner
from unrest_harness.assets import AssetLoader
from unrest_harness.models import Task
from unrest_harness.provider_review import ProviderReviewBlock, ReviewIdentity
from unrest_harness.server import (
    _register_foundation_tools,
    create_worker_server,
    create_validator_server,
)
from fastmcp import FastMCP
from tests.test_provider_review import controller_fixture, event

FIXTURES = Path(__file__).parent / "fixtures"
RUN = "run:" + "a" * 64
PRIVACY_COMMANDS = [
    "curl --user demo:approval-CANARY https://example.invalid",
    'curl -H "Authorization: Basic ZGVtbzphcHByb3ZhbC1DQU5BUlk=" https://example.invalid # approval-CANARY',
    "tool --password approval-CANARY",
    "AWS_SECRET_ACCESS_KEY=approval-CANARY tool",
    "tool --password='approval-CANARY'",
    "tool '--password' 'approval-CANARY'",
    "tool --pa''ssword approval-CANARY",
    "tool --passwd approval-CANARY",
    "tool --passphrase approval-CANARY",
    "tool --api-key approval-CANARY",
    "tool --access_token=approval-CANARY",
    "tool --client-secret approval-CANARY",
    "tool --user demo --password approval-CANARY",
    "tool --username=demo",
    "curl -u 'demo:approval-CANARY' https://example.invalid",
    "curl -udemo:approval-CANARY https://example.invalid",
    "curl -Udemo:approval-CANARY https://example.invalid",
    "curl --proxy-user=demo:approval-CANARY https://example.invalid",
    'curl -H "Proxy-Authorization: Basic approval-CANARY" https://example.invalid',
    'curl -H "X-Api-Key: approval-CANARY" https://example.invalid',
    'curl -H "Cookie: session=approval-CANARY" https://example.invalid',
    "env 'DB_PASSWORD=approval-CANARY' tool",
    "export AWS_SECRET_ACCESS_KEY='approval-CANARY'; tool",
    "mysql -papproval-CANARY",
    # Cluster position and attached/separated values must not change refusal.
    *[f"curl -{cluster}{option}{value} https://example.invalid"
      for cluster in ("sS", "fsS", "Is", "LsSf")
      for option in ("u", "U")
      for value in (" demo:approval-CANARY", "demo:approval-CANARY")],
    "sshpass -p approval-CANARY ssh demo@example.invalid",
    "sshpass -papproval-CANARY ssh demo@example.invalid",
    "openssl enc -aes-256-cbc -pass pass:approval-CANARY",
    "openssl pkcs12 -passin env:OPAQUE -passout file:/private/tmp/approval-CANARY",
    "openssl enc -k approval-CANARY",
    "wget --http-user=demo --http-passwd=approval-CANARY https://example.invalid",
    "psql postgresql://demo:approval-CANARY@example.invalid/db",
    "git -c http.extraHeader='X-Opaque: approval-CANARY' fetch",
    "curl -sSH 'X-Opaque: approval-CANARY' https://example.invalid",
    "curl -sSK /private/tmp/approval-CANARY https://example.invalid",
    "curl --oauth2-bearer approval-CANARY https://example.invalid",
    "curl --tlsauthtype SRP --tlsuser demo --tlspassword approval-CANARY https://example.invalid",
    "curl https://demo%3Aapproval-CANARY@example.invalid",
    "curl https://example.invalid/?opaque=approval-CANARY",
    "OPAQUE=approval-CANARY printf harmless",
    "env OPAQUE=approval-CANARY printf harmless",
    "LANG=approval-CANARY printf harmless",
    "printf pass:approval-CANARY",
    "printf env:approval-CANARY",
    "printf fd:3",
    "sh -c 'curl -sSu demo:approval-CANARY https://example.invalid'",
    "python -u script.py approval-CANARY",
    "unknown-tool -x approval-CANARY",
]


def denied():
    raw = deepcopy(event()["update"]["rawInput"])
    raw["action"]["command"] = "printf approval-CANARY"
    raw["action"]["cwd"] = "/private/tmp"
    raw["review"]["rationale"] = "private-rationale-CANARY"
    raw["review"]["riskLevel"] = "low"
    raw["review"]["userAuthorization"] = "low"
    return raw


def native_binding():
    binding = NativeBinding()
    binding.consume({"method": "thread/started", "params": {"thread": {"id": "thread-1"}}})
    binding.consume(
        {"method": "turn/started", "params": {"threadId": "thread-1", "turn": {"id": "turn-1"}}}
    )
    return binding


def test_exact_native_source_mapping_and_display():
    raw = denied()
    value = native_event(raw)
    assert value == {
        "id": "review-1",
        "turn_id": "turn-1",
        "started_at_ms": 1,
        "completed_at_ms": 2,
        "status": "denied",
        "decision_source": "agent",
        "risk_level": "low",
        "user_authorization": "low",
        "rationale": "private-rationale-CANARY",
        "action": raw["action"],
    }
    assert "target_item_id" not in value
    assert "approval-CANARY" in human_display(raw, ())
    assert "private-rationale-CANARY" not in human_display(raw, ())
    raw["action"] = {
        "type": "execve",
        "source": "unifiedExec",
        "program": "/bin/echo",
        "argv": ["echo", "literal\nline"],
        "cwd": "/private/tmp",
    }
    assert native_event(raw)["action"] == dict(raw["action"], source="unified_exec")
    assert "literal\\nline" in human_display(raw, ())


@pytest.mark.parametrize(
    "action",
    [
        {"type": "applyPatch", "cwd": "/private/tmp", "files": ["a"]},
        {
            "type": "mcpToolCall",
            "server": "s",
            "toolName": "t",
            "connectorId": None,
            "connectorName": None,
            "toolTitle": None,
        },
        {
            "type": "writeStdin",
            "approvalId": "a",
            "processId": "p",
            "stdin": "x",
            "cwd": "/private/tmp",
        },
        {"type": "networkAccess", "target": "x", "host": "x", "protocol": "https", "port": 443},
        {
            "type": "requestPermissions",
            "reason": None,
            "permissions": {"network": None, "fileSystem": None},
        },
        {"type": "command", "source": "shell", "command": "x", "cwd": "file://remote/path"},
    ],
)
def test_unreviewable_actions_refuse(action):
    raw = denied()
    raw["action"] = action
    with pytest.raises(ApprovalUnavailable):
        native_event(raw)


@pytest.mark.parametrize(
    "body", ["token=secret", "Bearer opaque", "x\u202ey", "x\x00y", "x" * 10000, "finite-secret"]
)
def test_unsafe_exact_display_refuses(body):
    raw = denied()
    raw["action"]["command"] = body
    with pytest.raises(ApprovalUnavailable):
        human_display(raw, ("finite-secret",))


@pytest.mark.parametrize(
    "mutation", ["foreign", "missing_start", "changed_action", "multiple", "misplaced"]
)
def test_origin_binding_refuses_ambiguity(mutation):
    binding = native_binding()
    raw = denied()
    started = deepcopy(raw)
    started.pop("completedAtMs")
    started.pop("decisionSource")
    started["review"]["status"] = "inProgress"
    if mutation != "missing_start":
        binding.consume({"method": "item/autoApprovalReview/started", "params": started})
    if mutation == "foreign":
        raw["threadId"] = "thread-other"
    if mutation == "changed_action":
        raw["action"]["command"] = "replacement"
    frame = {"method": "item/autoApprovalReview/completed", "params": raw}
    if mutation == "misplaced":
        frame["id"] = 1
    binding.consume(frame)
    if mutation == "multiple":
        assert binding.event == raw
        binding.consume({"method": "item/autoApprovalReview/started", "params": started})
        binding.consume(frame)
    assert binding.invalid and binding.event is None


async def test_request_routing_collision_and_wrong_reply():
    routing = Routing()
    a = routing.allocate("unrest-native:2")
    n = routing.allocate(native=True)
    future = routing.native[n]
    assert routing.reply({"id": a, "result": {"x": 1}}) == {
        "id": "unrest-native:2",
        "result": {"x": 1},
    }
    assert routing.reply({"id": n, "result": {}}) is None
    assert await future == {}
    with pytest.raises(ApprovalUnavailable):
        routing.reply({"id": n, "result": {}})
    with pytest.raises(ApprovalUnavailable):
        routing.allocate(True)


@pytest.mark.parametrize("value", ["true", "yes", "2", "", " 1"])
def test_optin_is_strict(monkeypatch, value):
    monkeypatch.setenv("UNREST_APPROVAL_RECOVERY", value)
    with pytest.raises(ValueError, match="must be 0 or 1"):
        recovery.HarnessConfig.discover()


def setup_owner(tmp_path, *, deadline=None):
    _, store, _ = controller_fixture(tmp_path)
    config = replace(store.config, approval_recovery=True)
    running = [True]
    context = recovery.RunApprovalContext(RUN, lambda: running[0])
    owner = recovery.ApprovalOwner(
        config,
        context,
        store,
        "project",
        "mission-001",
        "attempt-1",
        "w1",
        store.attempt_path("project", "mission-001", "attempt-1", "w1"),
        (),
        deadline=deadline,
    )
    return owner, store, running


def backend(tmp_path, monkeypatch):
    path = tmp_path / "controlled-backend"
    path.write_text(f"#!{sys.executable}\n" + (FIXTURES / "approval_native_backend.py").read_text())
    path.chmod(0o700)
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(recovery, "BACKEND_PINS", frozenset({pin}))
    return path, pin


@pytest.mark.parametrize("pin", [
    "cc0a05e34876414280a79726153d0fe8d55c93f704ef6c292ec409bfe36d5b06",
    "09fa44fdc37a5fc70dc1ace31235f90468a2e193d0e85f7552eab068ea2582be",
    "0d5ac7aae20c4eda6242428d5e218c55ba96d8763fda2a271088ff37104b9d28",
])
async def test_exact_supported_backend_admission(tmp_path, monkeypatch, pin):
    # Synthetic digest only; no native process or provider is started here.
    path = tmp_path / "backend"
    path.write_bytes(b"controlled backend")
    monkeypatch.setattr(
        recovery.hashlib, "file_digest", lambda *_: SimpleNamespace(hexdigest=lambda: pin)
    )
    owner, _, _ = setup_owner(tmp_path)
    environment = {"CODEX_PATH": str(path), "UNCHANGED": "value"}
    try:
        launched = await owner.launch_environment(environment)
        assert launched["UNCHANGED"] == "value"
        assert environment["CODEX_PATH"] == str(path)
        launcher = Path(launched["CODEX_PATH"])
        assert launcher != path and pin in launcher.read_text()
        assert str(path.resolve()) in launcher.read_text()
        assert owner.root is not None and owner.server is not None
    finally:
        await owner.close()
    assert not launcher.exists()


@pytest.mark.parametrize("payload", [
    b"codex 0.162.0-alpha.17.2",
    b"codex 0.162.0-alpha.17.2\x00",
    b"9b47aa34d14c35d87fbe2702fc6c4163d965b30fd88b3defd19e80e780f40d8d",
])
async def test_unpinned_backend_refuses_before_transport(tmp_path, payload):
    path = tmp_path / "backend"
    path.write_bytes(payload)
    owner, _, _ = setup_owner(tmp_path)
    with pytest.raises(ApprovalUnavailable):
        await owner.launch_environment({"CODEX_PATH": str(path)})
    assert owner.root is None and owner.server is None
    assert recovery.BACKEND_PINS == frozenset({
        "cc0a05e34876414280a79726153d0fe8d55c93f704ef6c292ec409bfe36d5b06",
        "09fa44fdc37a5fc70dc1ace31235f90468a2e193d0e85f7552eab068ea2582be",
        "0d5ac7aae20c4eda6242428d5e218c55ba96d8763fda2a271088ff37104b9d28",
    })


async def install_pending(owner, *, raw=None):
    owner.root = Path(__import__("tempfile").mkdtemp(prefix="unrest-approval-test-")).resolve()
    os.chmod(owner.root, 0o700)
    owner.server = await asyncio.start_unix_server(
        owner._accept, str(owner.root / "control"), limit=32768
    )
    os.chmod(owner.root / "control", 0o600)
    reader, writer = await asyncio.open_unix_connection(str(owner.root / "control"), limit=32768)
    await write_frame(writer, {"hello": owner.relay_token}, 32768)
    await owner.connected.wait()
    owner.transport_bound = lambda: True  # controlled IPC plumbing, not PID provenance
    body = raw or denied()
    await write_frame(writer, {"event": "denied", "body": body}, 32768)
    await owner.denied.wait()
    if owner.event is None:
        # Unsafe capture is rejected before settlement or selection exists.
        return reader, writer, asyncio.create_task(owner.wait_for_review())
    await write_frame(
        writer, {"event": "settled", "thread_id": "thread-1", "turn_id": "turn-1"}, 32768
    )
    try:
        await asyncio.wait_for(owner.settled.wait(), owner.remaining())
    except TimeoutError:
        # Expiry can close the relay before this setup handshake settles.
        return reader, writer, asyncio.create_task(owner.wait_for_review())
    store = owner.store
    store.begin_provider_review(*owner.binding, "thread-1")
    store.save_provider_review(
        *owner.binding,
        "thread-1",
        ProviderReviewBlock("denied", ReviewIdentity("thread-1", "turn-1", "review-1")),
    )
    pending = asyncio.create_task(owner.wait_for_review())
    while owner.phase == "active":
        await asyncio.sleep(0)
    return reader, writer, pending


async def mcp_review(
    owner,
    *,
    action="accept",
    content=None,
    capability=True,
    run_id=RUN,
    denial_id="review-1",
    calls=None,
    gate=None,
):
    tools = SimpleNamespace(
        config=owner.config,
        runs=SimpleNamespace(inspect_run=lambda _: SimpleNamespace(state="running")),
    )
    server = FastMCP("controlled-host-plumbing")
    _register_foundation_tools(server, tools)

    async def elicit(message, schema, params, context):
        if calls is not None:
            calls.append((message, schema))
        assert "approval-CANARY" in message
        assert "private-rationale-CANARY" not in message
        if gate is not None:
            await gate.wait()
        return ElicitResult(action=action, content=content)

    async with Client(server, elicitation_handler=elicit if capability else None) as client:
        return (
            await client.call_tool("review_approval", {"run_id": run_id, "denial_id": denial_id})
        ).data


@pytest.mark.parametrize("command,kind", [
    *[(command, kind) for command in PRIVACY_COMMANDS for kind in ("command", "execve")],
    ("printf harmless; curl -sSu demo:approval-CANARY https://example.invalid", "command"),
    ("printf harmless | sshpass -p approval-CANARY ssh demo@example.invalid", "command"),
    ("printf harmless\ncurl -sSu demo:approval-CANARY https://example.invalid", "command"),
])
async def test_credentials_refuse_before_actual_mcp_form(tmp_path, command, kind):
    raw = denied()
    if kind == "command":
        raw["action"]["command"] = command
    else:
        words = shlex.split(command)
        raw["action"] = {
            "type": "execve", "source": "unifiedExec", "program": words[0],
            "argv": words, "cwd": "/private/tmp",
        }
    with pytest.raises(ApprovalUnavailable, match="^approval recovery unavailable$"):
        human_display(raw, ())
    owner, store, _ = setup_owner(tmp_path)
    reader, writer, pending = await install_pending(owner, raw=raw)
    calls = []
    try:
        assert await asyncio.wait_for(pending, 1) is False
        reply = await mcp_review(owner, content={"confirm_one_submission": True}, calls=calls)
        assert reply["disposition"] == "unavailable"
        assert calls == []
        assert not owner.submit_requested and owner.event is None
        assert owner.phase == "unavailable"
        assert await asyncio.wait_for(reader.read(), 1) == b""
        assert b"approval-CANARY" not in json.dumps(reply).encode()
        assert all(b"approval-CANARY" not in p.read_bytes()
                   for p in store.bucket_root("project").rglob("*") if p.is_file())
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()
    assert owner.server is None or not owner.server.is_serving()


@pytest.mark.parametrize("command", [
    "tool --password", "printf $UNKNOWN", "printf $(cat file)",
    "printf `cat file`", "cat <<EOF\nbody\nEOF", "printf 'unterminated",
])
def test_ambiguous_shell_display_refuses(command):
    raw = denied()
    raw["action"]["command"] = command
    with pytest.raises(ApprovalUnavailable):
        human_display(raw, ())


@pytest.mark.parametrize("command", [
    "printf 'approval-CANARY exact action'", "LANG=C printf approval-CANARY",
    "curl -fsSLI https://example.invalid/path", "printf approval-CANARY | cat",
    "ls -lah /private/tmp", "printf harmless && echo exact",
])
def test_harmless_shell_display_preserves_exact_action(command):
    raw = denied()
    raw["action"]["command"] = command
    display = human_display(raw, ())
    value = json.loads(display.split("\n")[1])
    assert value["action"] == raw["action"]


def test_literal_execve_display_preserves_argument_boundaries():
    raw = denied()
    raw["action"] = {
        "type": "execve", "source": "unifiedExec", "program": "/bin/echo",
        "argv": ["echo", "can't", "literal $VALUE", "two words", "line\nbreak",
                 "curl -sSu opaque", "|", ";"],
        "cwd": "/private/tmp",
    }
    assert json.loads(human_display(raw, ()).split("\n")[1])["action"] == raw["action"]


@pytest.mark.parametrize("command", [
    "curl -sSq https://example.invalid", "curl --config safe-file",
    "curl -sS --output safe-file https://example.invalid", "ls --unknown safe-file",
    "printf harmless > file", "printf harmless & echo exact", "(printf harmless)",
    "printf harmless # comment", "LANG=C.UTF-8", "true extra", "pwd extra",
])
def test_unsupported_display_grammar_refuses(command):
    raw = denied()
    raw["action"]["command"] = command
    with pytest.raises(ApprovalUnavailable):
        human_display(raw, ())


@pytest.mark.parametrize("argv", [[], ["other", "literal"], ["sh", "-c", "echo exact"]])
def test_execve_requires_interpretable_executable_and_argv(argv):
    raw = denied()
    raw["action"] = {
        "type": "execve", "source": "unifiedExec", "program": "/bin/echo",
        "argv": argv, "cwd": "/private/tmp",
    }
    with pytest.raises(ApprovalUnavailable):
        human_display(raw, ())


async def test_selection_rechecks_unsafe_display_without_opening_form(tmp_path):
    owner, _, _ = setup_owner(tmp_path)
    _, writer, pending = await install_pending(owner)
    calls = []
    try:
        owner.event["action"]["command"] = "tool --password approval-CANARY"
        result = await mcp_review(owner, content={"confirm_one_submission": True}, calls=calls)
        assert result["disposition"] == "unavailable"
        assert calls == [] and not owner.submit_requested
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()


@pytest.mark.parametrize(
    "action,content,capability",
    [
        ("decline", None, True),
        ("cancel", None, True),
        ("accept", {"confirm_one_submission": False}, True),
        ("accept", {"confirm_one_submission": "true"}, True),
        ("accept", {"confirm_one_submission": True, "actor": "human"}, True),
        ("accept", {"confirm_one_submission": True}, False),
    ],
)
async def test_actual_mcp_nonconsent_never_submits(tmp_path, action, content, capability):
    owner, store, _ = setup_owner(tmp_path)
    reader, writer, pending = await install_pending(owner)
    try:
        result = await mcp_review(owner, action=action, content=content, capability=capability)
        assert result["disposition"] == "unavailable"
        assert not owner.submit_requested
        if capability:
            assert await asyncio.wait_for(pending, 1) is False
        assert b"approval-CANARY" not in json.dumps(result).encode()
        assert all(
            b"approval-CANARY" not in p.read_bytes()
            for p in store.bucket_root("project").rglob("*.json")
        )
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()


async def test_actual_mcp_accept_single_submit_and_receipt(tmp_path):
    owner, store, _ = setup_owner(tmp_path)
    reader, writer, pending = await install_pending(owner)
    task = asyncio.create_task(mcp_review(owner, content={"confirm_one_submission": True}))
    try:
        assert await asyncio.wait_for(pending, 2)
        submission = asyncio.create_task(owner.submit())
        assert await read_frame(reader, 32768) == {"command": "submit", "id": 1}
        assert not owner.handoff.exists()
        await write_frame(writer, {"id": 1, "result": "queued"}, 32768)
        assert await asyncio.wait_for(submission, 2)
        assert (await task)["disposition"] == "queued"
        assert owner.event is None
        owner.record("completed")
        assert store.read_provider_review(*owner.binding) is None
        assert await mcp_review(owner, content={"confirm_one_submission": True}) == {
            "run_id": RUN,
            "denial_id": "review-1",
            "disposition": "unavailable",
        }
        assert store.provider_review_paths(*owner.binding)[0].exists()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()
    assert owner.cursor is not None and not owner.cursor.exists()
    assert owner.root is not None and not owner.root.exists()


@pytest.mark.parametrize("condition", ["expiry", "cancel", "completion", "wrong_id"])
async def test_expiry_cancel_commit_and_wrong_id_refuse(tmp_path, condition):
    owner, _, running = setup_owner(tmp_path)
    reader, writer, pending = await install_pending(owner)
    try:
        if condition == "expiry":
            owner.expiry = __import__("time").monotonic()
        elif condition == "cancel":
            running[0] = False
        elif condition == "completion":
            owner.handoff.parent.mkdir(parents=True, exist_ok=True)
            owner.handoff.write_text("{}")
        result = await mcp_review(
            owner,
            content={"confirm_one_submission": True},
            denial_id="foreign" if condition == "wrong_id" else "review-1",
        )
        assert result["disposition"] == "unavailable"
        assert not owner.submit_requested
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()


async def test_worker_and_validator_have_no_review():
    assert "review_approval" not in {t.name for t in await create_worker_server().list_tools()}
    assert "review_approval" not in {t.name for t in await create_validator_server().list_tools()}


@pytest.mark.parametrize(
    "mode",
    [
        "success",
        "delayed_interrupt",
        "drop_ack",
        "re_denied",
        "multiple",
        "failed_interrupt",
        "outstanding",
        "late_ack",
        "crash_after_send",
    ],
)
async def test_actual_acp_owner_native_subprocess_order_and_cleanup(tmp_path, monkeypatch, mode):
    _, store, _ = controller_fixture(tmp_path)
    native, pin = backend(tmp_path, monkeypatch)
    # Injection exists ONLY in this controlled test; production pin selection
    # is fixed and cannot be overridden by environment/configuration.
    original_launch = recovery.ApprovalOwner.launch_environment

    async def launch(owner, env, **kwargs):
        return await original_launch(owner, dict(env, CODEX_PATH=str(native)))

    monkeypatch.setattr(recovery.ApprovalOwner, "launch_environment", launch)
    monkeypatch.setattr(acp, "verify_adapter", lambda *_: None)
    owners = []
    original_init = recovery.ApprovalOwner.__init__

    def init(owner, *args, **kwargs):
        original_init(owner, *args, **kwargs)
        owners.append(owner)

    monkeypatch.setattr(recovery.ApprovalOwner, "__init__", init)
    scenario = tmp_path / "scenario.json"
    trace = tmp_path / "trace.jsonl"
    handoff = store.attempt_path("project", "mission-001", "attempt-1", "w1")
    scenario.write_text(json.dumps({"mode": mode, "trace": str(trace), "handoff": str(handoff)}))
    config = replace(
        store.config,
        approval_recovery=True,
        worker_acp_command=f"{sys.executable} {FIXTURES / 'approval_recovery_acp.py'} {scenario}",
    )
    runner = ACPNodeRunner(
        config, AssetLoader(config), recovery.RunApprovalContext(RUN, lambda: True)
    )
    children = []
    spawn = asyncio.create_subprocess_exec

    async def tracked(*args, **kwargs):
        child = await spawn(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_exec", tracked)
    node = asyncio.create_task(
        asyncio.wait_for(
            runner.run_node(
                "project",
                "mission-001",
                Task(id="w1", type="work", body="controlled", targets=[], skill="s"),
                "attempt-1",
                store,
            ),
            25,
        )
    )
    try:
        while not node.done() and (not owners or owners[0].phase != "pending"):
            await asyncio.sleep(0.01)
        if not node.done():
            result = await mcp_review(owners[0], content={"confirm_one_submission": True})
            assert result["disposition"] in ("queued", "unavailable", "uncertain")
        handoff_result = await asyncio.wait_for(node, 15)
        rows = [json.loads(line) for line in trace.read_text().splitlines()]
        methods = [row["method"] for row in rows]
        assert methods.count("thread/approveGuardianDeniedAction") <= 1
        assert methods.count("turn/start") <= 2
        if mode in ("success", "delayed_interrupt"):
            assert handoff_result.done is True
            assert methods.count("thread/approveGuardianDeniedAction") == 1
            assert methods.index("override-handler-completed") < methods.index(
                "ordered-handler-completed"
            )
        else:
            assert not handoff_result.done
            assert (
                store.read_provider_review("project", "mission-001", "attempt-1", "w1") is not None
            )
        if mode == "outstanding":
            assert methods.count("thread/approveGuardianDeniedAction") == 0
        assert all(child.returncode is not None for child in children)
        assert owners[0].event is None and not owners[0].root.exists()
        assert not any(
            b"approval-CANARY" in p.read_bytes()
            for p in store.bucket_root("project").rglob("*.json")
        )
    finally:
        if not node.done():
            node.cancel()
        await asyncio.gather(node, return_exceptions=True)


async def test_unmodified_pinned_adapter_owned_relay(tmp_path, monkeypatch):
    """Actual installed ACP adapter, controlled native backend, no provider."""
    import shutil
    from unrest_harness.acp_runner import ACPClient
    from tests.test_acp_runner import _safe_policy
    from unrest_harness.provider_review import ProviderReviewCapture

    adapter_value = os.environ.get("UNREST_CONTROLLED_ADAPTER")
    if adapter_value is None:
        pytest.skip("explicit controlled installed-adapter location required")
    adapter = Path(adapter_value).resolve(strict=True)
    node = shutil.which("node")
    assert node is not None
    recovery.verify_adapter((node, str(adapter)), str(tmp_path), dict(os.environ))
    owner, store, _ = setup_owner(tmp_path)
    native, _ = backend(tmp_path, monkeypatch)
    trace = tmp_path / "native-methods.jsonl"
    environment = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "CODEX_HOME": str(tmp_path / "codex"),
        "CODEX_PATH": str(native),
        "CODEX_CONFIG": '{"sandbox_mode":"workspace-write","approval_policy":"on-request"}',
        "CONTROLLED_APPROVAL_TRACE": str(trace),
    }
    relayed = await owner.launch_environment(environment)
    assert {k: v for k, v in relayed.items() if k != "CODEX_PATH"} == {
        k: v for k, v in environment.items() if k != "CODEX_PATH"
    }
    process = await asyncio.create_subprocess_exec(
        node,
        str(adapter),
        env=relayed,
        cwd=tmp_path,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    owner.bind_adapter(process.pid)
    stderr = asyncio.create_task(process.stderr.read())
    client = ACPClient(process, str(tmp_path), _safe_policy("codex"), {})
    prompt = None
    review = None
    try:
        await client.start()
        await asyncio.wait_for(
            client.send_request(
                "initialize",
                {
                    "protocolVersion": 1,
                    "clientCapabilities": {},
                    "clientInfo": {"name": "controlled-readiness", "version": "1"},
                },
            ),
            5,
        )
        session = await asyncio.wait_for(
            client.send_request("session/new", {"cwd": str(tmp_path), "mcpServers": []}), 5
        )
        assert session["sessionId"] == "thread-1"
        store.begin_provider_review(*owner.binding, "thread-1")
        client.provider_review = ProviderReviewCapture(
            "thread-1", lambda block: store.save_provider_review(*owner.binding, "thread-1", block)
        )
        client.retain_provider_denial = True
        prompt = asyncio.create_task(
            client.send_request(
                "session/prompt",
                {
                    "sessionId": "thread-1",
                    "prompt": [{"type": "text", "text": "controlled local input"}],
                },
            )
        )
        await asyncio.wait_for(owner.denied.wait(), 5)
        await client._write(
            {"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": "thread-1"}}
        )
        await asyncio.wait_for(prompt, 5)
        await asyncio.wait_for(owner.settled.wait(), 5)
        assert client.provider_review.blocked.review == ReviewIdentity(
            "thread-1", "turn-1", "review-1"
        )
        pending = asyncio.create_task(owner.wait_for_review())
        review = asyncio.create_task(mcp_review(owner, content={"confirm_one_submission": True}))
        assert await asyncio.wait_for(pending, 5)
        assert await owner.submit()
        assert (await review)["disposition"] == "queued"
        client.provider_review = ProviderReviewCapture("thread-1", lambda _: None)
        result = await asyncio.wait_for(
            client.send_request(
                "session/prompt",
                {
                    "sessionId": "thread-1",
                    "prompt": [{"type": "text", "text": "controlled continuation"}],
                },
            ),
            5,
        )
        assert result["stopReason"] == "end_turn"
        methods = [json.loads(line)["method"] for line in trace.read_text().splitlines()]
        assert methods.count("thread/approveGuardianDeniedAction") == 1
        assert methods.count("turn/start") == 2
        assert methods.index("override-handler-completed") < methods.index(
            "ordered-handler-completed"
        )
        assert client.provider_review.blocked is None
    finally:
        for task in (prompt, review):
            if task is not None and not task.done():
                task.cancel()
        await owner.close()
        await client.cleanup()
        await asyncio.gather(
            *(t for t in (prompt, review) if t is not None), return_exceptions=True
        )
        await stderr
    assert process.returncode is not None
    with pytest.raises(ProcessLookupError):
        os.killpg(process.pid, 0)


@pytest.mark.parametrize(
    "boundary",
    [
        "success",
        "cancel",
        "crash",
        "cancel_after_send",
        "crash_after_send",
        "cancel_after_continue",
        "crash_after_continue",
    ],
)
async def test_durable_run_owner_and_restart_never_revives(tmp_path, monkeypatch, boundary):
    from unrest_harness.run_control import RunControl, TERMINAL_RUN_STATES
    import signal
    import time

    root = tmp_path / "run-fixture"
    root.mkdir()
    owner, store, _ = setup_owner(root)
    native, _ = backend(tmp_path, monkeypatch)
    scenario = tmp_path / "run-scenario.json"
    trace = tmp_path / "run-methods.jsonl"
    handoff = store.attempt_path("project", "mission-001", "attempt-1", "w1")
    scenario.write_text(
        json.dumps(
            {
                "mode": (
                    "drop_ack"
                    if boundary.endswith("after_send")
                    else "continuation_hold"
                    if boundary.endswith("after_continue")
                    else "success"
                ),
                "trace": str(trace),
                "handoff": str(handoff),
            }
        )
    )
    run_home = tmp_path / "run-home"
    run_home.mkdir()
    worker_environment = {
        "PYTHONPATH": str(Path(__file__).resolve().parents[1])
        + os.pathsep
        + str(Path(recovery.__file__).resolve().parent.parent),
        "UNREST_HOME": str(root / "home"),
        "UNREST_PROJECTS_DIR": str(root / "home" / "projects"),
        "CONTROLLED_RUN_ROOT": str(root),
        "CONTROLLED_RUN_NATIVE": str(native),
        "CONTROLLED_RUN_TRACE": str(trace),
        "CONTROLLED_RUN_COMMAND": f"{sys.executable} {FIXTURES / 'approval_recovery_acp.py'} {scenario}",
    }
    control = RunControl(
        run_home,
        executor_ref="tests.fixtures.approval_run_executor:execute",
        worker_environment=worker_environment,
    )
    admitted = control.submit_run(
        "advance_project", {"project_id": "project", "max_steps": 1}, "controlled-idem"
    )
    cursor = recovery.cursor_path(owner.config, admitted.run_id, "review-1")
    cutoff = time.monotonic() + 20
    while not cursor.exists() and time.monotonic() < cutoff:
        assert control.inspect_run(admitted.run_id).state not in TERMINAL_RUN_STATES
        await asyncio.sleep(0.02)
    assert cursor.exists()
    value = json.loads(cursor.read_text())
    assert control.inspect_run(admitted.run_id).state == "running"
    owner.config = replace(owner.config, harness_home=root / "home")
    review = None
    try:
        if boundary.endswith(("after_send", "after_continue")):
            owner.context = recovery.RunApprovalContext(admitted.run_id, lambda: True)
            review = asyncio.create_task(
                mcp_review(owner, content={"confirm_one_submission": True}, run_id=admitted.run_id)
            )
            cutoff = time.monotonic() + 5
            while time.monotonic() < cutoff:
                methods = [json.loads(line)["method"] for line in trace.read_text().splitlines()]
                if (
                    methods.count("turn/start") == 2
                    if boundary.endswith("after_continue")
                    else "thread/approveGuardianDeniedAction" in methods
                ):
                    break
                await asyncio.sleep(0.01)
            assert methods.count("thread/approveGuardianDeniedAction") == 1
            if boundary.endswith("after_continue"):
                assert methods.count("turn/start") == 2
        if boundary == "success":
            # Actual admitted process, actual request-associated controlled MCP
            # response; never represented as a real host-human response.
            owner.context = recovery.RunApprovalContext(admitted.run_id, lambda: True)
            result = await mcp_review(
                owner, content={"confirm_one_submission": True}, run_id=admitted.run_id
            )
            assert result["disposition"] == "queued"
        elif boundary in ("cancel", "cancel_after_send", "cancel_after_continue"):
            await asyncio.to_thread(
                control.cancel_run, admitted.run_id, "controlled cancellation", "cancel-idem"
            )
        else:
            # Kill only the owner: surviving relay/adapter must observe EOF and
            # reap their owned children, without test-driven group cleanup.
            os.kill(value["owner_pid"], signal.SIGKILL)
        cutoff = time.monotonic() + 15
        while time.monotonic() < cutoff:
            control.recover()
            summary = control.inspect_run(admitted.run_id)
            if summary.state in TERMINAL_RUN_STATES:
                break
            await asyncio.sleep(0.02)
        assert summary.state in TERMINAL_RUN_STATES
        assert (
            await mcp_review(
                owner, content={"confirm_one_submission": True}, run_id=admitted.run_id
            )
        )["disposition"] == "unavailable"
        methods = [json.loads(line)["method"] for line in trace.read_text().splitlines()]
        assert methods.count("thread/approveGuardianDeniedAction") == (
            1 if boundary == "success" or boundary.endswith(("after_send", "after_continue")) else 0
        )
        assert methods.count("turn/start") <= (
            2 if boundary == "success" or boundary.endswith("after_continue") else 1
        )
        assert not any(b"approval-CANARY" in p.read_bytes() for p in root.rglob("*.json"))
        if boundary.startswith("crash"):
            relay_root = Path(value["socket"]).parent
            cutoff = time.monotonic() + 12
            while relay_root.exists() and time.monotonic() < cutoff:
                await asyncio.sleep(0.02)
            assert not relay_root.exists()
            rows = [json.loads(line) for line in trace.read_text().splitlines()]
            pids = {row["pid"] for row in rows}
            assert sum(row["method"] == "controlled-owned-process" for row in rows) == 2
            cutoff = time.monotonic() + 5
            while time.monotonic() < cutoff:
                live = set()
                for pid in pids:
                    try:
                        os.kill(pid, 0)
                        live.add(pid)
                    except ProcessLookupError:
                        pass
                if not live:
                    break
                await asyncio.sleep(0.02)
            else:
                pytest.fail("owned process survived owner loss")

    finally:
        if review is not None:
            review.cancel()
            await asyncio.gather(review, return_exceptions=True)
        try:
            os.killpg(os.getpgid(value["owner_pid"]), signal.SIGKILL)
        except ProcessLookupError:
            pass


async def test_duplicate_review_does_not_open_or_clobber_first_form(tmp_path):
    owner, _, _ = setup_owner(tmp_path)
    reader, writer, pending = await install_pending(owner)
    calls = []
    gate = asyncio.Event()
    first = asyncio.create_task(
        mcp_review(owner, content={"confirm_one_submission": True}, calls=calls, gate=gate)
    )
    try:
        while not calls:
            await asyncio.sleep(0)
        duplicate_calls = []
        result = await mcp_review(
            owner, content={"confirm_one_submission": True}, calls=duplicate_calls
        )
        assert result["disposition"] == "unavailable"
        assert duplicate_calls == [] and len(calls) == 1 and owner.phase == "reviewing"
        gate.set()
        assert await asyncio.wait_for(pending, 2)
        submission = asyncio.create_task(owner.submit())
        assert await read_frame(reader, 32768) == {"command": "submit", "id": 1}
        await write_frame(writer, {"id": 1, "result": "queued"}, 32768)
        assert await submission
        assert (await first)["disposition"] == "queued"
        assert await owner.submit() is False
    finally:
        gate.set()
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()


async def test_exact_expiry_boundary_and_fixed_retention(tmp_path, monkeypatch):
    import time

    owner, _, _ = setup_owner(tmp_path)
    before = time.monotonic()
    reader, writer, pending = await install_pending(owner)
    try:
        assert before + 300 <= owner.expiry <= time.monotonic() + 300
        original_expiry = owner.expiry
        with monkeypatch.context() as patch:
            patch.setattr(
                recovery, "time", SimpleNamespace(monotonic=lambda: original_expiry - 0.000001)
            )
            assert owner.available()
            patch.setattr(recovery, "time", SimpleNamespace(monotonic=lambda: original_expiry))
            assert not owner.available()
        assert owner.expiry == original_expiry
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()


async def test_real_deadline_timer_erases_memory_and_cleans_reader(tmp_path):
    import time

    owner, _, _ = setup_owner(tmp_path, deadline=time.monotonic() + 0.2)
    reader, writer, pending = await install_pending(owner)
    try:
        assert await asyncio.wait_for(pending, 1) is False
        assert owner.event is None
        assert not owner.submit_requested
    finally:
        writer.close()
        await writer.wait_closed()
        await owner.close()


async def test_pending_inspection_reference_is_read_only(tmp_path):
    controller, store, _ = controller_fixture(tmp_path)
    owner = recovery.ApprovalOwner(
        replace(store.config, approval_recovery=True),
        recovery.RunApprovalContext(RUN, lambda: True),
        store,
        "project",
        "mission-001",
        "attempt-1",
        "w1",
        store.attempt_path("project", "mission-001", "attempt-1", "w1"),
        (),
    )
    reader, writer, pending = await install_pending(owner)
    try:

        def bytes_now():
            return {
                str(p): p.read_bytes()
                for p in store.bucket_root("project").rglob("*")
                if p.is_file()
            }

        before = bytes_now()
        view = controller.inspect_project("project")
        assert RUN in view.frontier and "denial_id=review-1" in view.frontier
        assert "approval-CANARY" not in view.model_dump_json()
        assert bytes_now() == before
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()


async def test_completion_commits_during_human_response_before_submit(tmp_path):
    """The real completion inode, not a separate approval-only mutex."""
    from unrest_harness.storage import completion_lock

    owner, _, _ = setup_owner(tmp_path)
    reader, writer, pending = await install_pending(owner)
    review = asyncio.create_task(mcp_review(owner, content={"confirm_one_submission": True}))
    submission = None
    try:
        assert await asyncio.wait_for(pending, 2)
        with completion_lock(owner.handoff):
            submission = asyncio.create_task(owner.submit())
            await asyncio.sleep(0.03)
            assert not submission.done()  # readers remain live under contention
            owner.handoff.write_text("{}")
        assert await asyncio.wait_for(submission, 2) is False
        assert owner.phase == "reviewing" and owner.pending is None
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(read_frame(reader, 32768), 0.03)
    finally:
        review.cancel()
        if submission is not None:
            submission.cancel()
        await asyncio.gather(review, *([submission] if submission else []), return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()


async def test_cleanup_failure_preserves_first_and_exhausts_owned_paths(tmp_path, monkeypatch):
    owner, _, _ = setup_owner(tmp_path)
    reader, writer, pending = await install_pending(owner)
    root, cursor, reference = owner.root, owner.cursor, owner.reference
    assert root.exists() and cursor.exists() and reference.exists()
    original = owner.server.wait_closed

    async def fail_after_closed():
        await original()
        raise OSError("controlled cleanup failure")

    monkeypatch.setattr(owner.server, "wait_closed", fail_after_closed)
    try:
        with pytest.raises(OSError, match="controlled cleanup failure"):
            await owner.close()
        assert owner.event is None and not root.exists()
        assert not cursor.exists() and not reference.exists()
        assert not owner.tasks
        assert await reader.read() == b""
        with pytest.raises(OSError, match="controlled cleanup failure"):
            await owner.close()  # same retained cleanup result, never restart
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        writer.close()
        await writer.wait_closed()


async def test_host_disconnect_during_form_never_submits(tmp_path):
    owner, _, _ = setup_owner(tmp_path)
    reader, writer, pending = await install_pending(owner)
    calls, gate = [], asyncio.Event()
    review = asyncio.create_task(
        mcp_review(owner, content={"confirm_one_submission": True}, calls=calls, gate=gate)
    )
    try:
        while not calls:
            await asyncio.sleep(0)
        review.cancel()
        await asyncio.gather(review, return_exceptions=True)
        assert await asyncio.wait_for(pending, 2) is False
        assert not owner.submit_requested
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(read_frame(reader, 32768), 0.03)
    finally:
        gate.set()
        review.cancel()
        pending.cancel()
        await asyncio.gather(review, pending, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()


async def test_host_waits_for_submission_receipt(tmp_path):
    """An intermediate submitting state is not a completed host response."""
    owner, _, _ = setup_owner(tmp_path)
    reader, writer, pending = await install_pending(owner)
    review = asyncio.create_task(mcp_review(owner, content={"confirm_one_submission": True}))
    submission = None
    try:
        assert await asyncio.wait_for(pending, 2)
        submission = asyncio.create_task(owner.submit())
        assert await read_frame(reader, 32768) == {"command": "submit", "id": 1}
        assert owner.phase == "submitting"
        await asyncio.sleep(0.08)
        assert not review.done()
        await write_frame(writer, {"id": 1, "result": "queued"}, 32768)
        assert await asyncio.wait_for(submission, 2)
        assert (await asyncio.wait_for(review, 2))["disposition"] == "queued"
        assert await owner.submit() is False
    finally:
        review.cancel()
        if submission is not None:
            submission.cancel()
        await asyncio.gather(review, *([submission] if submission is not None else []),
                             return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        await owner.close()


async def test_real_deadline_expires_during_settlement_handshake(tmp_path, monkeypatch):
    owner, _, _ = setup_owner(tmp_path)
    received, expired = asyncio.Event(), asyncio.Event()
    read, write = recovery.read_frame, write_frame

    async def held_settlement(reader, limit):
        message = await read(reader, limit)
        if message.get("event") == "settled":
            received.set()
            await expired.wait()
        return message

    async def expire_before_settlement(writer, message, limit):
        await write(writer, message, limit)
        if message.get("event") == "settled":
            await received.wait()
            owner.expiry = recovery.time.monotonic() + 0.02
            await owner._expire()
            expired.set()

    monkeypatch.setattr(recovery, "read_frame", held_settlement)
    monkeypatch.setitem(globals(), "write_frame", expire_before_settlement)
    writer = pending = None
    try:
        reader, writer, pending = await asyncio.wait_for(install_pending(owner), 2)
        assert received.is_set() and expired.is_set()
        assert not owner.settled.is_set()
        assert await asyncio.wait_for(pending, 1) is False
        assert owner.event is None
        assert not owner.submit_requested
    finally:
        expired.set()
        try:
            if pending is not None:
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
            if writer is not None:
                writer.close()
                await writer.wait_closed()
        finally:
            await owner.close()
