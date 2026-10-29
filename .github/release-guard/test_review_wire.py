"""Controlled wire fixture scope; these checks do not prove provider acceptance."""

from contextlib import contextmanager

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
import review_wire as wire


def source_files(monkeypatch):
    original, original_fstat = os.stat, os.fstat
    def owner(info):
        if not stat.S_ISREG(info.st_mode):
            return info
        row=list(info)
        row[4]=20000
        return os.stat_result(row)
    monkeypatch.setattr(os,'stat',lambda *args,**kwargs:owner(original(*args,**kwargs)))
    monkeypatch.setattr(os,'fstat',lambda fd:owner(original_fstat(fd)))


@pytest.mark.parametrize(
    "mutation",
    [None, "handoff", "mcp_receipt", "frames", "delay", "many", "raw", "linked", "mode", "outside"],
)
def test_scenario_is_inert_owned_bounded_protocol_data(tmp_path, monkeypatch, mutation):
    source_files(monkeypatch)
    base = tmp_path / "pytest/case"
    base.mkdir(parents=True)
    file = base / "scenario.json"
    value = {"events": [{"update": {"status": "failed"}}], "delay": 0, "raw_frame": None}
    if mutation in ("handoff", "mcp_receipt", "frames"):
        value[mutation] = "forbidden"
    elif mutation == "delay":
        value["delay"] = True
    elif mutation == "many":
        value["events"] *= 4
    elif mutation == "raw":
        value["raw_frame"] = "x" * 70001
    file.write_text(json.dumps(value))
    if mutation == "linked":
        os.link(file, base / "alias")
    elif mutation == "mode":
        file.chmod(0o666)
    elif mutation == "outside":
        file = tmp_path / "scenario.json"
        file.write_text(json.dumps(value))
    if mutation is None:
        assert wire.scenario(file, tmp_path) == file.read_bytes()
        value["raw_frame"] = "x" * 70000
        file.write_text(json.dumps(value))
        assert wire.scenario(file, tmp_path) == file.read_bytes()
    else:
        with pytest.raises(Refused):
            wire.scenario(file, tmp_path)


def test_original_wire_selection_preserves_oversized_parameter_without_large_messages():
    from case_inventory import identity

    cases = wire.CASES
    assert len(cases) == len(set(cases)) == 24
    node = (
        wire.TEST + "::test_malformed_and_oversized_wire_never_become_success[" + "x" * 70000 + "]"
    )
    assert identity(node) in cases and node not in cases
    assert [case for case in cases if wire.count(case) == 2] == [wire.DOUBLE]


@pytest.mark.parametrize(
    "mutation", [None, "environment", "path", "cwd", "entry", "quota", "unreaped", "second"]
)
def test_wire_proposal_is_fixed_and_snapshot_is_byte_current(tmp_path, monkeypatch, mutation):
    source_files(monkeypatch)
    native = "/runtime/python"
    checkout = tmp_path / "source"
    owned = tmp_path / "owned"
    base = owned / "pytest/case"
    base.mkdir(parents=True)
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    file = base / "scenario.json"
    file.write_text(json.dumps({"events": [], "delay": 0, "raw_frame": None}))
    calls = []
    case = wire.DOUBLE if mutation in ("unreaped", "second") else wire.CASES[0]
    environment = {
        "HOME": "/home",
        "PYTEST_VERSION": "9.0.2",
        "PYTEST_CURRENT_TEST": case + " (call)",
    }
    host = SimpleNamespace(
        case=case,
        root_only=lambda actor: None,
        binding={"entry": {"path": native, "sha256": "a" * 64}},
        meta={"checkout": str(checkout), "owned": str(owned)},
        meta_environment=lambda: {"HOME": "/home"},
        directory=profiles,
        intents={},
        ledger=SimpleNamespace(reaped=lambda *args: mutation == "second"),
    )

    def admit(*args, **kwargs):
        calls.append((args, kwargs))
        ticket = max(host.intents, default=0) + 1
        host.intents[ticket] = {"translated":args[3]}
        return {"ok": True, "ticket": ticket, "token": "owned"}

    host.admit_launch = admit
    raw = {
        "argv": [native, str(checkout / wire.SCRIPT), str(file)],
        "stdin": None,
        "cwd": str(checkout),
        "environment": environment,
    }
    if mutation == "environment":
        raw["environment"] = {**environment, "UNDECLARED": "value"}
    elif mutation == "path":
        raw["argv"][-1] = str(tmp_path / "scenario.json")
    elif mutation == "cwd":
        raw["cwd"] = str(owned)
    elif mutation == "entry":
        raw["argv"][1] += ".other"
    elif mutation in ("quota", "unreaped", "second"):
        host.intents[1] = {
            "case": case,
            "role": "review-wire",
            "consumed": True,
            "birth": object(),
            "token": "earlier",
        }
    if mutation in (None, "second"):
        answer = wire.proposal(host, {}, raw)
        snapshot = Path(answer["translated"][-1])
        assert snapshot.read_bytes() == file.read_bytes()
        assert snapshot.stat().st_mode & 0o777 == 0o444
        assert host.intents[answer["ticket"]]["translated"][-1] == str(snapshot)
        file.write_text("changed original")
        assert json.loads(snapshot.read_bytes()) == {"events": [], "delay": 0, "raw_frame": None}
        assert calls[0][0][2] == "review-wire"
        assert calls[0][1]["maximum"] == wire.count(case)
        if mutation == "second":
            host.intents[2].update(
                case=case, role="review-wire", consumed=True, birth=object(), token="second"
            )
            with pytest.raises(Refused, match="quota"):
                wire.proposal(host, {}, raw)
            assert len(calls) == 1
    else:
        with pytest.raises((Refused, FileNotFoundError)):
            wire.proposal(host, {}, raw)
        assert not calls and not list(profiles.iterdir())


@pytest.mark.parametrize("mutation", ["growth", "replacement"])
def test_scenario_read_is_bounded_and_binds_opened_file_generation(tmp_path, monkeypatch, mutation):
    source_files(monkeypatch)
    base = tmp_path / "pytest/case"
    base.mkdir(parents=True)
    file = base / "scenario.json"
    original = json.dumps({"events": [], "delay": 0, "raw_frame": None}).encode()
    file.write_bytes(original)
    original_fdopen=os.fdopen
    limits=[]
    def read(stream,limit):
        limits.append(limit)
        if mutation=='growth' and len(limits)==1:
            file.write_bytes(original+b'x'*200000)
        result=stream.read(limit)
        if mutation=='replacement' and len(limits)==1:
            file.unlink()
            file.write_bytes(original)
        return result
    @contextmanager
    def buffered(fd, *args, **kwargs):
        with original_fdopen(fd, *args, **kwargs) as stream:
            yield SimpleNamespace(read=lambda count: read(stream, count))
    monkeypatch.setattr(os,'fdopen',buffered)
    with pytest.raises(Refused,match='file_read'):
        wire.scenario(file,tmp_path)
    assert limits and all(0<limit<=131073 for limit in limits) and len(limits)<=2


def test_component_collection_and_reports_keep_actual_large_pytest_item(monkeypatch):
    import source_root
    from case_inventory import identity

    node = next(node for node in wire.NODES if len(node) > 70000)
    assert len(wire.NODES) == 24 and tuple(identity(node) for node in wire.NODES) == wire.CASES
    calls = []
    policy = SimpleNamespace(
        profile={"cases": [identity(node)]},
        poison=False,
        client=SimpleNamespace(request=lambda *args: calls.append(args)),
    )
    proof = source_root.OriginalCases(policy)
    monkeypatch.setattr(source_root, "Function", SimpleNamespace)
    item = SimpleNamespace(nodeid=node)
    proof.pytest_collection_finish(SimpleNamespace(items=[item]))
    protocol = proof.pytest_runtest_protocol(item, None)
    next(protocol)
    for phase in ("setup", "call", "teardown"):
        proof.pytest_runtest_logreport(
            SimpleNamespace(nodeid=node, when=phase, outcome="passed", failed=False)
        )
    with pytest.raises(StopIteration):
        next(protocol)
    assert item.nodeid == node and proof.items[0] is item and proof.completed == [identity(node)]
    assert calls == [
        ("case-start", {"case": identity(node)}),
        ("case-finish", {"case": identity(node)}),
    ]


@pytest.mark.parametrize("replace_before_open", [False, True])
def test_fifo_scenario_without_writer_refuses_before_any_blocking_read(
    tmp_path, monkeypatch, replace_before_open
):
    source_files(monkeypatch)
    base = tmp_path / "pytest/case"
    base.mkdir(parents=True)
    file = base / "scenario.json"
    if replace_before_open:
        file.write_text("{}")
    else:
        os.mkfifo(file)
    original_open = os.open
    calls = []

    def opening(path,flags,*args,**kwargs):
        if flags & os.O_DIRECTORY:
            return original_open(path,flags,*args,**kwargs)
        calls.append(flags)
        assert flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW
        if replace_before_open:
            file.unlink()
            os.mkfifo(file)
        return original_open(path,flags,*args,**kwargs)
    monkeypatch.setattr(os,'open',opening)
    monkeypatch.setattr(os,'fdopen',lambda *args, **kwargs:pytest.fail('FIFO must refuse before read'))
    with pytest.raises(Refused,match='nonregular|acquisition_race'):
        wire.scenario(file,tmp_path)
    assert len(calls)==int(replace_before_open)


@pytest.mark.parametrize(
    "code,signals,ready,accepted",
    [
        (0, set(), True, True),
        (-9, {9}, True, True),
        (-9, set(), True, False),
        (-15, {15}, True, True),
        (17, set(), True, True),
        (-9, {9}, False, False),
    ],
)
def test_wire_retirement_requires_ready_and_authorized_cleanup(code, signals, ready, accepted):
    from source_observer import Observer

    actor = {"role": "review-wire", "birth": object(), "body_ready": ready, "signals": signals,"case":"case","token":"owned"}
    host = SimpleNamespace(
        ledger=SimpleNamespace(process=lambda birth: SimpleNamespace(terminal=(1, 0, code)))
    )
    row={key:actor[key] for key in ('role','birth','case','token')}
    row.update(ticket=1,consumed=True)
    host.intents={1:row}
    actor['intent']=row
    assert Observer.completed_child(host, actor) is accepted
