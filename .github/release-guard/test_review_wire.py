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
    [None, "handoff", "mcp_receipt", "frames", "delay", "many", "raw", "linked", "mode", "outside", "too-large"],
)
def test_scenario_keeps_current_bytes_with_owned_bounded_acquisition(tmp_path, monkeypatch, mutation):
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
    elif mutation == "too-large":
        value["raw_frame"] = "x" * 131072
    file.write_text(json.dumps(value))
    if mutation == "linked":
        os.link(file, base / "alias")
    elif mutation == "mode":
        file.chmod(0o666)
    elif mutation == "outside":
        file = tmp_path / "scenario.json"
        file.write_text(json.dumps(value))
    if mutation not in ('linked','mode','outside','too-large'):
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
    assert len(cases) == len(set(cases)) == 84
    assert len([case for case in cases if not case.startswith(wire.REPAIR+'::')]) == 63
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
    assert len(wire.NODES) == 84 and tuple(identity(node) for node in wire.NODES) == wire.CASES
    calls = []
    policy = SimpleNamespace(
        children={},
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


@pytest.mark.parametrize('test_file',(wire.FRAMES,wire.REPAIR))
def test_extra_wire_catalogue_matches_the_unmodified_original_collection(monkeypatch,test_file):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    nodes=[]
    class Collected:
        def pytest_collection_finish(self,session):
            nodes.extend(item.nodeid for item in session.items)
    assert pytest.main(['--collect-only','-q','-o','addopts=',test_file],plugins=[Collected()])==0
    import ast
    unit=ast.parse(Path(test_file).read_bytes())
    consumers={fn.name for fn in unit.body if isinstance(fn,ast.AsyncFunctionDef)
        and any(isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='wire' for call in ast.walk(fn))}
    expected=tuple(node for node in nodes if node.split('::')[1].split('[')[0] in consumers)
    assert tuple(node for node in wire.NODES if node.startswith(test_file+'::'))==expected
    runners=tuple(node for node in nodes if node.split('::')[1].startswith('test_actual_runner_'))
    assert tuple(node for node in wire.RUNNER if node.startswith(test_file+'::'))==runners


@pytest.mark.parametrize('case',wire.RUNNER)
@pytest.mark.parametrize('mutation',(None,'handoff','receipt','ordering','command','frame','events'))
def test_runner_keeps_protocol_data_without_reconstructing_application_results(tmp_path,monkeypatch,case,mutation):
    import os
    from tests.test_provider_review_frames import malformed
    frame=malformed('result',{})
    frame['id']='$prompt_id'
    value={'events':[],'frames':[frame],'ordering':case.rsplit('[',1)[1][:-1],
        'handoff':str(tmp_path/'home/projects/project/.unrest-runtime/missions/mission-001/attempts/attempt-1__w1.json'),
        'mcp_receipt':str(tmp_path/'mcp-receipt')}
    if mutation=='handoff':
        value['handoff']='/foreign/handoff'
    elif mutation=='receipt':
        value['mcp_receipt']='/foreign/receipt'
    elif mutation=='ordering':
        value['ordering']='unknown'
    elif mutation=='command':
        value['command']='foreign'
    elif mutation=='frame':
        frame['id']=2
    elif mutation=='events':
        value['events']=[{}]
    body=json.dumps(value).encode()
    (tmp_path/'scenario.json').write_bytes(body)
    original=wire.read_regular
    monkeypatch.setattr(wire,'read_regular',lambda path,bound,**kwargs:original(path,bound,**{**kwargs,'uid':os.getuid()}))
    assert wire.runner_scenario(case,tmp_path)==body
    assert case not in wire.CASES
    with pytest.raises(Refused):
        wire.runner_scenario('foreign',tmp_path)


@pytest.mark.parametrize('case',tuple(case for case in wire.CASES if case.startswith(wire.REPAIR+'::')))
@pytest.mark.parametrize('mutation',(None,'argv','environment','cwd','owner','stdin','quota'))
def test_repair_wire_is_one_pinned_local_fixture_not_native_review(tmp_path,monkeypatch,case,mutation):
    from source_observer import Observer
    source_files(monkeypatch)
    checkout=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
    base=tmp_path/'pytest'/'case'
    base.mkdir(parents=True)
    scenario=base/'scenario.json'
    scenario.write_text('{"events":[],"delay":0,"raw_frame":null}')
    profiles=tmp_path/'profiles'
    profiles.mkdir()
    host=object.__new__(Observer)
    host.case,host.serial,host.root_birth=case,0,'root-birth'
    host.meta={'checkout':str(checkout),'owned':str(tmp_path)}
    host.binding={'entry':{'path':'/native','sha256':'a'*64}}
    host.intents={}
    host.directory=profiles
    host.meta_environment=lambda:{'PATH':'/bin'}
    host.root_only=lambda actor:None if actor['role']=='root' else (_ for _ in ()).throw(Refused('owner'))
    actor={'role':'root','birth':'root-birth'}
    environment={'PATH':'/bin','PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    raw={'argv':['/native',str(checkout/wire.SCRIPT),str(scenario)],'cwd':str(checkout),'environment':environment,'stdin':None}
    if mutation=='argv':
        raw['argv'][1]+='.foreign'
    elif mutation=='environment':
        raw['environment']['EXTRA']='foreign'
    elif mutation=='cwd':
        raw['cwd']=str(base)
    elif mutation=='owner':
        actor['role']='child'
    elif mutation=='stdin':
        raw['stdin']='foreign'
    elif mutation=='quota':
        host.intents[1]={'case':case}
    if mutation:
        with pytest.raises(Refused):
            wire.proposal(host,actor,raw)
        assert not list(profiles.iterdir())
    else:
        answer=wire.proposal(host,actor,raw)
        row=host.intents[answer['ticket']]
        assert row['role']=='review-wire' and row['script_sha256']==wire.PIN
        snapshot=Path(answer['translated'][-1])
        assert snapshot.read_bytes()==scenario.read_bytes() and snapshot.stat().st_mode&0o777==0o444
        with pytest.raises(Refused,match='quota'):
            wire.proposal(host,actor,raw)
        assert len(host.intents)==1
