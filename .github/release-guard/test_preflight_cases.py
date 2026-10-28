"""Complete-module discovery and explicit zero-effect case contracts."""
from pathlib import Path
from types import SimpleNamespace
import threading
import pytest

from content_manifest import Refused
from preflight_cases import CASES,NO_EFFECT
from plan_launch import CASES as LAUNCHES
from source_entry import Policy
from source_root import NoEffectCalls

ROOT=Path(__file__).resolve().parents[4]


def test_module_collection_matches_full_ordered_inventory_before_bodies(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    collected=[]
    class Collector:
        def pytest_collection_finish(self,session):
            collected.extend(item.nodeid for item in session.items)
    code=pytest.main(['--collect-only','-q','-o','addopts=','-p','pytest_asyncio.plugin','-p','pytest_mock','tests/test_launch_preflight.py'],plugins=[Collector()])
    assert code==0 and tuple(collected)==CASES
    assert len(CASES)==54 and len(NO_EFFECT)==45 and set(CASES)==set(LAUNCHES)|NO_EFFECT
    assert not set(LAUNCHES)&NO_EFFECT


def policy():
    value=object.__new__(Policy)
    value.poison=False
    records=[]
    value.client=SimpleNamespace(request=lambda kind,payload:records.append(kind))
    value.profile={'role':'root'}
    value.case=next(iter(NO_EFFECT))
    value.local=threading.local()
    value.calls=NoEffectCalls(value,None)
    return value,records


def test_no_effect_process_attempt_stays_fatal_when_caught():
    value,records=policy()
    with pytest.raises(Refused,match='undeclared process caller'):
        value.audit('subprocess.Popen',('/usr/bin/true',['/usr/bin/true'],'/owned',{}))
    assert value.poison and records==['guard-refusal']


@pytest.mark.parametrize('method,arguments',[('listener',()),('signal',(123,15,False))])
def test_no_effect_endpoint_and_signal_requests_are_sticky(method,arguments):
    value,records=policy()
    with pytest.raises(Refused):
        getattr(value.calls,method)(*arguments)
    assert value.poison and records==['guard-refusal']


def test_complete_module_run_uses_normal_discovery_not_selected_nodeids(monkeypatch,tmp_path):
    import source_entry,source_root
    requests=[]
    value=SimpleNamespace(profile={'role':'root','owned':str(tmp_path),'cases':list(CASES)},poison=False,client=SimpleNamespace(request=lambda *args:requests.append(args)))
    monkeypatch.setattr(source_entry,'ACTIVE',value)
    def run(arguments,plugins):
        assert arguments[-1]=='tests/test_launch_preflight.py'
        assert not any('::' in arg for arg in arguments)
        plugins[0].completed=list(CASES)
        return 0
    monkeypatch.setattr(source_root.pytest,'main',run)
    assert source_root.main()==0
    assert len(requests)==1 and requests[0][0]=='root-finish'


@pytest.mark.parametrize('with_child',[False,True])
def test_no_effect_host_requires_zero_children_not_observed_child_count(with_child):
    from source_observer import Observer
    from process_ledger import Birth
    observer=object.__new__(Observer)
    root=Birth(100,100,99,1,'boot',20000)
    case=next(iter(NO_EFFECT))
    actor={'birth':root,'role':'root','case':case}
    observer.root_birth=root
    observer.finished=False
    observer.case=case
    observer.actors={100:actor}
    observer.eof_drains={}
    observer.intents={}
    observer.completed=[]
    retired=[]
    observer.endpoints=SimpleNamespace(tickets={},retire_case=retired.append)
    if with_child:
        observer.actors[101]={'role':'foreign','case':case}
        with pytest.raises(Refused,match='actual cleanup incomplete'):
            observer.dispatch(actor,{'kind':'case-finish','payload':{'case':case}})
        assert not retired and not observer.completed
    else:
        assert observer.dispatch(actor,{'kind':'case-finish','payload':{'case':case}})=={'ok':True}
        assert retired==[case] and observer.completed==[case]
