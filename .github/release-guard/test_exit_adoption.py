"""A held follower exit resumes only after real reparenting admission."""
from types import SimpleNamespace

import pytest

import linux_trace
from linux_trace import OwnedTrace
import approval_adoption
from approval_launch import CRASH
from content_manifest import Refused


def test_kernel_exit_stop_remains_held_until_observer_accepts(monkeypatch):
    trace=object.__new__(OwnedTrace)
    ready=[False]
    calls=[]
    trace.on_exit=lambda current,pid:ready[0]
    trace.deferred_exits={}
    trace.records=[]
    trace.selective=True
    trace.pending={}
    trace.stopped={12:0}
    trace.harvested={12}
    monkeypatch.setattr(linux_trace,'ptrace',lambda *args:calls.append(args))
    monkeypatch.setattr(linux_trace.time,'monotonic',lambda:10.0)
    assert trace._exiting(12,256) is False
    assert trace.deferred_exits=={12:(256,10.0)} and not trace.records
    trace._resume_exits()
    assert not calls and trace.stopped=={12:0}
    ready[0]=True
    trace._resume_exits()
    assert calls==[(7,12)] and trace.records==[{'kind':'kernel_exit','pid':12,'raw':256}]
    assert not trace.deferred_exits and not trace.stopped and not trace.harvested


def test_held_exit_cannot_wait_beyond_provenance_deadline(monkeypatch):
    trace=object.__new__(OwnedTrace)
    trace.deferred_exits={12:(0,10.0)}
    monkeypatch.setattr(linux_trace.time,'monotonic',lambda:30.001)
    with pytest.raises(TimeoutError):
        trace._resume_exits()


@pytest.mark.parametrize('mutation',[None,'adopted','other-case','other-child','parent-alive','not-ready'])
def test_exit_hold_is_only_the_exact_ready_follower(monkeypatch,mutation):
    worker={'birth':SimpleNamespace(pid=11)}
    actor={'birth':SimpleNamespace(pid=12),'body_ready':mutation!='not-ready','intent':{}}
    process=SimpleNamespace(adopted_identity={} if mutation=='adopted' else None)
    owner=SimpleNamespace(exit=None if mutation=='parent-alive' else (1,9))
    host=SimpleNamespace(case='foreign' if mutation=='other-case' else CRASH[0],executed=lambda row:True,
        ledger=SimpleNamespace(process=lambda birth:owner if birth.pid==11 else process))
    monkeypatch.setattr(approval_adoption,'followers',lambda host:(worker,[actor]))
    if mutation=='not-ready':
        with pytest.raises(Refused,match='before ready generation'):
            approval_adoption.exiting(host,12)
    else:
        assert approval_adoption.exiting(host,99 if mutation=='other-child' else 12) is (mutation is not None)
