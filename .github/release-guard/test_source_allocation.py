"""The full-suite allocation is finite and separate from generic/leaf deadlines."""
import ast
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import linux_trace as trace


@pytest.mark.parametrize(('full','seconds','accepted'),[
    (False,180,True),(False,181,False),(True,7200,True),(True,7200.1,False),
    (True,float('inf'),False),(True,float('nan'),False),(1,7200,False)])
def test_full_source_allocation_never_broadens_generic_tracing(monkeypatch,full,seconds,accepted):
    monkeypatch.setattr(trace,'sys',SimpleNamespace(platform='linux'))
    monkeypatch.setattr(trace.os,'uname',lambda:os.uname_result(('Linux','control','test','test','x86_64')))
    pinned=[]
    monkeypatch.setattr(trace._observation,'process_identity',lambda pid:pinned.append(pid) or {'ppid':os.getpid()})
    read,write=os.pipe()
    try:
        if not accepted:
            with pytest.raises(ValueError,match='bounded owned trace'):
                trace.OwnedTrace(42,[],seconds,start_write=write,full_source=full)
            assert pinned==[]
        else:
            before=trace.time.monotonic()
            value=trace.OwnedTrace(42,[],seconds,start_write=write,full_source=full)
            after=trace.time.monotonic()
            assert value.timeout==seconds and before+seconds<=value.deadline<=after+seconds
            assert pinned==[42]
            with pytest.raises(ValueError,match='bounded owned trace'):
                trace.OwnedTrace(42,[],seconds,start_write=write,full_source=full,cleanup_seconds=61)
    finally:
        os.close(read)
        os.close(write)


def test_source_outer_envelopes_and_archive_allocation_are_coherent():
    support=Path(__file__).resolve().parent
    host=ast.parse((support/'source_host.py').read_text())
    worker=next(node for node in host.body if isinstance(node,ast.FunctionDef) and node.name=='worker')
    value=next(node.value for node in worker.body if isinstance(node,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id=='timeout' for target in node.targets))
    assert isinstance(value,ast.IfExp) and ast.unparse(value.test)=='full'
    assert ast.literal_eval(value.body)==7200 and ast.literal_eval(value.orelse)==100
    supervisor=next(node for node in host.body if isinstance(node,ast.FunctionDef) and node.name=='supervise')
    envelopes=[node for node in ast.walk(supervisor) if isinstance(node,ast.IfExp)
        and ast.unparse(node.test)=='archive' and isinstance(node.body,ast.Constant) and type(node.body.value) is int]
    assert len(envelopes)==1 and (envelopes[0].body.value,envelopes[0].orelse.value)==(110,7220)
    shell=ast.parse((support/'ci_shell.py').read_text())
    deadlines=[node.value.value for node in ast.walk(shell) if isinstance(node,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id=='deadline' for target in node.targets)]
    assert sorted(deadlines)==['180','7240']
    assert 'timeout-minutes: 135' in (support.parent/'workflows/ci.yml').read_text()
    assert 135*60>7240>7220>7200
