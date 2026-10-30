"""Intentional crash statuses stay separate from successful primitive retries."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from fixed_inline import SEQUENCES
from source_observer import Observer
import fixed_leaves as completion

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


@pytest.mark.parametrize('case',completion.COMPLETION_CASES)
def test_each_primitive_keeps_original_path_phase_literal_and_quota(tmp_path,monkeypatch,case):
    monkeypatch.setattr(completion,'OWNER',os.getuid())
    suffix,phase=completion.COMPLETION_CASES[case]
    root=tmp_path/'pytest'/(case.split('::')[1].split('[')[0][:30]+'0')
    root.mkdir(parents=True)
    host=SimpleNamespace(case=case,meta={'checkout':str(ROOT),'owned':str(tmp_path)},fixture_roots={})
    for operation in SEQUENCES[case]:
        argv=['/native/python','-c','placeholder',str(root/suffix),*((phase,) if operation=='crash' and phase is not None else ())]
        value=completion.expected(host,operation,argv,str(ROOT),{'PATH':'/bin'},argv[0],'a'*64)
        assert value.argv[:2]==('/native/python','-c') and value.argv[3:]==tuple(argv[3:])
        assert 'os._exit(73)' in value.argv[2] if operation=='crash' else 'publish_completion_json' in value.argv[2]
        assert dict(value.environment)=={'PATH':'/bin'}
    with pytest.raises(Refused):
        completion.expected(host,'undeclared',argv,str(ROOT),{},argv[0],'a'*64)


@pytest.mark.parametrize('operation,status,accepted',[('crash',73,True),('crash',0,True),('crash',-15,False),('retry',0,True),('retry',73,True)])
def test_primitive_application_status_is_left_to_original_assertions(operation,status,accepted):
    case=next(iter(completion.COMPLETION_CASES))
    birth=object()
    host=object.__new__(Observer)
    host.ledger=SimpleNamespace(process=lambda value:SimpleNamespace(terminal=(3,status<<8,status)))
    actor={'role':'fixed-inline','case':case,'birth':birth,'token':'owned','body_ready':True,'signals':set()}
    host.intents={1:{'birth':birth,'token':'owned','role':'fixed-inline','case':case,'consumed':True,'fixed_operation':operation}}
    host.intents[1].update(ticket=1,role=actor['role'],case=actor['case'])
    actor['intent']=host.intents[1]
    assert host.completed_child(actor)==accepted
    actor['body_ready']=False
    assert not host.completed_child(actor)
    actor['body_ready']=True
    host.intents[1]['consumed']=False
    assert not host.completed_child(actor)
