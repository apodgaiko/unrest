"""Original large-pipe child operands and closed owned workspace."""
from pathlib import Path
from types import SimpleNamespace
import os

import pytest

from content_manifest import Refused
from fixed_inline import DRAIN_CASE,SEQUENCES,GROUPS
from effect_proposals import proposal
import owned_fixture

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


@pytest.mark.parametrize('mutation',[None,'program','env','cwd','descendant'])
def test_original_chatty_child_retains_both_full_pipe_writes(tmp_path,monkeypatch,mutation):
    acquire=owned_fixture.acquire
    monkeypatch.setattr(owned_fixture,'acquire',lambda path,owned,prefix,owner:acquire(path,owned,prefix,os.getuid()))
    workspace=tmp_path/'pytest'/(DRAIN_CASE.split('::')[-1][:30]+'0')/'workspace'
    workspace.mkdir(parents=True)
    host=SimpleNamespace(case=DRAIN_CASE,meta={'owned':str(tmp_path),'checkout':str(ROOT)},
        binding={'entry':{'path':'/native','sha256':'a'*64}},fixture_roots={},intents={},actors={})
    host.meta_environment=lambda:{'PATH':'/usr/bin:/bin'}
    host.launch_owner=lambda actor:None
    admitted=[]
    def admit(*args,**kwargs):
        admitted.append((args,kwargs))
        host.intents[1]={}
        return {'ticket':1,'token':'1'}
    host.admit_launch=admit
    body="import sys; sys.stdout.write('o'*262144); sys.stdout.flush(); sys.stderr.write('e'*262144); sys.stderr.flush()"
    raw={'case':DRAIN_CASE,'executable':'/native','argv':['/native','-c',body],
        'cwd':str(workspace),'environment':{'PATH':'/usr/bin:/bin'},'stdin':None}
    actor={'role':'fixed-inline' if mutation=='descendant' else 'root'}
    if mutation=='program':
        raw['argv'][2]="print('smaller output')"
    elif mutation=='env':
        raw['environment']['EXTRA']='not original'
    elif mutation=='cwd':
        raw['cwd']=str(workspace.parent/'foreign')
    if mutation is None:
        answer=proposal(host,actor,raw)
        assert answer['translated']==['/native','-I','-S','-c',body]
        assert admitted[0][0][1].environment==(('PATH','/usr/bin:/bin'),)
        assert SEQUENCES[DRAIN_CASE]==('drain',) and (DRAIN_CASE,) in GROUPS
    else:
        with pytest.raises(Refused):
            proposal(host,actor,raw)
        assert not admitted
