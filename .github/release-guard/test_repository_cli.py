"""Copied CLI diagnostics keep three exact processes and sealed source imports."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from repository_cli import OWNERS, eligible, proposal


@pytest.mark.parametrize('mutation',[None,'cwd','environment','vector','copy','unwaited','query-owner'])
def test_repository_cli_is_exact_init_console_then_its_single_readonly_query(tmp_path,monkeypatch,mutation):
    import repository_cli
    import prepared_distribution
    import console_entries
    case=OWNERS[0]+'[step-${{ !true }}]'
    checkout=Path(__file__).resolve().parents[2]
    base=tmp_path/'case'
    cwd=base/'repository'
    cwd.mkdir(parents=True)
    monkeypatch.setattr(repository_cli,'retain',lambda *args:base)
    monkeypatch.setattr(repository_cli,'image',lambda:'a'*64)
    monkeypatch.setattr(prepared_distribution,'tree',lambda path: {'bytes':'changed' if mutation=='copy' and path==cwd/'src' else 'same'})
    monkeypatch.setattr(console_entries,'script',lambda *args:('/sealed/unrest','b'*64))
    monkeypatch.setattr(console_entries,'normalized',lambda *args:['/native','-I','-S','/sealed/unrest','check-repository'])
    host=SimpleNamespace(case=case,meta={'checkout':str(checkout),'runtime_root':'/native','dependencies':'/deps'},
        binding={'entry':{'sha256':'a'*64}},intents={},fixture_roots={},
        root_only=lambda actor:None,meta_environment=lambda:{'PATH':'/bin'},
        ledger=SimpleNamespace(reaped=lambda *args:mutation!='unwaited'))
    calls=[]
    def admit(actor,value,role,vector,payload,**options):
        ticket=len(host.intents)+1
        host.intents[ticket]={'case':case,'role':role,'birth':'birth'+str(ticket),'token':'token'+str(ticket),'consumed':True}
        calls.append((actor,value,role,vector,payload,options))
        return {'ok':True,'ticket':ticket,'token':'token'+str(ticket)}
    host.admit_launch=admit
    root={'role':'root','birth':'root'}
    env={'PATH':'/bin','PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    raw={'cwd':str(cwd),'environment':env,'argv':['git','init','--quiet'],'executable':'/usr/bin/git','stdin':None}
    if mutation=='cwd':
        raw['cwd']=str(base/'foreign')
    elif mutation=='environment':
        raw['environment']={**env,'CODEX_PATH':'foreign'}
    elif mutation=='vector':
        raw['argv'].append('--template=foreign')
    if mutation in ('cwd','environment','vector'):
        with pytest.raises(Refused):
            proposal(host,root,raw)
        assert not calls
        return
    assert proposal(host,root,raw)['translated']==['/usr/bin/git','init','--quiet']
    raw={**raw,'argv':['/native/bin/unrest','check-repository'],'executable':'/native/bin/unrest',
         'environment':{**env,'PYTHONPATH':str(cwd/'src')}}
    if mutation in ('copy','unwaited'):
        with pytest.raises(Refused):
            proposal(host,root,raw)
        assert len(calls)==1
        return
    proposal(host,root,raw)
    assert host.intents[2]['python_vector']==['/native','-I','-S','/sealed/unrest','check-repository']
    console={'role':'fixed-inline','birth':'birth2','token':'token2','body_ready':mutation!='query-owner'}
    raw={**raw,'argv':['git','-C',str(cwd),'rev-parse','--show-toplevel'],'executable':'/usr/bin/git'}
    if mutation=='query-owner':
        with pytest.raises(Refused):
            proposal(host,console,raw)
    else:
        proposal(host,console,raw)
        assert len(calls)==3
        with pytest.raises(Refused):
            proposal(host,console,raw)


def test_repository_case_eligibility_is_limited_to_the_four_pinned_owners():
    assert all(eligible(owner+'[parameter]') for owner in OWNERS)
    assert not eligible('tests/test_repository_contract.py::test_foreign[parameter]')
    assert not eligible('tests/foreign.py::'+OWNERS[0].split('::')[1])
