"""Finite custody templates and owned repository negatives; no native launch."""
from pathlib import Path

import pytest

from content_manifest import Refused
from controlled_cases import CASES
from custody_git import command,repository

CASE = next(case for case in CASES if 'test_ack_durability[' in case)


@pytest.mark.parametrize('args',[
    ('init','--initial-branch=main','--object-format=sha1'),('add','.'),
    ('commit','-m','finite fixture'),('rev-parse','HEAD'),('add','--','a'),
    ('diff','--cached','--name-only','a'*40),('commit','--allow-empty','-m','sealed candidate'),
])
def test_closed_original_templates(args):
    result,_ = command(CASE,('/usr/bin/git','--no-replace-objects',*args),'/owned/pytest/case/cohort/base',Path('/owned'))
    assert result.argv[2:] == args and result.stdin is None


@pytest.mark.parametrize('args',[
    ('fetch','https://example.invalid/private'),('clone','/foreign','.'),('add','--','../private'),
    ('-c','core.hooksPath=/foreign','commit','-m','base'),('diff','--cached','--name-only','HEAD'),
    ('commit','-m','foreign'),('add','--','auth.json'),
])
def test_external_or_unbounded_commands_refuse(args):
    with pytest.raises(Refused):
        command(CASE,('/usr/bin/git','--no-replace-objects',*args),'/owned/pytest/case/cohort/base',Path('/owned'))


def test_repository_cannot_leave_the_disposable_case(tmp_path):
    root = tmp_path/'foreign'
    root.mkdir()
    with pytest.raises(Refused):
        repository(str(root),tmp_path,initialize=True)
    with pytest.raises(Refused):
        command(CASE,('/usr/bin/git','--no-replace-objects','rev-parse','HEAD'),str(root),tmp_path)


_ACTIVE = [None]


def _audit(event,args):
    if event == 'subprocess.Popen' and _ACTIVE[0] is not None:
        _ACTIVE[0](args)
        raise RuntimeError('custody selection stopped before exec')


__import__('sys').addaudithook(_audit)


@pytest.mark.parametrize('mutation',[None,'arguments','environment','stdio','timeout'])
def test_actual_original_custody_helper_preexec_and_option_traps(tmp_path,monkeypatch,mutation):
    import custody_git
    from source_calls import Sources
    from unrest_harness import experimental_custody
    calls = object.__new__(Sources)
    calls.profile = {'checkout':str(Path(__file__).resolve().parents[2]),'owned':str(tmp_path)}
    calls.pins = {custody_git.SOURCE:custody_git.PIN}
    gate = custody_git.Calls(calls)
    monkeypatch.setattr(custody_git,'image',lambda:'1'*64)
    original_fields = custody_git.frame_fields
    class Trap:
        def __eq__(self,other):
            pytest.fail('subprocess equality callback')
        def __hash__(self):
            pytest.fail('subprocess hashing callback')
    def fields(frame):
        result = original_fields(frame)
        if frame.f_code is gate.run_code and mutation:
            result = dict(result)
            result['kwargs'] = dict(result['kwargs'])
            if mutation == 'arguments':
                result['popenargs'] = ([Trap()],)
            elif mutation == 'environment':
                result['kwargs']['env'] = {'FOREIGN':Trap()}
            elif mutation == 'stdio':
                result['kwargs']['stdin'] = Trap()
            else:
                result['timeout'] = Trap()
        return result
    monkeypatch.setattr(custody_git,'frame_fields',fields)
    root = tmp_path/'pytest/case/cohort/base'
    root.mkdir(parents=True)
    selected = []
    def inspect(args):
        selected.append(gate.select(CASE,args))
    _ACTIVE[0] = inspect
    try:
        with pytest.raises(RuntimeError if mutation is None else Refused):
            experimental_custody.git(root,'rev-parse','HEAD')
    finally:
        _ACTIVE[0] = None
    assert len(selected) == (1 if mutation is None else 0)


@pytest.mark.parametrize('replacement',['repository','metadata'])
def test_same_path_replacement_cannot_inherit_prior_repository_facts(monkeypatch,replacement):
    import custody_git
    from types import SimpleNamespace
    cwd = '/owned/pytest/case/cohort/base'
    directory = ((cwd,1,10,20000),)
    old = directory,(1,20,20000)
    new = (((cwd,1,11,20000),),(1,20,20000)) if replacement == 'repository' else (directory,(1,21,20000))
    host = SimpleNamespace(case=CASE,meta={'owned':'/owned'},intents={},root_only=lambda actor:None,
        git=SimpleNamespace(custody_roots={(CASE,cwd):old}))
    monkeypatch.setattr(custody_git,'repository',lambda *args,**kwargs:new)
    with pytest.raises(Refused,match='replaced repository generation'):
        custody_git.launch(host,None,{'original':{'argv':['/usr/bin/git','--no-replace-objects','rev-parse','HEAD'],'cwd':cwd}})


@pytest.mark.parametrize('mutation',[None,'operation','second-child','image','repository'])
def test_only_one_same_image_auto_maintenance_child_of_original_commit(monkeypatch,mutation):
    import custody_git
    from types import SimpleNamespace
    parent,birth = 'original-parent','child-birth'
    process = SimpleNamespace(token='commit',exit=None,terminal=None)
    intent = {'case':CASE,'operation':'custody-commit','consumed':True,'cwd':'/owned/pytest/case/base',
        'environment':custody_git.ENVIRONMENT,'executable_sha256':'1'*64}
    identity = ((('root',1,2,20000),),(1,3,20000))
    host = SimpleNamespace(case=CASE,meta={'owned':'/owned'},serial=0,intents={},
        ledger=SimpleNamespace(process=lambda value:process,children={parent:[birth]}),
        git=SimpleNamespace(commands={'commit':intent},helpers={},custody_roots={(CASE,intent['cwd']):identity}))
    monkeypatch.setattr(custody_git,'repository',lambda *args,**kwargs:identity)
    monkeypatch.setattr(custody_git,'image',lambda path:'2'*64 if mutation == 'image' else '1'*64)
    if mutation == 'operation':
        intent['operation'] = 'custody-head'
    elif mutation == 'second-child':
        host.ledger.children[parent].append('foreign')
    elif mutation == 'repository':
        host.git.custody_roots.clear()
    if mutation:
        with pytest.raises(Refused):
            custody_git.reserve_helper(host,birth,parent)
        assert not host.intents
    else:
        custody_git.reserve_helper(host,birth,parent)
        child = host.intents[1]
        assert child['translated'] == ['/usr/lib/git-core/git','maintenance','run','--auto','--no-quiet']
        assert child['parent'] == parent and not child['consumed']
