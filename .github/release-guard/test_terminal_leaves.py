"""Original terminal operand parity and closed scope; native execution is separate."""
import ast
import asyncio
import base64
import json
from pathlib import Path
from types import SimpleNamespace
import os
import sys
import hashlib

import pytest

from content_manifest import Refused
from launch_policy import source_unit,assignment,render_string
import terminal_leaves as leaves
import owned_fixture

PIN='ed83ec28c4830354cd4ab0876d6832a0187d211982964d2cf80f449992b46bb6'
POLICY='src/unrest_harness/capability_policy.py'
POLICY_PIN='0aaa3eca3a1b891bcf7458832aeed92768489826fda23320ab000ce3d1df3c30'

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def original_program(case):
    unit=source_unit(ROOT,leaves.TEST,PIN,(case.split('::')[1].split('[')[0],))
    if case==leaves.RAW:
        calls=[node for node in ast.walk(unit) if isinstance(node,ast.Dict) and any(isinstance(key,ast.Constant) and key.value=='args' for key in node.keys)]
        assert len(calls)==1
        key=next(key for key in calls[0].keys if isinstance(key,ast.Constant) and key.value=='args')
        args=ast.literal_eval(calls[0].values[calls[0].keys.index(key)])
        return args[1],{'ZAI_API_KEY':ast.literal_eval(assignment(unit,'secret'))}
    names=ast.literal_eval(assignment(source_unit(ROOT,POLICY,POLICY_PIN),'FINITE_CREDENTIAL_NAMES'))
    observed=(*names,*(f'UNRELATED_ALIAS_{i}' for i in range(len(names))),'HOME','TEMP','SSL_CERT_DIR','NO_PROXY','TMP')
    body=render_string(assignment(unit,'script'),(('observed_names',114,repr(observed)),))
    wrapped=f'terminal-sentinel-1-{names[1].lower()}'
    return body,{'SSL_CERT_DIR':'MONKEY','NO_PROXY':'ordinary-equal-free-value','TMP':base64.urlsafe_b64encode(wrapped.encode()).decode()}


@pytest.mark.parametrize('case',leaves.OPTIONAL)
@pytest.mark.parametrize('mutation',[None,'cwd','env','executable'])
def test_optional_nulls_keep_original_true_image_checkout_and_environment(monkeypatch,case,mutation):
    import git_policy as git_observer
    monkeypatch.setattr(git_observer,'image',lambda path:'b'*64)
    calls=[]
    host=SimpleNamespace(case=case,meta={'checkout':str(ROOT),'owned':'/owned'},fixture_roots={},intents={},
        binding={'entry':{'path':'/native','sha256':'a'*64}},root_only=lambda actor:None,
        meta_environment=lambda:{'PATH':'/bin'})
    def admit(*args,**kwargs):
        calls.append(args)
        host.intents[1]={}
        return {'ticket':1,'token':'bound'}
    host.admit_launch=admit
    raw={'case':case,'stdin':None,'executable':'/usr/bin/true','argv':['/usr/bin/true'],
        'cwd':str(ROOT),'environment':{'PATH':'/bin'}}
    if mutation=='cwd':
        raw['cwd']='/foreign'
    elif mutation=='env':
        raw['environment']['EXTRA']='foreign'
    elif mutation=='executable':
        raw['executable']=raw['argv'][0]='/usr/bin/false'
    if mutation is None:
        assert leaves.proposal(host,{'role':'root'},raw)['translated']==['/usr/bin/true']
        assert calls[0][2]=='terminal-native'
    else:
        with pytest.raises(Refused):
            leaves.proposal(host,{'role':'root'},raw)
        assert not calls


def test_terminal_catalogue_matches_original_collection(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    nodes=[]
    class Collected:
        def pytest_collection_finish(self,session):
            nodes.extend(item.nodeid for item in session.items)
    assert pytest.main(['--collect-only','-q',*leaves.CASES],plugins=[Collected()])==0
    assert tuple(nodes)==leaves.CASES


@pytest.mark.parametrize('case',(leaves.RAW,*leaves.TRANSFORM))
def test_program_is_identical_to_original_test_operands_without_executing_a_child(tmp_path,case):
    body,env=original_program(case)
    assert leaves.PROGRAMS[case]==(hashlib.sha256(body.encode()).hexdigest(),env)
    unit=source_unit(ROOT,leaves.TEST,PIN,(case.split('::')[1].split('[')[0],))
    unit.decorator_list=[]
    names=ast.literal_eval(next(node.value for node in ast.parse((ROOT/POLICY).read_bytes()).body
        if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='FINITE_CREDENTIAL_NAMES' for target in node.targets)))
    captured=[]
    class Client:
        def __init__(self,*args,**kwargs):
            pass
        def set_credential_inventory(self,value):
            pass
        async def _handle_terminal_create(self,value):
            captured.append(value)
            return {'terminalId':'original'}
        async def _handle_terminal_wait(self,value):
            pass
        def _handle_terminal_output(self,value):
            if case==leaves.RAW:
                return {'output':'<redacted:ZAI_API_KEY>'}
            result={name:None for name in (*names,*(f'UNRELATED_ALIAS_{i}' for i in range(len(names))),'HOME','TEMP')}
            return {'output':json.dumps({**result,**env})}
        async def cleanup(self,**kwargs):
            pass
    namespace={'Path':Path,'sys':sys,'os':os,'base64':base64,'json':json,'Any':object,'cast':lambda kind,value:value,
        '_resolved':lambda *args,**kwargs:object(),'build_role_environment':lambda *args,**kwargs:{},
        'finite_credential_values':lambda value:{},'credential_values':lambda *args:{},'ACPClient':Client,
        'FINITE_CREDENTIAL_NAMES':names}
    exec(compile(ast.Module(body=[unit],type_ignores=[]),leaves.TEST,'exec'),namespace)
    kwargs={} if case==leaves.RAW else {'provider_name':'claude','role':'worker','profile':'safe'}
    asyncio.run(namespace[unit.name](tmp_path,**kwargs))
    assert len(captured)==1 and captured[0]['args']==['-c',body]


@pytest.mark.parametrize('mutation',[None,'body','env','cwd','generation','descendant'])
def test_terminal_launch_does_not_grant_other_programs_or_fixture_generations(tmp_path,monkeypatch,mutation):
    acquire=owned_fixture.acquire
    monkeypatch.setattr(leaves,'acquire',lambda path,owned,prefix,owner:acquire(path,owned,prefix,os.getuid()))
    base=tmp_path/'pytest'/(leaves.RAW.split('::')[1][:30]+'0')
    workspace=base/'workspace'
    workspace.mkdir(parents=True)
    body,env=original_program(leaves.RAW)
    def root_only(actor):
        if actor['role']!='root':
            raise Refused('root only')
    host=SimpleNamespace(case=leaves.RAW,meta={'checkout':str(ROOT),'owned':str(tmp_path)},
        binding={'entry':{'path':'/native','sha256':'a'*64}},fixture_roots={},intents={},
        meta_environment=lambda:{'PATH':'/bin'},root_only=root_only)
    calls=[]
    def admit(*args,**kwargs):
        calls.append(args)
        host.intents[1]={}
        return {'ticket':1,'token':'bound'}
    host.admit_launch=admit
    raw={'case':leaves.RAW,'stdin':None,'executable':'/native','argv':['/native','-c',body],
        'cwd':str(workspace),'environment':{'PATH':'/bin',**env}}
    if mutation=='body':
        raw['argv'][2]='print("different")'
    elif mutation=='env':
        raw['environment']['ZAI_API_KEY']='different'
    elif mutation=='cwd':
        raw['cwd']=str(base/'other')
    elif mutation=='generation':
        host.fixture_roots[('terminal',host.case)]=('old',0,0)
    actor={'role':'child' if mutation=='descendant' else 'root'}
    if mutation is None:
        assert leaves.proposal(host,actor,raw)['translated']==['/native','-I','-S','-c',body]
    else:
        with pytest.raises(Refused):
            leaves.proposal(host,actor,raw)
        assert not calls
