"""Finite ordinary admission mutations; real original execution is separate CI."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from types import MappingProxyType

import pytest

from effect_proposals import proposal
from test_proposal_support import operands
from content_manifest import Refused
from ordinary_acp import CASES, MOCK, PINS, expected, plain_environment
import ordinary_acp
from test_role_data_oracle import ordinary_environment as environment
from source_observer import Observer
from process_ledger import Birth


from ordinary_acp import TEST
NEGATIVE_CASES = tuple(TEST + '::' + name for name in (
    *(f'test_owned_node_local_rejection_starts_no_mcp_client_or_protocol[{command}-{role}]'
      for command in ('empty', 'whitespace', 'tokenization', 'empty-argv0', 'missing', 'argv0-nul', 'later-argv-nul', 'unencodable')
      for role in ('work', 'validate')),
    *(f'test_owned_node_rejects_malformed_os_fields_before_any_launch_work[{malformation}-{field}-{role}]'
      for malformation in ('nul', 'unencodable') for field in ('cwd', 'env_key', 'env_value', 'path')
      for role in ('work', 'validate')),
    *(f'test_owned_node_rejects_illegal_environment_name_before_any_launch_work[{role}]' for role in ('work', 'validate')),
    *(f'test_owned_node_obstruction_starts_no_mcp_client_or_protocol[{fixture}-{category}-{role}]'
      for fixture, category in (('directory', 'directory'), ('non_executable', 'not_executable')) for role in ('work', 'validate')),
    'test_terminal_local_rejection_starts_no_mcp_client_or_protocol',
))

@pytest.mark.parametrize('mutation',[None,'environment','cwd','program','generation'])
def test_original_mock_agent_bare_sleep_is_bound_to_actual_owned_fixture(tmp_path,monkeypatch,mutation):
    import os
    from types import SimpleNamespace
    import owned_fixture
    from ordinary_acp import MOCK_CASE
    original=owned_fixture.acquire
    monkeypatch.setattr(owned_fixture,'acquire',lambda path,owned,prefix,owner:original(path,owned,prefix,os.getuid()))
    monkeypatch.setattr(ordinary_acp,'system_sleep',lambda:'b'*64)
    base=tmp_path/'pytest'/(MOCK_CASE.split('::')[1][:30]+'0')
    (base/'workspace').mkdir(parents=True)
    root=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
    root_env={'HOME':'/owned/home','TMPDIR':'/owned/tmp','PATH':'/usr/bin:/bin'}
    env=environment(MOCK_CASE,base,root_env)
    raw_env={**root_env,'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':MOCK_CASE+' (call)',
        **{key:env[key] for key in ('UNREST_NODE_ID','UNREST_NODE_TYPE','UNREST_HANDOFF_PATH')}}
    calls=[]
    host=SimpleNamespace(case=MOCK_CASE,meta={'checkout':str(root),'owned':str(tmp_path)},
        binding={'entry':{'path':'/native','sha256':'a'*64}},fixture_roots={},intents={},
        meta_environment=lambda:root_env,launch_owner=lambda actor:None,root_only=lambda actor:None)
    def admit(*args,**kwargs):
        calls.append(args)
        host.intents[1]={}
        return {'ticket':1,'token':'bound'}
    host.admit_launch=admit
    raw={'case':MOCK_CASE,'executable':'sleep','argv':['sleep','30'],'cwd':str(root),'environment':raw_env,'stdin':None}
    if mutation=='environment':
        raw_env['UNREST_NODE_ID']='other'
    elif mutation=='cwd':
        raw['cwd']=str(base)
    elif mutation=='program':
        raw['argv'][1]='1'
    elif mutation=='generation':
        host.fixture_roots[MOCK_CASE]=('different',0,0)
    if mutation is None:
        assert proposal(host,{'role':'root'},raw)['translated']==['sleep','30']
        assert calls[0][1].executable=='/usr/bin/sleep'
    else:
        with pytest.raises(Refused):
            proposal(host,{'role':'root'},raw)
        assert not calls


class CallbackTrap:
    def __eq__(self, other):
        pytest.fail("admission invoked caller equality")

    def __ne__(self, other):
        pytest.fail("admission invoked caller inequality")

    def __getitem__(self, key):
        pytest.fail("admission invoked mapping lookup")

    def __len__(self):
        pytest.fail("admission invoked mapping length")

    def __iter__(self):
        pytest.fail("admission invoked caller iteration")

    def __hash__(self):
        return hash("PATH")


def test_original_ordinary_files_are_byte_pinned():
    checkout = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
    for name, pin in PINS.items():
        assert hashlib.sha256((checkout / name).read_bytes()).hexdigest() == pin
    assert (checkout / MOCK).read_text().count("from unrest_harness") == 0


def test_mapping_proxy_refuses_custom_underlying_mapping_without_callbacks():
    with pytest.raises(Refused, match="underlying dictionary"):
        plain_environment(MappingProxyType(CallbackTrap()))
    with pytest.raises(Refused, match="primitives"):
        plain_environment(MappingProxyType({"PATH": CallbackTrap()}))
    assert plain_environment(MappingProxyType({"PATH": "/usr/bin:/bin"})) == {
        "PATH": "/usr/bin:/bin"
    }


@pytest.mark.parametrize("case", CASES)
def test_ordinary_independent_environment_and_no_crashed_sibling_route(tmp_path, case):
    root_environment = {
        "HOME": "/owned/home",
        "TMPDIR": "/owned/tmp",
        "PATH": "/usr/bin:/bin",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    result = environment(case, tmp_path, root_environment)
    assert set(result) == {
        "HOME",
        "TMPDIR",
        "PATH",
        "UNREST_CAPABILITY_PROFILE",
        "UNREST_CAPABILITY_POLICY_VERSION",
        "UNREST_HOME",
        "UNREST_PROJECT_ID",
        "UNREST_MISSION_ID",
        "UNREST_NODE_ID",
        "UNREST_NODE_TYPE",
        "UNREST_HANDOFF_PATH",
    } | ({"ANTHROPIC_API_KEY"} if case == CASES[2] else set())
    assert "v-crash" not in result["UNREST_HANDOFF_PATH"]
    assert result["UNREST_HOME"] == str(tmp_path / ".unrest")
    assert result["UNREST_CAPABILITY_PROFILE"] == "safe"


@pytest.mark.parametrize(
    "mutation",
    ("case", "site", "argv", "cwd", "environment", "pin", "owner", "script", "translated"),
)
def test_host_refuses_ordinary_request_mutations(tmp_path, mutation):
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = False, []
    observer.root_birth = Birth(1, 1, 1, 1, "test-boot", 20000)
    observer.finished, observer.case, observer.serial = False, CASES[0], 0
    observer.meta = {"mounts": {}, "owned": str(tmp_path), "checkout": str(tmp_path / "checkout")}
    observer.binding = {"entry": {"path": "/pinned/python", "sha256": "a" * 64}}
    observer.intents = {}
    cwd = tmp_path / "pytest/case/workspace"
    cwd.mkdir(parents=True)
    result = expected(
        CASES[0],
        "mock-acp",
        str(cwd),
        Path(observer.meta["checkout"]),
        "/pinned/python",
        "a" * 64,
        observer.meta_environment(),
        tmp_path,
        observed=environment(CASES[0],cwd.parent,observer.meta_environment()),
    )
    request = operands(result)
    changed = deepcopy(request)
    if mutation == "case":
        changed["case"] = CASES[1]
    elif mutation == "site":
        changed["source_line"] = 410
    elif mutation == "argv":
        changed["argv"].append("--foreign")
    elif mutation == "cwd":
        changed["cwd"] = str(tmp_path)
    elif mutation == "environment":
        changed["environment"]["FORBIDDEN"] = "1"
    elif mutation == "pin":
        changed["executable_sha256"] = "b" * 64
    elif mutation == "owner":
        changed["owner"] = "unrelated-caller"
    elif mutation == "script":
        changed["script_sha256"] = "b" * 64
    else:
        changed["translated"] = ["--foreign"]
    actor = {"birth": observer.root_birth, "role": "root"}
    with pytest.raises(Refused):
        proposal(observer, actor, changed)
    assert observer.intents == {}
    assert proposal(observer, actor, request)["ok"] is True
    with pytest.raises(Refused):
        proposal(observer, actor, request)


def test_native_fixture_keeps_original_executable_and_no_python_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(ordinary_acp, "system_sleep", lambda: "b" * 64)
    env = {
        "HOME": "/home",
        "TMPDIR": "/tmp",
        "PATH": "/usr/bin:/bin",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    result = expected(
        CASES[0], "sleep", str(tmp_path), tmp_path, "/python", "a" * 64, env, tmp_path
    )
    assert result.argv == ("/bin/sleep", "30")
    assert result.payload_kind == "native"
    assert dict(result.environment) == {
        **env,
        "PYTEST_VERSION": pytest.__version__,
        "PYTEST_CURRENT_TEST": CASES[0] + " (call)",
    }


@pytest.mark.parametrize("field", ("case", "executable", "argv", "cwd", "environment", "stdin"))
def test_constructor_options_refuse_callbacks_before_comparing(field):
    from effect_proposals import proposal
    from types import SimpleNamespace

    host = SimpleNamespace(case=CASES[0], launch_owner=lambda actor: None)
    raw = {
        "case": CASES[0],
        "executable": "/python",
        "argv": ["/python"],
        "cwd": "/owned",
        "environment": {},
        "stdin": None,
    }
    raw[field] = CallbackTrap()
    with pytest.raises(Refused):
        proposal(host, {}, raw)


def test_ordinary_cleanup_refuses_group_before_observing_any_process(monkeypatch):
    from test_controlled_signal import signal_model

    observer, parent, child, payload = signal_model(monkeypatch, CASES[0])
    child["role"] = "mock-acp"
    payload.update(signal=15, group=True)
    assert observer.dispatch(parent, {"kind": "custody_signal", "payload": payload}) == {
        "ok": True,
        "live": False,
    }
    assert not child["signals"]


def test_no_launch_catalogue_preserves_original_parameters_and_ids():
    import ast
    import itertools
    from ordinary_acp import TEST

    tree = ast.parse(
        (
            next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
            / TEST
        ).read_text()
    )
    names = {case.split("::")[1].split("[")[0] for case in NEGATIVE_CASES}
    collected = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name not in names:
            continue
        dimensions = []
        for call in reversed(node.decorator_list):
            if (
                not isinstance(call, ast.Call)
                or not isinstance(call.func, ast.Attribute)
                or call.func.attr != "parametrize"
            ):
                continue
            values = ast.literal_eval(call.args[1])
            ids = next(
                (ast.literal_eval(key.value) for key in call.keywords if key.arg == "ids"), None
            )
            dimensions.append(
                ids
                or ["-".join(value) if isinstance(value, tuple) else str(value) for value in values]
            )
        for values in itertools.product(*dimensions):
            collected.append(
                TEST + "::" + node.name + ("[" + "-".join(values) + "]" if values else "")
            )
    assert tuple(collected) == NEGATIVE_CASES and len(NEGATIVE_CASES) == 39


@pytest.mark.parametrize("case", NEGATIVE_CASES)
def test_no_launch_cases_have_no_process_route(tmp_path, case):
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = False, []
    observer.root_birth = Birth(1, 1, 1, 1, "test-boot", 20000)
    observer.finished, observer.case, observer.intents = False, case, {}
    actor = {"birth": observer.root_birth, "role": "root"}
    with pytest.raises(Refused):
        proposal(observer, actor, {'case':case,'executable':'/pinned/python','argv':['/pinned/python'],
            'cwd':'/source','environment':{},'stdin':None})
    assert observer.intents == {}


@pytest.mark.parametrize('case',ordinary_acp.STARTUP_CASES)
@pytest.mark.parametrize('mutation',[None,'bytes','mode','outside'])
def test_startup_failure_uses_exact_original_owned_non_executable_format(tmp_path,monkeypatch,case,mutation):
    import os
    import owned_fixture
    import content_manifest

    acquire=owned_fixture.acquire
    monkeypatch.setattr(owned_fixture,'acquire',lambda path,owned,prefix,owner:acquire(path,owned,prefix,os.getuid()))
    read=content_manifest.read_regular
    monkeypatch.setattr(content_manifest,'read_regular',lambda path,*args,**kwargs:read(path,*args,**{**kwargs,'uid':os.getuid()}))
    base=tmp_path/'pytest'/(case.split('::')[1][:30]+'0')
    workspace=base/'workspace'
    workspace.mkdir(parents=True)
    suffix='work' if case==ordinary_acp.STARTUP_CASES[0] else 'validate' if case==ordinary_acp.STARTUP_CASES[1] else 'reviewer'
    file=workspace/('invalid-format-'+suffix)
    file.write_bytes(b'mode executable, intentionally invalid format\n')
    file.chmod(0o700)
    if mutation=='bytes':
        file.write_bytes(b'#!/bin/sh\nexit 0\n')
    elif mutation=='mode':
        file.chmod(0o600)
    elif mutation=='outside':
        workspace=tmp_path
    if mutation is None:
        value=expected(case,'session-invalid',str(workspace),Path('/checkout'),'/native','a'*64,
            {'HOME':'/home','TMPDIR':'/tmp','PATH':'/usr/bin:/bin'},tmp_path,
            observed=environment(case,base,{'HOME':'/home','TMPDIR':'/tmp','PATH':'/usr/bin:/bin'}))
        assert value.argv==('./invalid-format-'+suffix,) and value.executable==str(file)
        assert value.payload_kind=='expected-exec-failure'
        assert value.payload_sha256==hashlib.sha256(file.read_bytes()).hexdigest()
        assert not any(key.startswith('CODEX') for key,_ in value.environment)
    else:
        with pytest.raises((Refused,OSError)):
            expected(case,'session-invalid',str(workspace),Path('/checkout'),'/native','a'*64,
                {'HOME':'/home','TMPDIR':'/tmp','PATH':'/usr/bin:/bin'},tmp_path,
            observed=environment(case,base,{'HOME':'/home','TMPDIR':'/tmp','PATH':'/usr/bin:/bin'}))


@pytest.mark.parametrize('case',(*ordinary_acp.TEMPLATE_CASES,*ordinary_acp.BATCH_CASES))
def test_mock_family_preserves_original_policy_environment(tmp_path,case):
    from unrest_harness.acp_runner import _acp_subprocess_env
    from unrest_harness.capability_policy import load_capability_policy,resolve_role_capability
    from unrest_harness.providers import PROVIDERS
    root=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
    workspace=tmp_path/'workspace'
    workspace.mkdir()
    record=tmp_path/'.unrest/projects/p1'
    record.mkdir(parents=True)
    provider=case.rsplit('[',1)[1][:-1].split('-')[-1]
    root_env={'HOME':str(tmp_path),'TMPDIR':str(tmp_path),'PATH':'/usr/bin:/bin'}
    observer_env=environment(case,tmp_path,root_env)
    if case in ordinary_acp.TEMPLATE_CASES:
        root_env.update(ordinary_acp.template_environment(case,root))
        observer_env.update({key:value for key,value in root_env.items() if key in ('LANG','PATH')})
    policy=resolve_role_capability(PROVIDERS[provider],role='worker' if observer_env['UNREST_NODE_TYPE']=='work' else 'validator',
        policy=load_capability_policy(root/'src/unrest_harness/bundled'),
        profile='safe',workspace=workspace,project_record=record)
    internal={key:value for key,value in observer_env.items() if key.startswith('UNREST_')}
    actual=_acp_subprocess_env(PROVIDERS[provider],policy=policy,internal=internal,host_environment=root_env)
    assert actual==observer_env


@pytest.mark.parametrize('case',(*ordinary_acp.TEMPLATE_CASES,*ordinary_acp.BATCH_CASES))
@pytest.mark.parametrize('mutation',(None,'identity','payload','environment','fixture','generation'))
def test_added_mock_launches_have_closed_identity_environment_and_quota(tmp_path,monkeypatch,case,mutation):
    import os
    from types import SimpleNamespace
    import owned_fixture
    acquire=owned_fixture.acquire
    monkeypatch.setattr(owned_fixture,'acquire',lambda path,owned,prefix,uid:acquire(path,owned,prefix,os.getuid()))
    root=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
    base=tmp_path/'pytest'/(case.split('::')[1][:30]+'0')
    cwd=base/'workspace'
    cwd.mkdir(parents=True)
    root_env={'HOME':'/owned/home','TMPDIR':'/owned/tmp','PATH':'/usr/bin:/bin'}
    fixture_env=environment(case,base,root_env)
    if case in ordinary_acp.TEMPLATE_CASES:
        fixture_env.update({key:value for key,value in ordinary_acp.template_environment(case,root).items() if key in ('LANG','PATH')})
    value=expected(case,'mock-acp',str(cwd),root,'/native','a'*64,root_env,tmp_path,observed=fixture_env)
    raw=operands(value)
    raw.pop('source_line',None)
    calls=[]
    host=SimpleNamespace(case=case,meta={'checkout':str(root),'owned':str(tmp_path)},
        binding={'entry':{'path':'/native','sha256':'a'*64}},fixture_roots={},intents={},
        meta_environment=lambda:root_env,launch_owner=lambda actor:None,root_only=lambda actor:None)
    def admit(*args,**kwargs):
        calls.append((args,kwargs))
        return {'ticket':1,'token':'bound'}
    host.admit_launch=admit
    if mutation=='identity':
        raw['environment']['UNREST_NODE_ID']='foreign'
    elif mutation=='payload':
        raw['argv'][1]='/foreign.py'
    elif mutation=='environment':
        raw['environment']['PYTHONPATH']='/foreign'
    elif mutation=='fixture':
        raw['cwd']=str(tmp_path)
    elif mutation=='generation':
        host.fixture_roots[case]=('foreign',0,0)
    if mutation is None:
        assert proposal(host,{'role':'root'},raw)['translated']==['/native','-I','-S',str(root/MOCK)]
        assert calls[0][1]['maximum']==(2 if case in ordinary_acp.BATCH_CASES else 1)
    else:
        with pytest.raises((Refused,FileNotFoundError)):
            proposal(host,{'role':'root'},raw)
        assert not calls
