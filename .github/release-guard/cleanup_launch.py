"""Finite original cleanup transport cases, module entry and native Git operands."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from content_manifest import Refused
from git_policy import image as system_git
from launch_policy import build_expected
from ordinary_acp import PRODUCT, PINS as ACP_PINS
from review_wire import RUNNER,runner_scenario,SCRIPT as REVIEW_SCRIPT,PIN as REVIEW_PIN,FRAMES,FRAMES_PIN

TEST = 'tests/test_acp_cleanup.py'
SCRIPT = 'tests/fixtures/cleanup_acp_process.py'
SERVER = 'src/unrest_harness/server.py'
PINS = {REVIEW_SCRIPT:REVIEW_PIN,FRAMES:FRAMES_PIN,PRODUCT: ACP_PINS[PRODUCT], TEST: '8903f87610c61684a4db0dcf22f771ed5a9f75bcade8ce4f1c528378b1c992ae',
    SCRIPT: 'f4b1c4ca59b7550e5bcd43210e487b0f979c3133196ff39470eae36b76726959',
    SERVER: 'd1abbe2f76ff874849d113919777efe1ccb8fee0a6327d5eaf27e87892fd886f',
    'tests/test_provider_review.py': 'dd9962020bcf265bc6a4e35de8ca7fe557666a1d0e63fa325b4ad955c2465a5e'}
CASES = tuple(TEST + '::' + name for name in (
    'test_recorded_transport_failures[success-work]',
    'test_recorded_transport_failures[array_id-work]',
    'test_cleanup_faults_and_repeated_cancellation[cancel-work]'))

RECORDED = tuple(TEST + f'::test_recorded_transport_failures[{variant}-{role}]'
                 for variant in ('deep_json', 'array_id', 'object_id', 'success')
                 for role in ('work', 'validate', 'terminal_reviewer'))
FAULTS = tuple(TEST + f'::test_cleanup_faults_and_repeated_cancellation[{variant}-{role}]'
               for variant in ('reader', 'client', 'progress', 'cancel', 'primary')
               for role in ('work', 'validate', 'terminal_reviewer'))
SAVED = tuple(TEST + f'::test_saved_review_observer_compatibility[{variant}]'
              for variant in ('observer', 'cancel', 'transport'))
ALL_CASES = (*RECORDED, *FAULTS)
EXECUTION_CASES = (*ALL_CASES, *SAVED,*RUNNER)
CREDENTIAL = {'OPENAI_API_KEY': 'controlled-secret-observer-value'}


def selection(case):
    if type(case) is not str or case not in EXECUTION_CASES:
        raise Refused('cleanup finite case declaration')
    if case in RUNNER:
        return True,case.rsplit('[',1)[1][:-1],'work'
    if case in SAVED:
        return False, case.rsplit('[', 1)[1][:-1], 'terminal_reviewer'
    variant, role = case.rsplit('[', 1)[1][:-1].split('-', 1)
    return case in RECORDED, variant, role


def base_path(value, owned):
    if type(value) is not str:
        raise Refused('cleanup base path type')
    path = Path(value)
    if (not path.is_absolute() or str(path.resolve(strict=True)) != value
            or path.parent != owned / 'pytest' or path.stat().st_uid != 20000):
        raise Refused('cleanup owned case directory')
    return path


def scenario(case, base):
    from content_manifest import read_regular
    return runner_scenario(case,base) if case in RUNNER else read_regular(base/'scenario.json',65536,uid=20000)[0]


def snapshot_path(directory, case):
    if case not in EXECUTION_CASES:
        raise Refused('cleanup snapshot case')
    return directory / ('scenario-' + hashlib.sha256(case.encode()).hexdigest() + '.json')


def environment(base, root_environment, *, agent, case=CASES[0]):
    recorded, _, role = selection(case)
    from node_environment import environment as role_environment
    result=role_environment(root_environment,base/'home','project','w1',role,'attempt-1')
    if agent:
        result.update(INITIAL_AGENT_MODE='agent', CODEX_CONFIG=json.dumps({
            'sandbox_mode': 'read-only' if role == 'terminal_reviewer' else 'workspace-write', 'approval_policy': 'on-request',
            'model_reasoning_effort': 'medium'}, separators=(',', ':'), sort_keys=True))
    elif role != 'terminal_reviewer':
        result['UNREST_NODE_ASSIGNMENT'] = json.dumps({'targets': ['VAL-CLEANUP'] if recorded and role == 'validate' else [],
                                                     'task_type': role}, separators=(',', ':'))
    if agent and case in SAVED:
        result.update(CREDENTIAL)
    return result


def read_pipe(birth,descriptor):
    from process_ledger import Birth
    from socket_observation import acquire,pipe_descriptor
    if type(birth) is not Birth or birth.uid!=20000:
        raise Refused('cleanup inventory process birth')
    return acquire(birth,descriptor,pipe_descriptor)



def expected(case, role, base, native, native_pin, checkout, root_environment, *, port=None, descriptor=None):
    recorded,_,node_role=selection(case)
    home = base / 'workspace'
    if case in RUNNER:
        from launch_policy import source_unit
        source_unit(checkout,FRAMES,FRAMES_PIN)
    vector: tuple[str, ...]
    payload: str | None
    if role == 'cleanup-acp':
        script=REVIEW_SCRIPT if case in RUNNER else SCRIPT
        vector = (native, str(checkout / script), str(base / 'scenario.json'))
        executable, pin, kind, payload = native, native_pin, 'python-script', PINS[script]
        env = environment(base, root_environment, agent=True, case=case)
        cwd = str(home)
    elif role == 'mcp':
        if type(port) is not int or not 0 < port <= 65535 or type(descriptor) is not int or not 3 <= descriptor <= 1024:
            raise Refused('cleanup finite listener or descriptor')
        vector = (native, '-m', 'unrest_harness', '--mode', {'work':'worker','validate':'validator','terminal_reviewer':'terminal-reviewer'}[node_role], '--transport', 'streamable-http',
                  '--host', '127.0.0.1', '--port', str(port), '--sensitive-inventory-fd', str(descriptor))
        executable, pin, kind, payload = native, native_pin, 'python-module', PINS[SERVER]
        env = environment(base, root_environment, agent=False, case=case)
        cwd = str(home)
    elif role in ('git-init', 'git-commit', 'git-observe') and (case in (*RECORDED,*RUNNER) if role != 'git-observe' else recorded and node_role=='work'):
        arguments = {'git-init': ('init', '-q', str(home)),
            'git-commit': ('-c', 'user.name=Controlled', '-c', 'user.email=controlled@example.invalid',
                           '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '--allow-empty', '-qm', 'Controlled'),
            'git-observe': ('rev-parse', 'HEAD')}[role]
        if case in RUNNER and role=='git-commit':
            arguments=('-c','user.name=Controlled Test','-c','user.email=controlled@example.invalid',
                'commit','--allow-empty','-qm','Controlled completion identity')
        vector, executable, pin, kind, payload = ('git', *arguments), '/usr/bin/git', system_git(), 'native', None
        env = (environment(base, root_environment, agent=False, case=case) if role == 'git-observe' else
               {**root_environment, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'})
        cwd = str(checkout) if role == 'git-init' else str(home)
    else:
        raise Refused('cleanup undeclared launch role')
    return build_expected(case, executable, pin, vector, tuple(sorted(env.items())), cwd, kind, payload)


def translated(result, directory, role):
    if result.payload_kind == 'native':
        return (result.executable, *result.argv[1:])
    argv = (result.argv[0], '-I', '-S', *result.argv[1:])
    if role == 'cleanup-acp':
        argv = (*argv[:-1], str(snapshot_path(directory, result.case)))
    return argv
