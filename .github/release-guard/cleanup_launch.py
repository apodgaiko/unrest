"""Finite original cleanup transport cases, module entry and native Git operands."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from content_manifest import Refused, native_digest
from launch_policy import build_expected
from ordinary_acp import PRODUCT, PINS as ACP_PINS

TEST = 'tests/test_acp_cleanup.py'
SCRIPT = 'tests/fixtures/cleanup_acp_process.py'
SERVER = 'src/unrest_harness/server.py'
PINS = {PRODUCT: ACP_PINS[PRODUCT], TEST: '8903f87610c61684a4db0dcf22f771ed5a9f75bcade8ce4f1c528378b1c992ae',
    SCRIPT: 'f4b1c4ca59b7550e5bcd43210e487b0f979c3133196ff39470eae36b76726959',
    SERVER: '166a002df8676817407a4345078e61135139e6a2ffc99e5bf3fa923117c07efc',
    'tests/test_provider_review.py': 'dd9962020bcf265bc6a4e35de8ca7fe557666a1d0e63fa325b4ad955c2465a5e'}
CASES = tuple(TEST + '::' + name for name in (
    'test_recorded_transport_failures[success-work]',
    'test_recorded_transport_failures[array_id-work]',
    'test_cleanup_faults_and_repeated_cancellation[cancel-work]'))
OFFLINE = {'FASTMCP_CHECK_FOR_UPDATES': 'off'}

RECORDED = tuple(TEST + f'::test_recorded_transport_failures[{variant}-{role}]'
                 for variant in ('deep_json', 'array_id', 'object_id', 'success')
                 for role in ('work', 'validate', 'terminal_reviewer'))
FAULTS = tuple(TEST + f'::test_cleanup_faults_and_repeated_cancellation[{variant}-{role}]'
               for variant in ('reader', 'client', 'progress', 'cancel', 'primary')
               for role in ('work', 'validate', 'terminal_reviewer'))
SAVED = tuple(TEST + f'::test_saved_review_observer_compatibility[{variant}]'
              for variant in ('observer', 'cancel', 'transport'))
ALL_CASES = (*RECORDED, *FAULTS)
EXECUTION_CASES = (*ALL_CASES, *SAVED)
GROUPS = (CASES, RECORDED, FAULTS, ALL_CASES, SAVED)
CREDENTIAL = {'OPENAI_API_KEY': 'controlled-secret-observer-value'}


def selection(case):
    if type(case) is not str or case not in EXECUTION_CASES:
        raise Refused('cleanup finite case declaration')
    if case in SAVED:
        return False, case.rsplit('[', 1)[1][:-1], 'terminal_reviewer'
    variant, role = case.rsplit('[', 1)[1][:-1].split('-', 1)
    return case in RECORDED, variant, role


def module_mode(case):
    return {'work': 'worker', 'validate': 'validator', 'terminal_reviewer': 'terminal-reviewer'}[selection(case)[2]]


def child_count(case):
    recorded, _, role = selection(case)
    return (5 if role == 'work' else 4) if recorded else 2


def git_completion(case):
    recorded, _, role = selection(case)
    return recorded and role == 'work'


def base_path(value, owned):
    if type(value) is not str:
        raise Refused('cleanup base path type')
    path = Path(value)
    if (not path.is_absolute() or str(path.resolve(strict=True)) != value
            or path.parent != owned / 'pytest' or path.stat().st_uid != 20000):
        raise Refused('cleanup owned case directory')
    return path


def scenario(case, base):
    recorded, variant, role = selection(case)
    if case in SAVED:
        record = {'role': role, 'progress': True, 'receipt': str(base / 'receipt'),
                  'raw': json.dumps({'jsonrpc': '2.0', 'id': [], 'result': {}}) if variant == 'transport' else None}
    elif not recorded:
        record = {'role': role, 'no_handoff': True}
    else:
        raw = (None if variant == 'success' else '[' * 10000 + '0' + ']' * 10000 if variant == 'deep_json'
               else json.dumps({'jsonrpc': '2.0', 'id': [] if variant == 'array_id' else {}, 'result': {}}))
        record = {'raw': raw, 'role': role, 'receipt': str(base / 'receipt')}
    return json.dumps(record).encode()


def snapshot_path(directory, case):
    if case not in EXECUTION_CASES:
        raise Refused('cleanup snapshot case')
    return directory / ('scenario-' + hashlib.sha256(case.encode()).hexdigest() + '.json')


def environment(base, root_environment, *, agent, case=CASES[0]):
    recorded, _, role = selection(case)
    result = {key: root_environment[key] for key in ('HOME', 'TMPDIR', 'PATH')}
    home = base / 'home'
    result.update(UNREST_CAPABILITY_PROFILE='safe', UNREST_CAPABILITY_POLICY_VERSION='1',
        UNREST_HOME=str(home), UNREST_PROJECT_ID='project', UNREST_MISSION_ID='mission-001')
    if role == 'terminal_reviewer':
        result['UNREST_TERMINAL_REVIEW_PATH'] = str(home / 'projects/project/.unrest-runtime/missions/mission-001/terminal-reviews/attempt-1.json')
    else:
        result.update(UNREST_NODE_ID='w1', UNREST_NODE_TYPE=role,
            UNREST_HANDOFF_PATH=str(home / 'projects/project/.unrest-runtime/missions/mission-001/attempts/attempt-1__w1.json'))
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


def read_pipe(pid, descriptor):
    if type(pid) is not int or pid <= 0 or type(descriptor) is not int or not 3 <= descriptor <= 1024:
        raise Refused('cleanup inventory descriptor primitive')
    path = Path('/proc') / str(pid) / 'fd' / str(descriptor)
    before = path.stat()
    file = path.parent.parent / 'fdinfo' / str(descriptor)
    with file.open('rb') as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise Refused('cleanup inventory descriptor information bound')
    flags = [row[6:].strip() for row in raw.splitlines() if row.startswith(b'flags:')]
    if (len(flags) != 1 or not flags[0] or len(flags[0]) > 16
            or any(character not in b'01234567' for character in flags[0])
            or int(flags[0], 8) & ~os.O_CLOEXEC):
        raise Refused('cleanup inventory must be a blocking read descriptor')
    after = path.stat()
    if (not stat.S_ISFIFO(before.st_mode) or before.st_uid != 20000
            or (before.st_dev, before.st_ino, before.st_mode, before.st_uid) !=
               (after.st_dev, after.st_ino, after.st_mode, after.st_uid)):
        raise Refused('cleanup original inventory pipe')
    return [descriptor, before.st_dev, before.st_ino]


def system_git():
    path = Path('/usr/bin/git')
    for member in (Path('/'), Path('/usr'), Path('/usr/bin'), path):
        info = member.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o6022:
            raise Refused('cleanup system Git custody')
        if (member == path and (not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111)
                or member != path and not stat.S_ISDIR(info.st_mode)):
            raise Refused('cleanup system Git type')
    return native_digest(path)


def expected(case, role, base, native, native_pin, checkout, root_environment, *, port=None, descriptor=None):
    if case not in EXECUTION_CASES:
        raise Refused('cleanup finite case')
    home = base / 'workspace'
    vector: tuple[str, ...]
    payload: str | None
    if role == 'cleanup-acp':
        vector = (native, str(checkout / SCRIPT), str(base / 'scenario.json'))
        executable, pin, kind, payload = native, native_pin, 'python-script', PINS[SCRIPT]
        env = environment(base, root_environment, agent=True, case=case)
        cwd = str(home)
    elif role == 'mcp':
        if type(port) is not int or not 0 < port <= 65535 or type(descriptor) is not int or not 3 <= descriptor <= 1024:
            raise Refused('cleanup finite listener or descriptor')
        vector = (native, '-m', 'unrest_harness', '--mode', module_mode(case), '--transport', 'streamable-http',
                  '--host', '127.0.0.1', '--port', str(port), '--sensitive-inventory-fd', str(descriptor))
        executable, pin, kind, payload = native, native_pin, 'python-module', PINS[SERVER]
        env = environment(base, root_environment, agent=False, case=case)
        cwd = str(home)
    elif role in ('git-init', 'git-commit', 'git-observe') and (case in RECORDED if role != 'git-observe' else git_completion(case)):
        arguments = {'git-init': ('init', '-q', str(home)),
            'git-commit': ('-c', 'user.name=Controlled', '-c', 'user.email=controlled@example.invalid',
                           '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '--allow-empty', '-qm', 'Controlled'),
            'git-observe': ('rev-parse', 'HEAD')}[role]
        vector, executable, pin, kind, payload = ('git', *arguments), '/usr/bin/git', system_git(), 'native', None
        env = ({**environment(base, root_environment, agent=False, case=case), **OFFLINE} if role == 'git-observe' else
               {**root_environment, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'})
        cwd = str(checkout) if role == 'git-init' else str(home)
    else:
        raise Refused('cleanup undeclared launch role')
    return build_expected('cleanup:' + role, case, executable, pin, vector, tuple(sorted(env.items())), cwd, kind, payload)


def translated(result, directory):
    if result.payload_kind == 'native':
        return (result.executable, *result.argv[1:])
    argv = (result.argv[0], '-I', '-S', *result.argv[1:])
    if result.rule == 'cleanup:cleanup-acp':
        argv = (*argv[:-1], str(snapshot_path(directory, result.case)))
    return argv
