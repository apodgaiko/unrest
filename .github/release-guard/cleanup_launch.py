"""Finite original cleanup transport cases, module entry and native Git operands."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import types

from content_manifest import Refused, capture, native_digest
from controlled_startup import Intent
from launch_policy import Observation, Rule, match, render
from ordinary_acp import PRODUCT, PINS as ACP_PINS, plain_environment
from source_owner import Link, active_frames, _namespace

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


def module_site(case):
    return 2247 if selection(case)[2] == 'terminal_reviewer' else 2191


def child_count(case):
    recorded, _, role = selection(case)
    return (5 if role == 'work' else 4) if recorded else 2


def git_completion(case):
    recorded, _, role = selection(case)
    return recorded and role == 'work'


def digest(path):
    return capture(path.parent, [path.name])['files'][0]['sha256']


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
        owner, cwd = PRODUCT + ':spawn_launch', str(home)
    elif role == 'mcp':
        if type(port) is not int or not 0 < port <= 65535 or type(descriptor) is not int or not 3 <= descriptor <= 1024:
            raise Refused('cleanup finite listener or descriptor')
        vector = (native, '-m', 'unrest_harness', '--mode', module_mode(case), '--transport', 'streamable-http',
                  '--host', '127.0.0.1', '--port', str(port), '--sensitive-inventory-fd', str(descriptor))
        executable, pin, kind, payload = native, native_pin, 'python-module', PINS[SERVER]
        env = environment(base, root_environment, agent=False, case=case)
        owner, cwd = PRODUCT + (':_start_terminal_reviewer_mcp' if module_site(case) == 2247 else ':_start_worker_mcp_server'), str(home)
    elif role in ('git-init', 'git-commit', 'git-observe') and (case in RECORDED if role != 'git-observe' else git_completion(case)):
        arguments = {'git-init': ('init', '-q', str(home)),
            'git-commit': ('-c', 'user.name=Controlled', '-c', 'user.email=controlled@example.invalid',
                           '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '--allow-empty', '-qm', 'Controlled'),
            'git-observe': ('rev-parse', 'HEAD')}[role]
        vector, executable, pin, kind, payload = ('git', *arguments), '/usr/bin/git', system_git(), 'native', None
        env = ({**environment(base, root_environment, agent=False, case=case), **OFFLINE} if role == 'git-observe' else
               {**root_environment, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'})
        cwd = str(checkout) if role == 'git-init' else str(home)
        owner = SERVER + ':_completion_context' if role == 'git-observe' else TEST + ':test_recorded_transport_failures'
    else:
        raise Refused('cleanup undeclared launch role')
    return render(Rule('cleanup:' + role, owner, (case,), executable, pin, vector,
                      tuple(sorted(env.items())), cwd, kind, payload), case, owner, {}, {})


def translated(result, directory):
    if result.payload_kind == 'native':
        return (result.executable, *result.argv[1:])
    argv = (result.argv[0], '-I', '-S', *result.argv[1:])
    if result.rule == 'cleanup:cleanup-acp':
        argv = (*argv[:-1], str(snapshot_path(directory, result.case)))
    return argv


class Launches:
    def __init__(self, calls):
        self.calls, self.policy, self.profile = calls, calls.policy, calls.profile
        self.module = sys_module('unrest_harness.acp_runner')
        self.unit = calls.unit(PRODUCT, self.module, calls.mode(self.module))
        self.constructor, self.constructor_code = asyncio.create_subprocess_exec, asyncio.create_subprocess_exec.__code__
        self.plan_type = self.module.LaunchPlan
        self.inventory_module = sys_module('unrest_harness.capability_policy')
        self.inventory_type = self.inventory_module.SensitiveValueInventory

    def select(self, case, audit):
        executable, vector, cwd, env = audit
        frames = active_frames()
        try:
            test = next((frame for frame in frames if frame.f_code is self.calls.test_owner.function.__code__
                         and frame.f_globals is vars(self.calls.tests)), None)
            if test is None:
                # The original fault cases intentionally launch in a separate
                # Task. Bind its root to the retained, externally selected
                # pytest item's actual fixture table, never another task scan.
                if case not in (*FAULTS, *SAVED):
                    raise Refused('cleanup active original case')
                self.calls.test_owner.verify_binding()
                values = _namespace(self.calls.case_item.funcargs)
                _, variant, case_role = selection(case)
                if (type(values) is not dict or type(values.get('fault')) is not str
                        or values['fault'] != variant or case not in SAVED and (type(values.get('role')) is not str
                        or values['role'] != case_role)):
                    raise Refused('cleanup original scheduled case parameters')
                base_value = values.get('tmp_path')
            else:
                self.calls.test_owner.verify(test)
                base_value = test.f_locals.get('tmp_path')
            if type(base_value) is not type(Path('/')):
                raise Refused('cleanup original tmp fixture')
            base = base_path(str(base_value), Path(self.profile['owned']))
            expected_env, port, descriptor = None, None, None
            if executable == 'git':
                role = 'git-init' if vector[1:3] == ['init', '-q'] else 'git-commit'
                line = 131 if role == 'git-init' else 132
                if test is None or test.f_lineno != line or env is not None:
                    raise Refused('cleanup original Git call')
                actual_env = dict(os.environ)
            else:
                constructors = [frame for frame in frames if frame.f_code is self.constructor_code
                                and frame.f_globals is self.constructor.__globals__]
                if len(constructors) != 1:
                    raise Refused('cleanup original asyncio constructor')
                local = constructors[0].f_locals
                if (type(local.get('kwds')) is not dict or any(type(k) is not str for k in local['kwds'])
                        or type(local.get('stdout')) is not int or local['stdout'] != -1
                        or type(local.get('stderr')) is not int or local['stderr'] != -1
                        or type(local.get('limit')) is not int or local['limit'] != 8 * 1024 * 1024):
                    raise Refused('cleanup original constructor options')
                kw = local['kwds']
                role = 'mcp' if vector[1:3] == ['-m', 'unrest_harness'] else 'cleanup-acp'
                name = ('_start_terminal_reviewer_mcp' if module_site(case) == 2247 else '_start_worker_mcp_server') if role == 'mcp' else 'spawn_launch'
                cls = self.module.ACPNodeRunner
                function = vars(cls)[name] if role == 'mcp' else vars(self.module)[name]
                links = (Link(cls, name, function),) if role == 'mcp' else (Link(self.module, name, function),)
                qualified = 'ACPNodeRunner.' + name if role == 'mcp' else name
                owner = self.calls.owner(self.unit, self.module, function, qualified, links)
                matches = [frame for frame in frames if frame.f_code is function.__code__ and frame.f_globals is vars(self.module)]
                if len(matches) != 1:
                    raise Refused('cleanup original product launch owner')
                owner.verify(matches[0])
                values = matches[0].f_locals
                line = matches[0].f_lineno
                if role == 'mcp':
                    port, descriptor = values.get('mcp_port'), values.get('read_fd')
                    if (line != module_site(case) or type(port) is not int or type(descriptor) is not int or self.inventory_module.SensitiveValueInventory is not self.inventory_type
                            or type(values.get('sensitive_inventory')) is not self.inventory_type
                            or dict.__len__(values['sensitive_inventory']) != (1 if case in SAVED else 0)
                            or any(type(key) is not str or type(value) is not str for key, value in dict.items(values['sensitive_inventory']))
                            or dict(dict.items(values['sensitive_inventory'])) != (CREDENTIAL if case in SAVED else {})
                            or set(kw) != {'cwd', 'env', 'pass_fds'} or type(kw['pass_fds']) is not tuple
                            or len(kw['pass_fds']) != 1 or type(kw['pass_fds'][0]) is not int or kw['pass_fds'][0] != descriptor
                            or local.get('stdin') is not None or kw['env'] is not env):
                        raise Refused('cleanup original MCP inventory and options')
                    read_pipe(os.getpid(), descriptor)
                else:
                    from ordinary_acp import options
                    plan = values.get('plan')
                    if type(plan) is not self.plan_type or self.module.LaunchPlan is not self.plan_type:
                        raise Refused('cleanup actual LaunchPlan')
                    fields = {key: object.__getattribute__(plan, key) for key in ('argv', 'cwd', 'environment', 'path')}
                    expected_env = options(local, 'mock-acp', fields)
                    if env is not fields['environment'] or type(fields['argv']) is not tuple or tuple(vector) != fields['argv']:
                        raise Refused('cleanup identical launch plan')
                    body = scenario(case, base)
                    if digest(base / 'scenario.json') != hashlib.sha256(body).hexdigest():
                        raise Refused('cleanup original scenario bytes')
                actual_env = plain_environment(env)
                if expected_env is not None and actual_env != expected_env:
                    raise Refused('cleanup original plan environment')
            result = expected(case, role, base, self.profile['native'], self.profile['native_sha256'],
                              Path(self.profile['checkout']), self.profile['environment'], port=port, descriptor=descriptor)
            actual_cwd = self.profile['checkout'] if cwd is None else str(cwd) if (type(cwd) is str or type(cwd) is type(Path('/'))) else None
            if actual_cwd != result.cwd or (executable != 'git' and executable != result.executable):
                raise Refused('cleanup actual executable or cwd')
            observation = Observation(result.executable, result.executable_sha256, tuple(vector),
                                      tuple(sorted(actual_env.items())), actual_cwd, result.payload_kind, result.payload_sha256)
            match((result,), observation, result.owner, case)
            return Intent(result, translated(result, self.policy.directory), line, result.payload_sha256)
        finally:
            del frames


def sys_module(name):
    import sys
    module = sys.modules.get(name)
    if type(module) is not types.ModuleType:
        raise Refused('cleanup original module absent')
    return module
