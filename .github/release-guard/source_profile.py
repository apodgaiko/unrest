"""Closed source profile consumption, before any candidate body."""
from __future__ import annotations

import os
import stat
import fcntl
import hashlib
import json
from pathlib import Path
import sys

from content_manifest import Refused, capture
from plan_launch import CASES as PLAN_CASES, PYTHON as PLAN_PYTHON, expected as plan_expected
from bootstrap_cases import BOOTSTRAP
from controlled_cases import CASES as CONTROLLED, GROUPS as CONTROLLED_GROUPS
from controlled_startup import expected_entry, CASES
from ordinary_acp import ALL_CASES, CASES as ORDINARY_CASES, MOCK, PINS
from cleanup_launch import EXECUTION_CASES as CLEANUP_CASES, GROUPS as CLEANUP_GROUPS, module_mode, SCRIPT, PINS as CLEANUP_PINS, scenario, snapshot_path
from cleanup_inline import NO_LAUNCH, STARTUP, DECLARATIONS, CLIENT_CASES, INFLIGHT, body as inline_body
from linux_observation import credential_identity, process_identity
from process_ledger import Birth, canonical
from git_sites import CASES as GIT_CASES, OWNED_BODY
from session_launch import CASES as SESSION_CASES, GROUPS as SESSION_GROUPS, SCRIPT as SESSION_SCRIPT, PINS as SESSION_PINS, expected as session_expected

from fixed_inline import CASES as FIXED_CASES, SEQUENCES as FIXED_SEQUENCES, expected as fixed_expected

ROOT_COMMAND = 'from source_root import main;raise SystemExit(main())'
METHODS = frozenset({'core-ready', 'body-ready', 'case-start', 'case-finish', 'root-finish',
    'launch-intent', 'launch-return', 'pair-intent', 'pair-seal', 'bind', 'bound', 'listen', 'accepted', 'connect', 'connected',
    'root-http-open', 'root-http-close', 'payload', 'drain_child', 'custody_signal', 'custody_close', 'git-pipe', 'git-output', 'self-stop', 'guard-refusal'})
FIELDS = {'schema', 'role', 'case', 'identity', 'parent', 'observer', 'argv', 'environment', 'cwd',
    'native', 'native_sha256', 'entry_sha256', 'nonce', 'token', 'seal', 'generation',
    'mount_namespace', 'checkout', 'owned', 'dependencies', 'runtime_root', 'mounts',
    'source_sha256', 'support_sha256', 'runtime_sha256', 'dependency_sha256', 'script', 'cases', 'inherited'}


def case_seal(cases):
    if type(cases) not in (tuple, list) or not 0 < len(cases) <= 20000 or any(type(case) is not str or not case or len(case) > 4096 for case in cases):
        raise Refused('source case inventory primitives')
    return {'count': len(cases), 'cases_sha256': hashlib.sha256(json.dumps(cases, separators=(',', ':')).encode()).hexdigest()}


def digest(path: Path) -> str:
    return capture(path.parent, [path.name])['files'][0]['sha256']


def inherited_descriptor(expected, descriptor, info, flags, uid):
    if (type(info) is not os.stat_result or type(flags) is not int or type(uid) is not int
            or type(descriptor) is not int or not 3 <= descriptor <= 1024
            or flags & ~os.O_CLOEXEC or not stat.S_ISFIFO(info.st_mode) or info.st_uid != uid
            or expected != [[descriptor, info.st_dev, info.st_ino]]):
        raise Refused('source ambient inherited descriptor')
    return [descriptor, info.st_dev, info.st_ino]


def readonly_mounts(expected: dict, namespace: str) -> None:
    if type(expected) is not dict or len(expected) not in (4,5) or os.readlink('/proc/self/ns/mnt') != namespace:
        raise Refused('source immutable generation')
    for point, identity in expected.items():
        if (type(point) is not str or type(identity) is not list or len(identity) != 3
                or any(type(value) is not int or value <= 0 for value in identity)):
            raise Refused('source mount identity types')
    observed = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        if len(fields) < 10:
            raise Refused('source mount ABI')
        point = fields[4]
        if point in expected:
            info = os.stat(point, follow_symlinks=False)
            observed[point] = [int(fields[0]), info.st_dev, info.st_ino]
            if 'ro' not in fields[5].split(','):
                raise Refused('source mutable input mount')
    if observed != expected:
        raise Refused('source mount generation changed')


def validate(profile: dict, event: str, arguments: tuple) -> tuple[dict, tuple]:
    if (type(profile) is not dict or set(profile) != FIELDS
            or profile['schema'] != 'unrest.bootstrap-source.v1'
            or type(profile['role']) is not str or profile['role'] not in ('root', 'backend', 'acp', 'delayed-backend', 'mock-acp', 'mcp', 'cleanup-acp', 'cleanup-inline', 'workspace-owned', 'session-adapter', 'session-child', 'session-inline', 'fixed-inline', 'plan-python')
            or type(profile['case']) is not str
            or profile['case'] not in (('<bootstrap>',) if profile['role'] == 'root' else (*BOOTSTRAP, *CONTROLLED, *ORDINARY_CASES, *CLEANUP_CASES, *DECLARATIONS, *GIT_CASES, *SESSION_CASES, *FIXED_CASES, *PLAN_CASES))
            or type(profile['cases']) is not list or tuple(profile['cases']) not in (CASES, BOOTSTRAP, ORDINARY_CASES, ALL_CASES, NO_LAUNCH, tuple(STARTUP), CLIENT_CASES, GIT_CASES, FIXED_CASES, *SESSION_GROUPS, *CLEANUP_GROUPS, *CONTROLLED_GROUPS.values(), PLAN_CASES)):
        raise Refused('source closed profile')
    for key in ('native', 'checkout', 'owned', 'dependencies', 'runtime_root', 'cwd'):
        value = profile[key]
        if type(value) is not str or not value.startswith('/') or str(Path(value).resolve()) != value:
            raise Refused('source canonical profile path')
    for key in ('native_sha256', 'entry_sha256', 'source_sha256', 'support_sha256', 'runtime_sha256',
                'dependency_sha256', 'nonce', 'seal', 'token'):
        value = profile[key]
        size = 32 if key == 'token' else 64
        if type(value) is not str or len(value) != size or any(char not in '0123456789abcdef' for char in value):
            raise Refused('source profile byte identity')
    expected_mounts = {profile['checkout'], profile['dependencies'], profile['runtime_root'], str(Path(__file__).parent)}
    if type(profile['mounts']) is not dict:
        raise Refused('source mounted input dictionary')
    if '/native' in profile['mounts']:
        expected_mounts.add('/native')
    if set(profile['mounts']) != expected_mounts:
        raise Refused('source exact mounted input inventory')
    if Path(profile['native']) != Path(profile['runtime_root']) / 'bin/python-unrest-guard-control':
        raise Refused('source native runtime root')
    actual = process_identity(os.getpid())
    parent, observer = Birth.read(profile['parent']), Birth.read(profile['observer'])
    if (canonical(profile['identity']) != profile['identity'] or canonical(actual) != profile['identity'] or parent.pid != os.getppid()
            or Birth.read(credential_identity(parent.pid)) != parent or observer.uid != 20001
            or (parent != observer if profile['role'] == 'root' else parent.uid != 20000)
            or actual['uids'] != [20000] * 4 or actual['gids'] != [20000] * 4
            or any(actual['capabilities'].values()) or actual['no_new_privs'] != 1 or actual['seccomp'] != 2
            or type(profile['generation']) is not int or profile['generation'] != 1
            or [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode, sys.flags.utf8_mode] != [1, 1, 0, 1]
            or profile['native'] != sys.executable or digest(Path(sys.executable)) != profile['native_sha256']
            or digest(Path(__file__).with_name('native_entry.py')) != profile['entry_sha256']):
        raise Refused('source actual profile binding')
    if (type(profile['environment']) is not dict
            or any(type(key) is not str or type(value) is not str for key, value in profile['environment'].items())
            or profile['environment'] != dict(os.environ) or profile['cwd'] != os.getcwd()
            or type(profile['argv']) is not list or any(type(arg) is not str for arg in profile['argv'])
            or profile['argv'] != sys.orig_argv):
        raise Refused('source actual request binding')
    inherited = profile['inherited']
    if (type(inherited) is not list or (profile['role'] != 'mcp' and inherited)
            or profile['role'] == 'mcp' and (len(inherited) != 1 or type(inherited[0]) is not list
                or len(inherited[0]) != 3 or any(type(value) is not int or value <= 0 for value in inherited[0]))):
        raise Refused('source finite inherited inventory')
    seen = []
    for name in os.listdir('/proc/self/fd'):
        descriptor = int(name)
        if descriptor > 2:
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            info = os.fstat(descriptor)
            seen.append(inherited_descriptor(inherited, descriptor, info,
                                              fcntl.fcntl(descriptor, fcntl.F_GETFL), actual['uids'][0]))
    if seen != inherited:
        raise Refused('source missing inherited inventory')
    readonly_mounts(profile['mounts'], profile['mount_namespace'])
    native = profile['native']
    role, script = profile['role'], profile['script']
    if role == 'root':
        if (profile['cwd'] != profile['checkout'] or script is not None or event != 'cpython.run_command' or arguments != (ROOT_COMMAND + '\n',)
                or profile['argv'] != [native, '-I', '-S', '-c', ROOT_COMMAND]):
            raise Refused('source fixed root body')
    elif role == 'plan-python':
        result=plan_expected(profile['case'],profile['cwd'],Path(profile['owned']),native,profile['native_sha256'])
        if (profile['case']!=PLAN_PYTHON or profile['case'] not in profile['cases'] or script is not None
                or profile['argv']!=list(result.vector) or event!='cpython.run_command'
                or arguments!=(result.expected.argv[2]+'\n',)):
            raise Refused('preflight fixed controlled Python entry')
    elif role == 'fixed-inline':
        if profile['case'] not in FIXED_CASES or profile['case'] not in profile['cases'] or script is not None:
            raise Refused('source fixed inline case')
        choices = [fixed_expected(profile['case'], operation, native, profile['native_sha256'], Path(profile['checkout']), profile['environment']) for operation in FIXED_SEQUENCES[profile['case']]]
        matches = [value for value in choices if profile['argv'] == [native,'-I','-S',*value.argv[1:]]]
        if len(matches) != 1 or event != 'cpython.run_command' or arguments != (matches[0].argv[2] + '\n',):
            raise Refused('source fixed inline exact entry')
    elif role.startswith('session-'):
        result = session_expected(profile['case'], profile['cwd'], Path(profile['checkout']), Path(profile['owned']),
            native, profile['native_sha256'], profile['environment'], child=role == 'session-child')
        inline = result.payload_kind == 'python-command'
        if (profile['case'] not in profile['cases'] or inline != (role == 'session-inline')
                or script != (None if inline else str(Path(profile['checkout']) / SESSION_SCRIPT))
                or profile['argv'] != [native, '-I', '-S', *result.argv[1:]]
                or event != ('cpython.run_command' if inline else 'cpython.run_file')
                or arguments != (('pass\n',) if inline else (script,))
                or not inline and digest(Path(script)) != SESSION_PINS[SESSION_SCRIPT]):
            raise Refused('source exact session entry')
    elif role == 'workspace-owned':
        if (profile['case'] != GIT_CASES[7] or profile['case'] not in profile['cases'] or script is not None
                or Path(profile['cwd']).name != 'process' or Path(profile['cwd']).parent.name != 'trees'
                or not Path(profile['cwd']).is_relative_to(Path(profile['owned']) / 'pytest')
                or profile['argv'] != [native, '-I', '-S', '-c', OWNED_BODY]
                or event != 'cpython.run_command' or arguments != (OWNED_BODY + '\n',)):
            raise Refused('source exact workspace owned body')
    elif role == 'cleanup-inline':
        if (profile['case'] not in DECLARATIONS or profile['case'] not in profile['cases']
                or (profile['cwd'] != profile['checkout'] and not (profile['case'] in INFLIGHT
                    and Path(profile['cwd']).parent == Path(profile['owned']) / 'pytest'
                    and profile['environment'] == {})) or script is not None
                or profile['argv'] != [native, '-I', '-S', '-c', inline_body(profile['case'])]
                or event != 'cpython.run_command' or arguments != (inline_body(profile['case']) + '\n',)):
            raise Refused('source exact inline cleanup body')
    elif role in ('mcp', 'cleanup-acp'):
        if (profile['case'] not in CLEANUP_CASES or profile['case'] not in profile['cases']
                or Path(profile['cwd']).name != 'workspace'
                or Path(profile['cwd']).parent.parent != Path(profile['owned']) / 'pytest'):
            raise Refused('source cleanup role or workspace')
        if role == 'mcp':
            argv = profile['argv']
            if (script is not None or event != 'cpython.run_module' or arguments != ('unrest_harness',)
                    or len(argv) != 15 or argv[:4] != [native, '-I', '-S', '-m'] or argv[4:12] != [
                        'unrest_harness', '--mode', module_mode(profile['case']), '--transport', 'streamable-http', '--host', '127.0.0.1', '--port']
                    or type(argv[12]) is not str or not argv[12].isdigit() or not 0 < int(argv[12]) <= 65535
                    or argv[13:] != ['--sensitive-inventory-fd', str(inherited[0][0])]):
                raise Refused('source exact worker module entry')
        else:
            expected_script = str(Path(profile['checkout']) / SCRIPT)
            snapshot = snapshot_path(Path(__file__).parent.parent / 'profiles', profile['case'])
            info = snapshot.stat(follow_symlinks=False)
            if (script != expected_script or profile['argv'] != [native, '-I', '-S', expected_script, str(snapshot)]
                    or event != 'cpython.run_file' or arguments != (expected_script,)
                    or digest(Path(expected_script)) != CLEANUP_PINS[SCRIPT]
                    or info.st_uid != 20001 or info.st_mode & 0o777 != 0o444 or info.st_nlink != 1
                    or digest(snapshot) != hashlib.sha256(scenario(profile['case'], Path(profile['cwd']).parent)).hexdigest()):
                raise Refused('source exact cleanup fixture and immutable scenario')
    elif role == 'mock-acp':
        if (profile['case'] not in ORDINARY_CASES or profile['case'] not in profile['cases']
                or not Path(profile['cwd']).is_relative_to(Path(profile['owned']) / 'pytest')
                or Path(profile['cwd']).name != 'workspace' or script != str(Path(profile['checkout']) / MOCK)
                or profile['argv'] != [native, '-I', '-S', script] or digest(Path(script)) != PINS[MOCK]
                or event != 'cpython.run_file' or arguments != (script,)):
            raise Refused('source original mock ACP leaf')
    else:
        home = Path(profile['cwd'])
        if (not home.is_relative_to(Path(profile['owned'])) or profile['case'] not in profile['cases']
                or home.name not in (('worker','validator') if profile['case'] in CONTROLLED else ('worker',))
                or type(script) is not str or str(Path(script).resolve()) != script):
            raise Refused('source closed leaf role or home')
        relay = json.loads(profile['environment']['SYNTHETIC_RELAY']) if role == 'acp' else None
        expected,source,pin = expected_entry(profile['case'],Path(profile['checkout']),home,native,
            profile['native_sha256'],backend=role != 'acp',relay=relay)
        delayed = expected.payload_kind == 'python-command'
        if (delayed != (role == 'delayed-backend') or script != source[1]
                or role != 'acp' and not Path(script).is_relative_to(Path(profile['owned']))
                or profile['argv'] != [native,'-I','-S',*expected.argv[1:]] or digest(Path(script)) != pin
                or event != ('cpython.run_command' if delayed else 'cpython.run_file')
                or arguments != ((expected.argv[2]+'\n',) if delayed else (script,))):
            raise Refused('source exact controlled entry')
    pins = tuple(sorted((('entry', profile['entry_sha256']), ('native', profile['native_sha256']),
                        ('source', profile['source_sha256']), ('support', profile['support_sha256']),
                        ('runtime', profile['runtime_sha256']), ('dependency', profile['dependency_sha256']))))
    return actual, pins
