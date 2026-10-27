"""Native activation of the finite pytest root and declared child domains."""
from __future__ import annotations

import errno
import hashlib
import io
import os
import signal as signals
from pathlib import Path
import subprocess
import sys
import threading
import traceback
import types
from typing import Any, NoReturn

from bootstrap_wire import Client
from content_manifest import Refused
from control_transport import finite
from bootstrap_cases import BOOTSTRAP
from ordinary_acp import CASES as ORDINARY_CASES
from cleanup_launch import EXECUTION_CASES as CLEANUP_CASES, OFFLINE
from cleanup_inline import DECLARATIONS
from git_sites import CASES as GIT_CASES
from session_launch import CASES as SESSION_CASES, INVALID as SESSION_INVALID
from controlled_startup import ACP
from launch_policy import Observation
from source_code import Bodies
from source_profile import METHODS, digest, validate

ACTIVE = None
PATH_TYPE = type(Path('/'))


class Policy:
    def __init__(self, directory, profile, actual, client):
        self.directory, self.profile, self.actual, self.client = directory, profile, actual, client
        self.case, self.poison = None, False
        self.calls: Any = None
        self.children: dict[int, dict] = {}
        self.local = threading.local()
        self.bodies: Any
        if profile['role'] in ('mcp', 'cleanup-acp', 'session-adapter', 'session-child'):
            from library_code import Computation
            self.bodies = Computation({'source': profile['checkout'], 'dependencies': profile['dependencies'],
                                       'stdlib': str(Path(profile['runtime_root']) / 'lib/python3.13')},
                entry_script=profile['script'] if profile['role'] in ('cleanup-acp', 'session-adapter', 'session-child') else None)
        else:
            self.bodies = Bodies(profile)
        self.wire_code = Client.request.__code__
        self.wire_globals = Client.request.__globals__
        self.sockets: Any = None

    def refuse(self, code) -> NoReturn:
        self.poison = True
        try:
            self.client.request('guard-refusal', {'code': code})
        except BaseException:
            pass
        raise Refused(code)

    def private_call(self):
        frame: types.FrameType | None = sys._getframe(1)
        for _ in range(64):
            if frame is None:
                return False
            if frame.f_code is self.wire_code and frame.f_globals is self.wire_globals and frame.f_locals.get('self') is self.client:
                return True
            frame = frame.f_back
            if frame is None:
                return False
        return False

    def popen(self, args):
        if self.profile['role'] not in ('root', 'mcp', 'session-adapter') or self.calls is None or self.case not in (*BOOTSTRAP, *ORDINARY_CASES, *CLEANUP_CASES, *DECLARATIONS, *GIT_CASES, *SESSION_CASES):
            raise Refused('source undeclared process caller')
        if type(args) is not tuple or len(args) != 4:
            raise Refused('source process audit schema')
        executable, vector, cwd, environment = args
        if self.case in (*ORDINARY_CASES, *CLEANUP_CASES, *DECLARATIONS, *GIT_CASES, *SESSION_CASES):
            if (type(executable) is not str or type(vector) is not list
                    or not (1 if self.case in SESSION_INVALID else 2) <= len(vector) <= 128 or any(type(arg) is not str for arg in vector)):
                raise Refused('ordinary process audit primitives')
            intent = self.calls.startup.select(self.case, args)
        else:
            if (type(executable) is not str or type(vector) is not list or not 2 <= len(vector) <= 128
                    or any(type(arg) is not str for arg in vector)
                    or type(cwd) not in (str, PATH_TYPE) or type(environment) is not dict
                    or any(type(key) is not str or type(value) is not str for key, value in environment.items())):
                raise Refused('source process audit primitives')
            command = vector[1] == '-c'
            if command:
                if len(vector) < 3 or len(vector[2]) > 4 * 1024 * 1024:
                    raise Refused('source inline payload bound')
                payload = hashlib.sha256(vector[2].encode()).hexdigest()
            else:
                file = Path(vector[1])
                if (not file.is_absolute() or str(file.resolve()) != str(file)
                        or not (file.is_relative_to(Path(self.profile['owned']))
                                    or file == Path(self.profile['checkout']) / ACP)):
                    raise Refused('source script observation root')
                payload = digest(file)
            observed = Observation(executable, digest(Path(executable)), tuple(vector),
                tuple(sorted(environment.items())), str(cwd), 'python-command' if command else 'python-script', payload)
            intent = self.calls.startup.select(self.case, observed)
        request = {'case': self.case, 'original': intent.original.wire(),
                   'translated': list(intent.translated_argv), 'source_line': intent.original_source_line,
                   'script_sha256': intent.script_sha256}
        if self.case in GIT_CASES:
            request['git'] = self.calls.pending[0]
        finite(request)
        answer = self.client.request('launch-intent', request)
        if set(answer) != {'ok', 'ticket', 'token'} or type(answer['ticket']) is not int or type(answer['token']) is not str:
            raise Refused('source launch intent response')
        if getattr(self.local, 'launch', None) is not None:
            raise Refused('source nested process constructor')
        self.local.launch = answer
        vector[:] = intent.translated_argv
        if intent.original.rule == 'cleanup:mcp':
            if type(environment) is not dict:
                self.refuse('source MCP environment translation type')
            environment.update(OFFLINE)

    def audit(self, event, args):
        try:
            if event in ('compile', 'exec', 'import'):
                return self.bodies.audit(event, args)
            if event == 'subprocess.Popen':
                self.popen(args)
                return True
            if event in ('socket.bind', 'socket.connect', 'socket.__new__'):
                if self.sockets is None:
                    import socket
                    if (event != 'socket.__new__' or type(args) is not tuple or len(args) != 4
                            or type(args[0]) not in (socket.socket, socket.SocketType)
                            or any(type(v) is not int for v in args[1:])
                            or args[1:] != (socket.AF_UNIX, socket.SOCK_STREAM, 0) or not self.private_call()):
                        raise Refused('source fixed-script private channel only')
                    return True
                return self.sockets.audit(event, args)
            if event in ('os.kill', 'os.killpg'):
                pending = getattr(self.local, 'signal', None)
                if pending != (event, args):
                    raise Refused('source signal outside approved cleanup')
                self.local.signal = None
                return True
            raise Refused('source unknown privileged effect')
        except BaseException as error:
            self.poison = True
            traceback.print_exc(file=sys.stderr)  # Owned output pipe; encrypted by the host.
            code = (error.args[0] if type(error) is Refused and len(error.args) == 1
                    and type(error.args[0]) is str and len(error.args[0]) <= 128
                    and all(char.isascii() and (char.isalnum() or char in ' -_') for char in error.args[0])
                    else 'source-audit-refused')
            try:
                self.client.request('guard-refusal', {'code': code})
            except BaseException:
                pass
            raise

    def install_process_hooks(self):
        process_class = subprocess.Popen
        original = process_class.__init__
        self.constructor_code, self.constructor_globals = original.__code__, original.__globals__
        original_communicate = process_class.communicate
        communicate_code, communicate_globals = original_communicate.__code__, original_communicate.__globals__
        original_wait = os.waitpid
        original_kill, original_group = os.kill, os.killpg
        policy = self

        def construct(process, *args, **kwargs):
            if type(process) is not process_class:
                policy.refuse('source process constructor type')
            policy.local.launch = None
            if original.__code__ is not policy.constructor_code or original.__globals__ is not policy.constructor_globals:
                policy.refuse('source original process constructor changed')
            policy.local.constructing = process
            try:
                original(process, *args, **kwargs)
            finally:
                policy.local.constructing = None
            pending = getattr(policy.local, 'launch', None)
            if pending is None:
                policy.refuse('source constructor without admitted audit')
            policy.local.launch = None
            policy.client.request('launch-return', {'pid': process.pid, 'ticket': pending['ticket'], 'token': pending['token']})
            saved = {'token': pending['token'], 'process': process, 'case': policy.case}
            policy.children[process.pid] = saved
            if policy.case in GIT_CASES:
                _, command = policy.calls.pending
                saved['git_command'] = command
                if command is None:
                    policy.calls.owned_pid = process.pid
                elif command.produces is not None:
                    if type(process.stdout) is not io.TextIOWrapper:
                        policy.refuse('git original stdout wrapper')
                    fd = io.TextIOWrapper.fileno(process.stdout)
                    info = os.fstat(fd)
                    saved['git_stdout'], saved['git_pipe'] = process.stdout, (fd, info.st_dev, info.st_ino)
                    policy.client.request('git-pipe', {'pid': process.pid, 'token': saved['token'],
                        'fd': fd, 'dev': info.st_dev, 'ino': info.st_ino})

        def communicate(process, *args, **kwargs):
            saved = policy.children.get(process.pid)
            command = None if saved is None else saved.get('git_command')
            if command is None or command.produces is None:
                return original_communicate(process, *args, **kwargs)
            if (saved['process'] is not process or saved['case'] != policy.case
                    or process.stdout is not saved['git_stdout'] or type(process.stdout) is not io.TextIOWrapper
                    or original_communicate.__code__ is not communicate_code or original_communicate.__globals__ is not communicate_globals):
                policy.refuse('git original communicate identity')
            fd, dev, inode = saved['git_pipe']
            info = os.fstat(io.TextIOWrapper.fileno(process.stdout))
            if (info.st_dev, info.st_ino) != (dev, inode):
                policy.refuse('git stdout descriptor generation changed')
            result = original_communicate(process, *args, **kwargs)
            if (original_communicate.__code__ is not communicate_code or saved.get('wait_raw') != 0
                    or type(result) is not tuple or len(result) != 2 or type(result[0]) is not str):
                policy.refuse('git stdout before successful actual parent wait')
            answer = policy.client.request('git-output', {'pid': process.pid, 'token': saved['token'],
                'pipe': [fd, dev, inode], 'stdout': result[0]})
            if command.produces[1] == 'integration-commit':
                policy.calls.integrations[answer['value']] = (command.produces[0], command.produces[2])
            return result

        def waitpid(pid, options):
            if (type(pid) is int and pid > 0 and pid not in policy.children
                    and getattr(policy.local, 'launch', None) is not None
                    and getattr(policy.local, 'constructing', None) is not None):
                pending = policy.local.launch
                if pending is None:
                    policy.refuse('source absent constructor ticket')
                process = policy.local.constructing
                if process.pid != pid:
                    policy.refuse('source failed-constructor child identity')
                policy.client.request('launch-return', {'pid': pid, 'ticket': pending['ticket'], 'token': pending['token']})
                policy.children[pid] = {'token': pending['token'], 'process': process, 'case': policy.case}
            if type(pid) is not int or pid <= 0 or type(options) is not int or pid not in policy.children:
                policy.refuse('source wait outside owned constructor')
            saved = policy.children[pid]
            actual, raw = original_wait(pid, options)
            if actual:
                if actual != pid or type(raw) is not int or not (os.WIFEXITED(raw) or os.WIFSIGNALED(raw)):
                    policy.refuse('source nonnumeric parent wait')
                policy.client.request('drain_child', {'pid': actual, 'requested_pid': pid, 'child_token': saved['token'],
                    'raw_status': raw, 'numeric_returncode': os.waitstatus_to_exitcode(raw), 'options': options})
                saved['wait_raw'] = raw
            return actual, raw

        def signal(pid, sig, *, group):
            if type(sig) not in (int, signals.Signals):
                policy.refuse('source nonnumeric signal')
            sig = int.__int__(sig)
            if policy.profile['role'] not in ('root', 'session-adapter') or policy.calls is None:
                policy.refuse('source signal role')
            try:
                self_stop = policy.calls.signal(pid, sig, group)
            except BaseException:
                traceback.print_exc(file=sys.stderr)  # Retained only in encrypted execution evidence.
                policy.refuse('source cleanup signal refused')
            if self_stop is True:
                if policy.client.request('self-stop', {'signal': sig}) != {'ok': True}:
                    policy.refuse('source self stop response')
                policy.local.signal = 'os.kill', (pid, sig)
                try:
                    return original_kill(pid, sig)
                finally:
                    policy.local.signal = None
            saved = policy.children[pid]
            answer = policy.client.request('custody_signal', {'pid': pid, 'child_token': saved['token'],
                                                              'signal': sig, 'group': group})
            if answer != {'ok': True, 'live': True}:
                if answer == {'ok': True, 'live': False}:
                    raise ProcessLookupError(errno.ESRCH, 'owned process already terminal')
                policy.refuse('source signal response')
            event = 'os.killpg' if group else 'os.kill'
            policy.local.signal = event, (pid, sig)
            try:
                return (original_group if group else original_kill)(pid, sig)
            finally:
                policy.local.signal = None

        def kill(pid, sig):
            return signal(pid, sig, group=False)

        def killpg(pid, sig):
            return signal(pid, sig, group=True)

        if self.profile['role'] in ('root', 'mcp', 'session-adapter'):
            setattr(subprocess.Popen, '__init__', construct)
            setattr(subprocess.Popen, 'communicate', communicate)
            safe = vars(subprocess).get('_del_safe')
            if type(safe) is not type or vars(safe).get('waitpid') is not original_wait:
                policy.refuse('source original polling wait binding')
            setattr(safe, 'waitpid', staticmethod(waitpid))
            os.waitpid, os.kill, os.killpg = waitpid, kill, killpg


def activate(directory, profile, event, arguments):
    global ACTIVE
    actual, pins = validate(profile, event, arguments)
    client = Client(directory, profile, METHODS)
    policy = Policy(directory, profile, actual, client)
    if profile['role'] in ('root', 'mcp', 'cleanup-acp', 'session-adapter', 'session-child'):
        sys.path[:0] = [profile['dependencies'], str(Path(profile['checkout']) / 'src'), profile['checkout']]
        # Only guard/locked dependencies initialize here; candidate test modules
        # are imported by the real pytest body after the native READY boundary.
        if profile['role'] == 'root':
            __import__('source_root')
        elif profile['role'] == 'mcp':
            from cleanup_effects import ModuleCalls
            policy.case, policy.calls = profile['case'], ModuleCalls(policy, None)
        elif profile['role'] == 'session-adapter':
            from session_calls import SessionChild
            policy.case, policy.calls = profile['case'], SessionChild(policy)
    if profile['role'] not in ('session-adapter', 'session-child'):
        from source_sockets import Hooks
        policy.sockets = Hooks(policy)
        from source_owner import bind_asyncio
        bind_asyncio()
    client.request('core-ready', {'pins': [list(pair) for pair in pins]})
    if policy.sockets is not None:
        policy.sockets.install()
    policy.install_process_hooks()
    client.request('body-ready', {'seal': profile['seal']})
    sys.dont_write_bytecode = True
    ACTIVE = policy
    return policy.audit
