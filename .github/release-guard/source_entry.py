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
from typing import Any, NoReturn, cast

from bootstrap_wire import Client
from content_manifest import Refused
from cleanup_launch import OFFLINE
from git_sites import CASES as GIT_CASES
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
        if profile['role']=='root':
            from input_manifest import read
            self.pins=read(directory,profile)
        self.sockets: Any = None

    def refuse(self, code) -> NoReturn:
        self.poison = True
        try:
            self.client.request('guard-refusal', {'code': code})
        except BaseException:
            pass
        raise Refused(code)

    def private_call(self):
        return getattr(self.client.local,'active',False) is True

    def popen(self, args):
        if self.profile['role'] not in ('root','mcp','session-adapter','fixed-inline','desktop','archive-checker') or self.case is None:
            raise Refused('source undeclared process role')
        if type(args) is not tuple or len(args)!=4:
            raise Refused('source process audit schema')
        executable,vector,cwd,environment=args
        from ordinary_acp import plain_environment
        if type(executable) is not str or type(vector) is not list or any(type(arg) is not str for arg in vector):
            raise Refused('source process audit primitives')
        if cwd is None:
            cwd=os.getcwd()
        elif type(cwd) in (str,PATH_TYPE):
            cwd=str(cwd)
        else:
            raise Refused('source process cwd primitive')
        environment=plain_environment(dict(os.environ) if environment is None else environment)
        commit_input=None
        if self.case in GIT_CASES and vector[1:2]==['commit-tree']:
            commit_input=getattr(self.local,'run_input',None)
            if (type(commit_input) is not str or len(commit_input)>16384
                    or not commit_input.startswith('Integrate Unrest workspaces\n\n')):
                self.refuse('Git finite commit input')
        answer=self.client.request('launch-proposal',{'case':self.case,'executable':executable,'argv':vector,
            'cwd':cwd,'environment':environment,'stdin':commit_input})
        if (type(answer) is not dict or not {'ok','ticket','token','translated','rule'}<=set(answer)
                or type(answer['ticket']) is not int or type(answer['token']) is not str
                or type(answer['translated']) is not list or any(type(arg) is not str for arg in answer['translated'])):
            raise Refused('source finite proposal response')
        if getattr(self.local,'launch',None) is not None:
            raise Refused('source nested process constructor')
        self.local.launch=answer
        self.local.custody=answer['rule']=='custody:git'
        vector[:]=answer['translated']
        if answer['rule'] in ('cleanup:mcp','http:mcp','completion:stdio'):
            args[3].update(OFFLINE)

    def audit(self, event, args):
        order=getattr(self,'audit_order',None)
        if order is not None and order.deferred(event):
            return True
        try:
            if event in ('compile', 'exec', 'import'):
                script=self.profile['script']
                if event=='compile' and script is not None and len(args)==2 and args[1]==script:
                    pin=self.profile['execution']['script_sha256']
                    data=args[0].encode() if type(args[0]) is str else args[0]
                    if digest(Path(script))!=pin or data is not None and (type(data) is not bytes or hashlib.sha256(data).hexdigest()!=pin):
                        raise Refused('source declared script bytes changed')
                return True
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
        original_communicate = process_class.communicate
        original_run = subprocess.run
        original_kill, original_group = os.kill, os.killpg
        policy = self

        def run(*args,**kwargs):
            previous=getattr(policy.local,'run_input',None)
            policy.local.run_input=kwargs.get('input')
            try:
                return original_run(*args,**kwargs)
            finally:
                policy.local.run_input=previous

        def construct(process, *args, **kwargs):
            if type(process) is not process_class:
                policy.refuse('source process constructor type')
            # CPython3.13 Popen's positional env is argument10. Only pytest's
            # framework metadata is shortened; actual test parameters stay intact.
            supplied=args[10] if len(args)>10 else kwargs.get('env')
            values=dict(os.environ) if supplied is None else supplied
            if type(values) is dict:
                from case_inventory import environment
                normalized=environment(values,policy.case)
                if normalized is not values:
                    if len(args)>10:
                        args=(*args[:10],normalized,*args[11:])
                    else:
                        kwargs['env']=normalized
            policy.local.launch = None
            original(process, *args, **kwargs)
            pending = getattr(policy.local, 'launch', None)
            if pending is None:
                policy.refuse('source constructor without admitted audit')
            policy.local.launch = None
            policy.client.request('launch-return', {'pid': process.pid, 'ticket': pending['ticket'], 'token': pending['token']})
            saved = {'token': pending['token'], 'process': process, 'case': policy.case}
            policy.children[process.pid] = saved
            custody = getattr(policy.local,'custody',False)
            policy.local.custody = False
            fields=pending.get('command')
            if fields is not None:
                from types import SimpleNamespace
                command=SimpleNamespace(**fields)
                saved['git_command'] = command
                if command.produces is not None:
                    stream_type = io.BufferedReader if custody else io.TextIOWrapper
                    if type(process.stdout) is not stream_type:
                        policy.refuse('git original stdout wrapper')
                    saved['git_stream_type'] = stream_type
                    fd = stream_type.fileno(cast(io.BufferedReader | io.TextIOWrapper,process.stdout))
                    info = os.fstat(fd)
                    saved['git_stdout'], saved['git_pipe'] = process.stdout, (fd, info.st_dev, info.st_ino)
                    policy.client.request('git-pipe', {'pid': process.pid, 'token': saved['token'],
                        'fd': fd, 'dev': info.st_dev, 'ino': info.st_ino})

        def communicate(process, *args, **kwargs):
            saved = policy.children.get(process.pid)
            if saved is None:
                return original_communicate(process,*args,**kwargs)
            command = saved.get('git_command')
            if command is None or command.produces is None:
                return original_communicate(process, *args, **kwargs)
            if (saved['process'] is not process or saved['case'] != policy.case
                    or process.stdout is not saved['git_stdout'] or type(process.stdout) is not saved['git_stream_type']
):
                policy.refuse('git original communicate identity')
            if command.stdin is not None:
                actual=kwargs.get('input',args[0] if args else None)
                if type(actual) is not str or actual!=command.stdin:
                    policy.refuse('Git original finite commit input changed')
            fd, dev, inode = saved['git_pipe']
            info = os.fstat(saved['git_stream_type'].fileno(process.stdout))
            if (info.st_dev, info.st_ino) != (dev, inode):
                policy.refuse('git stdout descriptor generation changed')
            result = original_communicate(process, *args, **kwargs)
            if (type(process.returncode) is not int or process.returncode != 0
                    or type(result) is not tuple or len(result) != 2
                    or type(result[0]) is not (bytes if saved['git_stream_type'] is io.BufferedReader else str)):
                policy.refuse('git stdout before successful actual parent wait')
            policy.client.request('git-output', {'pid': process.pid, 'token': saved['token'],
                'pipe': [fd, dev, inode], 'stdout': result[0].decode('ascii') if type(result[0]) is bytes else result[0]})
            return result

        def signal(pid, sig, *, group):
            if type(sig) not in (int, signals.Signals):
                policy.refuse('source nonnumeric signal')
            sig = int.__int__(sig)
            if policy.profile['role'] not in ('root', 'session-adapter') or policy.calls is None:
                policy.refuse('source signal role')
            self_stop = policy.profile['role']=='session-adapter' and pid==os.getpid() and sig==15 and not group
            if not self_stop and (type(pid) is not int or pid not in policy.children):
                policy.refuse('source signal outside owned children')
            if self_stop is True:
                if policy.client.request('self-stop', {'signal': sig}) != {'ok': True}:
                    policy.refuse('source self stop response')
                policy.local.signal = 'os.kill', (pid, sig)
                try:
                    return original_kill(pid, sig)
                finally:
                    policy.local.signal = None
            saved = policy.children[pid]
            try:
                answer = policy.client.request('custody_signal', {'pid': pid, 'child_token': saved['token'],
                                                                  'signal': sig, 'group': group})
            except Refused:
                policy.refuse('source cleanup signal refused')
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

        if self.profile['role'] in ('root', 'mcp', 'session-adapter', 'fixed-inline','desktop','archive-checker'):
            subprocess.run=run
            setattr(subprocess.Popen, '__init__', construct)
            setattr(subprocess.Popen, 'communicate', communicate)
            os.kill, os.killpg = kill, killpg


def activate(directory, profile, event, arguments):
    global ACTIVE
    actual, pins = validate(profile, event, arguments)
    client = Client(directory, profile, METHODS)
    policy = Policy(directory, profile, actual, client)
    if profile['role'] in ('root', 'mcp', 'cleanup-acp', 'session-adapter', 'session-child', 'fixed-inline', 'plan-python','mp-child','mp-tracker','review-wire','pytest-regression','desktop','archive-checker','archive-leaf','archive-installed'):
        if profile['role']=='archive-leaf':
            sys.path[:0]=[str(Path(profile['cwd'])/'src'),profile['dependencies'],profile['cwd']]
        elif profile['role'] in ('archive-checker','archive-installed'):
            sys.path.insert(0,profile['dependencies'])
        else:
            sys.path[:0] = [profile['dependencies'], str(Path(profile['checkout']) / 'src'), profile['checkout']]
        # Only guard/locked dependencies initialize here; candidate test modules
        # are imported by the real pytest body after the native READY boundary.
        if profile['role'] == 'root':
            __import__('source_root')
            if type(profile['cases']) is dict:
                sys.executable=profile['native']
        from source_context import Context
        policy.calls=Context(policy)
        if profile['role']!='root':
            policy.case=profile['case']
    if profile['role'] in ('archive-checker','archive-leaf'):
        os.environ.pop('PYTEST_PLUGINS',None)
        os.environ.pop('PYTEST_ADDOPTS',None)
    if profile['role']=='archive-leaf':
        temp=str(Path(profile['owned'])/('archive-'+profile['token']))
        os.environ.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',PYTEST_ADDOPTS='--basetemp='+temp+' -o cache_dir='+temp+'-cache')
    if profile['role']=='pytest-regression':
        temp=str(Path(profile['owned'])/('nested-'+profile['token']))
        os.environ.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',PYTEST_PLUGINS='nested_pytest,pytest_asyncio.plugin,pytest_mock',PYTEST_ADDOPTS='--basetemp='+temp+' -o cache_dir='+temp+'-cache')
    if profile['role'] not in ('session-adapter', 'session-child'):
        from source_sockets import Hooks
        policy.sockets = Hooks(policy)
    client.request('core-ready', {'pins': [list(pair) for pair in pins]})
    if policy.sockets is not None:
        policy.sockets.install()
    policy.install_process_hooks()
    client.request('body-ready', {'seal': profile['seal']})
    sys.dont_write_bytecode = True
    ACTIVE = policy
    return policy.audit
