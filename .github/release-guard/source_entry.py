"""Native activation of the finite pytest root and declared child domains."""
from __future__ import annotations

import errno
import hashlib
import os
import signal as signals
from pathlib import Path
import subprocess
import sys
import threading
import traceback
from typing import NoReturn

from bootstrap_wire import Client
from content_manifest import Refused
from git_policy import local_case
from inline_leaves import STREAM_CASES
from source_profile import digest, validate

def direct_native(args, kwargs, case, role):
    vector = args[0] if args else kwargs.get('args')
    executable = args[2] if len(args)>2 else kwargs.get('executable')
    # Popen computes its PATH search before its audit event. Selecting the fixed
    # image here prevents undeclared ENOENT probes; observer admission still owns
    # every case, argv, environment, image measurement and launch quota.
    name=vector[0] if type(vector) in (list,tuple) and vector and type(vector[0]) is str else None
    selected={'git':'/usr/bin/git','ps':'/usr/bin/ps','sleep':'/usr/bin/sleep'}.get(name)
    from approval_launch import CASES as APPROVAL
    normalized=role in ('approval-adapter','approval-relay') and case in APPROVAL
    if normalized:
        selected=sys.executable
    if (normalized or role in ('root','mcp','fixed-inline')) and selected is not None and executable is None:
        if len(args)>2:
            args=(*args[:2],selected,*args[3:])
        else:
            kwargs={**kwargs,'executable':selected}
    return args,kwargs


ACTIVE = None
PATH_TYPE = type(Path('/'))
PROCESS_OWNERS = ('root','mcp','session-adapter','fixed-inline','desktop','archive-checker','approval-adapter','approval-relay')


class Policy:
    def __init__(self, directory, profile, actual, client):
        self.directory, self.profile, self.actual, self.client = directory, profile, actual, client
        self.case, self.poison = None, False
        self.children: dict[int, dict] = {}
        self.local = threading.local()

    def refuse(self, code) -> NoReturn:
        self.poison = True
        try:
            self.client.request('guard-refusal', {'code': code})
        except BaseException:
            pass
        raise Refused(code)

    def popen(self, args):
        if self.profile['role'] not in PROCESS_OWNERS or self.case is None:
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
        if local_case(self.case) and vector[1:2]==['commit-tree'] and vector[3:4]==['-p']:
            commit_input=getattr(self.local,'run_input',None)
            from git_policy import operand_text
            try:
                operand_text(commit_input,16384)
            except Refused:
                self.refuse('Git finite commit input')
        request={'case':self.case,'executable':executable,'argv':vector,
            'cwd':cwd,'environment':environment,'stdin':commit_input}
        if self.case in STREAM_CASES:
            descriptors=getattr(self.local,'passfds',())
            if type(descriptors) is not tuple or len(descriptors)!=1 or type(descriptors[0]) is not int or not 3<=descriptors[0]<=1024:
                self.refuse('source exact inventory descriptor')
            request['inventory_fd']=descriptors[0]
        answer=self.client.request('launch-proposal',request)
        if getattr(self.local,'launch',None) is not None:
            raise Refused('source nested process constructor')
        self.local.launch=answer
        vector[:]=answer['translated']

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
            if event in ('socket.bind','socket.connect'):
                if type(self.case) is not str or not self.case.startswith('tests/test_approval_recovery.py::'):
                    raise Refused('source unknown private Unix endpoint')
                if self.client.request('private-unix',{'event':event,'address':args[1]})!={'ok':True}:
                    raise Refused('source private Unix acknowledgement')
                return True
            if event == 'subprocess.Popen':
                self.popen(args)
                return True
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
            args,kwargs=direct_native(args,kwargs,policy.case,policy.profile['role'])
            policy.local.launch = None
            previous=getattr(policy.local,'passfds',())
            policy.local.passfds=kwargs.get('pass_fds',())
            try:
                original(process, *args, **kwargs)
            finally:
                policy.local.passfds=previous
            pending = getattr(policy.local, 'launch', None)
            if pending is None:
                policy.refuse('source constructor without admitted audit')
            policy.local.launch = None
            saved = {'token': pending['token'], 'process': process, 'case': policy.case,
                     'wait_at_case_close':pending.get('wait_at_case_close') is True}
            policy.children[process.pid] = saved
        def deliver(pid, sig, group):
            policy.local.signal = 'os.killpg' if group else 'os.kill', (pid, sig)
            try:
                return (original_group if group else original_kill)(pid, sig)
            finally:
                policy.local.signal = None

        def signal(pid, sig, *, group):
            if type(sig) not in (int, signals.Signals):
                policy.refuse('source nonnumeric signal')
            sig = int.__int__(sig)
            if policy.profile['role'] not in PROCESS_OWNERS:
                policy.refuse('source signal role')
            self_probe=(type(pid) is int and pid==os.getpid() and sig==0 and not group
                and policy.profile['role']=='root' and type(policy.case) is str
                and policy.case.startswith('tests/test_approval_recovery.py::'))
            if self_probe:
                if policy.client.request('self-probe',{'pid':pid})!={'ok':True}:
                    policy.refuse('source self probe response')
                return deliver(pid, sig, False)
            self_stop = policy.profile['role']=='session-adapter' and pid==os.getpid() and sig==15 and not group
            from run_worker_launch import REGISTERED
            self_group=(policy.profile['role']=='fixed-inline' and policy.case==REGISTERED
                and type(pid) is int and pid==os.getpid() and sig==15 and group)
            resumed=not (self_stop or self_group) and type(pid) is int and pid not in policy.children
            from approval_launch import CASES as APPROVAL
            approval=resumed and policy.profile['role'] in ('root','fixed-inline') and policy.case in APPROVAL
            if not (self_stop or self_group) and (type(pid) is not int or resumed):
                from composed_cases import ADOPT
                if not approval and (not resumed or policy.profile['role']!='mcp' or policy.case not in ADOPT):
                    policy.refuse('source signal outside owned children')
            if self_stop or self_group:
                if policy.client.request('self-group' if self_group else 'self-stop', {'signal': sig}) != {'ok': True}:
                    policy.refuse('source self stop response')
                return deliver(pid, sig, self_group)
            try:
                answer = (policy.client.request('approval-signal' if approval else 'resumed-signal',{'pid':pid,'signal':sig,'group':group}) if resumed else
                    policy.client.request('custody_signal', {'pid': pid, 'child_token': policy.children[pid]['token'],
                                                              'signal': sig, 'group': group}))
            except Refused:
                policy.refuse('source cleanup signal refused')
            if answer != {'ok': True, 'live': True}:
                if answer == {'ok': True, 'live': False}:
                    raise ProcessLookupError(errno.ESRCH, 'owned process already terminal')
                policy.refuse('source signal response')
            return deliver(pid, sig, group)

        def kill(pid, sig):
            return signal(pid, sig, group=False)

        def killpg(pid, sig):
            return signal(pid, sig, group=True)

        if self.profile['role'] in PROCESS_OWNERS:
            subprocess.run=run
            setattr(subprocess.Popen, '__init__', construct)
            os.kill, os.killpg = kill, killpg


def activate(directory, profile, event, arguments):
    global ACTIVE
    actual = validate(profile, event, arguments)
    client = Client(directory, profile)
    policy = Policy(directory, profile, actual, client)
    if profile['role'] in ('root', 'mcp', 'cleanup-acp', 'session-adapter', 'session-child', 'fixed-inline', 'plan-python','mp-child','mp-tracker','review-wire','pytest-regression','desktop','archive-checker','archive-leaf','archive-installed','approval-adapter','approval-relay','approval-backend'):
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
    from run_worker_launch import install_fixture
    install_fixture(policy)
    policy.install_process_hooks()
    client.request('body-ready', {})
    sys.dont_write_bytecode = True
    ACTIVE = policy
    return policy.audit
