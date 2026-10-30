"""Independent finite observer for the original bootstrap cases.

No legacy resolver, arbitrary executable request, or provider permission path.
Kernel births/execs and actual waits remain independent of source-side reports.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import time

from content_manifest import Refused, native_digest
from http_cases import CASES as HTTP_CASES
from plan_launch import CASES as PLAN_CASES, INVALID as PLAN_INVALID, PYTHON as PLAN_PYTHON
from control_transport import Admission, Frame, REQUEST_LIMIT, cancelled_empty, reply
from controlled_cases import eligible as CONTROLLED, backend_path, WARNING_REFUSALS, NOTIFICATION_SIGNALS
from linux_observation import process_identity
from process_ledger import Birth, Ledger, canonical
from source_profile import METHODS
from session_launch import TIMEOUT as SESSION_TIMEOUT
from fixed_inline import CLI_CASE, JOURNAL_CASE
from completion_roles import CASES as ROLE_CASES,actor_slot
from git_policy import Git
from cleanup_launch import EXECUTION_CASES as CLEANUP_CASES, snapshot_path




def shape(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise Refused('source observer operation schema')


def number(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise Refused('source observer integer')
    return value


def native_class(role):
    return 'native-stock-uv' if role=='uv-cli' else 'native-git-command' if role == 'git-custody' else 'native-' + role


def bound_intent(host,actor):
    value=actor.get('intent')
    return value if value is not None and host.intents.get(value.get('ticket')) is value and value['consumed'] and all(value.get(key)==actor[key] for key in ('birth','token','case','role')) else None


class Observer:
    def __init__(self, binding, metadata, root_pid, out_read):
        self.binding, self.meta = binding, metadata
        self.full = type(metadata['cases']) is dict
        self.cases = () if self.full else tuple(metadata['cases'])
        self.launcher = root_pid if self.full else None
        self.full_started = False
        self.outcomes = []
        self.directory = Path(binding['profiles'])
        self.root = root_pid
        self.root_birth = Birth.read(process_identity(root_pid))
        self.ledger = Ledger(os.urandom(32).hex())
        self.admission = Admission(self.ledger, METHODS)
        self.git = Git(self)
        self.actors, self.intents, self.mp_pipes = {}, {}, {}

        self.cohort_observations=[]
        self.adoptions=[]
        self.fixture_roots = {}
        self.plan_records: list[dict] = []
        self.frames, self.controls, self.completed = [], [], []
        self.case, self.finished, self.serial = None, False, 0
        self.out_read, self.output = out_read, bytearray()
        os.set_blocking(out_read, False)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        path = self.directory / 'control.sock'
        self.server.bind(str(path))
        path.chmod(0o666)
        self.server.listen(32)
        self.server.setblocking(False)

    def profile(self, pid, role, case, vector, environment, cwd, token, inherited=()):
        actual = process_identity(pid)
        parent = Birth.read(process_identity(actual['ppid']))
        script=(vector[3] if vector[3] not in ('-c','-m') else
                str(backend_path(case,Path(cwd).parent) if CONTROLLED(case) else Path(cwd).parent/'fake-app-server')
                if role=='delayed-backend' else None)
        source = {'schema': 'unrest.bootstrap-source.v1', 'role': role, 'case': case,
            'identity': canonical(actual), 'parent': canonical(process_identity(parent.pid)),
            'observer': canonical(process_identity(os.getpid())), 'argv': vector,
            'environment': environment, 'cwd': cwd, 'native': self.binding['entry']['path'],
            'native_sha256': self.binding['entry']['sha256'], 'entry_sha256': self.binding['bootstrap']['sha256'],
            'nonce': self.ledger.nonce, 'token': token, 'generation': 1,
            'mount_namespace': os.readlink('/proc/self/ns/mnt'), **self.meta,
            'inherited': list(inherited),
            'script': script}
        from execution_spec import issue, admitted
        source['execution'],intent = ((issue(role,vector,None,None),None) if role=='root' else
            admitted(self.intents,role,case,pid,token,vector,environment,cwd,script))
        target = self.directory / (str(pid) + '.json')
        with target.open('x') as stream:
            stream.write(json.dumps(source, sort_keys=True))
        target.chmod(0o444)
        actor = {'birth': Birth.read(actual), 'role': role, 'case': case, 'token': token,
                 'profile': source, 'intent':intent, 'body_ready': False, 'signals': set()}
        self.actors[pid] = actor
        command_class = {**dict.fromkeys(('approval-adapter','approval-relay','approval-backend'),'controlled-approval-fixture'),'root': 'bootstrap-root', 'acp': 'controlled-acp',
                         'backend': 'controlled-backend', 'delayed-backend': 'controlled-backend-wrapper', 'mock-acp': 'ordinary-mock-acp', 'mcp': 'worker-mcp', 'cleanup-acp': 'cleanup-acp', 'cleanup-inline': 'cleanup-inline', 'workspace-owned': 'workspace-owned', 'session-adapter': 'session-adapter', 'session-child': 'session-child', 'session-inline': 'session-inline', 'fixed-inline': 'fixed-inline','plan-python':'plan-python','mp-child':'mp-child','mp-tracker':'mp-tracker','review-wire':'review-wire','pytest-regression':'pytest-regression','desktop':'desktop',**dict.fromkeys(('archive-checker','archive-leaf','archive-installed'),'archive-python')}[role]
        from run_worker_launch import ALL_CASES as RUN_WORKERS
        new_session = role in ('backend','delayed-backend','acp','workspace-owned','session-adapter','session-inline') or role=='mcp' and case in HTTP_CASES and vector[3]=='-c' or role=='fixed-inline' and case in (*ROLE_CASES,*RUN_WORKERS)
        self.ledger.register(actor['birth'], token, (), case=case,
                             command_class=command_class, new_session=new_session, expected_generation=1)
        if new_session:
            self.ledger.session(actor['birth'], actual)
        if role=='mp-child':
            self.mp_pipes.update({(actor['birth'],row[0]):row for row in inherited if len(row)==7})
        return actor

    def consume(self, trace):
        self.ledger_trace = trace
        while self.ledger.next_kernel < len(trace.records):
            from composed_adoption import refresh
            refresh(self)
            row = trace.records[self.ledger.next_kernel]
            self.ledger.kernel(self.ledger.next_kernel, row)
            if self.case in PLAN_CASES:
                from plan_observer import consume
                consume(self,row)
            if row['kind'] == 'kernel_child':
                birth = Birth.read(row['identity'])
                if birth.pid == birth.tgid:
                    parent = self.ledger.process(birth).parent
                    actor = self.actors.get(parent.pid) if parent is not None else None
                    if actor is not None and actor['role'] == 'git-command':
                        self.git.reserve_helper(birth, parent)
                    candidates = [value for value in self.intents.values()
                        if not value['consumed'] and value.get('parent', self.root_birth) == parent]
                    if self.full and parent is not None and parent.pid==self.launcher and not self.full_started:
                        continue
                    if actor is None or actor['role'] not in ('root', 'mcp', 'git-command', 'session-adapter', 'fixed-inline','desktop','archive-checker','uv-cli','approval-adapter','approval-relay') or len(candidates) != 1:
                        raise Refused('source fork without a unique original launch intent')
            if row['kind']=='original_parent_wait4':
                from cohort_controller import WAIVED
                for value in self.intents.values():
                    if self.case in WAIVED and value.get('cohort_controller') and value.get('pid')==row['child']:
                        value.setdefault('closeout_started',time.monotonic())
            if row['kind'] == 'kernel_exit' and row.get('raw') == 86 << 8:
                raise Refused('native guard refusal')
            if row['kind'] == 'kernel_root' and not self.full:
                from postbuild_root import COMMAND as ARCHIVE_COMMAND
                vector=[self.binding['entry']['path'],'-I','-S','-c',ARCHIVE_COMMAND,self.binding['checkout']]
                self.profile(self.root, 'root', '<bootstrap>',
                    vector,
                    self.meta_environment(), self.meta['checkout'], os.urandom(16).hex())
        from composed_adoption import refresh
        refresh(self)

    def meta_environment(self):
        if self.full:
            from full_source import child_environment
            return child_environment(self.meta)
        from console_entries import standalone_environment
        return standalone_environment(self.meta)

    def resolve(self, trace, pid, path, vector, environment, cwd):
        actual_namespaces=process_identity(pid)['namespaces']
        if (actual_namespaces['mnt'] != os.readlink('/proc/self/ns/mnt')
                or actual_namespaces['net'] != self.meta['network_namespace']
                or actual_namespaces['pid'] != self.meta['pid_namespace']):
            return False
        if self.case in PLAN_CASES:
            from plan_observer import resolve as plan_resolve
            return plan_resolve(self,trace,pid,path,vector,environment,cwd)
        self.consume(trace)
        if self.full and not self.full_started:
            from full_launch import resolve as full_resolve
            return full_resolve(self,pid,path,vector,environment,cwd)
        birth = self.ledger.current.get(pid)
        if birth is None:
            return False
        parent = self.ledger.process(birth).parent
        if parent is None:
            return False
        matches = [value for value in self.intents.values() if not value['consumed']
                   and value['translated'] == vector and value['environment'] == environment
                   and value.get('parent', self.root_birth) == parent
                   and value['cwd'] == cwd and path == value.get('attempt_path',value.get('executable', self.binding['entry']['path']))]
        if len(matches) != 1:
            return False
        from uv_cli import uv_digest
        measured=Path(path) if Path(path).is_absolute() else Path(cwd)/path
        actual_pin=(uv_digest(measured.resolve(strict=True)) if matches[0]['role']=='uv-cli'
                    else native_digest(measured.resolve(strict=True)))
        if actual_pin != matches[0].get('executable_sha256', self.binding['entry']['sha256']):
            return False
        intent = matches[0]
        if intent.get('credential_snapshot') is not None:
            from archive_snapshot import retained
            target,state=intent['credential_snapshot']
            retained(Path(target),state)
        if intent['role']=='archive-leaf':
            from archive_snapshot import retained
            state=self.fixture_roots[intent['case']]['document']
            retained(Path(state['root']),state['snapshot'])
        from desktop_launch import CASE as DESKTOP_CASE,retained as desktop_retained
        if intent['case']==DESKTOP_CASE:
            desktop_retained(self)
            if intent['role']=='ps' and str(Path(path).resolve(strict=True))!='/usr/bin/ps':
                raise Refused('desktop retained system ps alias')
        intent['consumed'], intent['pid'], intent['birth'] = True, pid, birth
        if intent['role'] in ('sleep', 'session-invalid','ps','uv-cli','terminal-native') or intent['role'].startswith('git-'):
            actual = process_identity(pid)
            birth = Birth.read(actual)
            pins = (('native-fixture', intent['executable_sha256']),)
            self.ledger.register(birth, intent['token'], pins,
                                 case=intent['case'], command_class=native_class(intent['role']), expected_generation=0 if intent['role'] == 'session-invalid' else 1)
            self.actors[pid] = {'birth': birth, 'role': intent['role'], 'case': intent['case'], 'token': intent['token'],
                'body_ready': False, 'signals': set(), 'kernel_admitted': True,'intent':intent}
            if intent['role']=='uv-cli':
                from uv_cli import reserve_child
                reserve_child(self,intent,birth)
        else:
            from speed_inline import CASES as SPEED_CASES,fixture
            if intent['case'] in (*SPEED_CASES,CLI_CASE):
                fixture(self)
            self.profile(pid, intent['role'], intent['case'], intent.get('python_vector',vector), environment, cwd, intent['token'], intent.get('inherited', ()))
        return True

    def root_only(self, actor):
        if actor['birth'] != self.root_birth or actor['role'] != 'root' or self.finished:
            raise Refused('source root-only operation')

    def launch_owner(self, actor):
        from approval_launch import CASES as APPROVAL
        if actor['role'] in ('approval-adapter','approval-relay') and self.case in APPROVAL and actor['case']==self.case and actor['body_ready'] and not self.finished:
            return
        if actor['role'] == 'root':
            self.root_only(actor)
            return
        if actor['role']=='archive-checker' and actor['case']==self.case and actor['body_ready'] and not self.finished:
            from package_cases import POSITIVE
            if self.case==POSITIVE:
                return
        if actor['role']=='desktop' and actor['case']==self.case and not self.finished:
            from desktop_launch import CASE
            if self.case==CASE:
                return
        if actor['role'] == 'fixed-inline' and actor['case'] == self.case and not self.finished:
            from cohort_controller import CASES as CRASH,owner
            if self.case in CRASH:
                owner(self,actor)
                return
            from composed_cases import CASES as COMPOSED
            if self.case in COMPOSED:
                from composed_runtime import owner
                owner(self,actor)
                return
            if self.case in ROLE_CASES:
                actor_slot(self,actor)
                return
            from run_worker_launch import MEASUREMENT_PROJECT
            if self.case==MEASUREMENT_PROJECT:
                from measurement_runtime import owner
                owner(self,actor)
                return
            from run_worker_launch import DESCENDANT
            if self.case==DESCENDANT and any(value.get('run_worker') and value.get('birth')==actor['birth'] and value['token']==actor['token'] for value in self.intents.values()):
                return
            if sum(value.get('fixed_operation') == 'check' and value['token'] == actor['token'] for value in self.intents.values()) != 1:
                raise Refused('fixed inline has no query authority')
            return
        if actor['role'] == 'session-adapter' and actor['case'] == self.case == SESSION_TIMEOUT and not self.finished:
            return
        if self.finished or actor['role'] not in ('root', 'mcp') or actor['role'] == 'mcp' and actor['case'] != self.case:
            raise Refused('source original launch owner')


    def admit_launch(self, actor, expected, role, vector, script_pin,
                     *, maximum=1, environment=None, inherited=(), port=None):
        if (expected.case != self.case or sum(value['case'] == self.case and value['role'] == role
                       and (role not in ('backend','acp') or not CONTROLLED(self.case) or value['cwd'] == expected.cwd)
                       for value in self.intents.values()) >= maximum):
            raise Refused('source independent launch reconstruction')
        # Hold the next constructor until the prior child passes exact exec
        # admission. The fork boundary keeps its unique-intent requirement.
        if any(not value['consumed'] and value.get('parent', self.root_birth) == actor['birth']
               for value in self.intents.values()):
            return None
        self.serial += 1
        token = os.urandom(16).hex()
        self.intents[self.serial] = {'ticket':self.serial,'case': self.case, 'role': role, 'parent': actor['birth'],
            'environment': dict(expected.environment) if environment is None else environment,
            'cwd': expected.cwd, 'translated': vector, 'token': token, 'consumed': False, 'pid': None,
            'executable': expected.executable, 'executable_sha256': expected.executable_sha256,
            'script_sha256': script_pin,
            'inherited': list(inherited), 'port': port}
        return {'ok': True, 'ticket': self.serial, 'token': token}

    def executed(self,intent):
        if not intent['consumed']:
            return False
        process=self.ledger.process(intent['birth'])
        return (process.token==intent['token'] and process.case==intent['case']
            and process.generation==process.registered_generation==1)

    def completed_child(self, actor):
        process = self.ledger.process(actor['birth'])
        terminal = process.terminal
        value=bound_intent(self,actor)
        from package_security import CASES as SECURITY_CASES
        if actor.get('case') in SECURITY_CASES and actor['role']=='archive-installed':
            from package_security import completed
            return value is not None and completed(self,value)
        if actor['role'] in ('archive-checker','archive-leaf','archive-installed'):
            from package_cases import MUTATIONS,NEGATIVE
            code=1 if actor['role']=='archive-checker' and actor['case'] in MUTATIONS or actor['role']=='archive-leaf' and actor['case'] in NEGATIVE else 0
            expected={'kind':NEGATIVE.get(actor['case'],'normal'),'count':0 if NEGATIVE.get(actor['case'])=='missing-package' else 15,
                'failed':15 if NEGATIVE.get(actor['case'])=='missing-corpus' else 0,'exit':code}
            return terminal is not None and terminal[2]==code and actor['body_ready'] and (actor['role']!='archive-leaf' or actor.get('archive_result')==expected)
        if actor['role'] in ('fixed-inline','mcp') and value is not None and 'server_slot' in value:
            from completion_server import status
            return value is not None and status(self,actor,value['server_slot'])
        if actor['role']=='git-command' and value is not None and value.get('operation')=='completion-head':
            return actor.get('kernel_admitted') is True and terminal is not None and terminal[2]==0
        if actor['role']=='pytest-regression':
            return terminal is not None and terminal[2]==0 and actor['body_ready'] and actor.get('preselected_complete') is True
        if actor['case'] in PLAN_CASES:
            if value is None or terminal is None:
                return False
            if actor['case']==PLAN_INVALID:
                return process.generation==0 and terminal[2]==255 and value.get('plan_failed') is True and not actor['body_ready']
            return (process.generation==1 and terminal[2]==0 and value.get('plan_exec_verified') is True
                    and (actor['body_ready'] if actor['case']==PLAN_PYTHON else actor.get('kernel_admitted') is True))
        if actor['role'] == 'session-invalid':
            failures = [row for row in self.ledger_trace.records if row['kind'] == 'exec_syscall_return' and row['pid'] == actor['birth'].pid]
            return process.generation == 0 and terminal is not None and terminal[2] == 255 and len(failures) == 1 and failures[0]['return'] == -8
        from mcp_inventory import DIAGNOSTICS
        if actor['case']==DIAGNOSTICS[1] and actor['role']=='mcp':
            return (value is not None and terminal is not None and process.generation==1
                and terminal[2] in (-9,-15) and -terminal[2] in actor['signals']
                and self.ledger.reaped(actor['birth'],actor['token']))
        if terminal is None or value is None or terminal[2]<0 and -terminal[2] not in actor['signals']:
            return False
        from run_worker_launch import MEASUREMENT_PROJECT,DESCENDANT
        early_cleanup=actor['case'] not in (MEASUREMENT_PROJECT,DESCENDANT) and actor['role'] in ('backend','delayed-backend','acp','mock-acp','cleanup-acp','cleanup-inline',
            'workspace-owned','session-adapter','session-child','session-inline') and terminal[2] in (-9,-15)
        return actor.get('kernel_admitted') is True or actor['body_ready'] or early_cleanup

    def dispatch(self, actor, request):
        kind, payload = request['kind'], request['payload']
        if kind == 'body-ready':
            if actor['role']=='mp-child':
                from multiprocess_pipe import retained
                for (birth,_),row in self.mp_pipes.items():
                    if birth==actor['birth']:
                        retained(self,actor,row,body=False)
            self.ledger.ready(actor['birth'], kind, payload)
            actor['body_ready'] = True
        elif kind == 'self-probe':
            self.root_only(actor)
            shape(payload,('pid',))
            if (type(self.case) is not str or not self.case.startswith('tests/test_approval_recovery.py::')
                    or not actor['body_ready'] or type(payload['pid']) is not int
                    or payload['pid']!=actor['birth'].pid or Birth.read(process_identity(payload['pid']))!=actor['birth']):
                raise Refused('approval exact self liveness probe')
        elif kind == 'private-unix':
            shape(payload,('event','address'))
            from approval_fixture import unix
            return unix(self,actor,payload['event'],payload['address'])
        elif kind == 'collection':
            from full_launch import collection
            return collection(self,actor,payload)
        elif kind in ('case-start', 'case-finish'):
            self.root_only(actor)
            shape(payload, ('case','outcome','phases') if self.full and kind=='case-finish' else ('case',))
            outcome=payload.get('outcome','passed')
            skipped=outcome=='skipped'
            if outcome not in ('passed','skipped','failed'):
                raise Refused('full source outcome primitive')
            if self.full and kind=='case-finish':
                phases=payload['phases']
                if (type(phases) is not dict or not set(phases)<= {'setup','call','teardown'}
                        or any(type(value) is not str or value not in ('passed','skipped','failed') for value in phases.values())
                        or outcome=='passed' and phases!={'setup':'passed','call':'passed','teardown':'passed'}
                        or outcome=='skipped' and phases not in ({'setup':'skipped','teardown':'passed'},{'setup':'passed','call':'skipped','teardown':'passed'})):
                    raise Refused('full source outcome phases')
            if kind == 'case-start':
                if self.case is not None or len(self.completed) >= len(self.cases) or payload['case'] != self.cases[len(self.completed)]:
                    raise Refused('source exact external case frontier')
                self.case = actor['case'] = payload['case']
                self.ledger.process(self.root_birth).case = self.case
            else:
                children = [value for value in self.actors.values() if value['role'] != 'root' and value['case'] == self.case]
                from package_security import CASES as SECURITY_CASES,provenance
                if self.case in SECURITY_CASES:
                    provenance(self)
                if skipped:
                    if children:
                        raise Refused('skipped source case launched children')
                from cohort_controller import CASES as CRASH,closeout
                waived=closeout(self,children) if self.case in CRASH else set()
                if waived is None:
                    return None
                from composed_adoption import closeout as adopted_closeout
                from composed_cases import ADOPT
                if not adopted_closeout(self,children):
                    return None
                ordinary=children if not waived else [value for value in children if value['birth'] not in waived]
                if (payload['case'] != self.case
                        or any(not self.completed_child(value) for value in ordinary)
                        or any(not value['consumed'] for value in self.intents.values() if value['case'] == self.case)
                        or any(not (self.git.reaped(value) if value['role']=='git-helper' else
                            self.ledger.reaped(value['birth'], value['token']) or self.case in ADOPT and self.ledger.process(value['birth']).init_wait is not None) for value in ordinary)):
                    raise Refused('source original case actual cleanup incomplete')
                if self.full:
                    self.outcomes.append(dict(payload))
                self.completed.append(self.case)
                self.case = None
        elif kind == 'root-finish':
            self.root_only(actor)
            from source_profile import case_seal
            shape(payload, ('count', 'cases_sha256'))
            if (self.case is not None or any(row['outcome']=='failed' for row in self.outcomes) or type(payload['count']) is not int or type(payload['cases_sha256']) is not str
                    or payload != case_seal(self.cases) or tuple(self.completed) != self.cases):
                raise Refused('source original source completion incomplete')
            self.finished = True
        elif kind == 'multiprocess-proposal':
            from multiprocess_entry import proposal
            return proposal(self,actor,payload)
        elif kind=='archive-snapshot':
            from package_proposals import snapshot
            return snapshot(self,actor,payload)
        elif kind=='archive-result':
            from package_cases import NEGATIVE,POSITIVE
            if (actor['role']!='archive-leaf' or actor['case']!=self.case or self.case not in (*NEGATIVE,POSITIVE)
                    or not actor['body_ready'] or 'archive_result' in actor):
                raise Refused('archive result scope')
            if bound_intent(self,actor) is None:
                raise Refused('archive result original consumed intent')
            expected={'kind':NEGATIVE.get(self.case,'normal'),'count':0 if NEGATIVE.get(self.case)=='missing-package' else 15,
                'failed':15 if NEGATIVE.get(self.case)=='missing-corpus' else 0,'exit':1 if self.case in NEGATIVE else 0}
            shape(payload,('kind','count','failed','exit'))
            if (type(payload['kind']) is not str or any(type(payload[key]) is not int for key in ('count','failed','exit'))
                    or payload!=expected):
                raise Refused('archive actual original result')
            actor['archive_result']=dict(payload)
        elif kind == 'preselected-finish':
            from nested_pytest import CASES
            from source_profile import case_seal
            if (actor['role']!='pytest-regression' or actor['case']!=self.case or self.case not in CASES
                    or not actor['body_ready'] or actor.get('preselected_complete') or payload!=case_seal(CASES[self.case]) or bound_intent(self,actor) is None):
                raise Refused('preselected child completion scope')
            actor['preselected_complete']=True
        elif kind == 'fixture-root':
            from speed_inline import CASES,directory
            self.root_only(actor)
            shape(payload,('path',))
            if self.case not in CASES or self.case in self.fixture_roots:
                raise Refused('speed fixture once per active case')
            self.fixture_roots[self.case]=directory(payload['path'],Path(self.meta['owned']),self.case)
        elif kind == 'launch-proposal':
            from effect_proposals import proposal
            return proposal(self,actor,payload)
        elif kind == 'self-stop':
            shape(payload, ('signal',))
            children = [value for value in self.actors.values() if self.ledger.process(value['birth']).parent == actor['birth']]
            if (actor['role'] != 'session-adapter' or actor['case'] != self.case or self.case != SESSION_TIMEOUT
                    or type(payload['signal']) is not int or payload['signal'] != 15 or 15 not in actor['signals']
                    or len(children) != 1 or not all(self.ledger.reaped(value['birth'], value['token']) for value in children)):
                raise Refused('session self stop before original child wait')
        elif kind=='approval-signal':
            shape(payload,('pid','signal','group'))
            from approval_launch import signal
            return signal(self,actor,payload)
        elif kind=='resumed-signal':
            shape(payload,('pid','signal','group'))
            if type(payload['pid']) is not int or type(payload['signal']) is not int or type(payload['group']) is not bool:
                raise Refused('composed resumed signal schema')
            from composed_adoption import signal
            return signal(self,actor,payload)
        elif kind == 'custody_signal':
            self.launch_owner(actor)
            shape(payload, ('pid', 'child_token', 'signal', 'group'))
            child = self.actors.get(number(payload['pid'], 1))
            if (child is None or child['role'] == 'root' or child['case'] != self.case or payload['child_token'] != child['token']
                    or self.ledger.process(child['birth']).parent != actor['birth']
                    or type(payload['signal']) is not int or type(payload['group']) is not bool
                    or payload['signal'] not in (0,9,15) and not (payload['signal'] == 10 and payload['group'] is False
                        and child['role'] == 'backend' and self.case in (*WARNING_REFUSALS,*NOTIFICATION_SIGNALS,'tests/test_experimental_bridge_shutdown.py::test_owned_teardown_completes_after_native_drain_failure'))):
                raise Refused('source exact owned signal')
            if payload['signal'] == 10 and self.case in (*WARNING_REFUSALS,*NOTIFICATION_SIGNALS) and 10 in child['signals']:
                raise Refused('controlled warning signal replay')
            process = self.ledger.process(child['birth'])
            if payload['signal'] == 0:
                intent=bound_intent(self,child)
                worker=child['role']=='fixed-inline' and intent is not None and intent.get('run_worker') is True
                journal=self.case==JOURNAL_CASE and child['role']=='fixed-inline'
                if (payload['group'] or child['role']!='workspace-owned' and not journal and not worker
                        or journal and child.get('liveness_probes',0)!=0):
                    raise Refused('source exact owned liveness probe')
                if journal:
                    child['liveness_probes']=1
                try:
                    if Birth.read(process_identity(child['birth'].pid)) != self.ledger.peer_birth(child['birth']):
                        raise Refused('source reused probe PID')
                except (FileNotFoundError, ProcessLookupError):
                    pass
                return {'ok': True, 'live': True}
            if process.exit is not None or process.terminal is not None:
                return {'ok': True, 'live': False}
            actual = process_identity(child['birth'].pid)
            if (Birth.read(actual) != self.ledger.peer_birth(child['birth']) or payload['group'] and (not process.new_session or actual['pgid'] != child['birth'].pid or actual['sid'] != child['birth'].pid)):
                return {'ok': True, 'live': False}
            if payload['group']:
                from composed_adoption import record_group
                record_group(self,child,payload['signal'])
            else:
                child['signals'].add(payload['signal'])
            return {'ok': True, 'live': True}
        elif kind == 'guard-refusal':
            shape(payload, ('code',))
            if (type(payload['code']) is not str or not 0 < len(payload['code']) <= 128
                    or any(not char.isascii() or not (char.isalnum() or char in ' -_') for char in payload['code'])):
                raise Refused('source refusal code schema')
            raise Refused('source guard refusal')
        else:
            raise Refused('source undeclared observer method')
        return {'ok': True}

    def validate_wait(self, trace, pid, requested):
        # Consume every birth/exec before resuming even a nonblocking/error wait.
        self.consume(trace)
        self.ledger.wait_entry(Birth.read(trace.identities[pid]), requested)

    def tick(self, trace):
        self.consume(trace)
        while len(self.frames) < 32:
            try:
                stream, _ = self.server.accept()
            except BlockingIOError:
                break
            pid, uid, gid = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            actor = self.actors.get(pid)
            if actor is None or uid != 20000 or gid != 20000:
                stream.close()
                raise Refused('source registered channel peer')
            frame = Frame(stream, REQUEST_LIMIT, seconds=8 if self.case in CLEANUP_CASES else 4)
            self.frames.append({'frame': frame, 'actor': actor, 'request': None})
            frame.capture(self.ledger, actor['birth'], actor['token'], 20000)
        for channel in list(self.frames):
            frame, actor = channel['frame'], channel['actor']
            if channel['request'] is None:
                value = frame.read()
                if value is None:
                    if frame.eof:
                        if cancelled_empty(frame, self.ledger, actor['birth'], actor['token']):
                            frame.stream.close()
                            self.frames.remove(channel)
                        elif self.ledger.process(actor['birth']).terminal is not None and actor['role'] != 'acp':
                            raise Refused('source undischarged empty control EOF')
                    continue
                admitted=self.admission.admit(frame)
                from cohort_controller import WAIVED
                from composed_cases import ADOPT
                if actor['role']=='root' and admitted['kind']=='case-finish' and self.case in (*WAIVED,*ADOPT):
                    frame.seconds=22
                channel['request'] = admitted
                self.controls.append({**admitted, 'observed_monotonic_ns': time.monotonic_ns()})
            if frame.output is None:
                answer = self.dispatch(actor, channel['request'])
                if answer is not None:
                    frame.answer(reply(channel['request'], answer))
            if frame.output is not None and frame.send():
                frame.stream.close()
                self.frames.remove(channel)
        while True:
            try:
                block = os.read(self.out_read, 65536)
            except BlockingIOError:
                break
            if not block:
                break
            self.output.extend(block)
            if len(self.output) > 8 * 1024 * 1024:
                raise Refused('source bounded private output')

    def close(self):
        self.server.close()
        for channel in self.frames:
            channel['frame'].stream.close()
        os.close(self.out_read)
        (self.directory / 'control.sock').unlink(missing_ok=True)
        for case in CLEANUP_CASES:
            snapshot_path(self.directory, case).unlink(missing_ok=True)
        for actor in self.actors.values():
            (self.directory / (str(actor['birth'].pid) + '.json')).unlink(missing_ok=True)
