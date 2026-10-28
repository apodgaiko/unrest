"""Independent finite observer for the original bootstrap cases.

No legacy resolver, arbitrary executable request, or provider permission path.
Kernel births/execs and actual waits remain independent of source-side reports.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import time

from review_wire import CASES as REVIEW_CASES,SCRIPT as REVIEW_SCRIPT,count as review_count
from multiprocess_entry import ALL_CASES as MP_CASES, count as mp_count
from content_manifest import Refused, native_digest
from http_cases import CASES as HTTP_CASES, TRANSPORT as MCP_CASES
from preflight_cases import NO_EFFECT
from plan_launch import CASES as PLAN_CASES, INVALID as PLAN_INVALID, PYTHON as PLAN_PYTHON
from control_transport import Admission, Frame, REQUEST_LIMIT, cancelled_empty, reply
from bootstrap_cases import BOOTSTRAP, declaration
from controlled_cases import CASES as CONTROLLED, backend_path, WARNING_REFUSALS, NOTIFICATION_SIGNALS, ROOT_HTTP
from controlled_pairs import before_bind, before_spawn, limits as controlled_limits, scope as controlled_scope
from controlled_startup import ACP
from endpoint_policy import Endpoints, Owner, Route
from linux_observation import process_identity
from process_ledger import Birth, Ledger, canonical
from socket_observation import acquire_tcp, acquire_unix_member, acquire_unix_pair
from source_profile import METHODS, ROOT_COMMAND
from ordinary_acp import CASES as ORDINARY_CASES, MOCK, NEGATIVE_CASES
from unix_endpoints import UnixPairs
from session_launch import CASES as SESSION_CASES, LIVE as SESSION_LIVE, TIMEOUT as SESSION_TIMEOUT, SCRIPT as SESSION_SCRIPT
from fixed_inline import CASES as FIXED_CASES, SEQUENCES as FIXED_SEQUENCES, CLI_CASE
from git_sites import CASES as GIT_CASES
from git_observer import Git
from cleanup_inline import NO_LAUNCH, STARTUP, DECLARATIONS, INFLIGHT, child_count as inline_count
from cleanup_launch import EXECUTION_CASES as CLEANUP_CASES, GROUPS as CLEANUP_GROUPS, child_count, SCRIPT, snapshot_path


def shape(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise Refused('source observer operation schema')


def number(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise Refused('source observer integer')
    return value


def native_class(role):
    return 'native-git-command' if role == 'git-custody' else 'native-' + role


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
        self.endpoints, self.actors, self.intents = Endpoints(self.ledger), {}, {}
        self.pairs = UnixPairs(self.endpoints)
        self.bindings, self.listeners, self.listener_fds, self.pair_intents = {}, {}, {}, {}
        self.routes, self.connections, self.descriptors, self.mp_pipes = {}, {}, {}, {}
        self.eof_drains, self.eof_fds, self.interrupted_records = {}, {}, []
        self.connected_routes: dict[str, int] = {}
        self.probe_ports = {}
        self.fixture_roots = {}
        self.plan_records: list[dict] = []
        self.http_contexts: dict[tuple[str,int],dict] = {}
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

    def owner(self, actor):
        return Owner(actor['birth'], actor['token'], 1)

    def profile(self, pid, role, case, vector, environment, cwd, token, inherited=()):
        actual = process_identity(pid)
        parent = Birth.read(process_identity(actual['ppid']))
        scripts = {'desktop':'tools/v046_desktop_fixture.py','review-wire':REVIEW_SCRIPT,'session-adapter': SESSION_SCRIPT, 'session-child': SESSION_SCRIPT,
                   'cleanup-acp': SCRIPT, 'acp': ACP, 'mock-acp': MOCK}
        script = (str(Path(self.meta['checkout']) / scripts[role]) if role in scripts else
                  str(backend_path(case,Path(cwd).parent) if case in CONTROLLED else Path(cwd).parent / 'fake-app-server') if role in ('backend', 'delayed-backend') else None)
        if role=='fixed-inline' and case==CLI_CASE:
            script=str(Path(self.meta['checkout'])/'tools/v04_speed_runner.py')
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
        source['execution'] = (issue(role,vector,None,None) if role=='root' else
            admitted(self.intents,role,case,pid,token,vector,environment,cwd,script))
        source['seal'] = hashlib.sha256(json.dumps(source, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        target = self.directory / (str(pid) + '.json')
        with target.open('x') as stream:
            stream.write(json.dumps(source, sort_keys=True))
        target.chmod(0o444)
        pins = tuple(sorted((('entry', source['entry_sha256']), ('native', source['native_sha256']),
            ('source', source['source_sha256']), ('support', source['support_sha256']),
            ('runtime', source['runtime_sha256']), ('dependency', source['dependency_sha256']))))
        actor = {'birth': Birth.read(actual), 'role': role, 'case': case, 'token': token,
                 'profile': source, 'pins': pins, 'sequence': 0, 'returned': role == 'root', 'body_ready': False, 'signals': set()}
        self.actors[pid] = actor
        command_class = {'root': 'bootstrap-root', 'acp': 'controlled-acp',
                         'backend': 'controlled-backend', 'delayed-backend': 'controlled-backend-wrapper', 'mock-acp': 'ordinary-mock-acp', 'mcp': 'worker-mcp', 'cleanup-acp': 'cleanup-acp', 'cleanup-inline': 'cleanup-inline', 'workspace-owned': 'workspace-owned', 'session-adapter': 'session-adapter', 'session-child': 'session-child', 'session-inline': 'session-inline', 'fixed-inline': 'fixed-inline','plan-python':'plan-python','mp-child':'mp-child','mp-tracker':'mp-tracker','review-wire':'review-wire','pytest-regression':'pytest-regression','desktop':'desktop'}[role]
        new_session = role in ('backend','delayed-backend','acp','workspace-owned','session-adapter','session-inline') or role=='mcp' and case in HTTP_CASES
        self.ledger.register(actor['birth'], token, pins, source['seal'], case=case,
                             command_class=command_class, new_session=new_session, expected_generation=1)
        if new_session:
            common = {'owner_pid': self.root, 'token': token, 'case': case, 'class': command_class}
            witnesses = ({'kind': 'admitted', **common}, {'kind': 'registered', 'pid': pid, 'python': True, **common},
                         {'kind': 'launch_lifecycle_binding', 'start_new_session': True, **common})
            self.ledger.session(actor['birth'], actual, witnesses)
        if role=='mp-child':
            self.mp_pipes.update({(actor['birth'],row[0]):row for row in inherited if len(row)==7})
        return actor

    def consume(self, trace):
        self.ledger_trace = trace
        while self.ledger.next_kernel < len(trace.records):
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
                    if actor is None or actor['role'] not in ('root', 'mcp', 'git-command', 'session-adapter', 'fixed-inline','desktop') or len(candidates) != 1:
                        raise Refused('source fork without a unique original launch intent')
            if row['kind'] == 'kernel_exit' and row.get('raw') == 86 << 8:
                self.ledger.poison.append('native guard refusal')
            if row['kind'] == 'kernel_root' and not self.full:
                from postbuild_root import CASES as ARCHIVE_CASES, COMMAND as ARCHIVE_COMMAND
                vector=([self.binding['entry']['path'],'-I','-S','-c',ARCHIVE_COMMAND,self.binding['checkout']]
                    if self.cases==ARCHIVE_CASES else [self.binding['entry']['path'],'-I','-S','-c',ROOT_COMMAND])
                self.profile(self.root, 'root', '<bootstrap>',
                    vector,
                    self.meta_environment(), self.meta['checkout'], os.urandom(16).hex())

    def meta_environment(self):
        if self.full:
            from full_source import child_environment
            return child_environment(self.meta)
        owned = Path(self.meta['owned'])
        return {'HOME': str(owned / 'home'), 'TMPDIR': str(owned / 'tmp'),
                'PATH': ('/native/bin:' if '/native' in self.meta['mounts'] else '')+'/usr/bin:/bin',
                'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}

    def stdio(self, pid, role, *, input_pipe=False, intent=None):
        if role=='mcp' and self.case in HTTP_CASES:
            from http_cases import stdio
            return stdio(self,pid,intent)
        parent = Path('/proc') / str(process_identity(pid)['ppid']) / 'fd'
        parent_inodes = set()
        for fd in parent.iterdir():
            try:
                info = fd.stat()
            except FileNotFoundError:
                continue
            if stat.S_ISFIFO(info.st_mode):
                parent_inodes.add((info.st_dev, info.st_ino))
        for descriptor in (0, 1, 2):
            info = (Path('/proc') / str(pid) / 'fd' / str(descriptor)).stat()
            inline = role == 'cleanup-inline'
            terminal = inline and self.case in INFLIGHT and os.readlink(Path('/proc') / str(pid) / 'cwd') != self.meta['checkout']
            inherited = inline and (descriptor == 0 if terminal or self.case in STARTUP else descriptor == 2)
            if terminal and descriptor == 2:
                other = (Path('/proc') / str(pid) / 'fd/1').stat()
                if (info.st_dev, info.st_ino) != (other.st_dev, other.st_ino):
                    raise Refused('cleanup inline merged terminal stderr')
            if role in ('git-init', 'git-commit', 'session-child','mp-child','mp-tracker') or role == 'git-command' and descriptor == 0 and not input_pipe or inherited or (descriptor == 0 and role in ('mcp', 'git-observe', 'fixed-inline', 'pytest-regression', 'git-fixed','ps') and not input_pipe):
                expected_info = (parent / str(descriptor)).stat()
                if (info.st_mode, info.st_dev, info.st_ino, info.st_rdev) != (expected_info.st_mode, expected_info.st_dev, expected_info.st_ino, expected_info.st_rdev):
                    raise Refused('source exact inherited descriptor')
            elif role == 'git-custody' and descriptor in (0,2):
                null = Path('/dev/null').stat()
                if not stat.S_ISCHR(info.st_mode) or info.st_rdev != null.st_rdev:
                    raise Refused('custody Git exact null descriptors')
            elif role == 'git-helper':
                null = Path('/dev/null').stat()
                if not ((stat.S_ISCHR(info.st_mode) and info.st_rdev == null.st_rdev)
                        or (stat.S_ISFIFO(info.st_mode) and (info.st_dev, info.st_ino) in parent_inodes)):
                    raise Refused('Git helper parent pipe or null descriptor')
            elif role == 'workspace-owned':
                null = Path('/dev/null').stat()
                if not stat.S_ISCHR(info.st_mode) or info.st_rdev != null.st_rdev:
                    raise Refused('workspace exact null descriptors')
            elif role == 'sleep' and (descriptor == 0 or self.case != ORDINARY_CASES[2]):
                expected_fd = parent / str(descriptor) if descriptor == 0 else Path('/dev/null')
                expected_info = expected_fd.stat()
                if (info.st_mode, info.st_dev, info.st_ino, info.st_rdev) != (expected_info.st_mode, expected_info.st_dev, expected_info.st_ino, expected_info.st_rdev):
                    raise Refused('source inherited native fixture descriptor')
            elif descriptor == 2 and role=='desktop':
                other=(parent/'2').stat()
                if (info.st_dev,info.st_ino,info.st_mode)!=(other.st_dev,other.st_ino,other.st_mode):
                    raise Refused('desktop exact inherited stderr')
            elif descriptor == 2 and role == 'acp':
                null = Path('/dev/null').stat()
                if not stat.S_ISCHR(info.st_mode) or info.st_rdev != null.st_rdev:
                    raise Refused('source exact ACP stderr')
            elif not stat.S_ISFIFO(info.st_mode) or (info.st_dev, info.st_ino) not in parent_inodes:
                raise Refused('source exact parent-owned pipe')

        output = (Path('/proc') / str(pid) / 'fd/1').stat()
        return (output.st_dev, output.st_ino)

    def resolve(self, trace, pid, path, vector, environment, cwd):
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
                   and value['cwd'] == cwd and path == value.get('executable', self.binding['entry']['path'])]
        if len(matches) != 1:
            return False
        if native_digest(Path(path).resolve(strict=True)) != matches[0].get('executable_sha256', self.binding['entry']['sha256']):
            return False
        intent = matches[0]
        from desktop_launch import CASE as DESKTOP_CASE,retained as desktop_retained
        if intent['case']==DESKTOP_CASE:
            desktop_retained(self)
            if intent['role']=='ps' and str(Path(path).resolve(strict=True))!='/usr/bin/ps':
                raise Refused('desktop retained system ps alias')
        if process_identity(pid)['namespaces']['mnt'] != os.readlink('/proc/self/ns/mnt'):
            return False
        intent['stdout'] = self.stdio(pid, intent['role'],
            input_pipe=intent.get('input_pipe',False) or intent['role'] == 'git-command' and intent['command'].stdin is not None,intent=intent)
        intent['consumed'], intent['pid'], intent['birth'] = True, pid, birth
        if intent['role'] in ('sleep', 'session-invalid','ps') or intent['role'].startswith('git-'):
            actual = process_identity(pid)
            birth = Birth.read(actual)
            pins = (('native-fixture', intent['executable_sha256']),)
            self.ledger.register(birth, intent['token'], pins, intent['executable_sha256'],
                                 case=intent['case'], command_class=native_class(intent['role']), expected_generation=0 if intent['role'] == 'session-invalid' else 1)
            self.actors[pid] = {'birth': birth, 'role': intent['role'], 'case': intent['case'], 'token': intent['token'],
                'returned': False, 'body_ready': False, 'signals': set(), 'kernel_admitted': True}
        else:
            from speed_inline import CASES as SPEED_CASES,fixture
            if intent['case'] in (*SPEED_CASES,CLI_CASE):
                fixture(self)
            self.profile(pid, intent['role'], intent['case'], vector, environment, cwd, intent['token'], intent.get('inherited', ()))
        return True

    def actor_control(self, actor, kind, payload):
        self.ledger.control(actor['birth'], actor['token'], 1, actor['sequence'], kind, payload)
        actor['sequence'] += 1

    def root_only(self, actor):
        if actor['birth'] != self.root_birth or actor['role'] != 'root' or self.finished:
            raise Refused('source root-only operation')

    def launch_owner(self, actor):
        if actor['role'] == 'root':
            self.root_only(actor)
            return
        if actor['role']=='desktop' and actor['case']==self.case and not self.finished:
            from desktop_launch import CASE
            if self.case==CASE:
                return
        if actor['role'] == 'fixed-inline' and actor['case'] == self.case and not self.finished:
            if sum(value.get('fixed_operation') == 'check' and value['token'] == actor['token'] for value in self.intents.values()) != 1:
                raise Refused('fixed inline has no query authority')
            return
        if actor['role'] == 'session-adapter' and actor['case'] == self.case == SESSION_TIMEOUT and not self.finished:
            return
        if self.finished or actor['role'] not in ('root', 'mcp') or actor['role'] == 'mcp' and actor['case'] != self.case:
            raise Refused('source original launch owner')


    def listener_key(self,case,tag,scope=None):
        return (case,tag,scope) if case in CONTROLLED else (case,tag)

    def admit_launch(self, actor, expected, role, vector, script_pin,
                     *, maximum=1, environment=None, inherited=(), port=None):
        if (expected.case != self.case or sum(value['case'] == self.case and value['role'] == role
                       and (self.case not in CONTROLLED or value['cwd'] == expected.cwd)
                       for value in self.intents.values()) >= maximum):
            raise Refused('source independent launch reconstruction')
        # Hold the next constructor until the prior child passes exact exec
        # admission. The fork boundary keeps its unique-intent requirement.
        if any(not value['consumed'] and value.get('parent', self.root_birth) == actor['birth']
               for value in self.intents.values()):
            return None
        self.serial += 1
        token = os.urandom(16).hex()
        self.intents[self.serial] = {'case': self.case, 'role': role, 'parent': actor['birth'],
            'environment': dict(expected.environment) if environment is None else environment,
            'cwd': expected.cwd, 'translated': vector, 'token': token, 'consumed': False, 'pid': None,
            'executable': expected.executable, 'executable_sha256': expected.executable_sha256,
            'script_sha256': script_pin,
            'inherited': list(inherited), 'port': port}
        return {'ok': True, 'ticket': self.serial, 'token': token}

    def socket_payload(self, actor, payload):
        shape(payload, ('fd', 'operation', 'bytes'))
        fd = number(payload['fd'])
        count = number(payload['bytes'])
        if payload['operation'] not in ('accept', 'send', 'sendall', 'recv', 'recv_into', 'recvfrom', 'recvfrom_into', 'fd-read', 'fd-write'):
            raise Refused('source payload operation')
        key = actor['birth'], fd
        serial = self.eof_fds.get(key)
        if serial is not None:
            drain = self.eof_drains[serial]
            if (payload['operation'] not in ('recv', 'recv_into', 'fd-read') or drain['reads'] >= 8
                    or acquire_tcp(actor['birth'], fd, retained=True, eof_only=True) != drain['socket']):
                raise Refused('source interrupted socket grants EOF reads only')
            drain['reads'] += 1
            return {'ok': True, 'eof_only': True}
        if key in self.mp_pipes:
            if payload['operation'] not in ('fd-read','fd-write'):
                raise Refused('spawn Pipe permits original Connection file I/O only')
            from multiprocess_pipe import retained as pipe_retained
            pipe_retained(self,actor,self.mp_pipes[key],body=True)
            return {'ok':True}
        pair = self.descriptors.get(key)
        if pair is not None:
            observed = acquire_unix_member(actor['birth'], fd, pair)
            self.pairs.retained(pair, self.owner(actor), observed)
            return {'ok': True}
        slot = self.listener_fds.get(key)
        if slot is not None and payload['operation'] == 'accept':
            if acquire_tcp(actor['birth'], fd, retained=True) != slot['socket']:
                raise Refused('source live listener acceptance')
            return {'ok': True}
        connection = self.connections.get(key)
        if connection is not None:
            observed = acquire_tcp(actor['birth'],fd,retained=True)
            if self.case in ROOT_HTTP:
                from root_http_observer import retained
                retained(self,connection,observed)
            self.endpoints.retained(connection,self.owner(actor),observed)
            return {'ok': True}
        tickets = [ticket for ticket in self.endpoints.tickets.values()
                   if ticket.client.owner == actor['birth'] and ticket.client.fd == fd]
        if len(tickets) == 1 and payload['operation'] in ('send', 'sendall', 'fd-write'):
            ticket = tickets[0]
            self.endpoints.queued_send(ticket,
                acquire_tcp(ticket.listener.owner, ticket.listener.fd, retained=True),
                acquire_tcp(actor['birth'], fd, retained=True), count)
            return {'ok': True}
        if len(tickets) == 1 and actor['birth'] != tickets[0].route.server.birth:
            return None  # A different process can make the actual accept join.
        raise Refused('source unadmitted payload descriptor')

    def completed_child(self, actor):
        process = self.ledger.process(actor['birth'])
        terminal = process.terminal
        if actor['role']=='desktop':
            return terminal is not None and terminal[2]==0 and actor['body_ready']
        if actor['role']=='pytest-regression':
            return terminal is not None and terminal[2]==0 and actor['body_ready'] and actor.get('preselected_complete') is True
        if actor['role']=='ps':
            return terminal is not None and terminal[2]==0 and actor.get('kernel_admitted') is True
        if actor['role']=='mcp' and actor['case'] in HTTP_CASES:
            return terminal is not None and actor['body_ready'] and (terminal[2]==0 or terminal[2] in (-9,-15) and -terminal[2] in actor['signals'])
        if actor['role']=='review-wire':
            return terminal is not None and actor['body_ready'] and (terminal[2]==0 or terminal[2]==-9 and 9 in actor['signals'])
        if actor['role'] in ('mp-child','mp-tracker'):
            rows=[row for row in self.intents.values() if row.get('birth')==actor['birth'] and row['token']==actor['token']
                and row['case']==actor['case'] and row['role']=='mp-child' and row['consumed']]
            if actor['role']=='mp-child' and len(rows)!=1:
                return False
            status=rows[0]['mp_status'] if actor['role']=='mp-child' else 0
            return terminal is not None and terminal[2]==status and actor['body_ready'] and (status>=0 or -status in actor['signals'])
        if actor['case'] in PLAN_CASES:
            values=[value for value in self.intents.values() if value['case']==actor['case'] and value.get('pid')==actor['birth'].pid]
            if len(values)!=1 or terminal is None:
                return False
            value=values[0]
            if actor['case']==PLAN_INVALID:
                return process.generation==0 and terminal[2]==255 and value.get('plan_failed') is True and not actor['body_ready']
            return (process.generation==1 and terminal[2]==0 and value.get('plan_exec_verified') is True
                    and (actor['body_ready'] if actor['case']==PLAN_PYTHON else actor.get('kernel_admitted') is True))
        if actor['role'] == 'session-invalid':
            failures = [row for row in self.ledger_trace.records if row['kind'] == 'exec_syscall_return' and row['pid'] == actor['birth'].pid]
            return process.generation == 0 and terminal is not None and terminal[2] == 255 and len(failures) == 1 and failures[0]['return'] == -8
        return (terminal is not None and (actor.get('kernel_admitted') is True or actor['body_ready']
                or terminal[2] in (-9, -15) and -terminal[2] in actor['signals']))

    def retire_cancelled_tickets(self):
        if self.case not in BOOTSTRAP or not declaration(self.case).interrupted:
            raise Refused('source cancelled ticket outside interrupted case')
        root = self.actors[self.root]
        for serial,ticket in sorted(list(self.endpoints.tickets.items())):
            if ticket.route.case != self.case or serial in self.eof_drains:
                continue
            child = self.actors.get(ticket.route.client.birth.pid)
            process = self.ledger.process(ticket.route.client.birth)
            terminal = process.terminal
            if (ticket.route.server != self.owner(root) or child is None or child['role']!='acp'
                    or child['birth']!=ticket.route.client.birth or child['token']!=ticket.route.client.token
                    or child['case']!=self.case or ticket.route.name not in (child['token']+':bridge',child['token']+':lifetime')
                    or terminal is None or terminal[2] not in (-9,-15) or -terminal[2] not in child['signals']
                    or not self.ledger.reaped(child['birth'],child['token'])):
                raise Refused('source cancelled ticket requires exact signalled parent reap')
            self.endpoints.abort_reaped(ticket)
            self.interrupted_records.append({'kind':'cancelled-unjoined','ticket':serial,
                'actual_original_parent_reap':True,'accepted_peer_proven':False,'descriptor_close_proven':False})

    def interrupted_accept(self, actor, matches, server):
        """No peer association is inferred from EOF; this is not a Connection."""
        if not declaration(self.case).interrupted or len(matches) != 1 or server is None:
            raise Refused('source unjoined accept outside interrupted case')
        ticket = matches[0]
        process = self.ledger.process(ticket.route.client.birth)
        child = self.actors[ticket.route.client.birth.pid]
        terminal = process.terminal
        if terminal is None:
            return None  # The tracer can harvest the dead child while root waits.
        if (terminal[2] not in (-9, -15) or -terminal[2] not in child['signals']
                or child['birth'] != ticket.route.client.birth or child['case'] != self.case
                or ticket.route.case != self.case or ticket.route.server != self.owner(actor)
                or server.owner != actor['birth'] or server.remote is None or server.remote[0] != '127.0.0.1'
                or server.local != ticket.listener.local or server.binding() == ticket.listener.binding()
                or acquire_tcp(actor['birth'], ticket.listener.fd, retained=True) != ticket.listener):
            raise Refused('source interrupted accept ownership or signal')
        eof = acquire_tcp(actor['birth'], server.fd, retained=True, eof_only=True)
        if eof is None or eof != server or ticket.serial in self.eof_drains:
            raise Refused('source interrupted accepted descriptor or EOF')
        self.eof_drains[ticket.serial] = {'ticket': ticket, 'socket': eof, 'reads': 0}
        self.eof_fds[actor['birth'], eof.fd] = ticket.serial
        self.interrupted_records.append({'kind': 'EOF-only-unjoined', 'ticket': ticket.serial,
            'root': actor['birth'].pid, 'fd': eof.fd, 'inode': eof.inode, 'cookie': eof.cookie,
            'accepted_peer_proven': False})
        return {'ok': True, 'eof_only': True}

    def dispatch(self, actor, request):
        kind, payload = request['kind'], request['payload']
        if kind == 'core-ready':
            shape(payload, ('pins',))
            if payload['pins'] != [list(pair) for pair in actor['pins']]:
                raise Refused('source exact READY pins')
            self.actor_control(actor, kind, {'pins': actor['pins']})
            if actor['role']=='mp-child':
                from multiprocess_pipe import retained
                for (birth,_),row in self.mp_pipes.items():
                    if birth==actor['birth']:
                        retained(self,actor,row,body=False)
            tags = (('bridge', 'lifetime') if actor['role'] == 'acp' else
                    ('broker',) if actor['role'] in ('backend', 'delayed-backend') and (controlled_limits(actor['case'])[1] > 0 if actor['case'] in CONTROLLED else declaration(actor['case']).broker_http) else ())
            if tags:
                root_actor = self.actors[self.root]
                for tag in tags:
                    scope = actor['profile']['cwd'] if tag in ('bridge','lifetime') else str(Path(actor['profile']['cwd']).parent)
                    slot = self.listeners[self.listener_key(actor['case'],tag,scope)]
                    name = actor['token'] + ':' + tag
                    route = Route(name, actor['case'], self.owner(root_actor), self.owner(actor), slot['socket'].local[1])
                    actual_listener = acquire_tcp(self.root_birth, slot['socket'].fd, retained=True)
                    sharing = actual_listener if any(value.port == route.port and value.case not in self.endpoints.retired for value in self.endpoints.routes.values()) else None
                    self.endpoints.declare(route, shared_listener=sharing)
                    self.endpoints.listen(name, actual_listener)
                    self.routes[actor['birth'], route.port] = name
        elif kind == 'body-ready':
            self.actor_control(actor, kind, payload)
            actor['body_ready'] = True
        elif kind == 'collection-finish':
            self.root_only(actor)
            from source_profile import case_seal
            if not self.binding.get('collection_only') or payload!=case_seal(self.cases) or self.completed:
                raise Refused('full collection-only completion')
            self.finished=True
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
                spec = declaration(self.case) if self.case in BOOTSTRAP else None
                count = review_count(self.case) if self.case in REVIEW_CASES else mp_count(self.case)+(2 if self.case in HTTP_CASES else 0) if self.case in MP_CASES else 0 if self.case in NO_EFFECT else 1 if self.case in PLAN_CASES else (len(FIXED_SEQUENCES[self.case]) + FIXED_SEQUENCES[self.case].count('check')) if self.case in FIXED_CASES else (2 if self.case == SESSION_TIMEOUT else 1 if self.case in SESSION_LIVE else 0) if self.case in SESSION_CASES else len(children) if self.case in (*GIT_CASES,*CONTROLLED) else inline_count(self.case) if self.case in DECLARATIONS else child_count(self.case) if self.case in CLEANUP_CASES else 0 if self.case in (*NEGATIVE_CASES, *NO_LAUNCH) else 3 if self.case == ORDINARY_CASES[2] else 2 if self.case in (*BOOTSTRAP,*ORDINARY_CASES) else 0
                if outcome=='failed':
                    count,spec=len(children),None
                if skipped:
                    count,spec=0,None
                    if children:
                        raise Refused('skipped source case launched children')
                for serial, drain in list(self.eof_drains.items()):
                    ticket = drain['ticket']
                    if ticket.route.case == self.case:
                        if spec is None or not spec.interrupted:
                            raise Refused('source aborted route in positive case')
                        self.endpoints.abort_reaped(ticket)
                        self.interrupted_records.append({'kind': 'aborted-unjoined', 'ticket': serial,
                            'actual_original_parent_reap': True, 'accepted_peer_proven': False})
                        self.eof_fds.pop((actor['birth'], drain['socket'].fd), None)
                        del self.eof_drains[serial]
                if spec is not None and spec.interrupted:
                    self.retire_cancelled_tickets()
                if (payload['case'] != self.case or outcome=='passed' and self.case in GIT_CASES and len(children) < 5 or not ((spec.minimum_children <= len(children) <= spec.children) if spec else len(children) == count)
                        or any(not self.completed_child(value) for value in children)
                        or any(not value['consumed'] for value in self.intents.values() if value['case'] == self.case)
                        or any(not (self.git.reaped(value) if self.case in (*GIT_CASES,*CONTROLLED) else self.ledger.reaped(value['birth'], value['token'])) for value in children)
                        or any(ticket.route.case == self.case for ticket in self.endpoints.tickets.values())):
                    raise Refused('source original case actual cleanup incomplete')
                if outcome=='passed' and self.case in ROOT_HTTP and (sum(case == self.case for case,_ in self.http_contexts) != (2 if 'initialized_owner' in self.case else 1)
                        or any(state['active'] for (case,_),state in self.http_contexts.items() if case == self.case)):
                    raise Refused('root HTTP original contexts incomplete')
                self.endpoints.retire_case(self.case)
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
        elif kind == 'git-pipe':
            return self.git.seal_pipe(actor, payload)
        elif kind == 'git-output':
            return self.git.output(actor, payload)
        elif kind == 'multiprocess-proposal':
            from multiprocess_entry import proposal
            return proposal(self,actor,payload)
        elif kind == 'preselected-finish':
            from nested_pytest import CASE,NODES
            from source_profile import case_seal
            rows=[row for row in self.intents.values() if row.get('birth')==actor['birth'] and row['token']==actor['token']
                  and row['consumed'] and row['role']==actor['role'] and row['case']==self.case]
            if (actor['role']!='pytest-regression' or actor['case']!=self.case or self.case!=CASE
                    or not actor['body_ready'] or actor.get('preselected_complete') or payload!=case_seal(NODES) or len(rows)!=1):
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
        elif kind == 'launch-return':
            self.launch_owner(actor)
            shape(payload, ('pid', 'ticket', 'token'))
            intent = self.intents[number(payload['ticket'], 1)]
            child = self.actors.get(number(payload['pid'], 1))
            if (not intent['consumed'] or intent['pid'] != payload['pid'] or child is None
                    or self.ledger.process(child['birth']).parent != actor['birth']
                    or intent['token'] != payload['token'] or child['returned']):
                raise Refused('source actual constructor return binding')
            child['returned'] = True
        elif kind == 'drain_child':
            self.launch_owner(actor)
            shape(payload, ('pid', 'requested_pid', 'child_token', 'raw_status', 'numeric_returncode', 'options'))
            child = self.actors.get(number(payload['pid'], 1))
            if child is None or not child['returned'] or self.ledger.process(child['birth']).parent != actor['birth']:
                raise Refused('source constructor before parent wait')
            row = {**payload, 'nonce': self.ledger.nonce, 'owner_pid': actor['birth'].pid,
                   'owner_identity': self.ledger.process(actor['birth']).registered_identity,
                   'owner_token': actor['token'], 'wait_event': 'actual_os_waitpid_return'}
            self.actor_control(actor, 'parent-wait', row)
        elif kind == 'pair-intent':
            shape(payload, ('site',))
            if payload['site'] != 'local-stream-pair' or len(self.pair_intents) >= 32:
                raise Refused('source finite self-pipe intent')
            self.serial += 1
            self.pair_intents[self.serial] = actor['birth']
            return {'ok': True, 'ticket': self.serial}
        elif kind == 'pair-seal':
            shape(payload, ('ticket', 'fds'))
            ticket = number(payload['ticket'], 1)
            if self.pair_intents.get(ticket) != actor['birth']:
                raise Refused('source self-pipe owner ticket')
            pair = self.pairs.admit(self.owner(actor), self.ledger.process(actor['birth']).case,
                                    acquire_unix_pair(actor['birth'], payload['fds']))
            del self.pair_intents[ticket]
            for member in pair.members:
                key = actor['birth'], member.fd
                self.eof_fds.pop(key, None)
                self.descriptors[key] = pair
                self.listener_fds.pop(key, None)
                self.connections.pop(key, None)
        elif kind == 'bind':
            if actor['role'] != 'mcp':
                self.root_only(actor)
            elif actor['case'] != self.case or self.case not in MCP_CASES:
                raise Refused('source declared module listener case')
            shape(payload, ('fd', 'tag', 'nonce', *(('scope',) if self.case in CONTROLLED else ())))
            scope = controlled_scope(self.case,payload['tag'],payload.get('scope'),Path(self.meta['owned'])) if self.case in CONTROLLED else None
            fd = number(payload['fd'])
            if ((actor['role'] == 'mcp' and payload['tag'] != 'mcp')
                    or actor['role'] == 'root' and (payload['tag'] not in (('mcp-probe',) if self.case in (*MCP_CASES, *STARTUP) else ('broker', 'bridge', 'lifetime'))
                        or self.case not in (*BOOTSTRAP, *CONTROLLED, *MCP_CASES, *STARTUP))):
                raise Refused('source finite root listener')
            if self.case in CONTROLLED:
                if scope is None:
                    raise Refused('controlled listener scope absent')
                slots = [row for row in (*self.bindings.values(),*self.listeners.values()) if row['case'] == self.case]
                before_bind(self.case,payload['tag'],scope,slots)
                if payload['tag'] == 'bridge':
                    before_spawn(self.case,scope,'acp',[v for v in self.intents.values() if v['case'] == self.case],self.actors)
            nonce = payload['nonce']
            if ((payload['tag'] in ('broker', 'mcp', 'mcp-probe') and nonce is not None)
                    or payload['tag'] not in ('broker', 'mcp', 'mcp-probe') and (type(nonce) is not str or len(nonce) != 64
                    or any(char not in '0123456789abcdef' for char in nonce))
                    or self.listener_key(self.case,payload['tag'],scope) in self.listeners):
                raise Refused('source listener application binding')
            observed = acquire_tcp(actor['birth'], fd, retained=True)
            if observed is None or observed.state != 7 or observed.local != ('0.0.0.0', 0) or observed.remote is not None:
                raise Refused('source fresh unbound TCP descriptor')
            key = actor['birth'], fd
            self.eof_fds.pop(key, None)
            self.descriptors.pop(key, None)
            self.connections.pop(key, None)
            self.listener_fds.pop(key, None)
            self.bindings[key] = {'socket': observed, 'tag': payload['tag'], 'nonce': nonce,
                                  'case': self.case, 'scope':scope, 'listening': False, 'listen_pending': False}
        elif kind == 'bound':
            self.root_only(actor)
            shape(payload, ('fd',))
            if self.case not in (*STARTUP,*HTTP_CASES) or self.case in self.probe_ports:
                raise Refused('source finite negative probe case')
            fd = number(payload['fd'])
            binding = self.bindings[actor['birth'], fd]
            observed = acquire_tcp(actor['birth'], fd, retained=True)
            if (binding['case'] != self.case or binding['tag'] != 'mcp-probe' or observed is None
                    or observed.binding() != binding['socket'].binding() or observed.state != 7
                    or observed.local[0] != '127.0.0.1' or not 0 < observed.local[1] <= 65535
                    or observed.remote is not None):
                raise Refused('source acquired negative probe port')
            self.probe_ports[self.case] = {'socket': observed, 'attempts': 0}
        elif kind == 'listen':
            if actor['role'] != 'mcp':
                self.root_only(actor)
            elif actor['case'] != self.case or self.case not in MCP_CASES:
                raise Refused('source declared module listener case')
            shape(payload, ('fd', 'stage'))
            fd = number(payload['fd'])
            binding = self.bindings[actor['birth'], fd]
            if binding['tag'] == 'mcp-probe':
                raise Refused('source advisory probe never grants a listener')
            observed = acquire_tcp(actor['birth'], fd, retained=True)
            if (binding['case'] != self.case or observed is None or observed.binding() != binding['socket'].binding()
                    or observed.local[0] != '127.0.0.1' or observed.remote is not None
                    or actor['role'] == 'mcp' and observed.local[1] != int(actor['profile']['argv'][12])):
                raise Refused('source original listener descriptor')
            if payload['stage'] == 'before':
                if (binding['listen_pending'] or observed.state != (10 if binding['listening'] else 7)
                        or binding['listening'] and observed != self.listeners[self.listener_key(self.case,binding['tag'],binding['scope'])]['socket']):
                    raise Refused('source listener before state')
                binding['listen_pending'] = True
            elif payload['stage'] == 'after':
                if not binding['listen_pending'] or observed.state != 10:
                    raise Refused('source listener after state')
                # asyncio re-applies Uvicorn's original backlog to this same
                # listener. A repeated listen grants no new endpoint authority.
                previous = self.listeners.get(self.listener_key(self.case,binding['tag'],binding['scope']))
                if previous is not None and observed != previous['socket']:
                    raise Refused('source changed repeated listener')
                binding['listen_pending'], binding['listening'] = False, True
                slot = {**binding, 'socket': observed}
                self.listeners[self.listener_key(self.case,binding['tag'],binding['scope'])] = slot
                self.listener_fds[actor['birth'], fd] = slot
            else:
                raise Refused('source listener stage')
        elif kind in ('root-http-open','root-http-close'):
            from root_http_observer import context as http_context
            return http_context(self,actor,kind,payload)
        elif kind == 'connect':
            root_http = actor['role'] == 'root' and self.case in ROOT_HTTP
            shape(payload, ('fd', 'address','context') if root_http else ('fd','address'))
            address = payload['address']
            if type(address) is not list or len(address) != 2 or address[0] != '127.0.0.1':
                raise Refused('source literal loopback connection')
            port = number(address[1], 1)
            if self.case in STARTUP:
                self.root_only(actor)
                probe = self.probe_ports.get(self.case)
                observed = acquire_tcp(actor['birth'], number(payload['fd']), retained=True)
                if (probe is None or probe['socket'].local != ('127.0.0.1', port) or probe['attempts'] >= 16
                        or observed is None or observed.owner != actor['birth'] or observed.uid != actor['birth'].uid
                        or observed.state != 7 or observed.local != ('0.0.0.0', 0) or observed.remote is not None):
                    raise Refused('source finite negative readiness probe')
                probe['attempts'] += 1
                return {'ok': True, 'probe': True}  # Never creates a Route, Ticket or Connection.
            if root_http:
                from root_http_observer import connection as http_connection
                name,maximum = http_connection(self,actor,payload,port)
            elif self.case in MCP_CASES:
                if actor['role'] not in (('root',) if self.case in HTTP_CASES else ('root', 'cleanup-acp')):
                    raise Refused('source cleanup connection role')
                targets = [value for value in self.intents.values() if value['case'] == self.case and value['role'] == 'mcp' and value['consumed']]
                if len(targets) != 1 or targets[0]['port'] != port:
                    raise Refused('source original owned MCP port')
                target = self.actors[targets[0]['pid']]
                if target['birth']!=targets[0]['birth'] or target['token']!=targets[0]['token'] or target['case']!=self.case or target['role']!='mcp':
                    raise Refused('source MCP consumed server generation changed')
                if self.ledger.process(target['birth']).terminal is not None:
                    raise Refused('source MCP startup ended before listening')
                slot = self.listeners.get((self.case, 'mcp'))
                if slot is None or not target['body_ready']:
                    return None  # The independent child can finish initialization.
                name = actor['token'] + ':mcp:' + hashlib.sha256(self.case.encode()).hexdigest()
                if name not in self.endpoints.routes:
                    route = Route(name, self.case, self.owner(target), self.owner(actor), port)
                    actual_listener = acquire_tcp(target['birth'], slot['socket'].fd, retained=True)
                    sharing = actual_listener if any(value.port == port and value.case not in self.endpoints.retired for value in self.endpoints.routes.values()) else None
                    self.endpoints.declare(route, shared_listener=sharing)
                    self.endpoints.listen(name, actual_listener)
                maximum = 64 if self.case in HTTP_CASES else 1 if actor['role'] == 'root' else 16
            else:
                if actor['role'] not in ('acp', 'backend', 'delayed-backend'):
                    raise Refused('source leaf connection role')
                name = self.routes[actor['birth'], port]
                maximum = 1 if actor['role'] == 'acp' else 8
            if self.case in CONTROLLED and actor['role'] == 'backend':
                total = sum(count for route,count in self.connected_routes.items()
                    if self.endpoints.routes[route].case == self.case
                    and self.actors[self.endpoints.routes[route].client.birth.pid]['role'] == 'backend')
                if total >= controlled_limits(self.case)[1]:
                    raise Refused('controlled case broker request bound')
            if self.connected_routes.get(name, 0) >= maximum:
                raise Refused('source finite connection count')
            listener = self.endpoints.listeners[name]
            ticket = self.endpoints.connect(name, acquire_tcp(listener.owner, listener.fd, retained=True),
                                            acquire_tcp(actor['birth'], number(payload['fd']), retained=True))
            self.connected_routes[name] = self.connected_routes.get(name, 0) + 1
            self.descriptors.pop((actor['birth'], ticket.client.fd), None)
            self.connections.pop((actor['birth'], ticket.client.fd), None)
            return {'ok': True, 'ticket': ticket.serial}
        elif kind == 'connected':
            shape(payload, ('fd', 'ticket'))
            serial = number(payload['ticket'], 1)
            connection = self.endpoints.connections.get(serial)
            ticket = connection.ticket if connection is not None else self.endpoints.tickets[serial]
            if ticket.route.client != self.owner(actor) or ticket.client.fd != number(payload['fd']):
                raise Refused('source connected ticket identity')
            if self.case in CLEANUP_CASES and connection is None:
                return None  # Join the real accepted FD before a short readiness probe closes.
        elif kind == 'accepted':
            if actor['role'] != 'mcp':
                self.root_only(actor)
            elif actor['case'] != self.case or self.case not in MCP_CASES:
                raise Refused('source declared module accept')
            shape(payload, ('listener', 'fd'))
            listener_fd, fd = number(payload['listener']), number(payload['fd'])
            matches = [ticket for ticket in self.endpoints.tickets.values()
                       if ticket.listener.owner == actor['birth'] and ticket.listener.fd == listener_fd]
            server = acquire_tcp(actor['birth'], fd, retained=True)
            candidates = []
            for ticket in matches:
                process = self.ledger.process(ticket.route.client.birth)
                if process.exit is not None or process.terminal is not None:
                    continue
                try:
                    client = acquire_tcp(ticket.route.client.birth, ticket.client.fd, retained=True)
                except FileNotFoundError:
                    return None  # Await its kernel terminal fact, never guess a peer.
                if client is not None and server is not None and client.remote == server.local and server.remote == client.local:
                    candidates.append((ticket, client))
            if not candidates:
                return self.interrupted_accept(actor, matches, server)
            if len(candidates) != 1:
                raise Refused('source exact accepted reciprocal peer')
            ticket, client = candidates[0]
            connection = self.endpoints.accepted(ticket, client, server)
            self.eof_fds.pop((actor['birth'], fd), None)
            self.descriptors.pop((actor['birth'], fd), None)
            self.listener_fds.pop((actor['birth'], fd), None)
            self.connections[actor['birth'], fd] = connection
            self.connections[ticket.route.client.birth, ticket.client.fd] = connection
        elif kind == 'payload':
            return self.socket_payload(actor, payload)
        elif kind == 'self-stop':
            shape(payload, ('signal',))
            children = [value for value in self.actors.values() if self.ledger.process(value['birth']).parent == actor['birth']]
            if (actor['role'] != 'session-adapter' or actor['case'] != self.case or self.case != SESSION_TIMEOUT
                    or type(payload['signal']) is not int or payload['signal'] != 15 or 15 not in actor['signals']
                    or len(children) != 1 or not all(self.ledger.reaped(value['birth'], value['token']) for value in children)):
                raise Refused('session self stop before original child wait')
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
                if child['role'] != 'workspace-owned' or payload['group']:
                    raise Refused('source exact owned liveness probe')
                try:
                    if Birth.read(process_identity(child['birth'].pid)) != child['birth']:
                        raise Refused('source reused probe PID')
                except (FileNotFoundError, ProcessLookupError):
                    pass
                return {'ok': True, 'live': True}
            if process.exit is not None or process.terminal is not None:
                return {'ok': True, 'live': False}
            actual = process_identity(child['birth'].pid)
            if (Birth.read(actual) != child['birth'] or payload['group'] and (not process.new_session or actual['pgid'] != child['birth'].pid or actual['sid'] != child['birth'].pid)):
                return {'ok': True, 'live': False}
            child['signals'].add(payload['signal'])
            return {'ok': True, 'live': True}
        elif kind == 'guard-refusal':
            shape(payload, ('code',))
            if (type(payload['code']) is not str or not 0 < len(payload['code']) <= 128
                    or any(not char.isascii() or not (char.isalnum() or char in ' -_') for char in payload['code'])):
                raise Refused('source refusal code schema')
            self.ledger.poison.append('source guard refusal')
        else:
            raise Refused('source undeclared observer method')
        return {'ok': True}

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
            frame = Frame(stream, REQUEST_LIMIT, self.ledger.poison, seconds=8 if self.cases in CLEANUP_GROUPS else 4)
            frame.capture(self.ledger, actor['birth'], actor['token'], 20000)
            self.frames.append({'frame': frame, 'actor': actor, 'request': None})
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
