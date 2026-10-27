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

from content_manifest import Refused
from control_transport import Admission, Frame, REQUEST_LIMIT, cancelled_empty, reply
from bootstrap_cases import BOOTSTRAP, configuration, declaration, wrapper
from controlled_startup import ACP, ACP_PIN, BACKEND_PIN, SESSION
from endpoint_policy import Endpoints, Owner, Route
from launch_policy import Rule, render
from linux_observation import process_identity
from process_ledger import Birth, Ledger, canonical
from socket_observation import acquire_tcp, acquire_unix_member, acquire_unix_pair
from source_profile import METHODS, ROOT_COMMAND, digest
from unix_endpoints import UnixPairs


def shape(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise Refused('source observer operation schema')


def number(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise Refused('source observer integer')
    return value


class Observer:
    def __init__(self, binding, metadata, root_pid, out_read):
        self.binding, self.meta = binding, metadata
        self.cases = tuple(metadata['cases'])
        self.directory = Path(binding['profiles'])
        self.root = root_pid
        self.root_birth = Birth.read(process_identity(root_pid))
        self.ledger = Ledger(os.urandom(32).hex())
        self.admission = Admission(self.ledger, METHODS)
        self.endpoints, self.actors, self.intents = Endpoints(self.ledger), {}, {}
        self.pairs = UnixPairs(self.endpoints)
        self.bindings, self.listeners, self.listener_fds, self.pair_intents = {}, {}, {}, {}
        self.routes, self.connections, self.descriptors = {}, {}, {}
        self.eof_drains, self.eof_fds, self.interrupted_records = {}, {}, []
        self.connected_routes: dict[str, int] = {}
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

    def profile(self, pid, role, case, vector, environment, cwd, token):
        actual = process_identity(pid)
        parent = self.root_birth if role != 'root' else Birth.read(process_identity(os.getpid()))
        source = {'schema': 'unrest.bootstrap-source.v1', 'role': role, 'case': case,
            'identity': canonical(actual), 'parent': canonical(process_identity(parent.pid)),
            'observer': canonical(process_identity(os.getpid())), 'argv': vector,
            'environment': environment, 'cwd': cwd, 'native': self.binding['entry']['path'],
            'native_sha256': self.binding['entry']['sha256'], 'entry_sha256': self.binding['bootstrap']['sha256'],
            'nonce': self.ledger.nonce, 'token': token, 'generation': 1,
            'mount_namespace': os.readlink('/proc/self/ns/mnt'), **self.meta,
            'script': None if role == 'root' else (str(Path(self.meta['checkout']) / ACP)
                if role == 'acp' else str(Path(cwd).parent / 'fake-app-server'))}
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
                         'backend': 'controlled-backend', 'delayed-backend': 'controlled-backend-wrapper'}[role]
        self.ledger.register(actor['birth'], token, pins, source['seal'], case=case,
                             command_class=command_class, new_session=role != 'root', expected_generation=1)
        if role != 'root':
            common = {'owner_pid': self.root, 'token': token, 'case': case, 'class': command_class}
            witnesses = ({'kind': 'admitted', **common}, {'kind': 'registered', 'pid': pid, 'python': True, **common},
                         {'kind': 'launch_lifecycle_binding', 'start_new_session': True, **common})
            self.ledger.session(actor['birth'], actual, witnesses)
        return actor

    def consume(self, trace):
        while self.ledger.next_kernel < len(trace.records):
            row = trace.records[self.ledger.next_kernel]
            self.ledger.kernel(self.ledger.next_kernel, row)
            if row['kind'] == 'kernel_exit' and row.get('raw') == 86 << 8:
                self.ledger.poison.append('native guard refusal')
            if row['kind'] == 'kernel_root':
                self.profile(self.root, 'root', '<bootstrap>',
                    [self.binding['entry']['path'], '-I', '-S', '-c', ROOT_COMMAND],
                    self.meta_environment(), self.meta['checkout'], os.urandom(16).hex())

    def meta_environment(self):
        owned = Path(self.meta['owned'])
        return {'HOME': str(owned / 'home'), 'TMPDIR': str(owned / 'tmp'), 'PATH': '/usr/bin:/bin',
                'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}

    def stdio(self, pid, role):
        parent = Path('/proc') / str(self.root) / 'fd'
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
            if descriptor == 2 and role == 'acp':
                null = Path('/dev/null').stat()
                if not stat.S_ISCHR(info.st_mode) or info.st_rdev != null.st_rdev:
                    raise Refused('source exact ACP stderr')
            elif not stat.S_ISFIFO(info.st_mode) or (info.st_dev, info.st_ino) not in parent_inodes:
                raise Refused('source exact parent-owned pipe')

    def resolve(self, trace, pid, path, vector, environment, cwd):
        self.consume(trace)
        birth = self.ledger.current.get(pid)
        if birth is None or self.ledger.process(birth).parent != self.root_birth:
            return False
        matches = [value for value in self.intents.values() if not value['consumed']
                   and value['translated'] == vector and value['environment'] == environment
                   and value['cwd'] == cwd and path == self.binding['entry']['path']]
        if len(matches) != 1 or digest(Path(path)) != self.binding['entry']['sha256']:
            return False
        intent = matches[0]
        if process_identity(pid)['namespaces']['mnt'] != os.readlink('/proc/self/ns/mnt'):
            return False
        self.stdio(pid, intent['role'])
        intent['consumed'], intent['pid'] = True, pid
        self.profile(pid, intent['role'], intent['case'], vector, environment, cwd, intent['token'])
        return True

    def actor_control(self, actor, kind, payload):
        self.ledger.control(actor['birth'], actor['token'], 1, actor['sequence'], kind, payload)
        actor['sequence'] += 1

    def root_only(self, actor):
        if actor['birth'] != self.root_birth or actor['role'] != 'root' or self.finished:
            raise Refused('source root-only operation')

    def launch(self, actor, payload):
        self.root_only(actor)
        shape(payload, ('case', 'original', 'translated', 'source_line', 'script_sha256'))
        if payload['case'] != self.case or self.case not in BOOTSTRAP or type(payload['source_line']) is not int:
            raise Refused('source declared launch case')
        original = payload['original']
        shape(original, ('rule', 'owner', 'case', 'executable', 'executable_sha256', 'argv', 'environment', 'cwd', 'payload_kind', 'payload_sha256'))
        cwd = original['cwd']
        if type(cwd) is not str:
            raise Refused('source launch cwd type')
        home = Path(cwd)
        if (not home.is_absolute() or str(home.resolve()) != cwd or not home.is_relative_to(Path(self.meta['owned']))
                or home.name != 'worker' or home.parent.name != 'owner'):
            raise Refused('source owned worker launch home')
        spec = declaration(self.case)
        if spec.children == 0:
            raise Refused('source declared no-launch case')
        native = self.binding['entry']['path']
        config_argv, config_json = configuration(Path(self.meta['checkout']), home) if spec.configured else ([], None)
        environment = {'HOME': cwd, 'CODEX_HOME': str(home / 'codex'), 'TMPDIR': str(home / 'tmp'), 'PATH': '/usr/bin:/bin'}
        if config_json is not None:
            environment.update(CODEX_HOME=str(home.parent.parent.parent / 'subscription'), CODEX_CONFIG=config_json)
        if payload['source_line'] == 506:
            script = home.parent / 'fake-app-server'
            role = 'backend' if wrapper(self.case) is None else 'delayed-backend'
            vector: tuple[str, ...] = (native, str(script), *config_argv, 'app-server')
            pin: str | None
            kind, pin = 'python-script', BACKEND_PIN
            if role == 'delayed-backend':
                vector, kind, pin = (native, '-c', wrapper(self.case), str(script), *config_argv, 'app-server'), 'python-command', None
            rule_name, script_pin = 'backend', BACKEND_PIN
        elif payload['source_line'] == 553:
            backends = [value for value in self.intents.values() if value['case'] == self.case and value['role'] in ('backend', 'delayed-backend')]
            if len(backends) != 1 or not backends[0]['consumed'] or not self.actors[backends[0]['pid']]['returned']:
                raise Refused('source ACP before owned backend return')
            bridge = self.listeners[(self.case, 'bridge')]
            lifetime = self.listeners[(self.case, 'lifetime')]
            environment.update({'CODEX_PATH': str(home.parent / 'fixed-relay'), 'INITIAL_AGENT_MODE': 'read-only',
                'SYNTHETIC_RELAY': json.dumps([bridge['socket'].local[1], bridge['nonce'], lifetime['socket'].local[1], lifetime['nonce']])})
            role, rule_name, script_pin = 'acp', 'acp', ACP_PIN
            vector = (native, str(Path(self.meta['checkout']) / ACP), '--controlled-local-acp-v1')
            kind, pin = 'python-script', ACP_PIN
        else:
            raise Refused('source unknown original launch site')
        rule = Rule('controlled-startup:' + rule_name, SESSION + ':_open_role_owned', (self.case,),
                    native, self.binding['entry']['sha256'], vector, tuple(sorted(environment.items())), cwd, kind, pin)
        expected = render(rule, self.case, rule.owner, {}, {})
        translated = [native, '-I', '-S', *expected.argv[1:]]
        if (original != expected.wire() or payload['translated'] != translated
                or payload['script_sha256'] != script_pin
                or any(value['case'] == self.case and value['role'] == role for value in self.intents.values())):
            raise Refused('source independently reconstructed launch mismatch')
        self.serial += 1
        token = os.urandom(16).hex()
        self.intents[self.serial] = {'case': self.case, 'role': role, 'environment': environment, 'cwd': cwd,
            'translated': translated, 'token': token, 'consumed': False, 'pid': None}
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
            self.endpoints.retained(connection, self.owner(actor), acquire_tcp(actor['birth'], fd, retained=True))
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
        terminal = self.ledger.process(actor['birth']).terminal
        return (terminal is not None and (actor['body_ready']
                or terminal[2] in (-9, -15) and -terminal[2] in actor['signals']))

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
            tags = (('bridge', 'lifetime') if actor['role'] == 'acp' else
                    ('broker',) if actor['role'] in ('backend', 'delayed-backend') and declaration(actor['case']).broker_http else ())
            if tags:
                root_actor = self.actors[self.root]
                for tag in tags:
                    slot = self.listeners[(actor['case'], tag)]
                    name = actor['token'] + ':' + tag
                    route = Route(name, actor['case'], self.owner(root_actor), self.owner(actor), slot['socket'].local[1])
                    self.endpoints.declare(route)
                    self.endpoints.listen(name, acquire_tcp(self.root_birth, slot['socket'].fd, retained=True))
                    self.routes[actor['birth'], route.port] = name
        elif kind == 'body-ready':
            self.actor_control(actor, kind, payload)
            actor['body_ready'] = True
        elif kind in ('case-start', 'case-finish'):
            self.root_only(actor)
            shape(payload, ('case',))
            if kind == 'case-start':
                if self.case is not None or len(self.completed) >= len(self.cases) or payload['case'] != self.cases[len(self.completed)]:
                    raise Refused('source exact external case frontier')
                self.case = actor['case'] = payload['case']
                self.ledger.process(self.root_birth).case = self.case
            else:
                children = [value for value in self.actors.values() if value['role'] != 'root' and value['case'] == self.case]
                spec = declaration(self.case)
                for serial, drain in list(self.eof_drains.items()):
                    ticket = drain['ticket']
                    if ticket.route.case == self.case:
                        if not spec.interrupted:
                            raise Refused('source aborted route in positive case')
                        self.endpoints.abort_reaped(ticket)
                        self.interrupted_records.append({'kind': 'aborted-unjoined', 'ticket': serial,
                            'actual_original_parent_reap': True, 'accepted_peer_proven': False})
                        self.eof_fds.pop((actor['birth'], drain['socket'].fd), None)
                        del self.eof_drains[serial]
                if (payload['case'] != self.case or not spec.minimum_children <= len(children) <= spec.children
                        or any(not self.completed_child(value) for value in children)
                        or any(not value['consumed'] for value in self.intents.values() if value['case'] == self.case)
                        or any(not self.ledger.reaped(value['birth'], value['token']) for value in children)
                        or any(ticket.route.case == self.case for ticket in self.endpoints.tickets.values())):
                    raise Refused('source original case actual cleanup incomplete')
                self.completed.append(self.case)
                self.case = None
        elif kind == 'root-finish':
            self.root_only(actor)
            shape(payload, ('cases',))
            if self.case is not None or payload['cases'] != list(self.cases) or tuple(self.completed) != self.cases:
                raise Refused('source original source completion incomplete')
            self.finished = True
        elif kind == 'launch-intent':
            return self.launch(actor, payload)
        elif kind == 'launch-return':
            self.root_only(actor)
            shape(payload, ('pid', 'ticket', 'token'))
            intent = self.intents[number(payload['ticket'], 1)]
            child = self.actors.get(number(payload['pid'], 1))
            if (not intent['consumed'] or intent['pid'] != payload['pid'] or child is None
                    or intent['token'] != payload['token'] or child['returned']):
                raise Refused('source actual constructor return binding')
            child['returned'] = True
        elif kind == 'drain_child':
            self.root_only(actor)
            shape(payload, ('pid', 'requested_pid', 'child_token', 'raw_status', 'numeric_returncode', 'options'))
            child = self.actors.get(number(payload['pid'], 1))
            if child is None or not child['returned']:
                raise Refused('source constructor before parent wait')
            row = {**payload, 'nonce': self.ledger.nonce, 'owner_pid': self.root,
                   'owner_identity': self.ledger.process(self.root_birth).registered_identity,
                   'owner_token': actor['token'], 'wait_event': 'actual_os_waitpid_return'}
            self.actor_control(actor, 'parent-wait', row)
        elif kind == 'pair-intent':
            shape(payload, ('site',))
            if payload['site'] != 'asyncio-self-pipe' or len(self.pair_intents) >= 32:
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
            self.root_only(actor)
            shape(payload, ('fd', 'tag', 'nonce'))
            fd = number(payload['fd'])
            if self.case not in BOOTSTRAP or payload['tag'] not in ('broker', 'bridge', 'lifetime'):
                raise Refused('source finite root listener')
            nonce = payload['nonce']
            if ((payload['tag'] == 'broker' and nonce is not None)
                    or payload['tag'] != 'broker' and (type(nonce) is not str or len(nonce) != 64
                    or any(char not in '0123456789abcdef' for char in nonce))
                    or (self.case, payload['tag']) in self.listeners):
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
                                  'case': self.case, 'listening': False, 'listen_pending': False}
        elif kind == 'listen':
            self.root_only(actor)
            shape(payload, ('fd', 'stage'))
            fd = number(payload['fd'])
            binding = self.bindings[actor['birth'], fd]
            observed = acquire_tcp(actor['birth'], fd, retained=True)
            if (binding['case'] != self.case or observed is None or observed.binding() != binding['socket'].binding()
                    or observed.local[0] != '127.0.0.1' or observed.remote is not None):
                raise Refused('source original listener descriptor')
            if payload['stage'] == 'before':
                if (binding['listen_pending'] or observed.state != (10 if binding['listening'] else 7)
                        or binding['listening'] and observed != self.listeners[self.case, binding['tag']]['socket']):
                    raise Refused('source listener before state')
                binding['listen_pending'] = True
            elif payload['stage'] == 'after':
                if not binding['listen_pending'] or observed.state != 10:
                    raise Refused('source listener after state')
                # asyncio re-applies Uvicorn's original backlog to this same
                # listener. A repeated listen grants no new endpoint authority.
                previous = self.listeners.get((self.case, binding['tag']))
                if previous is not None and observed != previous['socket']:
                    raise Refused('source changed repeated listener')
                binding['listen_pending'], binding['listening'] = False, True
                slot = {**binding, 'socket': observed}
                self.listeners[self.case, binding['tag']] = slot
                self.listener_fds[actor['birth'], fd] = slot
            else:
                raise Refused('source listener stage')
        elif kind == 'connect':
            if actor['role'] not in ('acp', 'backend', 'delayed-backend'):
                raise Refused('source leaf connection role')
            shape(payload, ('fd', 'address'))
            address = payload['address']
            if type(address) is not list or len(address) != 2 or address[0] != '127.0.0.1':
                raise Refused('source literal loopback connection')
            port = number(address[1], 1)
            name = self.routes[actor['birth'], port]
            maximum = 1 if actor['role'] == 'acp' else 8
            if self.connected_routes.get(name, 0) >= maximum:
                raise Refused('source finite connection count')
            listener = self.endpoints.listeners[name]
            ticket = self.endpoints.connect(name, acquire_tcp(self.root_birth, listener.fd, retained=True),
                                            acquire_tcp(actor['birth'], number(payload['fd']), retained=True))
            self.connected_routes[name] = self.connected_routes.get(name, 0) + 1
            self.descriptors.pop((actor['birth'], ticket.client.fd), None)
            self.connections.pop((actor['birth'], ticket.client.fd), None)
            return {'ok': True, 'ticket': ticket.serial}
        elif kind == 'connected':
            shape(payload, ('fd', 'ticket'))
            ticket = self.endpoints.tickets[number(payload['ticket'], 1)]
            if ticket.route.client != self.owner(actor) or ticket.client.fd != number(payload['fd']):
                raise Refused('source connected ticket identity')
        elif kind == 'accepted':
            self.root_only(actor)
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
        elif kind == 'custody_signal':
            self.root_only(actor)
            shape(payload, ('pid', 'child_token', 'signal', 'group'))
            child = self.actors.get(number(payload['pid'], 1))
            if (child is None or child['role'] == 'root' or payload['child_token'] != child['token']
                    or type(payload['signal']) is not int or payload['signal'] not in (9, 15) or type(payload['group']) is not bool):
                raise Refused('source exact owned signal')
            process = self.ledger.process(child['birth'])
            if process.exit is not None or process.terminal is not None:
                return {'ok': True, 'live': False}
            actual = process_identity(child['birth'].pid)
            if (Birth.read(actual) != child['birth'] or actual['pgid'] != child['birth'].pid or actual['sid'] != child['birth'].pid):
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
            frame = Frame(stream, REQUEST_LIMIT, self.ledger.poison)
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
                channel['request'] = self.admission.admit(frame)
                self.controls.append(channel['request'])
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
        for actor in self.actors.values():
            (self.directory / (str(actor['birth'].pid) + '.json')).unlink(missing_ok=True)
