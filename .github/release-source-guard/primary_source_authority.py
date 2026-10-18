"""Join primary root authority to existing finite source launch and receipt records."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import linux_git
from linux_supervisor import Supervisor
from linux_producers import NativeProducers
from finite.linux_identity import identity
from primary_policy import PYTHON, console
from producer_setup import write


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class SourceAuthority:
    def __init__(self, manifest_path, manifest_pin, common, contexts):
        self.path, self.pin, self.common = str(manifest_path), manifest_pin, common
        self.manifest = json.loads(Path(manifest_path).read_bytes())
        self.contexts = contexts
        self.supervisor = None
        self.producers = None
        self.consumed, self.maintenance = set(), set()
        self.bound, self.native_context = {}, {}

    def start(self, pid, output_fd):
        if self.supervisor is not None:
            raise RuntimeError('primary_source_duplicate_root')
        # These are the actual UV-produced consoles, after editable setup and
        # before pytest starts. Consume their exact renderer and interpreter;
        # source fixtures retain their existing copied-console checks.
        pins = {}
        for name in ('unrest', 'unrest-server'):
            path = Path('/source/.venv/bin') / name
            if path.read_bytes() != console(name):
                raise RuntimeError('primary_source_console_renderer')
            pins[name] = sha(path)
        self.manifest['copied_console_pins'] = {'unrest': pins['unrest']}
        self.manifest['console_routes'] = [{
            'name': 'unrest-server', 'argv': ['--mode', 'orchestrator', '--help'],
            'path': '/source/.venv/bin/unrest-server', 'python': '/source/.venv/bin/python',
            'sha256': pins['unrest-server']}]
        self.path = '/receipts/primary-source.json'
        self.pin = write(Path(self.path), self.manifest)
        spec = {'manifest': self.path, 'pins': {self.path: self.pin},
                'endpoint': self.manifest['endpoint']}
        for name in ('custody_host.py', 'drain_host.py'):
            path = '/guard/finite/' + name
            spec['pins'][path] = sha(path)
        self.supervisor = Supervisor(spec, SimpleNamespace(pid=pid))
        self.producers = NativeProducers(self.manifest, self.supervisor, self.common)
        objects = []
        for descriptor in (output_fd, self.supervisor.channel.fileno()):
            info = os.fstat(descriptor)
            objects.append({'device': info.st_dev, 'inode': info.st_ino,
                            'type': stat.S_IFMT(info.st_mode)})
        Path('/receipts/HOST-FDS.json').write_text(json.dumps({
            'nonce': self.manifest['endpoint']['nonce'], 'objects': objects}, sort_keys=True))

    def resolve(self, trace, pid, path, vector, environment, cwd):
        if self.supervisor is None:
            return None
        parent = trace.identities[pid]['ppid']
        if parent not in self.supervisor.registered and parent not in self.contexts:
            return None
        native = self.producers.resolve_child(pid, parent, path, vector, environment, cwd)
        if native is not None:
            if native:
                self.contexts[pid] = {'role': 'source-producer-child', 'identity': identity(pid)}
            return native
        if parent in self.native_context:
            if parent in self.maintenance:
                return False
            accepted = linux_git.admit(self.native_context[parent], path, vector, environment, cwd,
                                        self.manifest['git_maintenance_sha256'], self.manifest['owned_root'])
            if accepted:
                self.maintenance.add(parent)
                self.contexts[pid] = {'role': 'source-git-maintenance', 'identity': identity(pid)}
            return accepted
        # A primary UV query is not source authority. Only registered source
        # owners can consume a fixture's actual_launch_binding.
        if parent not in self.supervisor.registered:
            return None
        if pid not in self.bound:
            argv_pin = hashlib.sha256(json.dumps(vector).encode()).hexdigest()
            env_pin = hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()
            events = self.supervisor.events()
            matching = [row for row in events if row['kind'] == 'actual_launch_binding'
                        and row['owner_pid'] == parent and row['token'] not in self.consumed
                        and row['transformed_argv_sha256'] == argv_pin
                        and row['environment_sha256'] == env_pin and row['cwd'] == cwd]
            if len(matching) != 1:
                return False
            selected = matching[0]
            admitted = [row for row in events if row['kind'] == 'admitted'
                        and row['owner_pid'] == parent and row['token'] == selected['token']]
            if len(admitted) != 1:
                return False
            registration = admitted[0]
            binding = registration.get('source_binding', {})
            source = binding.get('path', '')
            if source.startswith('/source/'):
                if self.manifest['product_pins'].get(source.removeprefix('/source/')) != binding.get('sha256'):
                    return False
            elif (registration['class'] != 'restart-custodian'
                  or source != '/guard/finite/restart_custody.py'
                  or self.manifest['direct_support']['files'].get(source) != binding.get('sha256')):
                return False
            self.consumed.add(selected['token'])
            self.bound[pid] = {**selected, 'registration': registration}
        selected = self.bound[pid]
        if selected['bootstrap_sha256'] is not None:
            if (len(vector) < 3 or vector[-2] != '-c'
                    or hashlib.sha256(vector[-1].encode()).hexdigest() != selected['bootstrap_sha256']
                    or vector[0] not in self.manifest['runtime']['paths'] or path != vector[0]
                    or Path(path).resolve() != Path(PYTHON)
                    or sha(path) != self.manifest['runtime']['sha256']):
                return False
            self.contexts[pid] = {'role': 'source-bootstrap', 'identity': identity(pid)}
            return 'source-bootstrap'
        if selected['registration']['class'] in {'source-build', 'source-install'}:
            accepted = self.producers.admit_uv(pid, path, vector, environment, cwd, parent,
                                              selected['registration'], selected)
            if accepted:
                self.contexts[pid] = {'role': 'source-producer', 'identity': identity(pid)}
            return accepted
        if not vector or vector[0] not in {'git', 'ps', 'sleep'}:
            return False
        candidates = [directory + '/' + vector[0] for directory in environment['PATH'].split(':')]
        if path not in candidates:
            return False
        if not Path(path).exists():
            return True
        images = {**self.manifest['copy_git'], **self.manifest['cohort_native_pins']}
        if path not in images or sha(path) != images[path]:
            return False
        self.contexts[pid] = {'role': 'source-native', 'identity': identity(pid)}
        if vector[0] == 'git':
            self.native_context[pid] = {'path': path, 'argv': vector, 'cwd': cwd, 'environment': environment}
        return True

    def tick(self, trace):
        if self.supervisor is None:
            return
        self.producers.tick(trace)
        self.supervisor.tick()
        if trace.poison and not self.supervisor.poisoned:
            self.supervisor.poison('kernel_exec_poison')

    def finish(self):
        if self.supervisor is None:
            return {'guard_poison': True, 'receipt_ledger_poison': ['source_root_missing']}
        self.supervisor.close()
        return {'guard_poison': self.supervisor.poisoned,
                'receipt_ledger_poison': self.supervisor.ledger.poison,
                'source_events': self.supervisor.events(), 'receipts': self.supervisor.receipts,
                'event_timings': self.supervisor.event_timings,
                'native_source_records': self.producers.records}
