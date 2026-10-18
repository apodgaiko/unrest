"""Join primary root authority to existing finite source launch and receipt records."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import signal
import time

import linux_trace
from types import SimpleNamespace

import linux_git
from linux_supervisor import Supervisor
from linux_observation import process_identity
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
        self.pipe_records = []

    def prepare_bootstrap_cache(self, pid, trace, primary):
        if trace is None or primary is None or primary.source is not self or primary.contexts is not self.contexts:
            raise RuntimeError('primary_cache_bootstrap_owner')
        import producer_profile
        declaration = producer_profile.bootstrap_cache(self.common, trace, pid, primary)
        path = Path('/receipts/producers/primary-bootstrap-cache.json')
        pin = write(path, declaration)
        self.common = {**self.common, 'primary_producer': {
            **self.common['primary_producer'], 'bootstrap_cache': {'path': str(path), 'sha256': pin}}}
        common_path = Path('/receipts/producers/primary-common.json')
        common_pin = write(common_path, self.common)
        self.manifest['isolated_support'].update(spec_path=str(common_path), spec_sha256=common_pin)
        self.manifest['native_producer_support'].update(path=str(common_path), sha256=common_pin)

    def start(self, pid, output_fd, *, trace=None, primary=None):
        if self.supervisor is not None:
            raise RuntimeError('primary_source_duplicate_root')
        self.prepare_bootstrap_cache(pid, trace, primary)
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
        self.supervisor.source_response_output = self.producers.stage_response
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
                self.producer_profile(pid, parent, vector, environment, cwd)
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

    def producer_profile(self, pid, parent, vector, environment, cwd):
        item = self.producers.children[pid]
        actual = identity(pid)
        if (actual != item['identity'] or actual['ppid'] != parent
                or self.common['primary_producer']['entry'] != self.common['base_identity']
                or self.common['base'] != PYTHON):
            raise RuntimeError('primary_producer_profile_identity')
        native_path = Path('/receipts/native-startup') / (str(pid) + '.json')
        if sha(native_path) != item['profile_sha256']:
            raise RuntimeError('primary_producer_native_header_drift')
        native = json.loads(native_path.read_bytes())
        if (native['orig_argv'] != vector or native['environment'] != environment
                or native['cwd'] != cwd or native['role'] != item['role']):
            raise RuntimeError('primary_producer_native_profile_drift')
        profile = {
            'pid': pid, 'parent': parent, 'start_ticks': actual['start_ticks'],
            'boot_id': actual['boot_id'], 'orig_argv': vector, 'environment': environment,
            'cwd': cwd, 'event': 'cpython.run_command', 'flags': native['flags'],
            'body_sha256': native['command_sha256'], 'repository': False,
            'source_role': 'source-producer-child',
            'native_profile_sha256': item['profile_sha256'],
            'producer_consumer': self.common['primary_producer']['consumer'],
            'producer_image': self.common['base_identity'],
        }
        write(Path('/receipts/primary-startup') / (str(pid) + '.json'), profile)

    def pipe_binding(self, pid):
        selected = self.bound[pid]['registration']
        if selected['class'] not in {'source-owned-role:worker', 'source-owned-role:validator',
                                     'source-owned-role:terminal-reviewer'}:
            return None
        parent = identity(pid)['ppid']
        rows = [row for row in self.supervisor.events()
                if row['kind'] == 'concrete_owned_role_registration'
                and row['owner_pid'] == parent
                and row['role'] == selected['class'].removeprefix('source-owned-role:')
                and row['source_binding'] == selected['source_binding']
                and row['argv_sha256'] == selected['argv_sha256']]
        # Admission and the callback independently resolve the original pipe.
        if len(rows) != 2 or rows[0] != rows[1]:
            raise RuntimeError('primary_source_role_pipe_binding')
        return rows[0]

    @staticmethod
    def census(pid):
        root = Path('/proc/' + str(pid))
        paths = sorted((root / 'fd').iterdir(), key=lambda path: int(path.name))
        if len(paths) > 128:
            raise RuntimeError('primary_source_role_pipe_bound')
        observed = []
        for path in paths:
            fd = int(path.name)
            if fd < 3:
                continue
            info = path.stat()
            lines = (root / 'fdinfo' / str(fd)).read_text().splitlines()
            flags = int(next(line.split()[1] for line in lines if line.startswith('flags:')), 8)
            observed.append({'fd': fd, 'device': info.st_dev, 'inode': info.st_ino,
                             'mode': info.st_mode, 'uid': info.st_uid,
                             'access': flags & os.O_ACCMODE,
                             'close_on_exec': bool(flags & os.O_CLOEXEC)})
        return observed

    @staticmethod
    def safe_census(rows):
        return [{**{key: value for key, value in row.items() if key != 'mode'},
                 'type': stat.S_IFMT(row['mode'])} for row in rows]

    @staticmethod
    def inventory_pipe(observed, expected):
        matching = [row for row in observed
                    if stat.S_ISFIFO(row['mode']) and row['uid'] == 20000
                    and row['device'] == expected['pipe_device']
                    and row['inode'] == expected['pipe_inode']
                    and row['access'] == os.O_RDONLY]
        if len(matching) != 1:
            raise RuntimeError('primary_source_role_pipe_identity')
        return matching[0]

    def descriptors(self, pid):
        """Strict original pre-exec contract, also used for negative controls."""
        expected = self.pipe_binding(pid)
        if expected is None:
            return []
        observed = self.census(pid)
        pipe = self.inventory_pipe(observed, expected)
        if len(observed) != 1:
            raise RuntimeError('primary_source_role_pipe_cardinality')
        return [{key: value for key, value in pipe.items() if key != 'close_on_exec'}]

    def exec_descriptors(self, trace, pid, vector, environment, cwd):
        """Prove custody at successful exec, before the image's first instruction.

        No flag authorizes omission. Every pre-exec object is observed; every
        additional descriptor must actually be absent at PTRACE_EVENT_EXEC.
        The original tracer retains the syscall return and all parent waits.
        """
        try:
            expected = self.pipe_binding(pid)
            if expected is None:
                return []
            before = identity(pid)
            owner = identity(before['ppid'])
            credentials = process_identity(pid)
            if (self.supervisor.registered.get(owner['pid'], {}).get('identity') != owner
                    or credentials['uids'] != [20000] * 4
                    or any(credentials['capabilities'].values()) or credentials['no_new_privs'] != 1):
                raise RuntimeError('primary_source_role_pipe_owner_binding')
            if (trace.pending.get(pid, {}).get('syscall') != 59
                    or any(before[key] != trace.identities[pid][key]
                           for key in ('pid', 'ppid', 'start_ticks', 'boot_id'))):
                raise RuntimeError('primary_source_role_pipe_trace_binding')
            pre = self.census(pid)
            self.pipe_records.append({'kind': 'source_pipe_preexec_census', 'pid': pid,
                                      'identity': before, 'descriptors': self.safe_census(pre)})
            pipe = self.inventory_pipe(pre, expected)
            # Only the already-admitted exec syscall can run. A successful exec
            # stop precedes the dynamic loader, native entry, and Python startup.
            linux_trace.ptrace(24, pid)
            deadline = time.monotonic() + min(5, trace.timeout)
            while True:
                waited, raw = os.waitpid(pid, os.WNOHANG | 0x40000000)
                if waited:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('primary_source_role_pipe_exec_deadline')
                time.sleep(.0001)
            if os.WIFEXITED(raw) or os.WIFSIGNALED(raw):
                trace.active.discard(pid)
                trace.records.append({'kind': 'failure_cleanup_tracer_wait', 'pid': pid,
                                      'raw': raw, 'normalized': os.waitstatus_to_exitcode(raw),
                                      'root_original_parent': pid == trace.child})
            if (waited != pid or not os.WIFSTOPPED(raw)
                    or os.WSTOPSIG(raw) != signal.SIGTRAP or raw >> 16 != 4):
                raise RuntimeError('primary_source_role_pipe_exec_stop')
            trace.records.append({'kind': 'kernel_exec', 'pid': pid})
            after = identity(pid)
            post = self.census(pid)
            self.pipe_records.append({'kind': 'source_pipe_postexec_census', 'pid': pid,
                                      'identity': after, 'descriptors': self.safe_census(post)})
            root = Path('/proc/' + str(pid))
            actual_argv = (root / 'cmdline').read_bytes().split(b'\0')
            actual_environment = (root / 'environ').read_bytes().split(b'\0')
            after_credentials = process_identity(pid)
            if (after != before or identity(owner['pid']) != owner
                    or after_credentials['uids'] != credentials['uids']
                    or after_credentials['capabilities'] != credentials['capabilities']
                    or after_credentials['no_new_privs'] != 1 or actual_argv != [os.fsencode(value) for value in vector] + [b'']
                    or sorted(actual_environment) != sorted([
                        os.fsencode(key + '=' + value) for key, value in environment.items()] + [b''])
                    or os.readlink(root / 'cwd') != cwd
                    or sha(root / 'exe') != self.manifest['runtime']['sha256']):
                raise RuntimeError('primary_source_role_pipe_exec_identity')
            if self.pipe_binding(pid) != expected:
                raise RuntimeError('primary_source_role_pipe_registration_drift')
            survivor = self.inventory_pipe(post, expected)
            if post != [survivor] or survivor != pipe:
                raise RuntimeError('primary_source_role_pipe_postexec_inventory')
            self.pipe_records.append({
                'kind': 'source_pipe_exec_custody', 'pid': pid, 'identity': after, 'owner_identity': owner,
                'registration_sha256': hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest(),
                'exec_argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
                'closed_fds': [row['fd'] for row in pre if row != pipe],
                'surviving_fd': pipe['fd']})
            return [{key: value for key, value in survivor.items() if key != 'close_on_exec'}]
        except BaseException:
            trace.poison.append('primary_source_role_pipe_custody')
            self.supervisor.poison('primary_source_role_pipe_custody')
            raise

    def tick(self, trace):
        if self.supervisor is None:
            return
        self.producers.tick(trace)
        self.supervisor.trace_progress = {'records': len(trace.records),
                                          'active': len(trace.active),
                                          'pending': len(trace.pending)}
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
                'diagnostic_schedule': dict(self.supervisor.diagnostic_schedule),
                'event_timings': self.supervisor.event_timings,
                'receipt_channel_diagnostics': self.supervisor.channel_diagnostics,
                'receipt_channel_diagnostic_summary': self.supervisor.diagnostic_summary(),
                'native_source_records': self.producers.records,
                'source_pipe_records': self.pipe_records,
                'source_observer_poison_sha256': (hashlib.sha256(json.loads(
                    (self.supervisor.control / 'POISON.json').read_bytes())['reason'].encode()).hexdigest()
                    if (self.supervisor.control / 'POISON.json').is_file() else None)}
