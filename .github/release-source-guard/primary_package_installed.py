"""Current installed wheel bytes, original lifecycle return and owned supervision."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import types
import zipfile

from finite.linux_identity import identity
from linux_supervisor import Supervisor
from primary_custody import WHEEL, canonical, file_identity, sha
from primary_policy import PYTHON
from producer_setup import write

PREFIX = Path('/source/.wheel-venv')
SITE = PREFIX / 'lib/python3.13/site-packages/unrest_harness'


def verify_installation():
    descriptor = json.loads(Path('/inputs/package-input.json').read_bytes())
    wheel = Path('/source/dist') / WHEEL
    body = wheel.read_bytes()
    if (len(body) != descriptor['members'][WHEEL]['size']
            or sha(body) != descriptor['members'][WHEEL]['sha256']):
        raise RuntimeError('package_installed_wheel_input')
    for name in ('python', 'python3', 'python3.13'):
        path = PREFIX / 'bin' / name
        if path.resolve() != Path(PYTHON) or sha(path.read_bytes()) != sha(Path(PYTHON).read_bytes()):
            raise RuntimeError('package_installed_interpreter')
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        payload = {name.removeprefix('unrest_harness/'): archive.read(name)
                   for name in archive.namelist() if name.startswith('unrest_harness/') and not name.endswith('/')}
    paths = sorted(SITE.rglob('*'))
    files = [path for path in paths if path.is_file()]
    if (not payload or SITE.resolve() != SITE or any(path.is_symlink() for path in [SITE, *paths])
            or {p.relative_to(SITE).as_posix() for p in files} != set(payload)):
        raise RuntimeError('package_installed_inventory')
    for path in files:
        info = path.lstat()
        content = path.read_bytes()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20000 or info.st_nlink != 1
                or content != payload[path.relative_to(SITE).as_posix()]
                or file_identity(info) != file_identity(path.lstat())):
            raise RuntimeError('package_installed_complete_bytes')
    return sha(canonical({name: sha(body) for name, body in sorted(payload.items())}))


class InstalledSession:
    def __init__(self, path, pin, common, contexts):
        self.path, self.pin, self.common = str(path), pin, common
        self.manifest = json.loads(Path(path).read_bytes())
        self.contexts = contexts
        self.supervisor = None
        self.package_proof = None
        self.corruption = None
        self.records = []
        self.closed = False

    def resolve(self, *args):
        return None

    def start(self, pid, output_fd, *, trace, primary):
        if self.supervisor is not None or self.contexts is not primary.contexts:
            raise RuntimeError('package_installed_duplicate_root')
        declaration = verify_installation()
        # The installed lifecycle has no child-launch contract. Preserve the
        # original finite guard; remove SOURCE fixture adapters from this new
        # installed domain so they cannot confer checkout fixture authority.
        for name in ('operation_support', 'activation_support', 'isolated_support',
                     'source_activation_support', 'native_producer_support'):
            self.manifest.pop(name, None)
        self.manifest['runtime']['paths'] = [str(PREFIX / 'bin' / name)
                                            for name in ('python', 'python3', 'python3.13')]
        self.manifest['scope'] = 'primary installed wheel lifecycle'
        self.manifest['source_case'] = 'PRIMARY-installed-' + primary.plan['package_mode']
        self.manifest['installed_package_sha256'] = declaration
        self.path = '/receipts/primary-installed-source.json'
        self.pin = write(Path(self.path), self.manifest)
        spec = {'manifest': self.path, 'pins': {self.path: self.pin}, 'endpoint': self.manifest['endpoint']}
        self.supervisor = Supervisor(spec, types.SimpleNamespace(pid=pid))
        owner = self.supervisor
        original_authenticate = owner.authenticate
        def authenticate(supervisor, request, events):
            if (supervisor is not owner or original_authenticate.__self__ is not supervisor):
                raise RuntimeError('package_installed_ready_owner')
            if (request.get('kind') == 'ready' and request.get('pid') == pid
                    and request.get('token') == 'root'
                    and not any(row['kind'] == 'ready' and row['owner_pid'] == pid for row in events)):
                events = owner.events()
            return original_authenticate(request, events)
        owner.authenticate = types.MethodType(authenticate, owner)
        original = owner.handle

        def handle(supervisor, request, events):
            if request.get('kind') not in {'primary_package_installed_return', 'primary_package_installed_corruption'}:
                return original(request, events)
            saved = supervisor.authenticate(request, events)
            context = primary.contexts.get(request['pid'])
            if (supervisor is not owner or supervisor.poisoned or request['pid'] != pid
                    or request['token'] != 'root' or context is None
                    or context['role'] != 'package-installed-root'
                    or context['identity'] != saved['identity'] or identity(pid) != saved['identity']
                    or verify_installation() != declaration):
                raise RuntimeError('package_installed_current_return_owner')
            if request['kind'] == 'primary_package_installed_corruption':
                if (self.package_proof is None or self.corruption is not None
                        or set(request) != {'id', 'kind', 'nonce', 'pid', 'token', 'identity', 'result'}
                        or request['result'] != {'corrupt_state_refused': True, 'original_bytes_restored': True}):
                    raise RuntimeError('package_installed_corruption_result')
                self.corruption = request['result']
                self.records.append({'kind': 'primary_package_installed_corruption', 'pid': pid,
                                     'identity': saved['identity'], **self.corruption})
                return {'corruption_observed': True}
            expected = {'id', 'kind', 'nonce', 'pid', 'token', 'identity', 'source_sha256',
                        'function', 'cwd', 'module', 'result'}
            source = SITE / 'installed_wheel_check.py'
            if (self.package_proof is not None or set(request) != expected
                    or request['function'] != 'run_installed_wheel_check'
                    or request['source_sha256'] != sha(source.read_bytes())
                    or request['source_sha256'] != self.manifest['product_pins']['src/unrest_harness/installed_wheel_check.py']
                    or request['module'] != str(source) or request['cwd'] != primary.unrelated
                    or not Path(request['cwd']).is_relative_to('/work/owned/tmp')):
                raise RuntimeError('package_installed_original_return')
            proof = {'schema': 'unrest.v046.primary-installed-observation.v1',
                     **{key: request[key] for key in ('source_sha256', 'function', 'cwd', 'module', 'result')}}
            self.package_proof = proof
            primary.records.append({'kind': 'primary_function_return', 'pid': pid,
                                    'identity': saved['identity'], 'source_sha256': request['source_sha256'],
                                    'function': request['function'], 'proof_sha256': sha(canonical(proof))})
            return {'original_return_observed': True}

        owner.handle = types.MethodType(handle, owner)
        objects = []
        for descriptor in (output_fd, owner.channel.fileno()):
            info = os.fstat(descriptor)
            objects.append({'device': info.st_dev, 'inode': info.st_ino, 'type': stat.S_IFMT(info.st_mode)})
        with Path('/receipts/HOST-FDS.json').open('x') as stream:
            stream.write(json.dumps({'nonce': self.manifest['endpoint']['nonce'], 'objects': objects}, sort_keys=True))

    def tick(self, trace):
        if self.supervisor is None or self.closed:
            return
        self.supervisor.tick()
        waits = [row for row in trace.records if row['kind'] == 'original_parent_wait4'
                 and row['child'] == self.supervisor.child.pid]
        if waits:
            if len(waits) != 1 or waits[0]['raw'] != 0:
                raise RuntimeError('package_installed_original_root_wait')
            self.supervisor.close()
            self.closed = True

    def finish(self):
        if self.supervisor is None:
            return {'guard_poison': True, 'receipt_ledger_poison': ['installed_root_missing']}
        if not self.closed:
            self.supervisor.close()
            self.closed = True
        owner = self.supervisor
        return {'guard_poison': owner.poisoned, 'receipt_ledger_poison': owner.ledger.poison,
                'source_events': owner.events(), 'receipts': owner.receipts,
                'native_source_records': self.records, 'source_pipe_records': [],
                'source_observer_poison_sha256': None}

    def require_complete(self, trace):
        if (self.package_proof is None or self.corruption is None or self.supervisor is None
                or self.supervisor.poisoned or self.supervisor.ledger.poison or trace.poison or not self.closed):
            raise RuntimeError('package_installed_incomplete')
