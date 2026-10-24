"""PRIMARY-only operation domain; execute the exact unchanged legacy base."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

_UV_NATIVE = '/opt/source-bootstrap/bin/uv'
_CHECKER_SOURCE = '/source/tests/test_distribution_check.py'
_BASE = Path('/guard/finite/source_operations.py')
_BODY = _BASE.read_bytes()
if hashlib.sha256(_BODY).hexdigest() != '12108d981607212eac8b3f37413664229bee77fa1510a2adefaad2a397cbf89e':
    raise RuntimeError('primary_dependency_operations_base_drift')
exec(compile(_BODY, str(_BASE), 'exec', dont_inherit=True), globals())


_LegacyOperations: Any = globals()['Operations']
identity: Any = globals()['identity']
hashed: Any = globals()['hashed']
sha: Any = globals()['sha']
code_identity: Any = globals()['code_identity']


def original_guard_install(guard, state, guard_body, refuse):
    """Resolve only the byte-pinned endpoint wrapper's original guard function."""
    endpoint = sys.modules.get('endpoint')
    wrapper = guard.install
    path = Path(state['guard']).with_name('endpoint.py')
    binding = state.get('endpoint')
    if (endpoint is None or type(wrapper) is not types.FunctionType
            or wrapper.__globals__ is not endpoint.__dict__ or type(binding) is not dict):
        refuse('primary_native_route_endpoint_boundary')
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != binding.get('sha256'):
        refuse('primary_native_route_endpoint_drift')
    compiled = compile(body, str(path), 'exec', dont_inherit=True)
    attach = next(code for code in compiled.co_consts
                  if isinstance(code, types.CodeType) and code.co_name == 'attach')
    expected_wrapper = next(code for code in attach.co_consts
                            if isinstance(code, types.CodeType) and code.co_name == 'install')
    if code_identity(wrapper.__code__) != code_identity(expected_wrapper):
        refuse('primary_native_route_endpoint_code')
    cells = dict(zip(wrapper.__code__.co_freevars, wrapper.__closure__ or ()))
    original = cells['original_install'].cell_contents
    compiled = compile(guard_body, state['guard'], 'exec', dont_inherit=True)
    expected = next(code for code in compiled.co_consts
                    if isinstance(code, types.CodeType) and code.co_name == 'install')
    if (cells['guard'].cell_contents is not guard or type(original) is not types.FunctionType
            or original.__globals__ is not guard.__dict__
            or code_identity(original.__code__) != code_identity(expected)):
        refuse('primary_native_route_original_install')
    return original


class Operations(_LegacyOperations):
    def __init__(self, state, emit, refuse, require_ready):
        super().__init__(state, emit, refuse, require_ready)
        guard = sys.modules.get('runtime_guard')
        if guard is None or guard.__dict__.get('_STATE') is not state or state.get('phase') != 'INSTALLING':
            self.refuse('primary_native_route_install_boundary')
        guard_body = Path(state['guard']).read_bytes()
        if hashlib.sha256(guard_body).hexdigest() != 'd3029b485965d5e951ad7265bff3b58adeaf59e58c7708c9100f42407cf4b406':
            self.refuse('primary_native_route_guard_drift')
        original_install = original_guard_install(guard, state, guard_body, self.refuse)
        caller = sys._getframe(1)
        if (caller.f_code is not original_install.__code__ or caller.f_globals is not guard.__dict__
                or caller.f_locals.get('state') is not state):
            self.refuse('primary_native_route_install_caller')
        del caller
        initialize = next(code for code in original_install.__code__.co_consts
                          if isinstance(code, types.CodeType) and code.co_name == 'initialize_inner')
        original_init = subprocess.Popen.__init__
        if (getattr(original_init, '__globals__', None) is not subprocess.__dict__
                or original_init.__code__.co_filename != subprocess.__file__):
            self.refuse('primary_native_route_original_constructor')
        def native_init(handle, args, *positional, **kwargs):
            frame = sys._getframe(1)
            if (frame.f_code is not initialize or frame.f_globals is not guard.__dict__
                    or frame.f_locals.get('original_init') is not native_init
                    or guard._STATE is not state or state.get('operations') is not self
                    or positional or kwargs.get('executable') is not None
                    or list(args) != frame.f_locals.get('child_argv')):
                self.refuse('primary_native_route_launch_caller')
            require_ready(state['token'])
            selected = self.native_executable(frame.f_locals['registration'], frame.f_locals['argv'],
                                              kwargs.get('cwd'), kwargs.get('env'))
            del frame
            if selected is not None:
                kwargs['executable'] = selected
            return original_init(handle, args, **kwargs)
        # The unchanged guard captures this constructor later in install. Only
        # its admitted initialize_inner frame can reach the stdlib constructor.
        subprocess.Popen.__init__ = native_init

    def inputs(self):
        if hashlib.sha256(_BASE.read_bytes()).hexdigest() != '12108d981607212eac8b3f37413664229bee77fa1510a2adefaad2a397cbf89e':
            self.refuse('primary_dependency_operations_base_drift')
        observed = super().inputs()
        self.dependency('/source/.venv/lib/python3.13/site-packages')
        return observed

    def dependency(self, site):
        support = self.spec.get('primary_dependency_support')
        if (type(support) is not dict or set(support) != {'path', 'sha256', 'outputs_sha256'}
                or support['path'] != '/guard/primary_dependency.py'):
            self.refuse('primary_dependency_support_missing')
        body = Path(support['path']).read_bytes()
        if hashlib.sha256(body).hexdigest() != support['sha256']:
            self.refuse('primary_dependency_support_drift')
        if hashlib.sha256(Path('/guard/producer_outputs.py').read_bytes()).hexdigest() != support['outputs_sha256']:
            self.refuse('primary_dependency_outputs_support_drift')
        namespace = {'__file__': support['path'], '__name__': 'primary_dependency_consumer'}
        exec(compile(body, support['path'], 'exec', dont_inherit=True), namespace)
        try:
            observed = namespace['verify'](site, self.spec['primary_dependency'])
        except Exception as error:
            self.emit({'kind': 'primary_dependency_refusal',
                       'code_sha256': hashlib.sha256(str(error).encode()).hexdigest()})
            self.refuse('primary_dependency_consumption_refused')
        self.emit(observed)


    def native_executable(self, registration, argv, cwd, environment):
        """Resolve only the original checker's literal UV call, retaining argv."""
        if registration.get('class') != 'source-build' or not argv or argv[0] != 'uv':
            return None
        pending = self.pending.get(registration.get('operation_token'))
        if (pending is None or set(registration) != {'class', 'python', 'source_binding', 'operation_token'}
                or registration['python'] is not False):
            self.refuse('primary_native_route_registration')
        record = pending['record']
        binding = record['binding']
        profile = record.get('native_profile')
        if (record.get('kind') != 'operation_admission' or record['operation'] != 'source-build'
                or record['token'] != registration['operation_token'] or registration['source_binding'] != binding
                or binding.get('path') != _CHECKER_SOURCE
                or binding.get('function') != 'built_distribution'
                or record['owner_pid'] != os.getpid() or record['argv_sha256'] != sha(json.dumps(argv).encode())
                or record['cwd'] != str(cwd) or record['environment_sha256'] != hashed(environment)
                or type(profile) is not dict or profile['argv'] != argv
                or profile['environment'] != environment or profile['cwd'] != str(cwd)
                or profile.get('source_binding') != binding
                or len(argv) != 4 or argv[1:3] != ['build', '--out-dir']
                or argv[3] != record['output'] or str(cwd) != '/source'
                or self.spec.get('primary_dependency') is None):
            self.refuse('primary_native_route_original_operation')
        origin = next((row for row in self.spec['files'] if row['path'] == _CHECKER_SOURCE), None)
        if origin is None or binding.get('sha256') != origin['sha256'] or identity(_CHECKER_SOURCE) != origin:
            self.refuse('primary_native_route_source_drift')
        self.tool(argv[0], environment)
        selected = shutil.which(argv[0], path=environment.get('PATH'))
        if selected != _UV_NATIVE or Path(selected).resolve(strict=True) != Path(selected):
            self.refuse('primary_native_route_selection')
        before = os.stat(selected, follow_symlinks=False)
        image = identity(selected)
        after = os.stat(selected, follow_symlinks=False)
        def custody(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o555
                or before.st_uid != 0 or before.st_gid != 0 or before.st_nlink != 1
                or not os.statvfs(selected).f_flag & os.ST_RDONLY
                or image != self.spec['uv'] or custody(before) != custody(after)):
            self.refuse('primary_native_route_image')
        self.emit({'kind': 'primary_native_executable_route', 'owner_pid': os.getpid(),
                   'operation_token': record['token'], 'original_argv_sha256': record['argv_sha256'],
                   'source_binding': binding, 'image': image, 'custody': list(custody(after)),
                   'arguments_preserved': True})
        return selected
