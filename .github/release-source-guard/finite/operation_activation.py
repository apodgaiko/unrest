"""Finite private startup consumption gate; no OS or native-child guarantee.

Profiles are checked setup inputs, not caller capabilities. Original isolated
UV operations remain refused until their pre-site environment is resolvable.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import importlib.util
import json
import marshal
import os
from pathlib import Path
import stat
import sys
import types
from typing import NoReturn


def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def identity(path):
    path = Path(path)
    pathname = str(path)
    before = os.stat(pathname, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError('activation_nonregular_input')
    fd = os.open(pathname, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(fd)
    finally:
        os.close(fd)
    def key(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    if key(before) != key(opened) or key(after) != key(before) or key(after) != key(os.stat(pathname, follow_symlinks=False)):
        raise RuntimeError('activation_input_read_race')
    return {'path': pathname, 'identity': list(key(after)), 'sha256': digest}


def tree(root):
    root = Path(root)
    result = []
    for path in [root, *sorted(root.rglob('*'), key=lambda path: path.parts)]:
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            result.append({'path': str(path), 'directory': [info.st_dev, info.st_ino, info.st_mode]})
        else:
            result.append(identity(path))
    return result


def verify_caches(root):
    """Validate consumed Python cache code against its pinned source.

    This comparison never dispatches the compiled comparison code. CPython's
    normal loader remains responsible for choosing source or a valid cache.
    """
    checked = []
    for cache in sorted(Path(root).rglob('*.pyc')):
        if cache.parent.name != '__pycache__':
            raise RuntimeError('unknown_sourceless_cache')
        parts = cache.name.split('.')
        if len(parts) not in (3, 4) or parts[1] != 'cpython-313':
            raise RuntimeError('unknown_interpreter_cache')
        optimize = 0
        if len(parts) == 4:
            if parts[2] not in ('opt-1', 'opt-2'):
                raise RuntimeError('unknown_cache_optimization')
            optimize = int(parts[2][-1])
        source = cache.parent.parent / (parts[0] + '.py')
        body = source.read_bytes()
        payload = cache.read_bytes()
        if payload[:4] != importlib.util.MAGIC_NUMBER:
            raise RuntimeError('unknown_cache_magic')
        flags = int.from_bytes(payload[4:8], 'little')
        if flags == 0:
            info = source.stat()
            if (int.from_bytes(payload[8:12], 'little') != int(info.st_mtime) & 0xffffffff
                    or int.from_bytes(payload[12:16], 'little') != len(body) & 0xffffffff):
                raise RuntimeError('cache_source_header_drift')
        elif flags in (1, 3):
            if payload[8:16] != importlib.util.source_hash(body):
                raise RuntimeError('cache_source_hash_drift')
        else:
            raise RuntimeError('unknown_cache_flags')
        code = marshal.loads(payload[16:])
        expected = compile(body, str(source), 'exec', dont_inherit=True, optimize=optimize)
        # The selected interpreter was installed in this exact prefix; no
        # generic filename rewrite or unrelated cached body is admitted.
        if code_identity(code) != code_identity(expected):
            raise RuntimeError('cache_source_code_drift:' + str(cache))
        checked.append({'cache': identity(cache), 'source': identity(source), 'optimize': optimize})
    return checked


def source_code(frame, expected):
    """Check bytes and the running function; same-name replacement is refused."""
    path = Path(frame.f_code.co_filename)
    if str(path) != expected['path'] or identity(path) != expected['file']:
        raise RuntimeError('activation_caller_source_drift')
    namespace = compile(path.read_bytes(), str(path), 'exec', dont_inherit=True)
    matches = [code for code in namespace.co_consts if isinstance(code, type(namespace))
               and code.co_name == expected['function']]
    if len(matches) != 1 or code_identity(matches[0]) != code_identity(frame.f_code):
        raise RuntimeError('activation_caller_code_drift')


def code_identity(code):
    """Marshal reference/intern tables differ without changing a code object."""
    from types import CodeType
    def constant(value):
        if isinstance(value, CodeType):
            return code_identity(value)
        if isinstance(value, tuple):
            return ['tuple', [constant(v) for v in value]]
        if isinstance(value, frozenset):
            return ['frozenset', sorted(constant(v) for v in value)]
        return [type(value).__name__, repr(value)]
    return {key: getattr(code, key) for key in
            ['co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals',
             'co_stacksize', 'co_flags', 'co_filename', 'co_name', 'co_qualname', 'co_firstlineno',
             'co_names', 'co_varnames', 'co_freevars', 'co_cellvars']} | {
                 'code': code.co_code.hex(), 'lines': code.co_linetable.hex(),
                 'exceptions': code.co_exceptiontable.hex(),
                 'constants': [constant(v) for v in code.co_consts]}


class Activation:
    def __init__(self, state, emit, refuse, ready):
        self.state, self.emit, self.refuse, self.ready = state, emit, refuse, ready
        self.spec = state['activation_spec']
        self.active = None

    def reject(self, reason: str) -> NoReturn:
        self.refuse('operation_activation:' + reason)
        raise RuntimeError('refusal callback returned')

    def validate(self):
        """Parent gate BEFORE launching an interpreter and its site callbacks."""
        self.ready(self.state['token'])
        try:
            for expected in self.spec['files']:
                if identity(expected['path']) != expected:
                    self.reject('input_drift')
            for root, expected in self.spec['trees'].items():
                if tree(root) != expected:
                    self.reject('startup_or_cache_membership_drift')
            for root, expected in self.spec['python_caches'].items():
                if verify_caches(root) != expected:
                    self.reject('cache_source_correspondence_drift')
            for absent in self.spec['absent']:
                if Path(absent).exists() or Path(absent).is_symlink():
                    self.reject('unknown_startup_callback')
            link = self.spec['python_link']
            path = Path(link['path'])
            if (not path.is_symlink() or str(path.resolve()) != link['target']
                    or path.lstat().st_ino != link['inode']):
                self.reject('interpreter_link_drift')
            observed_cache = tree(self.spec['cache'])
            if self.state['class'] == 'stock-uv-build-wheel-prototype':
                expected_cache = {r['path']: r for r in self.spec['cache_preimage']}
                actual_cache = {r['path']: r for r in observed_cache}
                if any(actual_cache.get(p) != r for p, r in expected_cache.items()):
                    self.reject('uv_cache_input_drift')
                added = [r for p, r in actual_cache.items() if p not in expected_cache]
                request_dir = Path(self.spec['active_request']).parent
                if any('directory' not in r or Path(r['path']) not in
                       (Path(self.spec['cache']) / 'builds-v0', request_dir) for r in added):
                    self.reject('unknown_uv_generated_cache_input')
            elif observed_cache != self.spec['cache_preimage']:
                self.reject('uv_cache_input_drift')
        except (OSError, RuntimeError) as error:
            self.reject(str(error))

    def profile(self, argv, cwd, environment):
        matches = [p for p in self.spec['profiles'] if p['argv'] == argv
                   and p['cwd'] == str(Path(cwd or os.getcwd()).resolve())
                   and p['environment'] == environment]
        if len(matches) != 1:
            self.reject('unknown_command_config_environment_root')
        profile = matches[0]
        frames = inspect.stack()
        try:
            callers = [f.frame for f in frames if f.function == profile['caller']['function']
                       and f.filename == profile['caller']['path']]
            if len(callers) != 1:
                self.reject('source_owner_missing')
            try:
                source_code(callers[0], profile['caller'])
            except (RuntimeError, OSError) as error:
                self.reject(str(error))
        finally:
            del frames
        return profile

    def __call__(self, record):
        # The only supplier is the actual source Operations.activation frame.
        current = inspect.currentframe()
        if current is None or current.f_back is None:
            self.reject('callback_frame_missing')
        frame = current.f_back
        support = self.state['operation_support']
        if (frame.f_code.co_name != 'activation' or frame.f_code.co_filename != support['path']
                or frame.f_locals.get('record') is not record
                or frame.f_locals.get('self') is not self.state['operations']):
            self.reject('callback_not_operation_owned')
        self.validate()
        active = self.active
        if active is None or record is not active['record']:
            origin = frame.f_back
            if origin is None:
                self.reject('operation_source_frame_missing')
            operations = self.state['operations']
            methods = (operations.make.__func__.__code__, operations.registration.__func__.__code__)
            if (origin.f_code not in methods or origin.f_locals.get('self') is not operations):
                self.reject('operation_not_resolved')
            local = origin.f_locals
            profile = self.profile(local['argv'], local['directory'], local['environment'])
            if profile['kind'] != record['operation'] or profile.get('startup_resolution') != 'finite-shared':
                # Existing original isolated producer startup is deliberately
                # unresolved, even with a selected backend-distribution pin.
                self.reject('operation_startup_resolution_unavailable')
            if record['inputs'] != operations.inputs():
                self.reject('operation_input_binding_drift')
            if origin.f_code is operations.make.__func__.__code__ and local['record'] is not record:
                self.reject('operation_record_not_owned')
            active = {'record': record, 'profile': profile}
            self.active = active
        self.emit({'kind': 'operation_startup_consumption', 'operation': record['operation'],
                   'profile': active['profile']['name'], 'input_sha256': hashed(self.spec['trees']),
                   'record_sha256': hashed(record), 'pre_callback': True,
                   'helper_manifest': identity(Path(support['path']).parent / 'helper-manifest.json'),
                   'prototype_only': True})

    def admit_prototype(self, argv, cwd, environment):
        # Only finite scratch UV probes; no original-source operation exemption.
        if argv[0] != self.spec['uv']['path']:
            return None
        env = dict(os.environ if environment is None else environment)
        profile = self.profile(argv, cwd, env)
        if profile['kind'] != 'uv-wheel-prototype':
            return None
        self.validate()
        record = {'operation': profile['name'], 'argv_sha256': hashed(argv),
                  'environment_sha256': hashed(env), 'cwd': profile['cwd'],
                  'binding': profile['caller'], 'prototype_only': True}
        self.active = {'record': record, 'profile': profile}
        self.state['operations'].activation(record)
        return {'class': profile['name'], 'python': False, 'source_binding': profile['caller']}

    def before_python(self, argv, cwd, environment):
        env = dict(os.environ if environment is None else environment)
        profile = self.profile(argv, cwd, env)
        if (profile['kind'] != 'python-prototype' and profile.get('startup_resolution') != 'finite-shared'):
            self.reject('unknown_python_route')
        self.validate()
        self.emit({'kind': 'python_startup_consumption', 'profile': profile['name'],
                   'argv_sha256': hashed(argv), 'pre_callback': True, 'prototype_only': True})

    def generated_helper(self, script):
        self.ready(self.state['token'])
        try:
            return helper_class(script, self.spec)
        except (RuntimeError, SyntaxError, TypeError, ValueError, OSError) as error:
            self.reject(str(error))


def helper_class(script, spec):
    """Literal UV wheel renderer, with two finite owned output parameters.

    Comparison is to the pinned stock-UV source renderer, not observed code
    accepted into a growing allowlist. The original script is never replaced.
    """
    nodes = ast.parse(script).body
    if len(nodes) != 6:
        raise RuntimeError('unknown_generated_helper')
    try:
        output = nodes[4].value.args[0].value
        request = nodes[5].items[0].context_expr.args[0].value
    except (AttributeError, IndexError):
        raise RuntimeError('unknown_generated_helper') from None
    if output != spec['wheel_output']:
        raise RuntimeError('helper_output_drift')
    path = Path(request)
    cache = Path(spec['cache']) / 'builds-v0'
    if (not isinstance(request, str) or path.name != 'build_wheel.txt'
            or path.parent.parent != cache or not path.parent.name.startswith('.tmp')
            or path.resolve() != path or not path.parent.is_dir()):
        raise RuntimeError('helper_request_lineage')
    expected = ('import sys\n\nif sys.path[0] == "":\n    sys.path.pop(0)\n\n'
                'sys.path = ["."] + sys.path\n\nimport tiny_backend as backend\n\n\n'
                f'wheel_filename = backend.build_wheel("{output}", {{}}, None)\n'
                f'with open("{request}", "w") as fp:\n    fp.write(wheel_filename)\n')
    if script != expected:
        raise RuntimeError('unknown_generated_helper')
    return 'stock-uv-build-wheel'


def create(state, emit, refuse, ready):
    if state.get('isolated_support') is not None:
        support = state['isolated_support']
        # -S children have no setup search path. Load exact dependencies from
        # checked source rather than importing through ambient site/cache paths.
        for path, pin, name in [(state['activation_support']['path'], state['activation_support']['sha256'], 'operation_activation'),
                                (support['inputs_path'], support['inputs_sha256'], 'isolated_inputs')]:
            body = Path(path).read_bytes()
            if hashlib.sha256(body).hexdigest() != pin:
                raise RuntimeError('isolated_checked_dependency_drift')
            module = types.ModuleType(name)
            module.__file__ = path
            sys.modules[name] = module
            exec(compile(body, path, 'exec', dont_inherit=True), module.__dict__)
        data = Path(support['path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != support['sha256']:
            raise RuntimeError('isolated_activation_support_drift')
        namespace = {'__name__': '_isolated_activation', '__file__': support['path']}
        exec(compile(data, support['path'], 'exec', dont_inherit=True), namespace)
        if state.get('source_activation_support') is not None:
            item = state['source_activation_support']
            body = Path(item['path']).read_bytes()
            if hashlib.sha256(body).hexdigest() != item['sha256']:
                raise RuntimeError('source_activation_support_drift')
            isolated_module = types.ModuleType('isolated_activation')
            isolated_module.__dict__.update(namespace)
            sys.modules['isolated_activation'] = isolated_module
            source_namespace = {'__name__': '_source_activation', '__file__': item['path']}
            exec(compile(body, item['path'], 'exec', dont_inherit=True), source_namespace)
            return source_namespace['create'](state, emit, refuse, ready)
        return namespace['create'](state, emit, refuse, ready)
    return Activation(state, emit, refuse, ready)
