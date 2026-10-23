"""Exact canonical mock backend in a closed, standard-library execution domain.

Original source admission precedes translation. This restricts test setup only;
it grants no native provider authority and claims no operating-system isolation.
"""
from __future__ import annotations

import __future__
import hashlib
import importlib.machinery
import os
import stat
from pathlib import Path
import sys
import types

CLASS = 'source-canonical-stdlib-backend'
ORIGINAL = 'source-controlled-backend-postimage'
SCRIPT = 'tests/fixtures/experimental_session_app_server.py'
PIN = 'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53'


def support(state, name):
    path = Path(state['guard']).with_name(name)
    return sys.modules['runtime_guard'].checked_source(
        path, state['direct_support']['files'][str(path)])


def select(argv, cwd, environment, state, emit, refuse):
    if type(argv) not in (list, tuple) or any(type(value) is not str for value in argv):
        return None
    argv = list(argv)
    setup = support(state, 'mock_backend_setup.py')
    if state.get('case') not in setup['INITIALIZATION_CASES'] | setup['CANCELLATION_CASES']:
        return None
    # The unchanged resolver authenticates the original live owner, exact
    # config renderer, script digest, interpreter, streams and call expression.
    original = support(state, 'backend_postimage_route.py')['admit'](
        argv, cwd, environment, state, emit, refuse)
    if original is None:
        return None
    if original['class'] != ORIGINAL or original['script_sha256'] != PIN:
        refuse('stdlib_backend_original_registration')
    translated = [argv[0], '-I', '-S', *argv[1:]]
    return {**original, 'class': CLASS}, translated


def shared(activation):
    """Consume all current shared startup bytes; site packages cannot execute."""
    # This is deliberately independent of the ordinary shared() path. That path
    # still consumes the complete third-party input domain for every other child.
    from operation_activation import identity, tree
    activation.ready(activation.state['token'])
    spec = activation.spec
    for item in spec['shared_files']:
        if identity(item['path']) != item:
            activation.refuse('stdlib_backend_shared_file')
    expected_root = str(Path(sys.base_prefix) / 'lib/python3.13')
    if set(spec['shared_trees']) != {expected_root}:
        activation.refuse('stdlib_backend_shared_tree_domain')
    for path, expected in spec['shared_trees'].items():
        if tree(path) != expected:
            activation.refuse('stdlib_backend_shared_tree')
    for name in [*spec['shared_absent'], str(Path(sys.base_prefix) / 'lib/python313.zip')]:
        path = Path(name)
        if path.exists() or path.is_symlink():
            activation.refuse('stdlib_backend_startup_path')
    link = spec['shared_python_link']
    path = Path(link['path'])
    if (not path.is_symlink() or str(path.resolve()) != link['target']
            or path.lstat().st_ino != link['inode']):
        activation.refuse('stdlib_backend_interpreter_link')


def seal(guard, endpoint):
    """Seal after original endpoint setup, before original payload dispatch."""
    state = guard._STATE
    caller = sys._getframe(1)
    child = caller.f_back
    payload = child.f_locals.get('payload') if child is not None else None
    setup = support(state, 'mock_backend_setup.py')
    if (state.get('class') != CLASS or caller.f_globals is not vars(endpoint)
            or caller.f_code is not guard.install.__code__
            or child is None or child.f_globals is not vars(guard)
            or child.f_code is not guard.child.__code__
            or not setup['eligible'](state, endpoint.STATE, payload)
            or sys.flags.isolated != 1 or sys.flags.no_site != 1
            or sys.version_info[:2] != (3, 13)):
        guard.refuse('stdlib_backend_seal_context')
    # Freeze the exercised lazy-import closure before sealing. These are all
    # standard-library modules; no product or third-party body is imported.
    import copy  # noqa: F401
    import email.parser  # noqa: F401
    import encodings.idna  # noqa: F401
    import pkgutil  # noqa: F401
    import secrets  # noqa: F401
    import stringprep  # noqa: F401
    import tomllib  # noqa: F401
    import unicodedata  # noqa: F401
    import urllib.request  # noqa: F401
    import zipimport  # noqa: F401
    install_barrier(state, guard, payload)
    guard.append({'kind': 'stdlib_backend_execution_sealed', 'class': CLASS,
                  'token': state['token'], 'case': state['case'],
                  'script_sha256': PIN, 'isolated_flags': [1, 1],
                  'third_party_execution': 'refused',
                  'native_provider_acceptance': 'UNVERIFIED'})


def install_barrier(state, guard, payload):
    root = Path(sys.base_prefix) / 'lib/python3.13'
    paths = [str(root.parent / 'python313.zip'), str(root), str(root / 'lib-dynload')]
    if list(sys.path) != paths or Path(paths[0]).exists() or Path(paths[0]).is_symlink():
        guard.refuse('stdlib_backend_import_path')
    execution = support(state, 'isolated_activation.py')['read_spec'](state)
    if execution != state['operation_activation'].spec:
        guard.refuse('stdlib_backend_execution_spec_drift')
    rows = execution['shared_trees'].get(str(root))
    if rows is None:
        guard.refuse('stdlib_backend_missing_stdlib_inventory')
    pins = {row['path']: row['sha256'] for row in rows if 'sha256' in row}
    pins.update(state['direct_support']['files'])
    pins[state['guard']] = state['guard_sha256']
    endpoint_path = str(Path(state['guard']).with_name('endpoint.py'))
    pins[endpoint_path] = state['endpoint']['sha256']
    target = payload['target']
    pins[target] = PIN
    guard_paths = set(state['direct_support']['files']) | {state['guard'], endpoint_path}
    if sys.platform == 'linux':
        # This profile was consumed by the native pre-body hook. Reacquire its
        # observer-owned bytes before trusting the additional bootstrap module.
        receipt = Path('/receipts/primary-startup') / (str(os.getpid()) + '.json')
        info = receipt.lstat()
        if (info.st_uid != 20001 or stat.S_IMODE(info.st_mode) != 0o444
                or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size > 65536
                or getattr(sys, '_unrest_primary_source_bootstrap_consumed', None) is not True):
            guard.refuse('stdlib_backend_native_profile')
        fd = os.open(receipt, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if os.fstat(fd) != info:
                guard.refuse('stdlib_backend_native_profile_open')
            body = os.read(fd, 65537)
            if os.fstat(fd) != info or receipt.lstat() != info or len(body) != info.st_size:
                guard.refuse('stdlib_backend_native_profile_race')
        finally:
            os.close(fd)
        import json
        profile = json.loads(body)
        raw_stat = Path('/proc/self/stat').read_text()
        birth = int(raw_stat[raw_stat.rfind(')') + 2:].split()[19])
        if (profile['pid'] != os.getpid() or profile['parent'] != os.getppid()
                or profile['start_ticks'] != birth
                or profile['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                or profile['orig_argv'] != sys.orig_argv
                or profile['flags'] != [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode]
                or profile.get('python_environment', profile['environment']) != dict(os.environ)
                or profile['source_role'] != 'source-bootstrap'
                or profile['manifest'] != state['manifest_path']
                or profile['manifest_sha256'] != state['pin']):
            guard.refuse('stdlib_backend_native_profile_binding')
        bootstrap = '/guard/primary_source_entry.py'
        pins[bootstrap] = profile['source_entry_sha256']
        guard_paths.add(bootstrap)
    gate = state.get('linux_profile_gate')
    if gate is not None:
        pins[gate['path']] = gate['sha256']
        guard_paths.add(gate['path'])
    original_main = sys.modules['__main__']
    original_modules = dict(sys.modules)
    payload_module = [None]
    loaders = (importlib.machinery.SourceFileLoader, importlib.machinery.SourcelessFileLoader,
               importlib.machinery.ExtensionFileLoader)

    def current(path):
        source = Path(path)
        before = source.lstat()
        def key(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                    info.st_mtime_ns, info.st_ctime_ns)
        if (path not in pins or not stat.S_ISREG(before.st_mode)
                or source.resolve() != source or not 0 <= before.st_size <= 64 * 1024 * 1024):
            guard.refuse('stdlib_backend_current_code_path')
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if key(os.fstat(fd)) != key(before):
                guard.refuse('stdlib_backend_current_code_open')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                body = stream.read(before.st_size + 1)
            if (len(body) != before.st_size or key(os.fstat(fd)) != key(before)
                    or key(source.lstat()) != key(before)
                    or hashlib.sha256(body).hexdigest() != pins[path]):
                guard.refuse('stdlib_backend_current_code_bytes')
        finally:
            os.close(fd)
        return body

    def modules():
        if list(sys.path) != paths:
            guard.refuse('stdlib_backend_import_path_drift')
        for name, module in tuple(sys.modules.items()):
            if type(module) is not types.ModuleType:
                guard.refuse('stdlib_backend_module_type')
            if (name == '__mp_main__' and module is original_main
                    and original_modules.get(name) is original_main):
                # multiprocessing.util was loaded by the original endpoint
                # hook before sealing; only its exact original-main alias survives.
                continue
            if name == '__main__':
                if module is original_main:
                    continue
                if (getattr(module, '__file__', None) != target
                        or getattr(module, '__spec__', None) is not None
                        or payload_module[0] is not None and module is not payload_module[0]):
                    guard.refuse('stdlib_backend_main_module')
                continue
            if original_modules.get(name) is not module:
                guard.refuse('stdlib_backend_new_module')
            spec = getattr(module, '__spec__', None)
            if spec is not None and spec.origin in {'built-in', 'frozen'}:
                if (original_modules.get(name) is not module
                        or spec.loader not in (importlib.machinery.BuiltinImporter,
                                               importlib.machinery.FrozenImporter)):
                    guard.refuse('stdlib_backend_builtin_identity')
                continue
            path = getattr(module, '__file__', None)
            if type(path) is not str or path not in pins:
                guard.refuse('stdlib_backend_module_origin')
            if path.startswith(str(root) + '/'):
                if (spec is None or spec.origin != path or type(spec.loader) not in loaders
                        or module.__loader__ is not spec.loader or spec.loader.path != path
                        or spec.loader.name != name):
                    guard.refuse('stdlib_backend_module_loader')
            elif (original_modules.get(name) is not module
                  or path not in guard_paths):
                guard.refuse('stdlib_backend_support_identity')
        for name, module in original_modules.items():
            if name != '__main__' and sys.modules.get(name) is not module:
                guard.refuse('stdlib_backend_module_replacement')

    # A module identity is captured only after its physical execution origin and
    # current bytes have been checked against the inherited startup inventory.
    modules()
    for path in sorted({getattr(module, '__file__', None) for module in original_modules.values()}
                       - {None, getattr(original_main, '__file__', None)}):
        current(path)
    code_cache = {}
    dispatch = [False]
    checked_source = guard.checked_source
    run_code = sys.modules['runpy']._run_code

    def code(path, *, support_code=False):
        data = current(path)
        # Reuse comparison compilation only after reading current pinned bytes.
        flags = (checked_source.__code__.co_flags & __future__.annotations.compiler_flag
                 if support_code else 0)
        key = (path, flags)
        if key not in code_cache:
            code_cache[key] = compile(data, path, 'exec', flags=flags, dont_inherit=True)
        return code_cache[key]

    def audit(event, args):
        if event == 'import':
            modules()
            if (args[0] not in original_modules
                    or sys.modules.get(args[0]) is not original_modules[args[0]]):
                guard.refuse('stdlib_backend_unsealed_import')
            if len(args) > 1 and isinstance(args[1], str):
                path = args[1]
                if not path.startswith(str(root) + '/'):
                    guard.refuse('stdlib_backend_foreign_import')
                current(path)
        if event != 'exec':
            return
        modules()
        executed = args[0]
        path = executed.co_filename
        frame = sys._getframe(1)
        if path == target:
            if (dispatch[0] or executed != code(target)
                    or frame.f_code is not run_code.__code__
                    or frame.f_globals is not vars(sys.modules['runpy'])
                    or frame.f_locals.get('code') is not executed
                    or frame.f_locals.get('run_globals') is not vars(sys.modules['__main__'])):
                guard.refuse('stdlib_backend_payload_dispatch')
            payload_module[0] = sys.modules['__main__']
            dispatch[0] = True
            return
        if path in state['direct_support']['files']:
            if (frame.f_code is not checked_source.__code__
                    or frame.f_globals is not vars(guard)
                    or frame.f_locals.get('pin') != pins[path]
                    or str(frame.f_locals.get('path')) != path
                    or executed != code(path, support_code=True)):
                guard.refuse('stdlib_backend_support_exec')
            # CPython's exec audit fires in checked_source's own frame. Its
            # freshly allocated destination is the sole permitted namespace.
            namespace = frame.f_locals.get('namespace')
            if (type(namespace) is not dict or namespace != {
                    '__name__': '_finite_support', '__file__': path,
                    '__builtins__': namespace.get('__builtins__')}):
                guard.refuse('stdlib_backend_support_namespace')
            return
        guard.refuse('stdlib_backend_unknown_exec')

    sys.addaudithook(audit)
    state['stdlib_backend_barrier'] = audit
