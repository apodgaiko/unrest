"""Exact original controlled backend variants, never a mutable fixture-pin grant."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

CLASS = 'source-controlled-backend-postimage'
PRODUCT = 'src/unrest_harness/experimental_session.py'
CONFIG = 'src/unrest_harness/experimental_provider_config.py'
ACP = 'tests/fixtures/controlled_python_acp.py'



def original_function(module, function, path, state):
    import importlib.machinery
    from beartype.claw._importlib._clawimpload import BeartypeSourceFileLoader
    loader = getattr(module, '__loader__', None)
    if (type(loader) not in (importlib.machinery.SourceFileLoader, BeartypeSourceFileLoader)
            or getattr(module, '__spec__', None) is None or module.__spec__.loader is not loader
            or Path(module.__spec__.origin).resolve() != path
            or Path(loader.path).resolve() != path or loader.name != module.__name__
            or function.__globals__ is not vars(module)):
        return False
    if type(loader) is BeartypeSourceFileLoader:
        code = BeartypeSourceFileLoader.source_to_code(
            loader, path.read_bytes(), str(path), _optimize=sys.flags.optimize)
    else:
        code = compile(path.read_bytes(), str(path), 'exec', dont_inherit=True,
                       optimize=sys.flags.optimize)
    return function.__code__ == state['isolated_named'](code, function.__name__)


def select(argv, cwd, environment, state, frames, catalog):
    row = catalog['CASES'].get(state.get('case'))
    if row is None or len(argv) < 3:
        return None
    root = Path(state['checkout'])
    pins = {**catalog['PINS'], **row['sources']}
    if any(state['product_pins'].get(p) != pin or hashlib.sha256(
            (root / p).read_bytes()).hexdigest() != pin for p, pin in pins.items()):
        return None
    module = sys.modules.get('unrest_harness.experimental_session')
    if module is None or Path(module.__file__).resolve() != root / PRODUCT:
        return None
    function = module._SessionOwner._open_role_owned
    candidates = {id(f): f for f in frames if f.f_code is function.__code__
                  and f.f_globals is vars(module) and f.f_lineno == 506}
    if len(candidates) != 1:
        return None
    local = next(iter(candidates.values())).f_locals
    owner = local.get('self')
    if (type(owner) not in (module.SyntheticSession, module._SessionOwner)
            or owner.controlled is not True or owner.provider_package is not None
            or type(owner.transport) is not module.ControlledTransport
            or owner.transport._runtime is not module._TRUSTED_TEST_RUNTIME
            or owner.transport.fixture != root / ACP
            or owner.transport.interpreter.resolve() != Path(state['runtime']['realpath'])
            or argv[0] != str(owner.transport.interpreter.resolve())
            or argv[1] != str(owner.backend_launcher)
            or owner.backend_launcher.name != row['filename']
            or owner.backend_launcher.is_symlink()
            or not owner.backend_launcher.is_absolute()
            or not owner.backend_launcher.resolve().is_relative_to(Path(state['owned_root']))
            or hashlib.sha256(owner.backend_launcher.read_bytes()).hexdigest() != row['script_sha256']
            or owner.backend_digest != row['script_sha256']
            or not owner.root.resolve().is_relative_to(Path(state['owned_root']))
            or local.get('name') not in ('worker', 'validator')
            or local.get('home') != owner.root / local['name']
            or Path(cwd) != local['home'] or argv != local.get('argv')
            or type(environment) is not dict
            or environment is not local.get('backend_environment')):
        return None
    expected = [argv[0], str(owner.backend_launcher), 'app-server']
    config = owner.provider_config
    if config is not None:
        config_module = sys.modules.get('unrest_harness.experimental_provider_config')
        if (config_module is None or Path(config_module.__file__).resolve() != root / CONFIG
                or type(config) is not config_module.ProviderConfig
                or type(config.inputs) is not config_module.CommonInputs
                or any(not Path(p).resolve().is_relative_to(Path(state['owned_root']))
                       for p in (config.codex_home, config.user_home, config.inputs.runtime_root))
                or any(name in config.__dict__ for name in ('argv', 'overrides'))
                or 'verify' in config.inputs.__dict__):
            return None
        if any(not original_function(config_module, fn, root / CONFIG, state)
               for fn in (config.argv.__func__, config.overrides.__func__,
                          config.inputs.verify.__func__, config_module._toml)):
            return None
        expected = [argv[0], *config.argv(owner.backend_launcher, local['home'])]
    if argv != expected:
        return None
    owner.transport.verify(controlled=True, package=None)
    return {'class': CLASS, 'python': True,
            'source_binding': {'path': str(root / PRODUCT), 'line': 506,
                               'sha256': pins[PRODUCT], 'function': '_open_role_owned'},
            'script_sha256': row['script_sha256'], 'case': state['case']}


def admit(argv, cwd, env, state, append, refuse):
    guard = sys.modules['runtime_guard']
    support = state['direct_support']['files']
    path = Path(__file__).with_name('backend_postimage_catalog.py')
    catalog = guard.checked_source(path, support[str(path)])
    if state.get('case') not in catalog['CASES']:
        return None
    path = Path(__file__).with_name('fallback_binding.py')
    fallback = guard.checked_source(path, support[str(path)])
    frames = fallback['active_frames']()
    try:
        environment = dict(os.environ) if env is None else env
        registration = select(argv, cwd, environment, state, frames, catalog)
        if registration is None:
            return None
        # Authenticate the unchanged loader/code/globals and actual subprocess
        # call expression, including every argument and keyword. The catalog
        # alone cannot admit an arbitrary caller carrying the same script bytes.
        if fallback['matches'](registration, argv, cwd, environment, state) is None:
            refuse('controlled_backend_postimage_original_caller')
        append({'kind': 'concrete_controlled_backend_postimage',
                'case': state['case'], 'script_sha256': registration['script_sha256'],
                'source_binding': registration['source_binding'],
                'argv_sha256': hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                'cwd': str(cwd), 'environment_sha256': hashlib.sha256(
                    json.dumps(environment, sort_keys=True).encode()).hexdigest()})
        return registration
    finally:
        frames.clear()
