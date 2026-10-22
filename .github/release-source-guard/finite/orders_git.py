"""Original custody Git calls for the thirty controlled finite-order cases."""
from __future__ import annotations

import ast
import configparser
import hashlib
import json
from pathlib import Path
import sys

CLASS = 'source-orders-custody-git'
PRODUCT = 'src/unrest_harness/experimental_custody.py'
ORDERS = 'tests/test_experimental_finite_orders.py'
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
               'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
               'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid',
               'GIT_AUTHOR_DATE': '2000-01-01T00:00:00+0000',
               'GIT_COMMITTER_DATE': '2000-01-01T00:00:00+0000'}


def repository_profile(argv, cwd, owned_root, caller):
    path = Path(cwd)
    if (path.resolve() != path or not path.is_relative_to(Path(owned_root) / 'pytest')
            or path.parent.name != 'cohort' or argv[:2] != ['/usr/bin/git', '--no-replace-objects']):
        return False
    arguments = argv[2:]
    owner = caller['function']
    prefixes = {
        ('setup', 36): ['init', '--initial-branch=main', '--object-format=sha1'],
        ('setup', 45): ['add', '.'], ('setup', 46): ['commit', '-m', 'finite fixture'],
        ('setup', 47): ['rev-parse', 'HEAD'], ('seal', 193): ['add', '--'],
        ('seal', 194): ['diff', '--cached', '--name-only'],
        ('seal', 197): ['commit', '--allow-empty', '-m', 'sealed candidate'],
        ('seal', 198): ['rev-parse', 'HEAD'], ('integrate', 235): ['add', '--'],
        ('integrate', 236): ['diff', '--cached', '--name-only'],
        ('integrate', 239): ['commit', '--allow-empty', '-m', 'authored lane integration'],
        ('integrate', 241): ['rev-parse', 'HEAD'],
    }
    prefix = prefixes.get((owner, caller.get('line')))
    if prefix is None or arguments[:len(prefix)] != prefix:
        return False
    if owner == 'setup':
        if path.name != 'base':
            return False
        valid = arguments in [['init', '--initial-branch=main', '--object-format=sha1'],
                              ['add', '.'], ['commit', '-m', 'finite fixture'], ['rev-parse', 'HEAD']]
        if arguments == ['init', '--initial-branch=main', '--object-format=sha1']:
            return valid and not (path / '.git').exists() and not (path / '.git').is_symlink()
    elif owner == 'seal':
        valid = path.name in ('z-first-candidate', 'a-second-candidate') and (
            arguments in [['add', '--', 'a'], ['add', '--', 'b'],
                          ['commit', '--allow-empty', '-m', 'sealed candidate'], ['rev-parse', 'HEAD']]
            or len(arguments) == 4 and arguments[:3] == ['diff', '--cached', '--name-only'])
    elif owner == 'integrate':
        valid = path.name == 'integration' and (
            arguments in [['add', '--', 'a'], ['add', '--', 'b'],
                          ['commit', '--allow-empty', '-m', 'authored lane integration'], ['rev-parse', 'HEAD']]
            or len(arguments) == 4 and arguments[:3] == ['diff', '--cached', '--name-only'])
    else:
        return False
    if arguments[:3] == ['diff', '--cached', '--name-only']:
        valid = valid and len(arguments) == 4 and len(arguments[3]) == 40 and all(c in '0123456789abcdef' for c in arguments[3])
    if not valid:
        return False
    git = path / '.git'
    if git.resolve() != git or not git.is_dir():
        return False
    config = git / 'config'
    if config.is_symlink() or not config.is_file() or config.stat().st_nlink != 1 or config.stat().st_size > 4096:
        return False
    parsed = configparser.RawConfigParser(strict=True)
    parsed.read_string(config.read_text())
    return (not parsed.defaults() and set(parsed.sections()) == {'core', 'maintenance', 'gc'}
            and dict(parsed['core']) == {'repositoryformatversion': '0', 'filemode': 'true',
                'bare': 'false', 'logallrefupdates': 'true'}
            and dict(parsed['maintenance']) == {'auto': 'false'} and dict(parsed['gc']) == {'auto': '0'})


def matches(argv, cwd, environment, state, frames, data, cases):
    if state.get('case') not in cases or state['case'].split('::')[0] != ORDERS:
        return None
    root = Path(state['checkout'])
    if any(state['product_pins'].get(n) != pin or hashlib.sha256((root / n).read_bytes()).hexdigest() != pin
           for n, pin in data['PINS'].items()):
        return None
    module = sys.modules.get('unrest_harness.experimental_custody')
    if module is None or Path(module.__file__).resolve() != root / PRODUCT:
        return None
    helpers = {id(f): f for f in frames if f.f_code.co_filename == str(root / PRODUCT)
               and f.f_code.co_name == 'git' and f.f_lineno == 38 and f.f_globals is vars(module)}
    if len(helpers) != 1:
        return None
    helper = next(iter(helpers.values()))
    caller = helper.f_back
    if caller is None:
        return None
    if not Path(caller.f_code.co_filename).is_relative_to(root):
        return None
    relative = str(Path(caller.f_code.co_filename).relative_to(root))
    key = (relative, caller.f_lineno)
    if data['SITES'].get(key) != caller.f_code.co_name:
        return None
    for frame in (helper, caller):
        source = Path(frame.f_code.co_filename)
        loaded = sys.modules.get(frame.f_globals.get('__name__'))
        if loaded is None or vars(loaded) is not frame.f_globals:
            return None
        code = state['isolated_source_code'](source)
        expected = state['isolated_named'](code, frame.f_code.co_name)
        plain = state['isolated_named'](compile(source.read_bytes(), str(source), 'exec', dont_inherit=True), frame.f_code.co_name)
        if frame.f_code not in (expected, plain):
            return None
    if caller.f_code.co_name in ('seal', 'integrate'):
        instance = caller.f_locals.get('self' if caller.f_code.co_name == 'seal' else 'lane')
        if type(instance) is not module.Custody or instance.writes not in (('a',), ('b',)):
            return None
        if caller.f_code.co_name == 'seal' and instance.root != cwd:
            return None
        if caller.f_code.co_name == 'integrate' and caller.f_locals.get('destination') != cwd:
            return None
    calls = [c for c in ast.walk(ast.parse((root / relative).read_bytes())) if isinstance(c, ast.Call)
             and c.lineno == caller.f_lineno and isinstance(c.func, ast.Name) and c.func.id == 'git']
    if len(calls) != 1 or calls[0].keywords:
        return None
    values = []
    for argument in calls[0].args:
        target = argument.value if isinstance(argument, ast.Starred) else argument
        value = eval(compile(ast.Expression(target), str(root / relative), 'eval'), caller.f_globals, caller.f_locals)
        values.extend(value if isinstance(argument, ast.Starred) else [value])
    directory, *arguments = values
    binding = {'path': str(root / relative), 'line': caller.f_lineno,
               'sha256': data['PINS'][relative], 'function': caller.f_code.co_name}
    if (environment != ENVIRONMENT or cwd != directory or helper.f_locals.get('root') != directory
            or helper.f_locals.get('arguments') != tuple(arguments)
            or argv != ['/usr/bin/git', '--no-replace-objects', *arguments]
            or not repository_profile(argv, str(cwd), state['owned_root'], binding)):
        return None
    return {'class': CLASS, 'python': False, 'case': state['case'],
            'source_binding': {'path': str(root / PRODUCT), 'line': 38,
                               'sha256': data['PINS'][PRODUCT], 'function': 'git'},
            'caller_binding': binding}


def admit(argv, cwd, environment, state, append, refuse):
    guard = sys.modules['runtime_guard']
    support = state['direct_support']['files']
    base = Path(__file__).parent
    data = guard.checked_source(base / 'orders_git_data.py', support[str(base / 'orders_git_data.py')])
    catalog = guard.checked_source(base / 'backend_postimage_catalog.py', support[str(base / 'backend_postimage_catalog.py')])
    fallback = guard.checked_source(base / 'fallback_binding.py', support[str(base / 'fallback_binding.py')])
    frames = fallback['active_frames']()
    try:
        registration = matches(argv, cwd, environment, state, frames, data, catalog['CASES'])
        if registration is None:
            return None
        # Authenticate all original subprocess keywords as well as caller argv.
        if fallback['matches'](registration, argv, cwd, environment, state) is None:
            refuse('orders_git_original_subprocess_call')
        append({'kind': 'concrete_orders_custody_git', **registration,
                'argv_sha256': hashlib.sha256(json.dumps(argv).encode()).hexdigest(), 'cwd': str(cwd)})
        return registration
    finally:
        frames.clear()
