"""Prepare read-only source inputs without importing project code."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path('/source')
SUPPORT = Path('/guard/finite')
CASE = 'tests/test_server.py::test_completion_refusal_survives_server_restart'

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    nonce = sys.argv[1]
    if len(nonce) != 64 or any(c not in '0123456789abcdef' for c in nonce):
        raise RuntimeError('invalid source epoch')
    manifest = json.loads((SUPPORT / 'source-template.json').read_bytes())
    for name, pin in manifest['product_pins'].items():
        observed = sha(ROOT / name)
        if observed != pin:
            if not (name.startswith('.github/') or name in {
                'docs/release/lean-core-v0.4.6.md',
                'docs/release/v046-source-checkpoint-environment.md',
            }):
                raise RuntimeError('original source baseline drift: ' + name)
            manifest['product_pins'][name] = observed
    registry = ast.literal_eval(ast.parse((SUPPORT / 'registry.py').read_text()).body[1].value)
    for entry in registry:
        if not entry['python']:
            path = Path(entry['executable'])
            if path.is_file():
                entry['executable_sha256'] = sha(path)
            else:
                entry['executable_sha256'] = 'unavailable-on-linux'
    registry_text = '"""Finite vectors; unavailable platform images cannot match a byte pin."""\nCOMMANDS = ' + repr(registry) + '\n'
    manifest.update({
        'checkout': '/source', 'owned_root': '/work', 'events': '/work/events',
        'source_case': CASE, 'scope': 'focused original in-process completion restart; all four parameters',
        'source_checkpoint_ready': False, 'selected_carrier': None,
        'guard': str(SUPPORT / 'runtime_guard.py'), 'guard_sha256': sha(SUPPORT / 'runtime_guard.py'),
        'registry': {'path': '/inputs/registry.py', 'sha256': hashlib.sha256(registry_text.encode()).hexdigest()},
        'runtime': {'paths': ['/opt/deps/bin/python', '/usr/local/bin/python3.13'],
                    'realpath': '/usr/local/bin/python3.13', 'sha256': sha('/opt/deps/bin/python')},
        'root_environment': {'HOME': '/work/home', 'PATH': '/opt/deps/bin:/usr/local/bin:/usr/bin:/bin',
                             'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TMPDIR': '/work/tmp'},
        'endpoint': {'nonce': nonce, 'socket': '/receipts/source.sock', 'requests': '/requests',
                     'responses': '/receipts', 'observer_pid': 1, 'observer_uid': 20001,
                     'sha256': sha(SUPPORT / 'endpoint.py')},
        'direct_support': {'path': str(SUPPORT / 'direct_routes.py'),
                           'files': {str(p): sha(p) for p in sorted(SUPPORT.glob('*.py'))}},
        'copy_git': {p: sha(p) for p in ['/usr/bin/git', '/bin/git']},
        'console_routes': [], 'copied_console_pins': {}, 'cohort_native_pins': {p: sha(p) for p in ['/usr/bin/git','/bin/ps','/bin/sleep']},
        'copy_console': [], 'native_sysctl_offsets': {'system': 'Linux', 'abi': 'proc-stat-start-ticks'},
        'setup_mode': 'source',
        'source_only_support': [str(p) for p in sorted(SUPPORT.glob('*.py'))],
    })
    print(json.dumps({'manifest': manifest, 'registry': registry_text}, sort_keys=True))

if __name__ == '__main__':
    main()
