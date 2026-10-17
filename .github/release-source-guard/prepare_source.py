"""Prepare read-only source inputs without importing project code."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path('/source')
SUPPORT = Path('/guard/finite')
CASES = {
    'ci-mutations': 'tests/test_repository_contract.py',
    'producer-contract': 'tests/contracts/test_lean_provider_security.py::test_installed_supported_provider_matrix',
    'producer-controls': 'tests/test_distribution_check.py::test_checker_builds_and_executes_15_cases_with_extracted_provenance',
    'producer-distribution': 'tests/test_distribution_check.py::test_checker_builds_and_executes_15_cases_with_extracted_provenance',
    'drain-controls': 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct',
    'inprocess': 'tests/test_server.py::test_completion_refusal_survives_server_restart',
    'backend': 'tests/test_controlled_python_acp.py',
    'composed': 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct',
}

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    nonce, selection = sys.argv[1:]
    case = CASES[selection]
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
    if selection in {'composed', 'drain-controls'}:
        source = SUPPORT / 'restart_custody.py'
        function = next(node for node in ast.parse(source.read_bytes()).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'start_custodian')
        target = SUPPORT / 'custody_process.py'
        registry.append({'class': 'restart-custodian', 'python': True, 'argv': [str(target)],
                         'checkout_cwd': False,
                         'source_binding': {'path': str(source), 'line': function.lineno, 'sha256': sha(source)},
                         'source_function': function.name, 'source_function_line': function.lineno,
                         'source_cwd_local': 'work', 'files': {str(target): sha(target)}})
    registry_text = '"""Finite vectors; unavailable platform images cannot match a byte pin."""\nCOMMANDS = ' + repr(registry) + '\n'
    manifest.update({
        'checkout': '/source', 'owned_root': '/work/owned', 'events': '/work/events',
        'source_case': case, 'source_selection': selection, 'scope': 'focused original ' + selection,
        'source_checkpoint_ready': False, 'selected_carrier': None,
        'guard': str(SUPPORT / 'runtime_guard.py'), 'guard_sha256': sha(SUPPORT / 'runtime_guard.py'),
        'registry': {'path': '/inputs/registry.py', 'sha256': hashlib.sha256(registry_text.encode()).hexdigest()},
        'runtime': {'paths': ['/opt/deps/bin/python', '/usr/local/bin/python3.13'],
                    'realpath': '/usr/local/bin/python3.13', 'sha256': sha('/opt/deps/bin/python')},
        'root_environment': {'HOME': '/work/home', 'PATH': ('/native/bin:' if selection == 'backend' else '') + '/opt/deps/bin:/usr/local/bin:/usr/bin:/bin',
                             'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TMPDIR': '/work/tmp'},
        'endpoint': {'nonce': nonce, 'socket': '/receipts/source.sock', 'requests': '/requests',
                     'responses': '/receipts', 'observer_pid': 1, 'observer_uid': 20001,
                     'sha256': sha(SUPPORT / 'endpoint.py')},
        'direct_support': {'path': str(SUPPORT / 'direct_routes.py'),
                           'files': {str(p): sha(p) for p in sorted(SUPPORT.glob('*.py'))}},
        'git_maintenance_sha256': sha('/usr/lib/git-core/git'),
        'copy_git': {p: sha(p) for p in ['/usr/bin/git', '/bin/git']},
        'console_routes': [], 'copied_console_pins': {}, 'cohort_native_pins': {p: sha(p) for p in ['/usr/bin/git','/bin/git','/usr/bin/ps','/bin/ps','/usr/bin/sleep','/bin/sleep']},
        'copy_console': [], 'native_sysctl_offsets': {'system': 'Linux', 'abi': 'proc-stat-start-ticks'},
        'linux_profile_gate': {'path': '/opt/source-guard/profile_gate.so',
                               'sha256': sha('/opt/source-guard/profile_gate.so'),
                               'source_sha256': sha('/guard/profile_gate.c')},
        'setup_mode': 'source',
        'source_only_support': [str(p) for p in sorted(SUPPORT.glob('*.py'))],
    })
    if selection.startswith('producer-'):
        manifest['root_environment'].update({
            'PATH': '/opt/source-bootstrap/bin:' + manifest['root_environment']['PATH'],
            'TMPDIR': '/work/owned/tmp',
            'UV_CACHE_DIR': '/work/producer-cache', 'UV_OFFLINE': '1', 'UV_NO_INDEX': '1',
            'UV_FIND_LINKS': '/opt/source-bootstrap/wheelhouse',
            'UV_PYTHON': '/receipts/producers/selected/bin/python',
            'UV_PYTHON_DOWNLOADS': 'never', 'UV_CONFIG_FILE': '/receipts/producers/uv.toml',
            'PYTHONDONTWRITEBYTECODE': '1', 'SOURCE_DATE_EPOCH': '1700000000',
        })
    if selection == 'drain-controls':
        manifest['integration_mode'] = 'NONCANONICAL-drain-controls'
    print(json.dumps({'manifest': manifest, 'registry': registry_text}, sort_keys=True))

if __name__ == '__main__':
    main()
