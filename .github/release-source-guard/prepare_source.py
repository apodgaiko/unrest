"""Prepare read-only source inputs without importing project code."""
from __future__ import annotations
import ast
import hashlib
import json
import os
import stat
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

def admit_clock(manifest):
    path = Path('/guard/clock_source_inputs.py')
    before = path.lstat()
    def key(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o644
            or before.st_nlink != 1 or path.resolve(strict=True) != path
            or not os.statvfs(path).f_flag & os.ST_RDONLY):
        raise RuntimeError('clock_support_custody')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if key(os.fstat(descriptor)) != key(before):
            raise RuntimeError('clock_support_open_race')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(65537)
        if (len(body) != before.st_size or len(body) > 65536
                or key(os.fstat(descriptor)) != key(before) or key(path.lstat()) != key(before)
                or hashlib.sha256(body).hexdigest() != '4637ca4915c16acfe5caa54c6b34a134c53e1ed76979b3a6971563e98b96a144'):
            raise RuntimeError('clock_support_byte_drift')
    finally:
        os.close(descriptor)
    namespace = {'__file__': str(path), '__name__': 'clock_source_inputs'}
    exec(compile(body, str(path), 'exec', dont_inherit=True), namespace)
    namespace['admit'](manifest, ROOT)
    global CLOCK_READER
    CLOCK_READER = namespace['read']


def admit_ownership_document(manifest):
    # The acquisition repair changed this canonical document with its two
    # owners. Retain the old oracle; admit only that exact reviewed composition.
    name = 'docs/architecture/experimental-lease.md'
    if manifest['product_pins'].get(name) != '39850b53b447a0dd6b9be5e37ec7cfea4deabc0571a929ee8f6a91acd8484d14':
        raise RuntimeError('ownership_document_preimage')
    pin = '43a6baeaf6e971be1ce879c81626f206df68ad709add71eea2471bfd8ac5462f'
    if hashlib.sha256(CLOCK_READER(ROOT, name)).hexdigest() != pin:
        raise RuntimeError('ownership_document_postimage')
    for owner, expected in {
        'src/unrest_harness/experimental_lease.py': 'b5989f7e1f151400ba6bba01d2e7984430657bc2b072cfb193deb86739f8cecb',
        'src/unrest_harness/experimental_session.py': '7a3df1d049cd8a72aac48bc376154f7701335397ad8a0e0634cf2d0a9509cbd2',
    }.items():
        if (manifest['product_pins'].get(owner) != expected
                or hashlib.sha256(CLOCK_READER(ROOT, owner)).hexdigest() != expected):
            raise RuntimeError('ownership_document_engine')
    manifest['product_pins'][name] = pin


def admit_tracker_acquisition(manifest):
    name = 'tests/multiprocess_lifetime.py'
    if manifest['product_pins'].get(name) != 'e992a1dd5575250cea540ccb52c42f54dca28ec87cf2843e13c11237d9a291d3':
        raise RuntimeError('tracker_acquisition_preimage')
    pin = 'ec9139b91f766ec4fb05f7c2ade84801a6f99de1475ffa15c676bf00becb5b54'
    if hashlib.sha256(CLOCK_READER(ROOT, name)).hexdigest() != pin:
        raise RuntimeError('tracker_acquisition_postimage')
    manifest['product_pins'][name] = pin


def admit_candidate_template(manifest):
    body = CLOCK_READER(Path('/guard'), 'candidate_template_source_inputs.py')
    if hashlib.sha256(body).hexdigest() != '0a10e29619137a6dfbfeac7655f02b6503f15932c60961adbe4c8264affbde78':
        raise RuntimeError('candidate_template_support_drift')
    namespace = {'__name__': 'candidate_template_source_inputs'}
    exec(compile(body, '/guard/candidate_template_source_inputs.py', 'exec', dont_inherit=True), namespace)
    namespace['admit'](manifest, ROOT, CLOCK_READER)


def main():
    nonce, selection = sys.argv[1:]
    case = CASES[selection]
    if len(nonce) != 64 or any(c not in '0123456789abcdef' for c in nonce):
        raise RuntimeError('invalid source epoch')
    manifest = json.loads((SUPPORT / 'source-template.json').read_bytes())
    admit_clock(manifest)
    release_body = CLOCK_READER(Path('/guard'), 'release_source_inputs.py')
    if hashlib.sha256(release_body).hexdigest() != '411620d745783ba7fd2064f537823747e7561e61d2126dd938ac3b8b4531d877':
        raise RuntimeError('release_identity_support_drift')
    release = {'__name__': 'release_source_inputs'}
    exec(compile(release_body, '/guard/release_source_inputs.py', 'exec', dont_inherit=True), release)
    release['admit'](manifest, ROOT, CLOCK_READER)
    admit_ownership_document(manifest)
    admit_tracker_acquisition(manifest)
    admit_candidate_template(manifest)
    for name, pin in manifest['product_pins'].items():
        observed = sha(ROOT / name)
        if observed != pin:
            if not (name.startswith('.github/') or name in {
                'docs/release/lean-core-v0.4.6.md',
                'docs/release/v046-source-checkpoint-environment.md',
            }):
                raise RuntimeError('original source baseline drift: ' + name)
            manifest['product_pins'][name] = observed
    manifest['product_pins']['.github/release-source-guard/nested_owner_methods.py'] = sha(
        ROOT / '.github/release-source-guard/nested_owner_methods.py')
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
    if selection == 'ci-mutations':
        manifest['copied_console_pins'] = {'unrest': sha('/opt/deps/bin/unrest')}
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
    try:
        main()
    except BaseException as error:
        from runpy import run_path
        failure = run_path('/guard/preparation_diagnostics.py')['failure']
        print(json.dumps(failure(error), sort_keys=True), file=sys.stderr)
        raise SystemExit(125) from None
