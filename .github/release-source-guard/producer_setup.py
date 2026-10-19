"""Finite source-compartment setup; source never receives coordinator authority."""
from __future__ import annotations

import hashlib
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil

ROOT = Path('/receipts/producers')
CACHE = Path('/work/producer-cache')
BASE = Path('/usr/local/bin/python-source-audit')
WHEEL = Path('/opt/source-bootstrap/wheelhouse/setuptools-84.0.0-py3-none-any.whl')


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    body = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    with Path(path).open('xb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    Path(path).chmod(0o444)
    return hashlib.sha256(body).hexdigest()


def source_child_setup(*, primary=False):
    if os.getuid() != 20000 or CACHE.exists():
        raise RuntimeError('fresh unprivileged producer setup required')
    (Path('/work/owned') / 'tmp').mkdir(mode=0o700)
    try:
        descriptor = os.open('/source/pyproject.toml', os.O_WRONLY | os.O_NOFOLLOW)
    except OSError as error:
        if error.errno not in (errno.EROFS, errno.EACCES):
            raise
        source_denial = error.errno
    else:
        os.close(descriptor)
        raise RuntimeError('candidate source entry is writable')
    canary = Path('/source/.source-artifact-directory-canary')
    canary.mkdir()
    canary.rmdir()
    Path('/work/producer-setup-controls.json').write_text(json.dumps({
        'candidate_write_errno': source_denial, 'artifact_directory_create_remove': True,
        'source_uid': os.getuid(), 'source_checkpoint_ready': False}, sort_keys=True))
    if primary:
        return
    seed = Path('/opt/source-bootstrap/cache')
    CACHE.mkdir(mode=0o700)
    # Preserve native-produced file bytes. Only the finite cache-root prefix of
    # internal archive links changes when making the writable source copy.
    for path in sorted(seed.rglob('*')):
        target = CACHE / path.relative_to(seed)
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(seed) or not resolved.is_dir():
                raise RuntimeError('seed cache link is not an internal native archive')
            target.symlink_to(CACHE / resolved.relative_to(seed))
        elif path.is_dir():
            target.mkdir(mode=path.stat().st_mode & 0o777)
        elif path.is_file():
            shutil.copy2(path, target)
        else:
            raise RuntimeError('unknown seed cache member type')


def prepare(manifest, input_pin):
    if os.getuid() != 20001 or ROOT.exists():
        raise RuntimeError('fresh observer-owned producer inputs required')
    ROOT.mkdir(mode=0o755)
    (Path('/receipts') / 'native-startup').mkdir(mode=0o755)
    setup_controls = json.loads(Path('/work/producer-setup-controls.json').read_bytes())
    if (setup_controls['source_uid'] != 20000
            or setup_controls['candidate_write_errno'] not in (errno.EROFS, errno.EACCES)
            or setup_controls['artifact_directory_create_remove'] is not True):
        raise RuntimeError('producer source view controls did not close')
    write(ROOT / 'setup-controls.json', setup_controls)
    selected = ROOT / 'selected'
    (selected / 'bin').mkdir(parents=True, mode=0o755)
    site = selected / 'lib/python3.13/site-packages'
    site.mkdir(parents=True, mode=0o755)
    python = selected / 'bin/python'
    primary = manifest['source_selection'] == 'primary-source'
    base = Path('/usr/local/bin/python-primary-audit') if primary else BASE
    python.symlink_to(base)
    config = selected / 'pyvenv.cfg'
    config.write_text('home = /usr/local/bin\nimplementation = CPython\n'
                      'version_info = 3.13.12\ninclude-system-site-packages = false\n')
    config.chmod(0o444)
    uv_config = ROOT / 'uv.toml'
    uv_config.write_bytes(b'')
    uv_config.chmod(0o444)
    cache = Path('/work/cache') if primary else CACHE
    if primary and (manifest['runtime']['realpath'] != str(base)
                    or manifest['runtime']['sha256'] != digest(base)):
        raise RuntimeError('primary producer runtime setup drift')
    operations = load('source_operations_setup', '/guard/finite/source_operations.py')
    activation = load('operation_activation_setup', '/guard/finite/operation_activation.py')
    closure = load('dependency_closure_setup', '/guard/dependency_closure.py')
    seed = Path('/opt/primary-cache') if primary else Path('/opt/source-bootstrap/cache')
    expected_cache = closure.inventory(seed)
    actual_cache = closure.inventory(cache)
    for name, value in expected_cache.items():
        if value['type'] == 'symlink':
            target = (seed / name).resolve(strict=True)
            if not target.is_relative_to(seed) or not target.is_dir():
                raise RuntimeError('native seed link does not name an internal archive')
            value['target'] = str(cache / target.relative_to(seed))
    if actual_cache != expected_cache:
        raise RuntimeError('source cache differs from its finite native-produced seed')
    source_files = [operations.identity(Path('/source') / name)
                    for name in sorted(manifest['product_pins'])
                    if not name.startswith('src/unrest_harness.egg-info/')]
    backend = {'wheel': activation.identity(WHEEL),
               'publisher_sha256': digest(WHEEL), 'backend': 'setuptools.build_meta',
               'requirement': 'setuptools>=77',
               'selection': 'offline/no-index sole byte-authenticated public wheel'}
    dependency_site = Path('/opt/deps/lib/python3.13/site-packages')
    stock = Path('/opt/deps/bin/python')
    common = {
        'native_preinit': True, 'guarded': True, 'root': str(ROOT),
        'project': '/source', 'events': manifest['events'], 'cache': str(cache),
        'base': str(base), 'base_identity': activation.identity(base),
        'wheel': str(WHEEL), 'virtualenv_source': '/opt/source-bootstrap/upstream/_virtualenv.py',
        'query_python': str(base if primary else python), 'full_build': True, 'original_source_coverage': True,
        'source_files': source_files, 'backend_distribution': backend,
        'uv': activation.identity('/opt/source-bootstrap/bin/uv'),
        'files': [activation.identity(path) for path in sorted([
            base, WHEEL, config, uv_config, Path('/opt/source-bootstrap/bin/uv'),
            Path('/guard/finite/source_activation.py'), Path('/guard/finite/source_integration_activation.py'),
            Path('/guard/finite/isolated_inputs.py'),
            Path('/guard/finite/isolated_activation.py')])],
        'trees': {str(path): activation.tree(path)
                  for path in (site, Path('/opt/source-bootstrap/upstream'))},
        'shared_files': [activation.identity(path) for path in (
            Path('/opt/deps/pyvenv.cfg'), stock.resolve(), base,
            Path('/usr/local/lib/libpython3.13.so.1.0'), config)],
        'shared_trees': {str(path): activation.tree(path)
                         for path in ((Path('/usr/local/lib/python3.13'),) if primary else
                                      (dependency_site, Path('/usr/local/lib/python3.13')))},
        'shared_absent': ['/opt/deps/bin/pyvenv.cfg', '/opt/deps/lib/python313.zip',
                          '/usr/local/bin/pyvenv.cfg', '/usr/local/pyvenv.cfg',
                          str(selected / 'bin/pyvenv.cfg')],
        'shared_python_link': {'path': str(stock), 'target': str(stock.resolve()),
                               'inode': stock.lstat().st_ino},
    }
    if primary:
        import primary_dependency
        common['primary_producer'] = {
            'entry': activation.identity(base),
            'bootstrap': activation.identity('/guard/primary_entry.py'),
            'consumer': activation.identity('/guard/native_entry.py'),
            'cache_support': activation.identity('/guard/producer_profile.py'),
            'cache_seed_inventory': closure.inventory(Path('/opt/primary-cache')),
            'dependency_support': {
                'path': '/guard/primary_dependency.py', 'sha256': digest('/guard/primary_dependency.py'),
                'outputs_sha256': digest('/guard/producer_outputs.py')},
            'source_custody': {str(path): primary_dependency.key(path.lstat())
                               for path in [Path('/source/src'),
                                            *(Path(row['path']) for row in source_files)]},
        }
    common_path = ROOT / 'common.json'
    common_pin = write(common_path, common)
    operation_spec = {
        'files': source_files, 'trees': [] if primary else [operations.tree_identity(dependency_site)],
        'uv': operations.identity('/opt/source-bootstrap/bin/uv'),
        'backend_distribution': backend,
        'mapping_support': {'path': '/guard/finite/installed_outputs.py',
                            'sha256': digest('/guard/finite/installed_outputs.py')},
        'installed_interpreter': {'path': common['query_python'], 'file': operations.identity(base),
                                  'link_inode': python.lstat().st_ino,
                                  **({'route_path': str(python)} if primary else {})},
    }
    if primary:
        operation_spec['primary_dependency_diagnostic'] = {
            'path': '/guard/producer_profile.py', 'sha256': digest('/guard/producer_profile.py')}
    operation_path = ROOT / 'operations.json'
    operation_pin = write(operation_path, operation_spec)
    activation_path = ROOT / 'activation.json'
    activation_pin = write(activation_path, {'profiles': []})
    manifest.update({
        'input_manifest_sha256': input_pin,
        'operation_support': {'path': '/guard/finite/source_operations.py',
                              'sha256': digest('/guard/finite/source_operations.py'),
                              'spec_path': str(operation_path), 'spec_sha256': operation_pin},
        'activation_support': {'path': '/guard/finite/operation_activation.py',
                               'sha256': digest('/guard/finite/operation_activation.py'),
                               'spec_path': str(activation_path), 'spec_sha256': activation_pin},
        'isolated_support': {'path': '/guard/finite/isolated_activation.py',
                             'sha256': digest('/guard/finite/isolated_activation.py'),
                             'inputs_path': '/guard/finite/isolated_inputs.py',
                             'inputs_sha256': digest('/guard/finite/isolated_inputs.py'),
                             'spec_path': str(common_path), 'spec_sha256': common_pin},
        'source_activation_support': {'path': '/guard/finite/source_integration_activation.py',
                                      'sha256': digest('/guard/finite/source_integration_activation.py')},
        'native_producer_support': {'path': str(common_path), 'sha256': common_pin,
                                    'profile_support_sha256': digest('/guard/producer_profile.py')},
    })
    derived = Path('/receipts/source.json')
    pin = write(derived, manifest)
    return derived, pin, common
