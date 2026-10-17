"""Finite stock-UV generated environment validation, never a root exemption."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile
import zipfile

from operation_activation import identity, verify_caches


def wheel_site(wheel: Path, site: Path, virtualenv_source: Path) -> dict:
    """Match all selected wheel bytes and the stock producer's generated files.

    This records actual selected members; publisher authentication is supplied
    separately by the parent's sealed wheel input. Unknown members refuse.
    """
    with zipfile.ZipFile(wheel) as archive:
        payload = {n: archive.read(n) for n in archive.namelist() if not n.endswith('/')}
    records = [n for n in payload if n.endswith('.dist-info/RECORD') and len(Path(n).parts) == 2]
    if len(records) != 1:
        raise RuntimeError('isolated_distribution_cardinality')
    record = records[0]
    dist = str(Path(record).parent)
    generated = {dist + '/INSTALLER': b'uv', dist + '/REQUESTED': b'',
                 '_virtualenv.pth': b'import _virtualenv',
                 '_virtualenv.py': virtualenv_source.read_bytes()}
    ctime = wheel.stat().st_ctime_ns
    generated[dist + '/uv_cache.json'] = json.dumps({
        'timestamp': {'secs_since_epoch': ctime // 1_000_000_000, 'nanos_since_epoch': ctime % 1_000_000_000},
        'commit': None, 'tags': None, 'env': {}, 'directories': {}}, separators=(',', ':')).encode()
    expected = {**payload, **generated}
    observed = {}
    for file in sorted(site.rglob('*')):
        mode = file.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise RuntimeError('isolated_site_special_file')
        relative = file.relative_to(site).as_posix()
        if relative.endswith('.pyc'):
            continue
        observed[relative] = file.read_bytes()
    if set(observed) != set(expected):
        raise RuntimeError('isolated_site_membership:' + ','.join(sorted(set(observed) ^ set(expected))))
    for name, body in expected.items():
        if name != record and observed[name] != body:
            raise RuntimeError('isolated_selected_member_drift:' + name)
    rows = list(csv.reader(io.StringIO(observed[record].decode())))
    actual = {}
    for row in rows:
        if len(row) != 3 or row[0] in actual:
            raise RuntimeError('isolated_record_duplicate_or_shape')
        actual[row[0]] = row[1:]
    # UV emits sorted original entries plus its recorded INSTALLER/REQUESTED.
    names = set(payload) | {dist + '/INSTALLER', dist + '/REQUESTED', dist + '/uv_cache.json'}
    if set(actual) != names or actual[record] != ['', '']:
        raise RuntimeError('isolated_record_membership')
    for name in sorted(names - {record}):
        body = expected[name]
        digest = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b'=').decode()
        if actual[name] != [digest, str(len(body))]:
            raise RuntimeError('isolated_record_member_drift:' + name)
    if [r[0] for r in rows] != sorted(actual):
        raise RuntimeError('isolated_record_order')
    caches = verify_caches(site)
    return {'site': str(site), 'wheel': identity(wheel), 'wheel_members': len(payload),
            'generated': [identity(site / n) for n in sorted(generated)],
            'selected_build_meta': identity(site / 'setuptools/build_meta.py'),
            'caches': caches, 'selection': 'actual_helper_environment',
            'pre_callback_enforcement': False}


def runtime(spec: dict, executable: str) -> dict:
    path = Path(executable)
    prefix = path.parent.parent
    cache = Path(spec['cache']) / 'builds-v0'
    if (prefix.parent != cache or not prefix.name.startswith('.tmp')
            or path.name != 'python' or path.resolve() != Path(spec['base'])
            or not path.is_symlink()):
        raise RuntimeError('isolated_interpreter_route')
    if identity(path.resolve()) != spec['base_identity']:
        raise RuntimeError('isolated_interpreter_bytes')
    expected = ('home = ' + str(Path(spec['base']).parent) + '\n'
                'implementation = CPython\nuv = 0.11.0\nversion_info = 3.13.12\n'
                'include-system-site-packages = false\n')
    if (prefix / 'pyvenv.cfg').read_text() != expected:
        raise RuntimeError('isolated_pyvenv_config')
    return wheel_site(Path(spec['wheel']), prefix / 'lib/python3.13/site-packages',
                      Path(spec['virtualenv_source'])) | {'prefix': str(prefix), 'python_link': str(path)}


def extracted_source(spec: dict, cwd: Path, receipts: list[dict], parent_pid: int) -> dict:
    """Consume the actual in-operation sdist return, not a refreshed snapshot."""
    matched = [r for r in receipts if r['kind'] == 'isolated_backend_output'
               and r['helper'] == 'build_sdist' and r['parent_pid'] == parent_pid]
    if len(matched) != 1:
        raise RuntimeError('isolated_actual_sdist_return_missing')
    archive = Path(matched[0]['artifact']['path'])
    if identity(archive) != matched[0]['artifact']:
        raise RuntimeError('isolated_actual_sdist_output_drift')
    if (cwd.parent.parent != Path(spec['cache']) / 'sdists-v9'
            or not cwd.parent.name.startswith('.tmp') or cwd.resolve() != cwd):
        raise RuntimeError('isolated_extracted_root_lineage')
    expected = {}
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream.getmembers():
            parts = Path(member.name).parts
            if (not parts or parts[0] != cwd.name or '..' in parts or Path(member.name).is_absolute()
                    or not (member.isfile() or member.isdir())):
                raise RuntimeError('isolated_sdist_member_class')
            if member.isfile():
                reader = stream.extractfile(member)
                if reader is None:
                    raise RuntimeError('isolated_sdist_missing_body')
                name = Path(*parts[1:]).as_posix()
                if name in expected:
                    raise RuntimeError('isolated_sdist_duplicate')
                expected[name] = reader.read()
    if spec.get('original_source_coverage'):
        originals = {str(Path(v['path']).relative_to(spec['project'])): v['sha256']
                     for v in spec['source_files']}
        for name, body in expected.items():
            if name.endswith('.py') or name == 'pyproject.toml':
                if originals.get(name) != hashlib.sha256(body).hexdigest():
                    raise RuntimeError('source_sdist_unbound_executable_member:' + name)
    else:
        for name in ['pyproject.toml', 'sample.py']:
            if expected.get(name) != (Path(spec['project']) / name).read_bytes():
                raise RuntimeError('isolated_sdist_original_input_drift')
        if any(n.endswith('.py') and n != 'sample.py' for n in expected):
            raise RuntimeError('isolated_sdist_unknown_executable_source')
    observed = {}
    for file in sorted(cwd.rglob('*')):
        if file.is_dir():
            continue
        item = identity(file)
        observed[file.relative_to(cwd).as_posix()] = item
    mutations = [r for r in receipts if r['kind'] == 'isolated_extraction_mutation'
                 and r['parent_pid'] == parent_pid and r['root'] == str(cwd)]
    if mutations:
        if len(mutations) != 1 or {v['path']: v for v in mutations[0]['files']} != {v['path']: v for v in observed.values()}:
            raise RuntimeError('isolated_admitted_extraction_mutation_drift')
        expected = admitted_egg_info(expected, cwd)
    if set(observed) != set(expected) or any(observed[n]['sha256'] != hashlib.sha256(expected[n]).hexdigest() for n in observed):
        raise RuntimeError('isolated_extracted_member_drift')
    return {'actual_sdist': matched[0]['artifact'], 'extracted_root': str(cwd),
            'members': [observed[n] for n in sorted(observed)], 'functional_archive_pass': False}


def admitted_egg_info(expected: dict, cwd: Path) -> dict:
    """The selected get-requires hook adds setup.cfg to its text-only manifest.

    All other extracted payload stays byte exact; this cannot admit executable
    output or a callback supplied tree. The actual hook return is separately
    required by the caller before recording this one mutation.
    """
    names = [n for n in expected if n.endswith('.egg-info/SOURCES.txt')]
    if len(names) != 1:
        raise RuntimeError('isolated_manifest_cardinality')
    name = names[0]
    old = expected[name].decode().splitlines()
    if 'setup.cfg' in old:
        raise RuntimeError('isolated_unexpected_existing_setup_manifest')
    # Setuptools' sdist-generated setup.cfg is added by egg_info's sorted
    # manifest writer; only this text addition is admitted.
    index = next((i for i,n in enumerate(old) if n > 'setup.cfg'), len(old))
    old.insert(index, 'setup.cfg')
    changed = {**expected, name: '\n'.join(old).encode()}
    for relative, body in changed.items():
        if (cwd / relative).read_bytes() != body:
            raise RuntimeError('isolated_unregistered_egg_info_mutation:' + relative)
    return changed


def record_egg_info_mutation(spec: dict, cwd: Path, receipts: list[dict], parent_pid: int) -> list[dict]:
    matches = [r for r in receipts if r['kind'] == 'isolated_backend_output'
               and r['helper'] == 'build_sdist' and r['parent_pid'] == parent_pid]
    if len(matches) != 1:
        raise RuntimeError('isolated_mutation_sdist_owner_missing')
    archive = Path(matches[0]['artifact']['path'])
    if identity(archive) != matches[0]['artifact']:
        raise RuntimeError('isolated_mutation_sdist_drift')
    expected = {}
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream.getmembers():
            if member.isfile():
                reader = stream.extractfile(member)
                if reader is None:
                    raise RuntimeError('isolated_mutation_missing_member')
                expected[Path(*Path(member.name).parts[1:]).as_posix()] = reader.read()
    admitted_egg_info(expected, cwd)
    files = [identity(p) for p in sorted(cwd.rglob('*')) if not p.is_dir()]
    if len(files) != len(expected):
        raise RuntimeError('isolated_mutation_membership_drift')
    return files
