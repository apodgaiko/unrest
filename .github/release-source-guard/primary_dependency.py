"""Observer-owned derivation of the original PRIMARY bootstrap dependency site.

This domain is deliberately separate from the standalone /opt/deps inventory.
Only the immutable image and the byte-bound original bootstrap produce inputs.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import zipfile

SITE = Path('/source/.venv/lib/python3.13/site-packages')
SOURCE_ROOT = Path('/source')
IMAGE = Path('/opt/primary-deps/lib/python3.13/site-packages')
RECEIPTS = Path('/receipts/producers')
DIST = 'unrest_harness-0.4.6.dist-info'
PTH = '__editable__.unrest_harness-0.4.6.pth'
WHEEL_NAME = 'unrest_harness-0.4.6-0.editable-py3-none-any.whl'
LIMIT = 64 * 1024 * 1024


def sha(body):
    return hashlib.sha256(body).hexdigest()


def decode(body):
    def unique(pairs):
        value = {}
        for name, item in pairs:
            if name in value:
                raise RuntimeError('primary_dependency_duplicate_field')
            value[name] = item
        return value
    return json.loads(body, object_pairs_hook=unique)


def key(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def read(path, uid, gid=None):
    pathname = os.fspath(path)
    if type(pathname) is not str:
        raise RuntimeError('primary_dependency_path_type')
    before = os.stat(pathname, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid
            or before.st_gid != (uid if gid is None else gid) or not 0 <= before.st_size <= LIMIT):
        raise RuntimeError('primary_dependency_file_custody')
    descriptor = os.open(pathname, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if key(os.fstat(descriptor)) != key(before):
            raise RuntimeError('primary_dependency_open_race')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(LIMIT + 1)
        if (len(body) != before.st_size or key(os.fstat(descriptor)) != key(before)
                or key(os.stat(pathname, follow_symlinks=False)) != key(before)):
            raise RuntimeError('primary_dependency_read_race')
    finally:
        os.close(descriptor)
    return body, {'path': pathname, 'identity': key(before), 'sha256': sha(body)}


def wheel_payload(body):
    from producer_outputs import record_hash, record_rows
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        names = archive.namelist()
        wanted = {PTH, *(DIST + '/' + name for name in (
            'METADATA', 'WHEEL', 'RECORD', 'entry_points.txt', 'top_level.txt',
            'licenses/LICENSE', 'licenses/NOTICE'))}
        if (len(names) != len(set(names)) or set(names) != wanted
                or sum(item.file_size for item in archive.infolist()) > 2 * LIMIT
                or any(item.file_size > LIMIT or item.flag_bits & 1
                       or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG)
                       for item in archive.infolist())):
            raise RuntimeError('primary_dependency_editable_wheel_members')
        payload = {name: archive.read(name) for name in sorted(names)}
    if payload[PTH] != b'/source/src\n':
        raise RuntimeError('primary_dependency_editable_pth')
    record = DIST + '/RECORD'
    rows = record_rows(payload[record], record)
    if set(rows) != set(payload):
        raise RuntimeError('primary_dependency_editable_record_members')
    if any(rows[name] != record_hash(value) for name, value in payload.items() if name != record):
        raise RuntimeError('primary_dependency_editable_record_bytes')
    return payload


def capture(owner, trace):
    """Read before the tracer reaps the child and permits UV's real wait.

    PTRACE_EVENT_EXIT precedes the tracer's terminal wait. The real UV parent
    cannot retire this response until the tracer has made that wait available.
    This is provisional evidence; seal() requires the later numeric UV wait.
    """
    from finite.linux_identity import identity
    from primary_policy import backend_request
    from producer_setup import write

    captures = getattr(owner, 'bootstrap_outputs', None)
    if captures is None:
        captures = owner.bootstrap_outputs = {}
    for event_index, event in enumerate(trace.records):
        pid = event.get('pid')
        context = owner.contexts.get(pid)
        if (event['kind'] != 'kernel_exit' or context is None
                or context['role'] != 'editable_backend' or pid in captures):
            continue
        if event['raw'] != 0 or trace.poison or identity(pid) != context['identity']:
            raise RuntimeError('primary_dependency_bootstrap_exit')
        if any(row['kind'] == 'tracer_terminal_wait' and row['pid'] == pid
               or row['kind'] in {'original_parent_wait4', 'original_parent_waitid'}
               and row.get('child') == pid for row in trace.records):
            raise RuntimeError('primary_dependency_bootstrap_capture_late')
        path = Path('/receipts/primary-startup') / (str(pid) + '.json')
        header_body, header_file = read(path, 20001)
        if path.stat().st_nlink != 1 or stat.S_IMODE(path.stat().st_mode) != 0o444:
            raise RuntimeError('primary_dependency_bootstrap_profile_custody')
        header = decode(header_body)
        actual = context['identity']
        if (header['pid'] != pid or header['parent'] != actual['ppid']
                or header['start_ticks'] != actual['start_ticks']
                or header['boot_id'] != actual['boot_id'] or header['cwd'] != '/source'
                or header['flags'] != [0, 0, 1]):
            raise RuntimeError('primary_dependency_bootstrap_profile')
        script = header['orig_argv'][-1]
        helper = backend_request(script)
        if helper not in {'get_requires_for_build_editable', 'build_editable'}:
            raise RuntimeError('primary_dependency_bootstrap_helper')
        nodes = ast.parse(script).body
        response = Path(nodes[-1].items[0].context_expr.args[0].value)
        result, response_file = read(response, 20000)
        row = {'pid': pid, 'helper': helper, 'identity': actual,
               'profile_sha256': header_file['sha256'], 'response': response_file,
               'kernel_exit_raw': 0, 'provisional': True,
               'kernel_exit_index': event_index, 'capture_record_count': len(trace.records)}
        if helper == 'get_requires_for_build_editable':
            if result != b'[]':
                raise RuntimeError('primary_dependency_bootstrap_requirements')
        else:
            if result != WHEEL_NAME.encode():
                raise RuntimeError('primary_dependency_bootstrap_wheel_name')
            call = next(node for node in ast.walk(ast.parse(script)) if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute) and node.func.attr == 'build_editable')
            wheel = Path(call.args[0].value) / WHEEL_NAME
            body, wheel_file = read(wheel, 20000)
            wheel_payload(body)
            retained = RECEIPTS / ('editable-' + str(pid) + '.whl')
            with retained.open('xb') as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            retained.chmod(0o444)
            row.update(wheel=wheel_file, retained_wheel=read(retained, 20001)[1])
        receipt = RECEIPTS / ('bootstrap-response-' + str(pid) + '.json')
        row['receipt_sha256'] = write(receipt, row)
        captures[pid] = row


def source_cache_info(source_files, source_custody):
    """UV0.11.0's default Unix CacheInfo, from immutable source inputs."""
    import tomllib
    import ctypes
    expected = {row['path']: row for row in source_files}
    def source_read(path):
        info = Path(path).lstat()
        if Path(path).resolve(strict=True) != Path(path) or not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise RuntimeError('primary_dependency_source_not_readonly')
        body, observed = read(path, info.st_uid, info.st_gid)
        if (str(path) not in expected or observed['sha256'] != expected[str(path)]['sha256']
                or observed['identity'] != source_custody[str(path)]):
            raise RuntimeError('primary_dependency_source_input')
        return body, observed
    project, _ = source_read(SOURCE_ROOT / 'pyproject.toml')
    settings = tomllib.loads(project.decode()).get('tool', {}).get('uv', {})
    if settings.get('cache-keys') is not None:
        raise RuntimeError('primary_dependency_custom_cache_keys')
    stamps = []
    for name in ('pyproject.toml', 'setup.py', 'setup.cfg'):
        path = SOURCE_ROOT / name
        if path.exists():
            _, observed = source_read(path)
            stamps.append(observed['identity'][-1])
        elif path.is_symlink():
            raise RuntimeError('primary_dependency_cache_key_link')
    src = SOURCE_ROOT / 'src'
    before = src.lstat()
    if (not stat.S_ISDIR(before.st_mode) or src.resolve() != src
            or not os.statvfs(src).f_flag & os.ST_RDONLY
            or key(before) != source_custody[str(src)]):
        raise RuntimeError('primary_dependency_source_directory')
    # Match Rust Metadata::created on the required x86_64 Linux statx ABI.
    if sys.platform != 'linux' or os.uname().machine != 'x86_64':
        raise RuntimeError('primary_dependency_statx_abi')
    libc = ctypes.CDLL(None, use_errno=True)
    buffer = ctypes.create_string_buffer(256)
    if libc.statx(-100, os.fsencode(src), 0, 0xFFF, buffer) != 0:
        raise RuntimeError('primary_dependency_statx')
    mask = struct.unpack_from('=I', buffer.raw, 0)[0]
    inode = struct.unpack_from('=Q', buffer.raw, 32)[0]
    if inode != before.st_ino or key(src.lstat()) != key(before):
        raise RuntimeError('primary_dependency_statx_race')
    if mask & 0x800:
        seconds, nanos = struct.unpack_from('=qI', buffer.raw, 80)
        directory = {'secs_since_epoch': seconds, 'nanos_since_epoch': nanos}
    else:
        directory = inode
    timestamp = max(stamps)
    return {'timestamp': {'secs_since_epoch': timestamp // 1_000_000_000,
                          'nanos_since_epoch': timestamp % 1_000_000_000},
            'commit': None, 'tags': None, 'env': {}, 'directories': {'src': directory}}


def verify_source_inputs(files, custody):
    fields = {'path', 'device', 'inode', 'size', 'mode', 'mtime_ns', 'ctime_ns', 'sha256'}
    if (type(files) is not list or any(type(row) is not dict or set(row) != fields for row in files)
            or len({row['path'] for row in files}) != len(files)
            or [row['path'] for row in files] != sorted(row['path'] for row in files)):
        raise RuntimeError('primary_dependency_source_schema')
    if set(custody) != {str(SOURCE_ROOT / 'src'), *(row['path'] for row in files)}:
        raise RuntimeError('primary_dependency_source_custody_membership')
    if key((SOURCE_ROOT / 'src').lstat()) != custody[str(SOURCE_ROOT / 'src')]:
        raise RuntimeError('primary_dependency_source_directory_drift')
    for row in files:
        path = Path(row['path'])
        if (not path.is_relative_to(SOURCE_ROOT) or '..' in path.parts
                or path.resolve(strict=True) != path):
            raise RuntimeError('primary_dependency_source_scope')
        expected = custody[row['path']]
        if (type(expected) is not list or len(expected) != 9
                or any(type(field) is not int for field in expected)
                or any(row[name] != expected[index] for name, index in (
                    ('device', 0), ('inode', 1), ('mode', 2), ('size', 6),
                    ('mtime_ns', 7), ('ctime_ns', 8)))):
            raise RuntimeError('primary_dependency_source_identity_binding')
        if not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise RuntimeError('primary_dependency_source_writable')
        _, current = read(path, expected[3], expected[4])
        if current['identity'] != expected or current['sha256'] != row['sha256']:
            raise RuntimeError('primary_dependency_source_drift')


def validate_bootstrap(value):
    producers = value['bootstrap']
    fields = {'pid', 'role', 'parent_wait_raw', 'identity_sha256', 'profile_sha256'}
    def digest(item):
        return type(item) is str and len(item) == 64 and not set(item) - set('0123456789abcdef')
    if (type(producers) is not list or len(producers) != 3
            or any(type(row) is not dict or set(row) != fields for row in producers)
            or sorted(row['role'] for row in producers) != ['editable_backend', 'editable_backend', 'query']
            or any(type(row['pid']) is not int or row['pid'] <= 0
                   or type(row['parent_wait_raw']) is not int or row['parent_wait_raw'] != 0
                   or not all(digest(row[name]) for name in ('identity_sha256', 'profile_sha256'))
                   for row in producers)
            or len({row['pid'] for row in producers}) != 3):
        raise RuntimeError('primary_dependency_bootstrap_schema')
    captures = value['bootstrap_captures']
    by_pid = {row['pid']: row for row in producers if row['role'] == 'editable_backend'}
    if type(captures) is not list or len(captures) != 2:
        raise RuntimeError('primary_dependency_capture_schema')
    seen = set()
    helpers = set()
    for row in captures:
        common = {'pid', 'helper', 'identity', 'profile_sha256', 'response', 'kernel_exit_raw',
                  'provisional', 'kernel_exit_index', 'capture_record_count', 'receipt_sha256'}
        helper = row.get('helper')
        expected = common | ({'wheel', 'retained_wheel'} if helper == 'build_editable' else set())
        pid = row.get('pid')
        if (set(row) != expected or pid not in by_pid or pid in seen
                or helper not in {'build_editable', 'get_requires_for_build_editable'}
                or helper in helpers or row['provisional'] is not True
                or type(row['kernel_exit_raw']) is not int or row['kernel_exit_raw'] != 0
                or type(row['kernel_exit_index']) is not int or row['kernel_exit_index'] < 0
                or type(row['capture_record_count']) is not int
                or row['capture_record_count'] <= row['kernel_exit_index']
                or row['profile_sha256'] != by_pid[pid]['profile_sha256']
                or not digest(row['receipt_sha256'])):
            raise RuntimeError('primary_dependency_capture_binding')
        identity = row['identity']
        names = {'pid', 'ppid', 'pgid', 'sid', 'uid', 'start_ticks', 'clock_ticks_per_second', 'boot_id'}
        if (set(identity) != names or identity['pid'] != pid or identity['uid'] != 20000
                or any(type(identity[name]) is not int or identity[name] <= 0
                       for name in names - {'boot_id'})
                or type(identity['boot_id']) is not str or not identity['boot_id']
                or sha(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode())
                != by_pid[pid]['identity_sha256']):
            raise RuntimeError('primary_dependency_capture_birth')
        response = row['response']
        expected_body = b'[]' if helper.startswith('get_requires') else WHEEL_NAME.encode()
        path = Path(response['path'])
        file = response['identity']
        if (set(response) != {'path', 'identity', 'sha256'}
                or path.name != helper + '.txt' or path.parent.parent != Path('/work/cache/builds-v0')
                or not path.parent.name.startswith('.tmp') or '..' in path.parts
                or type(file) is not list or len(file) != 9
                or any(type(field) is not int for field in file)
                or not stat.S_ISREG(file[2]) or stat.S_IMODE(file[2]) != 0o644
                or file[3:6] != [20000, 20000, 1] or file[6] != len(expected_body)
                or response['sha256'] != sha(expected_body)):
            raise RuntimeError('primary_dependency_capture_response')
        if helper == 'build_editable':
            wheel = row['wheel']
            retained = row['retained_wheel']
            if (set(wheel) != {'path', 'identity', 'sha256'}
                    or Path(wheel['path']).name != WHEEL_NAME
                    or not Path(wheel['path']).is_relative_to('/work/cache')
                    or '..' in Path(wheel['path']).parts or not digest(wheel['sha256'])
                    or set(retained) != {'path', 'identity', 'sha256'} or retained['sha256'] != wheel['sha256']
                    or retained['path'] != str(RECEIPTS / ('editable-' + str(pid) + '.whl'))
                    or retained != value['wheel']):
                raise RuntimeError('primary_dependency_capture_wheel')
            for file, uid, mode in ((wheel, 20000, 0o644), (retained, 20001, 0o444)):
                identity = file['identity']
                if (type(identity) is not list or len(identity) != 9
                        or any(type(field) is not int for field in identity)
                        or not stat.S_ISREG(identity[2]) or stat.S_IMODE(identity[2]) != mode
                        or identity[3:6] != [uid, uid, 1] or not 0 < identity[6] <= LIMIT):
                    raise RuntimeError('primary_dependency_capture_wheel_custody')
        seen.add(pid)
        helpers.add(helper)


def image_projection():
    """Remove only the separately seeded backend; relocate complete manifests."""
    from producer_inputs import SETUPTOOLS_SHA256
    from producer_outputs import record_rows, relocate_record
    backend, _ = read('/opt/source-bootstrap/wheelhouse/setuptools-84.0.0-py3-none-any.whl', 0)
    if sha(backend) != SETUPTOOLS_SHA256:
        raise RuntimeError('primary_dependency_backend_pin')
    with zipfile.ZipFile(io.BytesIO(backend)) as archive:
        omitted = {name for name in archive.namelist() if not name.endswith('/')}
    omitted.update('setuptools-84.0.0.dist-info/' + name
                   for name in ('INSTALLER', 'REQUESTED', 'uv_cache.json'))
    image = {}
    modes = {}
    for path in sorted(IMAGE.rglob('*')):
        if path.is_dir() and not path.is_symlink():
            continue
        body, observed = read(path, 0)
        name = path.relative_to(IMAGE).as_posix()
        image[name], modes[name] = body, stat.S_IMODE(observed['identity'][2])
    if not omitted <= image.keys():
        raise RuntimeError('primary_dependency_backend_members')
    expected = {name: body for name, body in image.items() if name not in omitted}
    scripts = {}
    for name in sorted(expected):
        if not name.endswith('.dist-info/RECORD'):
            continue
        rows = record_rows(expected[name], name)
        for member in rows:
            if member.startswith('../../../bin/'):
                body, _ = read(IMAGE / member, 0)
                scripts[member] = body
        expected[name] = relocate_record(expected[name], name, image, scripts,
                                         '/opt/primary-deps/bin/python', '/source/.venv/bin/python')
    script_outputs = {}
    for name, body in scripts.items():
        path = IMAGE / name
        _, observed = read(path, 0)
        source_header = b'#!/opt/primary-deps/bin/python\n'
        target = (b'#!/source/.venv/bin/python\n' + body[len(source_header):]
                  if body.startswith(source_header) else body)
        script_outputs[name] = (target, stat.S_IMODE(observed['identity'][2]))
    return expected, modes, omitted, script_outputs


def seal(owner, bootstrap):
    """Join provisional original outputs to actual waits, then derive every byte."""
    from producer_setup import write
    from finite.operation_activation import verify_caches
    from producer_outputs import record_hash

    verify_source_inputs(owner.common['source_files'],
                         owner.common['primary_producer']['source_custody'])

    captures = getattr(owner, 'bootstrap_outputs', {})
    producers = {row['pid']: row for row in bootstrap['producers'] if row['role'] == 'editable_backend'}
    if len(producers) != 2 or set(producers) != set(captures):
        raise RuntimeError('primary_dependency_original_outputs_missing')
    for pid, producer in producers.items():
        row = captures[pid]
        if (row['profile_sha256'] != producer['profile_sha256'] or producer['parent_wait_raw'] != 0
                or sha(json.dumps(row['identity'], sort_keys=True, separators=(',', ':')).encode())
                != producer['identity_sha256']):
            raise RuntimeError('primary_dependency_original_output_lineage')
        receipt_path = RECEIPTS / ('bootstrap-response-' + str(pid) + '.json')
        receipt_body, receipt_file = read(receipt_path, 20001)
        if (receipt_file['sha256'] != row['receipt_sha256'] or receipt_file['identity'][5] != 1
                or stat.S_IMODE(receipt_file['identity'][2]) != 0o444
                or decode(receipt_body) != {name: value for name, value in row.items()
                                              if name != 'receipt_sha256'}):
            raise RuntimeError('primary_dependency_original_receipt_drift')
        response = Path(row['response']['path'])
        if response.exists():
            if read(response, 20000)[1] != row['response']:
                raise RuntimeError('primary_dependency_original_response_drift')
        elif response.is_symlink():
            raise RuntimeError('primary_dependency_original_response_link')
    builds = [row for row in captures.values() if row['helper'] == 'build_editable']
    if len(builds) != 1:
        raise RuntimeError('primary_dependency_original_build_count')
    retained = builds[0]['retained_wheel']
    body, retained_file = read(retained['path'], 20001)
    if retained_file != retained:
        raise RuntimeError('primary_dependency_original_wheel_drift')
    payload = wheel_payload(body)
    expected, modes, omitted, script_outputs = image_projection()
    generated = {DIST + '/INSTALLER': b'uv', DIST + '/REQUESTED': b'',
                 DIST + '/direct_url.json': b'{"url":"file:///source","dir_info":{"editable":true}}',
                 DIST + '/uv_build.json': b'{}',
                 DIST + '/uv_cache.json': json.dumps(source_cache_info(
                     owner.common['source_files'], owner.common['primary_producer']['source_custody']),
                     separators=(',', ':')).encode()}
    expected.update(payload)
    expected.update(generated)
    record = DIST + '/RECORD'
    rows = {name: record_hash(value) for name, value in {**payload, **generated}.items() if name != record}
    # The two actual project console renderers are also part of this manifest.
    from primary_policy import console
    for name in ('unrest', 'unrest-server'):
        rows['../../../bin/' + name] = record_hash(console(name))
        script_outputs['../../../bin/' + name] = (console(name), 0o755)
    rows[record] = ['', '']
    import csv
    stream = io.StringIO(newline='')
    csv.writer(stream, lineterminator='\n').writerows([name, *rows[name]] for name in sorted(rows))
    expected[record] = stream.getvalue().encode()
    caches = verify_caches(SITE)
    cache_names = set()
    for cache in caches:
        source = Path(cache['source']['path']).relative_to(SITE).as_posix()
        if source not in expected or sha(expected[source]) != cache['source']['sha256']:
            raise RuntimeError('primary_dependency_cache_source')
        _, file = read(cache['cache']['path'], 20000)
        if stat.S_IMODE(file['identity'][2]) != 0o644 or file['identity'][5] != 1:
            raise RuntimeError('primary_dependency_cache_custody')
        cache_names.add(Path(cache['cache']['path']).relative_to(SITE).as_posix())
    observed = {}
    for path in sorted(SITE.rglob('*')):
        if path.is_dir() and not path.is_symlink():
            continue
        value, file = read(path, 20000)
        name = path.relative_to(SITE).as_posix()
        if name in cache_names:
            continue
        if (name not in expected or value != expected[name]
                or stat.S_IMODE(file['identity'][2]) != modes.get(name, 0o644)):
            raise RuntimeError('primary_dependency_projected_member')
        observed[name] = file
    if set(observed) != set(expected):
        raise RuntimeError('primary_dependency_projected_membership')
    directories = directory_view(set(expected) | cache_names)
    scripts = {}
    for name, (wanted, mode) in script_outputs.items():
        path = SITE / name
        actual, file = read(path, 20000)
        if actual != wanted or stat.S_IMODE(file['identity'][2]) != mode:
            raise RuntimeError('primary_dependency_projected_script')
        scripts[name] = file
    declaration = {'schema': 'unrest.v046.primary-dependency-output.v1', 'site': str(SITE),
                   'files': observed, 'bootstrap': bootstrap['producers'],
                   'bootstrap_captures': [captures[pid] for pid in sorted(captures)],
                   'directories': directories, 'scripts': scripts,
                   'omitted_backend_members': len(omitted), 'initial_source_bound_caches': len(caches),
                   'wheel': retained, 'source_files': owner.common['source_files'],
                   'source_custody': owner.common['primary_producer']['source_custody'],
                   'source_checkpoint_ready': False, 'selected_carrier': None}
    validate_bootstrap(declaration)
    path = RECEIPTS / 'primary-dependency.json'
    pin = write(path, declaration)
    return {'path': str(path), 'sha256': pin}


def directory_view(names):
    if SITE.resolve(strict=True) != SITE:
        raise RuntimeError('primary_dependency_directory_route')
    wanted = {'.'} | {parent.as_posix() for name in names for parent in Path(name).parents}
    observed = {}
    for path in [SITE, *sorted(SITE.rglob('*'))]:
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            name = path.relative_to(SITE).as_posix()
            if (name not in wanted or info.st_uid != 20000 or info.st_gid != 20000
                    or stat.S_IMODE(info.st_mode) != 0o755):
                raise RuntimeError('primary_dependency_directory')
            children = sum(child.is_dir() and not child.is_symlink() for child in path.iterdir())
            if info.st_nlink != 2 + children or key(path.lstat()) != key(info):
                raise RuntimeError('primary_dependency_directory_links_or_race')
            observed[name] = {'identity': key(info)[:5], 'links': info.st_nlink}
        elif not stat.S_ISREG(info.st_mode):
            raise RuntimeError('primary_dependency_special_member')
    if set(observed) != wanted:
        raise RuntimeError('primary_dependency_directory_membership')
    return observed


def site_metadata():
    """Fresh no-follow census; no file byte is authorized by these stat rows."""
    if SITE.resolve(strict=True) != SITE:
        raise RuntimeError('primary_dependency_directory_route')
    root = str(SITE)
    pending = [root]
    files, directories = {}, {}
    while pending:
        path = pending.pop()
        info = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 20000 or info.st_gid != 20000
                or stat.S_IMODE(info.st_mode) != 0o755):
            raise RuntimeError('primary_dependency_directory')
        with os.scandir(path) as stream:
            children = sorted(entry.name for entry in stream)
        child_directories = 0
        for child in children:
            name = path + '/' + child
            child_info = os.stat(name, follow_symlinks=False)
            if child_info.st_uid != 20000 or child_info.st_gid != 20000:
                raise RuntimeError('primary_dependency_member_owner')
            if stat.S_ISDIR(child_info.st_mode):
                child_directories += 1
                pending.append(name)
            elif stat.S_ISREG(child_info.st_mode):
                files[name[len(root) + 1:]] = key(child_info)
            else:
                raise RuntimeError('primary_dependency_special_member')
        if info.st_nlink != 2 + child_directories or key(os.stat(path, follow_symlinks=False)) != key(info):
            raise RuntimeError('primary_dependency_directory_links_or_race')
        relative = '.' if path == root else path[len(root) + 1:]
        directories[relative] = {'identity': key(info)[:5], 'links': info.st_nlink}
    return files, directories


def cache_sources(names, ordinary):
    result = {}
    for name in names:
        if not name.endswith('.pyc'):
            continue
        path = Path(name)
        parts = path.name.split('.')
        if (path.parent.name != '__pycache__' or len(parts) not in (3, 4)
                or parts[1] != 'cpython-313' or parts[-1] != 'pyc'
                or len(parts) == 4 and parts[2] not in {'opt-1', 'opt-2'}):
            raise RuntimeError('primary_dependency_cache_domain')
        source = (path.parent.parent / (parts[0] + '.py')).as_posix()
        if source not in ordinary:
            raise RuntimeError('primary_dependency_cache_source')
        result[name] = (source, 0 if len(parts) == 3 else int(parts[2][-1]))
    if set(names) - set(result) != set(ordinary):
        raise RuntimeError('primary_dependency_current_membership')
    return result


def immutable_cache(namespace, name, source_name, optimize, expected_source):
    """Retain the legacy verifier, then bind code to immutable image source.

    A transient mutable-site source observation cannot mint expected code.
    Compilation is comparison only and never dispatches the resulting object.
    """
    import importlib.util
    import marshal
    image = IMAGE / source_name
    if image.resolve(strict=True) != image or not os.statvfs(image).f_flag & os.ST_RDONLY:
        raise RuntimeError('primary_dependency_cache_image_route')
    source, image_file = read(image, 0)
    if image_file['sha256'] != expected_source['sha256']:
        raise RuntimeError('primary_dependency_cache_image_source')
    payload, current = read(SITE / name, 20000)
    if (stat.S_IMODE(current['identity'][2]) != 0o644 or current['identity'][5] != 1
            or payload[:4] != importlib.util.MAGIC_NUMBER):
        raise RuntimeError('primary_dependency_cache_custody')
    flags = int.from_bytes(payload[4:8], 'little')
    info = os.stat(str(SITE / source_name), follow_symlinks=False)
    expected = expected_source['identity']
    # UID/GID/link custody is checked by the census and final full-byte read.
    if any(key(info)[index] != expected[index] for index in (0, 1, 2, 6, 7, 8)):
        raise RuntimeError('primary_dependency_cache_source_identity')
    if flags == 0:
        if (int.from_bytes(payload[8:12], 'little') != int(info.st_mtime) & 0xFFFFFFFF
                or int.from_bytes(payload[12:16], 'little') != len(source) & 0xFFFFFFFF):
            raise RuntimeError('primary_dependency_cache_immutable_header')
    elif flags in (1, 3):
        if payload[8:16] != importlib.util.source_hash(source):
            raise RuntimeError('primary_dependency_cache_immutable_header')
    else:
        raise RuntimeError('primary_dependency_cache_immutable_flags')
    code = marshal.loads(payload[16:])
    compiled = compile(source, str(SITE / source_name), 'exec', dont_inherit=True, optimize=optimize)
    if namespace['code_identity'](code) != namespace['code_identity'](compiled):
        raise RuntimeError('primary_dependency_cache_immutable_code')
    return current


def verify(site, support):
    """Consume only the observer-pinned PRIMARY domain; no path-prefix fallback."""
    if (Path(site) != SITE or set(support) != {'path', 'sha256', 'activation_sha256'}
            or support['path'] != str(RECEIPTS / 'primary-dependency.json')):
        raise RuntimeError('primary_dependency_consumer_domain')
    body, receipt = read(support['path'], 20001)
    if (receipt['sha256'] != support['sha256'] or receipt['identity'][5] != 1
            or stat.S_IMODE(receipt['identity'][2]) != 0o444):
        raise RuntimeError('primary_dependency_receipt')
    value = decode(body)
    if (set(value) != {'schema', 'site', 'files', 'directories', 'scripts', 'bootstrap', 'bootstrap_captures', 'omitted_backend_members',
                       'initial_source_bound_caches', 'wheel', 'source_files', 'source_custody',
                       'source_checkpoint_ready', 'selected_carrier'}
            or value['schema'] != 'unrest.v046.primary-dependency-output.v1'
            or value['site'] != str(SITE) or value['source_checkpoint_ready'] is not False
            or value['selected_carrier'] is not None):
        raise RuntimeError('primary_dependency_schema')
    validate_bootstrap(value)
    verify_source_inputs(value['source_files'], value['source_custody'])
    if read(value['wheel']['path'], 20001)[1] != value['wheel']:
        raise RuntimeError('primary_dependency_current_original_wheel_drift')
    source = Path('/guard/finite/operation_activation.py')
    source_body = source.read_bytes()
    if sha(source_body) != support['activation_sha256']:
        raise RuntimeError('primary_dependency_cache_verifier')
    namespace = {'__file__': str(source), '__name__': 'primary_dependency_activation'}
    exec(compile(source_body, str(source), 'exec', dont_inherit=True), namespace)
    first, directories = site_metadata()
    source_map = cache_sources(first, value['files'])
    wanted_directories = {'.'}
    for name in first:
        parent = name.rpartition('/')[0]
        while parent:
            wanted_directories.add(parent)
            parent = parent.rpartition('/')[0]
    if set(directories) != wanted_directories:
        raise RuntimeError('primary_dependency_directory_membership')
    if any(name not in directories or directories[name]['identity'] != row['identity']
           for name, row in value['directories'].items()):
        raise RuntimeError('primary_dependency_current_directory_drift')
    caches = namespace['verify_caches'](SITE)
    checked = {Path(row['cache']['path']).relative_to(SITE).as_posix(): row for row in caches}
    if len(checked) != len(caches) or set(checked) != set(source_map):
        raise RuntimeError('primary_dependency_cache_membership')
    current_caches = {}
    for name in sorted(checked):
        cache = checked[name]
        source_name, optimize = source_map[name]
        if (cache['source']['path'] != str(SITE / source_name)
                or cache['source']['sha256'] != value['files'][source_name]['sha256']
                or cache['optimize'] != optimize):
            raise RuntimeError('primary_dependency_current_cache_source')
        current = immutable_cache(namespace, name, source_name, optimize, value['files'][source_name])
        if current['identity'] != first[name]:
            raise RuntimeError('primary_dependency_current_cache_drift')
        current_caches[name] = current
    # Stat rows never replace a byte check: every ordinary file is fully read
    # here, after discovery/cache comparison and immediately before consumption.
    for name in sorted(value['files']):
        _, current = read(str(SITE) + '/' + name, 20000)
        if current != value['files'][name] or current['identity'] != first[name]:
            raise RuntimeError('primary_dependency_current_file_drift')
    for name, expected in value['scripts'].items():
        parts = Path(name).parts
        path = SITE / name
        canonical = SITE.parents[2] / 'bin' / parts[-1]
        if (not name.startswith('../../../bin/') or len(parts) != 5
                or parts[-1] in {'.', '..'} or str(Path(name)) != name
                or expected['path'] != str(path) or path.resolve(strict=True) != canonical
                or read(path, 20000)[1] != expected or path.resolve(strict=True) != canonical):
            raise RuntimeError('primary_dependency_current_script_drift')
    for name, expected in current_caches.items():
        if read(str(SITE) + '/' + name, 20000)[1] != expected:
            raise RuntimeError('primary_dependency_late_cache_drift')
    final, final_directories = site_metadata()
    if final != first or final_directories != directories:
        raise RuntimeError('primary_dependency_late_census_drift')
    return {'kind': 'primary_dependency_consumption', 'files': len(value['files']),
            'source_bound_caches': len(caches), 'declaration_sha256': support['sha256']}
