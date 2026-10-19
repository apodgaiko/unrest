"""Finite public UV renderer and protected original-source profile consumption."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time

ROOT = Path('/receipts/producers')


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


public_inputs = load('producer_inputs', '/guard/producer_inputs.py')
identities = load('linux_identity', '/guard/finite/linux_identity.py')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def protected_json(path, pin):
    path = Path(path)
    if path.parent != ROOT or path.is_symlink():
        raise RuntimeError('producer profile root refused')
    info = path.stat()
    body = path.read_bytes()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20001
            or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1
            or hashlib.sha256(body).hexdigest() != pin):
        raise RuntimeError('producer profile custody or byte drift')
    return json.loads(body)


def events(spec):
    return [json.loads(line) for path in sorted(Path(spec['events']).glob('*.jsonl'))
            for line in path.read_text().splitlines()]


def query_package(script, spec):
    try:
        nodes = ast.parse(script).body
        assignment = nodes[1]
        if (not isinstance(assignment, ast.Assign)
                or not isinstance(assignment.value, ast.BinOp)
                or not isinstance(assignment.value.left, ast.List)
                or len(assignment.value.left.elts) != 1
                or not isinstance(assignment.value.left.elts[0], ast.Constant)):
            raise RuntimeError('query renderer shape drift')
        directory = assignment.value.left.elts[0].value
        if not isinstance(directory, str):
            raise RuntimeError('query renderer directory type drift')
    except (SyntaxError, AttributeError, IndexError, TypeError):
        raise RuntimeError('query renderer shape drift') from None
    path = Path(directory)
    if (path.parent != Path(spec['cache']) or not path.name.startswith('.tmp')
            or path.resolve() != path or path.is_symlink()):
        raise RuntimeError('query package is outside its finite UV cache')
    expected = ('import sys; sys.path = ["' + directory + '"] + sys.path; '
                'from python.get_interpreter_info import main; main()')
    if script != expected:
        raise RuntimeError('query literal renderer drift')
    wanted = {name: item['sha256'] for name, item in public_inputs.UV_EMBEDDED.items()
              if name.startswith('python/')}
    paths = list(path.rglob('*'))
    if any(item.is_symlink() for item in paths):
        raise RuntimeError('query package symlink refused')
    actual = {item.relative_to(path).as_posix(): digest(item)
              for item in paths if item.is_file()}
    if actual != wanted:
        raise RuntimeError('query generated package or cache drift')
    return {'path': str(path), 'members': actual,
            'script_sha256': hashlib.sha256(script.encode()).hexdigest()}


def consume(profile):
    spec = protected_json(profile['spec'], profile['spec_sha256'])
    parent = spec['parent_operation']
    primary = spec.get('primary_producer')
    base = '/usr/local/bin/python-primary-audit' if primary is not None else '/usr/local/bin/python-source-audit'
    if primary is not None:
        if (primary['entry'] != spec['base_identity']
                or primary['entry']['path'] != base
                or spec['cache'] != '/work/cache'
                or primary['bootstrap']['path'] != '/guard/primary_entry.py'
                or primary['consumer']['path'] != '/guard/native_entry.py'
                or any(digest(primary[key]['path']) != primary[key]['sha256']
                       for key in ('entry', 'bootstrap', 'consumer'))):
            raise RuntimeError('primary producer setup consumption drift')
    if (parent['pid'] != os.getppid() or parent['identity'] != identities.identity(os.getppid())
            or parent['operation'] not in ('source-build', 'source-install')
            or digest('/opt/source-bootstrap/bin/uv') != public_inputs.SOURCE_UV_ELF_SHA256
            or digest(spec['base']) != spec['base_identity']['sha256']
            or spec['base'] != base
            or os.getcwd() != profile['cwd'] or sys.executable != profile['orig_argv'][0]):
        raise RuntimeError('native original UV parent/runtime binding drift')
    if 'primary_package_origin' in spec:
        origin = spec['primary_package_origin']
        value = protected_json(origin['path'], origin['sha256'])
        plan = json.loads(Path('/inputs/plan.json').read_bytes())
        script = Path('/inputs/github-script.sh').read_bytes()
        if (set(origin) != {'path', 'sha256'}
                or value['schema'] != 'unrest.v046.primary-package-build-origin.v1'
                or value['plan'] != plan or plan['duty'] != 'Build wheel and source distribution'
                or plan['commands'] != [['uv', 'build']]
                or plan['script_sha256'] != hashlib.sha256(script).hexdigest()
                or script not in {b'uv build', b'uv build\n'}
                or plan['package_mode'] not in {'TEST', 'FULL'}
                or (plan['package_mode'] == 'TEST') != Path('/inputs/package-test').is_file()
                or plan['workflow_sha256'] != digest('/source/.github/workflows/ci.yml')
                or value['identity'] != identities.identity(parent['pid'])
                or parent['identity'] != value['identity']
                or value['parent_identity'] != identities.identity(parent['owner_pid'])
                or value['identity']['ppid'] != parent['owner_pid']
                or value['identity']['uid'] != 20000
                or value['argv'] != ['uv', 'build'] or value['cwd'] != '/source'
                or spec['profile'] != {'argv': value['argv'], 'cwd': value['cwd'],
                                       'environment': value['environment']}
                or parent['record_sha256'] != origin['sha256'] or parent['token'] != value['token']
                or Path('/proc/' + str(parent['pid']) + '/exe').resolve()
                != Path('/opt/source-bootstrap/bin/uv') or profile['ppid'] != parent['pid']):
            raise RuntimeError('primary_package_live_origin')
        if profile['role'] == 'isolated-uv-query':
            if sys.orig_argv[1:4] != ['-I', '-B', '-c'] or len(sys.orig_argv) != 5:
                raise RuntimeError('native original isolated query flags drift')
            if sys.executable != spec['query_python']:
                raise RuntimeError('native selected query interpreter drift')
            query_package(sys.orig_argv[-1], spec)
        elif sys.orig_argv[1:-1] != ['-c']:
            raise RuntimeError('native original backend flags drift')
        return spec
    deadline = time.monotonic() + 4
    while True:
        rows = events(spec)
        retained = [row for row in rows if row['kind'] == 'operation_retained'
                    and row['owner_pid'] == parent['owner_pid'] and row['pid'] == parent['pid']
                    and row['launch_token'] == parent['launch_token'] and row['token'] == parent['token']]
        if retained or time.monotonic() >= deadline:
            break
        if identities.identity(os.getppid()) != parent['identity']:
            raise RuntimeError('native original parent changed before retention')
        time.sleep(.001)
    admissions = [row for row in rows if row['kind'] == 'operation_admission'
                  and row['owner_pid'] == parent['owner_pid'] and row['token'] == parent['token']]
    if (len(retained) != 1 or len(admissions) != 1
            or hashed(admissions[0]) != parent['record_sha256']):
        raise RuntimeError('native actual source operation consumption missing or changed')
    if profile['role'] == 'isolated-uv-query':
        if sys.orig_argv[1:4] != ['-I', '-B', '-c'] or len(sys.orig_argv) != 5:
            raise RuntimeError('native original isolated query flags drift')
        if sys.executable != spec['query_python']:
            raise RuntimeError('native selected query interpreter drift')
        query_package(sys.orig_argv[-1], spec)
    elif sys.orig_argv[1:-1] != ['-c']:
        raise RuntimeError('native original backend flags drift')
    return spec


def cache_view(spec, external_links):
    """Read the complete finite cache with no caller-supplied inventory authority."""
    activation = load('cache_domain_identity', '/guard/finite/operation_activation.py')
    root = Path(spec['cache'])
    root_info = root.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 20000
            or root.resolve(strict=True) != root):
        raise RuntimeError('primary_cache_domain_root')
    root_key = hashlib.sha256(b'.').hexdigest()
    root_identity = [root_info.st_dev, root_info.st_ino, root_info.st_mode, root_info.st_uid]
    entries = {root_key: {'type': 'directory', 'identity': root_identity}}
    names = {root_key: '.'}
    def link_key(info):
        return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_ctime_ns]
    paths = sorted(root.rglob('*'))
    for path in paths:
        name = path.relative_to(root).as_posix()
        key = hashlib.sha256(name.encode()).hexdigest()
        info = path.lstat()
        if info.st_uid != 20000:
            raise RuntimeError('primary_cache_domain_owner')
        if stat.S_ISREG(info.st_mode):
            file = activation.identity(path)
            entry = {'type': 'file', 'file_identity': file['identity'], 'sha256': file['sha256'],
                     'uid': info.st_uid, 'nlink': info.st_nlink}
        elif stat.S_ISDIR(info.st_mode):
            entry = {'type': 'directory', 'identity': [info.st_dev, info.st_ino, info.st_mode, info.st_uid]}
        elif stat.S_ISLNK(info.st_mode):
            target = path.resolve(strict=True)
            outside = not target.is_relative_to(root)
            if outside and (key not in external_links or target != Path(spec['base'])
                            or activation.identity(target) != spec['base_identity'] or target.stat().st_uid != 0):
                raise RuntimeError('primary_cache_domain_external_link')
            target_info = target.stat()
            target_entry = ({'file_identity': activation.identity(target)['identity'], 'sha256': digest(target)}
                            if target.is_file() else {'directory': [target_info.st_dev, target_info.st_ino, target_info.st_mode]})
            entry = {'type': 'symlink', 'identity': link_key(info),
                     'target_sha256': hashlib.sha256(os.readlink(path).encode()).hexdigest(),
                     'resolved_sha256': hashlib.sha256(str(target).encode()).hexdigest(),
                     'target': target_entry, 'target_uid': target_info.st_uid, 'external': outside}
            if link_key(path.lstat()) != link_key(info):
                raise RuntimeError('primary_cache_domain_link_race')
        else:
            raise RuntimeError('primary_cache_domain_type')
        entries[key], names[key] = entry, name
    after = root.lstat()
    if (sorted(root.rglob('*')) != paths
            or [after.st_dev, after.st_ino, after.st_mode, after.st_uid] != root_identity):
        raise RuntimeError('primary_cache_domain_membership_race')
    return entries, names


def bootstrap_cache(spec, trace, pid, primary):
    """Seal the original PRIMARY bootstrap outputs before product Python runs."""
    parent = trace.identities[pid]['ppid']
    context = primary.contexts.get(parent)
    if (trace.poison or primary.denials or context is None or context['role'] != 'uv'
            or context['command'][:3] != ['uv', 'run', 'pytest']
            or identities.identity(parent) != context['identity']):
        raise RuntimeError('primary_cache_bootstrap_context')
    children = [(child, value) for child, value in primary.contexts.items()
                if value.get('role') in {'query', 'editable_backend'} and value['identity']['ppid'] == parent]
    if (len(children) != 3 or [value['role'] for _, value in children].count('query') != 1
            or [value['role'] for _, value in children].count('editable_backend') != 2):
        raise RuntimeError('primary_cache_bootstrap_original_producers')
    external, provenance = set(), []
    policy = load('cache_bootstrap_policy', '/guard/primary_policy.py')
    for child, value in children:
        records = [record for record in primary.records if record['kind'] == 'primary_native_preinit'
                   and record['pid'] == child and record['parent'] == parent and record['role'] == value['role']]
        waits = [event for event in trace.records if event['kind'] == 'original_parent_wait4'
                 and event['child'] == child and event['parent_tgid'] == parent]
        if len(records) != 1 or len(waits) != 1 or waits[0]['raw'] != 0 or records[0]['identity'] != value['identity']:
            raise RuntimeError('primary_cache_bootstrap_actual_wait')
        path = Path('/receipts/primary-startup') / (str(child) + '.json')
        info, body = path.lstat(), path.read_bytes()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20001 or stat.S_IMODE(info.st_mode) != 0o444
                or info.st_nlink != 1 or hashlib.sha256(body).hexdigest() != records[0]['profile_sha256']):
            raise RuntimeError('primary_cache_bootstrap_profile')
        header = json.loads(body)
        if (header['pid'] != child or header['parent'] != parent
                or header['start_ticks'] != value['identity']['start_ticks']
                or header['boot_id'] != value['identity']['boot_id']):
            raise RuntimeError('primary_cache_bootstrap_birth')
        if value['role'] == 'editable_backend':
            helper = policy.backend_request(header['orig_argv'][-1])
            if helper not in {'get_requires_for_build_editable', 'build_editable'}:
                raise RuntimeError('primary_cache_bootstrap_helper')
            runtime = Path(header['orig_argv'][0]).parent.parent
            for name in ('python', 'python3', 'python3.13'):
                link = runtime / 'bin' / name
                external.add(hashlib.sha256(str(link.relative_to(spec['cache'])).encode()).hexdigest())
        provenance.append({'pid': child, 'role': value['role'], 'parent_wait_raw': 0,
                           'identity_sha256': hashed(value['identity']),
                           'profile_sha256': records[0]['profile_sha256']})
    # The only live writer before this exec fence is the already admitted UV;
    # its exact query/editable children have returned and been numerically reaped.
    for task in trace.active:
        tgid = trace.identities[task]['tgid']
        if tgid not in {primary.root, parent, pid}:
            raise RuntimeError('primary_cache_bootstrap_foreign_writer')
    entries, _ = cache_view(spec, external)
    return {'schema': 'unrest.v046.primary-cache-bootstrap.v1', 'entries': entries,
            'external_links': sorted(external), 'source_pid': pid, 'parent': parent,
            'parent_identity_sha256': hashed(context['identity']), 'producers': provenance,
            'source_checkpoint_ready': False, 'selected_carrier': None}


def cache_core(entry):
    """UV hardlink creation changes ctime/nlink, never published input bytes."""
    if entry['type'] == 'file':
        return {'type': 'file', 'identity': entry['file_identity'][:5],
                'sha256': entry['sha256'], 'uid': entry['uid']}
    return entry


def read_cache_operation(spec, build):
    path = ROOT / ('cache-output-' + str(build['pid']) + '.json')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 20001 or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1:
        raise RuntimeError('primary_cache_operation_custody')
    value = json.loads(path.read_bytes())
    if (value['pid'] != build['pid'] or value['owner_pid'] != build['owner_pid']
            or value['operation_sha256'] != hashlib.sha256(build['token'].encode()).hexdigest()
            or value['operation'] != 'source-build' or value['kernel_exit_raw'] != 0
            or value['bootstrap_sha256'] != spec['primary_producer']['bootstrap_cache']['sha256']):
        raise RuntimeError('primary_cache_operation_lineage')
    return value


def original_response_output(spec, profile, helper, producer_pid=None):
    """Capture the completed original -c program's still-owned response bytes."""
    activation = load('program_response_identity', '/guard/finite/operation_activation.py')
    nodes = ast.parse(profile['orig_argv'][-1]).body
    request = Path(nodes[-1].items[0].context_expr.args[0].value)
    root = Path(spec['primary_runtime_output']['root'])
    if request != root / (helper + '.txt'):
        raise RuntimeError('primary_response_program_path_drift')
    info = request.lstat()
    file = activation.identity(request)
    if info.st_uid != 20000 or not stat.S_ISREG(info.st_mode):
        raise RuntimeError('primary_response_program_custody')
    header = Path('/receipts/native-startup') / (str(os.getpid() if producer_pid is None else producer_pid) + '.json')
    return {'kind': 'isolated_original_response_output', 'helper': helper,
            'member_sha256': hashlib.sha256(str(request).encode()).hexdigest(),
            'file_identity': file['identity'], 'sha256': file['sha256'],
            'uid': info.st_uid, 'nlink': info.st_nlink,
            'profile_sha256': digest(header)}


def response_receipt(spec, header, child, wait, produced=None):
    """Observe the exact original helper response after its numeric UV wait."""
    activation = load('response_identity', '/guard/finite/operation_activation.py')
    resolver = load('response_renderer', '/guard/finite/isolated_activation.py')
    helper = resolver.helper_class(header['orig_argv'][-1], spec)
    if helper != child['helper'] or wait['raw'] != 0 or wait['parent_tgid'] != child['parent']:
        raise RuntimeError('primary_response_original_wait_drift')
    nodes = ast.parse(header['orig_argv'][-1]).body
    request = Path(nodes[-1].items[0].context_expr.args[0].value)
    root = Path(spec['primary_runtime_output']['root'])
    if request != root / (helper + '.txt'):
        raise RuntimeError('primary_response_original_path_drift')
    rows = events(spec)
    calls = [r for r in rows if r['kind'] == 'isolated_actual_backend_call'
             and r['owner_pid'] == child['pid'] and r['parent_pid'] == child['parent']
             and r['helper'] == helper]
    ready = [r for r in rows if r['kind'] == 'ready' and r['owner_pid'] == child['pid']
             and r['token'] == child['token']]
    if len(calls) != 1 or len(ready) != 1 or ready[0]['manifest_sha256'] != header['manifest_sha256']:
        raise RuntimeError('primary_response_original_call_ready_missing')
    if helper.startswith('get_requires_for_build_'):
        expected = b'[]'
        role = 'requirements-response'
    else:
        outputs = [r for r in rows if r['kind'] == 'isolated_backend_output'
                   and r['owner_pid'] == child['pid'] and r['parent_pid'] == child['parent']
                   and r['helper'] == helper]
        if len(outputs) != 1 or Path(outputs[0]['artifact']['path']).parent != Path(spec['output']):
            raise RuntimeError('primary_response_actual_archive_missing')
        expected = Path(outputs[0]['artifact']['path']).name.encode()
        role = 'archive-name-response'
    if (produced is None or produced['profile_sha256'] != child['profile_sha256']
            or produced['member_sha256'] != hashlib.sha256(str(request).encode()).hexdigest()
            or produced['sha256'] != hashlib.sha256(expected).hexdigest() or produced['uid'] != 20000):
        raise RuntimeError('primary_response_original_program_output_missing')
    output = produced
    retained = request.exists()
    if retained:
        file = activation.identity(request)
        info = request.lstat()
        if (file['identity'] != output['file_identity'] or file['sha256'] != output['sha256']
                or info.st_uid != output['uid'] or info.st_nlink != output['nlink']):
            raise RuntimeError('primary_response_original_body_custody_drift')
    elif request.is_symlink():
        raise RuntimeError('primary_response_dangling_link')
    return {'schema': 'unrest.v046.original-uv-response.v1', 'role': role,
            'helper': helper, 'pid': child['pid'], 'parent': child['parent'],
            'child_identity_sha256': hashed(child['identity']),
            'child_start_ticks': child['identity']['start_ticks'],
            'child_boot_sha256': hashlib.sha256(child['identity']['boot_id'].encode()).hexdigest(),
            'parent_identity_sha256': hashed(spec['parent_operation']['identity']),
            'operation_sha256': hashlib.sha256(spec['parent_operation']['token'].encode()).hexdigest(),
            'profile_sha256': child['profile_sha256'],
            'runtime_root_sha256': hashlib.sha256(str(root).encode()).hexdigest(),
            'member': helper + '.txt', 'member_sha256': hashlib.sha256(str(request).encode()).hexdigest(),
            'file_identity': output['file_identity'], 'sha256': output['sha256'],
            'uid': output['uid'], 'nlink': output['nlink'], 'parent_wait_raw': wait['raw'],
            'response_retained_at_wait': retained, 'runtime_retained_at_wait': root.exists()}


def check_response_binding(receipt, spec, root):
    parent = spec['parent_operation']
    names = {helper + '.txt' for helper in ('get_requires_for_build_sdist', 'build_sdist',
                                          'get_requires_for_build_wheel', 'build_wheel')}
    name = receipt['member']
    path = root / name
    if (name not in names or receipt['member_sha256'] != hashlib.sha256(str(path).encode()).hexdigest()
            or receipt['runtime_root_sha256'] != hashlib.sha256(str(root).encode()).hexdigest()
            or receipt['operation_sha256'] != hashlib.sha256(parent['token'].encode()).hexdigest()
            or receipt['parent'] != parent['pid'] or receipt['parent_identity_sha256'] != hashed(parent['identity'])
            or receipt['parent_wait_raw'] != 0):
        raise RuntimeError('primary_response_current_operation_drift')
    return path


def response_member(receipt, spec, root, activation):
    path = check_response_binding(receipt, spec, root)
    file = activation.identity(path)
    info = path.lstat()
    if (file['identity'] != receipt['file_identity'] or file['sha256'] != receipt['sha256']
            or info.st_uid != receipt['uid'] or info.st_uid != 20000 or info.st_nlink != receipt['nlink']):
        raise RuntimeError('primary_response_current_file_drift')
    return {'type': 'file', 'file': file, 'uid': info.st_uid, 'nlink': info.st_nlink}


def read_response(pid):
    path = ROOT / ('response-' + str(pid) + '.json')
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20001
            or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1):
        raise RuntimeError('primary_response_receipt_custody')
    body = path.read_bytes()
    after = path.lstat()
    def key(item):
        return (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_nlink,
                item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if key(after) != key(info):
        raise RuntimeError('primary_response_receipt_read_race')
    return json.loads(body)


def runtime_metadata(spec, root):
    """Render only the pinned UV0.11.0 Linux, nonrelocatable CPython outputs."""
    directory = str(root)
    if any(character in directory for character in ("'", "\\", "\n", "\r")):
        raise RuntimeError('primary_runtime_unrenderable_directory')
    result = {'.gitignore': b'*',
              'CACHEDIR.TAG': b'Signature: 8a477f597d28d172789f06886806bc55'}
    upstream = Path(spec['virtualenv_source']).parent
    for name, binding in public_inputs.UV_EMBEDDED.items():
        if not name.startswith('virtualenv/activator/'):
            continue
        path = upstream / name
        body = path.read_bytes()
        if path.is_symlink() or len(body) != binding['size'] or hashlib.sha256(body).hexdigest() != binding['sha256']:
            raise RuntimeError('primary_runtime_activator_input_drift')
        substitutions = {'{{ VIRTUAL_ENV_DIR }}': "'" + directory + "'" if path.name == 'activate.nu' else directory,
                         '{{ BIN_NAME }}': 'bin', '{{ VIRTUAL_PROMPT }}': '',
                         '{{ PATH_SEP }}': ':', '{{ RELATIVE_SITE_PACKAGES }}': '../lib/python3.13/site-packages'}
        text = body.decode()
        for before, after in substitutions.items():
            text = text.replace(before, after)
        result['bin/' + path.name] = text.encode()
    return result


def runtime_members(spec, selected, emit=None, responses=None):
    """Declare one already validated original UV backend environment at exec."""
    activation = load('runtime_member_identity', '/guard/finite/operation_activation.py')
    root = Path(selected['prefix'])
    python = Path(selected['python_link'])
    if python != root / 'bin/python' or python.resolve(strict=True) != Path(spec['base']):
        raise RuntimeError('primary_runtime_declared_python_drift')
    site = root / 'lib/python3.13/site-packages'
    metadata = runtime_metadata(spec, root)
    responses = {} if responses is None else responses
    declared_responses = {}
    for receipt in responses.values():
        if receipt['runtime_root_sha256'] == hashlib.sha256(str(root).encode()).hexdigest():
            path = check_response_binding(receipt, spec, root)
            if path.exists():
                declared_responses[receipt['member']] = response_member(receipt, spec, root, activation)
            elif path.is_symlink():
                raise RuntimeError('primary_runtime_retired_response_symlink')
    import zipfile
    with zipfile.ZipFile(spec['wheel']) as archive:
        wheel_names = archive.namelist()
    site_files = {name for name in wheel_names if not name.endswith('/')}
    site_files.update(str(Path(item['path']).relative_to(site)) for item in selected['generated'])
    site_files.update(str(Path(item['cache']['path']).relative_to(site)) for item in selected['caches'])
    site_directories = {parent.as_posix() for name in site_files
                        for parent in Path(name).parents if parent != Path('.')}
    site_directories.update(name.rstrip('/') for name in wheel_names if name.endswith('/'))
    rows = {}
    def refuse(code, name, kind):
        if emit is not None:
            emit({'kind': 'primary_runtime_member_refusal', 'stage': code,
                  'member_sha256': hashlib.sha256(name.encode()).hexdigest(),
                  'member_type': kind,
                  'actual_sha256': digest(root / name) if kind == 'file' else None,
                  'size': (root / name).lstat().st_size})
        raise RuntimeError(code)
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        name = path.relative_to(root).as_posix()
        if info.st_uid != 20000 or (not path.is_symlink() and stat.S_IMODE(info.st_mode) & 0o022):
            raise RuntimeError('primary_runtime_member_owner_mode')
        if path.is_symlink():
            allowed = {root / 'bin/python': spec['base'], root / 'bin/python3': 'python',
                       root / 'bin/python3.13': 'python', root / 'lib64': 'lib'}
            if path not in allowed or os.readlink(path) != allowed[path]:
                refuse('primary_runtime_unbound_link', name, 'symlink')
            target = path.resolve(strict=True)
            expected_target = root / 'lib' if name == 'lib64' else Path(spec['base'])
            if target != expected_target:
                refuse('primary_runtime_link_target_drift', name, 'symlink')
            target_identity = activation.identity(target) if target.is_file() else {
                'directory': [target.stat().st_dev, target.stat().st_ino, target.stat().st_mode]}
            if name != 'lib64' and (target_identity != spec['base_identity'] or target.stat().st_uid != 0):
                refuse('primary_runtime_link_image_drift', name, 'symlink')
            after = path.lstat()
            if ([info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_ctime_ns]
                    != [after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_ctime_ns]
                    or os.readlink(path) != allowed[path]):
                refuse('primary_runtime_link_read_race', name, 'symlink')
            rows[name] = {'type': 'symlink', 'target': os.readlink(path),
                          'identity': [info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                                       info.st_ctime_ns], 'target_identity': target_identity,
                          'target_uid': target.stat().st_uid}
        elif path.is_dir():
            if not (path in {root / 'bin', root / 'lib', root / 'lib/python3.13'}
                    or path == site or (path.is_relative_to(site)
                        and path.relative_to(site).as_posix() in site_directories)):
                refuse('primary_runtime_unbound_directory', name, 'directory')
            rows[name] = {'type': 'directory', 'identity': [info.st_dev, info.st_ino,
                                                          info.st_mode, info.st_uid]}
        elif path.is_file():
            if name in declared_responses:
                if activation.identity(path) != declared_responses[name]['file']:
                    refuse('primary_runtime_response_drift', name, 'file')
            elif name in metadata:
                if path.read_bytes() != metadata[name]:
                    refuse('primary_runtime_metadata_bytes', name, 'file')
            elif not (path == root / 'pyvenv.cfg' or (path.is_relative_to(site)
                    and path.relative_to(site).as_posix() in site_files)):
                refuse('primary_runtime_unbound_file', name, 'file')
            rows[name] = {'type': 'file', 'file': activation.identity(path), 'uid': info.st_uid, 'nlink': info.st_nlink}
        else:
            raise RuntimeError('primary_runtime_nonregular_member')
    if not set(metadata) | set(declared_responses) <= set(rows):
        raise RuntimeError('primary_runtime_metadata_missing')
    info = root.lstat()
    return {'root': str(root), 'root_identity': [info.st_dev, info.st_ino, info.st_mode, info.st_uid],
            'members': rows}


def original_runtime_outputs(spec, operations):
    """Read only the current original build's authenticated READY child headers."""
    build = operations.require(spec['output'], 'source-build')
    rows = events(spec)
    admissions = [r for r in rows if r['kind'] == 'operation_admission'
                  and r['token'] == build['token'] and r['owner_pid'] == build['owner_pid']]
    if len(admissions) != 1:
        raise RuntimeError('primary_runtime_build_admission_missing')
    helpers = [r for r in rows if r['kind'] == 'isolated_original_dispatch'
               and r['parent_pid'] == build['pid']]
    wanted = {'get_requires_for_build_sdist', 'build_sdist',
              'get_requires_for_build_wheel', 'build_wheel'}
    if len(helpers) != 4 or {r['helper'] for r in helpers} != wanted:
        raise RuntimeError('primary_runtime_original_helpers_missing')
    outputs, temporary_names = {}, {}
    for helper in helpers:
        pid = helper['owner_pid']
        path = Path('/receipts/native-startup') / (str(pid) + '.json')
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20001
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1):
            raise RuntimeError('primary_runtime_header_custody')
        header = json.loads(path.read_bytes())
        child = protected_json(header['spec'], header['spec_sha256'])
        parent = child['parent_operation']
        ready = [r for r in rows if r['kind'] == 'ready' and r['owner_pid'] == pid
                 and r['token'] == header['token']]
        if (len(ready) != 1 or ready[0]['manifest_sha256'] != header['manifest_sha256']
                or header['pid'] != pid or header['ppid'] != build['pid']
                or parent['pid'] != build['pid'] or parent['token'] != build['token']
                or parent['owner_pid'] != build['owner_pid']
                or parent['record_sha256'] != hashed(admissions[0])
                or child['cache'] != spec['cache'] or child['base_identity'] != spec['base_identity']
                or header['role'] != 'isolated-uv-helper'):
            raise RuntimeError('primary_runtime_current_operation_drift')
        output = child['primary_runtime_output']
        root = output['root']
        if (Path(header['orig_argv'][0]) != Path(root) / 'bin/python'
                or header['orig_argv'][1] != '-c'
                or hashlib.sha256(json.dumps(header['orig_argv']).encode()).hexdigest() != helper['orig_argv_sha256']
                or child['output'] != spec['output']):
            raise RuntimeError('primary_runtime_original_dispatch_drift')
        receipt = read_response(pid)
        if (receipt['profile_sha256'] != hashlib.sha256(path.read_bytes()).hexdigest()
                or receipt['child_start_ticks'] != header['start_ticks']
                or receipt['child_boot_sha256'] != hashlib.sha256(header['boot_id'].encode()).hexdigest()
                or receipt['pid'] != pid or receipt['helper'] != helper['helper']):
            raise RuntimeError('primary_runtime_response_profile_drift')
        check_response_binding(receipt, child, Path(root))
        temporary_names.setdefault(root, set()).add(receipt['member'])
        if not Path(root).exists():
            if Path(root).is_symlink():
                raise RuntimeError('primary_runtime_retired_root_symlink')
            continue
        # Each helper validates this same generated environment before dispatch.
        # Keep the earliest inode identities; later admissions cannot replace it.
        if root not in outputs:
            outputs[root] = {'root': root, 'root_identity': output['root_identity'],
                             'members': dict(output['members'])}
        else:
            for name, member in output['members'].items():
                old = outputs[root]['members'].get(name)
                if old is not None and old != member:
                    raise RuntimeError('primary_runtime_prior_member_drift')
                outputs[root]['members'][name] = member
        activation = load('response_consumption', '/guard/finite/operation_activation.py')
        response_path = Path(root) / receipt['member']
        if not response_path.exists():
            if response_path.is_symlink():
                raise RuntimeError('primary_runtime_retired_response_symlink')
            outputs[root]['members'].pop(receipt['member'], None)
            continue
        response = response_member(receipt, child, Path(root), activation)
        old = outputs[root]['members'].get(receipt['member'])
        if old is not None and old != response:
            raise RuntimeError('primary_runtime_prior_response_drift')
        outputs[root]['members'][receipt['member']] = response
    for root, output in outputs.items():
        for name in temporary_names[root]:
            path = Path(root) / name
            if not path.exists():
                if path.is_symlink():
                    raise RuntimeError('primary_runtime_retired_response_symlink')
                output['members'].pop(name, None)
    return outputs


def primary_inventory(root, runtime_outputs, observed=None, declared_external=None):
    """Separate dependency inputs from exact observer-declared runtime outputs."""
    # Inventory each individual dependency-domain member with the original shape.
    # External targets require an exact prior original-operation declaration.
    activation = load('primary_cache_read_identity', '/guard/finite/operation_activation.py')
    result = {}
    if observed is None:
        observed = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        name = path.relative_to(root).as_posix()
        if info.st_uid != 20000:
            raise RuntimeError('primary_cache_member_owner_drift')
        if stat.S_ISDIR(info.st_mode):
            result[name] = {'type': 'directory', 'mode': stat.S_IMODE(info.st_mode)}
        elif stat.S_ISREG(info.st_mode):
            read = activation.identity(path)
            if path.lstat().st_uid != info.st_uid or path.lstat().st_nlink != info.st_nlink:
                raise RuntimeError('primary_cache_file_custody_race')
            observed[name] = {'file': read, 'uid': info.st_uid, 'nlink': info.st_nlink}
            result[name] = {'type': 'file', 'mode': stat.S_IMODE(info.st_mode),
                            'size': info.st_size, 'sha256': read['sha256']}
        elif stat.S_ISLNK(info.st_mode):
            target = path.resolve(strict=True)
            if not target.is_relative_to(root):
                matches = [output for directory, output in runtime_outputs.items()
                           if path.is_relative_to(directory)
                           and str(path.relative_to(directory)) in output['members']]
                if not matches and declared_external is not None and hashlib.sha256(name.encode()).hexdigest() in declared_external:
                    result[name] = {'type': 'symlink', 'target': os.readlink(path), 'resolved_sha256': digest(target)}
                    observed[name] = {'link': [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_ctime_ns],
                                      'target': os.readlink(path), 'resolved': str(target)}
                    continue
                if len(matches) != 1:
                    raise RuntimeError('primary_cache_undeclared_external_link')
                declared = matches[0]['members'][str(path.relative_to(matches[0]['root']))]
                activation = load('primary_link_identity', '/guard/finite/operation_activation.py')
                if (declared['type'] != 'symlink' or os.readlink(path) != declared['target']
                        or [info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                            info.st_ctime_ns] != declared['identity']
                        or activation.identity(target) != declared['target_identity']
                        or target.stat().st_uid != declared['target_uid']
                        or path.lstat() != info):
                    raise RuntimeError('primary_cache_declared_link_drift')
            result[name] = {'type': 'symlink', 'target': os.readlink(path)}
            if target.is_file():
                result[name]['resolved_sha256'] = digest(target)
        else:
            raise RuntimeError('primary_cache_nonregular_member')
        if stat.S_ISDIR(info.st_mode):
            observed[name] = {'directory': [info.st_dev, info.st_ino, info.st_mode, info.st_uid]}
        elif stat.S_ISLNK(info.st_mode):
            observed[name] = {'link': [info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                                       info.st_ctime_ns], 'target': os.readlink(path),
                              'resolved': str(target)}
            if path.lstat() != info:
                raise RuntimeError('primary_cache_link_read_race')
    return result


def primary_cache_tree(spec, emit=None, operations=None):
    """Validate the primary's whole native seed plus original finite UV additions.

    Extra dependency wheels have immutable image provenance. A writable member
    that was not in that seed still needs the original finite cache predicates;
    observing it here cannot turn it into an authorized input.
    """
    primary = spec['primary_producer']
    if spec['cache'] != '/work/cache' or spec['base'] != '/usr/local/bin/python-primary-audit':
        raise RuntimeError('source_primary_cache_context_drift')
    closure = load('primary_cache_closure', '/guard/dependency_closure.py')
    seed = Path('/opt/primary-cache')
    expected = closure.inventory(seed)
    if expected != primary['cache_seed_inventory']:
        raise RuntimeError('source_primary_cache_seed_drift')
    root = Path(spec['cache'])
    runtime_outputs = original_runtime_outputs(spec, operations)
    build = operations.require(spec['output'], 'source-build')
    produced_cache = read_cache_operation(spec, build)
    external = set(produced_cache['external_links'])
    actual_domain, _ = cache_view(spec, external)
    if actual_domain != produced_cache['entries']:
        raise RuntimeError('primary_cache_current_produced_output_drift')
    observed = {}
    current = primary_inventory(root, runtime_outputs, observed, external)
    for directory, output in runtime_outputs.items():
        actual_members = {str((root / name).relative_to(directory)) for name in current
                          if (root / name).is_relative_to(directory) and root / name != Path(directory)}
        if actual_members != set(output['members']):
            raise RuntimeError('primary_cache_runtime_membership_drift')
    for name, item in expected.items():
        wanted = dict(item)
        if item['type'] == 'symlink':
            target = (seed / name).resolve(strict=True)
            if not target.is_relative_to(seed) or not target.is_dir():
                raise RuntimeError('source_primary_cache_seed_link')
            wanted['target'] = str(root / target.relative_to(seed))
        if current.get(name) != wanted:
            raise RuntimeError('source_primary_cache_input_drift')
    links = [root / name for name, item in current.items() if item['type'] == 'symlink'
             and len(Path(name).parts) == 5
             and Path(name).parts[:2] == ('wheels-v6', 'index')
             and Path(name).parts[3:] == ('setuptools', '84.0.0-py3-none-any')]
    if len(links) != 1:
        raise RuntimeError('source_cache_link_cardinality')
    link = links[0]
    target = link.resolve()
    if target.parent != root / 'archive-v0' or target.is_symlink():
        raise RuntimeError('source_cache_unknown_link')
    import zipfile
    with zipfile.ZipFile(spec['wheel']) as archive:
        payload = {n: archive.read(n) for n in archive.namelist() if not n.endswith('/')}
    actual = {p.relative_to(target).as_posix(): p.read_bytes()
              for p in target.rglob('*') if p.is_file()}
    if actual != payload:
        raise RuntimeError('source_cache_selected_wheel_drift')
    fixed = {'.gitignore': b'*', '.lock': b'',
             'CACHEDIR.TAG': b'Signature: 8a477f597d28d172789f06886806bc55',
             'sdists-v9/.git': b'', 'sdists-v9/.gitignore': b''}
    known_files = set(expected) | set(fixed)
    known_files.update(name for name, item in current.items()
                       if item['type'] == 'file' and len(Path(name).parts) == 3
                       and Path(name).parts[0] == 'interpreter-v4' and Path(name).suffix == '.msgpack')
    for directory, output in runtime_outputs.items():
        prefix = Path(directory).relative_to(root)
        known_files.add(prefix.as_posix())
        known_files.update((prefix / name).as_posix() for name in output['members'])
    known_directories = {parent.as_posix() for name in known_files
                         for parent in Path(name).parents if parent != Path('.')}
    # Re-evaluate every complete file byte and every link on each consumption.
    # Only original UV interpreter records/metadata may extend the sealed seed.
    for name, item in current.items():
        runtime_matches = [output for directory, output in runtime_outputs.items()
                           if (root / name).is_relative_to(directory)]
        if runtime_matches:
            if len(runtime_matches) != 1:
                raise RuntimeError('primary_cache_runtime_overlap')
            output = runtime_matches[0]
            path = root / name
            relative = path.relative_to(output['root']).as_posix()
            declared = output['members'].get(relative)
            if relative != '.' and declared is None:
                raise RuntimeError('primary_cache_runtime_extra_member')
            activation = load('primary_runtime_file', '/guard/finite/operation_activation.py')
            info = path.lstat()
            if relative == '.':
                if [info.st_dev, info.st_ino, info.st_mode, info.st_uid] != output['root_identity']:
                    raise RuntimeError('primary_cache_runtime_root_drift')
            elif declared['type'] == 'file':
                if activation.identity(path) != declared['file'] or info.st_uid != declared['uid'] or info.st_nlink != declared['nlink']:
                    raise RuntimeError('primary_cache_runtime_file_drift')
            elif declared['type'] == 'directory':
                if [info.st_dev, info.st_ino, info.st_mode, info.st_uid] != declared['identity']:
                    raise RuntimeError('primary_cache_runtime_directory_drift')
            elif declared['type'] == 'symlink':
                target = path.resolve(strict=True)
                current_target = activation.identity(target) if target.is_file() else {
                    'directory': [target.stat().st_dev, target.stat().st_ino, target.stat().st_mode]}
                if ([info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_ctime_ns] != declared['identity']
                        or os.readlink(path) != declared['target'] or current_target != declared['target_identity']
                        or target.stat().st_uid != declared['target_uid']
                        or path.lstat() != info):
                    raise RuntimeError('primary_cache_runtime_link_drift')
            else:
                raise RuntimeError('primary_cache_runtime_member_type')
            continue
        if name in expected:
            continue
        if hashlib.sha256(name.encode()).hexdigest() in produced_cache['entries']:
            continue
        if item['type'] == 'directory':
            if name not in known_directories:
                if emit is not None:
                    emit({'kind': 'primary_cache_unbound_member', 'member_type': 'directory',
                          'member_sha256': hashlib.sha256(name.encode()).hexdigest()})
                raise RuntimeError('source_primary_cache_unbound_directory')
            continue
        if item['type'] != 'file':
            raise RuntimeError('source_primary_cache_unbound_link')
        path = root / name
        parts = Path(name).parts
        permitted = (len(parts) == 3 and parts[0] == 'interpreter-v4'
                     and path.suffix == '.msgpack') or name == str(link.relative_to(root)) + '.rev'
        if name in fixed:
            if path.read_bytes() != fixed[name]:
                raise RuntimeError('source_cache_metadata_drift')
        elif not permitted:
            if emit is not None:
                emit({'kind': 'primary_cache_unbound_member', 'member_type': 'file',
                      'member_sha256': hashlib.sha256(name.encode()).hexdigest()})
            raise RuntimeError('source_primary_cache_unbound_member')
    rows = []
    activation = load('primary_cache_identity', '/guard/finite/operation_activation.py')
    final_names = set()
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        final_names.add(name)
        if name not in observed:
            raise RuntimeError('primary_cache_late_extra_member')
        info = path.lstat()
        original = observed[name]
        if info.st_uid != 20000:
            raise RuntimeError('primary_cache_late_owner_drift')
        if path.is_symlink():
            if original != {'link': [info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                                      info.st_ctime_ns], 'target': os.readlink(path),
                            'resolved': str(path.resolve(strict=True))}:
                raise RuntimeError('primary_cache_late_link_drift')
            rows.append({'path': str(path), 'target': str(path.resolve()), 'inode': info.st_ino})
        elif path.is_dir():
            info = path.lstat()
            if original != {'directory': [info.st_dev, info.st_ino, info.st_mode, info.st_uid]}:
                raise RuntimeError('primary_cache_late_directory_drift')
            rows.append({'path': str(path), 'directory': [info.st_dev, info.st_ino, info.st_mode]})
        else:
            # Use the original inode/ctime/full-byte file identity shape, so
            # build-to-install comparison retains its original failure model.
            current_file = activation.identity(path)
            if original != {'file': current_file, 'uid': info.st_uid, 'nlink': info.st_nlink}:
                raise RuntimeError('primary_cache_late_file_drift')
            rows.append(current_file)
    if final_names != set(observed):
        raise RuntimeError('primary_cache_late_missing_member')
    final_domain, _ = cache_view(spec, external)
    if final_domain != produced_cache['entries']:
        raise RuntimeError('primary_cache_late_producer_output_drift')
    return rows


def dependency_diagnostic(site):
    """Closed current dependency comparison; this result supplies no authority."""
    site = Path(site)
    mirror = Path('/opt/primary-deps/lib/python3.13/site-packages')
    if site != Path('/source/.venv/lib/python3.13/site-packages'):
        return {'kind': 'primary_dependency_comparison', 'expected_primary_site': False,
                'requested_root_sha256': hashlib.sha256(str(site).encode()).hexdigest()}
    def files(root):
        result = {}
        for path in sorted(root.rglob('*')):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            name = path.relative_to(root).as_posix()
            result[name] = {'type': 'file' if stat.S_ISREG(info.st_mode) else 'other',
                            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid,
                            'sha256': digest(path) if stat.S_ISREG(info.st_mode) else None}
        return result
    actual, seed = files(site), files(mirror)
    missing, extra = sorted(set(seed) - set(actual)), sorted(set(actual) - set(seed))
    changed = sorted(n for n in set(actual) & set(seed) if actual[n]['type'] != seed[n]['type']
                     or actual[n]['sha256'] != seed[n]['sha256'])
    import zipfile
    with zipfile.ZipFile('/opt/source-bootstrap/wheelhouse/setuptools-84.0.0-py3-none-any.whl') as archive:
        backend = {n for n in archive.namelist() if not n.endswith('/')}
    backend.update('setuptools-84.0.0.dist-info/' + n for n in ('INSTALLER', 'REQUESTED', 'uv_cache.json'))
    activation = load('dependency_cache_diagnostic', '/guard/finite/operation_activation.py')
    checked = []
    cache_error = None
    try:
        checked = activation.verify_caches(site)
    except Exception as error:
        cache_error = hashlib.sha256(str(error).encode()).hexdigest()
    checked_names = {str(Path(item['cache']['path']).relative_to(site)): item for item in checked}
    def classification(name):
        if name.endswith('.pyc'):
            item = checked_names.get(name)
            if item is None:
                return 'unverified-bytecode'
            source_name = str(Path(item['source']['path']).relative_to(site))
            if source_name not in seed or item['source']['sha256'] != seed[source_name]['sha256']:
                return 'bytecode-source-not-in-mirror'
            return 'exact-mirror-source-bytecode'
        if name.startswith('unrest_harness-0.4.7.dist-info/'):
            leaf = Path(name).name
            return leaf if leaf in {'METADATA', 'WHEEL', 'RECORD', 'entry_points.txt',
                                   'INSTALLER', 'REQUESTED', 'direct_url.json', 'uv_cache.json'} else 'other'
        if name == '__editable__.unrest_harness-0.4.7.pth':
            return 'editable-pth'
        return 'other'
    extra_classes = {}
    changed_classes = {}
    for names, counts in ((extra, extra_classes), (changed, changed_classes)):
        for name in names:
            label = classification(name)
            counts[label] = counts.get(label, 0) + 1
    # Non-cache outputs must not disappear behind a large sorted cache prefix.
    sample = sorted(extra, key=lambda name: (name.endswith('.pyc'), name))[:16]
    rows = []
    for name in sample:
        row = {'name_sha256': hashlib.sha256(name.encode()).hexdigest(), **actual[name]}
        if name == '__editable__.unrest_harness-0.4.7.pth':
            row['exact_source_path'] = row['type'] == 'file' and (site / name).read_bytes() == b'/source/src\n'
        row['class'] = classification(name)
        rows.append(row)
    changed_rows = [{'name_sha256': hashlib.sha256(name.encode()).hexdigest(),
                     'class': classification(name), 'actual': actual[name], 'mirror': seed[name]}
                    for name in changed[:16]]
    return {'kind': 'primary_dependency_comparison', 'expected_primary_site': True,
            'actual_files': len(actual), 'mirror_files': len(seed),
            'missing_count': len(missing), 'extra_count': len(extra), 'changed_count': len(changed),
            'missing_is_exact_backend': set(missing) == backend,
            'missing_names_sha256': hashed(missing), 'extra_names_sha256': hashed(extra),
            'changed_names_sha256': hashed(changed), 'extra': rows,
            'extra_classes': extra_classes, 'changed_classes': changed_classes,
            'changed': changed_rows, 'verified_cache_count': len(checked),
            'cache_error_sha256': cache_error, 'authority': False}
