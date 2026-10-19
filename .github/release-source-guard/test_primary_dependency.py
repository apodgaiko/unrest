"""PRIMARY output derivation and real Linux response-retirement ordering."""
from __future__ import annotations

import hashlib
import ast
import importlib.util
import io
import os
import json
import py_compile
import stat
from pathlib import Path
import sys
import zipfile
from types import SimpleNamespace

import pytest

from producer_outputs import record_hash

ROOT = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('primary_dependency_under_test', ROOT / 'primary_dependency.py')
assert SPEC is not None and SPEC.loader is not None
dependency = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dependency)


def wheel(change='none'):
    import csv
    dist = dependency.DIST
    payload = {dist + '/' + name: b'public metadata\n' for name in (
        'METADATA', 'WHEEL', 'entry_points.txt', 'top_level.txt', 'licenses/LICENSE', 'licenses/NOTICE')}
    payload[dependency.PTH] = b'/source/src\n'
    record = dist + '/RECORD'
    rows = [[name, *record_hash(body)] for name, body in payload.items()]
    rows.append([record, '', ''])
    stream = io.StringIO(newline='')
    csv.writer(stream, lineterminator='\n').writerows(sorted(rows))
    payload[record] = stream.getvalue().encode()
    if change == 'pth':
        payload[dependency.PTH] = b'/foreign\n'
    elif change == 'extra':
        payload['unrest_harness/__init__.py'] = b'foreign project code'
    elif change == 'missing':
        del payload[dist + '/WHEEL']
    elif change == 'metadata':
        payload[dist + '/METADATA'] += b'changed'
    elif change == 'record':
        payload[record] += payload[record].splitlines(keepends=True)[0]
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as archive:
        for name, body in payload.items():
            item = zipfile.ZipInfo(name)
            item.external_attr = (0o120777 if change == 'link' else 0o100644) << 16
            archive.writestr(item, body)
        if change == 'duplicate':
            archive.writestr(dependency.PTH, payload[dependency.PTH])
    return out.getvalue(), payload


def test_original_editable_wheel_complete_mapping():
    body, payload = wheel()
    assert dependency.wheel_payload(body) == payload


@pytest.mark.parametrize('change', ['pth', 'extra', 'missing', 'metadata', 'record', 'link', 'duplicate'])
def test_editable_output_refuses_unknown_or_changed_members(change):
    body, _ = wheel(change)
    with pytest.raises(RuntimeError):
        dependency.wheel_payload(body)


@pytest.mark.parametrize('change', ['none', 'wrong_owner', 'wrong_group', 'link', 'directory', 'replace_on_open'])
def test_stable_file_acquisition(tmp_path, monkeypatch, change):
    path = tmp_path / 'output'
    path.write_bytes(b'original response')
    uid, gid = path.stat().st_uid, path.stat().st_gid
    if change == 'wrong_owner':
        uid += 1
    elif change == 'wrong_group':
        gid += 1
    elif change == 'link':
        other = tmp_path / 'other'
        path.rename(other)
        path.symlink_to(other)
    elif change == 'directory':
        path.unlink()
        path.mkdir()
    elif change == 'replace_on_open':
        original = dependency.os.open
        def replacing(name, flags):
            path.rename(tmp_path / 'retired')
            path.write_bytes(b'foreign replacement')
            return original(name, flags)
        monkeypatch.setattr(dependency.os, 'open', replacing)
    if change == 'none':
        body, row = dependency.read(path, uid, gid)
        assert body == b'original response'
        assert row['sha256'] == hashlib.sha256(body).hexdigest()
        assert row['identity'] == dependency.key(path.lstat())
    else:
        with pytest.raises(RuntimeError):
            dependency.read(path, uid, gid)


@pytest.mark.skipif(sys.platform != 'linux', reason='requires actual Linux ptrace parent-wait ordering')
@pytest.mark.parametrize('selective', [False, True])
def test_original_parent_cannot_retire_response_before_tracer_terminal_wait(tmp_path, selective):
    import linux_trace
    response = tmp_path / 'response'
    retired = tmp_path / 'parent-retired'
    body = (
        'import os\n'
        'child=os.fork()\n'
        'if child == 0:\n'
        f'    with open({str(response)!r}, "wb") as stream: stream.write(b"original response")\n'
        '    os._exit(0)\n'
        'actual, raw=os.waitpid(child, 0)\n'
        'assert actual == child and raw == 0\n'
        f'os.unlink({str(response)!r})\n'
        f'with open({str(retired)!r}, "wb") as stream: stream.write(b"actual parent wait completed")\n'
    )
    argv = [sys.executable, '-I', '-S', '-c', body]
    allowed = [{'path': sys.executable, 'argv': argv, 'environment': {}, 'cwd': os.getcwd(),
                'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}]
    child = os.fork()
    if child == 0:
        try:
            if selective:
                linux_trace.install_observation_filter()
            linux_trace.trace_me()
            os.execve(sys.executable, argv, {})
        finally:
            os._exit(127)
    captured = []
    def tick(trace):
        for row in trace.records:
            if row['kind'] != 'kernel_exit' or row['pid'] == child or captured:
                continue
            assert row['raw'] == 0
            assert not any(wait['kind'] == 'tracer_terminal_wait' and wait['pid'] == row['pid']
                           for wait in trace.records)
            assert not retired.exists()
            assert response.read_bytes() == b'original response'
            captured.append(row['pid'])
    result = linux_trace.OwnedTrace(child, allowed, timeout=30, selective=selective, on_tick=tick).run()
    assert result['root_parent_wait_raw'] == 0 and not result['poison']
    assert len(captured) == 1 and not response.exists() and retired.exists()
    waits = [row for row in result['records'] if row['kind'] == 'original_parent_wait4']
    assert [(row['parent'], row['child'], row['raw']) for row in waits] == [(child, captured[0], 0)]


@pytest.mark.parametrize('suffix', ['01', '02', '03', '04', '05', '06',
                                    '00', '07', '1', '01-extra', '', 'foreign'])
@pytest.mark.parametrize('workflow', ['v0.4.6 source guard readiness', 'CI', 'foreign'])
def test_finite_dependency_controller_refs(suffix, workflow):
    tree = ast.parse((ROOT / 'ci_shell.py').read_bytes())
    gate = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                and isinstance(node.body[0], ast.Raise)
                and any(isinstance(child, ast.Constant) and child.value == 'primary_test_workflow_identity'
                        for child in ast.walk(node.body[0])))
    environment = {'GITHUB_WORKFLOW': workflow,
                   'GITHUB_REF': 'refs/heads/codex/source-guard-structured-20261018-primary-dependency-' + suffix}
    refusal = eval(compile(ast.Expression(gate.test), 'actual_dependency_gate', 'eval'),
                   {'os': SimpleNamespace(environ=environment)})
    assert refusal is not (workflow == 'v0.4.6 source guard readiness'
                           and suffix in {'01', '02', '03', '04', '05', '06'})


@pytest.mark.parametrize('suffix', ['01', '02', '03', '04', '05', '06',
                                    '00', '07', '1', '01-extra', '', 'foreign'])
def test_finite_dependency_evidence_refs(suffix):
    from structured_evidence import identity_check, EvidenceRefused
    row = {'repository': 'apodgaiko/unrest', 'head_sha': 'a' * 40, 'workflow_sha': 'a' * 40,
           'run_id': '1', 'run_attempt': '1', 'support_sha256': 'b' * 64,
           'artifact_name': 'v046-source-primary-source-positive-1-1',
           'workflow_ref': ('apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@'
                            'refs/heads/codex/source-guard-structured-20261018-primary-dependency-' + suffix)}
    if suffix in {'01', '02', '03', '04', '05', '06'}:
        identity_check(row)
    else:
        with pytest.raises(EvidenceRefused):
            identity_check(row)


@pytest.mark.parametrize('tail', ['primary-dependency', 'primary-dependencyx-01',
                                  'primary-dependency01', 'primary-dependency--01',
                                  'primary-dependency-01-extra'])
def test_dependency_family_lookalikes_refused_at_both_gates(tail):
    from structured_evidence import identity_check, EvidenceRefused
    ref = 'refs/heads/codex/source-guard-structured-20261018-' + tail
    row = {'repository': 'apodgaiko/unrest', 'head_sha': 'a' * 40, 'workflow_sha': 'a' * 40,
           'run_id': '1', 'run_attempt': '1', 'support_sha256': 'b' * 64,
           'artifact_name': 'v046-source-primary-source-positive-1-1',
           'workflow_ref': 'apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@' + ref}
    with pytest.raises(EvidenceRefused):
        identity_check(row)
    tree = ast.parse((ROOT / 'ci_shell.py').read_bytes())
    gate = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                and isinstance(node.body[0], ast.Raise)
                and any(isinstance(child, ast.Constant) and child.value == 'primary_test_workflow_identity'
                        for child in ast.walk(node.body[0])))
    assert eval(compile(ast.Expression(gate.test), 'actual_dependency_gate', 'eval'),
                {'os': SimpleNamespace(environ={'GITHUB_WORKFLOW': 'v0.4.6 source guard readiness',
                                               'GITHUB_REF': ref})}) is True


def test_only_primary_compartment_selects_dependency_authority():
    import primary_source_authority
    import primary_dependency_authority
    import owned_multiprocess_authority
    original = primary_source_authority.SourceAuthority
    specialized = primary_dependency_authority.DependencySourceAuthority
    assert specialized.__bases__ == (original,)
    for name in ('resolve', 'producer_profile', 'exec_descriptors', 'pipe_binding', 'finish'):
        assert getattr(specialized, name) is getattr(original, name)
    tree = ast.parse((ROOT / 'primary_compartment.py').read_bytes())
    imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)
               and any(name.asname == 'SourceAuthority' for name in node.names)]
    assert len(imports) == 1 and [(name.name, name.asname) for name in imports[0].names] == [
        ('DependencySourceAuthority', 'SourceAuthority')]
    assert imports[0].module == 'owned_multiprocess_authority'
    selected = owned_multiprocess_authority.DependencySourceAuthority
    assert selected.__bases__ == (owned_multiprocess_authority.OwnedMultiprocessCustody, specialized)
    assert selected.exec_descriptors is owned_multiprocess_authority.OwnedMultiprocessCustody.exec_descriptors
    for name in ('resolve', 'producer_profile', 'pipe_binding', 'finish'):
        assert getattr(selected, name) is getattr(original, name)
    assert {node.name for node in ast.parse((ROOT / 'owned_multiprocess_authority.py').read_bytes()).body
            if isinstance(node, ast.ClassDef)} == {
                'OwnedMultiprocessCustody', 'SourceAuthority', 'DependencySourceAuthority'}


def test_focused_controls_wired_before_original_source():
    tree = ast.parse((ROOT / 'compartment_probe.py').read_bytes())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == 'run'
             and node.args and isinstance(node.args[0], ast.List)
             and any(isinstance(item, ast.Constant) and item.value == 'pytest'
                     for item in node.args[0].elts)]
    assert len(calls) == 1
    arguments = [node.value for node in calls[0].args[0].elts if isinstance(node, ast.Constant)]
    for name in ('test_primary_dependency.py', 'test_primary_dependency_outputs.py',
                 'test_linux_supervisor.py'):
        assert arguments.count('/guard/' + name) == 1


@pytest.fixture
def consumer_site(tmp_path, monkeypatch):
    # Translate only fixture ownership and literal roots. Actual byte reads,
    # inode/ctime comparisons, cache compilation and mutation checks still run.
    site = tmp_path / 'site'
    site.mkdir(mode=0o755)
    source = site / 'data.py'
    source.write_bytes(b'VALUE = 1\n')
    source.chmod(0o644)
    receipts = tmp_path / 'receipts'
    receipts.mkdir()
    image = tmp_path / 'image'
    image.mkdir()
    (image / 'data.py').write_bytes(b'VALUE = 1\n')
    original_read = dependency.read
    def fixture_read(path, uid, gid=None):
        expected_uid = 0 if Path(path).is_relative_to(image) else (
            20001 if Path(path).is_relative_to(receipts) else 20000)
        assert uid == expected_uid
        info = Path(path).lstat()
        body, row = original_read(path, info.st_uid, info.st_gid)
        row['identity'][3:5] = [uid, uid]
        return body, row
    def directories(names):
        wanted = {'.'} | {parent.as_posix() for name in names for parent in Path(name).parents}
        actual = {path.relative_to(site).as_posix(): {
            'identity': dependency.key(path.lstat())[:5], 'links': path.lstat().st_nlink}
                  for path in [site, *site.rglob('*')] if path.is_dir() and not path.is_symlink()}
        if set(actual) != wanted:
            raise RuntimeError('fixture_directory_membership')
        return actual
    monkeypatch.setattr(dependency, 'SITE', site)
    monkeypatch.setattr(dependency, 'IMAGE', image)
    monkeypatch.setattr(dependency, 'RECEIPTS', receipts)
    monkeypatch.setattr(dependency, 'read', fixture_read)
    monkeypatch.setattr(dependency, 'directory_view', directories)
    def metadata():
        files, dirs = {}, {}
        for path in [site, *site.rglob('*')]:
            info = path.lstat()
            name = path.relative_to(site).as_posix()
            if stat.S_ISDIR(info.st_mode):
                dirs[name] = {'identity': dependency.key(info)[:5], 'links': info.st_nlink}
            elif stat.S_ISREG(info.st_mode):
                row = dependency.key(info)
                row[3:5] = [20000, 20000]
                files[name] = row
            else:
                raise RuntimeError('fixture_special_member')
        return files, dirs
    monkeypatch.setattr(dependency, 'site_metadata', metadata)
    actual_statvfs = dependency.os.statvfs
    monkeypatch.setattr(dependency.os, 'statvfs', lambda path: SimpleNamespace(f_flag=os.ST_RDONLY)
                        if Path(path).is_relative_to(image) else actual_statvfs(path))
    source_calls = []
    monkeypatch.setattr(dependency, 'verify_source_inputs', lambda *args: source_calls.append(args))
    actual_path = Path
    activation = ROOT / 'finite/operation_activation.py'
    def mapped_path(path):
        return activation if str(path) == '/guard/finite/operation_activation.py' else actual_path(path)
    monkeypatch.setattr(dependency, 'Path', mapped_path)
    producers = [dict(pid=pid, role=role, parent_wait_raw=0,
                      identity_sha256='a' * 64, profile_sha256='b' * 64)
                 for pid, role in [(11, 'query'), (12, 'editable_backend'), (13, 'editable_backend')]]
    retained = receipts / 'editable-13.whl'
    retained.write_bytes(b'original fixture archive')
    retained.chmod(0o444)
    retained_file = fixture_read(retained, 20001)[1]
    captures = []
    for producer, helper in zip(producers[1:], ('get_requires_for_build_editable', 'build_editable')):
        pid = producer['pid']
        identity = dict(pid=pid, ppid=10, pgid=10, sid=10, uid=20000,
                        start_ticks=pid * 10, clock_ticks_per_second=100, boot_id='fixture-boot')
        producer['identity_sha256'] = hashlib.sha256(json.dumps(
            identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        expected_body = b'[]' if helper.startswith('get_requires') else dependency.WHEEL_NAME.encode()
        row = dict(pid=pid, helper=helper, identity=identity, profile_sha256=producer['profile_sha256'],
                   response={'path': '/work/cache/builds-v0/.tmpfixture/' + helper + '.txt',
                             'identity': [1, pid, 0o100644, 20000, 20000, 1, len(expected_body), 10, 10],
                             'sha256': hashlib.sha256(expected_body).hexdigest()},
                   kernel_exit_raw=0, provisional=True, kernel_exit_index=10,
                   capture_record_count=11, receipt_sha256='d' * 64)
        if helper == 'build_editable':
            row['retained_wheel'] = retained_file
            row['wheel'] = {'path': '/work/cache/built-wheels-v5/fixture/' + dependency.WHEEL_NAME,
                            'identity': [1, 100, 0o100644, 20000, 20000, 1,
                                         len(b'original fixture archive'), 10, 10],
                            'sha256': retained_file['sha256']}
        captures.append(row)
    value = {'schema': 'unrest.v046.primary-dependency-output.v1', 'site': str(site),
             'files': {'data.py': fixture_read(source, 20000)[1]},
             'directories': directories({'data.py'}), 'scripts': {}, 'bootstrap': producers,
             'bootstrap_captures': captures,
             'omitted_backend_members': 346, 'initial_source_bound_caches': 0,
             'wheel': retained_file, 'source_files': [], 'source_custody': {},
             'source_checkpoint_ready': False, 'selected_carrier': None}
    receipt = receipts / 'primary-dependency.json'
    def publish():
        receipt.chmod(0o644) if receipt.exists() else None
        body = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        receipt.write_bytes(body)
        receipt.chmod(0o444)
        return {'path': str(receipt), 'sha256': hashlib.sha256(body).hexdigest(),
                'activation_sha256': hashlib.sha256(activation.read_bytes()).hexdigest()}
    support = publish()
    return SimpleNamespace(site=site, source=source, receipt=receipt, value=value,
                           support=support, publish=publish, source_calls=source_calls,
                           read=fixture_read, directories=directories, image=image, metadata=metadata)


def test_consumer_reacquires_complete_file_bytes(consumer_site):
    fixture = consumer_site
    observed = dependency.verify(fixture.site, fixture.support)
    assert observed['kind'] == 'primary_dependency_consumption'
    assert observed['files'] == 1 and observed['source_bound_caches'] == 0
    assert len(fixture.source_calls) == 1


@pytest.mark.parametrize('change', ['unknown_file', 'missing_file', 'changed_bytes', 'replace_same_bytes',
    'changed_mode', 'link', 'extra_empty_directory', 'directory_identity', 'receipt_mode',
    'receipt_hardlink', 'receipt_digest', 'foreign_site', 'foreign_receipt', 'foreign_support',
    'schema', 'extra_schema', 'foreign_role', 'duplicate_pid', 'nonzero_wait', 'boolean_wait',
    'unknown_birth', 'missing_query', 'activation_pin', 'poison_selection', 'ready_true',
    'missing_capture', 'capture_extra_field', 'capture_helper', 'capture_profile', 'capture_birth',
    'capture_response_bytes', 'capture_response_route', 'capture_response_owner',
    'capture_response_links', 'capture_response_mode', 'capture_exit', 'capture_late',
    'wheel_route', 'retained_wheel_bytes', 'retained_wheel_mode', 'retained_wheel_replacement'])
def test_consumer_default_denies_drift_and_foreign_lineage(consumer_site, change):
    fixture = consumer_site
    site, support = fixture.site, dict(fixture.support)
    if change == 'unknown_file':
        (site / 'unknown.txt').write_bytes(b'unknown')
    elif change == 'missing_file':
        fixture.source.unlink()
    elif change == 'changed_bytes':
        fixture.source.write_bytes(b'VALUE = 2\n')
    elif change == 'replace_same_bytes':
        fixture.source.rename(site.parent / 'retired')
        fixture.source.write_bytes(b'VALUE = 1\n')
    elif change == 'changed_mode':
        fixture.source.chmod(0o777)
    elif change == 'link':
        fixture.source.rename(site.parent / 'retired')
        fixture.source.symlink_to(site.parent / 'retired')
    elif change == 'extra_empty_directory':
        (site / 'unknown').mkdir()
    elif change == 'directory_identity':
        fixture.value['directories']['.']['identity'][1] += 1
        support = fixture.publish()
    elif change == 'receipt_mode':
        fixture.receipt.chmod(0o644)
    elif change == 'receipt_hardlink':
        os.link(fixture.receipt, site.parent / 'receipt-alias')
    elif change == 'receipt_digest':
        support['sha256'] = 'a' * 64
    elif change == 'foreign_site':
        site = site / 'foreign'
    elif change == 'foreign_receipt':
        support['path'] = str(fixture.receipt.parent / 'foreign.json')
    elif change == 'foreign_support':
        support['unknown'] = 'a' * 64
    elif change == 'activation_pin':
        support['activation_sha256'] = 'a' * 64
    elif change.startswith('retained_wheel_'):
        retained = Path(fixture.value['wheel']['path'])
        if change == 'retained_wheel_bytes':
            retained.chmod(0o644)
            retained.write_bytes(b'changed archive')
            retained.chmod(0o444)
        elif change == 'retained_wheel_mode':
            retained.chmod(0o644)
        else:
            retained.rename(retained.with_suffix('.retired'))
            retained.write_bytes(b'original fixture archive')
            retained.chmod(0o444)
    else:
        if change == 'schema':
            fixture.value['schema'] = 'foreign'
        elif change == 'extra_schema':
            fixture.value['unknown'] = True
        elif change == 'foreign_role':
            fixture.value['bootstrap'][0]['role'] = 'foreign'
        elif change == 'duplicate_pid':
            fixture.value['bootstrap'][1]['pid'] = fixture.value['bootstrap'][0]['pid']
        elif change == 'nonzero_wait':
            fixture.value['bootstrap'][0]['parent_wait_raw'] = 256
        elif change == 'boolean_wait':
            fixture.value['bootstrap'][0]['parent_wait_raw'] = False
        elif change == 'unknown_birth':
            fixture.value['bootstrap'][0]['identity_sha256'] = 'unknown'
        elif change == 'missing_query':
            fixture.value['bootstrap'].pop(0)
        elif change == 'poison_selection':
            fixture.value['selected_carrier'] = 'foreign'
        elif change == 'ready_true':
            fixture.value['source_checkpoint_ready'] = True
        elif change == 'missing_capture':
            fixture.value['bootstrap_captures'].pop()
        elif change.startswith('capture_'):
            row = fixture.value['bootstrap_captures'][0]
            if change == 'capture_extra_field':
                row['foreign'] = True
            elif change == 'capture_helper':
                row['helper'] = 'foreign'
            elif change == 'capture_profile':
                row['profile_sha256'] = 'e' * 64
            elif change == 'capture_birth':
                row['identity']['start_ticks'] += 1
            elif change == 'capture_response_bytes':
                row['response']['sha256'] = 'e' * 64
            elif change == 'capture_response_route':
                row['response']['path'] = '/foreign/get_requires_for_build_editable.txt'
            elif change == 'capture_response_owner':
                row['response']['identity'][3] = 20001
            elif change == 'capture_response_links':
                row['response']['identity'][5] = 2
            elif change == 'capture_response_mode':
                row['response']['identity'][2] = 0o100777
            elif change == 'capture_exit':
                row['kernel_exit_raw'] = 256
            elif change == 'capture_late':
                row['capture_record_count'] = row['kernel_exit_index']
        elif change == 'wheel_route':
            fixture.value['bootstrap_captures'][1]['wheel']['path'] = '/foreign/' + dependency.WHEEL_NAME
        support = fixture.publish()
    with pytest.raises((RuntimeError, FileNotFoundError)):
        dependency.verify(site, support)


@pytest.mark.parametrize('change', ['none', 'magic', 'header', 'code', 'mode', 'hardlink'])
def test_consumer_requires_exact_current_source_cache(consumer_site, change):
    import marshal
    fixture = consumer_site
    cache = Path(py_compile.compile(str(fixture.source), doraise=True))
    cache.chmod(0o644)
    body = cache.read_bytes()
    if change == 'magic':
        cache.write_bytes(b'BAD!' + body[4:])
    elif change == 'header':
        cache.write_bytes(body[:4] + (15).to_bytes(4, 'little') + body[8:])
    elif change == 'code':
        foreign = compile(b'VALUE = 2\n', str(fixture.source), 'exec', dont_inherit=True)
        cache.write_bytes(body[:16] + marshal.dumps(foreign))
    elif change == 'mode':
        cache.chmod(0o777)
    elif change == 'hardlink':
        os.link(cache, fixture.site.parent / 'foreign-cache-alias')
    if change == 'none':
        result = dependency.verify(fixture.site, fixture.support)
        assert result['source_bound_caches'] == 1
    else:
        with pytest.raises(RuntimeError):
            dependency.verify(fixture.site, fixture.support)


@pytest.mark.parametrize('phase', ['before_full_read', 'after_full_read', 'late_membership'])
def test_consumer_refuses_mutation_before_consumption(consumer_site, monkeypatch, phase):
    fixture = consumer_site
    original = fixture.read
    calls = 0
    def racing(path, uid, gid=None):
        nonlocal calls
        if Path(path) == fixture.source:
            calls += 1
            if phase == 'before_full_read' and calls == 1:
                fixture.source.write_bytes(b'VALUE = 2\n')
        result = original(path, uid, gid)
        if Path(path) == fixture.source:
            if phase == 'after_full_read' and calls == 1:
                fixture.source.write_bytes(b'VALUE = 2\n')
            elif phase == 'late_membership' and calls == 1:
                (fixture.site / 'late.txt').write_bytes(b'late')
        return result
    monkeypatch.setattr(dependency, 'read', racing)
    with pytest.raises(RuntimeError):
        dependency.verify(fixture.site, fixture.support)


def test_declaration_duplicate_fields_refused():
    with pytest.raises(RuntimeError, match='duplicate_field'):
        dependency.decode(b'{"schema":"first","schema":"second"}')


def test_mutable_source_observation_cannot_authorize_foreign_cache(consumer_site, monkeypatch):
    import marshal
    fixture = consumer_site
    cache = Path(py_compile.compile(str(fixture.source), doraise=True))
    payload = cache.read_bytes()
    foreign = compile(b'VALUE = 2\n', str(fixture.source), 'exec', dont_inherit=True)
    cache.write_bytes(payload[:16] + marshal.dumps(foreign))
    cache.chmod(0o644)
    original = Path.read_bytes
    def transient_source(path):
        return b'VALUE = 2\n' if path == fixture.source else original(path)
    monkeypatch.setattr(Path, 'read_bytes', transient_source)
    with pytest.raises(RuntimeError, match='cache_immutable_code'):
        dependency.verify(fixture.site, fixture.support)


@pytest.mark.skipif(sys.platform != 'linux', reason='requires the actual closed source UID/GID20000')
@pytest.mark.parametrize('change', ['none', 'extra_empty_directory', 'link', 'wrong_mode', 'late_member'])
def test_actual_site_census_matches_original_directory_and_file_predicates(tmp_path, monkeypatch, change):
    assert os.getuid() == os.getgid() == 20000
    site = tmp_path / 'site'
    site.mkdir(mode=0o755)
    (site / 'package').mkdir(mode=0o755)
    source = site / 'package/module.py'
    source.write_bytes(b'VALUE = 1\n')
    source.chmod(0o644)
    monkeypatch.setattr(dependency, 'SITE', site)
    if change == 'link':
        (site / 'alias').symlink_to(source)
    elif change == 'wrong_mode':
        (site / 'package').chmod(0o777)
    if change in {'link', 'wrong_mode'}:
        with pytest.raises(RuntimeError):
            dependency.site_metadata()
        return
    first, dirs = dependency.site_metadata()
    assert set(first) == {'package/module.py'}
    assert first['package/module.py'] == dependency.read(source, 20000)[1]['identity']
    assert dirs == dependency.directory_view(first)
    if change == 'extra_empty_directory':
        (site / 'unknown').mkdir(mode=0o755)
        with pytest.raises(RuntimeError):
            dependency.directory_view(first)
    elif change == 'late_member':
        (site / 'late.txt').write_bytes(b'unknown')
        final, _ = dependency.site_metadata()
        assert set(final) != set(first)


@pytest.fixture
def source_inputs(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    root.mkdir()
    src = root / 'src'
    src.mkdir()
    project = root / 'pyproject.toml'
    project.write_bytes(b'[project]\nname="public-fixture"\nversion="1"\n')
    files, custody = [], {str(src): dependency.key(src.lstat())}
    for path in [project]:
        body, row = dependency.read(path, path.stat().st_uid, path.stat().st_gid)
        info = path.stat()
        files.append(dict(path=str(path), device=info.st_dev, inode=info.st_ino, size=info.st_size,
                          mode=info.st_mode, mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
                          sha256=hashlib.sha256(body).hexdigest()))
        custody[str(path)] = row['identity']
    monkeypatch.setattr(dependency, 'SOURCE_ROOT', root)
    original_statvfs = dependency.os.statvfs
    def readonly(path):
        if Path(path).is_relative_to(root):
            return SimpleNamespace(f_flag=os.ST_RDONLY)
        return original_statvfs(path)
    monkeypatch.setattr(dependency.os, 'statvfs', readonly)
    return SimpleNamespace(root=root, src=src, project=project, files=files, custody=custody)


def test_source_input_custody_reacquired(source_inputs):
    dependency.verify_source_inputs(source_inputs.files, source_inputs.custody)


@pytest.mark.parametrize('change', ['bytes', 'inode', 'mode', 'directory', 'foreign',
                                     'duplicate', 'schema', 'writable', 'lost'])
def test_source_input_custody_denies_drift(source_inputs, monkeypatch, change):
    fixture = source_inputs
    if change == 'bytes':
        fixture.project.write_bytes(b'foreign source metadata')
    elif change == 'inode':
        fixture.project.rename(fixture.root / 'retired')
        fixture.project.write_bytes(b'[project]\nname="public-fixture"\nversion="1"\n')
    elif change == 'mode':
        fixture.project.chmod(0o777)
    elif change == 'directory':
        (fixture.src / 'unknown').mkdir()
    elif change == 'foreign':
        fixture.files[0]['path'] = '/foreign/pyproject.toml'
    elif change == 'duplicate':
        fixture.files.append(dict(fixture.files[0]))
    elif change == 'schema':
        fixture.files[0]['foreign'] = True
    elif change == 'writable':
        monkeypatch.setattr(dependency.os, 'statvfs', lambda path: SimpleNamespace(f_flag=0))
    elif change == 'lost':
        fixture.project.unlink()
    with pytest.raises((RuntimeError, FileNotFoundError)):
        dependency.verify_source_inputs(fixture.files, fixture.custody)


@pytest.mark.skipif(sys.platform != 'linux', reason='requires the actual x86_64 Linux statx ABI used by UV')
def test_uv_default_source_cache_key_matches_current_kernel_inputs(source_inputs):
    fixture = source_inputs
    value = dependency.source_cache_info(fixture.files, fixture.custody)
    ctime = fixture.project.stat().st_ctime_ns
    assert value['timestamp'] == {'secs_since_epoch': ctime // 1_000_000_000,
                                  'nanos_since_epoch': ctime % 1_000_000_000}
    assert value['commit'] is None and value['tags'] is None and value['env'] == {}
    directory = value['directories']['src']
    if type(directory) is int:
        assert directory == fixture.src.stat().st_ino
    else:
        assert set(directory) == {'secs_since_epoch', 'nanos_since_epoch'}
        assert directory['secs_since_epoch'] > 0 and 0 <= directory['nanos_since_epoch'] < 1_000_000_000


def test_unknown_uv_cache_key_never_falls_back_to_observation(source_inputs):
    fixture = source_inputs
    body = b'[tool.uv]\ncache-keys=["foreign"]\n'
    fixture.project.write_bytes(body)
    info = fixture.project.stat()
    fixture.files[0].update(size=info.st_size, mtime_ns=info.st_mtime_ns,
                            ctime_ns=info.st_ctime_ns, sha256=hashlib.sha256(body).hexdigest())
    fixture.custody[str(fixture.project)] = dependency.key(info)
    with pytest.raises(RuntimeError, match='custom_cache_keys'):
        dependency.source_cache_info(fixture.files, fixture.custody)
