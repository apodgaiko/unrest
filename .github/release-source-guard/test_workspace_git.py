"""Finite original Git scopes and maintenance custody refuse unrelated inputs."""
import ast
import hashlib
import json
from pathlib import Path
import zlib

import pytest
import fixture_git_maintenance as maintenance
from finite.workspace_git_data import CASES, FIXTURE_COMMITS, PINS, SITES
from primary_policy import TEST_WORKSPACE_GIT_CASES, root_seconds
from primary_source_inputs import test_plan as plan_for

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(__file__).parent / 'finite/workspace_git_data.py'


def test_scope_is_all_original_cases_from_both_unchanged_modules():
    expected = []
    for name in ('tests/test_evolution.py', 'tests/test_workspaces.py'):
        body = (ROOT / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == PINS[name]
        for node in ast.parse(body).body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.name.startswith('test_'):
                continue
            params = [d for d in node.decorator_list if isinstance(d, ast.Call)
                      and ast.unparse(d.func) == 'pytest.mark.parametrize']
            if params:
                assert len(params) == 1 and ast.literal_eval(params[0].args[0]) == 'boundary'
                expected.extend(name + '::' + node.name + '[' + p + ']'
                                for p in ast.literal_eval(params[0].args[1]))
            else:
                expected.append(name + '::' + node.name)
    assert CASES == TEST_WORKSPACE_GIT_CASES == tuple(expected) and len(CASES) == 24
    script = ('env -u CODEX_PATH uv run pytest -q ' + ' '.join(CASES)).encode()
    plan = plan_for(script, 'bounded', 'TEST-positive')
    assert plan['timeout_seconds'] == root_seconds(plan) == 600
    assert plan['source_checkpoint_ready'] is False and plan['selected_carrier'] is None
    for changed in (script + b' -k freeze', script.replace(CASES[0].encode(), b'tests/other.py::test_other')):
        with pytest.raises(RuntimeError, match='primary_source_test_script'):
            plan_for(changed, 'bounded', 'TEST-positive')


def test_product_sites_keep_original_bytes_and_exact_call_expressions():
    source = 'src/unrest_harness/workspaces.py'
    body = (ROOT / source).read_bytes()
    assert hashlib.sha256(body).hexdigest() == PINS[source]
    calls = {n.lineno: n for n in ast.walk(ast.parse(body))
             if isinstance(n, ast.Call) and ast.unparse(n.func) == 'self._git'}
    assert set(calls) == set(SITES) and len(calls) == 23
    assert all(hashlib.sha256(ast.dump(calls[line], include_attributes=False).encode()).hexdigest() == site[1]
               for line, site in SITES.items())


def fixture(tmp_path, key):
    relative, line = key
    site = FIXTURE_COMMITS[key]
    root = tmp_path.resolve() / 'pytest/project'
    git = root / '.git'
    (git / 'refs/heads').mkdir(parents=True)
    (git / 'config').write_text('[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\n[user]\nname = ' + site['user'] + '\nemail = ' + site['email'] + '\n')
    (git / 'HEAD').write_bytes(b'ref: refs/heads/main\n')
    body = ('tree ' + '0' * 40 + '\nauthor ' + site['user'] + ' <' + site['email'] + '> 123456 +0000\ncommitter ' + site['user'] + ' <' + site['email'] + '> 123456 +0000\n\n' + site['vector'][-1] + '\n').encode()
    raw = b'commit ' + str(len(body)).encode() + b'\0' + body
    oid = hashlib.sha1(raw).hexdigest()
    target = git / 'objects' / oid[:2] / oid[2:]
    target.parent.mkdir(parents=True)
    target.write_bytes(zlib.compress(raw))
    (git / 'refs/heads/main').write_text(oid + '\n')
    if key == ('tests/test_workspaces.py', 325):
        root = root / '.unrest-runtime/workspaces/trees/self-merge'
        root.mkdir(parents=True)
        admin = git / 'worktrees/self-merge'
        admin.mkdir(parents=True)
        (root / '.git').write_text('gitdir: ' + str(admin) + '\n')
        (admin / 'commondir').write_text('../..\n')
        (admin / 'gitdir').write_text(str(root / '.git') + '\n')
        (admin / 'HEAD').write_text(oid + '\n')
    parent = {'argv': site['vector'], 'cwd': str(root), 'environment': {'PATH': '/usr/bin:/bin'}}
    binding = {'path': str(ROOT / relative), 'line': site['helper_line'], 'function': '_git',
               'caller': site['caller'], 'caller_line': line, 'sha256': site['source_sha256'],
               'expression_ast_sha256': site['expression_ast_sha256']}
    registration = {'class': 'source-literal-git:' + relative + ':' + str(line),
                    'source_binding': binding, 'owner_pid': 20, 'token': 'actual',
                    'case': (relative + '::test_child_commit_is_not_parent_authority' if key == ('tests/test_workspaces.py', 325) else relative + '::test_fixture')}
    selected = {'registration': registration, 'bootstrap_sha256': None, 'owner_pid': 20,
                'token': 'actual', 'cwd': str(root),
                'transformed_argv_sha256': hashlib.sha256(json.dumps(parent['argv']).encode()).hexdigest(),
                'environment_sha256': hashlib.sha256(json.dumps(parent['environment'], sort_keys=True).encode()).hexdigest()}
    env = {**parent['environment'], 'PATH': '/usr/lib/git-core:/usr/bin:/bin',
           'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '', 'GIT_AUTHOR_NAME': site['user'],
           'GIT_AUTHOR_EMAIL': site['email'], 'GIT_AUTHOR_DATE': '@123456 +0000'}
    manifest = {'owned_root': str(tmp_path.resolve()), 'product_pins': {relative: site['source_sha256']},
                'direct_support': {'files': {'/guard/finite/workspace_git_data.py': hashlib.sha256(DATA.read_bytes()).hexdigest()}}}
    return parent, selected, env, str(root), manifest


@pytest.mark.parametrize('key', sorted(FIXTURE_COMMITS))
def test_each_literal_fixture_commit_has_only_its_exact_metadata(tmp_path, key):
    assert maintenance.metadata(*fixture(tmp_path, key), checkout=str(ROOT))


@pytest.mark.parametrize('change', ['class', 'case', 'python', 'owner', 'token', 'cwd', 'argv', 'argv_hash',
                                    'env_hash', 'bootstrap', 'source_pin', 'data_pin', 'helper_line',
                                    'caller', 'callsite', 'expression', 'environment', 'config', 'object'])
def test_any_broken_fixture_binding_or_metadata_refuses(tmp_path, change):
    parent, selected, env, cwd, manifest = fixture(tmp_path, sorted(FIXTURE_COMMITS)[0])
    binding = selected['registration']['source_binding']
    if change in {'class', 'case', 'python'}:
        selected['registration'][change] = 'foreign'
    elif change == 'owner':
        selected['owner_pid'] = 99
    elif change == 'token':
        selected['token'] = 'foreign'
    elif change == 'cwd':
        selected['cwd'] = '/foreign'
    elif change == 'argv':
        parent['argv'] = ['git', 'status']
    elif change == 'argv_hash':
        selected['transformed_argv_sha256'] = 'foreign'
    elif change == 'env_hash':
        selected['environment_sha256'] = 'foreign'
    elif change == 'bootstrap':
        selected['bootstrap_sha256'] = 'foreign'
    elif change == 'source_pin':
        manifest['product_pins'] = {}
    elif change == 'data_pin':
        manifest['direct_support']['files']['/guard/finite/workspace_git_data.py'] = 'foreign'
    elif change == 'helper_line':
        binding['line'] = 0
    elif change == 'caller':
        binding['caller'] = 'foreign'
    elif change == 'callsite':
        binding['caller_line'] = 0
    elif change == 'expression':
        binding['expression_ast_sha256'] = 'foreign'
    elif change == 'environment':
        env['GIT_CONFIG_GLOBAL'] = '/foreign'
    elif change == 'config':
        (Path(cwd) / '.git/config').write_text('[core]\nbare = true\n')
    else:
        target = next((Path(cwd) / '.git/objects').glob('*/*'))
        target.write_bytes(zlib.compress(b'blob 0\0'))
    assert not maintenance.metadata(parent, selected, env, cwd, manifest, checkout=str(ROOT))


@pytest.mark.parametrize('change', ['gitfile', 'commondir', 'backlink', 'head', 'case', 'ordinary'])
def test_linked_fixture_requires_exact_owned_worktree_chain(tmp_path, change):
    parent, selected, env, cwd, manifest = fixture(tmp_path, ('tests/test_workspaces.py', 325))
    root = Path(cwd)
    admin = root.parents[3] / '.git/worktrees/self-merge'
    if change == 'case':
        selected['registration']['case'] = 'tests/test_workspaces.py::test_other'
    elif change == 'ordinary':
        (root / '.git').unlink()
        (root / '.git').mkdir()
    else:
        target = {'gitfile': root / '.git', 'commondir': admin / 'commondir',
                  'backlink': admin / 'gitdir', 'head': admin / 'HEAD'}[change]
        target.write_text('foreign\n')
    assert not maintenance.metadata(parent, selected, env, cwd, manifest, checkout=str(ROOT))


def worktree_child_fixture(tmp_path, site=314):
    from worktree_git_custody import IMAGE, SOURCE
    repository = tmp_path.resolve() / 'pytest/project'
    tree = repository / ('.unrest-runtime/workspaces/trees/candidate-one' if site == 314 else '.unrest-runtime/workspaces/integration-abcdefgh' if site == 616 else '.unrest-runtime/evolution/rollback-abcdefgh')
    admin = repository / '.git/worktrees' / tree.name
    tree.mkdir(parents=True)
    admin.mkdir(parents=True)
    (tree / '.git').write_text('gitdir: ' + str(admin) + '\n')
    (admin / 'gitdir').write_text(str(tree / '.git') + '\n')
    (admin / 'commondir').write_text('../..\n')
    (admin / 'HEAD').write_text('0' * 40 + '\n')
    vector = ['git', 'worktree', 'add', '--detach', *(['--no-checkout'] if site == 314 else []), str(tree), 'a' * 40]
    parent = {'argv': vector, 'cwd': str(repository), 'environment': {'PATH': '/usr/bin:/bin'}}
    binding = {'path': str(ROOT / SOURCE), 'sha256': PINS[SOURCE], 'function': '_git', 'line': 222,
               'caller': 'lease_workspace' if site == 314 else '_build_integration_commit', 'caller_line': site, 'expression_ast_sha256': SITES[site][1] if site in SITES else 'rollback-pending'}
    if site == 1881:
        from finite.workspace_git_data import ROLLBACK_AST
        SOURCE = 'src/unrest_harness/evolution.py'
        binding = {'path': str(ROOT / SOURCE), 'sha256': PINS[SOURCE], 'line': site, 'expression_ast_sha256': ROLLBACK_AST}
    registration = {'class': ('source-git:' + SOURCE + ':1881') if site == 1881 else 'source-workspace-bound-git', 'source_binding': binding,
                    'owner_pid': 22, 'token': 'consumed-parent', 'case': CASES[1]}
    selected = {'registration': registration, 'owner_pid': 22, 'token': 'consumed-parent',
                'bootstrap_sha256': None, 'cwd': str(repository),
                'transformed_argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
                'environment_sha256': hashlib.sha256(json.dumps(parent['environment'], sort_keys=True).encode()).hexdigest()}
    environment = {**parent['environment'], 'PATH': '/usr/lib/git-core:/usr/bin:/bin',
                   'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_PREFIX': '',
                   'GIT_DIR': str(tree / '.git'), 'GIT_WORK_TREE': str(tree)}
    manifest = {'owned_root': str(tmp_path.resolve()), 'product_pins': {SOURCE: PINS[SOURCE]},
                'direct_support': {'files': {'/guard/finite/workspace_git_data.py': hashlib.sha256(DATA.read_bytes()).hexdigest()}}}
    return parent, selected, [IMAGE, 'update-ref', 'HEAD', 'a' * 40], environment, str(repository), manifest


@pytest.mark.parametrize('change', [None, 'vector', 'oid', 'environment', 'parent', 'token', 'owner',
                                    'bootstrap', 'site', 'class', 'source', 'data', 'cwd', 'gitfile',
                                    'backlink', 'commondir', 'symlink', 'symbolic-head', 'foreign-head', 'missing-head', 'symlink-head'])
@pytest.mark.parametrize('site', [314, 616, 1881])
def test_stock_worktree_child_is_only_the_exact_owned_parent_operation(tmp_path, change, site):
    from worktree_git_custody import metadata
    parent, selected, vector, env, cwd, manifest = worktree_child_fixture(tmp_path, site)
    tree = Path(parent['argv'][-2])
    admin = Path(cwd) / '.git/worktrees' / tree.name
    if change == 'vector':
        vector[1] = 'reset'
    elif change == 'oid':
        vector[-1] = 'b' * 40
    elif change == 'environment':
        env['GIT_COMMON_DIR'] = '/foreign'
    elif change == 'parent':
        parent['argv'][1] = 'foreign'
    elif change == 'token':
        selected['token'] = 'foreign'
    elif change == 'owner':
        selected['owner_pid'] = 99
    elif change == 'bootstrap':
        selected['bootstrap_sha256'] = 'foreign'
    elif change == 'site':
        selected['registration']['source_binding']['caller_line'] = 999
    elif change == 'class':
        selected['registration']['class'] = 'foreign'
    elif change == 'source':
        manifest['product_pins'].clear()
    elif change == 'data':
        manifest['direct_support']['files']['/guard/finite/workspace_git_data.py'] = 'foreign'
    elif change == 'cwd':
        selected['cwd'] = '/foreign'
    elif change in {'gitfile', 'backlink', 'commondir'}:
        target = {'gitfile': tree / '.git', 'backlink': admin / 'gitdir', 'commondir': admin / 'commondir'}[change]
        target.write_text('foreign\n')
    elif change in {'symbolic-head', 'foreign-head'}:
        (admin / 'HEAD').write_text('ref: refs/heads/foreign\n' if change == 'symbolic-head' else 'b' * 40 + '\n')
    elif change == 'missing-head':
        (admin / 'HEAD').unlink()
    elif change == 'symlink-head':
        (admin / 'HEAD').rename(admin / 'retained-head')
        (admin / 'HEAD').symlink_to(admin / 'retained-head')
    elif change == 'symlink':
        admin.rename(admin.with_name('foreign'))
        admin.symlink_to(admin.with_name('foreign'), target_is_directory=True)
    assert metadata(parent, selected, vector, env, cwd, manifest, checkout=str(ROOT)) is (change is None)


@pytest.mark.parametrize('change', [None, 'parent-birth', 'parent-drift', 'child-parent', 'image'])
def test_worktree_child_resolver_requires_fresh_birth_and_one_actual_child(tmp_path, monkeypatch, change):
    from types import SimpleNamespace
    import worktree_git_custody as custody
    image = tmp_path / 'git-image'
    image.write_bytes(b'pinned image')
    cwd = tmp_path / 'cwd'
    cwd.mkdir()
    saved = {'pid': 10, 'ppid': 2, 'start_ticks': 20}
    reads = []
    def current(pid):
        if pid == 11:
            return {'pid': 11, 'ppid': 99 if change == 'child-parent' else 10, 'start_ticks': 30}
        reads.append(pid)
        return {**saved, 'start_ticks': 21 if change == 'parent-birth' or (change == 'parent-drift' and len(reads) > 1) else 20}
    def paths(value):
        return image if value == custody.IMAGE else cwd if value == '/proc/10/cwd' else Path(value)
    monkeypatch.setattr(custody, 'identity', current)
    monkeypatch.setattr(custody, 'Path', paths)
    monkeypatch.setattr(custody, 'metadata', lambda *args: True)
    authority = SimpleNamespace(native_context={10: {}}, bound={10: {'token': 'actual-parent'}},
                                contexts={10: {'identity': saved}}, pipe_records=[],
                                manifest={'git_maintenance_sha256': 'foreign' if change == 'image' else hashlib.sha256(image.read_bytes()).hexdigest()})
    trace = SimpleNamespace(identities={11: {'ppid': 10}}, records=[])
    vector = [custody.IMAGE, 'update-ref', 'HEAD', 'a' * 40]
    assert custody.resolve(authority, trace, 11, custody.IMAGE, vector, {}, str(cwd)) is (change is None)
    if change is None:
        assert len(authority.pipe_records) == 1
        assert authority.pipe_records[0]['original_worktree_token'] == 'actual-parent'
        assert not custody.resolve(authority, trace, 11, custody.IMAGE, vector, {}, str(cwd))



def test_other_original_workspace_callers_have_exact_finite_case_and_source_bindings():
    from finite.workspace_git_data import ADDITIONAL_CASES, CASE_PINS
    assert len(ADDITIONAL_CASES) == len(set(ADDITIONAL_CASES)) == 36
    assert not set(ADDITIONAL_CASES).intersection(CASES)
    assert len(set(CASES + ADDITIONAL_CASES)) == 60
    for name, pin in CASE_PINS.items():
        body = (ROOT / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == pin
        functions = {n.name for n in ast.parse(body).body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        selected = [case for case in ADDITIONAL_CASES if case.split('::', 1)[0] == name]
        assert selected and all(case.split('::', 1)[1].split('[', 1)[0] in functions for case in selected)
    assert all(case.split('::', 1)[0] in CASE_PINS for case in ADDITIONAL_CASES)


@pytest.mark.parametrize('site,head,allowed', [(314, 'a' * 40, False), (616, 'a' * 40, True),
                                             (616, '0' * 40, False), (616, 'ref: refs/heads/main', False)])
def test_integration_reset_requires_only_its_exact_detached_revision(tmp_path, site, head, allowed):
    from worktree_git_custody import metadata, IMAGE
    parent, selected, _, env, cwd, manifest = worktree_child_fixture(tmp_path, site)
    tree = Path(parent['argv'][-2])
    (Path(cwd) / '.git/worktrees' / tree.name / 'HEAD').write_text(head + '\n')
    assert metadata(parent, selected, [IMAGE, 'reset', '--hard', '--no-recurse-submodules'],
                    env, cwd, manifest, checkout=str(ROOT)) is allowed


@pytest.mark.parametrize('change', [None, 'no-update', 'no-wait', 'nonzero', 'wrong-parent', 'exit-birth',
                                    'duplicate-wait', 'parent-token', 'parent-birth', 'historical-wait'])
def test_integration_reset_requires_actual_preceding_native_wait(tmp_path, monkeypatch, change):
    from types import SimpleNamespace
    import worktree_git_custody as custody
    image = tmp_path / 'git-image'
    image.write_bytes(b'pinned image')
    cwd = tmp_path / 'cwd'
    cwd.mkdir()
    parent = {'pid': 10, 'ppid': 2, 'start_ticks': 20, 'boot_id': 'boot'}
    first = {'pid': 11, 'ppid': 10, 'start_ticks': 30, 'boot_id': 'boot'}
    def current(pid):
        return dict(parent) if pid == 10 else {**first, 'pid': pid, 'start_ticks': 30 if pid == 11 else 40}
    def paths(value):
        return image if value == custody.IMAGE else cwd if value == '/proc/10/cwd' else Path(value)
    monkeypatch.setattr(custody, 'identity', current)
    monkeypatch.setattr(custody, 'Path', paths)
    monkeypatch.setattr(custody, 'metadata', lambda *args: True)
    authority = SimpleNamespace(native_context={10: {}}, bound={10: {'token': 'parent-token'}},
                                contexts={10: {'identity': dict(parent)}}, pipe_records=[],
                                manifest={'git_maintenance_sha256': hashlib.sha256(image.read_bytes()).hexdigest()})
    trace = SimpleNamespace(identities={11: {'ppid': 10}, 12: {'ppid': 10}}, records=[])
    if change == 'historical-wait':
        trace.records = [{'kind': 'original_parent_wait4', 'parent_tgid': 10, 'child': 11, 'raw': 0, 'normalized': 0}]
    assert custody.resolve(authority, trace, 11, custody.IMAGE,
                           [custody.IMAGE, 'update-ref', 'HEAD', 'a' * 40], {}, str(cwd))
    wait = {'kind': 'original_parent_wait4', 'parent_tgid': 10, 'child': 11, 'raw': 0, 'normalized': 0}
    terminal = {'kind': 'tracer_terminal_wait', 'pid': 11, 'raw': 0, 'normalized': 0, 'identity': dict(first)}
    trace.records = [wait, terminal]
    if change == 'no-update':
        authority.worktree_ref_children.clear()
    elif change == 'no-wait':
        trace.records = [terminal]
    elif change == 'nonzero':
        wait['raw'] = 256
    elif change == 'wrong-parent':
        wait['parent_tgid'] = 99
    elif change == 'exit-birth':
        terminal['identity']['start_ticks'] = 99
    elif change == 'duplicate-wait':
        trace.records.append(dict(wait))
    elif change == 'parent-token':
        authority.bound[10]['token'] = 'foreign'
    elif change == 'parent-birth':
        parent['start_ticks'] = 99
    vector = [custody.IMAGE, 'reset', '--hard', '--no-recurse-submodules']
    assert custody.resolve(authority, trace, 12, custody.IMAGE, vector, {}, str(cwd)) is (change is None)
    if change is None:
        record = authority.pipe_records[-1]
        assert record['prior_actual_wait_sha256'] == hashlib.sha256(json.dumps(wait, sort_keys=True).encode()).hexdigest()
        assert not custody.resolve(authority, trace, 12, custody.IMAGE, vector, {}, str(cwd))
