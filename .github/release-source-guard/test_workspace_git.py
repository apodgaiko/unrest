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
