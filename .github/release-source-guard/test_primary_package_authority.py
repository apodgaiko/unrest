"""Archive entry is a separate finite route; SOURCE authority remains exact."""
import ast
import hashlib
from pathlib import Path
from types import SimpleNamespace, ModuleType
import sys

import pytest

# Compile the exact package subclass with a controlled rejecting original base.
# Runtime imports require the real /guard capsule; hosted TEST proves that seam.
class Authority:
    def resolve(self, *args):
        return False

    def refuse(self, code):
        self.denials.append(code)
        return False


path = Path(__file__).with_name('primary_package_authority.py')
node = next(n for n in ast.parse(path.read_bytes()).body if isinstance(n, ast.ClassDef))
package = ModuleType('controlled_package_authority')
package.__dict__.update(Authority=Authority, Path=Path, hashlib=hashlib,
                        json=__import__('json'), PYTHON='', COMMAND=[
                            'uv', 'run', 'python', 'tools/check_distribution.py', 'dist'],
                        SOURCE=None, digest=None, identity=None, command_environment=None)
exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), package.__dict__)


def test_original_whole_primary_authority_ast_is_preserved():
    tree = ast.parse(Path(__file__).with_name('primary_authority.py').read_text())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == 'self.source.start']
    assert len(calls) == 1
    calls[0].keywords = []
    assert hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest() == '779b322196c778dae817d5987556e0a9d9befc0faad7ae17540a65d9d4399f1c'


@pytest.mark.parametrize('mutation', ['none', 'wrong-duty', 'wrong-command', 'wrong-mode',
                                    'foreign-owner', 'cwd', 'argv', 'source', 'duplicate'])
def test_only_actual_original_archive_entry_has_package_profile(tmp_path, monkeypatch, mutation):
    source = tmp_path / 'check_distribution.py'
    source.write_text('pass\n')
    profiles = tmp_path / 'profiles'
    profiles.mkdir()
    real_path = Path
    monkeypatch.setattr(package, 'Path', lambda p: profiles if str(p) == '/receipts/primary-startup' else real_path(p))
    monkeypatch.setattr(package, 'SOURCE', source)
    python = str(Path(sys.executable).resolve())
    monkeypatch.setattr(package, 'PYTHON', python)
    monkeypatch.setattr(package, 'digest', lambda path: 'a' * 64)
    monkeypatch.setattr(package, 'identity', lambda pid: {'pid': pid, 'start_ticks': 111, 'boot_id': 'current'})
    monkeypatch.setattr(package, 'command_environment', lambda *a, **k: True)
    monkeypatch.setattr(Authority, 'resolve', lambda *a: False)
    owner = package.PackageArchivePrimaryAuthority.__new__(package.PackageArchivePrimaryAuthority)
    owner.plan = {'duty': 'Check distribution archives', 'commands': [package.COMMAND.copy()], 'package_mode': 'TEST'}
    context = {'role': 'uv', 'command': package.COMMAND.copy(), 'final': False,
               'python_calls': 0, 'identity': {'pid': 8, 'start_ticks': 111, 'boot_id': 'current'}}
    owner.contexts = {8: context}
    owner.records, owner.denials = [], []
    owner.environment = {}
    owner.output_fd = 44
    starts = []
    owner.source = SimpleNamespace(manifest={'product_pins': {'tools/check_distribution.py': 'a' * 64}},
                                   path='manifest', pin='pin', start=lambda *a, **k: starts.append((a, k)))
    cwd = '/source'
    vector = [python, 'tools/check_distribution.py', 'dist']
    if mutation == 'wrong-duty':
        owner.plan['duty'] = 'foreign'
    elif mutation == 'wrong-command':
        owner.plan['commands'] = [['foreign']]
    elif mutation == 'wrong-mode':
        owner.plan['package_mode'] = 'foreign'
    elif mutation == 'foreign-owner':
        context['identity'] = {'pid': 99}
    elif mutation == 'cwd':
        cwd = '/foreign'
    elif mutation == 'argv':
        vector[-1] = 'foreign'
    elif mutation == 'source':
        owner.source.manifest['product_pins']['tools/check_distribution.py'] = 'b' * 64
    elif mutation == 'duplicate':
        (profiles / '12.json').write_text('{}')
    result = owner.resolve(SimpleNamespace(identities={12: {'ppid': 8}}), 12, python, vector, {}, cwd)
    assert result is (mutation == 'none')
    if mutation == 'none':
        assert starts and owner.records[0]['role'] == 'package-root'
        assert owner.contexts[12]['identity'] == {'pid': 12, 'start_ticks': 111, 'boot_id': 'current'}
    else:
        assert not owner.records
