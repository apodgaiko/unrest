"""Closure evidence binds bytes, modes and symlink targets, not just filenames."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "dependency_closure", Path(__file__).with_name("dependency_closure.py")
)
assert spec is not None and spec.loader is not None
closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(closure)


def test_file_byte_and_symlink_drift(tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    member = package / "module.py"
    member.write_bytes(b"original\n")
    link = tmp_path / "module-link"
    link.symlink_to("package/module.py")
    before = closure.inventory(tmp_path)
    member.write_bytes(b"modified\n")
    after = closure.inventory(tmp_path)
    assert before["package/module.py"]["sha256"] != after["package/module.py"]["sha256"]
    assert before["module-link"]["resolved_sha256"] != after["module-link"]["resolved_sha256"]
    assert after["module-link"]["target"] == "package/module.py"
    member.chmod(0o400)
    assert closure.inventory(tmp_path)["package/module.py"]["mode"] == 0o400


def test_outside_symlink_refuses(tmp_path):
    (tmp_path / "outside").symlink_to("/etc/passwd")
    with pytest.raises(RuntimeError, match="escapes"):
        closure.inventory(tmp_path)


@pytest.mark.parametrize('member', ['lib/python3.13/site-packages/unrest-source.pth', 'pyvenv.cfg'])
def test_actual_readonly_environment_rejects_changed_manifest(member):
    import json
    expected = Path('/environment-closure.json').read_bytes()
    assert closure.verify_source_view(expected)['verified']
    changed = json.loads(expected)
    changed[member]['sha256'] = '0' * 64
    with pytest.raises(RuntimeError, match='closure drift'):
        closure.verify_source_view(json.dumps(changed).encode())
