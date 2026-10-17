"""Only the exact declared SOURCE console may be materialized."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('source_console', Path(__file__).with_name('source_console.py'))
assert spec is not None and spec.loader is not None
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)


def test_current_declaration_renders_finite_readonly_data():
    project = (Path(__file__).resolve().parents[2] / 'pyproject.toml').read_bytes()
    body = console.render(project)
    assert body.splitlines()[0] == b'#!/opt/deps/bin/python'
    assert b'from unrest_harness.cli import cli' in body
    assert console.TARGET == '/opt/deps/bin/unrest'


@pytest.mark.parametrize('value', ['arbitrary.module:main', 'unrest_harness.cli:other'])
def test_other_entrypoints_refuse(value):
    with pytest.raises(RuntimeError):
        console.render(('[project.scripts]\nunrest="' + value + '"\n').encode())
