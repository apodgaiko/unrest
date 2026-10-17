"""Repository integration checks; the source-free synthetic capsule omits these."""
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('primary_ci_commands', Path(__file__).with_name('ci_commands.py'))
assert spec is not None and spec.loader is not None
commands = importlib.util.module_from_spec(spec)
spec.loader.exec_module(commands)

def test_current_primary_original_run_blocks_bind_and_literal_mutation_anchors_survive():
    actual = (Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml').read_text()
    assert actual.count('  primary:\n    name: primary source and package gate (py3.13)') == 1
    assert actual.count('      - name: Type-check (mypy)\n        run: uv run mypy src') == 1
    registry = json.loads(commands.REGISTRY.read_bytes())
    for name, script in registry.items():
        assert commands.bind(script.encode(), actual)['name'] == name
