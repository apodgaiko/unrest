"""Actual pre-initialization hook refuses an unbound body under original flags."""
import importlib.util
from pathlib import Path
import subprocess

import pytest

spec = importlib.util.spec_from_file_location(
    'native_entry_build', Path(__file__).with_name('native_entry_build.py')
)
assert spec is not None and spec.loader is not None
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


@pytest.mark.parametrize('flags', [[], ['-I'], ['-S'], ['-I', '-S']])
def test_native_preinit_refuses_before_unregistered_body(tmp_path, flags):
    binding = entry.verify()
    marker = tmp_path / 'unadmitted-body'
    code = f'from pathlib import Path; Path({str(marker)!r}).write_text("ran")'
    child = subprocess.Popen([binding['entry']['path'], *flags, '-c', code],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, errors = child.communicate(timeout=5)
    assert child.returncode == 86 and output == b''
    assert b'native-startup' in errors
    assert not marker.exists()
