"""Supplementary original type duty through the unchanged production executor."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

from full_bootstrap import produce
from preflight_policy import context


def main():
    context()
    parent = Path(os.environ['RUNNER_TEMP'])
    root = parent / 'type-cache-proof'
    root.mkdir(mode=0o700)
    shutil.copytree(parent / 'source-readiness', root / 'source-readiness')
    os.environ['RUNNER_TEMP'] = str(root)
    produce('PREFLIGHT')
    script = root / 'type-script.sh'
    script.write_bytes(b'uv run mypy src')
    with (root / 'type-private.log').open('xb') as output:
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('ci_shell.py')),
                                 '--preflight-phase', str(script)], stdout=output,
                                stderr=subprocess.STDOUT, check=False)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
