"""Primary-only public dependency/cache preparation; never execute project code."""
from __future__ import annotations

from pathlib import Path
import subprocess


def build(root, base, support, log):
    if not base.startswith('sha256:') or len(base) != 71:
        raise RuntimeError('primary_base_image_identity')
    root.mkdir()
    for name in ('primary_entry.c', 'primary_entry.py', 'primary_entry_build.py'):
        (root / name).write_bytes((support / name).read_bytes())
    (root / 'Dockerfile').write_text(
        'FROM ' + base + '\n'
        'COPY primary_entry.c primary_entry.py /opt/source-guard/\n'
        'COPY primary_entry_build.py /bootstrap/primary_entry_build.py\n'
        'RUN python -I /bootstrap/primary_entry_build.py && rm -rf /bootstrap\n'
        'WORKDIR /metadata\n'
        'RUN UV_CACHE_DIR=/opt/primary-cache UV_PROJECT_ENVIRONMENT=/opt/primary-deps '
        'UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy /opt/source-bootstrap/bin/uv '
        'sync --locked --no-install-project --python /usr/local/bin/python '
        '&& UV_CACHE_DIR=/opt/primary-cache /opt/source-bootstrap/bin/uv pip install '
        '--python /opt/primary-deps/bin/python --no-index '
        '--find-links /opt/source-bootstrap/wheelhouse setuptools==84.0.0 '
        '&& rm -rf /opt/primary-cache/interpreter-v4\n'
        'WORKDIR /\n')
    with log.open('ab') as output:
        subprocess.run(['docker', 'build', '--tag', 'primary-script-environment', str(root)],
                       stdout=output, stderr=subprocess.STDOUT, check=True)
    return subprocess.check_output(['docker', 'image', 'inspect', '--format={{.Id}}',
                                    'primary-script-environment'], text=True).strip()
