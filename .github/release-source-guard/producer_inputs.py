"""Public, content-addressed source-build backend input; no project execution."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

SETUPTOOLS_URL = (
    'https://files.pythonhosted.org/packages/95/9c/'
    'c510029fc6ef33a6275cd2c5d3cecd6613dfd6aa401d57c54f1c18852ccf/'
    'setuptools-84.0.0-py3-none-any.whl'
)
SOURCE_UV_URL = (
    'https://files.pythonhosted.org/packages/36/fa/'
    '086616d98b0b8a2cc5e7b49c389118a8196027a79a5a501f5e738f718f59/'
    'uv-0.11.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl'
)
SOURCE_UV_SHA256 = '30a08ee4291580784a5e276a1cbec8830994dba2ed5c94d878cce8b2121367cf'
SETUPTOOLS_SHA256 = '51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670'


def prepare(root: Path) -> Path:
    root.mkdir()
    wheelhouse = root / 'wheelhouse'
    wheelhouse.mkdir()
    wheel = wheelhouse / 'setuptools-84.0.0-py3-none-any.whl'
    with urllib.request.urlopen(SETUPTOOLS_URL, timeout=60) as response:
        body = response.read(818217)
    if len(body) != 818216 or hashlib.sha256(body).hexdigest() != SETUPTOOLS_SHA256:
        raise RuntimeError('public source-build backend wheel drift')
    wheel.write_bytes(body)
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if (len(names) != len(set(names)) or any(Path(name).is_absolute()
                or '..' in Path(name).parts for name in names)
                or archive.read('setuptools-84.0.0.dist-info/METADATA').splitlines()[1:3]
                != [b'Name: setuptools', b'Version: 84.0.0']):
            raise RuntimeError('source-build backend member or identity drift')
    with urllib.request.urlopen(SOURCE_UV_URL, timeout=60) as response:
        uv_wheel = response.read(24508502)
    if len(uv_wheel) != 24508501 or hashlib.sha256(uv_wheel).hexdigest() != SOURCE_UV_SHA256:
        raise RuntimeError('public source UV wheel drift')
    with zipfile.ZipFile(io.BytesIO(uv_wheel)) as archive:
        binary = archive.read('uv/uv')
    if binary[:4] != b'\x7fELF':
        raise RuntimeError('source UV is not the pinned Linux ELF member')
    (root / 'bin').mkdir()
    executable = root / 'bin/uv'
    executable.write_bytes(binary)
    executable.chmod(0o555)
    (root / 'input-binding.json').write_text(json.dumps({
        'source_uv_wheel_sha256': SOURCE_UV_SHA256,
        'source_uv_elf_sha256': hashlib.sha256(binary).hexdigest(),
        'setuptools_wheel_sha256': SETUPTOOLS_SHA256,
    }, sort_keys=True) + '\n')
    return wheel
