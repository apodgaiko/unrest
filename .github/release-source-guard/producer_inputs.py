"""Public, content-addressed source-build backend input; no project execution."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile
from typing import TypedDict

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
SOURCE_UV_ELF_SHA256 = '0a6ec289b04da0352d8b439cb0b05fbe43dff1face7707bd5764fdd4478c1561'
SETUPTOOLS_SHA256 = '51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670'

class EmbeddedBinding(TypedDict):
    url: str
    sha256: str
    size: int


UV_EMBEDDED: dict[str, EmbeddedBinding] = {'python/get_interpreter_info.py': {'url': 'https://raw.githubusercontent.com/astral-sh/uv/0.11.0/crates/uv-python/python/get_interpreter_info.py', 'sha256': '945f3c1d58672269fa3d18db78dbb8e338163af5cb6c4862df197cf456ac5e15', 'size': 27533}, 'python/__init__.py': {'url': 'https://raw.githubusercontent.com/astral-sh/uv/0.11.0/crates/uv-python/python/__init__.py', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'size': 0}, 'python/packaging/__init__.py': {'url': 'https://raw.githubusercontent.com/astral-sh/uv/0.11.0/crates/uv-python/python/packaging/__init__.py', 'sha256': 'ca14c7118e8aea7e2c6ce8ebe8d3ca0c29fbc7f14f93ba7a7c1713b08642ef04', 'size': 501}, 'python/packaging/_elffile.py': {'url': 'https://raw.githubusercontent.com/astral-sh/uv/0.11.0/crates/uv-python/python/packaging/_elffile.py', 'sha256': '00f42dc324664fd8a577a61246550d9253705e1a72787531bd5914b7635f0771', 'size': 3230}, 'python/packaging/_manylinux.py': {'url': 'https://raw.githubusercontent.com/astral-sh/uv/0.11.0/crates/uv-python/python/packaging/_manylinux.py', 'sha256': '8b9a979a7c3a31e3f6127ac6f502bfc293ae36e5f1dae94abbd00dfd028012c2', 'size': 9533}, 'python/packaging/_musllinux.py': {'url': 'https://raw.githubusercontent.com/astral-sh/uv/0.11.0/crates/uv-python/python/packaging/_musllinux.py', 'sha256': '14f5466e6abeb2ad1318e2440f38bc5e38f7bfc7b9ca1354ed15c20ce7cc0be1', 'size': 2664}, '_virtualenv.py': {'url': 'https://raw.githubusercontent.com/astral-sh/uv/0.11.0/crates/uv-virtualenv/src/_virtualenv.py', 'sha256': '6cf30c56faf2a55228914dbbd17f8088ed371ebb08f5e7fa6fd931f913fcaf1d', 'size': 4342}}


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
        binary = archive.read('uv-0.11.0.data/scripts/uv')
        licenses = {name: archive.read('uv-0.11.0.dist-info/licenses/' + name)
                    for name in ('LICENSE-APACHE', 'LICENSE-MIT')}
    if hashlib.sha256(binary).hexdigest() != SOURCE_UV_ELF_SHA256:
        raise RuntimeError('source UV ELF differs from its authenticated wheel member')
    if binary[:6] != b'\x7fELF\x02\x01' or binary[18:20] != b'\x3e\x00':
        raise RuntimeError('source UV is not the pinned Linux ELF member')
    for name, binding in UV_EMBEDDED.items():
        with urllib.request.urlopen(binding['url'], timeout=30) as response:
            body = response.read(binding['size'] + 1)
        if (len(body) != binding['size'] or hashlib.sha256(body).hexdigest() != binding['sha256']
                or (body and body not in binary)):
            raise RuntimeError('UV embedded source differs from its public pinned member')
        target = root / 'upstream' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    (root / 'licenses').mkdir()
    for name, data in licenses.items():
        (root / 'licenses' / name).write_bytes(data)
    (root / 'bin').mkdir()
    executable = root / 'bin/uv'
    executable.write_bytes(binary)
    executable.chmod(0o555)
    (root / 'input-binding.json').write_text(json.dumps({
        'source_uv_wheel_sha256': SOURCE_UV_SHA256,
        'source_uv_elf_sha256': hashlib.sha256(binary).hexdigest(),
        'setuptools_wheel_sha256': SETUPTOOLS_SHA256,
        'embedded_source': {name: item['sha256'] for name, item in UV_EMBEDDED.items()},
    }, sort_keys=True) + '\n')
    return wheel


def verify() -> dict:
    root = Path('/opt/source-bootstrap')
    expected = {'source_uv_wheel_sha256': SOURCE_UV_SHA256,
                'source_uv_elf_sha256': SOURCE_UV_ELF_SHA256,
                'setuptools_wheel_sha256': SETUPTOOLS_SHA256,
                'embedded_source': {name: item['sha256'] for name, item in UV_EMBEDDED.items()}}
    if json.loads((root / 'input-binding.json').read_bytes()) != expected:
        raise RuntimeError('producer input binding drift')
    for path, pin in ((root / 'bin/uv', SOURCE_UV_ELF_SHA256),
                      (root / 'wheelhouse/setuptools-84.0.0-py3-none-any.whl', SETUPTOOLS_SHA256)):
        if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != pin:
            raise RuntimeError('producer immutable input bytes drift')
    for name, binding in UV_EMBEDDED.items():
        path = root / 'upstream' / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != binding['sha256']:
            raise RuntimeError('UV embedded source view drift')
    return expected
