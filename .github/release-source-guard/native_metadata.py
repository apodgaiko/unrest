"""Public original native pin inputs, retained as data and never executed."""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tarfile
import urllib.request

INPUTS = (
    ('index.js', 'https://registry.npmjs.org/@agentclientprotocol/codex-acp/-/codex-acp-1.1.0.tgz',
     'f7349603f0f7a40da3f79d62ba4c855d7b0fdcd9487dfaef6217ba390b0d9462',
     'package/dist/index.js', '878d6a3d825725d0a579305a3e206c7bbb5724a95751b4e3e86af8030cdee758'),
    ('node.data', 'https://nodejs.org/dist/v22.22.0/node-v22.22.0-darwin-arm64.tar.xz',
     '2bd596bbfc4a275ceb8721a5954ee97daea5ebe673e96a185ebd732f6fb023ac',
     'node-v22.22.0-darwin-arm64/bin/node',
     '913b144fdb40638b1acef7974ab3c33fbd527cc0974cb5da467ab1e6ac51b4d4'),
)


def prepare(root: Path) -> None:
    root.mkdir()
    for name, url, archive_pin, member, member_pin in INPUTS:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(100 * 1024 * 1024 + 1)
        if len(data) > 100 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != archive_pin:
            raise RuntimeError('public native metadata archive drift')
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            entry = archive.getmember(member)
            if not entry.isfile() or entry.size > 150 * 1024 * 1024:
                raise RuntimeError('public native metadata member refused')
            stream = archive.extractfile(entry)
            assert stream is not None
            body = stream.read()
        if hashlib.sha256(body).hexdigest() != member_pin:
            raise RuntimeError('original native metadata byte pin differs')
        target = root / name
        target.write_bytes(body)
        target.chmod(0o444)


def verify() -> dict:
    adapter = Path('/native/lib/node_modules/@agentclientprotocol/codex-acp/dist/index.js')
    node = Path('/native/bin/node')
    expected = {adapter: INPUTS[0][-1], node: INPUTS[1][-1]}
    for path, digest in expected.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('original public native metadata changed')
    if (node.stat().st_mode & 0o111 or Path('/native/bin/codex-acp').resolve() != adapter
            or node.open('rb').read(4) != bytes.fromhex('cffaedfe')):
        raise RuntimeError('nonexecuted native metadata view drift')
    return {'purpose': 'nonexecuted original native-pin metadata', 'execution_admission': 'forbidden; metadata presence grants no transport selection',
            'node_platform': 'darwin-arm64',
            'members': {str(path): digest for path, digest in expected.items()}}
