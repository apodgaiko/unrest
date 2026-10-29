"""Original public native pins as readonly data; never executable authority."""
from __future__ import annotations

import hashlib
import io
import tarfile
import urllib.request

from content_manifest import Refused
from git_observer import regular

INPUTS = (
    ('index.js', 'https://registry.npmjs.org/@agentclientprotocol/codex-acp/-/codex-acp-1.1.0.tgz',
     'f7349603f0f7a40da3f79d62ba4c855d7b0fdcd9487dfaef6217ba390b0d9462',
     'package/dist/index.js', '878d6a3d825725d0a579305a3e206c7bbb5724a95751b4e3e86af8030cdee758'),
    ('node.data', 'https://nodejs.org/dist/v22.22.0/node-v22.22.0-darwin-arm64.tar.xz',
     '2bd596bbfc4a275ceb8721a5954ee97daea5ebe673e96a185ebd732f6fb023ac',
     'node-v22.22.0-darwin-arm64/bin/node',
     '913b144fdb40638b1acef7974ab3c33fbd527cc0974cb5da467ab1e6ac51b4d4'),
)
MEMBERS = (
    ('bin/node', 0o444, 111673840, INPUTS[1][-1]),
    ('lib/node_modules/@agentclientprotocol/codex-acp/dist/index.js', 0o555, 1052009, INPUTS[0][-1]),
)
LINK = 'bin/codex-acp', '../lib/node_modules/@agentclientprotocol/codex-acp/dist/index.js'
OWNER = 0


def descriptor():
    return {'schema':'unrest.native-metadata.v1','members':[list(row) for row in MEMBERS],
            'link':list(LINK),'platform':'darwin-arm64','execution':'forbidden'}


def prepare(root):
    if root.resolve()!=root:
        raise Refused('native metadata canonical root')
    root.mkdir(mode=0o755)
    for name, url, archive_pin, member, member_pin in INPUTS:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(100*1024*1024+1)
        if len(data) > 100*1024*1024 or hashlib.sha256(data).hexdigest() != archive_pin:
            raise Refused('public native metadata archive drift')
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            entry = archive.getmember(member)
            if not entry.isfile() or entry.size > 150*1024*1024:
                raise Refused('public native metadata member')
            stream = archive.extractfile(entry)
            if stream is None:
                raise Refused('public native metadata missing body')
            body = stream.read()
        if hashlib.sha256(body).hexdigest() != member_pin:
            raise Refused('original native metadata member pin')
        relative, mode, _, _ = MEMBERS[0 if name == 'node.data' else 1]
        target = root/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(body)
        target.chmod(mode)
        written=regular(target,maximum=150*1024*1024,uid=OWNER)
        if len(written)!=MEMBERS[0 if name=='node.data' else 1][2] or hashlib.sha256(written).hexdigest()!=member_pin:
            raise Refused('native metadata complete written bytes')
    (root/LINK[0]).symlink_to(LINK[1])
    for path in [root,*sorted(root.rglob('*'))]:
        if not path.is_symlink() and path.is_dir():
            path.chmod(0o555)
    return descriptor()
