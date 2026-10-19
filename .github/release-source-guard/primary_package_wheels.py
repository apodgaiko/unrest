"""Image-only, hash/size-pinned public wheel inputs for offline package install.

Read the frozen public lock without executing the project. Offer only its
current Linux/Python wheel selections to the original UV pip consumer. No index,
cache prefix, source archive, credentials, or interpreter is exported.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
import tomllib
import urllib.parse
import urllib.request

from packaging.tags import sys_tags
from packaging.utils import parse_wheel_filename, canonicalize_name

LIMIT = 64 * 1024 * 1024
TOTAL = 128 * 1024 * 1024


def select(lock, tags):
    ranks = {tag: index for index, tag in enumerate(tags)}
    selected = []
    for package in sorted(lock['package'], key=lambda row: (row['name'], row['version'])):
        candidates = []
        for wheel in package.get('wheels', []):
            url = urllib.parse.urlsplit(wheel['url'])
            name = Path(url.path).name
            if (url.scheme != 'https' or url.netloc != 'files.pythonhosted.org'
                    or url.query or url.fragment or not url.path.startswith('/packages/')):
                raise RuntimeError('package_wheel_public_url')
            parsed_name, version, _, wheel_tags = parse_wheel_filename(name)
            if canonicalize_name(parsed_name) != canonicalize_name(package['name']) or str(version) != package['version']:
                raise RuntimeError('package_wheel_identity')
            rank = min((ranks[tag] for tag in wheel_tags if tag in ranks), default=None)
            if rank is not None:
                if (type(wheel.get('size')) is not int or not 0 < wheel['size'] <= LIMIT
                        or not re.fullmatch(r'sha256:[0-9a-f]{64}', wheel['hash'])):
                    raise RuntimeError('package_wheel_pin')
                candidates.append((rank, name, wheel))
        if candidates:
            _, name, wheel = min(candidates, key=lambda row: (row[0], row[1]))
            selected.append({'name': name, **wheel})
    if (not selected or len(selected) > 256 or sum(row['size'] for row in selected) > TOTAL
            or len({row['name'] for row in selected}) != len(selected)):
        raise RuntimeError('package_wheel_input_bound')
    return selected


def prepare(lock_path=Path('/metadata/uv.lock'), root=Path('/opt/primary-installed-wheels')):
    lock_body = lock_path.read_bytes()
    rows = select(tomllib.loads(lock_body.decode()), list(sys_tags()))
    root.mkdir(mode=0o755)
    for row in rows:
        with urllib.request.urlopen(row['url'], timeout=60) as response:
            body = response.read(row['size'] + 1)
        if len(body) != row['size'] or 'sha256:' + hashlib.sha256(body).hexdigest() != row['hash']:
            raise RuntimeError('package_wheel_download_pin')
        with (root / row['name']).open('xb') as stream:
            stream.write(body)
        (root / row['name']).chmod(0o444)
    (root / 'manifest.json').write_text(json.dumps({'lock_sha256': hashlib.sha256(lock_body).hexdigest(),
                                                 'members': rows}, sort_keys=True))
    (root / 'manifest.json').chmod(0o444)
    root.chmod(0o555)


if __name__ == '__main__':
    prepare()
