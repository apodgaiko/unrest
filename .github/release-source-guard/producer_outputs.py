"""Byte derivation for UV's installed dependency RECORD relocation.

The immutable image supplies the input bytes. A current installation or a
caller-provided RECORD never supplies expected hashes.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
from pathlib import PurePosixPath


def record_hash(body: bytes) -> list[str]:
    digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b'=').decode()
    return ['sha256=' + digest, str(len(body))]


def record_rows(body: bytes, record: str) -> dict[str, list[str]]:
    """Parse only the original finite UV site/bin member domain."""
    rows: dict[str, list[str]] = {}
    for row in csv.reader(io.StringIO(body.decode('utf-8'), newline='')):
        if len(row) != 3 or row[0] in rows:
            raise RuntimeError('primary_dependency_record_shape')
        name = row[0]
        path = PurePosixPath(name)
        script = (name.startswith('../../../bin/') and len(path.parts) == 5
                  and path.parts[-1] not in {'.', '..'})
        if (not name or path.is_absolute() or str(path) != name
                or ('..' in path.parts and not script)):
            raise RuntimeError('primary_dependency_record_path')
        if name == record:
            if row[1:] != ['', '']:
                raise RuntimeError('primary_dependency_record_self')
        elif (not row[1].startswith('sha256=') or len(row[1]) != 50
              or not row[2].isascii() or not row[2].isdecimal()
              or str(int(row[2])) != row[2]):
            raise RuntimeError('primary_dependency_record_digest')
        rows[name] = row[1:]
    if record not in rows:
        raise RuntimeError('primary_dependency_record_self_missing')
    return rows


def relocate_record(
    body: bytes, record: str, image_members: dict[str, bytes],
    image_scripts: dict[str, bytes], source_executable: str, target_executable: str,
) -> bytes:
    """Derive the complete manifest; only the fixed interpreter shebang changes.

    Native scripts retain their exact image bytes. Every source row is checked
    against the independently admitted image before any target row is rendered.
    """
    if (source_executable != '/opt/primary-deps/bin/python'
            or target_executable != '/source/.venv/bin/python'):
        raise RuntimeError('primary_dependency_record_interpreter')
    rows = record_rows(body, record)
    rendered: dict[str, list[str]] = {}
    source_header = ('#!' + source_executable + '\n').encode()
    target_header = ('#!' + target_executable + '\n').encode()
    for name, fields in rows.items():
        if name == record:
            rendered[name] = ['', '']
            continue
        script = name.startswith('../../../bin/')
        members = image_scripts if script else image_members
        if name not in members or record_hash(members[name]) != fields:
            raise RuntimeError('primary_dependency_record_image_member')
        payload = members[name]
        if script and payload.startswith(source_header):
            payload = target_header + payload[len(source_header):]
        elif script and payload.startswith(b'#!'):
            raise RuntimeError('primary_dependency_record_unknown_shebang')
        rendered[name] = record_hash(payload)
    output = io.StringIO(newline='')
    writer = csv.writer(output, lineterminator='\n')
    writer.writerows([name, *rendered[name]] for name in sorted(rendered))
    return output.getvalue().encode()
