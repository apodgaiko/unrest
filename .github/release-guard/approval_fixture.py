"""Controlled approval fixture IPC; never native provider permission authority."""
import re
import stat
from pathlib import Path

from content_manifest import Refused

TEST='tests/test_approval_recovery.py'


def unix(host,actor,event,address):
    if (host.finished or type(host.case) is not str or not host.case.startswith(TEST+'::') or actor['case'] not in (host.case,'<bootstrap>')
            or not actor['body_ready'] or event not in ('socket.bind','socket.connect')
            or type(address) is not str or re.fullmatch(r'/tmp/unrest-approval-(?:test-)?[a-z0-9_]{8}/control',address) is None):
        raise Refused('approval exact private Unix endpoint')
    path=Path(address)
    parent=path.parent
    info=parent.lstat()
    if parent.resolve()!=parent or not stat.S_ISDIR(info.st_mode) or info.st_uid!=20000 or stat.S_IMODE(info.st_mode)!=0o700:
        raise Refused('approval private Unix directory custody')
    generation=(info.st_dev,info.st_ino)
    key=('approval-unix',host.case,address)
    if event=='socket.bind':
        if actor['role']!='root' or key in host.fixture_roots or path.exists() or path.is_symlink():
            raise Refused('approval private Unix repeated bind')
        host.fixture_roots[key]=generation
    else:
        endpoint=path.lstat()
        if (host.fixture_roots.get(key)!=generation or not stat.S_ISSOCK(endpoint.st_mode)
                or endpoint.st_uid!=20000 or stat.S_IMODE(endpoint.st_mode)!=0o600):
            raise Refused('approval private Unix endpoint custody')
    return {'ok':True}
