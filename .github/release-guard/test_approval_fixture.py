"""Only the controlled approval fixture can use its private named socket."""
import os
import socket
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from approval_fixture import TEST, unix
from content_manifest import Refused


@pytest.fixture
def socket_root():
    with tempfile.TemporaryDirectory(prefix='guard-unix-',dir='/tmp') as root:
        yield Path(root).resolve()


@pytest.mark.parametrize('mutation',[None,'case','role-case','not-ready','event','path','directory-mode','directory-alias'])
def test_private_unix_constructor_is_case_and_custody_bound(socket_root,monkeypatch,mutation):
    tmp_path=socket_root
    parent=tmp_path/'unrest-approval-abcdefgh'
    parent.mkdir(mode=0o700)
    path=parent/'control'
    original=Path.lstat
    def measured(file):
        info=original(file)
        return SimpleNamespace(st_mode=info.st_mode,st_uid=20000,st_dev=info.st_dev,st_ino=info.st_ino)
    monkeypatch.setattr(Path,'lstat',measured)
    monkeypatch.setattr('approval_fixture.re.fullmatch',lambda pattern,value,expected=str(path): True if value==expected else None)
    host=SimpleNamespace(finished=False,case=TEST+'::original',fixture_roots={})
    actor={'case':'<bootstrap>','body_ready':True,'role':'root'}
    event='socket.bind'
    if mutation=='case':
        host.case='tests/other.py::case'
    elif mutation=='role-case':
        actor['case']='tests/other.py::case'
    elif mutation=='not-ready':
        actor['body_ready']=False
    elif mutation=='event':
        event='socket.sendto'
    elif mutation=='path':
        path=tmp_path/'foreign'
    elif mutation=='directory-mode':
        parent.chmod(0o755)
    elif mutation=='directory-alias':
        alias=tmp_path/'alias'
        alias.symlink_to(parent,target_is_directory=True)
        path=alias/'control'
    if mutation:
        with pytest.raises(Refused):
            unix(host,actor,event,str(path))
    else:
        assert unix(host,actor,event,str(path))=={'ok':True}
        with pytest.raises(Refused,match='repeated bind'):
            unix(host,actor,event,str(path))
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            server.bind(str(path))
            os.chmod(path,0o600)
            assert unix(host,actor,'socket.connect',str(path))=={'ok':True}
            path.chmod(0o666)
            with pytest.raises(Refused,match='endpoint custody'):
                unix(host,actor,'socket.connect',str(path))
        finally:
            server.close()


@pytest.mark.parametrize('address',['/tmp/elsewhere/control','\0abstract','/tmp/unrest-approval-abcdefgh/../control',b'/tmp/unrest-approval-abcdefgh/control'])
def test_unix_path_shape_is_not_a_general_private_socket_allowlist(address):
    host=SimpleNamespace(finished=False,case=TEST+'::original',fixture_roots={})
    with pytest.raises(Refused):
        unix(host,{'case':'<bootstrap>','body_ready':True,'role':'root'},'socket.bind',address)
