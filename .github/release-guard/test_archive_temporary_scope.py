"""Temporary extraction belongs to the attested private filesystem, not host /tmp."""
import os
from types import SimpleNamespace

import pytest

import archive_snapshot
from content_manifest import Refused
from package_cases import POSITIVE
import package_proposals as transport


@pytest.mark.parametrize('mutation',[None,'filesystem','outside','prefix','owner','mode','alias','actor','unready','repeat'])
def test_positive_extraction_requires_private_root_owned_temporary_and_original_actor(tmp_path,monkeypatch,mutation):
    scratch=tmp_path/'private-tmp'
    scratch.mkdir()
    parent=scratch/'unrest-sdist-check-original'
    parent.mkdir(mode=0o700)
    source=parent/'candidate'
    source.mkdir()
    dist=tmp_path/'prepared'
    dist.mkdir()
    (dist/'candidate.tar.gz').write_bytes(b'archive identity is independently checked')
    root=os.stat('/')
    host=SimpleNamespace(case=POSITIVE,fixture_roots={},directory=tmp_path/'profiles',
        meta={'owned':str(tmp_path/'owned'),'filesystem_root':[root.st_dev,root.st_ino]},launch_owner=lambda actor:None)
    actor={'role':'archive-checker','body_ready':True,'birth':'original-parent','token':'original-token'}
    calls=[]
    monkeypatch.setattr(transport,'TEMPORARY_ROOT',scratch)
    monkeypatch.setattr(transport,'SOURCE_UID',os.getuid())
    monkeypatch.setattr(transport,'inputs',lambda host:{'dist':dist,'extracted':tmp_path/'reference'})
    monkeypatch.setattr(archive_snapshot,'acquire',lambda *args:calls.append(args) or {'sealed':'complete bytes checked separately'})
    if mutation=='filesystem':
        host.meta['filesystem_root'][1]+=1
    elif mutation=='outside':
        other=tmp_path/'outside'
        other.mkdir()
        parent.rename(other/parent.name)
        source=other/parent.name/source.name
    elif mutation=='prefix':
        replacement=parent.with_name('foreign-temporary')
        parent.rename(replacement)
        source=replacement/source.name
    elif mutation=='owner':
        monkeypatch.setattr(transport,'SOURCE_UID',os.getuid()+1)
    elif mutation=='mode':
        parent.chmod(0o755)
    elif mutation=='alias':
        source.rename(source.with_name('original'))
        source.symlink_to(source.with_name('original'))
    elif mutation=='actor':
        actor['role']='root'
    elif mutation=='unready':
        actor['body_ready']=False
    elif mutation=='repeat':
        host.fixture_roots[POSITIVE]={'previous':'generation'}
    if mutation is not None:
        with pytest.raises(Refused):
            transport.snapshot(host,actor,{'path':str(source)})
        assert calls==[]
    else:
        answer=transport.snapshot(host,actor,{'path':str(source)})
        assert answer['ok'] and len(calls)==1 and calls[0][0]==source
        retained=host.fixture_roots[POSITIVE]
        assert retained['parent']==actor['birth'] and retained['token']==actor['token']
        assert retained['document']['kind']=='normal'
