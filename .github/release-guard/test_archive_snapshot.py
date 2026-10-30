"""Actual requested bytes, complete mutation inventory, and sealed generation."""
import os
import shutil

import pytest

from content_manifest import Refused
import archive_snapshot as snapshots


def setup(tmp_path,monkeypatch,kind):
    monkeypatch.setattr(snapshots,"SOURCE_UID",os.getuid())
    monkeypatch.setattr(snapshots,"OBSERVER_UID",os.getuid())
    reference=tmp_path/"reference"
    for name in (snapshots.CORPUS,snapshots.PACKAGE+"/__init__.py","tests/test_case.py"):
        path=reference/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(name.encode())
    (reference/"empty").mkdir()
    source=tmp_path/"actual-extraction"
    shutil.copytree(reference,source)
    if kind=="missing-corpus":
        (source/snapshots.CORPUS).unlink()
    elif kind=="missing-package":
        shutil.move(source/snapshots.PACKAGE,source/"removed-unrest-harness")
    parent=tmp_path/"profiles"
    parent.mkdir(mode=0o755)
    return source,reference,parent/"snapshot"


@pytest.mark.parametrize("kind", ["normal","missing-corpus","missing-package"])
def test_acquires_the_actual_complete_transformed_tree(tmp_path,monkeypatch,kind):
    source,reference,target=setup(tmp_path,monkeypatch,kind)
    record=snapshots.acquire(source,reference,target,kind)
    snapshots.retained(target,record)
    assert sorted(p.relative_to(target) for p in target.rglob('*'))==sorted(p.relative_to(source) for p in source.rglob('*'))
    for path in target.rglob('*'):
        assert path.stat().st_uid==os.getuid()
        assert path.stat().st_mode&0o777==(0o555 if path.is_dir() else 0o444)
        if path.is_file():
            assert path.read_bytes()==(source/path.relative_to(target)).read_bytes()
            assert path.stat().st_ino!=(source/path.relative_to(target)).stat().st_ino
    (source/"tests/test_case.py").write_bytes(b"later source change")
    snapshots.retained(target,record)
    assert (target/"tests/test_case.py").read_bytes()==b"tests/test_case.py"


@pytest.mark.parametrize("mutation", ["extra","empty","missing","changed","link","hardlink","wrong-kind","race"])
def test_unknown_contents_and_acquisition_races_refuse(tmp_path,monkeypatch,mutation):
    source,reference,target=setup(tmp_path,monkeypatch,"normal")
    member=source/"tests/test_case.py"
    if mutation=="extra":
        (source/"extra").write_bytes(b"extra")
    elif mutation=="empty":
        (source/"foreign-empty").mkdir()
    elif mutation=="missing":
        member.unlink()
    elif mutation=="changed":
        member.write_bytes(b"changed")
    elif mutation=="link":
        member.unlink()
        member.symlink_to(reference/"tests/test_case.py")
    elif mutation=="hardlink":
        os.link(member,source/"alias")
    elif mutation=="race":
        original=snapshots.read_regular
        def read(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path==member:
                member.rename(source/"old")
                member.write_bytes(b"replacement")
            return value
        monkeypatch.setattr(snapshots,"read_regular",read)
    with pytest.raises(Refused):
        snapshots.acquire(source,reference,target,"missing-corpus" if mutation=="wrong-kind" else "normal")
    assert not target.exists()


def test_sealed_root_generation_cannot_be_replaced_by_equivalent_bytes(tmp_path,monkeypatch):
    source,reference,target=setup(tmp_path,monkeypatch,"normal")
    record=snapshots.acquire(source,reference,target,"normal")
    target.rename(target.with_name("old"))
    shutil.copytree(target.with_name("old"),target)
    with pytest.raises(Refused,match="identity"):
        snapshots.retained(target,record)



def test_retained_sealed_tree_uses_custody_without_rewalking_bytes(tmp_path,monkeypatch):
    source,reference,target=setup(tmp_path,monkeypatch,"normal")
    record=snapshots.acquire(source,reference,target,"normal")
    def repeated(*args,**kwargs):
        pytest.fail('sealed tree was recursively acquired again')
    monkeypatch.setattr(snapshots,'tree',repeated)
    monkeypatch.setattr(type(target),'rglob',repeated)
    snapshots.retained(target,record)
    target.chmod(0o755)
    with pytest.raises(Refused,match='identity'):
        snapshots.retained(target,record)


def test_retained_snapshot_parent_must_remain_observer_protected(tmp_path,monkeypatch):
    source,reference,target=setup(tmp_path,monkeypatch,"normal")
    record=snapshots.acquire(source,reference,target,"normal")
    target.parent.chmod(0o777)
    with pytest.raises(Refused,match='ancestry'):
        snapshots.retained(target,record)
