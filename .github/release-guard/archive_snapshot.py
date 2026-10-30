"""Acquire actual extracted bytes into a new observer-owned immutable tree."""
from pathlib import Path
import stat

from content_manifest import Refused, read_regular, _key, _directory_key
from prepared_distribution import tree

SOURCE_UID = 20000
OBSERVER_UID = 20001
CORPUS = 'tests/fixtures/persistence_schema_v1/corpus.json'
PACKAGE = 'src/unrest_harness'


def project(name,kind):
    if kind=='missing-corpus' and name==CORPUS:
        return None
    if kind=='missing-package' and (name==PACKAGE or name.startswith(PACKAGE+'/')):
        return 'removed-unrest-harness'+name[len(PACKAGE):]
    return name


def graph(root):
    rows=[root,*sorted(root.rglob('*'))]
    if len(rows)>20000 or str(root.resolve(strict=True))!=str(root):
        raise Refused('snapshot bounded canonical graph')
    result={str(path.relative_to(root)):path.lstat() for path in rows}
    if any(info.st_uid!=SOURCE_UID or info.st_mode&0o6022
           or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
           or stat.S_ISREG(info.st_mode) and info.st_nlink!=1 for info in result.values()):
        raise Refused('snapshot original member custody')
    return result


def acquire(source,reference,target,kind):
    if kind not in ('normal','missing-corpus','missing-package'):
        raise Refused('snapshot finite transformation')
    before=graph(source)
    baseline=tree(reference)
    expected={project(row['path'],kind):(row['size'],row['sha256']) for row in baseline['content']['files']
              if project(row['path'],kind) is not None}
    directories={'.',*(project(name,kind) for name in baseline['directories'])}
    if (set(before)!=set(expected)|directories or any(not stat.S_ISDIR(before[name].st_mode) for name in directories)):
        raise Refused('snapshot complete original inventory')
    acquired={}
    total=0
    for name,(size,pin) in sorted(expected.items()):
        body,_,actual=read_regular(source/name,4*1024*1024,uid=SOURCE_UID,forbidden=0o6022)
        total+=len(body)
        if total>512*1024*1024 or len(body)!=size or actual!=pin:
            raise Refused('snapshot original extracted bytes')
        acquired[name]=body
    after=graph(source)
    if before.keys()!=after.keys() or any(_key(before[name])!=_key(after[name]) for name in before):
        raise Refused('snapshot original acquisition race')
    target.mkdir(mode=0o700)
    if target.stat().st_uid!=OBSERVER_UID:
        raise Refused('snapshot observer owner')
    for name in sorted(directories-{'.'},key=lambda value:(len(Path(value).parts),value)):
        (target/name).mkdir(mode=0o700)
    for name,body in acquired.items():
        (target/name).write_bytes(body)
        (target/name).chmod(0o444)
    for name in sorted(directories,key=lambda value:-len(Path(value).parts)):
        (target/name).chmod(0o555)
    result=tree(target)
    if ({row['path']:(row['size'],row['sha256']) for row in result['content']['files']}!=expected
            or set(result['directories'])!=directories-{'.'}):
        raise Refused('snapshot copied inventory changed')
    record={"identity":list(_directory_key(target.lstat()))}
    retained(target,record)
    return record


def retained(root,record):
    if str(root.resolve(strict=True))!=str(root) or list(_directory_key(root.lstat()))!=record["identity"]:
        raise Refused('snapshot retained root identity')
    if root.parent.stat().st_uid!=OBSERVER_UID or root.parent.stat().st_mode&0o6022:
        raise Refused('snapshot nonwritable observer ancestry')
