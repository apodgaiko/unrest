"""Current custody of mutable pytest data; selected paths stay case-bound."""
from pathlib import Path
import stat

from content_manifest import Refused, refuse_if


def acquire(path,owned,owner=20000):
    refuse_if(type(path) is not str, 'fixture path primitive')
    root=Path(path)
    boundary=owned/'pytest'
    if (root.resolve()!=root
            or root==boundary or not root.is_relative_to(boundary)):
        raise Refused('fixture canonical owned directory')
    for parent in (root,*(p for p in root.parents if p.is_relative_to(boundary))):
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode&0o6022:
            raise Refused('fixture current directory custody')
    return root,root.lstat()


def retain(host,path,owner=20000):
    root,_=acquire(str(path),Path(host.meta['owned']),owner)
    selected=(str(root),)
    refuse_if(host.fixture_roots.setdefault(host.case,selected)!=selected, 'fixture changed selected path')
    return root
