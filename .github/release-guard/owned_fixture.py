"""One canonical acquisition of an externally declared pytest directory."""
from pathlib import Path
import stat

from content_manifest import Refused


def acquire(path,owned,prefix,owner):
    if type(path) is not str or type(prefix) is not str or not prefix or type(owner) is not int:
        raise Refused('fixture directory primitives')
    root=Path(path)
    info=root.stat(follow_symlinks=False)
    suffix=root.name[len(prefix):]
    if (str(root.resolve())!=path or root.parent!=owned/'pytest' or not root.name.startswith(prefix)
            or not suffix.isascii() or not suffix.isdigit() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner):
        raise Refused('fixture exact owned directory')
    return root,info
