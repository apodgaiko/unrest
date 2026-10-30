"""An empty filesystem root with only selected test inputs and private scratch."""
import ctypes
import errno
import os
from pathlib import Path
import stat
import sys

from content_manifest import Refused


def enter(metadata, support, output):
    if os.getuid() != 0:
        raise Refused('filesystem setup requires its trusted root')
    libc = ctypes.CDLL(None, use_errno=True)
    root = Path(metadata['owned']).parent / 'filesystem'
    root.mkdir(mode=0o755)

    def target(path, *, directory=True):
        if not path.is_absolute() or '..' in path.parts or path == Path('/'):
            raise Refused('filesystem absolute selected input')
        result = root / path.relative_to('/')
        result.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if directory:
            result.mkdir(mode=0o755, exist_ok=True)
        else:
            result.touch(mode=0o644, exist_ok=False)
        if result.resolve() != result:
            raise Refused('filesystem mount target alias')
        return os.fsencode(result)

    def mount(source, destination, flags, kind=None, data=None):
        if libc.mount(source, destination, kind, ctypes.c_ulong(flags), data):
            raise OSError(ctypes.get_errno(), 'selected filesystem mount refused')

    def bind(source, destination=None, *, writable=False, device=False):
        source = Path(source)
        destination = source if destination is None else Path(destination)
        if source.resolve(strict=True) != source:
            raise Refused('filesystem selected input alias')
        mode = source.stat().st_mode
        if not (stat.S_ISCHR(mode) if device else stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise Refused('filesystem selected input kind')
        selected = target(destination, directory=source.is_dir())
        mount(os.fsencode(source), selected, 4096)
        mount(None, selected, 4096 | 32 | 2 | (0 if device else 4) | (0 if writable else 1))

    # No inherited directory or file handle can retain the old filesystem root.
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd > 2:
            try:
                mode = os.fstat(fd).st_mode
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                continue  # The closed directory-enumeration descriptor.
            if not stat.S_ISFIFO(mode):
                raise Refused('filesystem outside inherited handle')
    bind('/usr')
    for name in ('bin', 'sbin', 'lib', 'lib64'):
        source = Path('/') / name
        if not source.is_symlink() or os.readlink(source) != 'usr/' + name:
            raise Refused('filesystem supported system alias')
        (root / name).symlink_to('usr/' + name)
    for name in ('hosts', 'nsswitch.conf', 'passwd', 'group', 'localtime', 'ld.so.cache'):
        source = Path('/etc') / name
        if source.exists():
            bind(source.resolve(strict=True), source)
    for path in metadata['mounts']:
        bind(path)
    # Already imported observer packages retain this prefix. It exposes only the
    # same measured interpreter copy, never the original host runtime directory.
    if sys.base_prefix != metadata['runtime_root']:
        bind(metadata['runtime_root'], sys.base_prefix)
    for path in (metadata['owned'], str(Path(support).parent / 'profiles'), str(output)):
        bind(path, writable=True)
    for name in ('null', 'zero', 'random', 'urandom'):
        bind('/dev/' + name, writable=True, device=True)
    (root / 'dev/fd').symlink_to('/proc/self/fd')
    temporary = root / 'tmp'
    temporary.mkdir(mode=0o1777, exist_ok=True)
    temporary.chmod(0o1777)
    mount(b'tmpfs', target(Path('/dev/shm')), 14, b'tmpfs', b'mode=1777,size=8m')
    mount(b'proc', target(Path('/proc')), 15, b'proc')
    os.chroot(root)
    os.chdir('/')
    info = os.stat('/')
    mounts = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        if fields[4] in metadata['mounts']:
            selected = os.stat(fields[4], follow_symlinks=False)
            if 'ro' not in fields[5].split(','):
                raise Refused('filesystem selected input remained writable')
            mounts[fields[4]] = [int(fields[0]), selected.st_dev, selected.st_ino]
    if set(mounts) != set(metadata['mounts']):
        raise Refused('filesystem selected mount inventory incomplete')
    return {**metadata, 'mounts': mounts, 'filesystem_root': [info.st_dev, info.st_ino]}
