"""An empty filesystem root with only selected test inputs and private scratch."""
import ctypes
import errno
import os
from pathlib import Path
import stat
import sys

from content_manifest import Refused, refuse_if


def enter(metadata, support, output):
    refuse_if(os.getuid() != 0, 'filesystem setup requires its trusted root')
    libc = ctypes.CDLL(None, use_errno=True)
    # This dedicated fork needs no inherited handles beyond stdio. Discard even
    # the interpreter's main-script handle before acquiring any compartment I/O.
    os.closerange(3, 1 << 20)
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
        refuse_if(result.resolve() != result, 'filesystem mount target alias')
        return os.fsencode(result)

    def mount(source, destination, flags, kind=None, data=None):
        if libc.mount(source, destination, kind, ctypes.c_ulong(flags), data):
            raise OSError(ctypes.get_errno(), 'selected filesystem mount refused')

    def bind(source, destination=None, *, writable=False, device=False):
        source = Path(source)
        destination = source if destination is None else Path(destination)
        refuse_if(source.resolve(strict=True) != source, 'filesystem selected input alias')
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
                os.fstat(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                continue  # The closed directory-enumeration descriptor.
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
    for destination,source in metadata['mounts'].items():
        bind(source,destination)
    native=metadata.get('_native_input')
    if native is not None:
        selected=(root/'native').stat()
        if ([selected.st_dev,selected.st_ino]!=native['generation'] or selected.st_uid!=0
                or stat.S_IMODE(selected.st_mode)!=0o555):
            raise Refused('filesystem mounted native input generation')
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
            refuse_if('ro' not in fields[5].split(','), 'filesystem selected input remained writable')
            mounts[fields[4]] = [int(fields[0]), selected.st_dev, selected.st_ino]
    refuse_if(set(mounts) != set(metadata['mounts']), 'filesystem selected mount inventory incomplete')
    return {**{key:value for key,value in metadata.items() if key!='_native_input'}, 'mounts': mounts, 'filesystem_root': [info.st_dev, info.st_ino]}
