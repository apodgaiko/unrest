"""Real empty-root containment, including UID and old-proc-root escape negatives."""
import errno
import os
from pathlib import Path
import sys
import tempfile
import traceback

def main():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from compartment import credentials
    from filesystem_scope import enter
    from namespace_supervisor import run
    assert sys.platform == 'linux' and os.getuid() == 0
    with tempfile.TemporaryDirectory(prefix='unrest-filesystem-scope-') as temporary:
        base = Path(temporary)
        base.chmod(0o755)
        for name in ('input', 'owned', 'support', 'profiles', 'output'):
            (base / name).mkdir(mode=0o755)
        (base / 'outside').write_text('public outside test sentinel')
        (base / 'input/member').write_text('public selected input')
        os.chown(base / 'owned', 20000, 20000)
        os.chown(base / 'output', 20001, 20001)
        (base / 'output').chmod(0o700)
        (base / 'output/private').write_text('public observer custody sentinel')
        runtime = str(Path(sys.base_prefix).resolve(strict=True))
        metadata = {'owned': str(base / 'owned'), 'runtime_root': runtime,
                    'mounts': dict.fromkeys((str(base / 'input'), str(base / 'support'), runtime))}

        def contained():
            child = os.fork()
            if child == 0:
                try:
                    os.chdir(base)
                    os.open(base, os.O_RDONLY | os.O_DIRECTORY)  # Deliberate old-root handle.
                    os.open(base / 'outside', os.O_RDONLY)
                    result = enter(metadata, str(base / 'support'), base / 'output')
                    root = os.stat('/')
                    assert result['filesystem_root'] == [root.st_dev, root.st_ino]
                    assert Path.cwd() == Path('/') and not (base / 'outside').exists()
                    credentials(20000)
                    assert (base / 'input/member').read_text() == 'public selected input'
                    (base / 'owned/created').write_text('owned scratch')
                    for path in (base / 'input/member', base / 'input/new-member'):
                        try:
                            path.write_text('forbidden write')
                        except OSError as error:
                            assert error.errno in (errno.EACCES, errno.EROFS)
                        else:
                            raise AssertionError('selected input remained writable')
                    for path in (base / 'output/private', Path('/proc/1/root') / (base / 'outside').relative_to('/')):
                        try:
                            path.read_bytes()
                        except PermissionError:
                            pass
                        else:
                            raise AssertionError('observer or old host root was reachable')
                    # No directory descriptor retaining the old cwd/root survived.
                    for name in os.listdir('/proc/self/fd'):
                        if int(name) > 2:
                            try:
                                assert not os.path.isdir('/proc/self/fd/' + name)
                            except FileNotFoundError:
                                pass
                except BaseException:
                    traceback.print_exc()
                    os._exit(1)
                os._exit(0)
            assert os.waitpid(child, 0) == (child, 0)

        run(contained)
        assert (base / 'input/member').read_text() == 'public selected input'
        assert (base / 'owned/created').read_text() == 'owned scratch'
    print('Private filesystem controls passed; actual owned wait zero', flush=True)


if __name__ == '__main__':
    main()
