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
    import package_proposals
    import source_observer  # Preload trusted guard code before discarding the host root.
    from types import SimpleNamespace
    assert sys.platform == 'linux' and os.getuid() == 0
    with tempfile.TemporaryDirectory(prefix='unrest-filesystem-scope-') as temporary:
        base = Path(temporary)
        base.chmod(0o755)
        for name in ('input', 'owned', 'support', 'profiles', 'output'):
            (base / name).mkdir(mode=0o755)
        (base / 'outside').write_text('public outside test sentinel')
        (base / 'input/member').write_text('public selected input')
        (base/'input/extracted').mkdir()
        (base/'input/extracted/member').write_text('public extracted input')
        (base/'input/candidate.tar.gz').write_text('public archive name control')
        os.chown(base / 'owned', 20000, 20000)
        os.chown(base / 'output', 20001, 20001)
        (base / 'output').chmod(0o700)
        (base / 'output/private').write_text('public observer custody sentinel')
        sealed=base/'profiles/sealed'
        sealed.mkdir(mode=0o755)
        (sealed/'member').write_text('public sealed snapshot sentinel')
        for path,mode in ((base/'profiles',0o755),(sealed,0o555),(sealed/'member',0o444)):
            os.chown(path,20001,20001)
            path.chmod(mode)
        runtime = str(Path(sys.base_prefix).resolve(strict=True))
        native=base/'native-input'
        native.mkdir(mode=0o755)
        (native/'node.data').write_text('public native metadata sentinel')
        native.chmod(0o555)
        native_identity=native.stat()
        metadata = {'owned' : str(base / 'owned'), 'runtime_root': runtime,
                    'mounts': {**{path:path for path in (str(base / 'input'),str(base / 'support'),runtime)},'/native':str(native)},
                    '_native_input':{'root':str(native),'generation':[native_identity.st_dev,native_identity.st_ino]}}

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
                    assert '_native_input' not in result and '/native' in result['mounts']
                    credentials(20000)
                    assert (base / 'input/member').read_text() == 'public selected input'
                    assert Path('/native/node.data').read_text()=='public native metadata sentinel'
                    assert not native.exists()
                    assert (sealed/'member').read_text()=='public sealed snapshot sentinel'
                    operations=(lambda:(sealed/'member').write_text('forbidden'),
                        lambda:(sealed/'member').chmod(0o644),
                        lambda:sealed.chmod(0o755),
                        lambda:(sealed/'new').write_text('forbidden'),
                        lambda:(sealed/'member').unlink(),
                        lambda:(sealed/'member').rename(sealed/'renamed'),
                        lambda:os.link(sealed/'member',base/'owned/alias'))
                    for index,operation in enumerate(operations):
                        try:
                            operation()
                        except OSError as error:
                            # The only source-writable hardlink destination is
                            # on the separately bound owned mount.
                            allowed=(errno.EACCES,errno.EPERM,errno.EROFS,*((errno.EXDEV,) if index==len(operations)-1 else ()))
                            assert error.errno in allowed
                        else:
                            raise AssertionError('source changed an observer-sealed snapshot')
                    assert (sealed/'member').read_text()=='public sealed snapshot sentinel'
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

        def rejected_generation():
            from content_manifest import Refused
            child=os.fork()
            if child==0:
                code=1
                try:
                    bad={**metadata,'owned':str(base/'negative/owned'),
                        '_native_input':{**metadata['_native_input'],'generation':[0,0]}}
                    enter(bad,str(base/'support'),base/'output')
                except Refused as error:
                    if str(error)=='filesystem mounted native input generation':
                        code=0
                except BaseException:
                    traceback.print_exc()
                os._exit(code)
            assert os.waitpid(child,0)==(child,0)

        def extraction_scope():
            # This exercises real private-/tmp acquisition and both UIDs, not
            # the actor protocol or the separate fifteen-case certification.
            child=os.fork()
            if child==0:
                try:
                    result=enter({**metadata,'owned':str(base/'archive/owned')},str(base/'support'),base/'output')
                    source=Path('/tmp/unrest-sdist-check-native/candidate')
                    writer=os.fork()
                    if writer==0:
                        credentials(20000)
                        source.parent.mkdir(mode=0o700)
                        source.mkdir()
                        (source/'member').write_text('public extracted input')
                        os._exit(0)
                    assert os.waitpid(writer,0)==(writer,0)
                    credentials(20001)
                    host=SimpleNamespace(case=package_proposals.POSITIVE,meta=result,directory=base/'profiles',
                        fixture_roots={'<prepared-distribution>':{'dist':base/'input','extracted':base/'input/extracted'}},
                        launch_owner=lambda actor:None)
                    actor={'role':'archive-checker','body_ready':True,'birth':'scope-control','token':'scope-control'}
                    answer=package_proposals.snapshot(host,actor,{'path':str(source)})
                    assert answer['ok'] and (Path(answer['path'])/'member').read_text()=='public extracted input'
                    assert Path(answer['path']).stat().st_uid==20001
                    assert source.parent.stat().st_uid==20000
                    assert source_observer.shape({'path':str(source)},('path',)) is None
                except BaseException:
                    traceback.print_exc()
                    os._exit(1)
                os._exit(0)
            assert os.waitpid(child,0)==(child,0)

        (base/'negative').mkdir(mode=0o755)
        (base/'negative/owned').mkdir(mode=0o755)
        os.chown(base/'negative/owned',20000,20000)
        run(rejected_generation)
        run(contained)
        (base/'archive').mkdir(mode=0o755)
        (base/'archive/owned').mkdir(mode=0o755)
        os.chown(base/'archive/owned',20000,20000)
        run(extraction_scope)
        assert (base / 'input/member').read_text() == 'public selected input'
        assert (base / 'owned/created').read_text() == 'owned scratch'
    print('Private filesystem controls passed; actual owned wait zero', flush=True)


if __name__ == '__main__':
    main()
