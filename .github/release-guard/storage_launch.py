"""Original fresh-process reads, scoped to each actual atomic-write fixture."""
from pathlib import Path
import stat

from content_manifest import Refused
from owned_fixture import retain
from launch_policy import build_expected

OWNER=20000
TEST='tests/test_storage.py'
PREFIX=TEST+'::TestAtomicWriteText::'
FAIL=PREFIX+'test_failure_preserves_target_and_cleans_unique_temp'
DIRECTORY=PREFIX+'test_directory_fsync_failure_accepts_visible_generation'
NESTED=PREFIX+'test_regular_nested_destinations_remain_atomic'
CASES=(*(FAIL+'['+stage+']' for stage in ('write','content_fsync','replace')),DIRECTORY,
    *(NESTED+f'[{existing}-{depth}-{relative}]' for existing in ('fresh','existing')
      for depth in (0,1,3) for relative in ('absolute','relative')))
PROGRAM='import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())'


def expected(host,argv,cwd,environment,native,pin):
    case=host.case
    if case not in CASES or len(argv)!=4:
        raise Refused('storage finite read declaration')
    checkout,owned=Path(host.meta['checkout']),Path(host.meta['owned'])
    target=Path(argv[3])
    actual=Path(cwd)/target
    try:
        root=owned/'pytest'/actual.relative_to(owned/'pytest').parts[0]
    except (ValueError,IndexError):
        raise Refused('storage owned fixture root') from None
    root=retain(host,root, OWNER)
    location=Path(cwd)
    if (actual.resolve()!=actual or location.resolve()!=location
            or location!=checkout and not location.is_relative_to(root)):
        raise Refused('storage canonical owned read path')
    file=actual.stat(follow_symlinks=False)
    if not stat.S_ISREG(file.st_mode) or file.st_uid!=OWNER or file.st_nlink!=1:
        raise Refused('storage owned regular read input')
    return build_expected(case,native,pin,(native,'-c',PROGRAM,str(target)),
        tuple(sorted(environment.items())),cwd,'python-command')
