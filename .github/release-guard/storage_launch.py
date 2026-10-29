"""Original fresh-process reads, scoped to each actual atomic-write fixture."""
import ast
from pathlib import Path
import stat

from content_manifest import Refused
from owned_fixture import retain
from launch_policy import build_expected,source_unit

OWNER=20000
TEST='tests/test_storage.py'
PREFIX=TEST+'::TestAtomicWriteText::'
FAIL=PREFIX+'test_failure_preserves_target_and_cleans_unique_temp'
DIRECTORY=PREFIX+'test_directory_fsync_failure_accepts_visible_generation'
NESTED=PREFIX+'test_regular_nested_destinations_remain_atomic'
CASES={**{FAIL+'['+stage+']':(False,0,'accepted generation\n') for stage in ('write','content_fsync','replace')},
    DIRECTORY:(False,0,'{"generation":2}\n'),
    **{NESTED+f'[{existing}-{depth}-{relative}]':(relative=='relative',depth,'replacement generation\n')
       for existing in ('fresh','existing') for depth in (0,1,3) for relative in ('absolute','relative')}}
PIN='68418a6fac8295d675e2ca6f0849b16469a816c114c0b80a523f1b1d8797b20b'


def expected(host,argv,cwd,environment,native,pin):
    case=host.case
    if case not in CASES or len(argv)!=4:
        raise Refused('storage finite read declaration')
    checkout,owned=Path(host.meta['checkout']),Path(host.meta['owned'])
    function=source_unit(checkout,TEST,PIN,('TestAtomicWriteText','_fresh_process_bytes'))
    calls=[node for node in ast.walk(function) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='check_output']
    if len(calls)!=1:
        raise Refused('storage sole original read')
    script=ast.literal_eval(calls[0].args[0].elts[2])
    relative,depth,contents=CASES[case]
    target=Path(argv[3])
    actual=Path(cwd)/target if relative else target
    try:
        root=owned/'pytest'/actual.relative_to(owned/'pytest').parts[0]
    except (ValueError,IndexError):
        raise Refused('storage owned fixture root') from None
    root=retain(host,root,case.split('::')[-1].split('[')[0][:30],OWNER)
    expected=root/'state.json'
    if case.startswith(NESTED+'['):
        expected=root/'trusted'/Path(*(f'level-{index}' for index in range(depth)))/'state.json'
    original=expected.relative_to(root) if relative else expected
    if (actual!=expected or target!=original or cwd!=str(root if relative else checkout)
            or expected.resolve()!=expected):
        raise Refused('storage exact original read path')
    file=expected.stat(follow_symlinks=False)
    if not stat.S_ISREG(file.st_mode) or file.st_uid!=OWNER or file.st_nlink!=1 or expected.read_bytes()!=contents.encode():
        raise Refused('storage original read input')
    return build_expected(case,native,pin,(native,'-c',script,str(original)),
        tuple(sorted(environment.items())),cwd,'python-command')
