"""Original intentional-crash completion primitives and their real retry."""
import ast
import hashlib
from pathlib import Path

from content_manifest import Refused
from launch_policy import build_expected
from owned_fixture import acquire

PUBLICATION='tests/test_completion_ownership.py::test_interrupted_publication_and_lock_recovery'
MARKER='tests/test_completion_setup.py::test_consumed_marker_survives_recovery_interruption'
SETUP='tests/test_completion_setup.py::test_process_dies_during_first_setup'
CASES={**{PUBLICATION+'['+phase+']':('attempt.json',phase) for phase in ('before','after')},
    **{MARKER+'['+kind+'-'+phase+']':('marker.json',phase)
       for kind in ('corrupt','wrong-mode','symlink') for phase in ('temporary','before-replace','after-replace')},
    SETUP:('bucket/.unrest-runtime/attempts/result.json',None)}
SEQUENCES={case:('crash','retry') if case.startswith(PUBLICATION+'[') else ('crash',) for case in CASES}
PINS={'tests/test_completion_ownership.py': '2b67510bdd8f40d584baab65837174b2f5a3935aff343b7d9eaccedf09b5df8b', 'tests/test_completion_setup.py': 'fe1a1c98792d1b30d81d975cb23ad9122ae74678295ef4ed8c5e532a7aa00b6a'}
OWNER=20000


def expected(host,operation,argv,cwd,environment,native,pin):
    case=host.case
    if case not in CASES or operation not in SEQUENCES[case]:
        raise Refused('completion exact primitive sequence')
    suffix,phase=CASES[case]
    if len(argv)!=(5 if operation=='crash' and phase is not None else 4):
        raise Refused('completion original argument count')
    checkout=Path(host.meta['checkout'])
    path,name=case.split('::')
    name=name.split('[')[0]
    body=(checkout/path).read_bytes()
    if hashlib.sha256(body).hexdigest()!=PINS[path]:
        raise Refused('completion original primitive bytes')
    owner=next(node for node in ast.parse(body).body if isinstance(node,ast.FunctionDef) and node.name==name)
    values=[node.value for node in owner.body if isinstance(node,ast.Assign) and len(node.targets)==1
            and isinstance(node.targets[0],ast.Name) and node.targets[0].id==('retry' if operation=='retry' else 'script')]
    if len(values)!=1 or not isinstance(values[0],ast.Constant) or type(values[0].value) is not str:
        raise Refused('completion original sole primitive literal')
    root=Path(argv[3]).parents[len(Path(suffix).parts)-1]
    root,info=acquire(str(root),Path(host.meta['owned']),name[:30],OWNER)
    generation=(str(root),info.st_dev,info.st_ino)
    if host.fixture_roots.setdefault(case,generation)!=generation or cwd!=str(checkout):
        raise Refused('completion changed fixture generation or cwd')
    vector=(native,'-c',values[0].value,str(root/suffix),*((phase,) if operation=='crash' and phase is not None else ()))
    return build_expected('fixed:completion',case,native,pin,vector,tuple(sorted(environment.items())),cwd,'python-command')
