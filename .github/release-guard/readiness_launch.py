"""Four original local-readiness leaves; connect permission never grants payload."""
import ast
from pathlib import Path

from content_manifest import Refused
from launch_policy import source_unit,build_expected,admit_expected

TEST='tests/test_acp_runner.py'
NAME='test_readiness_attributes_local_child_and_drains'
CASES=tuple(TEST+'::'+NAME+'['+mode+']' for mode in ('early_exit','never_ready','ready','cancel'))
READY=CASES[2]
PIN='0edac8224b6b1760230026567fb1c3a1d591dc70d0b70e9990b0b52d68a71561'


def proposal(host,actor,raw):
    host.root_only(actor)
    if host.case not in CASES or raw['stdin'] is not None:
        raise Refused('readiness original child scope')
    unit=source_unit(Path(host.meta['checkout']),TEST,PIN,(NAME,'exercise'))
    bodies=[ast.literal_eval(node.value) for node in ast.walk(unit) if isinstance(node,ast.Assign)
            and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='body']
    if len(bodies)!=3 or any(type(body) is not str for body in bodies):
        raise Refused('readiness three pinned original literal branches')
    body=bodies[0 if host.case==READY else 1 if host.case==CASES[0] else 2]
    native=host.binding['entry']['path']
    env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    value=build_expected('fixed:readiness',host.case,native,host.binding['entry']['sha256'],
        (native,'-c',body),tuple(sorted(env.items())),host.meta['checkout'],'python-command')
    return admit_expected(host,actor,raw,value,'fixed-inline',[native,'-I','-S','-c',body])
