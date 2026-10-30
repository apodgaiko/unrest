"""Two original isolated programs bound to an acquired pytest fixture directory."""
import ast
from pathlib import Path

from content_manifest import Refused, refuse_if
from launch_policy import render_string
from owned_fixture import acquire

NAMES = ('test_precaptured_constructor_resolver_and_command_aliases_are_audit_denied',
         'test_local_control_sockets_and_event_loop_survive_guard_and_runner')
CASES = tuple('tests/test_v04_speed_runner.py::'+name for name in NAMES)
OWNER = 20000
CLI_CASE = 'tests/test_v04_speed_runner.py::test_result_schema_closes_every_declared_object_and_accepts_real_result'
CLI_TOOL = 'tools/v04_speed_runner.py'
CLI_PIN = '65fe88a826aef366009d272ec30875a99e38a1a4b920d09329f333868915b474'
PRELUDE = 'from product_audit import child;child();'


def directory(path, owned, case):
    refuse_if(type(path) is not str or case not in (*CASES,CLI_CASE), 'speed fixture path primitive')
    acquire(path,owned,OWNER)
    refuse_if(not all(c.isascii() and (c.isalnum() or c in '/._-') for c in path), 'speed source template path')
    return (path,)


def fixture(host):
    value=host.fixture_roots.get(host.case)
    if value is None or directory(value[0],Path(host.meta['owned']),host.case)!=value:
        raise Refused('speed fixture generation')
    return Path(value[0])


def body(tree, operation, root, checkout):
    refuse_if(root is None, 'speed fixture missing')
    function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==NAMES[CASES.index(operation)])
    calls=[node for node in ast.walk(function) if isinstance(node,ast.Call)
           and isinstance(node.func,ast.Name) and node.func.id=='_isolated_python' and len(node.args)==1]
    constants={node.targets[0].id:node.value.value for node in tree.body if isinstance(node,ast.Assign)
               and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)
               and isinstance(node.value,ast.Constant) and type(node.value.value) is str}
    values=({'marker_system':(str(root/'system-marker'),-1),'marker_run':(str(root/'run-marker'),-1)}
            if operation==CASES[0] else {'str(tmp_path)':(str(root),114),
            'str(FIXTURE)':(str(checkout/'tests/fixtures/v04_speed_workloads.v2.json'),114),
            'HEAD':(constants['HEAD'],114),'TREE':(constants['TREE'],114)})
    order=('marker_system','marker_run','marker_system','marker_run') if operation==CASES[0] else ('str(tmp_path)','str(FIXTURE)','HEAD','TREE')
    return render_string(calls[0].args[0],tuple((name,values[name][1],repr(values[name][0]) if values[name][1]==114 else values[name][0]) for name in order))


def cli_expected(native,pin,checkout,root,operation):
    from launch_policy import build_expected
    refuse_if(root is None or operation not in tuple('run-'+str(i) for i in range(5)), 'speed CLI finite run')
    run=root/operation
    refuse_if(run.resolve()!=run, 'speed CLI output alias')
    vector=(native,str(checkout/CLI_TOOL),'--fixture',str(checkout/'tests/fixtures/v04_speed_workloads.v2.json'),
            '--schema',str(checkout/'src/unrest_harness/schemas/v04-speed-result.v2.schema.json'),
            '--result-root',str(run/'artifacts'),'--output',str(run/'speed-result.json'),
            '--candidate-head','c90a98626d7d595b40a3ac0d1ac954f24e1e12ad',
            '--candidate-tree','d05eec79be56cfa8a9011bfa8859e0a65bfc05ad')
    environment=(('LANG','C'),('LC_ALL','C'),('PYTHONUTF8','1'),('TZ','UTC'))
    return build_expected(CLI_CASE,native,pin,vector,environment,str(checkout),'python-script',CLI_PIN)
