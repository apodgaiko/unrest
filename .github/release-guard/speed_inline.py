"""Two original isolated programs bound to an acquired pytest fixture directory."""
import ast
from pathlib import Path

from content_manifest import Refused
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
    if type(path) is not str or case not in (*CASES,CLI_CASE):
        raise Refused('speed fixture path primitive')
    prefix='v04-speed-runs' if case==CLI_CASE else NAMES[CASES.index(case)][:30]
    root,info=acquire(path,owned,prefix,OWNER)
    if not all(c.isascii() and (c.isalnum() or c in '/._-') for c in path):
        raise Refused('speed source template path')
    return path,info.st_dev,info.st_ino,info.st_mode,info.st_uid


def fixture(host):
    value=host.fixture_roots.get(host.case)
    if value is None or directory(value[0],Path(host.meta['owned']),host.case)!=value:
        raise Refused('speed fixture generation')
    return Path(value[0])


def body(tree, operation, root, checkout):
    if root is None:
        raise Refused('speed fixture missing')
    function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==NAMES[CASES.index(operation)])
    calls=[node for node in ast.walk(function) if isinstance(node,ast.Call)
           and isinstance(node.func,ast.Name) and node.func.id=='_isolated_python' and len(node.args)==1]
    if len(calls)!=1 or not isinstance(calls[0].args[0],ast.JoinedStr):
        raise Refused('speed sole string template')
    constants={node.targets[0].id:node.value.value for node in tree.body if isinstance(node,ast.Assign)
               and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)
               and isinstance(node.value,ast.Constant) and type(node.value.value) is str}
    values=({'marker_system':(str(root/'system-marker'),-1),'marker_run':(str(root/'run-marker'),-1)}
            if operation==CASES[0] else {'str(tmp_path)':(str(root),114),
            'str(FIXTURE)':(str(checkout/'tests/fixtures/v04_speed_workloads.v2.json'),114),
            'HEAD':(constants['HEAD'],114),'TREE':(constants['TREE'],114)})
    result=[]
    for part in calls[0].args[0].values:
        if isinstance(part,ast.Constant) and type(part.value) is str:
            result.append(part.value)
        elif isinstance(part,ast.FormattedValue) and part.format_spec is None:
            value=values.get(ast.unparse(part.value))
            if value is None or part.conversion!=value[1]:
                raise Refused('speed closed string substitution')
            result.append(repr(value[0]) if value[1]==114 else value[0])
        else:
            raise Refused('speed string template shape')
    return ''.join(result)


def cli_expected(native,pin,checkout,root,operation):
    from launch_policy import build_expected
    if root is None or operation not in tuple('run-'+str(i) for i in range(5)):
        raise Refused('speed CLI finite run')
    run=root/operation
    if run.resolve()!=run:
        raise Refused('speed CLI output alias')
    vector=(native,str(checkout/CLI_TOOL),'--fixture',str(checkout/'tests/fixtures/v04_speed_workloads.v2.json'),
            '--schema',str(checkout/'src/unrest_harness/schemas/v04-speed-result.v2.schema.json'),
            '--result-root',str(run/'artifacts'),'--output',str(run/'speed-result.json'),
            '--candidate-head','c90a98626d7d595b40a3ac0d1ac954f24e1e12ad',
            '--candidate-tree','d05eec79be56cfa8a9011bfa8859e0a65bfc05ad')
    environment=(('LANG','C'),('LC_ALL','C'),('PYTHONUTF8','1'),('TZ','UTC'))
    return build_expected(CLI_CASE,native,pin,vector,environment,str(checkout),'python-script',CLI_PIN)
