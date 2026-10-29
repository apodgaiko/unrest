"""Three exact guarded console paths; installed scripts remain actual file bodies."""
from pathlib import Path
import configparser
import tomllib

from content_manifest import Refused,read_regular,native_digest

REGISTRATIONS={'unrest':'unrest_harness.cli:cli','unrest-server':'unrest_harness.server:main'}


def normalized(runtime,dependencies,name,arguments):
    from prepared_distribution import NAME
    if name=='pytest':
        return [str(runtime/'bin/pytest'),'-I','-S','-m','pytest',*arguments]
    if name not in REGISTRATIONS:
        raise Refused('console exact registration')
    return [str(runtime/'bin/python-unrest-guard-control'),'-I','-S',
        str(dependencies/NAME/'installed/bin'/name),*arguments]


def script(host,name):
    metadata=host.meta
    if name not in REGISTRATIONS:
        raise Refused('console undeclared installed script')
    checkout=Path(metadata['checkout'])
    declaration=tomllib.loads((checkout/'pyproject.toml').read_text())['project']['scripts']
    if declaration!=REGISTRATIONS:
        raise Refused('console current exact project registrations')
    from prepared_distribution import observer_inputs
    value=observer_inputs(host)
    root=value['installed_site']
    names=sorted(root.glob('*.dist-info/entry_points.txt'))
    if len(names)!=1:
        raise Refused('console installed registration cardinality')
    parser=configparser.RawConfigParser(strict=True)
    parser.read_string(read_regular(names[0],65536,uid=0)[0].decode())
    if parser.sections()!=['console_scripts'] or dict(parser['console_scripts'])!=REGISTRATIONS:
        raise Refused('console installed registration bytes')
    path=root/'bin'/name
    pin=native_digest(path)
    if pin!=value['installed_members'].get('bin/'+name):
        raise Refused('console retained installed script changed')
    return path,pin

CASE='tests/test_cli.py::TestUserScopeInit::test_registered_command_launches_from_another_workspace'
CONFIG_ENV={'UNREST_ORCHESTRATOR_PROVIDER':'codex','UNREST_WORKER_PROVIDER':'codex',
    'UNREST_WORKER_ACP_COMMAND':'codex-acp','UNREST_CAPABILITY_PROFILE':'safe','UNREST_CAPABILITY_POLICY_VERSION':'1'}


def standalone_environment(metadata):
    owned=Path(metadata['owned'])
    return {'HOME':str(owned/'home'),'TMPDIR':str(owned/'tmp'),
        'PATH':'/usr/bin:/bin','PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1'}


def proposal(host,actor,raw):
    from owned_fixture import acquire
    from launch_policy import admit_expected,build_expected
    host.root_only(actor)
    if host.case!=CASE or raw['stdin'] is not None:
        raise Refused('console exact unrelated-workspace case')
    runtime=Path(host.meta['runtime_root'])
    cwd=Path(raw['cwd'])
    parent,info=acquire(str(cwd.parent),Path(host.meta['owned']),CASE.split('::')[-1][:30],20000)
    if cwd!=parent/'unrelated workspace' or cwd.resolve()!=cwd:
        raise Refused('console original unrelated workspace')
    generation=(str(parent),info.st_dev,info.st_ino)
    if host.fixture_roots.setdefault(CASE,generation)!=generation:
        raise Refused('console changed original fixture')
    config=parent/'home/.codex/config.toml'
    body,_,_=read_regular(config,65536,uid=20000)
    registration=tomllib.loads(body.decode())['mcp_servers']['unrest']
    if (registration['command']!='unrest-server' or registration['args']!=['--mode','orchestrator']
            or registration['env']!=CONFIG_ENV):
        raise Refused('console actual independently matched registration')
    ambient={**host.meta_environment(),'HOME':str(parent/'home'),'UNREST_HOME':str(parent/'.unrest'),
        'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':CASE+' (call)'}
    environment={**ambient,**CONFIG_ENV}
    vector=['unrest-server','--mode','orchestrator','--help']
    executable=runtime/'bin/unrest-server'
    pin=native_digest(executable)
    if pin!=host.binding['entry']['sha256']:
        raise Refused('console exact native guard bytes')
    file,file_pin=script(host,'unrest-server')
    value=build_expected(CASE,str(executable),pin,tuple(vector),
        tuple(sorted(environment.items())),str(cwd),'native')
    if raw['executable']!='unrest-server':
        raise Refused('console exact registered command')
    effective=normalized(runtime,Path(host.meta['dependencies']),'unrest-server',vector[1:])
    if effective[3]!=str(file):
        raise Refused('console prepared normalized script identity')
    return admit_expected(host,actor,raw,value,'fixed-inline',vector,file_pin,fields={'python_vector':effective})
