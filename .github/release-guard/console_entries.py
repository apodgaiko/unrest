"""Three exact guarded console paths; installed scripts remain actual file bodies."""
from pathlib import Path

from content_manifest import Refused as Refused, native_digest, refuse_if

REGISTRATIONS={'unrest':'unrest_harness.cli:cli','unrest-server':'unrest_harness.server:main'}


def normalized(runtime,dependencies,name,arguments):
    from prepared_distribution import NAME
    if name=='pytest':
        return [str(runtime/'bin/pytest'),'-I','-S','-m','pytest',*arguments]
    refuse_if(name not in REGISTRATIONS, 'console exact registration')
    return [str(runtime/'bin/python-unrest-guard-control'),'-I','-S',
        str(dependencies/NAME/'installed/bin'/name),*arguments]


def script(host,name):
    refuse_if(name not in REGISTRATIONS, 'console undeclared installed script')
    from prepared_distribution import observer_inputs
    value=observer_inputs(host)
    root=value['installed_site']
    path=root/'bin'/name
    pin=native_digest(path)
    refuse_if(pin!=value['installed_members'].get('bin/'+name), 'console retained installed script changed')
    return path,pin

CASE='tests/test_cli.py::TestUserScopeInit::test_registered_command_launches_from_another_workspace'
CONFIG_ENV={'UNREST_ORCHESTRATOR_PROVIDER':'codex','UNREST_WORKER_PROVIDER':'codex',
    'UNREST_WORKER_ACP_COMMAND':'codex-acp','UNREST_CAPABILITY_PROFILE':'safe','UNREST_CAPABILITY_POLICY_VERSION':'1'}


def standalone_environment(metadata):
    owned=Path(metadata['owned'])
    return {'HOME':str(owned/'home'),'TMPDIR':'/tmp',
        'PATH':'/usr/bin:/bin','PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1'}


def proposal(host,actor,raw):
    from owned_fixture import retain
    from launch_policy import admit_expected,build_expected
    host.root_only(actor)
    refuse_if(host.case!=CASE or raw['stdin'] is not None, 'console exact unrelated-workspace case')
    runtime=Path(host.meta['runtime_root'])
    cwd=Path(raw['cwd'])
    parent=retain(host,cwd.parent, 20000)
    refuse_if(cwd!=parent/'unrelated workspace' or cwd.resolve()!=cwd, 'console original unrelated workspace')
    ambient={**host.meta_environment(),'HOME':str(parent/'home'),'UNREST_HOME':str(parent/'.unrest'),
        'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':CASE+' (call)'}
    environment={**ambient,**CONFIG_ENV}
    vector=['unrest-server','--mode','orchestrator','--help']
    executable=runtime/'bin/unrest-server'
    pin=native_digest(executable)
    refuse_if(pin!=host.binding['entry']['sha256'], 'console exact native guard bytes')
    _,file_pin=script(host,'unrest-server')
    value=build_expected(CASE,str(executable),pin,tuple(vector),
        tuple(sorted(environment.items())),str(cwd),'native')
    refuse_if(raw['executable']!='unrest-server', 'console exact registered command')
    effective=normalized(runtime,Path(host.meta['dependencies']),'unrest-server',vector[1:])
    return admit_expected(host,actor,raw,value,'fixed-inline',vector,file_pin,fields={'python_vector':effective})
