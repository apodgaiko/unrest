"""Normal pytest discovery through the fixed native console entry.

This plugin adds inventory/outcome accounting; it never selects or deselects a
case. Original skips remain visible and are not provider-acceptance evidence.
"""
import pytest
import hashlib
import json
from pathlib import Path

from content_manifest import Refused, refuse_if
from source_root import OriginalCases
from case_inventory import identity


def environment(metadata):
    runtime, owned = Path(metadata['runtime_root']), Path(metadata['owned'])
    return {'HOME':str(owned/'home'),'TMPDIR':'/tmp',
        'PATH':str(runtime/'bin')+':'+('/native/bin:' if '/native' in metadata.get('mounts',{}) else '')+'/usr/bin:/bin',
        'UV_PYTHON':str(runtime/'bin/python3.13'),'UV_NO_PROJECT':'1',
        'UV_NO_ENV_FILE':'1','UV_PYTHON_DOWNLOADS':'never','UV_CACHE_DIR':str(owned/'uv-cache'),
        'PYTEST_PLUGINS':'full_source','PYTEST_ADDOPTS':'--basetemp='+str(owned/'pytest')+' -o cache_dir='+str(owned/'pytest-cache')}


def child_environment(metadata):
    from uv_cli import child_environment as uv_environment
    return uv_environment(metadata,environment(metadata))


class FullCases(OriginalCases):
    normal_outcomes = True
    def pytest_collection_finish(self,session):
        from case_inventory import document,load
        nodes=[item.nodeid for item in session.items]
        profile=self.policy.profile
        value=document({'cases':nodes,'source':profile['source_sha256'], 'dependency':profile['dependency_sha256']})
        body=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        path=Path(profile['owned'])/'collection.json'
        with path.open('xb') as stream:
            stream.write(body)
        path.chmod(0o444)
        answer=self.policy.client.request('collection',{'path':str(path),'sha256':hashlib.sha256(body).hexdigest()})
        refuse_if(type(answer) is not dict or set(answer)!={'ok','reference'} or answer['ok'] is not True, 'full source inventory acknowledgement')
        ref=answer['reference']
        self.cases=tuple(load(ref,self.policy.directory,profile['source_sha256'],profile['dependency_sha256'])['cases'])
        super().pytest_collection_finish(session)
        self.cases=tuple(identity(node) for node in self.cases)
        profile['cases']=list(self.cases)
        from multiprocess_hooks import install
        install(self.policy)

    @pytest.hookimpl(wrapper=True,tryfirst=True)
    def pytest_sessionfinish(self,session,exitstatus):
        yield
        exitstatus=session.exitstatus
        if exitstatus!=0:
            return  # Ordinary pytest failures retain normal continuation and exit.
        if self.policy.poison or tuple(self.completed)!=self.cases or not self.cases:
            raise Refused('full source incomplete normal discovery')
        from source_profile import case_seal
        self.policy.client.request('root-finish',case_seal(self.completed))


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    from source_entry import ACTIVE
    nested={
        'setup':'cee06040110ea6a36a0377dbd8779a9f994c26471206f5d29ede65a06fa94e31',
        'body':'8be87984b01652aa33b55ab95adc00b4d951352ad8d5ca362f4433b737474e88'}
    if ACTIVE is not None and ACTIVE.profile['role']=='root' and type(ACTIVE.profile['cases']) is list:
        phase=next((phase for phase in nested if ACTIVE.case=='tests/test_session_resource_ownership.py::test_actual_pytest_failure_finalizes_exact_factory['+phase+']'),None)
        args=config.invocation_params.args
        refuse_if(phase is None or len(args)!=4 or args[:3]!=('-c',str(Path(ACTIVE.profile['checkout'])/'pyproject.toml'),'-q'), 'nested pytest exact original invocation')
        source=Path(args[3])
        refuse_if(not source.is_relative_to(Path(ACTIVE.profile['owned'])/'pytest') or source.resolve()!=source
                or source.name!='test_owned_failure_'+phase+'.py' or source.is_symlink()
                or hashlib.sha256(source.read_bytes()).hexdigest()!=nested[phase]
                or getattr(ACTIVE,'nested_case',None)==ACTIVE.case, 'nested pytest exact owned fixture')
        ACTIVE.nested_case=ACTIVE.case
        config.option.basetemp=str(source.parent/'nested-pytest')
        return  # Same active native policy; the outer test owns failure/cleanup assertions.
    if ACTIVE is None or ACTIVE.profile['role']!='root' or type(ACTIVE.profile['cases']) is not dict:
        raise Refused('full source native activation absent')
    config.pluginmanager.register(FullCases(ACTIVE),'release-full-outcomes')
    from prepared_distribution import Provider
    config.pluginmanager.register(Provider(ACTIVE),'release-prepared-distribution')
