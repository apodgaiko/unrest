"""Normal pytest discovery through the fixed native console entry.

This plugin adds inventory/outcome accounting; it never selects or deselects a
case. Original skips remain visible and are not provider-acceptance evidence.
"""
import hashlib
import json
from pathlib import Path

import pytest
from content_manifest import Refused
from source_root import OriginalCases
from case_inventory import identity


def environment(metadata):
    runtime, owned = Path(metadata['runtime_root']), Path(metadata['owned'])
    return {'HOME':str(owned/'home'),'TMPDIR':str(owned/'tmp'),
        'PATH':str(runtime/'bin')+':/usr/bin:/bin',
        'UV_PYTHON':str(runtime/'bin/python3.13'),'UV_NO_PROJECT':'1','UV_NO_SYNC':'1',
        'UV_NO_ENV_FILE':'1','UV_PYTHON_DOWNLOADS':'never','UV_CACHE_DIR':str(owned/'uv-cache'),
        'PYTEST_PLUGINS':'full_source','PYTEST_ADDOPTS':'--basetemp='+str(owned/'pytest')+' -o cache_dir='+str(owned/'pytest-cache')}


def child_environment(metadata):
    result=environment(metadata)
    runtime=Path(metadata['runtime_root'])
    return {**result,'PATH':str(runtime/'bin')+':'+result['PATH'],
        'UV':str(runtime/'bin/uv'),'UV_RUN_RECURSION_DEPTH':'1'}


class FullCases(OriginalCases):
    def __init__(self,policy):
        super().__init__(policy)
        self.skips=[]

    def pytest_collection_finish(self,session):
        from case_inventory import document,load
        nodes=[item.nodeid for item in session.items]
        profile=self.policy.profile
        value=document({'cases':nodes,'skips':[], 'source':profile['source_sha256'], 'dependency':profile['dependency_sha256']})
        body=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        path=Path(profile['owned'])/'collection.json'
        with path.open('xb') as stream:
            stream.write(body)
        path.chmod(0o444)
        ref=self.policy.client.request('collection',{'path':str(path),'sha256':hashlib.sha256(body).hexdigest()})
        self.cases=tuple(load(ref,self.policy.directory,profile['source_sha256'],profile['dependency_sha256'])['cases'])
        super().pytest_collection_finish(session)
        self.cases=tuple(identity(node) for node in self.cases)
        if len(set(self.cases))!=len(self.cases):
            raise Refused('full source ambiguous case references')
        profile['cases']=list(self.cases)
        self.policy.calls.install()

    @pytest.hookimpl(hookwrapper=True,tryfirst=True)
    def pytest_runtest_protocol(self,item,nextitem):
        index=len(self.completed)
        if index>=len(self.cases) or item is not self.items[index]:
            raise Refused('full source original cursor')
        policy=self.policy
        case=identity(item.nodeid)
        if case!=self.cases[index]:
            raise Refused('full source original case identity')
        policy.case=case
        policy.client.request('case-start',{'case':case})
        yield
        phases=self.reports.get(case,{})
        skipped=phases in ({'setup':'skipped','teardown':'passed'}, {'setup':'passed','call':'skipped','teardown':'passed'})
        passed=phases=={'setup':'passed','call':'passed','teardown':'passed'}
        if policy.poison:
            raise Refused('full source forbidden effect')
        if skipped:
            self.skips.append(case)
        from controlled_cases import ROOT_HTTP
        if item.nodeid in ROOT_HTTP and passed:
            policy.calls.http.finish()
        policy.client.request('case-finish',{'case':case,'outcome':'skipped' if skipped else 'passed' if passed else 'failed','phases':phases})
        self.completed.append(case)
        policy.case=None

    def pytest_runtest_logreport(self,report):
        self.record(report,identity(report.nodeid))

    def pytest_sessionfinish(self,session,exitstatus):
        if session.config.option.collectonly:
            from source_profile import case_seal
            if exitstatus!=0 or not self.cases or self.policy.poison or self.completed:
                raise Refused('full normal collection failed')
            self.policy.client.request('collection-finish',case_seal(self.cases))
            return
        if exitstatus!=0:
            return  # Ordinary pytest failures retain normal continuation and exit.
        if self.policy.poison or tuple(self.completed)!=self.cases or not self.cases:
            raise Refused('full source incomplete normal discovery')
        from source_profile import case_seal
        self.policy.client.request('root-finish',case_seal(self.completed))


def pytest_configure(config):
    from source_entry import ACTIVE
    if ACTIVE is None or ACTIVE.profile['role']!='root' or type(ACTIVE.profile['cases']) is not dict:
        raise Refused('full source native activation absent')
    config.pluginmanager.register(FullCases(ACTIVE),'release-full-outcomes')
