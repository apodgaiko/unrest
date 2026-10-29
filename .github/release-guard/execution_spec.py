"""Exact observer-issued execution domain; no candidate-derived authority."""
from pathlib import Path

from content_manifest import Refused, capture

def issue(role, vector, script, script_pin, fixture=None):
    if vector[3] in ('-c','-m'):
        event='cpython.run_command' if vector[3]=='-c' else 'cpython.run_module'
        argument=vector[4]+('\n' if vector[3]=='-c' else '')
    else:
        event,argument='cpython.run_file',vector[3]
    return {'event':event,'argument':argument,'script_sha256':script_pin,'fixture':fixture}


def validate(profile,event,arguments,directory):
    value=profile['execution']
    if event!=value['event'] or arguments!=(value['argument'],):
        raise Refused('execution specification exact body or domain')
    if value['fixture'] is not None:
        from run_worker_launch import WORKERS
        binding=value['fixture']
        if (profile['case'] not in WORKERS or profile['role']!='fixed-inline'
                or profile['argv'][3:5]!=['-m','unrest_harness.run_worker']
                or binding['path']!=str(Path(profile['cwd'])/'executor_fixture.py')):
            raise Refused('execution specification finite executor fixture')
    if profile['script'] is not None:
        file=Path(profile['script'])
        if (str(file.resolve())!=str(file)
                or capture(file.parent,[file.name])['files'][0]['sha256']!=value['script_sha256']):
            raise Refused('execution specification current script bytes')


def admitted(intents,role,case,pid,token,vector,environment,cwd,script):
    values=[value for value in intents.values() if value['token']==token
            and value['case']==case and value['role']==role and value['consumed']
            and value['pid']==pid and value.get('python_vector',value['translated'])==vector
            and value['environment']==environment and value['cwd']==cwd]
    if len(values)!=1:
        raise Refused('execution specification unique admitted intent')
    value=values[0]
    return issue(role,vector,script,value['script_sha256'] if script is not None else None,value.get('execution_fixture'))

