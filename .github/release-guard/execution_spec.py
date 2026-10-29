"""Exact observer-issued execution domain; no candidate-derived authority."""
from pathlib import Path
import stat

from content_manifest import Refused, capture

def issue(role, vector, script, script_pin, data=(), fixture=None):
    if vector[3] in ('-c','-m'):
        event='cpython.run_command' if vector[3]=='-c' else 'cpython.run_module'
        argument=vector[4]+('\n' if vector[3]=='-c' else '')
    else:
        event,argument='cpython.run_file',vector[3]
    return {'event':event,'argument':argument,'script_sha256':script_pin,'data':list(data),'fixture':fixture}


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
    if profile['role']=='archive-leaf':
        archive_snapshot(profile,directory)
    for row in value['data']:
        file=Path(row[0])
        info=file.stat(follow_symlinks=False)
        if (file.parent!=directory or str(file.resolve())!=str(file) or not stat.S_ISREG(info.st_mode)
                or info.st_uid!=20001 or stat.S_IMODE(info.st_mode)!=0o444 or info.st_nlink!=1
                or capture(file.parent,[file.name])['files'][0]['sha256']!=row[1]
                or profile['argv'][-1]!=str(file)):
            raise Refused('execution specification immutable data binding')


def admitted(intents,role,case,pid,token,vector,environment,cwd,script):
    values=[value for value in intents.values() if value['token']==token
            and value['case']==case and value['role']==role and value['consumed']
            and value['pid']==pid and value.get('python_vector',value['translated'])==vector
            and value['environment']==environment and value['cwd']==cwd]
    if len(values)!=1:
        raise Refused('execution specification unique admitted intent')
    value=values[0]
    return issue(role,vector,script,value['script_sha256'] if script is not None else None,value.get('execution_data',()),value.get('execution_fixture'))


def archive_snapshot(profile,directory):
    import json
    from content_manifest import read_regular
    from control_transport import unique
    from package_cases import NEGATIVE
    from archive_snapshot import retained
    file,pin=profile['execution']['data'][0]
    body,_,actual=read_regular(Path(file),16*1024*1024,uid=20001,mode=0o444)
    document=json.loads(body,object_pairs_hook=unique)
    if (actual!=pin or type(document) is not dict or set(document)!={'schema','case','kind','root','snapshot'}
            or document['schema']!='unrest.archive-snapshot.v1' or document['case']!=profile['case']
            or document['kind']!=NEGATIVE.get(profile['case'],'normal') or document['root']!=profile['cwd']
            or Path(document['root']).parent!=directory):
        raise Refused('archive exact admitted snapshot reference')
    retained(Path(document['root']),document['snapshot'])
