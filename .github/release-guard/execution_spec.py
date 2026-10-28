"""Exact observer-issued execution domain; no candidate-derived authority."""
from pathlib import Path
import stat

from content_manifest import Refused, capture

LIBRARY = ('mcp','cleanup-acp','session-adapter','session-child','fixed-inline','plan-python','mp-child','mp-tracker','review-wire','pytest-regression','desktop')
SEALED = ('backend','delayed-backend','acp','mock-acp','cleanup-inline','workspace-owned','session-inline')
DOMAINS = {'root':'root', **dict.fromkeys(LIBRARY,'library'), **dict.fromkeys(SEALED,'sealed')}


def issue(role, vector, script, script_pin, data=()):
    if (type(role) is not str or role not in DOMAINS or type(vector) is not list
            or len(vector)<4 or any(type(arg) is not str for arg in vector)
            or vector[1:3]!=['-I','-S']):
        raise Refused('execution specification role or vector')
    if script is not None and (type(script) is not str or not Path(script).is_absolute()):
        raise Refused('execution specification script primitive')
    if vector[3] in ('-c','-m'):
        if len(vector)<5:
            raise Refused('execution specification entry argument')
        event='cpython.run_command' if vector[3]=='-c' else 'cpython.run_module'
        argument=vector[4]+('\n' if vector[3]=='-c' else '')
    else:
        event,argument='cpython.run_file',vector[3]
        if script!=argument or not Path(argument).is_absolute():
            raise Refused('execution specification script path')
    if script is not None and vector[3]=='-c' and (role!='delayed-backend' or len(vector)<6 or vector[5]!=script):
        raise Refused('execution specification auxiliary script path')
    if script_pin is not None and (type(script_pin) is not str or len(script_pin)!=64 or any(char not in '0123456789abcdef' for char in script_pin)):
        raise Refused('execution specification script digest')
    if (script is None)!=(script_pin is None):
        raise Refused('execution specification script pin presence')
    return {'domain':DOMAINS[role],'event':event,'argument':argument,'script_sha256':script_pin,'data':list(data)}


def validate(profile,event,arguments,directory):
    value=profile['execution']
    if (type(value) is not dict or set(value)!={'domain','event','argument','script_sha256','data'}
            or type(value['data']) is not list or len(value['data'])!=(1 if profile['role'] in ('cleanup-acp','review-wire') else 0)
            or value!=issue(profile['role'],profile['argv'],profile['script'],value['script_sha256'],value['data'])
            or event!=value['event'] or arguments!=(value['argument'],)):
        raise Refused('execution specification exact body or domain')
    if profile['script'] is not None:
        file=Path(profile['script'])
        if (type(profile['script']) is not str or str(file.resolve())!=str(file)
                or capture(file.parent,[file.name])['files'][0]['sha256']!=value['script_sha256']):
            raise Refused('execution specification current script bytes')
    for row in value['data']:
        if type(row) is not list or len(row)!=2 or any(type(part) is not str for part in row):
            raise Refused('execution specification immutable data record')
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
            and value['pid']==pid and value['translated']==vector
            and value['environment']==environment and value['cwd']==cwd]
    if len(values)!=1:
        raise Refused('execution specification unique admitted intent')
    value=values[0]
    return issue(role,vector,script,value['script_sha256'] if script is not None else None,value.get('execution_data',()))
