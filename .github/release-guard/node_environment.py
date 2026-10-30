"""Exact security settings and scoped application data for owned role processes."""
import json
from pathlib import Path

from content_manifest import Refused
from control_transport import unique


def baseline(ambient,home,project):
    return {**{key:ambient[key] for key in ('HOME','LANG','LC_ALL','NO_PROXY','PATH','SSL_CERT_DIR',
        'SSL_CERT_FILE','TEMP','TMP','TMPDIR') if key in ambient},
        'UNREST_CAPABILITY_PROFILE':'safe','UNREST_CAPABILITY_POLICY_VERSION':'1',
        'UNREST_HOME':str(home),'UNREST_PROJECT_ID':project,'UNREST_MISSION_ID':'mission-001'}


def environment(ambient,home,project,node,role,attempt):
    result=baseline(ambient,home,project)
    runtime=home/'projects'/project/'.unrest-runtime/missions/mission-001'
    if role=='terminal_reviewer':
        result['UNREST_TERMINAL_REVIEW_PATH']=str(runtime/'terminal-reviews'/(attempt+'.json'))
    else:
        result.update(UNREST_NODE_ID=node,UNREST_NODE_TYPE=role,
            UNREST_HANDOFF_PATH=str(runtime/'attempts'/(attempt+'__'+node+'.json')))
    return result


def scoped(observed,base,home,project,role,*,module):
    def component(value):
        if (type(value) is not str or not 0<len(value)<=4096 or value in ('.','..')
                or any(char in value for char in ('/','\\','\0'))):
            raise Refused('node scoped data component')
        return value
    mission=component(observed.get('UNREST_MISSION_ID'))
    runtime=home/'projects'/project/'.unrest-runtime/missions'/mission
    if role=='terminal_reviewer':
        key='UNREST_TERMINAL_REVIEW_PATH'
        path=Path(observed.get(key,''))
        component(path.stem)
        valid=path.parent==runtime/'terminal-reviews' and path.suffix=='.json'
        data={key:str(path)}
    else:
        node=component(observed.get('UNREST_NODE_ID'))
        key='UNREST_HANDOFF_PATH'
        path=Path(observed.get(key,''))
        suffix='__'+node+'.json'
        valid=path.parent==runtime/'attempts' and path.name.endswith(suffix)
        component(path.name[:-len(suffix)])
        data={key:str(path),'UNREST_NODE_ID':node,'UNREST_NODE_TYPE':role}
        if module:
            body=observed.get('UNREST_NODE_ASSIGNMENT','')
            if type(body) is not str or len(body)>8192:
                raise Refused('node assignment bound')
            try:
                value=json.loads(body,object_pairs_hook=unique)
            except (ValueError,RecursionError):
                raise Refused('node assignment JSON') from None
            if (type(value) is not dict or set(value)!={'targets','task_type'} or value['task_type']!=role
                    or type(value['targets']) is not list or len(value['targets'])>128
                    or any(type(item) is not str or not 0<len(item)<=4096 or '\0' in item for item in value['targets'])):
                raise Refused('node assignment data shape')
            data['UNREST_NODE_ASSIGNMENT']=body
    if not valid or path.resolve()!=path:
        raise Refused('node output outside acquired project')
    expected={**base,'UNREST_HOME':str(home),'UNREST_PROJECT_ID':project,'UNREST_MISSION_ID':mission,**data}
    if observed!=expected:
        raise Refused('node exact security environment')
    return expected
