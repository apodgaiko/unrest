"""Observer-owned normal-discovery inventory; profiles carry a small reference."""
import hashlib
import json
import os
from pathlib import Path

from content_manifest import Refused as Refused, read_regular, is_sha256, refuse_if
from control_transport import unique

LIMIT=8*1024*1024
# Product monkeypatches must not rewrite framework case identities.
_STRING,_SHA=json.dumps,hashlib.sha256


def identity(node):
    encoded=_STRING(node,ensure_ascii=True).encode()
    return node if len(encoded)<=1024 else '@node:'+_SHA(encoded).hexdigest()


def environment(values,case):
    current=values.get('PYTEST_CURRENT_TEST')
    if type(current) is not str or ' (' not in current:
        return values
    node,phase=current.rsplit(' (',1)
    name=identity(node)
    if name==node or name!=case or phase not in ('setup)','call)','teardown)'):
        return values
    return {**values,'PYTEST_CURRENT_TEST':name+' ('+phase}


def document(value):
    refuse_if(type(value) is not dict or set(value)!={'cases','source','dependency'}
            or any(not is_sha256(value[name]) for name in ('source','dependency')), 'inventory input binding')
    rows=value['cases']
    refuse_if(type(rows) is not list or len(rows)>20000 or any(type(row) is not str or not row or len(row)>131071 for row in rows)
            or len(set(rows))!=len(rows), 'inventory finite nodes')
    refuse_if(sum(len(json.dumps(row)) for row in rows)>LIMIT, 'inventory total node bytes')
    return value


def reference(value,directory):
    refuse_if(type(value) is not dict or set(value)!={'path','sha256','count'}
            or not is_sha256(value['sha256'])
            or type(value['count']) is not int or not 0<=value['count']<=20000
            or value['path']!=str(directory/('cases-'+value['sha256']+'.json')), 'inventory reference')


def load(value,directory,source,dependency):
    reference(value,directory)
    path=Path(value['path'])
    body,_,pin=read_regular(path,LIMIT,uid=20001,mode=0o444)
    refuse_if(pin!=value['sha256'], 'inventory current bytes')
    result=document(json.loads(body,object_pairs_hook=unique))
    refuse_if(len(result['cases'])!=value['count'] or (result['source'],result['dependency'])!=(source,dependency), 'inventory source generation')
    return result


def seal(value,directory):
    body=json.dumps(document(value),sort_keys=True,separators=(',',':')).encode()
    refuse_if(len(body)>LIMIT, 'inventory byte bound')
    digest=hashlib.sha256(body).hexdigest()
    path=directory/('cases-'+digest+'.json')
    with path.open('xb') as stream:
        stream.write(body)
    os.chown(path,20001,20001)
    path.chmod(0o444)
    return {'path':str(path),'sha256':digest,'count':len(value['cases'])}
