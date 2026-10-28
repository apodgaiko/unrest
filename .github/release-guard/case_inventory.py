"""Observer-owned normal-discovery inventory; profiles carry a small reference."""
import hashlib
import json
import os
from pathlib import Path
import stat

from content_manifest import Refused
from control_transport import unique
from native_entry import key

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
    if (type(value) is not dict or set(value)!={'cases','skips','source','dependency'}
            or any(type(value[name]) is not str or len(value[name])!=64
                or any(c not in '0123456789abcdef' for c in value[name]) for name in ('source','dependency'))):
        raise Refused('inventory input binding')
    for name in ('cases','skips'):
        rows=value[name]
        if (type(rows) is not list or len(rows)>20000 or any(type(row) is not str or not row or len(row)>131071 for row in rows)
                or len(set(rows))!=len(rows)):
            raise Refused('inventory finite nodes')
    if sum(len(json.dumps(row)) for name in ('cases','skips') for row in value[name])>LIMIT:
        raise Refused('inventory total node bytes')
    if not set(value['skips'])<=set(value['cases']):
        raise Refused('inventory skip subset')
    return value


def reference(value,directory):
    if (type(value) is not dict or set(value)!={'path','sha256','count'}
            or type(value['sha256']) is not str or len(value['sha256'])!=64
            or any(c not in '0123456789abcdef' for c in value['sha256'])
            or type(value['count']) is not int or not 0<=value['count']<=20000
            or value['path']!=str(directory/('cases-'+value['sha256']+'.json'))):
        raise Refused('inventory reference')
    info=Path(value['path']).lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=20001 or info.st_nlink!=1
            or stat.S_IMODE(info.st_mode)!=0o444 or info.st_size>LIMIT):
        raise Refused('inventory protected file')
    return value


def load(value,directory,source,dependency):
    reference(value,directory)
    path=Path(value['path'])
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        with os.fdopen(fd,'rb',closefd=False) as stream:
            body=stream.read(LIMIT+1)
        if (len(body)!=before.st_size or key(before)!=key(os.fstat(fd))
                or key(before)!=key(path.lstat()) or hashlib.sha256(body).hexdigest()!=value['sha256']):
            raise Refused('inventory current bytes')
    finally:
        os.close(fd)
    result=document(json.loads(body,object_pairs_hook=unique))
    if len(result['cases'])!=value['count'] or (result['source'],result['dependency'])!=(source,dependency):
        raise Refused('inventory source generation')
    return result


def seal(value,directory):
    body=json.dumps(document(value),sort_keys=True,separators=(',',':')).encode()
    if len(body)>LIMIT:
        raise Refused('inventory byte bound')
    digest=hashlib.sha256(body).hexdigest()
    path=directory/('cases-'+digest+'.json')
    with path.open('xb') as stream:
        stream.write(body)
    os.chown(path,20001,20001)
    path.chmod(0o444)
    return {'path':str(path),'sha256':digest,'count':len(value['cases'])}
