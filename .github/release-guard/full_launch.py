"""Fixed env/uv/pytest launch and observer-owned full discovery inventory."""
import json
import os
from pathlib import Path
import subprocess

from case_inventory import LIMIT,document,seal,identity
from content_manifest import Refused,native_digest,read_regular
from control_transport import unique
from full_source import environment,child_environment
from source_profile import pytest_arguments as arguments


def prepare_uv(binding,metadata):
    runtime=Path(metadata['runtime_root'])
    # Warm only stock uv's interpreter metadata before candidate execution.
    # A cache miss during the guarded run never grants a Python helper launch.
    if subprocess.check_output([str(runtime/'bin/uv'),'--version'],text=True,timeout=5).split()[:2]!=['uv','0.11.8']:
        raise Refused('full source supported stock uv version')
    from uv_cli import child_environment as nested_environment
    records=[]
    parent=environment(metadata)
    for _ in range(2):
        raw=subprocess.check_output([str(runtime/'bin/uv'),'run','/usr/bin/env'],
            cwd=metadata['checkout'],env=parent,timeout=30)
        rows=raw.decode().splitlines()
        observed=dict(row.split('=',1) for row in rows)
        expected=nested_environment(metadata,parent)
        records.append({'observed':observed,'expected':expected})
        (Path(binding['profiles']).parent/'source-private/uv-preparation.json').write_text(json.dumps(records,sort_keys=True))
        if len(rows)!=len(observed) or observed!=expected:
            raise Refused('full source stock uv environment')
        parent=expected
    cache=Path(metadata['owned'])/'uv-cache'
    for path in [cache,*sorted(cache.rglob('*'))]:
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise Refused('full source uv cache input')
        os.chown(path,20000,20000)


def prepare(binding,metadata):
    prepare_uv(binding,metadata)
    value={'cases':[],'skips':[],'source':metadata['source_sha256'],'dependency':metadata['dependency_sha256']}
    return {**metadata,'cases':seal(value,Path(binding['profiles']))}


def resolve(host,pid,path,vector,env,cwd):
    runtime=Path(host.meta['runtime_root'])
    birth=host.ledger.current.get(pid)
    if birth is None or cwd!=host.meta['checkout']:
        return False
    process=host.ledger.process(birth)
    if (pid==host.launcher and process.generation==1 and path==str(runtime/'bin/uv')
            and vector==['uv','run',*arguments(host.meta,host.binding)] and env==environment(host.meta)):
        from uv_cli import uv_digest
        pin=uv_digest(Path(path))
        if host.binding['uv']!={'path':path,'sha256':pin}:
            return False
        host.ledger.register(birth,os.urandom(16).hex(),(('uv',pin),),pin,
            case='<full-launcher>',command_class='native-full-uv',expected_generation=2)
        return True
    if (process.parent is None or process.parent.pid!=host.launcher or process.generation!=0
            or path!=str(runtime/'bin/pytest') or vector!=arguments(host.meta,host.binding)
            or env!=child_environment(host.meta) or native_digest(Path(path))!=host.binding['entry']['sha256']):
        return False
    host.root,host.root_birth,host.full_started=pid,birth,True
    host.profile(pid,'root','<bootstrap>',[path,'-I','-S','-m',*arguments(host.meta,host.binding)],env,cwd,os.urandom(16).hex())
    return True


def collection(host,actor,payload):
    from source_observer import shape
    host.root_only(actor)
    shape(payload,('path','sha256'))
    path=Path(host.meta['owned'])/'collection.json'
    if not host.full or host.cases or payload['path']!=str(path):
        raise Refused('full source collection frontier')
    body,_,pin=read_regular(path,LIMIT,uid=20000,mode=0o444)
    if pin!=payload['sha256']:
        raise Refused('full source collection current bytes')
    value=document(json.loads(body,object_pairs_hook=unique))
    if (not value['cases'] or value['skips'] or value['source']!=host.meta['source_sha256']
            or value['dependency']!=host.meta['dependency_sha256']):
        raise Refused('full source complete discovery binding')
    host.cases=tuple(identity(node) for node in value['cases'])
    if len(set(host.cases))!=len(host.cases):
        raise Refused('full source ambiguous case references')
    host.meta['cases']=seal(value,host.directory)
    return {'ok':True,'reference':host.meta['cases']}


def finished(host):
    process=host.ledger.process(host.root_birth)
    if (not host.full_started or process.exit is None or process.exit[1]!=0
            or process.parent_wait is None or process.parent_wait[1]!=0
            or host.ledger.process(host.ledger.current[host.launcher]).exit is None
            or host.ledger.process(host.ledger.current[host.launcher]).exit[1]!=0):
        raise Refused('full source original uv wait missing')
