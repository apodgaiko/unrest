"""Fixed env/uv/pytest launch and observer-owned full discovery inventory."""
import json
import os
from pathlib import Path
import subprocess

from case_inventory import LIMIT,document,seal,identity
from content_manifest import Refused as Refused, native_digest, read_regular, refuse_if
from control_transport import unique
from full_source import environment,child_environment
from source_profile import PYTEST_COMMAND


def prepare_uv(metadata):
    runtime=Path(metadata['runtime_root'])
    # Warm only stock uv's interpreter metadata before candidate execution.
    # A cache miss during the guarded run never grants a Python helper launch.
    refuse_if(subprocess.check_output([str(runtime/'bin/uv'),'--version'],text=True,timeout=5).split()[:2]!=['uv','0.11.8'], 'full source supported stock uv version')
    subprocess.check_output([str(runtime/'bin/uv'),'run','/usr/bin/env'],
        cwd=metadata['checkout'],env=environment(metadata),timeout=30)
    cache=Path(metadata['owned'])/'uv-cache'
    for path in [cache,*sorted(cache.rglob('*'))]:
        refuse_if(path.is_symlink() or not (path.is_file() or path.is_dir()), 'full source uv cache input')
        os.chown(path,20000,20000)


def prepare(binding,metadata):
    prepare_uv(metadata)
    value={'cases':[],'source':metadata['source_sha256'],'dependency':metadata['dependency_sha256']}
    return {**metadata,'cases':seal(value,Path(binding['profiles']))}


def resolve(host,pid,path,vector,env,cwd):
    runtime=Path(host.meta['runtime_root'])
    birth=host.ledger.current.get(pid)
    if birth is None or cwd!=host.meta['checkout']:
        return False
    process=host.ledger.process(birth)
    if (pid==host.launcher and process.generation==1 and path==str(runtime/'bin/uv')
            and vector==['uv','run',*PYTEST_COMMAND] and env==environment(host.meta)):
        from uv_cli import uv_digest
        pin=uv_digest(Path(path))
        if host.binding['uv']!={'path':path,'sha256':pin}:
            return False
        host.ledger.register(birth,os.urandom(16).hex(),(('uv',pin),),
            case='<full-launcher>',command_class='native-full-uv',expected_generation=2)
        return True
    if (process.parent is None or process.parent.pid!=host.launcher or process.generation!=0
            or path!=str(runtime/'bin/pytest') or vector!=list(PYTEST_COMMAND)
            or env!=child_environment(host.meta) or native_digest(Path(path))!=host.binding['entry']['sha256']):
        return False
    host.root,host.root_birth,host.full_started=pid,birth,True
    host.profile(pid,'root','<bootstrap>',[path,'-I','-S','-m',*PYTEST_COMMAND],env,cwd,os.urandom(16).hex())
    return True


def collection(host,actor,payload):
    from source_observer import shape
    host.root_only(actor)
    shape(payload,('path','sha256'))
    path=Path(host.meta['owned'])/'collection.json'
    refuse_if(not host.full or host.cases or payload['path']!=str(path), 'full source collection frontier')
    body,_,pin=read_regular(path,LIMIT,uid=20000,mode=0o444)
    refuse_if(pin!=payload['sha256'], 'full source collection current bytes')
    value=document(json.loads(body,object_pairs_hook=unique))
    refuse_if(not value['cases'] or value['source']!=host.meta['source_sha256']
            or value['dependency']!=host.meta['dependency_sha256'], 'full source complete discovery binding')
    host.cases=tuple(identity(node) for node in value['cases'])
    refuse_if(len(set(host.cases))!=len(host.cases), 'full source ambiguous case references')
    host.meta['cases']=seal(value,host.directory)
    return {'ok':True,'reference':host.meta['cases']}


def finished(host):
    process=host.ledger.process(host.root_birth)
    refuse_if(not host.full_started or process.exit is None or process.exit[1]!=0
            or process.parent_wait is None or process.parent_wait[1]!=0
            or host.ledger.process(host.ledger.current[host.launcher]).exit is None
            or host.ledger.process(host.ledger.current[host.launcher]).exit[1]!=0, 'full source requires successful pytest and original uv waits')
