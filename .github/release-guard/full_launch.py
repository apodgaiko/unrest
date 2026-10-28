"""Fixed env/uv/pytest launch and observer-owned full discovery inventory."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from case_inventory import LIMIT,document,seal
from content_manifest import Refused,native_digest
from control_transport import unique
from full_source import environment,child_environment


def prepare(binding,metadata):
    runtime=Path(metadata['runtime_root'])
    # Warm only stock uv's interpreter metadata before candidate execution.
    # A cache miss during the guarded run never grants a Python helper launch.
    if subprocess.check_output([str(runtime/'bin/uv'),'--version'],text=True,timeout=5).split()[:2]!=['uv','0.11.8']:
        raise Refused('full source supported stock uv version')
    raw=subprocess.check_output([str(runtime/'bin/uv'),'run','/usr/bin/env'],
        cwd=metadata['checkout'],env=environment(metadata),timeout=30)
    rows=raw.decode().splitlines()
    observed=dict(row.split('=',1) for row in rows)
    (Path(binding['profiles']).parent/'source-private/uv-preparation.json').write_text(json.dumps({'observed':observed,'expected':child_environment(metadata)},sort_keys=True))
    if len(rows)!=len(observed) or observed!=child_environment(metadata):
        raise Refused('full source stock uv environment')
    cache=Path(metadata['owned'])/'uv-cache'
    for path in [cache,*sorted(cache.rglob('*'))]:
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise Refused('full source uv cache input')
        os.chown(path,20000,20000)
    value={'cases':[],'skips':[],'source':metadata['source_sha256'],'dependency':metadata['dependency_sha256']}
    return {**metadata,'cases':seal(value,Path(binding['profiles']))}


def resolve(host,pid,path,vector,env,cwd):
    runtime=Path(host.meta['runtime_root'])
    birth=host.ledger.current.get(pid)
    if birth is None or cwd!=host.meta['checkout']:
        return False
    process=host.ledger.process(birth)
    if (pid==host.launcher and process.generation==1 and path==str(runtime/'bin/uv')
            and vector==['uv','run','pytest','-q',*(['--collect-only'] if host.binding.get('collection_only') else [])] and env==environment(host.meta)):
        pin=native_digest(Path(path))
        host.ledger.register(birth,os.urandom(16).hex(),(('uv',pin),),pin,
            case='<full-launcher>',command_class='native-full-uv',expected_generation=2)
        return True
    if (process.parent is None or process.parent.pid!=host.launcher or process.generation!=0
            or path!=str(runtime/'bin/pytest') or vector!=[path,'-q',*(['--collect-only'] if host.binding.get('collection_only') else [])]
            or env!=child_environment(host.meta) or native_digest(Path(path))!=host.binding['entry']['sha256']):
        return False
    host.root,host.root_birth,host.full_started=pid,birth,True
    host.profile(pid,'root','<bootstrap>',[path,'-I','-S','-m','pytest','-q',*(['--collect-only'] if host.binding.get('collection_only') else [])],env,cwd,os.urandom(16).hex())
    return True


def collection(host,actor,payload):
    from source_observer import shape
    host.root_only(actor)
    shape(payload,('path','sha256'))
    path=Path(host.meta['owned'])/'collection.json'
    if not host.full or host.cases or payload['path']!=str(path):
        raise Refused('full source collection frontier')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        from native_entry import key
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=20000 or before.st_nlink!=1
                or stat.S_IMODE(before.st_mode)!=0o444 or before.st_size>LIMIT):
            raise Refused('full source collection custody')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            body=stream.read(LIMIT+1)
        if (len(body)!=before.st_size or key(before)!=key(os.fstat(fd)) or key(before)!=key(path.lstat())
                or hashlib.sha256(body).hexdigest()!=payload['sha256']):
            raise Refused('full source collection current bytes')
    finally:
        os.close(fd)
    value=document(json.loads(body,object_pairs_hook=unique))
    if (not value['cases'] or value['skips'] or value['source']!=host.meta['source_sha256']
            or value['dependency']!=host.meta['dependency_sha256']):
        raise Refused('full source complete discovery binding')
    host.cases=tuple(value['cases'])
    host.meta['cases']=seal(value,host.directory)
    return host.meta['cases']


def finished(host):
    process=host.ledger.process(host.root_birth)
    if (not host.full_started or process.exit is None or process.exit[1]!=0
            or process.parent_wait is None or process.parent_wait[1]!=0
            or host.ledger.process(host.ledger.current[host.launcher]).exit is None
            or host.ledger.process(host.ledger.current[host.launcher]).exit[1]!=0):
        raise Refused('full source original uv wait missing')
