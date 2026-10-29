"""Real candidate build/install preparation; never a cached test verdict."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from content_manifest import Refused, capture, read_regular
from control_transport import unique

NAME = '.release-distribution'
OWNER = 0


def files(root):
    rows=sorted(root.rglob('*'))
    if len(rows)>20000 or any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in rows):
        raise Refused('prepared distribution member graph')
    return sorted(path.relative_to(root).as_posix() for path in rows if path.is_file())


def prepare(binding, source, source_manifest, dependencies):
    from compartment import credentials
    from source_host import inventory
    target=dependencies/NAME
    target.mkdir(mode=0o755)
    runtime=Path(binding['entry']['path']).parent.parent
    uv=runtime/'bin/uv'
    if hashlib.sha256(uv.read_bytes()).hexdigest()!=binding['uv']['sha256']:
        raise Refused('prepared stock uv bytes')
    with tempfile.TemporaryDirectory(prefix='package-preparation-',dir=source.parent) as raw:
        work=Path(raw)
        build=work/'source'
        build.mkdir()
        for row in source_manifest['files']:
            path=build/row['path']
            path.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source/row['path'],path)
            path.chmod(row['mode'])
        if capture(build,[row['path'] for row in source_manifest['files']])!=source_manifest:
            raise Refused('prepared candidate source copy')
        for path in (work/'home',work/'cache',work/'archives'):
            path.mkdir()
        for path in (work,*sorted(work.rglob('*'))):
            os.chown(path,20000,20000)
        environment={'HOME':str(work/'home'),'PATH':str(runtime/'bin')+':/usr/bin:/bin',
            'UV_CACHE_DIR':str(work/'cache'),'UV_PYTHON':str(runtime/'bin/python3.13'),
            'UV_PYTHON_DOWNLOADS':'never','UV_LINK_MODE':'copy','PYTHONDONTWRITEBYTECODE':'1',
            'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC'}
        log_file=Path(binding['profiles']).parent/'source-private/package-preparation.log'
        def run(argv,cwd):
            result=subprocess.run(argv,cwd=cwd,env=environment,check=False,capture_output=True,
                timeout=180,preexec_fn=lambda:credentials(20000))
            output=result.stdout+result.stderr
            with log_file.open('ab') as stream:
                stream.write(output[:4*1024*1024])
            if result.returncode or len(output)>4*1024*1024:
                raise Refused('candidate package preparation failed; private log retained')
            return output
        log=run([str(uv),'build','--out-dir',str(work/'archives'),'--verbose'],build)
        if capture(build,[row['path'] for row in source_manifest['files']])!=source_manifest:
            raise Refused('build changed frozen candidate source')
        wheels=sorted((work/'archives').glob('*.whl'))
        if len(wheels)!=1 or len(list((work/'archives').glob('*.tar.gz')))!=1:
            raise Refused('prepared archive cardinality')
        backend=work/'cache/archive-v0'
        if not any(backend.glob('*/setuptools-*.dist-info/METADATA')):
            raise Refused('actual isolated build backend missing')
        capture(backend,files(backend))
        shutil.copytree(backend,target/'backend',symlinks=False)
        log+=run([str(uv),'pip','install','--target',str(work/'installed'),'--no-deps',
            '--force-reinstall',str(wheels[0])],work)
        for name,origin in (('archives',work/'archives'),('installed',work/'installed')):
            capture(origin,files(origin))
            shutil.copytree(origin,target/name,symlinks=False)
        (target/'preparation.log').write_bytes(log)
    for path in (target,*sorted(target.rglob('*'))):
        os.chown(path,0,0)
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode&0o111 else 0o644)
    receipt={'schema':'unrest.prepared-distribution.v1','source':source_manifest,
        'uv':binding['uv']['sha256'],'runtime':inventory(runtime),
        **{name:capture(target/name,files(target/name)) for name in ('backend','archives','installed')}}
    (target/'receipt.json').write_bytes(json.dumps(receipt,sort_keys=True,separators=(',',':')).encode())
    (target/'receipt.json').chmod(0o644)


def inputs(policy):
    profile=policy.profile
    root=Path(profile['dependencies'])/NAME
    body,_,_=read_regular(root/'receipt.json',16*1024*1024,uid=OWNER,mode=0o644)
    receipt=json.loads(body,object_pairs_hook=unique)
    if (type(receipt) is not dict or set(receipt)!={'schema','source','uv','runtime','backend','archives','installed'}
            or receipt['schema']!='unrest.prepared-distribution.v1'
            or receipt['runtime']!=profile['runtime_sha256']
            or hashlib.sha256((Path(profile['runtime_root'])/'bin/uv').read_bytes()).hexdigest()!=receipt['uv']):
        raise Refused('prepared tool/runtime binding')
    source=receipt['source']
    if (capture(Path(profile['checkout']),[row['path'] for row in source['files']])!=source
            or {row['path']:row['sha256'] for row in source['files']}!=policy.pins):
        raise Refused('prepared frozen source binding')
    for name in ('backend','archives','installed'):
        if capture(root/name,files(root/name))!=receipt[name]:
            raise Refused('prepared complete member bytes')
    return {'dist':root/'archives','installed_site':root/'installed','dependency_site':Path(profile['dependencies'])}


class Provider:
    def __init__(self,policy):
        self.policy,self.value=policy,None

    def inputs(self):
        if self.value is None:
            self.value=inputs(self.policy)
        return dict(self.value)
