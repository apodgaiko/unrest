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


def files(root):
    rows=sorted(root.rglob('*'))
    if len(rows)>20000 or any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in rows):
        raise Refused('prepared distribution member graph')
    return sorted(path.relative_to(root).as_posix() for path in rows if path.is_file())


def tree(root):
    return {'content':capture(root,files(root)),
        'directories':sorted(path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_dir())}


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
        from archive_leaf import oracle
        extracted=oracle(source)._extract_sdist_safely(next((target/'archives').glob('*.tar.gz')),work/'extracted')
        capture(extracted,files(extracted))
        shutil.copytree(extracted,target/'extracted',symlinks=False)
        (target/'preparation.log').write_bytes(log)
    for path in (target,*sorted(target.rglob('*'))):
        os.chown(path,0,0)
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode&0o111 else 0o644)
    receipt={'schema':'unrest.prepared-distribution.v1','source':source_manifest,
        'uv':binding['uv']['sha256'],'runtime':inventory(runtime),
        **{name:tree(target/name) for name in ('backend','archives','installed','extracted')}}
    (target/'receipt.json').write_bytes(json.dumps(receipt,sort_keys=True,separators=(',',':')).encode())
    (target/'receipt.json').chmod(0o644)
    info=(target/'archives').stat()
    diagnostic={'receipt':receipt,'archives_identity':[info.st_uid,info.st_gid,info.st_mode]}
    (Path(binding['profiles']).parent/'source-private/package-inputs.json').write_text(json.dumps(diagnostic,sort_keys=True))


def inputs(profile):
    root=Path(profile['dependencies'])/NAME
    return {'dist':root/'archives','installed_site':root/'installed','dependency_site':Path(profile['dependencies']),'extracted':root/'extracted'}


def observer_inputs(host):
    key='<prepared-distribution>'
    if key not in host.fixture_roots:
        value=inputs(host.meta)
        body,_,_=read_regular(Path(host.meta['dependencies'])/NAME/'receipt.json',16*1024*1024,uid=0,mode=0o644)
        receipt=json.loads(body,object_pairs_hook=unique)
        value['installed_members']={row['path']:row['sha256'] for row in receipt['installed']['content']['files']}
        host.fixture_roots[key]=value
    return host.fixture_roots[key]


class Provider:
    def __init__(self,policy):
        self.policy=policy

    def inputs(self):
        return inputs(self.policy.profile)


    def snapshot(self,path):
        reply=self.policy.client.request('archive-snapshot',{'path':str(path)})
        if type(reply) is not dict or set(reply)!={'ok','path'} or reply['ok'] is not True or type(reply['path']) is not str:
            raise Refused('snapshot acquisition acknowledgement')
        root=Path(reply['path'])
        if root.parent!=self.policy.directory or root.resolve(strict=True)!=root:
            raise Refused('snapshot observer-selected root')
        return root
