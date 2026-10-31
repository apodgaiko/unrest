"""Trusted preparation changes import cost without compiling any source body."""
import importlib.util
import json
from pathlib import Path
import py_compile
import subprocess
import sys

import pytest

from source_host import inventory,prepare_bytecode


def header(file):
    body=Path(importlib.util.cache_from_source(str(file))).read_bytes()
    assert body[:4]==importlib.util.MAGIC_NUMBER
    assert int.from_bytes(body[4:8],'little')==3
    assert body[8:16]==importlib.util.source_hash(file.read_bytes())
    return body


def test_checked_support_is_regenerated_measured_and_consumed_without_source_compilation(tmp_path):
    dependencies=tmp_path/'dependencies'
    support=tmp_path/'support'
    source=tmp_path/'source'
    for root in (dependencies,support,source):
        root.mkdir()
        (root/'fixture.py').write_text('value=29\n')
    module=support/'fixture.py'
    py_compile.compile(str(module),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
    stale=Path(importlib.util.cache_from_source(str(module)))
    assert int.from_bytes(stale.read_bytes()[4:8],'little')==0
    source_pin=inventory(source)
    prepare_bytecode({'runtime':{'path':sys.executable},'support':str(support)},dependencies,tmp_path/'preparation.log')
    for root in (dependencies,support):
        header(root/'fixture.py')
    assert inventory(source)==source_pin and not (source/'__pycache__').exists()
    program="""import sys,json
sys.path.insert(0,sys.argv[1]);events=[]
sys.addaudithook(lambda event,args: events.append(event) if event=='compile' else None)
import fixture
print(json.dumps({'value':fixture.value,'compilations':len(events)}))
"""
    result=subprocess.run([sys.executable,'-I','-S','-B','-c',program,str(support)],check=True,
        capture_output=True,text=True,timeout=5)
    assert json.loads(result.stdout)=={'value':29,'compilations':0}
    before=inventory(support)
    body=header(module)
    stale.write_bytes(body[:-1]+bytes([body[-1]^1]))
    assert inventory(support)!=before
    prepare_bytecode({'runtime':{'path':sys.executable},'support':str(support)},dependencies,tmp_path/'second.log')
    assert header(module)==body and inventory(support)==before
    stale.chmod(0o666)
    with pytest.raises(RuntimeError,match='mutable'):
        inventory(support)


def test_trusted_compile_failure_retains_log_and_refuses(tmp_path,monkeypatch):
    import source_host
    def failed(argv,**kwargs):
        assert argv[1:]==['-I','-S','-m','compileall','-q','-f','-j','1','--invalidation-mode','checked-hash',
            str(tmp_path/'dependencies'),str(tmp_path/'support')]
        assert kwargs=={'capture_output':True,'timeout':60,'check':False}
        return subprocess.CompletedProcess(argv,1,b'bounded preparation failure',b'')
    monkeypatch.setattr(source_host.subprocess,'run',failed)
    log=tmp_path/'failure.log'
    with pytest.raises(RuntimeError,match='bytecode preparation failed'):
        prepare_bytecode({'runtime':{'path':'/pinned/python'},'support':str(tmp_path/'support')},tmp_path/'dependencies',log)
    assert log.read_bytes()==b'bounded preparation failure'
