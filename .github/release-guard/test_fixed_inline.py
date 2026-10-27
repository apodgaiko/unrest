"""Fixed command contracts and unchanged original import-boundary assertions."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from content_manifest import Refused
from fixed_inline import ARGUMENTS, CASES, PINS, PRODUCT, SEQUENCES, TEST, FixedCalls, expected, run_options, script
from test_session_source import Probe

ROOT = Path(__file__).resolve().parents[2]


def test_literal_sources_and_exact_call_sites_are_pinned():
    for path,pin in PINS.items():
        assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest() == pin
    tree = ast.parse((ROOT/TEST).read_bytes())
    found = {}
    for function in tree.body:
        if isinstance(function,ast.FunctionDef) and function.name in ('_import_probe','test_mcp_help_does_not_import_repository_modules'):
            calls = [call for call in ast.walk(function) if isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute)
                     and isinstance(call.func.value,ast.Name) and call.func.value.id == 'subprocess' and call.func.attr == 'run']
            assert len(calls) == 1
            found[function.name] = calls[0].lineno
    assert found == {'_import_probe':540,'test_mcp_help_does_not_import_repository_modules':587}
    assert script(ROOT,'help') == script(ROOT,'check') and script(ROOT,'mcp') != script(ROOT,'help')
    assert PRODUCT.startswith('src/')


@pytest.mark.parametrize('case',CASES)
def test_each_fixed_declaration_is_limited_to_its_original_sequence(case):
    for operation in SEQUENCES[case]:
        result = expected(case,operation,'/native/python','a'*64,ROOT,{'PATH':'/usr/bin:/bin'})
        assert result.argv[:2] == ('/native/python','-c') and result.argv[2] == script(ROOT,operation)
        assert result.payload_sha256 == hashlib.sha256(result.argv[2].encode()).hexdigest()
        if operation != 'mcp':
            assert json.loads(result.argv[-1]) == list(ARGUMENTS[operation])
        if operation != 'check':
            with pytest.raises(Refused,match='query scope'):
                expected(case,operation,'/native/python','a'*64,ROOT,{},query=True)
    with pytest.raises(Refused,match='closed'):
        expected(case,'unregistered','/native/python','a'*64,ROOT,{})


def test_run_options_refuse_mixed_or_missing_parent_options():
    argv = ('/python','-c','pass')
    local = dict(popenargs=(list(argv),),kwargs=dict(cwd=ROOT,stdout=-1,stderr=-1,text=True),capture_output=True,check=True,timeout=20,input=None)
    run_options(local,argv,cwd=str(ROOT),check=True,timeout=20)
    for key,value in (('check',1),('timeout',20.0),('input','foreign'),('capture_output',False)):
        with pytest.raises(Refused):
            run_options({**local,key:value},argv,cwd=str(ROOT),check=True,timeout=20)


def test_original_import_boundary_callers_keep_their_real_assertions(tmp_path):
    environment = {'HOME':str(tmp_path),'TMPDIR':str(tmp_path),'PATH':'/usr/bin:/bin','PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1'}
    result = subprocess.run([sys.executable,'-B',str(Path(__file__).resolve()),str(tmp_path)],cwd=ROOT,env=environment,capture_output=True,text=True,timeout=30)
    assert result.returncode == 0,(result.stdout+result.stderr)[-10000:]
    report = json.loads((tmp_path/'fixed-probe.json').read_bytes())
    assert report['completed'] == list(CASES) and not report['poison']
    assert report['launches'] == [case for case in CASES for _ in SEQUENCES[case]]
    assert report['source_admission_certified'] is False


def main():
    directory = Path(sys.argv[1]).resolve()
    sys.path[:0] = [str(ROOT/'src'),str(ROOT)]
    probe = Probe(directory,ROOT,pins=PINS,cases=CASES,factory=FixedCalls,limits={case:len(SEQUENCES[case]) for case in CASES})
    probe.install()
    code = pytest.main(['-q','-s','-p','pytest_asyncio.plugin','-p','pytest_mock','-o','addopts=',
                       '-o','cache_dir='+str(directory/'cache'),'--basetemp',str(directory/'pytest'),*CASES],plugins=[probe])
    (directory/'fixed-probe.json').write_text(json.dumps(dict(completed=probe.completed,launches=probe.launches,poison=probe.poison,source_admission_certified=False)))
    return int(code != 0 or probe.poison or probe.completed != list(CASES))


if __name__ == '__main__':
    raise SystemExit(main())
