"""Only the original simulated flow command may write its owned result."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from fixed_inline import SEQUENCES,translated
import measurement_launch as measurement

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def fixture(tmp_path,monkeypatch):
    monkeypatch.setattr(measurement,'OWNER',os.getuid())
    root=tmp_path/'pytest'/(measurement.CASE.split('::')[1][:30]+'0')
    root.mkdir(parents=True)
    host=SimpleNamespace(case=measurement.CASE,meta={'checkout':str(ROOT),'owned':str(tmp_path)},fixture_roots={})
    argv=['/native/python',str(ROOT/measurement.TOOL),'--case-manifest',str(ROOT/measurement.FIXTURE),
        '--mode','simulated','--output',str(root/'flow.json')]
    return host,argv


def test_original_mode_manifest_and_output_are_exact(tmp_path,monkeypatch):
    host,argv=fixture(tmp_path,monkeypatch)
    value=measurement.expected(host,argv,str(ROOT),{'PATH':'/bin'},argv[0],'a'*64)
    assert value.argv==tuple(argv)
    assert value.payload_sha256==measurement.PINS[measurement.TOOL]
    assert translated(value)==('/native/python','-I','-S',*argv[1:])
    assert SEQUENCES[measurement.CASE]==('simulate',)


@pytest.mark.parametrize('mutation',['cwd','outside','generation','case','count'])
def test_no_foreign_fixture_or_frontier_can_select_simulation(tmp_path,monkeypatch,mutation):
    host,argv=fixture(tmp_path,monkeypatch)
    cwd=str(ROOT)
    measurement.expected(host,argv,cwd,{},argv[0],'a'*64)
    if mutation=='cwd':
        cwd=str(tmp_path)
    elif mutation=='outside':
        argv[-1]=str(tmp_path/'foreign.json')
    elif mutation=='generation':
        host.fixture_roots[measurement.CASE]=('foreign',1,1)
    elif mutation=='case':
        host.case='foreign'
    else:
        argv.append('extra')
    with pytest.raises(Refused):
        measurement.expected(host,argv,cwd,{},argv[0],'a'*64)
