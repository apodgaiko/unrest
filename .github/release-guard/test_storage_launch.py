"""Exact storage-reader commands, lexical paths and real owned input generations."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
import storage_launch as storage
from fixed_inline import SEQUENCES, GROUPS

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
BODY='import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())'


def fixture(tmp_path,monkeypatch,case):
    monkeypatch.setattr(storage,'OWNER',os.getuid())
    owned=tmp_path/'owned'
    directory=owned/'pytest'/(case.split('::')[-1].split('[')[0][:30]+'0')
    directory.mkdir(parents=True)
    relative,depth,contents=storage.CASES[case]
    target=directory/'state.json'
    if case.startswith(storage.NESTED+'['):
        target=directory/'trusted'/Path(*(f'level-{i}' for i in range(depth)))/'state.json'
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(contents)
    host=SimpleNamespace(case=case,meta={'checkout':str(ROOT),'owned':str(owned)},fixture_roots={})
    argv=['/native/python','-c',BODY,str(target.relative_to(directory) if relative else target)]
    return host,argv,str(directory if relative else ROOT),target


@pytest.mark.parametrize('case',storage.CASES)
def test_every_original_parameter_keeps_lexical_operand_and_input_bytes(tmp_path,monkeypatch,case):
    host,argv,cwd,target=fixture(tmp_path,monkeypatch,case)
    value=storage.expected(host,argv,cwd,{'PATH':'/bin:/usr/bin'},argv[0],'a'*64)
    assert value.argv==tuple(argv) and value.cwd==cwd
    assert target.read_bytes()==storage.CASES[case][2].encode()
    assert len(SEQUENCES[case])==(2 if case==storage.DIRECTORY else 1)
    assert tuple(storage.CASES) in GROUPS


@pytest.mark.parametrize('mutation',['outside','alias','hardlink','contents','cwd','path','generation','owner'])
def test_read_declaration_never_borrows_other_file_or_fixture_generation(tmp_path,monkeypatch,mutation):
    case=next(iter(storage.CASES))
    host,argv,cwd,target=fixture(tmp_path,monkeypatch,case)
    storage.expected(host,argv,cwd,{},argv[0],'a'*64)
    if mutation=='outside':
        argv[3]=str(tmp_path/'other')
    elif mutation=='alias':
        target.rename(target.with_suffix('.original'))
        target.symlink_to(target.with_suffix('.original'))
    elif mutation=='hardlink':
        os.link(target,target.with_suffix('.link'))
    elif mutation=='contents':
        target.write_text('wrong generation')
    elif mutation=='cwd':
        cwd=str(tmp_path)
    elif mutation=='path':
        argv[3]=str(target.parent/'foreign.json')
    elif mutation=='owner':
        monkeypatch.setattr(storage,'OWNER',os.getuid()+1)
    else:
        host.fixture_roots[case]=('foreign',1,1)
    with pytest.raises((Refused,FileNotFoundError)):
        storage.expected(host,argv,cwd,{},argv[0],'a'*64)
