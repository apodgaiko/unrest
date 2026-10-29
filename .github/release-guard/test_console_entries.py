"""Console image selection and current installed script bytes remain distinct."""
from pathlib import Path
from types import SimpleNamespace
import hashlib
import os

import pytest

from content_manifest import Refused
import console_entries as console


def test_three_closed_normalized_entries_keep_real_console_files():
    runtime,dependencies=Path('/runtime'),Path('/dependencies')
    assert console.normalized(runtime,dependencies,'pytest',['-q'])==['/runtime/bin/pytest','-I','-S','-m','pytest','-q']
    for name in console.REGISTRATIONS:
        vector=console.normalized(runtime,dependencies,name,['--help'])
        assert vector==['/runtime/bin/python-unrest-guard-control','-I','-S',
            '/dependencies/.release-distribution/installed/bin/'+name,'--help']
    with pytest.raises(Refused):
        console.normalized(runtime,dependencies,'python',['-c','foreign'])


@pytest.fixture
def retained(tmp_path,monkeypatch):
    checkout=tmp_path/'source'
    checkout.mkdir()
    (checkout/'pyproject.toml').write_text('[project.scripts]\nunrest="unrest_harness.cli:cli"\nunrest-server="unrest_harness.server:main"\n')
    installed=tmp_path/'installed'
    (installed/'bin').mkdir(parents=True)
    (installed/'package.dist-info').mkdir()
    (installed/'package.dist-info/entry_points.txt').write_text('[console_scripts]\nunrest = unrest_harness.cli:cli\nunrest-server = unrest_harness.server:main\n')
    file=installed/'bin/unrest-server'
    file.write_bytes(b'#!/pinned/interpreter\nfrom unrest_harness.server import main\nmain()\n')
    value={'installed_site':installed,'installed_members':{'bin/unrest-server':hashlib.sha256(file.read_bytes()).hexdigest()}}
    host=SimpleNamespace(meta={'checkout':str(checkout),'source_sha256':'a'*64},
        fixture_roots={'<prepared-distribution>':value})
    original=console.read_regular
    monkeypatch.setattr(console,'read_regular',lambda path,*args,**kwargs:original(path,*args,**{**kwargs,'uid':os.getuid()}))
    return host,file


def test_retained_script_is_executed_as_a_file_not_synthesized_import(retained):
    host,file=retained
    path,pin=console.script(host,'unrest-server')
    assert path==file and pin==hashlib.sha256(file.read_bytes()).hexdigest()


@pytest.mark.parametrize('mutation',['script','project-registration','installed-registration','alias','extra-registration'])
def test_retained_console_cannot_borrow_changed_script_or_registration(retained,mutation):
    host,file=retained
    if mutation=='script':
        file.write_bytes(b'print("changed")\n')
    elif mutation=='project-registration':
        (Path(host.meta['checkout'])/'pyproject.toml').write_text('[project.scripts]\nunrest="other:call"\n')
    elif mutation=='installed-registration':
        (file.parents[1]/'package.dist-info/entry_points.txt').write_text('[console_scripts]\nunrest-server = other:call\n')
    elif mutation=='alias':
        file.rename(file.with_suffix('.old'))
        file.symlink_to(file.with_suffix('.old'))
    else:
        (file.parents[1]/'other.dist-info').mkdir()
        (file.parents[1]/'other.dist-info/entry_points.txt').write_text('[console_scripts]\nunrest-server = other:call\n')
    with pytest.raises(Refused):
        console.script(host,'unrest-server')
