"""Resolve the native Git image before CPython captures Popen.executable."""
import subprocess

import pytest

from test_git_catalogue import SITE_CASES as CASES
from source_entry import direct_native


@pytest.mark.parametrize('positional',[False,True])
def test_original_git_vector_avoids_path_probe_before_audit(tmp_path,positional):
    decoy=tmp_path/'git'
    decoy.write_text('#!/bin/sh\nexit 73\n')
    decoy.chmod(0o700)
    vector=['git','--version']
    args=(vector,-1,None) if positional else (vector,)
    kwargs={'env':{'PATH':str(tmp_path)},'capture_output':True}
    args,kwargs=direct_native(args,kwargs,CASES[0],'root')
    # Popen has no capture_output keyword; run forwards its explicit executable.
    process=subprocess.run(*args,**kwargs,check=True)
    assert process.stdout.startswith(b'git version ') and vector==['git','--version']


@pytest.mark.parametrize('role', ['session-child','acp','backend'])
def test_roles_without_subprocess_ownership_receive_no_substitution(role):
    args,kwargs=(['git','--version'],),{}
    assert direct_native(args,kwargs,'foreign',role)==(args,kwargs)


def test_canonical_resolution_grants_no_undeclared_case_permission():
    from types import SimpleNamespace
    from content_manifest import Refused
    from effect_proposals import proposal
    args,kwargs=direct_native((['git','--version'],),{},'foreign','root')
    host=SimpleNamespace(case='foreign',launch_owner=lambda actor:None)
    with pytest.raises(Refused,match='no declaration'):
        proposal(host,{'role':'root'},{'case':'foreign','argv':args[0],
            'executable':kwargs['executable'],'cwd':'/owned','environment':{},'stdin':None})


@pytest.mark.parametrize('name',('git','ps','sleep'))
def test_only_fixed_native_images_bypass_path_probes_without_granting_launch(name):
    from effect_proposals import proposal
    from types import SimpleNamespace
    from content_manifest import Refused
    args,kwargs=direct_native(([name,'foreign'],),{},'foreign','root')
    assert args==([name,'foreign'],) and kwargs=={'executable':'/usr/bin/'+name}
    host=SimpleNamespace(case='foreign',launch_owner=lambda actor:None)
    with pytest.raises(Refused,match='no declaration'):
        proposal(host,{'role':'root'},{'case':'foreign','argv':args[0],
            'executable':kwargs['executable'],'cwd':'/owned','environment':{},'stdin':None})


@pytest.mark.parametrize('name',('python','uv','bash','unknown','/bin/sleep'))
def test_other_executables_keep_original_resolution(name):
    args=([name],)
    assert direct_native(args,{},'foreign','root')==(args,{})
