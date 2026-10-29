"""Resolve the native Git image before CPython captures Popen.executable."""
import subprocess

import pytest

from git_sites import CASES
from source_entry import direct_git


@pytest.mark.parametrize('positional',[False,True])
def test_original_git_vector_avoids_path_probe_before_audit(tmp_path,positional):
    decoy=tmp_path/'git'
    decoy.write_text('#!/bin/sh\nexit 73\n')
    decoy.chmod(0o700)
    vector=['git','--version']
    args=(vector,-1,None) if positional else (vector,)
    kwargs={'env':{'PATH':str(tmp_path)},'capture_output':True}
    args,kwargs=direct_git(args,kwargs,CASES[0],'root')
    # Popen has no capture_output keyword; run forwards its explicit executable.
    process=subprocess.run(*args,**kwargs,check=True)
    assert process.stdout.startswith(b'git version ') and vector==['git','--version']


@pytest.mark.parametrize('case,role', [('foreign','root'),(CASES[0],'fixed-inline')])
def test_unrelated_cases_receive_no_executable_substitution(case,role):
    args,kwargs=(['git','--version'],),{}
    assert direct_git(args,kwargs,case,role)==(args,kwargs)
