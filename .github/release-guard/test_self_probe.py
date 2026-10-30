"""Read-only own-PID probing never grants another signal or process target."""
import os
import subprocess
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from source_entry import Policy


@pytest.mark.parametrize('change',[None,'pid','signal','group','case'])
def test_approval_self_probe_has_no_general_signal_authority(tmp_path,monkeypatch,change):
    calls=[]
    def request(kind,payload):
        calls.append((kind,payload))
        return {'ok':True}
    for obj,name in ((subprocess.Popen,'__init__'),(subprocess,'run'),(os,'kill'),(os,'killpg')):
        monkeypatch.setattr(obj,name,getattr(obj,name))
    actual=[]
    monkeypatch.setattr(os,'kill',lambda pid,sig:actual.append((pid,sig)))
    monkeypatch.setattr(os,'killpg',lambda pid,sig:actual.append((pid,sig)))
    policy=Policy(tmp_path,{'role':'root'},{},SimpleNamespace(request=request))
    policy.case='tests/test_approval_recovery.py::original'
    policy.install_process_hooks()
    pid,sig,group=os.getpid(),0,False
    if change=='pid':
        pid+=1
    elif change=='signal':
        sig=15
    elif change=='group':
        group=True
    elif change=='case':
        policy.case='tests/other.py::original'
    if change:
        with pytest.raises(Refused):
            (os.killpg if group else os.kill)(pid,sig)
        assert not actual and policy.poison
    else:
        os.kill(pid,sig)
        assert actual==[(pid,0)] and calls==[('self-probe',{'pid':pid})]
        assert policy.local.signal is None
