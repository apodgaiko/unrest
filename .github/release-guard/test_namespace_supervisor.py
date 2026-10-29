"""Actual PID1 adoption and numeric wait; no application or provider execution."""
import os
import json
from pathlib import Path
import sys

import pytest

from namespace_supervisor import run


def actual_namespace_control(failure_file=None):
    def init():
        assert os.getpid()==os.getpgrp()==os.getsid(0)==1
        read,write=os.pipe()
        parent=os.fork()
        if parent==0:
            os.close(read)
            child=os.fork()
            if child==0:
                # Parent death is observed through a real namespace-local PPid.
                import time
                deadline=time.monotonic()+3
                while os.getppid()!=1 and time.monotonic()<deadline:
                    time.sleep(.001)
                assert os.getppid()==1
                os.write(write,str(os.getpid()).encode())
                os.close(write)
                os._exit(23)
            os.close(write)
            os._exit(17)
        os.close(write)
        parent_wait=os.waitpid(parent,0)
        assert parent_wait==(parent,17<<8)
        child=int(os.read(read,64))
        os.close(read)
        stat=Path(f'/proc/{child}/stat').read_text().split(') ',1)[1].split()
        assert int(stat[1])==1
        adopted_wait=os.waitpid(child,0)
        assert adopted_wait==(child,23<<8)
        if failure_file is not None:
            Path(str(failure_file)+'.proof.json').write_text(json.dumps({
                'namespace':os.readlink('/proc/self/ns/pid'),'init_pid':os.getpid(),
                'init_pgid':os.getpgrp(),'init_sid':os.getsid(0),
                'adopted_ppid':int(stat[1]),'parent_wait':parent_wait,'adopted_wait':adopted_wait}))
    run(init,failure_file)


@pytest.mark.skipif(sys.platform!='linux' or os.getuid()!=0,reason='root Linux namespace control')
def test_actual_namespace_init_adopts_and_numerically_reaps():
    actual_namespace_control()


def test_namespace_supervisor_refuses_unprivileged_or_nonlinux_before_fork(monkeypatch):
    monkeypatch.setattr(os,'getuid',lambda:20000)
    monkeypatch.setattr(os,'fork',lambda:pytest.fail('must refuse before fork'))
    with pytest.raises(RuntimeError,match='trusted root'):
        run(lambda:None)
