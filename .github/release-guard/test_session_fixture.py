"""Real pending group-TERM during fixture startup; no provider acceptance claim."""
import os
from pathlib import Path
import signal
import subprocess
import sys


def test_group_term_pending_before_handler_is_delivered_after_fixture_setup(tmp_path):
    root=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
    read,write=os.pipe()
    stopped=tmp_path/'stopped'
    body='''import os, runpy, signal, sys, time
assert signal.SIGTERM in signal.pthread_sigmask(signal.SIG_BLOCK, set())
os.write(int(sys.argv[1]), b'R')
os.close(int(sys.argv[1]))
time.sleep(0.1)
script=sys.argv[2]
sys.argv=[script, '--child', sys.argv[3]]
runpy.run_path(script, run_name='__main__')
'''
    old_mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM})
    try:
        child=subprocess.Popen([sys.executable,'-I','-c',body,str(write),
            str(root/'tests/mock_provider_session_acp.py'),str(stopped)],
            pass_fds=(write,),start_new_session=True)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)
        os.close(write)
    try:
        import select
        assert select.select([read],[],[],5)[0] and os.read(read,1)==b'R'
        assert signal.pthread_sigmask(signal.SIG_BLOCK,set())==old_mask
        os.killpg(child.pid,signal.SIGTERM)
        assert child.wait(timeout=5)==0
        assert stopped.read_text()=='stopped'
    finally:
        os.close(read)
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
