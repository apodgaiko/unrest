"""Trusted PID1 supervision; no candidate-derived process admission."""
import ctypes
import os
from pathlib import Path
import signal
import sys
import traceback


def children():
    return Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()


def run(callback,failure_file=None):
    if (sys.platform!='linux' or os.getuid()!=0 or not callable(callback) or children()
            or signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL):
        raise RuntimeError('namespace supervisor requires a childless trusted root')
    def interrupted(signum,frame):
        raise InterruptedError('namespace supervision interrupted')
    previous=signal.signal(signal.SIGTERM,interrupted)
    def wait(pid):
        try:
            actual,raw=os.waitpid(pid,0)
        except BaseException:
            try:
                if os.waitpid(pid,os.WNOHANG)[0]==0:
                    os.kill(pid,signal.SIGKILL)
                    os.waitpid(pid,0)
            except (ChildProcessError,ProcessLookupError):
                pass
            raise
        if actual!=pid or raw!=0:
            raise RuntimeError('namespace child failed')
    try:
        holder=os.fork()
    except BaseException:
        signal.signal(signal.SIGTERM,previous)
        raise
    if holder:
        try:
            wait(holder)
        finally:
            signal.signal(signal.SIGTERM,previous)
        return
    code=125
    try:
        libc=ctypes.CDLL(None,use_errno=True)
        before=os.readlink('/proc/self/ns/pid')
        if libc.unshare(0x20000000):
            raise OSError(ctypes.get_errno(),'private PID namespace refused')
        init=os.fork()
        if init:
            wait(init)
        else:
            if (libc.unshare(0x20000) or libc.mount(None,b'/',None,0x44000,None)
                    or libc.mount(b'proc',b'/proc',b'proc',14,None)):
                raise OSError(ctypes.get_errno(),'private procfs refused')
            if os.getpid()!=1 or os.readlink('/proc/self/ns/pid')==before:
                raise RuntimeError('namespace init identity refused')
            callback()
            if children():
                raise RuntimeError('namespace init has unretired children')
        code=0
    except BaseException:
        if failure_file is not None and not Path(failure_file).exists():
            Path(failure_file).write_text(traceback.format_exc())
    os._exit(code)
