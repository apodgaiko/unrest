"""The supported CPython kernel wrapper retains exact operands and errors."""

import errno
import os
from types import SimpleNamespace

import pytest

import linux_observation as observation


@pytest.mark.parametrize('failure',[False,True])
def test_supported_cpython_pidfd_wrapper_preserves_actual_kernel_result(monkeypatch,failure):
    calls=[]
    def acquire(pid,flags):
        calls.append((pid,flags))
        if failure:
            raise OSError(errno.EPERM,'refused')
        return 29
    monkeypatch.setattr(os,'pidfd_open',acquire,raising=False)
    if failure:
        with pytest.raises(OSError) as error:
            observation.pidfd_open(1234)
        assert error.value.errno==errno.EPERM
    else:
        assert observation.pidfd_open(1234)==29
    assert calls==[(1234,0)]


@pytest.mark.parametrize("pid,flags", [(True, 0), (0, 0), ((1 << 32) + 1, 0), (1, True), (1, 1)])
def test_pidfd_wrapper_does_not_accept_flags_or_non_numeric_identity(pid, flags):
    with pytest.raises(ValueError):
        observation.pidfd_open(pid, flags)


@pytest.mark.parametrize(
    "full,seconds,valid",
    [
        (False, 180, True),
        (False, 181, False),
        (True, 1200, True),
        (True, 1201, False),
        (True, float("nan"), False),
    ],
)
def test_only_explicit_full_source_scope_gets_the_finite_suite_deadline(
    monkeypatch, full, seconds, valid
):
    import linux_trace as trace

    monkeypatch.setattr(trace.sys, "platform", "linux")
    monkeypatch.setattr(trace.os, "uname", lambda: SimpleNamespace(machine="x86_64"))
    monkeypatch.setattr(trace._observation, "process_identity", lambda pid: {"ppid": os.getpid()})
    read, write = os.pipe()
    try:
        if valid:
            proof = trace.OwnedTrace(1234, [], seconds, start_write=write, full_source=full)
            assert proof.timeout == seconds
        else:
            with pytest.raises(ValueError, match="bounded"):
                trace.OwnedTrace(1234, [], seconds, start_write=write, full_source=full)
    finally:
        os.close(read)
        os.close(write)
