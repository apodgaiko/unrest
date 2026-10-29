"""Syscall entry decoding precedes every possible wait4 return."""
from types import SimpleNamespace

import pytest

from content_manifest import Refused
import linux_trace
from process_ledger import Birth
from source_observer import Observer
from test_process_ledger import setup, identity


@pytest.mark.parametrize('register,expected', [(0xffffffffffffffff, -1), (0xffffffff, -1), (0x1234567800000065, 101), (0, 0)])
def test_wait_pid_is_signed_kernel_pid_t_before_return(monkeypatch, register, expected):
    trace = object.__new__(linux_trace.OwnedTrace)
    trace.pending, trace.records = {}, []
    trace.identities = {100: identity(100, 99)}
    seen = []
    def refuse(pid, requested):
        seen.append((pid, requested))
        raise Refused('entry refused before return')
    trace.validate_wait = refuse
    def syscall_info(request, pid, size, data):
        assert request == 0x420E and pid == 100
        data._obj[0] = b'\x01'
        for index, value in enumerate((0xC000003E).to_bytes(4, 'little'), 4):
            data._obj[index] = bytes([value])
        return 80
    monkeypatch.setattr(linux_trace, 'ptrace', syscall_info)
    monkeypatch.setattr(linux_trace, 'registers', lambda pid: SimpleNamespace(
        orig_rax=61, rdi=register, rsi=123, rdx=1, r10=0))
    with pytest.raises(Refused, match='entry refused'):
        trace.syscall(100)
    assert seen == [(100, expected)] and not trace.records
    assert trace.pending[100]['requested_pid'] == expected


def test_production_callback_consumes_birth_records_before_entry_authority():
    ledger, root, child = setup()
    observer = object.__new__(Observer)
    observer.ledger = ledger
    called = []
    trace = SimpleNamespace(identities={root.pid: identity(root.pid, 99)})
    observer.consume = lambda value: called.append(value)
    observer.validate_wait(trace, root.pid, child.pid)
    assert called == [trace]
    assert Birth.read(trace.identities[root.pid]) == root
    with pytest.raises(Refused):
        observer.validate_wait(trace, root.pid, -1)
