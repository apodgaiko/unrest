"""Exact bounded memory reads; these controls launch no source/provider process."""
import importlib.util
import os
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('memory_trace', Path(__file__).with_name('linux_trace.py'))
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


@pytest.mark.parametrize('length', (0, 1, 7, 8, 4094, 4095, 4096, 4097, 65536, 131071))
@pytest.mark.parametrize('offset', (0, 1, 4095))
def test_string_reads_only_bounded_pages_and_retains_exact_bytes(monkeypatch, length, offset):
    start = 4096 + offset
    body = b'x' * length + b'\0'
    calls = []

    def read(pid, address, count):
        calls.append((address, count))
        assert pid == 123 and address // 4096 == (address + count - 1) // 4096
        assert 0 < count <= 4096 and address + count <= start + trace.MAX_EXEC_STRING + 1
        position = address - start
        return (body[position:position + count] + b'z' * count)[:count]

    monkeypatch.setattr(trace, 'read_bytes', read)
    assert trace.read_string(123, start) == b'x' * length
    assert len(calls) <= (offset + length) // 4096 + 1
    if length == 65536:
        assert len(calls) == 17  # Old eight-byte PEEK loop required 8,193.


def test_overflow_refuses_without_reading_beyond_the_original_limit(monkeypatch):
    calls = []

    def read(pid, address, count):
        calls.append((address, count))
        return b'x' * count

    monkeypatch.setattr(trace, 'read_bytes', read)
    with pytest.raises(RuntimeError, match='unbounded exec string'):
        trace.read_string(123, 4097)
    assert sum(count for _, count in calls) == trace.MAX_EXEC_STRING + 1


@pytest.mark.parametrize('length', (0, 3, 4))
def test_fixed_read_requires_kernel_stop_readonly_cloexec_and_exact_size(monkeypatch, length):
    calls = []
    monkeypatch.setattr(trace, 'ptrace', lambda *args: calls.append(('ptrace', args)))
    def opened(path, flags):
        assert calls == [('ptrace', (2, 123, 4096))]
        assert path == '/proc/123/mem' and flags == os.O_RDONLY | os.O_CLOEXEC
        return 19
    monkeypatch.setattr(trace.os, 'open', opened)
    monkeypatch.setattr(trace.os, 'pread', lambda fd, count, address: b'x' * length)
    monkeypatch.setattr(trace.os, 'close', lambda fd: calls.append(('close', fd)))
    if length == 4:
        assert trace.read_bytes(123, 4099, 4) == b'xxxx'
    else:
        with pytest.raises(RuntimeError, match='incomplete bounded'):
            trace.read_bytes(123, 4099, 4)
    assert calls[-1] == ('close', 19)


def test_unattached_process_never_reaches_privileged_memory_open(monkeypatch):
    def unattached(*args):
        raise OSError('not a stopped tracee')
    monkeypatch.setattr(trace, 'ptrace', unattached)
    monkeypatch.setattr(trace.os, 'open', lambda *args: pytest.fail('foreign memory open'))
    with pytest.raises(OSError, match='not a stopped tracee'):
        trace.read_bytes(123, 4096, 4)


def test_read_error_closes_the_address_space_handle(monkeypatch):
    closed = []
    monkeypatch.setattr(trace, 'ptrace', lambda *args: 0)
    monkeypatch.setattr(trace.os, 'open', lambda *args: 19)
    def error(*args):
        raise OSError('unmapped memory')
    monkeypatch.setattr(trace.os, 'pread', error)
    monkeypatch.setattr(trace.os, 'close', closed.append)
    with pytest.raises(OSError, match='unmapped memory'):
        trace.read_bytes(123, 4096, 4)
    assert closed == [19]
