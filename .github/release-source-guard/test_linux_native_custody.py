"""Real retained/zombie birth identity for the Linux native-leaf adapter."""
import importlib.util
import os
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "native_custody", Path(__file__).with_name("finite") / "native_custody.py"
)
assert spec is not None and spec.loader is not None
custody = importlib.util.module_from_spec(spec)
spec.loader.exec_module(custody)


def test_linux_native_custody_before_and_after_exit():
    assert os.uname().sysname == "Linux"
    query = custody.prepare({"system": "Linux", "abi": "proc-stat-start-ticks"})
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(write)
        os.read(read, 1)
        os._exit(17)
    os.close(read)
    try:
        before = custody.observe(child, query)
        assert before["native_pid"] == child and before["native_ppid"] == os.getpid()
        assert before["native_start_ticks"] > 0 and before["native_uid"] == os.getuid()
        os.write(write, b"1")
        retained = os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT)
        assert retained is not None and retained.si_pid == child and retained.si_status == 17
        assert custody.observe(child, query) == before
    finally:
        os.close(write)
        actual, raw = os.waitpid(child, 0)
    assert actual == child and raw == 17 << 8
    with pytest.raises(FileNotFoundError):
        custody.observe(child, query)


def test_unknown_native_abi_refuses():
    with pytest.raises(RuntimeError, match="ABI drift"):
        custody.prepare({"system": "Darwin", "abi": "proc-stat-start-ticks"})


def test_native_inherited_environment_binds_libc_bytes_without_mutation():
    runtime_spec = importlib.util.spec_from_file_location(
        "runtime_environment_probe", Path(__file__).with_name("finite") / "runtime_guard.py"
    )
    assert runtime_spec is not None and runtime_spec.loader is not None
    runtime = importlib.util.module_from_spec(runtime_spec)
    runtime_spec.loader.exec_module(runtime)
    key = "FINITE_LIBC_ENVIRONMENT_CONTROL"
    assert key not in os.environ
    before = dict(os.environ)
    os.putenv(key, "actual-native-value")
    try:
        observed = runtime.inherited_environment()
        assert observed[key] == "actual-native-value"
        assert dict(os.environ) == before
    finally:
        os.unsetenv(key)
    assert key not in runtime.inherited_environment()
