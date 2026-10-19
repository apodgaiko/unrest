"""Explicit new methods requiring the real inherited Linux certification guard."""

from __future__ import annotations

import multiprocessing
from multiprocessing import util, popen_spawn_posix
import os
import sys
import types

import pytest

from tests.multiprocess_lifetime import SpawnResources
from tests.test_multiprocess_resource_ownership import _exit_with_status, _publish


def test_owned_exit17_keeps_raw_status():
    guard = sys.modules["runtime_guard"]
    with SpawnResources() as owner:
        context = owner.context(multiprocessing.get_context("spawn"))
        process = context.Process(target=_exit_with_status, args=(17,))
        process.start()
        child = process.pid
        process.join(10)
        assert process.exitcode == 17
    assert owner.closed and owner.tracker._pid is None and owner.tracker._exitcode == 0
    rows = guard.summarize(guard._STATE["manifest_path"])["events"]
    assert any(
        row["kind"] == "raw_actual_parent_waitpid"
        and row["pid"] == child
        and row["raw_status"] == 17 << 8
        for row in rows
    )

    _acquisition_faults()
    _binding_inventory()
    _lease_factories()
    _refused_acquisition()


@pytest.mark.parametrize("kind", ["globals", "arguments", "case", "descriptor", "caller"])
def test_refusal_is_sticky(kind):
    guard = sys.modules["runtime_guard"]
    original_case = guard._STATE["case"]
    with SpawnResources() as owner:
        context = owner.context(multiprocessing.get_context("spawn"))
        queue = context.Queue()
        gate = context.Event()
        value = context.Value("i", 0)
        process = context.Process(target=_publish, args=(queue, gate, value))
        extra = []
        original_launch = None
        try:
            if kind == "globals":
                original_launch = popen_spawn_posix.Popen._launch
                popen_spawn_posix.Popen._launch = types.FunctionType(
                    original_launch.__code__,
                    dict(original_launch.__globals__),
                    original_launch.__name__,
                    original_launch.__defaults__,
                    original_launch.__closure__,
                )

            elif kind == "arguments":
                process._args = tuple(list(process._args))
            elif kind == "case":
                guard._STATE["case"] = "outside-current-finite-case"
            elif kind == "descriptor":
                other = os.open(os.devnull, os.O_WRONLY)
                try:
                    os.dup2(other, owner.fd, inheritable=False)
                finally:
                    os.close(other)
            with pytest.raises(guard.GuardRefusal):
                if kind == "caller":
                    read, write = os.pipe()
                    extra.extend((read, write))
                    util.spawnv_passfds(
                        sys.executable,
                        [
                            sys.executable,
                            "-B",
                            "-c",
                            "from multiprocessing.resource_tracker import main;main("
                            + str(read)
                            + ")",
                        ],
                        [sys.stderr.fileno(), read],
                    )
                else:
                    process.start()
            assert process.pid is None
        finally:
            if original_launch is not None:
                popen_spawn_posix.Popen._launch = original_launch
            guard._STATE["case"] = original_case
            if kind == "descriptor":
                os.dup2(owner.custody, owner.fd, inheritable=False)
            for descriptor in extra:
                os.close(descriptor)
    summary = guard.summarize(guard._STATE["manifest_path"])
    assert not summary["ready"]
    assert any(
        row["kind"] == "forbidden" and "multiprocess_binding:" in row["reason"]
        for row in summary["failures"]
    )
    assert not any(row["kind"] == "missing_wait" for row in summary["failures"])


def _acquisition_faults():
    """Real tracker launches; fail only this owner's post-launch acquisition."""
    from unittest.mock import patch
    import errno
    import inspect

    guard = sys.modules['runtime_guard']
    for operation in ('dup', 'fstat', 'get_inheritable', 'set_inheritable'):
        census = len(os.listdir('/proc/self/fd'))
        owner = SpawnResources()
        original = getattr(os, operation)
        error = OSError(errno.EMFILE, 'injected owned acquisition failure')
        injected = False

        def fail_once(*args, **kwargs):
            nonlocal injected
            frame = inspect.currentframe().f_back
            wanted = (owner.custody if operation == 'set_inheritable' else owner.tracker._fd)
            if (not injected and wanted is not None and args[0] == wanted
                    and frame.f_code.co_filename == SpawnResources.context.__code__.co_filename
                    and frame.f_code.co_name in {'context', '_acquired_pipe'}):
                injected = True
                raise error
            return original(*args, **kwargs)

        with patch.object(os, operation, fail_once):
            with pytest.raises(OSError) as caught:
                with owner:
                    owner.context(multiprocessing.get_context('spawn'))
        assert injected and caught.value is error
        assert owner.closed and owner.tracker._pid is None and owner.tracker._fd is None
        assert owner.tracker._exitcode == 0
        with pytest.raises(ChildProcessError):
            os.waitpid(owner.pid, os.WNOHANG)
        assert len(os.listdir('/proc/self/fd')) == census
        guard.append({'kind': 'owned_acquisition_fault', 'operation': operation,
                      'tracker_pid': owner.pid, 'parent': owner.parent,
                      'pipe_identity': list(owner.identity), 'errno': error.errno,
                      'before_fds': census, 'after_fds': len(os.listdir('/proc/self/fd')),
                      'original_exception_preserved': True})


def _lease_launch(owner, mode, directory):
    # These are the two immutable original source literals. This helper has its
    # own guard-method identity and never impersonates an original test owner.
    if mode == 'ignore':
        return owner.launch_local([sys.executable, '-c',
            'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);time.sleep(30)'],
            cwd=directory, env={})
    if mode == 'cleanup':
        return owner.launch_local([sys.executable, '-c', 'import time;time.sleep(30)'],
                                  cwd=directory, env={})
    return owner.launch_local([sys.executable, '-c',
                               'import time;print("ready",flush=True);time.sleep(30)'],
                              cwd=directory, env={})


def _lease_factories():
    from pathlib import Path
    from concurrent.futures import ThreadPoolExecutor
    from unittest.mock import patch
    import threading
    import subprocess
    from unrest_harness.experimental_confinement import OwnedProcesses
    from unrest_harness.experimental_lease import TurnBroker

    guard = sys.modules['runtime_guard']
    base = Path(guard._STATE['owned_root']) / 'guard-lease-factories'
    base.mkdir()
    for mode in ('ignore', 'cleanup', 'spawn', 'registration'):
        census = len(os.listdir('/proc/self/fd'))
        directory = base / mode
        directory.mkdir()
        candidate = directory / 'candidate'
        candidate.mkdir()
        broker = TurnBroker(candidate, directory / 'records')
        owner = OwnedProcesses(broker)
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        original = subprocess.Popen
        children = []
        def paused_spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            # Core READY precedes endpoint setup. This supplementary probe
            # observes both before deliberately terminating its cleanup child.
            import json
            import time
            ready_path = Path(guard._STATE['guard']).with_name('multiprocess_routes.py')
            ready = guard.checked_source(ready_path, guard._STATE['direct_support']['files'][str(ready_path)])['endpoint_ready']
            journal = Path(guard._STATE['events']) / (str(child.pid) + '.jsonl')
            token = next(row['token'] for row in guard.summarize(guard._STATE['manifest_path'])['events']
                         if row['kind'] == 'registered' and row.get('pid') == child.pid)
            deadline = time.monotonic() + 5
            while not ready([json.loads(line) for line in journal.read_text().splitlines()],
                            guard._STATE, token, child.pid):
                assert child.poll() is None and time.monotonic() < deadline
                time.sleep(.001)
            if mode != 'cleanup':
                assert child.stdout.readline() == b'ready\n'
            if mode == 'spawn':
                entered.set()
                assert release.wait(5)
            return child
        class RegistrationBarrier(list):
            def append(self, child):
                entered.set()
                assert release.wait(5)
                super().append(child)
        if mode == 'registration':
            owner._processes = RegistrationBarrier()
        try:
            with patch.object(subprocess, 'Popen', paused_spawn):
                if mode == 'ignore':
                    child = _lease_launch(owner, mode, directory)
                    assert owner.close(.05) and child.returncode == -9
                elif mode == 'cleanup':
                    child = _lease_launch(owner, mode, directory)
                    terminate = child.terminate
                    with patch.object(child, 'terminate', side_effect=OSError('controlled cleanup failure')):
                        assert not owner.close(.05) and owner.quarantined and broker.quarantined
                    terminate()
                    child.wait(timeout=3)
                    for stream in (child.stdin, child.stdout, child.stderr):
                        stream.close()
                else:
                    def close():
                        result = owner.close(.1)
                        closed.set()
                        return result
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        launch = pool.submit(_lease_launch, owner, mode, directory)
                        assert entered.wait(5)
                        cleanup = pool.submit(close)
                        try:
                            assert not closed.wait(.1)
                        finally:
                            release.set()
                        assert launch.result(timeout=5) is children[0]
                        assert cleanup.result(timeout=5)
        finally:
            release.set()
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close()
            broker.close()
        assert len(os.listdir('/proc/self/fd')) == census
        guard.append({'kind': 'guard_lease_factory_proof', 'mode': mode,
                      'child_pid': children[0].pid, 'child_returncode': children[0].returncode,
                      'before_fds': census, 'after_fds': len(os.listdir('/proc/self/fd')),
                      'quarantine': owner.quarantined, 'closed': owner.closed})


def _refused_acquisition():
    from unittest.mock import patch
    guard = sys.modules['runtime_guard']
    hook = guard._STATE['_owned_multiprocess_hook']
    namespace = hook.__globals__
    original = namespace['endpoint_ready']
    cause = RuntimeError('controlled post-READY acquisition failure')
    injected = False
    def fail(rows, state, token, pid):
        nonlocal injected
        answer = original(rows, state, token, pid)
        if answer and not injected:
            injected = True
            raise cause
        return answer
    census = len(os.listdir('/proc/self/fd'))
    owner = SpawnResources()
    with patch.dict(namespace, endpoint_ready=fail):
        with pytest.raises(RuntimeError) as caught:
            with owner:
                owner.context(multiprocessing.get_context('spawn'))
    assert injected and caught.value is cause and owner.closed
    assert owner.tracker._fd is None and owner.tracker._pid is None
    assert len(os.listdir('/proc/self/fd')) == census
    rows = guard.summarize(guard._STATE['manifest_path'])['events']
    proof = [row for row in rows if row['kind'] == 'multiprocess_refused_acquisition_wait']
    assert len(proof) == 1
    child = proof[0]['pid']
    assert any(row['kind'] == 'raw_actual_parent_waitpid' and row['pid'] == child for row in rows)
    with pytest.raises(ChildProcessError):
        os.waitpid(child, os.WNOHANG)
    guard.append({'kind': 'guard_refused_acquisition_proof', 'child_pid': child,
                  'before_fds': census, 'after_fds': len(os.listdir('/proc/self/fd')),
                  'original_exception_preserved': True})


def _binding_inventory():
    """Own supplementary identity for the original shared inventory helpers."""
    import importlib.util
    from pathlib import Path
    guard = sys.modules['runtime_guard']
    root = Path(guard._STATE['checkout'])
    path = root / 'tools/release_binding.py'
    spec = importlib.util.spec_from_file_location('_guard_binding_inventory', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    paths = module.candidate_regular_paths(root)
    assert paths == sorted(set(paths), key=lambda name: name.encode('utf-8'))
    assert 'pyproject.toml' in paths and 'uv.lock' in paths
    guard.append({'kind': 'guard_shared_binding_probe', 'path_count': len(paths),
                  'original_source_sha256': guard.digest(path)})
