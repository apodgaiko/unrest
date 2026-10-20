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
    _source_environment_probe()
    _binding_inventory()
    _nested_owner_probe()
    from child_relative_methods import probe
    probe()
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


def _nested_owner_probe():
    import subprocess
    from pathlib import Path
    guard = sys.modules['runtime_guard']
    directory = Path(guard._STATE['owned_root']) / 'execution-owner-probe'
    directory.mkdir()
    before = len(os.listdir('/proc/self/fd'))
    completed = subprocess.run(
        [sys.executable, '-m', 'pytest', '-q', '-ra', '-p', 'no:cacheprovider',
         '--junitxml=' + str(directory / 'pytest.xml'),
         '.github/release-source-guard/nested_owner_methods.py::test_nested_owner'],
        cwd=Path(guard._STATE['checkout']), check=True)
    assert completed.returncode == 0
    assert before == len(os.listdir('/proc/self/fd'))
    guard.append({'kind': 'guard_nested_execution_owner_proof', 'returncode': completed.returncode,
                  'before_fds': before, 'after_fds': len(os.listdir('/proc/self/fd')),
                  'custody_case': guard._STATE['case']})


def _lease_popen(popen, mode, *args, **kwargs):
    """Own-identity counterpart of the immutable original captured Popen call."""
    return popen(*args, **kwargs)


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
        publication = threading.Lock()
        cleanup_lock = threading.RLock()
        cancelling = threading.Event()
        errors = []
        error_lock = threading.Lock()

        def retain(role, error):
            with error_lock:
                if not any(existing_role == role and existing is error
                           for existing_role, existing in errors):
                    errors.append((role, error))

        def observe(stage, child=None, **fields):
            import time
            # Capture the event time here, in the actual executing thread.
            event = {'kind': 'own_lease_probe_stage', 'mode': mode, 'stage': stage,
                     'monotonic_ns': time.monotonic_ns(),
                     'thread_id': threading.get_ident(), **fields}
            if child is not None:
                event['child_pid'] = child.pid
            try:
                guard.append(event)
            except BaseException as error:
                retain('diagnostic_write', error)

        def exercise():
            def paused_spawn(*args, **kwargs):
                observe('constructor_begin')
                child = _lease_popen(original, mode, *args, **kwargs)
                with publication:
                    children.append(child)
                    cancelled = cancelling.is_set()
                observe('constructor_return', child)
                if cancelled:
                    finish_child(child)
                    raise RuntimeError('owned_lease_probe_cancelled')
                # Core READY precedes endpoint setup. This supplementary probe
                # observes both before deliberately terminating its cleanup child.
                import time
                ready_path = Path(guard._STATE['guard']).with_name('multiprocess_routes.py')
                readers = guard.checked_source(ready_path, guard._STATE['direct_support']['files'][str(ready_path)])
                ready = readers['endpoint_ready']
                journal_rows = readers['journal_rows']
                journal = Path(guard._STATE['events']) / (str(child.pid) + '.jsonl')
                observe('registration_lookup_begin', child)
                token = next(row['token'] for row in guard.summarize(guard._STATE['manifest_path'])['events']
                             if row['kind'] == 'registered' and row.get('pid') == child.pid)
                observe('registration_lookup_complete', child)
                deadline = time.monotonic() + 5
                while not ready(journal_rows(journal),
                                guard._STATE, token, child.pid):
                    assert child.poll() is None and time.monotonic() < deadline
                    time.sleep(.001)
                observe('endpoint_complete', child)
                if cancelling.is_set():
                    finish_child(child)
                    raise RuntimeError('owned_lease_probe_cancelled')
                if mode != 'cleanup':
                    observe('stdout_begin', child)
                    assert child.stdout.readline() == b'ready\n'
                    observe('stdout_complete', child)
                if mode == 'spawn':
                    entered.set()
                    observe('entered_set', child)
                    assert release.wait(5)
                return child
            class RegistrationBarrier(list):
                def append(self, child):
                    entered.set()
                    observe('entered_set', child)
                    assert release.wait(5)
                    super().append(child)
            if mode == 'registration':
                owner._processes = RegistrationBarrier()
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
                    try:
                        child.wait(timeout=3)
                    except BaseException as error:
                        retain('synchronous_wait', error)
                    finally:
                        close_streams(child)
                else:
                    def close():
                        with cleanup_lock:
                            result = owner.close(.1)
                        closed.set()
                        return result
                    def run_launch():
                        try:
                            result = _lease_launch(owner, mode, directory)
                        except BaseException as error:
                            retain('worker', error)
                            observe('worker_error', error_type=type(error).__name__,
                                    errno=getattr(error, 'errno', None))
                            raise
                        observe('worker_return')
                        return result
                    futures = []
                    try:
                        with ThreadPoolExecutor(max_workers=2) as pool:
                            try:
                                launch = pool.submit(run_launch)
                                futures.append(('worker', launch))
                                assert entered.wait(5)
                                cleanup = pool.submit(close)
                                futures.append(('owner_cleanup', cleanup))
                                try:
                                    assert not closed.wait(.1)
                                finally:
                                    release.set()
                                assert launch.result(timeout=5) is children[0]
                                assert cleanup.result(timeout=5)
                            except BaseException as error:
                                retain('main', error)
                                cancel_owned()
                            finally:
                                # This must run before Executor.__exit__ joins workers.
                                release.set()
                    except BaseException as error:
                        retain('executor_shutdown', error)
                    finally:
                        # A joined executor establishes completion; an absent future
                        # or a worker-stage observation never stands in for this.
                        for role, future in futures:
                            if not future.done():
                                retain(role, RuntimeError('owned_lease_future_incomplete'))
                                continue
                            try:
                                future_error = future.exception()
                            except BaseException as error:
                                future_error = error
                                retain(role, error)
                            else:
                                if future_error is not None:
                                    retain(role, future_error)
                            observe('future_joined_observation', role=role,
                                    failed=future_error is not None)

        def close_streams(child):
            # Keep the handle's lock across every action. A failing close may
            # already have consumed its fd; retry only the stream object, never
            # its former numeric descriptor (which may now belong to someone else).
            with cleanup_lock:
                for name in ('stdin', 'stdout', 'stderr'):
                    try:
                        stream = getattr(child, name)
                        if stream is not None and not stream.closed:
                            stream.close()
                    except BaseException as error:
                        retain('stream_close_' + name, error)
                        observe('stream_close_error', child, stream=name,
                                error_type=type(error).__name__, errno=getattr(error, 'errno', None))

        def finish_child(child):
            with cleanup_lock:
                observe('child_cleanup_begin', child, status_before_poll=child.returncode)
                stopped = False
                try:
                    stopped = child.poll() is not None
                except BaseException as error:
                    retain('child_poll', error)
                if not stopped:
                    try:
                        child.kill()
                    except BaseException as error:
                        retain('child_stop', error)
                wait_cached = child.returncode is not None
                waited = False
                try:
                    child.wait(timeout=5)
                    waited = True
                except BaseException as error:
                    retain('child_wait', error)
                finally:
                    close_streams(child)
                unsettled = []
                for name in ('stdin', 'stdout', 'stderr'):
                    try:
                        stream = getattr(child, name)
                        if stream is not None and not stream.closed:
                            unsettled.append(name)
                    except BaseException as error:
                        retain('stream_state_' + name, error)
                        unsettled.append(name)
                observe('child_cleanup_complete' if waited and not unsettled else 'child_cleanup_unsettled',
                        child, wait_cached=wait_cached, returncode=child.returncode,
                        waited=waited, unsettled_streams=unsettled)

        def cancel_owned():
            # Publish cancellation before taking the snapshot. A late constructor
            # must clean its own returned handle before endpoint/stdout work.
            with publication:
                cancelling.set()
                published = tuple(children)
            release.set()
            observe('cancellation_published')
            for child in published:
                try:
                    finish_child(child)
                except BaseException as error:
                    retain('cancellation_cleanup', error)

        try:
            exercise()
        except BaseException as error:
            retain('main', error)
        finally:
            release.set()
            for child in children:
                try:
                    finish_child(child)
                except BaseException as error:
                    retain('outer_cleanup', error)
            try:
                broker.close()
            except BaseException as error:
                retain('broker_cleanup', error)
        try:
            after_fds = len(os.listdir('/proc/self/fd'))
        except BaseException as error:
            retain('descriptor_census', error)
            after_fds = None
        observe('mode_failed' if errors else 'mode_settled', before_fds=census,
                after_fds=after_fds, child_count=len(children))
        if errors:
            import hashlib
            failures = tuple(errors)
            for role, failure in failures:
                frames = []
                frame = failure.__traceback__
                while frame is not None:
                    try:
                        digest = hashlib.sha256(Path(frame.tb_frame.f_code.co_filename).read_bytes()).hexdigest()
                    except OSError:
                        digest = None
                    frames.append({'source_sha256': digest, 'line': frame.tb_lineno})
                    frame = frame.tb_next
                observe('failure', role=role, error_type=type(failure).__name__,
                        errno=getattr(failure, 'errno', None), frames=frames[-8:])
            actual = []
            for _, failure in errors:
                if not any(existing is failure for existing in actual):
                    actual.append(failure)
            if len(actual) == 1:
                raise actual[0]
            raise BaseExceptionGroup('owned lease probe failures', actual)
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


def _source_environment_probe():
    """Exercise actual SOURCE root custody without an original owner identity."""
    from pathlib import Path
    guard = sys.modules['runtime_guard']
    state = guard._STATE
    path = Path(state['guard']).with_name('source_environment.py')
    support = guard.checked_source(path, state['direct_support']['files'][str(path)])
    assert support['matches'](state)
    original = os.environ['TMPDIR']
    failures = []
    try:
        for value in ('/work/owned', '/work/owned/tmp/..'):
            os.environ['TMPDIR'] = value
            assert not support['matches'](state)
            failures.append(value)
    finally:
        os.environ['TMPDIR'] = original
    assert support['matches'](state)
    guard.append({'kind': 'guard_source_environment_proof',
                  'source_environment_sha256': guard.digest(path),
                  'directories': state['operation_activation'].owned_environment['directories'],
                  'tmpdir': original, 'refused_tmpdir_values': failures,
                  'original_environment_restored': True})
