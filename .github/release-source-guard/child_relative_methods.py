"""Own-identity constructor probe through the unchanged production guard."""
from __future__ import annotations

import os
import errno
import json
from pathlib import Path
import stat
import select
import time
import types
import subprocess
import sys


def probe():
    guard = sys.modules['runtime_guard']
    marker = Path('/inputs/own-constructor-fault.json')
    if marker.exists():
        request = json.loads(marker.read_bytes())
        assert set(request) == {'mode', 'source_sha256'}
        assert request['source_sha256'] == guard._STATE['product_pins'][
            '.github/release-source-guard/child_relative_methods.py']
        fault_probe(request['mode'])
        raise AssertionError('own constructor fault unexpectedly returned')
    before = len(os.listdir('/proc/self/fd'))
    outcomes = []
    for mode in ('constructor-error', 'positive'):
        options = {'pass_fds': (-1,)} if mode == 'constructor-error' else {}
        try:
            result = subprocess.run([sys.executable, '-I', '-S', '-c', 'pass'],
                                    check=True, **options)
        except ValueError as error:
            assert mode == 'constructor-error' and 'fds_to_keep' in str(error)
            outcomes.append({'mode': mode, 'error_type': type(error).__name__})
        else:
            assert mode == 'positive' and result.returncode == 0
            outcomes.append({'mode': mode, 'returncode': result.returncode})
        assert before == len(os.listdir('/proc/self/fd'))
    after = len(os.listdir('/proc/self/fd'))
    rows = guard.summarize(guard._STATE['manifest_path'])['events']
    selected = [row for row in rows if row['kind'] == 'child_relative_constructor'
                and row['class'] == 'source-child-relative-probe']
    assert len(selected) == 2 and len({row['token'] for row in selected}) == 2
    guard.append({'kind': 'guard_child_relative_probe', 'tokens': [row['token'] for row in selected],
                  'before_fds': before, 'after_fds': after, 'outcomes': outcomes})
    postfork()


BARRIER = ('import os,json,time;'
           'before=os.stat(".");'
           'print(json.dumps({"pid":os.getpid(),"cwd":os.getcwd(),'
           '"identity":[before.st_dev,before.st_ino],"time":time.monotonic_ns()}),flush=True);'
           'assert os.read(0,1)==b"G";after=os.stat(".");'
           'print(json.dumps({"pid":os.getpid(),"cwd":os.getcwd(),'
           '"identity":[after.st_dev,after.st_ino],"time":time.monotonic_ns()}),flush=True)')


def cells(function):
    return dict(zip(function.__code__.co_freevars,
                    (cell.cell_contents for cell in function.__closure__ or ()), strict=True))


class Observer:
    """One own saved-stock call; the native observer always receives events first."""

    def __init__(self, mode):
        if mode not in {'postfork', 'wrongcwd', 'nonsearchable'}:
            raise RuntimeError('own_constructor_mode')
        self.mode = mode
        self.guard = sys.modules['runtime_guard']
        self.state = self.guard._STATE
        self.outer = subprocess.Popen.__init__
        outer = cells(self.outer)
        self.inner = outer['initialize_inner']
        self.constructor = cells(self.inner)['original_init']
        captured = cells(self.constructor)
        self.stock = captured['stock']
        self.previous = outer['selected_port']
        self.origin = os.getcwd()
        self.directory = None
        self.directory_fd = None
        self.native_error = None
        self.token = None
        self.handle = None
        self.calls = 0
        self.forks = []
        self.events = []
        self.installed = False
        if (self.outer.__globals__ is not vars(self.guard)
                or self.inner.__globals__ is not vars(self.guard)
                or cells(self.inner)['state'] is not self.state
                or captured['state'] is not self.state
                or type(self.stock) is not types.FunctionType
                or self.stock.__globals__ is not vars(subprocess)
                or sys.getprofile() is not self.previous
                or type(self.previous).__module__ != 'profile_gate'
                or type(self.previous).__name__ != 'Gate'
                or self.origin != self.state['checkout']
                or self.state['case'] != '.github/release-source-guard/multiprocess_guard_methods.py::test_owned_exit17_keeps_raw_status'):
            raise RuntimeError('own_constructor_observer_boundary')
        named = self.state['isolated_named']
        guard_code = compile(Path(self.state['guard']).read_bytes(), self.state['guard'], 'exec', dont_inherit=True)
        boundary = Path(self.state['guard']).with_name('child_relative.py')
        boundary_code = compile(boundary.read_bytes(), str(boundary), 'exec', dont_inherit=True)
        if (self.guard.digest(self.state['guard']) != self.state['guard_sha256']
                or self.outer.__code__ != named(guard_code, 'initialize')
                or self.inner.__code__ != named(guard_code, 'initialize_inner')
                or self.guard.digest(boundary) != self.state['direct_support']['files'][str(boundary)]
                or self.constructor.__code__ != named(boundary_code, 'constructor')
                or self.stock.__code__ != captured['stock_code']
                or self.stock.__defaults__ != captured['defaults']
                or self.stock.__kwdefaults__ != captured['keyword_defaults']):
            raise RuntimeError('own_constructor_observer_callable_drift')
        self.callback = self.observe
        self.code = self.stock.__code__
        self.native_code = self.inner.__code__
        self.constructor_code = self.constructor.__code__
        if mode == 'nonsearchable':
            self.directory = Path(self.state['owned_root']) / 'own-constructor-nonsearchable'
            self.directory.mkdir(mode=0o700)
            info = self.directory.lstat()
            self.directory_identity = (info.st_dev, info.st_ino, info.st_uid)
            if info.st_uid != os.geteuid() or not stat.S_ISDIR(info.st_mode):
                raise RuntimeError('own_constructor_directory_owner')
            try:
                self.directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                opened = os.fstat(self.directory_fd)
                if (opened.st_dev, opened.st_ino, opened.st_uid) != self.directory_identity:
                    raise RuntimeError('own_constructor_directory_open_drift')
            except BaseException:
                if self.directory_fd is not None:
                    os.close(self.directory_fd)
                    self.directory_fd = None
                current = self.directory.lstat()
                if self.directory_identity == (current.st_dev, current.st_ino, current.st_uid):
                    self.directory.rmdir()
                raise

    def observe(self, frame, event, value):
        # A native exception propagates unchanged. In particular it never counts
        # as an injected constructor fault; the enclosing finally restores it.
        try:
            self.previous(frame, event, value)
        except BaseException as error:
            self.native_error = error
            raise
        if event == 'call' and frame.f_code is self.code:
            parent = frame.f_back
            core = parent.f_back if parent else None
            if (self.calls or parent is None or parent.f_code is not self.constructor_code
                    or parent.f_locals.get('stock') is not self.stock
                    or core is None or core.f_code is not self.native_code
                    or core.f_globals is not vars(self.guard)
                    or core.f_locals.get('state') is not self.state
                    or core.f_locals.get('original_init') is not self.constructor
                    or core.f_locals.get('handle') is not frame.f_locals.get('self')
                    or frame.f_globals is not vars(subprocess)
                    or frame.f_locals.get('args') is not core.f_locals.get('child_argv')
                    or frame.f_locals.get('cwd') != '.'
                    or parent.f_locals.get('registration', {}).get('class') != 'source-child-relative-probe'
                    or parent.f_locals.get('token') != core.f_locals.get('launch_token')
                    or self.guard._STATE is not self.state
                    or subprocess.Popen.__init__ is not self.outer
                    or sys.getprofile() is not self.callback):
                raise RuntimeError('own_constructor_observer_context')
            self.calls += 1
            self.token = core.f_locals['launch_token']
            self.handle = frame.f_locals['self']
            self.events.append({'stage': 'stock-call', 'time': time.monotonic_ns(),
                                'cwd': os.getcwd(), 'token': self.token})
            if self.mode == 'wrongcwd':
                os.chdir('/source/docs')
            elif self.mode == 'nonsearchable':
                os.fchdir(self.directory_fd)
                os.fchmod(self.directory_fd, 0)
            self.events.append({'stage': 'before-fork', 'time': time.monotonic_ns(),
                                'cwd': os.getcwd(), 'token': self.token})
        if (self.calls and event == 'c_return' and value is subprocess._fork_exec
                and frame.f_code is subprocess.Popen._execute_child.__code__
                and frame.f_locals.get('self') is self.handle):
            self.forks.append(time.monotonic_ns())

    def __enter__(self):
        self.installed = True
        try:
            sys.setprofile(self.callback)
        except BaseException as initiating:
            try:
                self.restore()
            except BaseException as cleanup:
                raise BaseExceptionGroup('own observer installation and restoration failed',
                                         [initiating, cleanup]) from None
            raise
        return self

    def restore(self):
        errors = []
        descriptor_owned = False
        if self.directory is not None:
            try:
                opened = os.fstat(self.directory_fd)
                if (opened.st_dev, opened.st_ino, opened.st_uid) != self.directory_identity:
                    raise RuntimeError('own_constructor_descriptor_drift')
                descriptor_owned = True
                os.fchmod(self.directory_fd, 0o700)
            except BaseException as error:
                errors.append(error)
            try:
                info = self.directory.lstat()
                if (info.st_dev, info.st_ino, info.st_uid) != self.directory_identity:
                    raise RuntimeError('own_constructor_directory_drift')
            except BaseException as error:
                errors.append(error)
        try:
            os.chdir(self.origin)
        except BaseException as error:
            errors.append(error)
        try:
            if self.installed:
                sys.setprofile(self.previous)
            if sys.getprofile() is not self.previous or subprocess.Popen.__init__ is not self.outer:
                raise RuntimeError('own_constructor_observer_restoration')
        except BaseException as error:
            errors.append(error)
        if self.directory_fd is not None and descriptor_owned:
            descriptor, self.directory_fd = self.directory_fd, None
            try:
                os.close(descriptor)
            except BaseException as error:
                errors.append(error)
        if self.directory is not None and not errors:
            try:
                self.directory.rmdir()
            except BaseException as error:
                errors.append(error)
        if errors:
            raise BaseExceptionGroup('own constructor restoration failed', errors)

    def __exit__(self, kind, error, traceback):
        try:
            self.restore()
        except BaseException as cleanup:
            if error is not None:
                raise BaseExceptionGroup('own constructor and restoration failed', [error, cleanup]) from None
            raise


def postfork():
    guard = sys.modules['runtime_guard']
    before = len(os.listdir('/proc/self/fd'))
    child = None
    original = os.getcwd()
    observer = Observer('postfork')
    try:
        with observer:
            child = subprocess.Popen([sys.executable, '-I', '-S', '-c', BARRIER],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        assert observer.calls == 1 and len(observer.forks) == 1
        assert select.select([child.stdout], [], [], 8)[0]
        entered = json.loads(child.stdout.readline())
        assert entered['pid'] == child.pid and entered['cwd'] == original
        assert child.poll() is None
        os.chdir('/source/docs')
        changed = time.monotonic_ns()
        output, _ = child.communicate(b'G', timeout=8)
        released = json.loads(output)
        assert child.returncode == 0 and released['pid'] == child.pid
        assert released['cwd'] == entered['cwd'] and released['identity'] == entered['identity']
        assert observer.forks[0] < entered['time'] < changed < released['time']
    finally:
        os.chdir(original)
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait()
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
    after = len(os.listdir('/proc/self/fd'))
    assert before == after and sys.getprofile() is observer.previous
    guard.append({'kind': 'own_constructor_postfork', 'token': observer.token,
                  'pid': child.pid, 'events': observer.events, 'fork_returns': observer.forks,
                  'body_entered': entered, 'parent_changed': changed, 'body_released': released,
                  'before_fds': before, 'after_fds': after, 'profile_restored': True})


def fault_probe(mode):
    if mode not in {'wrongcwd', 'nonsearchable'}:
        raise RuntimeError('own_constructor_fault_mode')
    guard = sys.modules['runtime_guard']
    before = len(os.listdir('/proc/self/fd'))
    before_identity = fd_census()
    observer = Observer(mode)
    child = None
    outcome = None
    try:
        with observer:
            child = subprocess.Popen([sys.executable, '-I', '-S', '-c', 'pass'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except BaseException as error:
        outcome = {'class': type(error).__name__, 'errno': getattr(error, 'errno', None),
                   'filename': getattr(error, 'filename', None)}
        raise
    finally:
        if child is not None:
            try:
                child.wait(timeout=8)
            finally:
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()
        after = len(os.listdir('/proc/self/fd'))
        guard.append({'kind': 'own_constructor_fault', 'mode': mode, 'token': observer.token,
                      'calls': observer.calls, 'fork_returns': observer.forks,
                      'native_callback_error': None if observer.native_error is None else type(observer.native_error).__name__,
                      'events': observer.events, 'outcome': outcome,
                      'pid': getattr(observer.handle, 'pid', None),
                      'returncode': getattr(observer.handle, 'returncode', None),
                      'before_fds': before, 'after_fds': after,
                      'before_identity': before_identity, 'after_identity': fd_census(),
                      'profile_restored': sys.getprofile() is observer.previous,
                      'cwd_restored': os.getcwd() == observer.origin,
                      'directory_absent': observer.directory is None or not observer.directory.exists()})


def fd_census():
    rows = []
    for fd in sorted(map(int, os.listdir('/proc/self/fd'))):
        try:
            info = os.fstat(fd)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        rows.append([fd, info.st_dev, info.st_ino, info.st_mode, info.st_rdev])
    return rows
