"""Own scheduling/restoration controls; these grant no production launch authority."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from child_relative_methods import Observer


def model(directory=None):
    observer = object.__new__(Observer)
    observer.directory = directory
    observer.directory_fd = None
    observer.native_error = None
    observer.origin = os.getcwd()
    observer.previous = sys.getprofile()
    observer.outer = subprocess.Popen.__init__
    observer.installed = True
    observer.callback = observer.observe
    observer.code = object()
    observer.calls = 0
    if directory is not None:
        info = directory.lstat()
        observer.directory_identity = info.st_dev, info.st_ino, info.st_uid
        observer.directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    return observer


def test_previous_callback_failure_precedes_own_effect_and_restores_exact_profile():
    observer = model()
    error = RuntimeError('own callback error identity')
    def previous(frame, event, value):
        if event == 'call' and frame.f_code is target.__code__:
            raise error
    def target():
        raise AssertionError('body after refusal')
    saved = sys.getprofile()
    observer.previous = previous
    try:
        sys.setprofile(previous)
        with pytest.raises(RuntimeError) as caught:
            with observer:
                target()
        assert caught.value is error and observer.native_error is error
        assert sys.getprofile() is previous
    finally:
        sys.setprofile(saved)


@pytest.mark.parametrize('boundary', ['chmod', 'cwd', 'both'])
def test_restoration_attempts_profile_after_independent_os_errors(tmp_path, monkeypatch, boundary):
    directory = tmp_path / 'owned'
    directory.mkdir()
    observer = model(directory)
    error_mode, error_cwd = OSError('mode'), OSError('cwd')
    def chmod(descriptor, mode):
        raise error_mode
    def chdir(path):
        raise error_cwd
    with monkeypatch.context() as patch:
        if boundary in {'chmod', 'both'}:
            patch.setattr(os, 'fchmod', chmod)
        if boundary in {'cwd', 'both'}:
            patch.setattr(os, 'chdir', chdir)
        with pytest.raises(BaseExceptionGroup) as caught:
            observer.restore()
        assert sys.getprofile() is observer.previous
    assert directory.exists()
    actual = caught.value.exceptions
    assert (error_mode in actual) is (boundary in {'chmod', 'both'})
    assert (error_cwd in actual) is (boundary in {'cwd', 'both'})


def test_owned_directory_is_restored_removed_without_touching_source(tmp_path):
    directory = tmp_path / 'owned'
    directory.mkdir()
    observer = model(directory)
    directory.chmod(0)
    observer.restore()
    assert not directory.exists() and os.getcwd() == observer.origin


def test_changed_directory_identity_is_not_chmodded_or_removed(tmp_path):
    directory = tmp_path / 'owned'
    directory.mkdir()
    observer = model(directory)
    directory.chmod(0)
    directory.rename(tmp_path / 'retained')
    directory.mkdir(mode=0o700)
    with pytest.raises(BaseExceptionGroup, match='restoration failed'):
        observer.restore()
    assert directory.is_dir() and (tmp_path / 'retained').is_dir()
    assert (tmp_path / 'retained').stat().st_mode & 0o777 == 0o700
    assert observer.directory_fd is None
    assert sys.getprofile() is observer.previous


def test_existing_negative_capsule_cannot_be_invoked_with_unknown_mode():
    import child_relative_host
    with pytest.raises(RuntimeError, match='own_constructor_fault_mode'):
        child_relative_host.reduce_fault({}, 'unknown')


@pytest.mark.skipif(not Path('/opt/source-guard/profile_gate.so').is_file(),
                    reason='current compiled native gate is provided by the Linux control image')
@pytest.mark.parametrize('failure', [False, True])
def test_current_native_gate_chains_original_arguments_and_restores_after_error(failure):
    import importlib.util
    specification = importlib.util.spec_from_file_location('profile_gate', '/opt/source-guard/profile_gate.so')
    gate = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(gate)
    observer = model()
    events = []
    error = RuntimeError('native previous callback failure')
    def target():
        return 17
    def previous(frame, event, value):
        if frame.f_code is target.__code__:
            events.append((frame, event, value))
            if failure and event == 'call':
                raise error
    native = gate.make(previous, {}, {__file__})
    observer.previous = native
    saved = sys.getprofile()
    try:
        sys.setprofile(native)
        if failure:
            with pytest.raises(RuntimeError) as caught:
                with observer:
                    target()
            assert caught.value is error and [row[1] for row in events] == ['call']
        else:
            with observer:
                assert target() == 17
            assert [row[1] for row in events] == ['call', 'return']
            assert events[0][0] is events[1][0] and events[1][2] == 17
        assert sys.getprofile() is native and observer.calls == 0
    finally:
        sys.setprofile(saved)
