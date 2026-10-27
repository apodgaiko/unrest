"""Original 24-case caller probe; kernel isolation and native helpers are separate.

The probe's test-only hooks never supply release enforcement or a certificate.
"""
import faulthandler
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import types

import pytest

from content_manifest import capture, encode, Refused
from git_sites import CASES, PINS, SITES
from git_source import GitCalls
from source_owner import active_frames, frame_fields, instance_fields


def test_site_table_pins_and_original_collection_are_distinct_from_admission():
    root = Path(__file__).resolve().parents[2]
    for name, pin in PINS.items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == pin
    assert len(CASES) == 24 and len(set(CASES)) == 24
    assert len(SITES) == 75
    assert set(SITES.values()) <= __import__('git_commands').FIELDS.keys()


def test_original_workspace_evolution_callers_keep_their_real_assertions(tmp_path):
    try:
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), str(tmp_path)],
        cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=90,
        env={'PATH': '/usr/bin:/bin', 'HOME': str(tmp_path / 'home'), 'TMPDIR': str(tmp_path),
             'LC_ALL': 'C.UTF-8', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'})
    except subprocess.TimeoutExpired as error:
        progress = (tmp_path / 'progress.jsonl').read_text() if (tmp_path / 'progress.jsonl').exists() else 'no case progress'
        pytest.fail(progress[-4000:] + '\n' + (error.stderr or b'no task stack').decode('utf-8', 'replace')[-12000:], pytrace=False)
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((tmp_path / 'probe-result.json').read_text())
    assert report['cases'] == list(CASES) and report['poison'] == []
    assert report['git_calls'] > 100 and report['owned_python'] == 1
    assert report['source_admission_certified'] is False


def test_typed_records_retain_initial_class_and_module_bindings(monkeypatch):
    module = types.ModuleType('git_record_control')
    cls = type('WorkspaceLease', (), {})
    module.WorkspaceLease = cls
    monkeypatch.setitem(sys.modules, module.__name__, module)
    calls = object.__new__(GitCalls)
    calls.record_types = {('workspaces', 'WorkspaceLease'): (module, cls)}
    value = cls()
    value.lease_id = 'lease:one'
    assert calls.record(value, 'workspaces', 'WorkspaceLease') == {'lease_id': 'lease:one'}
    replacement = type('WorkspaceLease', (), {})
    module.WorkspaceLease = replacement
    with pytest.raises(Refused, match='original typed record'):
        calls.record(replacement(), 'workspaces', 'WorkspaceLease')
    module.WorkspaceLease = cls
    monkeypatch.setitem(sys.modules, module.__name__, types.ModuleType(module.__name__))
    with pytest.raises(Refused, match='original typed record'):
        calls.record(value, 'workspaces', 'WorkspaceLease')


class Probe:
    def __init__(self, directory, root):
        self.directory, self.root = directory, root
        raw = encode(capture(root, sorted(PINS)))
        (directory / 'source-manifest.json').write_bytes(raw)
        self.profile = {'checkout': str(root), 'owned': str(directory), 'native': sys.executable,
            'environment': dict(os.environ), 'source_sha256': hashlib.sha256(raw).hexdigest()}
        self.case, self.calls, self.pending = None, None, None
        self.completed, self.poison, self.processes, self.rows = [], [], {}, []
        self.owned = 0
        self.original_init, self.original_communicate = subprocess.Popen.__init__, subprocess.Popen.communicate

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_protocol(self, item, nextitem):
        assert item.nodeid == CASES[len(self.completed)]
        self.case = item.nodeid
        self.progress('start')
        self.calls = GitCalls(self, item)
        self.progress('prepared')
        yield
        self.progress('finished')
        self.completed.append(item.nodeid)
        self.case, self.calls = None, None

    def progress(self, stage):
        with (self.directory / 'progress.jsonl').open('a') as stream:
            stream.write(json.dumps({'case': self.case, 'stage': stage, 'time': time.monotonic(), 'git_calls': len(self.rows), 'failures': len(self.poison)}) + '\n')

    def pytest_runtest_logreport(self, report):
        if report.failed or report.skipped:
            self.poison.append(report.nodeid + ':' + report.when)

    def audit(self, event, arguments):
        if event != 'subprocess.Popen':
            return
        try:
            if self.calls is None or self.pending is not None:
                raise Refused('probe no selected caller')
            executable, vector, cwd, env = arguments
            if type(vector) is not list or any(type(v) is not str for v in vector):
                raise Refused('probe argv primitives')
            if vector == [sys.executable, '-c', 'import time; time.sleep(60)']:
                self.check_owned(cwd, env)
                self.pending = (self.calls, None)
                return
            site, operation, fields, command = self.calls.select_command()
            if vector != list(command.argv) or str(cwd) != command.cwd or executable != 'git':
                raise Refused('probe exact original command')
            if env is not None and operation != 'commit-tree':
                raise Refused('probe unexpected environment override')
            self.rows.append((self.case, site, operation))
            self.pending = (self.calls, command)
        except BaseException:
            self.poison.append('launch-refused')
            raise

    def check_owned(self, cwd, env):
        if self.case != CASES[7] or self.owned or env is not None:
            raise Refused('probe exact owned-process case')
        calls = self.calls
        frames = active_frames()
        try:
            calls.test_owner.current(frames)
            source = 'src/unrest_harness/workspaces.py'
            owner = calls.owner_for(source, 'WorkspaceManager.start_owned_process')
            local = frame_fields(owner.current(frames, line=754))
            cls = vars(calls.sources[source][0])['WorkspaceManager']
            if type(local.get('self')) is not cls:
                raise Refused('probe original owned manager')
            lease = calls.record(local.get('lease'), 'workspaces', 'WorkspaceLease')
            expected = calls.repository + '/.unrest-runtime/workspaces/trees/process'
            if str(cwd) != expected or lease.get('worktree_path') != expected:
                raise Refused('probe original owned cwd')
            budget = instance_fields(lease['resource_budget'])
            if budget != {'max_processes': 1, 'max_patch_bytes': 1000}:
                raise Refused('probe original owned budget')
            constructors = [f for f in frames if f.f_code is self.original_init.__code__]
            if len(constructors) != 1:
                raise Refused('probe original constructor')
            options = frame_fields(constructors[0])
            if any(options.get(key) != -3 for key in ('stdin', 'stdout', 'stderr')) or options.get('start_new_session') is not True:
                raise Refused('probe original owned descriptors')
            self.owned += 1
        finally:
            del frames

    def install(self):
        probe = self
        def construct(process, *args, **kwargs):
            probe.pending = None
            probe.original_init(process, *args, **kwargs)
            if probe.pending is None:
                raise Refused('probe constructor absent intent')
            probe.processes[process.pid] = (process, probe.pending)
            probe.pending = None
        def communicate(process, *args, **kwargs):
            result = probe.original_communicate(process, *args, **kwargs)
            saved, (calls, command) = probe.processes[process.pid]
            assert saved is process
            if command is not None and command.produces is not None and command.produces[1] == 'integration-commit' and process.returncode == 0:
                output = result[0]
                assert type(output) is str and len(output) == 41 and output.endswith('\n')
                calls.integrations[output[:-1]] = (command.produces[0], command.produces[2])
            return result
        subprocess.Popen.__init__, subprocess.Popen.communicate = construct, communicate
        sys.addaudithook(self.audit)

    def cleanup(self):
        for process, (_, command) in self.processes.values():
            if command is None and process.poll() is None:
                os.killpg(process.pid, 9)
                process.wait(timeout=5)


def main():
    directory = Path(sys.argv[1]).resolve()
    root = Path(__file__).resolve().parents[2]
    sys.path[:0] = [str(root / 'src'), str(root)]
    os.environ['HOME'] = str(directory / 'home')
    Path(os.environ['HOME']).mkdir()
    Path(os.environ['HOME'], '.gitconfig').write_text('[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n')
    faulthandler.dump_traceback_later(15, repeat=True)
    probe = Probe(directory, root)
    probe.install()
    try:
        code = pytest.main(['-q', '-s', '-o', 'faulthandler_timeout=10', '-p', 'pytest_asyncio.plugin', '-p', 'pytest_mock', '-o', 'addopts=', '-o', 'cache_dir=' + str(directory / 'cache'),
            '--basetemp', str(directory / 'pytest'), *CASES], plugins=[probe])
    finally:
        faulthandler.cancel_dump_traceback_later()
        probe.cleanup()
    (directory / 'probe-result.json').write_text(json.dumps({'cases': probe.completed, 'poison': probe.poison,
        'git_calls': len(probe.rows), 'owned_python': probe.owned, 'source_admission_certified': False}))
    return int(code != 0 or probe.poison or probe.completed != list(CASES))


if __name__ == '__main__':
    raise SystemExit(main())
