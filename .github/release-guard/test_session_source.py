"""Original session caller probe; separate from native execution certification."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from content_manifest import capture, encode, Refused
from session_calls import SessionCalls
from session_launch import CASES, LIVE, PINS


def test_original_session_callers_preserve_all_assertions(tmp_path):
    environment = {'HOME': str(tmp_path), 'TMPDIR': str(tmp_path), 'PATH': '/usr/bin:/bin', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), str(tmp_path)],
        cwd=Path(__file__).resolve().parents[2], env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (result.stdout + result.stderr)[-12000:]
    report = json.loads((tmp_path / 'session-probe.json').read_bytes())
    assert report['completed'] == list(CASES) and report['launches'] == list(LIVE) and not report['poison']
    assert report['source_admission_certified'] is False


class Probe:
    def __init__(self, directory, root):
        self.directory = directory
        raw = encode(capture(root, sorted(PINS)))
        (directory / 'source-manifest.json').write_bytes(raw)
        self.profile = {'checkout': str(root), 'owned': str(directory), 'native': sys.executable,
            'native_sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            'source_sha256': hashlib.sha256(raw).hexdigest(), 'environment': dict(os.environ)}
        self.completed, self.launches, self.poison, self.children = [], [], [], {}
        self.case, self.calls = None, None
        self.original_init = subprocess.Popen.__init__

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_protocol(self, item, nextitem):
        assert item.nodeid == CASES[len(self.completed)]
        self.case, self.calls = item.nodeid, SessionCalls(self, item)
        yield
        self.completed.append(item.nodeid)
        self.case, self.calls = None, None

    def pytest_runtest_logreport(self, report):
        if report.failed or report.skipped:
            self.poison.append(report.nodeid + ':' + report.when)

    def audit(self, event, args):
        if event == 'subprocess.Popen':
            try:
                if self.calls is None or self.case in self.launches:
                    raise Refused('probe no original selected session')
                self.calls.select(self.case, args)
                self.launches.append(self.case)
            except BaseException:
                self.poison.append('launch-refused')
                __import__('traceback').print_exc()
                raise

    def install(self):
        probe = self
        def construct(process, *args, **kwargs):
            probe.original_init(process, *args, **kwargs)
            probe.children[process.pid] = {'process': process}
        subprocess.Popen.__init__ = construct
        sys.addaudithook(self.audit)


def main():
    directory = Path(sys.argv[1]).resolve()
    root = Path(__file__).resolve().parents[2]
    sys.path[:0] = [str(root / 'src'), str(root)]
    probe = Probe(directory, root)
    probe.install()
    code = pytest.main(['-q', '-s', '-p', 'pytest_asyncio.plugin', '-p', 'pytest_mock', '-o', 'addopts=',
        '-o', 'cache_dir=' + str(directory / 'cache'), '--basetemp', str(directory / 'pytest'), *CASES], plugins=[probe])
    (directory / 'session-probe.json').write_text(json.dumps({'completed': probe.completed, 'launches': probe.launches,
        'poison': probe.poison, 'source_admission_certified': False}))
    return int(code != 0 or probe.poison or probe.completed != list(CASES))


if __name__ == '__main__':
    raise SystemExit(main())
