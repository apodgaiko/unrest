"""Controller Git must stay synchronous and independent of ambient configuration."""
from pathlib import Path
import subprocess

import pytest

from unrest_harness import experimental_custody


def test_custody_git_disables_background_maintenance_and_ambient_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[list[str], dict[str, object]]] = []

    def run(argv: list[str], **options: object) -> subprocess.CompletedProcess[bytes]:
        observed.append((argv, options))
        return subprocess.CompletedProcess(argv, 0, stdout=b'1' * 40 + b'\n')

    monkeypatch.setenv('GIT_CONFIG_PARAMETERS', 'UNRELATED_AMBIENT_CONFIGURATION')
    monkeypatch.setattr(experimental_custody.subprocess, 'run', run)
    assert experimental_custody.git(tmp_path, 'rev-parse', 'HEAD') == '1' * 40
    argv, options = observed[0]
    assert argv == ['/usr/bin/git', '--no-replace-objects', '-c', 'maintenance.auto=false',
                    '-c', 'gc.auto=0', 'rev-parse', 'HEAD']
    assert options['cwd'] == tmp_path and options['timeout'] == 5 and options['check'] is True
    assert options['stdin'] == options['stderr'] == subprocess.DEVNULL
    assert options['stdout'] == subprocess.PIPE
    environment = options['env']
    assert isinstance(environment, dict)
    assert environment['GIT_CONFIG_GLOBAL'] == '/dev/null'
    assert environment['GIT_CONFIG_NOSYSTEM'] == '1'
    assert 'GIT_CONFIG_PARAMETERS' not in environment
