"""A socket file fixture grants neither listener nor message permissions."""
from types import SimpleNamespace

import pytest

from finite import fixture_unix as fixture
import primary_environment
from journal_supervisor import JournalSupervisor


def test_only_original_two_socket_parameter_cases():
    assert fixture.CASES == frozenset(fixture.SOURCE + '::test_static_carrier_refuses_without_outside_effects[socket-' + v + ']'
                                     for v in ('False', 'True'))
    for event in ('socket.connect', 'socket.listen', 'socket.sendmsg'):
        assert fixture.authorize(event, (), {'case': next(iter(fixture.CASES))}, None, None) is False
    assert fixture.authorize('socket.bind', (), {'case': 'foreign'}, None, None) is False


def test_alias_is_readonly_image_metadata_pointing_only_to_owned_tmp(tmp_path, monkeypatch):
    support = tmp_path / 'support'
    support.mkdir()
    for name in ('primary_entry.c', 'primary_entry.py', 'primary_entry_build.py'):
        (support / name).write_bytes(b'fixture')
    calls = []
    monkeypatch.setattr(primary_environment.subprocess, 'run', lambda argv, **kwargs: calls.append(argv) or SimpleNamespace(stdout=b'', returncode=0))
    monkeypatch.setattr(primary_environment.subprocess, 'check_output', lambda *args, **kwargs: 'sha256:' + 'b' * 64)
    image = tmp_path / 'image'
    assert primary_environment.build(image, 'sha256:' + 'a' * 64, support, tmp_path / 'image.log') == 'sha256:' + 'b' * 64
    dockerfile = (image / 'Dockerfile').read_text()
    assert 'RUN install -d -m 0755 /private && ln -s /work/owned/tmp /private/tmp\n' in dockerfile
    assert 'VOLUME' not in dockerfile and 'chmod 0777 /private' not in dockerfile
    assert [c[:2] for c in calls] == [['docker', 'tag'], ['docker', 'build']]


@pytest.mark.parametrize('kind', ['approval_unix', 'fixture_unix_bind'])
def test_both_unix_paths_preserve_global_poison(kind):
    owner = JournalSupervisor.__new__(JournalSupervisor)
    owner.poisoned = True
    with pytest.raises(RuntimeError, match='global_poison_retained'):
        owner.handle({'kind': kind}, [])
