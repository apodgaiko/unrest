"""Fresh producer READY evidence retains every original ownership/pin refusal."""
import json
import os
from types import SimpleNamespace

import pytest

import linux_supervisor as host
from linux_producers import NativeProducers
from primary_ready_snapshot import install


@pytest.fixture
def ready(tmp_path, monkeypatch):
    value = host.Supervisor.__new__(host.Supervisor)
    birth = {'pid': 17, 'start_ticks': 111}
    pins = dict(manifest_sha256='a' * 64, guard_sha256='b' * 64,
                registry_sha256='c' * 64, runtime_sha256='d' * 64)
    value.spec = {'endpoint': {'nonce': 'n' * 64}}
    value.registered = {17: {'identity': birth, 'token': 'producer', 'ready_pins': pins}}
    value.manifest_pin = 'e' * 64
    journal = tmp_path / 'events'
    journal.mkdir()
    value.manifest = {'events': str(journal), 'guard_sha256': pins['guard_sha256'],
                      'registry': {'sha256': pins['registry_sha256']},
                      'runtime': {'sha256': pins['runtime_sha256']}}
    monkeypatch.setattr(host.kernel, 'identity', lambda pid: birth)
    request = {'pid': 17, 'token': 'producer', 'nonce': 'n' * 64, 'kind': 'ready', 'identity': birth}
    event = {'kind': 'ready', 'owner_pid': 17, 'token': 'producer', **pins}
    producers = object.__new__(NativeProducers)
    producers.supervisor = value
    producers.children = {17: {'token': 'producer', 'identity': birth}}
    install(value, producers)
    return SimpleNamespace(value=value, request=request, event=event, journal=journal, birth=birth, producers=producers)


@pytest.mark.parametrize('change', ['none', 'missing', 'nonce', 'token', 'birth', 'owner',
                                    'event_token', 'manifest', 'guard', 'registry', 'runtime',
                                    'ordinary_registration', 'other_request', 'unowned_child', 'child_token',
                                    'child_birth', 'current_birth'])
def test_late_producer_ready_is_freshly_read_without_broadening(ready, monkeypatch, change):
    f = ready
    if change == 'nonce':
        f.request['nonce'] = 'foreign'
    elif change == 'token':
        f.request['token'] = 'foreign'
    elif change == 'birth':
        f.request['identity'] = {'pid': 17, 'start_ticks': 112}
    elif change == 'owner':
        f.event['owner_pid'] = 18
    elif change == 'event_token':
        f.event['token'] = 'foreign'
    elif change in {'manifest', 'guard', 'registry', 'runtime'}:
        f.event[change + '_sha256'] = 'f' * 64
    elif change == 'ordinary_registration':
        del f.value.registered[17]['ready_pins']
    elif change == 'other_request':
        f.request['kind'] = 'connect'
    elif change == 'unowned_child':
        f.producers.children.clear()
    elif change == 'child_token':
        f.producers.children[17]['token'] = 'foreign'
    elif change == 'child_birth':
        f.producers.children[17]['identity'] = {'pid': 17, 'start_ticks': 112}
    elif change == 'current_birth':
        monkeypatch.setattr(host.kernel, 'identity', lambda pid: {'pid': 17, 'start_ticks': 112})
    if change != 'missing':
        (f.journal / 'producer.jsonl').write_text(json.dumps(f.event) + '\n')
    if change == 'none':
        assert f.value.authenticate(f.request, []) is f.value.registered[17]
    else:
        with pytest.raises(RuntimeError):
            f.value.authenticate(f.request, [])


def test_current_wrong_ready_cannot_be_replaced_by_a_later_good_record(ready):
    f = ready
    (f.journal / 'producer.jsonl').write_text(json.dumps(f.event) + '\n')
    wrong = {**f.event, 'runtime_sha256': 'f' * 64}
    with pytest.raises(RuntimeError, match='authenticated_READY_missing'):
        f.value.authenticate(f.request, [wrong])


def test_actual_receipt_uses_ready_appended_after_tick_snapshot(tmp_path, monkeypatch):
    import socket
    import struct
    import sys
    if sys.platform != 'linux':
        pytest.skip('actual Linux SO_PEERCRED and proc birth identity required')
    manifest = tmp_path / 'manifest.json'
    manifest.write_text('{}')
    config = {'manifest': str(manifest), 'pins': {str(manifest): host.sha(manifest)},
              'endpoint': {'responses': str(tmp_path), 'nonce': 'a' * 64,
                           'socket': str(tmp_path / 'receipt.sock')}}
    supervisor = host.Supervisor(config, type('Child', (), {'pid': os.getpid()})())
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pins = dict(manifest_sha256='a' * 64, guard_sha256='b' * 64,
                    registry_sha256='c' * 64, runtime_sha256='d' * 64)
        journal = tmp_path / 'events'
        journal.mkdir()
        supervisor.manifest.update(events=str(journal), guard_sha256=pins['guard_sha256'],
                                   registry={'sha256': pins['registry_sha256']},
                                   runtime={'sha256': pins['runtime_sha256']})
        supervisor.registered[os.getpid()]['ready_pins'] = pins
        producers = object.__new__(NativeProducers)
        producers.supervisor = supervisor
        producers.children = {os.getpid(): {'token': 'root', 'identity': supervisor.root}}
        install(supervisor, producers)
        monkeypatch.setattr(supervisor, 'refresh', lambda: [])
        event = {'kind': 'ready', 'owner_pid': os.getpid(), 'token': 'root', **pins}
        (journal / 'producer.jsonl').write_text(json.dumps(event) + '\n')
        client.connect(config['endpoint']['socket'])
        client.settimeout(1)
        request = {'kind': 'ready', 'id': 'b' * 32, 'pid': os.getpid(), 'token': 'root',
                   'nonce': 'a' * 64, 'identity': supervisor.root}
        body = json.dumps(request).encode()
        client.sendall(struct.pack('!I', len(body)) + body)
        supervisor.tick()
        assert client.recv(16388)
        assert not supervisor.poisoned and supervisor.receipts[-1]['ok'] is True
        assert supervisor.receipts[-1]['kernel_peer']['birth'] == supervisor.root
    finally:
        client.close()
        supervisor.close()


@pytest.mark.parametrize('change', ['duplicate', 'foreign_owner', 'foreign_producer', 'foreign_supervisor'])
def test_hook_requires_the_original_owned_producer_supervisor_pair(ready, change):
    f = ready
    owner, producers = f.value, f.producers
    if change == 'foreign_owner':
        producers.supervisor = object()
    elif change == 'foreign_producer':
        producers = object()
    elif change == 'foreign_supervisor':
        owner = object()
    with pytest.raises(RuntimeError, match='primary_ready_snapshot_owner'):
        install(owner, producers)
