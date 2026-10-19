"""Controlled observer-return boundaries; real archive acceptance is separate."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import primary_package_archive as archive
import primary_outputs
from primary_custody import ARCHIVE, canonical, sha
from test_checkpoint_issuer import archives
from test_primary_custody import records
from linux_supervisor import Supervisor


@pytest.fixture
def returned(tmp_path, monkeypatch):
    owner = Supervisor.__new__(Supervisor)
    birth = {'pid': os.getpid(), 'start_ticks': 111}
    owner.child = SimpleNamespace(pid=os.getpid())
    owner.poisoned = False
    owner.authenticate = lambda request, events: {'identity': birth}
    value = SimpleNamespace(supervisor=owner, package_proof=None,
                            manifest={'product_pins': {'tools/check_distribution.py': 'a' * 64}})
    primary = SimpleNamespace(contexts={os.getpid(): {'role': 'package-root', 'identity': birth}}, records=[])
    output = archives()
    descriptor = tmp_path / 'input.json'
    descriptor.write_bytes(canonical({'members': {name: {'sha256': sha(body), 'size': len(body)}
                                                 for name, body in output.items()}}))
    monkeypatch.setattr(archive, 'Path', lambda p: descriptor if p == '/inputs/package-input.json' else Path(p))
    monkeypatch.setattr(archive, 'sha', lambda p: 'a' * 64)
    monkeypatch.setattr(archive, 'identity', lambda pid: birth)
    monkeypatch.setattr(primary_outputs, 'export', lambda duty: records(ARCHIVE, output)['package-output.json'])
    result = {'package_files': 1, 'wheel': 'unrest_harness-0.4.6-py3-none-any.whl',
              'sdist': 'unrest_harness-0.4.6.tar.gz', 'restart_oracle': {'cases': 15}}
    request = {'id': 'b' * 32, 'kind': 'primary_package_function_return', 'nonce': 'n',
               'pid': os.getpid(), 'token': 'root', 'identity': birth,
               'function': 'check_distribution', 'source_sha256': 'a' * 64, 'result': result}
    archive.install_return_observer(value, primary)
    return owner, value, primary, request, descriptor


def test_original_return_is_observer_owned_and_archive_bytes_rechecked(returned):
    owner, value, primary, request, _ = returned
    assert owner.handle(request, []) == {'original_function_return_observed': True}
    assert value.package_proof['result'] is request['result']
    assert primary.records[0]['proof_sha256'] == sha(canonical(value.package_proof))
    assert primary.records[0]['identity'] == request['identity']


@pytest.mark.parametrize('mutation', ['poison', 'duplicate', 'function', 'source', 'foreign_pid',
                                    'token', 'role', 'birth', 'extra', 'failed_result',
                                    'fewer_cases', 'foreign_archive'])
def test_refused_or_forged_returns_never_become_package_proof(returned, mutation):
    owner, value, primary, request, descriptor = returned
    if mutation == 'poison':
        owner.poisoned = True
    elif mutation == 'duplicate':
        value.package_proof = {'old': True}
    elif mutation == 'function':
        request['function'] = 'foreign'
    elif mutation == 'source':
        request['source_sha256'] = 'f' * 64
    elif mutation == 'foreign_pid':
        request['pid'] += 1
    elif mutation == 'token':
        request['token'] = 'foreign'
    elif mutation == 'role':
        primary.contexts[os.getpid()]['role'] = 'query'
    elif mutation == 'birth':
        primary.contexts[os.getpid()]['identity'] = {'foreign': 1}
    elif mutation == 'extra':
        request['untrusted'] = True
    elif mutation == 'failed_result':
        request['result'] = None
    elif mutation == 'fewer_cases':
        request['result']['restart_oracle']['cases'] = 14
    else:
        body = json.loads(descriptor.read_bytes())
        body['members']['unrest_harness-0.4.6.tar.gz']['sha256'] = 'f' * 64
        descriptor.write_text(json.dumps(body))
    with pytest.raises((RuntimeError, KeyError)):
        owner.handle(request, [])
    assert not primary.records
