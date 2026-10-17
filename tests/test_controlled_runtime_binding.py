"""Trusted runtime binding controls; simulated platforms do not prove remote CI."""
from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import sys

import pytest

from unrest_harness import experimental_session as session

FIXTURE = Path(__file__).parent / 'fixtures/controlled_python_acp.py'


def selection():
    return session.ControlledTransport(FIXTURE, Path(sys.executable))


def test_current_host_binding_and_fixed_command():
    transport = selection()
    binding = transport._runtime
    assert binding.path == Path(sys.executable)
    assert binding.realpath == Path(sys.executable).resolve()
    assert binding.sha256 == hashlib.sha256(binding.realpath.read_bytes()).hexdigest()
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == session.CONTROLLED_ACP_SHA256
    assert transport.argv() == (str(binding.realpath), str(FIXTURE.resolve()),
                                '--controlled-local-acp-v1')
    with pytest.raises(FrozenInstanceError):
        binding.sha256 = '0' * 64
    with pytest.raises(TypeError):
        session.ControlledTransport(FIXTURE, binding.path, expected_digest=binding.sha256)


@pytest.mark.parametrize('platform', ['linux', 'darwin'])
@pytest.mark.parametrize('version', [(3, 13, 0), (3, 13, 12), (3, 14, 0)])
def test_platform_selection_controls_use_actual_host_bytes(monkeypatch, platform, version):
    transport = selection()
    # Only the selection branch is simulated. This is still the local executable,
    # not evidence of a Linux child, remote runner or Python version execution.
    monkeypatch.setattr(sys, 'platform', platform)
    monkeypatch.setattr(sys, 'version_info', version)
    transport.verify(controlled=True, package=None)
    assert transport._runtime is session._TRUSTED_TEST_RUNTIME


@pytest.mark.parametrize('attack', ['copy', 'alias', 'wrong', 'forged-binding',
                                  'runtime-path-drift', 'realpath-drift', 'byte-drift',
                                  'old-python', 'non-cpython'])
def test_runtime_identity_refuses_without_child(monkeypatch, tmp_path, attack):
    transport = selection()
    binding = transport._runtime
    if attack in ('copy', 'alias', 'wrong'):
        other = tmp_path / 'python3.13'
        if attack == 'alias':
            other.symlink_to(binding.realpath)
        else:
            other.write_bytes(binding.realpath.read_bytes() if attack == 'copy' else b'not python')
        transport = session.ControlledTransport(FIXTURE, other)
    elif attack == 'forged-binding':
        object.__setattr__(transport, '_runtime', replace(binding))
    elif attack == 'runtime-path-drift':
        monkeypatch.setattr(sys, 'executable', str(tmp_path / 'python3.13'))
    elif attack == 'realpath-drift':
        resolve = Path.resolve
        monkeypatch.setattr(Path, 'resolve', lambda p, **kw:
            tmp_path / 'redirect' if p == binding.path else resolve(p, **kw))
    elif attack == 'byte-drift':
        read = Path.read_bytes
        monkeypatch.setattr(Path, 'read_bytes', lambda p:
            b'changed executable' if p == binding.realpath else read(p))
    elif attack == 'old-python':
        monkeypatch.setattr(sys, 'version_info', (3, 12, 99))
    else:
        monkeypatch.setattr(sys.implementation, 'name', 'pypy')
    with pytest.raises(session.LeaseRefused):
        transport.argv()


@pytest.mark.parametrize('stage', ['backend', 'adapter'])
async def test_runtime_rechecked_at_each_child_boundary(tmp_path, monkeypatch, stage):
    from tests.test_controlled_python_acp import local_session, transport as transport_fixture
    selected = transport_fixture.__wrapped__()
    owner = local_session.__wrapped__(tmp_path, selected)
    environment = owner._environment
    calls = []
    async def no_launch(*args, **kwargs):
        calls.append(args)
        raise RuntimeError('test child boundary')
    def drift_after_environment(home):
        result = environment(home)
        monkeypatch.setattr(sys, 'executable', str(tmp_path / 'redirected-python'))
        return result
    if stage == 'backend':
        monkeypatch.setattr(session.asyncio, 'create_subprocess_exec', no_launch)
        monkeypatch.setattr(owner, '_environment', drift_after_environment)
        with pytest.raises(session.LeaseRefused):
            await owner._open_role_owned('worker', session.StartupDiagnostics())
        assert calls == []
        assert not owner.roles and not owner.backends
        assert owner.last_completion is None
    else:
        start_bridge = session.Bridge.start
        async def drift_after_backend(bridge):
            result = await start_bridge(bridge)
            monkeypatch.setattr(sys, 'executable', str(tmp_path / 'redirected-python'))
            return result
        # Permit the fixed backend; adapter selection must fail after its actual
        # registration and bridge start, before the second child is attempted.
        monkeypatch.setattr(session.Bridge, 'start', drift_after_backend)
        await owner.start()
        try:
            with pytest.raises(session.LeaseRefused):
                await owner.turn('worker')
            assert not owner.roles
            assert len(owner.backends) == 1
            assert owner.last_completion is None
        finally:
            with pytest.raises(session.LeaseRefused, match='synthetic_session_quarantined'):
                await owner.close()
        assert all(b.process.returncode is not None for b in owner.backends.values())
    owner.ledger.close()
    owner.broker.close()


def test_controlled_constructor_does_not_require_native_installation(tmp_path):
    from tests.test_controlled_python_acp import local_session, transport as transport_fixture
    selected = transport_fixture.__wrapped__()
    original = local_session.__wrapped__(tmp_path, selected)
    owner = session.SyntheticSession(tmp_path / 'portable-owner', original.broker._root, ('a',),
        adapter=Path('/missing-native'),
        fixture=Path(__file__).parent / 'fixtures/experimental_session_app_server.py',
        policy=original.policy, transport=selected)
    assert owner.transport is selected
    assert not owner.roles and not owner.backends
    owner.ledger.close()
    owner.broker.close()
    original.ledger.close()
    original.broker.close()
