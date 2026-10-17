"""Package path safety plus explicitly opted-in actual no-launch readiness."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import shutil

import pytest

from unrest_harness.experimental_lease import LeaseRefused, PilotLedger, REAL_PROVIDER
from unrest_harness.experimental_provider import check_package
import unrest_harness.experimental_provider as provider


@pytest.fixture
def package(tmp_path, monkeypatch):
    root = tmp_path / 'package'
    (root / 'bin').mkdir(parents=True)
    (root / 'resources').mkdir()
    contents = {'bin/codex': b'fixed executable', 'resources/helper': b'fixed helper'}
    members = {}
    for name, data in contents.items():
        path = root / name
        path.write_bytes(data)
        path.chmod(0o755)
        members[name] = (hashlib.sha256(data).hexdigest(), len(data), 0o755)
    monkeypatch.setattr(provider, '_MEMBERS', members)
    return root


def test_complete_package_explicit_location(package):
    assert check_package(package) == package / 'bin/codex'
    with pytest.raises(LeaseRefused, match='required'):
        check_package(None)
    with pytest.raises(LeaseRefused, match='location_invalid'):
        check_package(Path('relative'))


@pytest.mark.parametrize('change', ['binary', 'helper', 'extra', 'extra-directory', 'missing',
                                    'symlink', 'directory-link', 'ancestor-link', 'hardlink',
                                    'fifo', 'mode'])
def test_package_rejects_changed_or_unsafe_members(package, tmp_path, change):
    member = package / 'resources/helper'
    if change in ('binary', 'helper'):
        target = package / 'bin/codex' if change == 'binary' else member
        data = target.read_bytes()
        target.write_bytes(b'x' + data[1:])
    elif change == 'extra':
        (package / 'bin/extra').write_bytes(b'not approved')
        (package / 'bin/extra').chmod(0o755)
    elif change == 'extra-directory':
        (package / 'extra').mkdir()
    elif change == 'missing':
        member.unlink()
    elif change == 'symlink':
        member.unlink()
        member.symlink_to('/not-to-be-followed')
    elif change == 'directory-link':
        shutil.rmtree(package / 'resources')
        (package / 'resources').symlink_to(tmp_path, target_is_directory=True)
    elif change == 'ancestor-link':
        (tmp_path / 'alias').symlink_to(package, target_is_directory=True)
        package = tmp_path / 'alias'
    elif change == 'hardlink':
        os.link(member, tmp_path / 'external')
    elif change == 'fifo':
        member.unlink()
        os.mkfifo(member)
    else:
        member.chmod(0o644)
    with pytest.raises(LeaseRefused, match='provider_package'):
        check_package(package)


def test_stale_campaign_rejected_before_journal(tmp_path):
    journal = tmp_path / 'campaign'
    with pytest.raises(LeaseRefused, match='unsupported_provider'):
        PilotLedger(journal, provider='codex-0.160.0/acp-1.1.0/gpt-6-astra/medium')
    assert not journal.exists()


@pytest.fixture
def official_package():
    value = os.environ.get('UNREST_TEST_PROVIDER_PACKAGE')
    if value is None:
        pytest.skip('explicit official package path required; no provider is launched')
    return Path(value)


async def test_actual_real_constructor_and_pre_root_negatives(tmp_path, official_package):
    # No substitution of manifests, constructors, controls or pin functions.
    import json
    import sys
    import unrest_harness
    from unrest_harness.capability_policy import SAFE_PROFILE, load_capability_policy, resolve_role_capability
    from unrest_harness.experimental_session import LeaseLane, _SessionOwner
    from unrest_harness.providers import PROVIDERS
    launches = []
    auditing = True
    def audit(event, args):
        if auditing and event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork', 'os.exec'):
            launches.append(event)
            raise RuntimeError('no_launch_check')
    sys.addaudithook(audit)
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'a').write_bytes(b'base\n')
    policy = resolve_role_capability(PROVIDERS['codex'], role='worker',
        policy=load_capability_policy(Path(unrest_harness.__file__).parent / 'bundled'),
        profile=SAFE_PROFILE, workspace=candidate, project_record=tmp_path)
    expected = hashlib.sha256(json.dumps([
        ('a', hashlib.sha256(b'base\n').hexdigest())], separators=(',', ':')).encode()).hexdigest()
    adapter = Path(shutil.which('codex-acp') or '/missing').resolve()
    ledger = PilotLedger(tmp_path / 'readiness-ledger', provider=REAL_PROVIDER)
    ledger.admit('P1')
    def construct(name, package, campaign=ledger):
        return LeaseLane(tmp_path / name, candidate, ('a',), expected_candidate=expected,
            lane=name, adapter=adapter, policy=policy, ledger=campaign,
            trusted_process=True, fixture=None, provider_package=package)
    try:
        lane = construct('ready', official_package)
        assert lane.fixture is None and lane.backend == official_package / 'bin/codex'
        assert lane.owner is None and lane.owners == []
        await lane.close()
        assert lane.phase == 'closed'
        with pytest.raises(LeaseRefused, match='required'):
            construct('missing-package', None)
        assert not (tmp_path / 'missing-package').exists()
        with closing(PilotLedger(tmp_path / 'wrong-campaign')) as wrong:
            wrong.admit('P1')
            with pytest.raises(LeaseRefused, match='campaign_provider_mismatch'):
                construct('wrong-campaign-lane', official_package, wrong)
        assert not (tmp_path / 'wrong-campaign-lane').exists()
        for name, member in [('wrong-binary', 'bin/codex'),
                             ('changed-adjacent', 'bin/codex-code-mode-host')]:
            package = tmp_path / name
            shutil.copytree(official_package, package)
            owner = _SessionOwner(tmp_path / (name + '-prechecked-owner'), candidate, ('a',),
                adapter=adapter, fixture=package / 'bin/codex', policy=policy,
                controlled=False, ledger=ledger, provider_package=package)
            with (package / member).open('r+b') as stream:
                first = stream.read(1)
                stream.seek(0)
                stream.write(bytes([first[0] ^ 1]))
            with pytest.raises(LeaseRefused, match='member_mismatch'):
                construct(name + '-lane', package)
            assert not (tmp_path / (name + '-lane')).exists()
            # The generation owner independently refuses before creating its root.
            with pytest.raises(LeaseRefused, match='member_mismatch'):
                _SessionOwner(tmp_path / (name + '-owner'), candidate, ('a',),
                    adapter=adapter, fixture=package / 'bin/codex', policy=policy,
                    controlled=False, ledger=ledger, provider_package=package)
            assert not (tmp_path / (name + '-owner')).exists()
            try:
                with pytest.raises(LeaseRefused, match='member_mismatch'):
                    await owner._open_role('worker')
                assert not owner.roles and not owner.backends and not owner._claims
            finally:
                await owner.close()
            shutil.rmtree(package)
        assert not launches and not ledger._leases and not ledger._turns
        assert ledger._counts == {'P1': 0}
    finally:
        auditing = False
        ledger.close()
