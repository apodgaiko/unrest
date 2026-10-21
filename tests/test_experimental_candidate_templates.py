"""Legacy empty Git template directories carry no candidate input or authority."""
from pathlib import Path
import subprocess

import pytest

from unrest_harness.experimental_candidate import CandidateInputError, _Observation


def metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, _Observation]:
    root = tmp_path.resolve() / 'repository'
    git = root / '.git'
    git.mkdir(parents=True)
    (git / 'HEAD').write_text('ref: refs/heads/main\n')
    (git / 'index').write_bytes(b'')
    (git / 'config').write_text('[core]\nrepositoryformatversion=0\nbare=false\n')
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail('metadata validation must not launch Git')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    return git, _Observation(root)


def test_empty_legacy_branches_template_is_inert(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    git, observation = metadata(tmp_path, monkeypatch)
    observation.metadata()
    before = {p.relative_to(git).as_posix(): p.read_bytes() for p in git.iterdir()}
    (git / 'branches').mkdir()
    _Observation(observation.root).metadata()
    assert list((git / 'branches').iterdir()) == []
    assert {p.relative_to(git).as_posix(): p.read_bytes() for p in git.iterdir() if p.is_file()} == before


@pytest.mark.parametrize('kind', ['file', 'nested-directory', 'symlink', 'symlink-child', 'case-alias', 'unknown'])
def test_legacy_directory_admission_does_not_admit_metadata_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    git, observation = metadata(tmp_path, monkeypatch)
    branches = git / 'branches'
    code = 'unsupported_git_metadata'
    if kind == 'symlink':
        target = observation.root / 'outside'
        target.mkdir()
        branches.symlink_to(target, target_is_directory=True)
        code = 'file_kind'
    else:
        branches.mkdir()
        if kind == 'file':
            (branches / 'master').write_text('https://example.invalid/repository\n')
        elif kind == 'nested-directory':
            (branches / 'nested').mkdir()
        elif kind == 'symlink-child':
            (branches / 'master').symlink_to(git / 'HEAD')
            code = 'file_kind'
        elif kind == 'case-alias':
            branches.rename(git / 'Branches')
        else:
            branches.rename(git / 'unknown-template')
    with pytest.raises(CandidateInputError, match=code):
        observation.metadata()
