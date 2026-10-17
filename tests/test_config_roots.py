"""Trusted root selection must not bless redirects during later dispatch."""
from dataclasses import fields, replace
from pathlib import Path

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.storage import ProjectStore
from unrest_harness import supervision as s
from tests.test_supervision import STEERING_TARGETS, _config, _prepare_role_checkpoint


@pytest.mark.parametrize("spelling", ["alias", "relative", "home"])
def test_direct_and_discovered_roots_agree(tmp_path, monkeypatch, spelling):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    base = {"alias": alias, "relative": Path("alias"), "home": Path("~/alias")}[spelling]
    direct = _config(base)
    monkeypatch.setenv("UNREST_HOME", str(base))
    monkeypatch.setenv("UNREST_PROJECTS_DIR", str(base / "projects"))
    discovered = HarnessConfig.discover()
    assert direct.harness_home == discovered.harness_home == real
    assert direct.projects_dir == discovered.projects_dir == real / "projects"


@pytest.mark.parametrize("changed", ["harness_home", "projects_dir", "both"])
@pytest.mark.parametrize("spelling", ["alias", "relative", "home"])
def test_explicit_replacement_normalizes_only_selected_roots(tmp_path, monkeypatch, changed, spelling):
    config = _config(tmp_path / "original")
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    base = {"alias": alias, "relative": Path("alias"), "home": Path("~/alias")}[spelling]
    changes = {}
    if changed in {"harness_home", "both"}:
        changes["harness_home"] = base / "home"
    if changed in {"projects_dir", "both"}:
        changes["projects_dir"] = base / "projects"
    result = replace(config, **changes)
    assert result.harness_home == (real / "home" if "harness_home" in changes else config.harness_home)
    assert result.projects_dir == (real / "projects" if "projects_dir" in changes else config.projects_dir)
    assert result.capability_policy is config.capability_policy


@pytest.mark.parametrize("root_name", ["harness_home", "projects_dir"])
@pytest.mark.parametrize("change", ["validator", "terminal_reviewer", "provider", "other_root"])
def test_established_roots_survive_later_redirect(tmp_path, root_name, change):
    config = replace(_config(tmp_path / "home"), projects_dir=tmp_path / "projects")
    selected = getattr(config, root_name)
    selected.mkdir()
    outside = tmp_path / "outside"
    selected.rename(outside)
    selected.symlink_to(outside, target_is_directory=True)
    before = outside.stat()
    if change in {"validator", "terminal_reviewer"}:
        result = config.for_role(change)
    elif change == "provider":
        result = replace(config, worker_provider_name="codex")
    else:
        other = "projects_dir" if root_name == "harness_home" else "harness_home"
        result = replace(config, **{other: tmp_path / "new-root"})
    assert getattr(result, root_name) == selected
    assert result.capability_policy is config.capability_policy
    assert outside.stat() == before
    assert list(outside.iterdir()) == []


def _inventory(root):
    return {str(p.relative_to(root)): (p.lstat().st_mode, p.read_bytes() if p.is_file() else None)
            for p in [root, *sorted(root.rglob("*"))]}


@pytest.mark.parametrize("change", ["validator", "terminal_reviewer", "provider", "other_root"])
@pytest.mark.parametrize("ancestor", [False, True])
def test_redirected_established_projects_refused_by_runtime(tmp_path, change, ancestor):
    store, _, snapshot, _ = _prepare_role_checkpoint(tmp_path, "validator")
    config = store.config
    selected = config.projects_dir.parent if ancestor else config.projects_dir
    outside = tmp_path / "outside"
    selected.rename(outside)
    selected.symlink_to(outside, target_is_directory=True)
    before = _inventory(outside)
    if change in {"validator", "terminal_reviewer"}:
        result = config.for_role(change)
    elif change == "provider":
        result = replace(config, worker_provider_name="codex")
    else:
        result = replace(config, harness_home=tmp_path / "new-home")
    assert result.projects_dir == config.projects_dir
    redirected_store = ProjectStore(result)
    with pytest.raises(s.SupervisionSnapshotError, match="unsafe snapshot directory"):
        s.save_snapshot(redirected_store, snapshot, assigned_target_ids=STEERING_TARGETS)
    assert _inventory(outside) == before
    assert not (tmp_path / "new-home").exists()


def test_root_provenance_is_private_nonsemantic_metadata(tmp_path):
    config = _config(tmp_path / "home")
    field = next(f for f in fields(config) if f.name == "_established_roots")
    assert field.init and not field.repr and not field.compare
    assert "_established_roots" not in repr(config)
    assert replace(config) == config
