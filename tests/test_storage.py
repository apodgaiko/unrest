"""Storage layer tests. See specs/memory_v2/PRODUCT.md for layout."""
from __future__ import annotations

import json
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from unrest_harness.capability_policy import credential_source_values
from unrest_harness.config import HarnessConfig
from unrest_harness.models import (
    AttentionItemInternal,
    Decision,
    ProjectRecord,
    Task,
    TaskList,
    TaskStateFile,
    TerminalReviewConfig,
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
)
from unrest_harness.storage import (
    AttemptValidationError,
    ProjectStore,
    atomic_write_text,
    slugify,
    utc_now_filesafe,
)


class TestAtomicWriteText:
    def test_explicit_mode_replaces_existing_mode_atomically(self, tmp_path: Path) -> None:
        target = tmp_path / "managed.txt"
        target.write_text("corrupt\n")
        target.chmod(0o600)

        atomic_write_text(
            target,
            "authoritative\n",
            trusted_root=tmp_path,
            mode=0o644,
            _redact=False,
        )

        assert target.read_bytes() == b"authoritative\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o644

    @staticmethod
    def _fresh_process_bytes(target: Path) -> bytes:
        return subprocess.check_output(
            [
                sys.executable,
                "-c",
                (
                    "import pathlib,sys; "
                    "sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())"
                ),
                str(target),
            ]
        )

    def test_fresh_target_has_intended_mode(self, tmp_path: Path) -> None:
        target = tmp_path / "fresh.json"
        atomic_write_text(target, "fresh\n", trusted_root=tmp_path, _redact=False)
        assert target.read_bytes() == b"fresh\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o644

    def test_preserves_mode_and_deterministic_bytes(self, tmp_path: Path) -> None:
        target = tmp_path / "state.json"
        target.write_bytes(b"old\n")
        target.chmod(0o600)

        atomic_write_text(target, "new ☃\n", trusted_root=tmp_path, _redact=False)
        first = target.read_bytes()
        atomic_write_text(target, "new ☃\n", trusted_root=tmp_path, _redact=False)

        assert target.read_bytes() == first == "new ☃\n".encode()
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert sorted(path.name for path in tmp_path.iterdir()) == ["state.json"]

    @pytest.mark.parametrize("stage", ("write", "content_fsync", "replace"))
    def test_failure_preserves_target_and_cleans_unique_temp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
    ) -> None:
        import unrest_harness.storage as storage

        target = tmp_path / "state.json"
        target.write_bytes(b"accepted generation\n")
        target.chmod(0o600)
        before = target.read_bytes()

        if stage == "write":
            real_fdopen = storage.os.fdopen

            class RejectingStream:
                def __init__(self, stream):
                    self.stream = stream

                def __enter__(self):
                    self.stream.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.stream.__exit__(*args)

                def write(self, value: str) -> int:
                    raise OSError("injected write failure")

                def flush(self) -> None:
                    self.stream.flush()

                def fileno(self) -> int:
                    return self.stream.fileno()

            monkeypatch.setattr(
                storage.os,
                "fdopen",
                lambda *args, **kwargs: RejectingStream(real_fdopen(*args, **kwargs)),
            )
        elif stage == "content_fsync":
            monkeypatch.setattr(
                storage.os,
                "fsync",
                lambda _fd: (_ for _ in ()).throw(
                    OSError("injected content_fsync failure")
                ),
            )
        else:
            monkeypatch.setattr(
                storage.os,
                "replace",
                lambda _src, _dst: (_ for _ in ()).throw(
                    OSError("injected replace failure")
                ),
            )

        with pytest.raises(OSError, match=f"injected {stage} failure"):
            atomic_write_text(
                target,
                "rejected generation\n",
                trusted_root=tmp_path,
                _redact=False,
            )

        assert target.read_bytes() == before
        assert self._fresh_process_bytes(target) == before
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert sorted(path.name for path in tmp_path.iterdir()) == ["state.json"]

    def test_directory_fsync_failure_accepts_visible_generation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import unrest_harness.storage as storage

        target = tmp_path / "state.json"
        target.write_bytes(b'{"generation":1}\n')
        target.chmod(0o600)
        calls = 0

        def fail_directory_fsync(_path: Path) -> None:
            nonlocal calls
            calls += 1
            raise OSError("injected directory fsync failure")

        monkeypatch.setattr(storage, "_fsync_directory", fail_directory_fsync)

        for _ in range(2):
            assert atomic_write_text(
                target,
                '{"generation":2}\n',
                trusted_root=tmp_path,
                _redact=False,
            ) is None
            assert target.read_bytes() == b'{"generation":2}\n'
            assert self._fresh_process_bytes(target) == b'{"generation":2}\n'
            assert stat.S_IMODE(target.stat().st_mode) == 0o600
            assert sorted(path.name for path in tmp_path.iterdir()) == ["state.json"]
        assert calls == 2

    def test_rejects_symlink_and_nonregular_targets(self, tmp_path: Path) -> None:
        actual = tmp_path / "actual"
        actual.write_text("unchanged")
        link = tmp_path / "link"
        link.symlink_to(actual)
        directory = tmp_path / "directory"
        directory.mkdir()

        for target in (link, directory):
            with pytest.raises(OSError, match="regular file"):
                atomic_write_text(
                    target, "rejected", trusted_root=tmp_path, _redact=False
                )
        assert actual.read_text() == "unchanged"
        assert not any(path.name.endswith(".tmp") for path in tmp_path.iterdir())

        parent_link = tmp_path / "parent-link"
        parent_link.symlink_to(directory, target_is_directory=True)
        with pytest.raises(OSError, match="path component"):
            atomic_write_text(
                parent_link / "escaped",
                "rejected",
                trusted_root=tmp_path,
                _redact=False,
            )
        assert not (directory / "escaped").exists()

    @pytest.mark.parametrize(
        ("prefix", "suffix"),
        (
            ((), ("nested", "deeper")),
            (("level-1",), ("nested",)),
            (("level-1", "level-2"), ()),
        ),
        ids=("top-level-ancestor", "intermediate-ancestor", "immediate-parent"),
    )
    @pytest.mark.parametrize("existing_target", (False, True), ids=("fresh", "existing"))
    def test_rejects_symlink_at_every_parent_depth_before_writing(
        self,
        tmp_path: Path,
        prefix: tuple[str, ...],
        suffix: tuple[str, ...],
        existing_target: bool,
    ) -> None:
        trusted = tmp_path / "trusted"
        trusted.mkdir()
        outside = tmp_path / "outside"
        referent_parent = outside.joinpath(*suffix)
        referent_parent.mkdir(parents=True)
        referent = referent_parent / "state.json"
        if existing_target:
            referent.write_bytes(b"accepted generation\n")
            referent.chmod(0o600)

        link_parent = trusted.joinpath(*prefix)
        link_parent.mkdir(parents=True, exist_ok=True)
        alias = link_parent / "alias"
        alias.symlink_to(outside, target_is_directory=True)
        target = alias.joinpath(*suffix, "state.json")
        before_inventory = sorted(
            path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")
        )
        before_bytes = referent.read_bytes() if referent.exists() else None

        with pytest.raises(OSError, match="path component"):
            atomic_write_text(
                target,
                "rejected generation\n",
                trusted_root=trusted,
                _redact=False,
            )

        assert (referent.read_bytes() if referent.exists() else None) == before_bytes
        assert sorted(
            path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")
        ) == before_inventory
        assert not any(path.name.endswith(".tmp") for path in tmp_path.rglob("*"))

    def test_rejects_symlinked_trusted_root(self, tmp_path: Path) -> None:
        actual = tmp_path / "actual"
        actual.mkdir()
        trusted = tmp_path / "trusted"
        trusted.symlink_to(actual, target_is_directory=True)

        with pytest.raises(OSError, match="trusted root must be a regular directory"):
            atomic_write_text(
                trusted / "state.json",
                "rejected\n",
                trusted_root=trusted,
                _redact=False,
            )
        assert list(actual.iterdir()) == []

    def test_absent_trusted_root_requires_explicit_existing_allowed_ancestor(
        self, tmp_path: Path
    ) -> None:
        trusted = tmp_path / "managed" / "nested"
        target = trusted / "deeper" / "state.json"

        with pytest.raises(OSError, match="trusted root does not exist"):
            atomic_write_text(
                target,
                "rejected\n",
                trusted_root=trusted,
                _redact=False,
            )
        assert not (tmp_path / "managed").exists()

        atomic_write_text(
            target,
            "accepted\n",
            trusted_root=trusted,
            allowed_ancestor=tmp_path,
            _redact=False,
        )
        assert target.read_bytes() == b"accepted\n"

    def test_atomic_containment_matrix_preserves_inside_and_outside_hashes(
        self, tmp_path: Path
    ) -> None:
        import hashlib

        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"outside-generation\n")
        outside_hash = hashlib.sha256(outside.read_bytes()).hexdigest()
        target = allowed / "missing" / "parents" / "state.json"

        atomic_write_text(
            target,
            "inside-generation\n",
            trusted_root=allowed / "missing",
            allowed_ancestor=allowed,
            _redact=False,
        )
        inside_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        assert inside_hash == hashlib.sha256(b"inside-generation\n").hexdigest()

        escape = allowed / "escape"
        escape.symlink_to(tmp_path, target_is_directory=True)
        rejected = (
            (allowed / ".." / "outside.txt", "beneath its trusted root"),
            (escape / "outside.txt", "path component"),
        )
        for candidate, message in rejected:
            with pytest.raises(OSError, match=message):
                atomic_write_text(
                    candidate,
                    "escaped-generation\n",
                    trusted_root=allowed,
                    allowed_ancestor=allowed,
                    _redact=False,
                )

        symlink_root = tmp_path / "root-link"
        symlink_root.symlink_to(allowed, target_is_directory=True)
        with pytest.raises(OSError, match="trusted-root component"):
            atomic_write_text(
                symlink_root / "state.json",
                "escaped-generation\n",
                trusted_root=symlink_root,
                allowed_ancestor=tmp_path,
                _redact=False,
            )

        assert hashlib.sha256(target.read_bytes()).hexdigest() == inside_hash
        assert hashlib.sha256(outside.read_bytes()).hexdigest() == outside_hash

    @pytest.mark.parametrize("control", ("outside", "missing", "symlink", "file"))
    def test_allowed_ancestor_is_a_validated_creation_boundary(
        self, tmp_path: Path, control: str
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        ancestor = tmp_path / "boundary"
        trusted = ancestor / "managed"
        if control == "outside":
            ancestor.mkdir()
            trusted = outside / "managed"
            match = "beneath its allowed ancestor"
        elif control == "missing":
            match = "allowed ancestor does not exist"
        elif control == "symlink":
            ancestor.symlink_to(outside, target_is_directory=True)
            match = "allowed ancestor must be a regular directory"
        else:
            ancestor.write_text("not a directory", encoding="utf-8")
            match = "allowed ancestor must be a regular directory"

        with pytest.raises(OSError, match=match):
            atomic_write_text(
                trusted / "state.json",
                "rejected\n",
                trusted_root=trusted,
                allowed_ancestor=ancestor,
                _redact=False,
            )
        assert list(outside.iterdir()) == []

    @pytest.mark.parametrize("control", ("trusted-root", "intermediate"))
    def test_allowed_ancestor_never_traverses_existing_symlink_components(
        self, tmp_path: Path, control: str
    ) -> None:
        boundary = tmp_path / "boundary"
        boundary.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        trusted = boundary / "managed"
        if control == "trusted-root":
            trusted.symlink_to(outside, target_is_directory=True)
            target = trusted / "state.json"
            match = "trusted-root component"
        else:
            trusted.mkdir()
            (trusted / "nested").symlink_to(outside, target_is_directory=True)
            target = trusted / "nested" / "state.json"
            match = "path component"

        with pytest.raises(OSError, match=match):
            atomic_write_text(
                target,
                "rejected\n",
                trusted_root=trusted,
                allowed_ancestor=boundary,
                _redact=False,
            )
        assert list(outside.iterdir()) == []

    def test_rejects_non_directory_ancestor_and_out_of_root_target(
        self, tmp_path: Path
    ) -> None:
        trusted = tmp_path / "trusted"
        trusted.mkdir()
        blocking_component = trusted / "blocked"
        blocking_component.write_text("not a directory")

        with pytest.raises(OSError, match="path component"):
            atomic_write_text(
                blocking_component / "nested" / "state.json",
                "rejected\n",
                trusted_root=trusted,
                _redact=False,
            )
        with pytest.raises(OSError, match="beneath its trusted root"):
            atomic_write_text(
                tmp_path / "outside.json",
                "rejected\n",
                trusted_root=trusted,
                _redact=False,
            )

        assert blocking_component.read_text() == "not a directory"
        assert not (tmp_path / "outside.json").exists()
        assert not any(path.name.endswith(".tmp") for path in tmp_path.rglob("*"))

    @pytest.mark.parametrize("relative", (False, True), ids=("absolute", "relative"))
    @pytest.mark.parametrize("depth", (0, 1, 3))
    @pytest.mark.parametrize("existing_target", (False, True), ids=("fresh", "existing"))
    def test_regular_nested_destinations_remain_atomic(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        relative: bool,
        depth: int,
        existing_target: bool,
    ) -> None:
        trusted = tmp_path / "trusted"
        trusted.mkdir()
        target = trusted.joinpath(*(f"level-{index}" for index in range(depth))) / "state.json"
        if existing_target:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"accepted generation\n")
            target.chmod(0o600)
        if relative:
            monkeypatch.chdir(tmp_path)
            trusted = Path("trusted")
            target = target.relative_to(tmp_path)

        atomic_write_text(
            target,
            "replacement generation\n",
            trusted_root=trusted,
            _redact=False,
        )

        assert target.read_bytes() == b"replacement generation\n"
        assert stat.S_IMODE(target.stat().st_mode) == (0o600 if existing_target else 0o644)
        assert self._fresh_process_bytes(target) == b"replacement generation\n"
        assert not any(path.name.endswith(".tmp") for path in trusted.rglob("*"))


@pytest.fixture
def config(harness_home: Path) -> HarnessConfig:
    bundled = Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled"
    return HarnessConfig(
        bundled_dir=bundled,
        harness_home=harness_home,
        projects_dir=harness_home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
    )


@pytest.fixture
def store(config: HarnessConfig) -> ProjectStore:
    return ProjectStore(config)


class TestProjectLifecycle:
    def test_create_lays_out_bucket(
        self, store: ProjectStore, workspace: Path, harness_home: Path
    ) -> None:
        record = store.create_project("Build a thing.", workspace, project_id="p1")
        assert record.id == "p1"
        bucket_root = harness_home / "projects" / "p1"
        unrest = bucket_root / ".unrest"
        runtime = bucket_root / ".unrest-runtime"
        # Durable
        assert (unrest / "brief.md").read_text().startswith("Build a thing.")
        assert (unrest / "AGENTS.md").exists()
        assert (unrest / "MEMORY.md").read_text().startswith("# Project memory")
        assert (unrest / "decisions").is_dir()
        assert (unrest / "skills").is_dir()
        assert (unrest / "missions").is_dir()
        # Runtime
        assert (runtime / "project.json").exists()
        assert (runtime / "missions").is_dir()
        # Workspace stays clean of .unrest/
        assert not (workspace / ".unrest").exists()

    def test_project_worker_overrides_round_trip_and_legacy_defaults(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        record = store.create_project(
            "Build a thing.",
            workspace,
            project_id="p1",
            worker_model="gpt-test",
            worker_reasoning_effort="high",
        )
        assert record.worker_model == "gpt-test"
        assert record.worker_reasoning_effort == "high"
        assert store.load_project("p1") == record

        legacy = ProjectRecord.model_validate(
            {
                "id": "legacy",
                "workspace_dir": str(workspace),
                "created_at": "2026-01-01T00:00:00Z",
            }
        )
        assert legacy.worker_model is None
        assert legacy.worker_reasoning_effort is None

    def test_workspace_gitignore_untouched(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        gitignore = workspace / ".gitignore"
        gitignore.write_text("node_modules/\n")
        original = gitignore.read_text()
        store.create_project("brief", workspace, project_id="p1")
        assert gitignore.read_text() == original

    def test_symlink_shims_created(
        self, store: ProjectStore, workspace: Path, harness_home: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        skills_target = (harness_home / "projects" / "p1" / ".unrest" / "skills").resolve()
        for host in (".agents", ".claude", ".codex"):
            link = workspace / host / "skills"
            assert link.is_symlink()
            assert link.resolve() == skills_target
        root_md = workspace / "AGENTS.md"
        assert root_md.is_symlink()
        assert root_md.resolve() == (
            harness_home / "projects" / "p1" / ".unrest" / "AGENTS.md"
        ).resolve()

    def test_existing_workspace_agents_md_is_preserved(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        agents_md = workspace / "AGENTS.md"
        agents_md.write_text("# User project guidance\n\nKeep this.\n")

        store.create_project("brief", workspace, project_id="p1")
        store.sync_workspace_skill_surfaces("p1")

        assert agents_md.is_file()
        assert not agents_md.is_symlink()
        assert agents_md.read_text() == "# User project guidance\n\nKeep this.\n"

    @pytest.mark.parametrize("host", [".agents", ".claude", ".codex"])
    def test_existing_host_skills_dir_is_merged(
        self, store: ProjectStore, workspace: Path, host: str
    ) -> None:
        skills_dir = workspace / host / "skills"
        skills_dir.mkdir(parents=True)
        (skills_dir / "project-skill" / "SKILL.md").parent.mkdir()
        (skills_dir / "project-skill" / "SKILL.md").write_text("# Project skill\n")

        store.create_project("brief", workspace, project_id="p1")
        bucket_skills = store.unrest_dir("p1") / "skills"

        assert skills_dir.is_dir()
        assert not skills_dir.is_symlink()
        assert (bucket_skills / "project-skill" / "SKILL.md").read_text() == (
            "# Project skill\n"
        )
        assert (skills_dir / "scrutiny-validator" / "SKILL.md").exists()

    def test_sync_workspace_skill_surfaces_updates_preserved_host_dir(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        skills_dir = workspace / ".codex" / "skills"
        skills_dir.mkdir(parents=True)
        (skills_dir / "project-skill" / "SKILL.md").parent.mkdir()
        (skills_dir / "project-skill" / "SKILL.md").write_text("# Project skill\n")

        store.create_project("brief", workspace, project_id="p1")
        bucket_skill = store.unrest_dir("p1") / "skills" / "new-worker" / "SKILL.md"
        bucket_skill.parent.mkdir(parents=True)
        bucket_skill.write_text("# New worker\n")

        assert skills_dir.is_dir()
        assert not skills_dir.is_symlink()
        assert not (skills_dir / "new-worker" / "SKILL.md").exists()

        store.sync_workspace_skill_surfaces("p1")

        assert skills_dir.is_dir()
        assert not skills_dir.is_symlink()
        assert (skills_dir / "new-worker" / "SKILL.md").read_text() == "# New worker\n"

    @pytest.mark.parametrize("host", [".agents", ".claude", ".codex"])
    def test_bootstrap_host_skills_dir_becomes_bucket_symlink(
        self, store: ProjectStore, workspace: Path, harness_home: Path, host: str
    ) -> None:
        skills_dir = workspace / host / "skills"
        bundled_skill = (
            store.config.bundled_dir / "skills" / "scrutiny-validator" / "SKILL.md"
        )
        seeded_skill = skills_dir / "scrutiny-validator" / "SKILL.md"
        seeded_skill.parent.mkdir(parents=True)
        seeded_skill.write_text(bundled_skill.read_text())

        store.create_project("brief", workspace, project_id="p1")

        assert skills_dir.is_symlink()
        assert skills_dir.resolve() == (
            harness_home / "projects" / "p1" / ".unrest" / "skills"
        ).resolve()
        assert (skills_dir / "scrutiny-validator" / "SKILL.md").exists()

    def test_init_is_idempotent(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        unrest = store.unrest_dir("p1")
        original_brief = (unrest / "brief.md").read_text()
        memory_path = unrest / "MEMORY.md"
        memory_path.write_text("custom memory\n")
        store.create_project("DIFFERENT brief", workspace, project_id="p1")
        assert (unrest / "brief.md").read_text() == original_brief
        assert memory_path.read_text() == "custom memory\n"

    def test_dangling_shim_retargeted(
        self, store: ProjectStore, workspace: Path, harness_home: Path, tmp_path: Path
    ) -> None:
        # Plant a dangling symlink at workspace/.claude/skills.
        (workspace / ".claude").mkdir()
        dangling = workspace / ".claude" / "skills"
        dangling.symlink_to(tmp_path / "does-not-exist")
        store.create_project("brief", workspace, project_id="p1")
        assert dangling.is_symlink() and dangling.exists()
        assert dangling.resolve() == (
            harness_home / "projects" / "p1" / ".unrest" / "skills"
        ).resolve()

    def test_load_project_roundtrip(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        loaded = store.load_project("p1")
        assert loaded.id == "p1"
        assert loaded.workspace_dir == str(workspace.resolve())

    def test_missing_workspace_rejected(
        self, store: ProjectStore, tmp_path: Path
    ) -> None:
        with pytest.raises(FileNotFoundError):
            store.create_project("brief", tmp_path / "ghost", project_id="p1")

    def test_list_projects(
        self, store: ProjectStore, workspace: Path, tmp_path: Path
    ) -> None:
        ws2 = tmp_path / "ws2"
        ws2.mkdir()
        store.create_project("a", workspace, project_id="a-pid")
        store.create_project("b", ws2, project_id="b-pid")
        ids = {p.id for p in store.list_projects()}
        assert ids == {"a-pid", "b-pid"}


class TestTaskListAndContract:
    def test_save_and_load_task_list(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        tl = TaskList(tasks=[
            Task(id="w1", type="work", body="b", targets=["VAL-001"], skill="s")
        ])
        store.save_task_list("p1", "mission-001", tl)
        back = store.load_task_list("p1", "mission-001")
        assert back == tl

    def test_list_contract_assertions(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        d = store.ensure_contract_dir("p1", "mission-001")
        (d / "VAL-001.md").write_text("body 1\n")
        (d / "VAL-002.md").write_text("body 2\n")
        (d / "README.md").write_text("overview\n")
        assert store.list_contract_assertions("p1", "mission-001") == [
            "VAL-001",
            "VAL-002",
        ]

    def test_load_contract_assertion(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        d = store.ensure_contract_dir("p1", "mission-001")
        (d / "VAL-001.md").write_text("Hello.\n")
        assert store.load_contract_assertion("p1", "mission-001", "VAL-001") == "Hello.\n"


class TestTaskState:
    def test_default_empty(self, store: ProjectStore, workspace: Path) -> None:
        store.create_project("brief", workspace, project_id="p1")
        ts = store.load_task_state("p1", "mission-001")
        assert ts.tasks == {}

    def test_roundtrip(self, store: ProjectStore, workspace: Path) -> None:
        store.create_project("brief", workspace, project_id="p1")
        ts = TaskStateFile()
        ts.set_status("w1", "running")
        ts.set_status("v1", "cleared")
        store.save_task_state("p1", "mission-001", ts)
        back = store.load_task_state("p1", "mission-001")
        assert back.status_of("w1") == "running"
        assert back.status_of("v1") == "cleared"


class TestAttempts:
    @pytest.mark.parametrize(
        ("mutation", "message"),
        (
            ({"attempt_id": None}, "attempt_id must not be null"),
            ({"attempt_id": "older"}, "attempt_id does not match"),
            ({"node_id": "w2"}, "node_id does not match"),
            ({"done": "not-a-boolean"}, "payload is malformed"),
        ),
        ids=("present-null", "stale-generation", "wrong-task", "malformed"),
    )
    def test_current_attempt_identity_rejections_preserve_bytes(
        self,
        store: ProjectStore,
        workspace: Path,
        mutation: dict[str, object],
        message: str,
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        generation = "2026-08-10T12-00-00Z"
        path = store.attempt_path("p1", "mission-001", generation, "w1")
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, object] = {
            "node_id": "w1",
            "attempt_id": generation,
            "done": True,
            "report": "current",
            "request_attention": False,
        }
        payload.update(mutation)
        path.write_text(json.dumps(payload), encoding="utf-8")
        before = path.read_bytes()

        with pytest.raises(AttemptValidationError, match=message):
            store.read_attempt("p1", "mission-001", generation, "w1")

        assert path.read_bytes() == before

    def test_replay_under_another_attempt_filename_preserves_both_files(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        old_generation = "2026-08-09T12-00-00Z"
        new_generation = "2026-08-10T12-00-00Z"
        old = store.save_attempt(
            "p1",
            "mission-001",
            old_generation,
            "w1",
            WorkHandoff(node_id="w1", done=True, report="old"),
        )
        replay = store.attempt_path(
            "p1", "mission-001", new_generation, "w1"
        )
        replay.write_bytes(old.read_bytes())
        before = {path: path.read_bytes() for path in (old, replay)}

        with pytest.raises(AttemptValidationError, match="generation"):
            store.read_attempt("p1", "mission-001", new_generation, "w1")

        assert {path: path.read_bytes() for path in (old, replay)} == before

    def test_explicit_inventory_redacts_json_and_markdown_mirrors(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        secret = "plum"
        inventory = credential_source_values(
            {"DECLARED_AUTH": secret},
            declared_names=("DECLARED_AUTH",),
        )
        handoff = WorkHandoff(node_id="w1", done=True, report=secret)
        ts = utc_now_filesafe()
        json_path = store.save_attempt(
            "p1",
            "mission-001",
            ts,
            "w1",
            handoff,
            inventory=inventory,
        )
        md_path = store.attempt_report_path("p1", "mission-001", ts, "w1")
        for path in (json_path, md_path):
            persisted = path.read_text(encoding="utf-8")
            assert secret not in persisted
            assert "<redacted:DECLARED_AUTH>" in persisted

    def test_roundtrip_work(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        h = WorkHandoff(node_id="w1", done=True, report="done", request_attention=False)
        ts = utc_now_filesafe()
        path = store.save_attempt("p1", "mission-001", ts, "w1", h)
        assert path.exists()
        back = store.read_attempt("p1", "mission-001", ts, "w1")
        assert isinstance(back, WorkHandoff)
        assert back == h.model_copy(update={"attempt_id": ts})
        # JSON handoff lives in the runtime cursor tree; MD mirror in durable .unrest.
        assert path.parent == store.attempts_runtime_dir("p1", "mission-001")
        assert ".unrest-runtime" in path.parts
        md_path = store.attempt_report_path("p1", "mission-001", ts, "w1")
        assert md_path.exists()
        assert md_path.parent == store.attempts_dir("p1", "mission-001")

    def test_roundtrip_validate(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        h = ValidateHandoff(
            node_id="v1",
            done=True,
            report="audited",
            items=[ValidationItem(item_id="VAL-001", passed=True)],
            passed=True,
        )
        ts = utc_now_filesafe()
        store.save_attempt("p1", "mission-001", ts, "v1", h)
        back = store.read_attempt("p1", "mission-001", ts, "v1")
        assert isinstance(back, ValidateHandoff)
        assert back.items[0].item_id == "VAL-001"

    def test_idempotent_overwrite(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        h = WorkHandoff(node_id="w1", done=True, report="v1")
        ts = utc_now_filesafe()
        store.save_attempt("p1", "mission-001", ts, "w1", h)
        h2 = WorkHandoff(node_id="w1", done=True, report="v2")
        store.save_attempt("p1", "mission-001", ts, "w1", h2)
        back = store.read_attempt("p1", "mission-001", ts, "w1")
        assert isinstance(back, WorkHandoff)
        assert back.report == "v2"

    def test_list_filters_by_node(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        for ts, nid in [("2026-01-01T00-00-00Z", "w1"), ("2026-01-02T00-00-00Z", "w2")]:
            store.save_attempt(
                "p1", "mission-001", ts, nid,
                WorkHandoff(node_id=nid, done=True, report=""),
            )
        records = store.list_attempts("p1", "mission-001", node_id="w1")
        assert len(records) == 1 and records[0].node_id == slugify("w1", "w1")


class TestAttention:
    def test_save_and_load(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        items = [
            AttentionItemInternal(
                id="att-1",
                kind="gate_checkpoint",
                mission_id="mission-001",
                report="Gate report from g1",
                node_id="g1",
            )
        ]
        store.save_attention("p1", items)
        back = store.load_attention("p1")
        assert back[0].id == "att-1"

    def test_clear(self, store: ProjectStore, workspace: Path) -> None:
        store.create_project("brief", workspace, project_id="p1")
        store.save_attention(
            "p1",
            [
                AttentionItemInternal(
                    id="x",
                    kind="gate_checkpoint",
                    mission_id="m1",
                    report="Gate report from g1",
                )
            ],
        )
        store.clear_attention("p1")
        assert store.load_attention("p1") == []


class TestDecisions:
    def test_appends_numbered_files(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        items = [
            AttentionItemInternal(
                id="att-1",
                kind="gate_checkpoint",
                mission_id="mission-001",
                report="Gate report from g1",
                node_id="g1",
            )
        ]
        decisions = [Decision(item_id="att-1", action="continue")]
        path1 = store.append_decision_record("p1", decisions, items, summary="first")
        path2 = store.append_decision_record("p1", decisions, items, summary="second")
        assert path1.stem.startswith("001-")
        assert path2.stem.startswith("002-")


class TestTerminalReviews:
    def test_explicit_inventory_redacts_json_and_markdown_mirrors(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        secret = "plum"
        inventory = credential_source_values(
            {"DECLARED_AUTH": secret},
            declared_names=("DECLARED_AUTH",),
        )
        review = TerminalReviewHandoff(done=True, report=secret)
        ts = utc_now_filesafe()
        md_path = store.save_terminal_review(
            "p1",
            "mission-001",
            ts,
            review,
            inventory=inventory,
        )
        json_path = store.terminal_review_path("p1", "mission-001", ts)
        for path in (json_path, md_path):
            persisted = path.read_text(encoding="utf-8")
            assert secret not in persisted
            assert "<redacted:DECLARED_AUTH>" in persisted

    def test_save_and_path(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        rep = TerminalReviewHandoff(done=False, report="One blocking gap")
        ts = utc_now_filesafe()
        path = store.save_terminal_review("p1", "mission-001", ts, rep)
        assert path.exists()
        assert path.parent.name == "terminal-reviews"
        # JSON handoff lives in the runtime cursor tree; MD mirror in durable .unrest.
        assert path.parent == store.terminal_reviews_dir("p1", "mission-001")
        assert store.mission_dir("p1", "mission-001") in path.parents
        assert store.mission_runtime_dir("p1", "mission-001") not in path.parents
        assert path.suffix == ".md"
        json_path = store.terminal_review_path("p1", "mission-001", ts)
        assert json_path.exists()
        assert json_path.parent == store.terminal_reviews_runtime_dir(
            "p1", "mission-001"
        )
        assert store.mission_runtime_dir("p1", "mission-001") in json_path.parents
        assert store.mission_dir("p1", "mission-001") not in json_path.parents
        assert json_path.suffix == ".json"

    def test_declared_roots_are_narrow_and_persisted(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        mission = store.mission_dir("p1", "mission-001")
        evidence = mission / "evidence"
        report_dir = evidence / "final"
        report = report_dir / "report.md"
        report_dir.mkdir(parents=True)
        report.write_text("report", encoding="utf-8")
        product_dir = workspace / "src"
        product_dir.mkdir()
        product = product_dir / "product.py"
        product.write_text("VALUE = 1\n", encoding="utf-8")
        product_alias = workspace / "product-alias.py"
        product_alias.symlink_to(product)

        roots = store.resolve_terminal_review_roots(
            "p1",
            "mission-001",
            [
                str(report_dir),
                str(product),
                str(report),
                str(report),
                str(product_alias),
                str(product.relative_to(workspace)),
            ],
        )
        assert roots == sorted(
            [str(report_dir.resolve()), str(report.resolve()), str(product.resolve())]
        )
        config = TerminalReviewConfig(deliverable_roots=roots)
        store.save_terminal_review_config("p1", "mission-001", config)
        assert store.load_terminal_review_config("p1", "mission-001") == config

    def test_declared_roots_accept_aliased_allowed_base_ancestors(
        self, config: HarnessConfig, tmp_path: Path
    ) -> None:
        physical_root = tmp_path / "physical"
        physical_root.mkdir()
        aliased_root = tmp_path / "aliased"
        aliased_root.symlink_to(physical_root, target_is_directory=True)
        harness_home = aliased_root / "harness-home"
        aliased_store = ProjectStore(
            replace(
                config,
                harness_home=harness_home,
                projects_dir=harness_home / "projects",
            )
        )
        workspace = aliased_root / "workspace"
        workspace.mkdir()
        aliased_store.create_project("brief", workspace, project_id="p1")

        product = workspace / "product.md"
        product.write_text("product", encoding="utf-8")
        report = (
            aliased_store.mission_dir("p1", "mission-001")
            / "evidence"
            / "report.md"
        )
        report.parent.mkdir(parents=True)
        report.write_text("report", encoding="utf-8")

        assert aliased_store.resolve_terminal_review_roots(
            "p1",
            "mission-001",
            [str(report), str(product), str(report.resolve()), str(product.resolve())],
        ) == sorted([str(report.resolve()), str(product.resolve())])

    def test_declared_roots_reject_process_and_control_surfaces(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        mission = store.mission_dir("p1", "mission-001")
        process_paths = [
            mission / "mission.md",
            mission / "contract" / "VAL-001.md",
            mission / "attempts" / "worker.md",
            mission / "regressions" / "VAL-001.md",
            mission / "terminal-reviews" / "prior.md",
            mission / "closeout.md",
            store.unrest_dir("p1") / "decisions" / "prior.md",
            store.unrest_dir("p1") / "MEMORY.md",
            store.mission_runtime_dir("p1", "mission-001") / "cursor.json",
            store.unrest_dir("p1") / "AGENTS.md",
            store.unrest_dir("p1") / "skills" / "control.md",
        ]
        for path in process_paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("private process history", encoding="utf-8")

        forbidden_workspace = [
            workspace / ".git",
            workspace / ".unrest",
            workspace / ".unrest-runtime",
            workspace / ".agents",
            workspace / ".claude",
            workspace / ".codex",
            workspace / "AGENTS.md",
        ]
        for path in forbidden_workspace[:3]:
            path.mkdir(exist_ok=True)

        outside = workspace.parent / "outside.md"
        outside.write_text("outside", encoding="utf-8")
        rejected = [
            mission,
            store.bucket_root("p1"),
            *process_paths,
            *forbidden_workspace,
            workspace,
            outside,
        ]
        for path in rejected:
            with pytest.raises(ValueError):
                store.resolve_terminal_review_roots(
                    "p1", "mission-001", [str(path)]
                )

    def test_project_bucket_nested_in_workspace_is_not_product_surface(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        harness_home = workspace / "control-home"
        nested_store = ProjectStore(
            replace(
                store.config,
                harness_home=harness_home,
                projects_dir=harness_home / "projects",
            )
        )
        nested_store.create_project("brief", workspace, project_id="p1")
        mission = nested_store.mission_dir("p1", "mission-001")
        report = mission / "evidence" / "report.md"
        report.parent.mkdir(parents=True)
        report.write_text("report", encoding="utf-8")
        product = workspace / "product.md"
        product.write_text("product", encoding="utf-8")

        assert nested_store.resolve_terminal_review_roots(
            "p1", "mission-001", [str(product), str(report)]
        ) == sorted([str(product.resolve()), str(report.resolve())])

        rejected = [
            harness_home,
            nested_store.config.projects_dir,
            nested_store.bucket_root("p1"),
            nested_store.unrest_dir("p1") / "MEMORY.md",
        ]
        for path in rejected:
            with pytest.raises(ValueError):
                nested_store.resolve_terminal_review_roots(
                    "p1", "mission-001", [str(path)]
                )

    def test_declared_roots_reject_escaping_or_injecting_paths(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        mission = store.mission_dir("p1", "mission-001")
        report_dir = mission / "evidence" / "report"
        report_dir.mkdir(parents=True)
        (report_dir / "escape").symlink_to(store.unrest_dir("p1") / "MEMORY.md")
        with pytest.raises(ValueError, match="symlink outside"):
            store.resolve_terminal_review_roots(
                "p1", "mission-001", [str(report_dir)]
            )

        product = workspace / "product.md"
        product.write_text("product", encoding="utf-8")
        direct_escape = mission / "evidence" / "direct-escape"
        direct_escape.symlink_to(product)
        with pytest.raises(ValueError, match="mission evidence subtree"):
            store.resolve_terminal_review_roots(
                "p1", "mission-001", [str(direct_escape)]
            )

        broken_dir = mission / "evidence" / "broken"
        broken_dir.mkdir()
        (broken_dir / "missing").symlink_to(mission / "evidence" / "missing")
        with pytest.raises(ValueError, match="broken symlink"):
            store.resolve_terminal_review_roots(
                "p1", "mission-001", [str(broken_dir)]
            )

        with pytest.raises(ValueError, match="does not exist"):
            store.resolve_terminal_review_roots(
                "p1", "mission-001", [str(mission / "evidence" / "absent")]
            )

        bad_name = mission / "evidence" / "report\ninjected.md"
        bad_name.write_text("report", encoding="utf-8")
        with pytest.raises(ValueError, match="control characters"):
            store.resolve_terminal_review_roots(
                "p1", "mission-001", [str(bad_name)]
            )


class TestSeal:
    def test_writes_closeout(
        self, store: ProjectStore, workspace: Path
    ) -> None:
        store.create_project("brief", workspace, project_id="p1")
        path = store.seal_mission(
            "p1", "mission-001", status="done", body="Everything shipped."
        )
        text = path.read_text()
        assert "status: done" in text and "Everything shipped." in text
        assert path == store.mission_dir("p1", "mission-001") / "closeout.md"
