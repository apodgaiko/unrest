"""v5 ProjectStore — memory_v2 layout.

BUCKET_PROJECT = `$UNREST_HOME/projects/<pid>/`. Inside it:
  - `.unrest/`            — durable record (brief, memory, decisions, skills,
                            missions/<mid>/attempts/*.md mirrors, ...)
  - `.unrest-runtime/`    — orchestrator-only cursors (state.json, tasks.json,
                            missions/<mid>/attempts/*.json handoffs, ...)

Workspace itself is left clean except for host-agent discovery shims
(`.agents/skills`, `.claude/skills`, `.codex/skills`, `AGENTS.md`) that
retarget into the bucket. If the workspace already has a real host `skills/`
directory, Unrest preserves it and copies missing bucket skills into it.

See `specs/memory_v2/PRODUCT.md` and `specs/task_list/PRODUCT.md`.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping

from .capability_policy import redact_sensitive_value
from .config import HarnessConfig
from .models import (
    AttentionFile,
    AttentionItemInternal,
    ContractStateFile,
    Decision,
    ProjectRecord,
    ProjectState,
    TaskList,
    TaskStateFile,
    TerminalReviewConfig,
    TerminalReviewHandoff,
    ValidateHandoff,
    WorkHandoff,
)

# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def utc_now_iso() -> str:
    """ISO-8601 UTC timestamp with second precision."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_now_filesafe() -> str:
    """`2026-05-17T10-15-00Z` (colons turned into hyphens) for filenames."""
    return utc_now_iso().replace(":", "-")


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str, fallback: str = "item") -> str:
    slug = _SLUG_RE.sub("-", value.lower()).strip("-")
    return slug[:64] or fallback


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _lexical_absolute(path: str | Path) -> Path:
    """Return an absolute lexical path without following filesystem links."""
    return Path(os.path.abspath(os.fspath(path)))


def _prepare_atomic_write_destination(
    path: str | Path,
    trusted_root: str | Path,
    *,
    create_parents: bool,
    allowed_ancestor: str | Path | None = None,
) -> tuple[Path, Path]:
    """Validate a destination from its trusted root without following links."""
    target = _lexical_absolute(path)
    root = _lexical_absolute(trusted_root)
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise OSError(
            f"atomic write target must be beneath its trusted root: {target}"
        ) from exc
    if relative == Path("."):
        raise OSError(f"atomic write target must be beneath its trusted root: {target}")

    if allowed_ancestor is None:
        try:
            root_stat = root.lstat()
        except FileNotFoundError as exc:
            raise OSError(f"atomic write trusted root does not exist: {root}") from exc
        if not stat.S_ISDIR(root_stat.st_mode):
            raise OSError(
                f"atomic write trusted root must be a regular directory: {root}"
            )
    else:
        ancestor = _lexical_absolute(allowed_ancestor)
        try:
            root_relative = root.relative_to(ancestor)
        except ValueError as exc:
            raise OSError(
                f"atomic write trusted root must be beneath its allowed ancestor: {root}"
            ) from exc
        try:
            ancestor_stat = ancestor.lstat()
        except FileNotFoundError as exc:
            raise OSError(
                f"atomic write allowed ancestor does not exist: {ancestor}"
            ) from exc
        if not stat.S_ISDIR(ancestor_stat.st_mode):
            raise OSError(
                "atomic write allowed ancestor must be a regular directory: "
                f"{ancestor}"
            )
        candidate = ancestor
        for part in root_relative.parts:
            candidate /= part
            try:
                candidate_stat = candidate.lstat()
            except FileNotFoundError:
                if not create_parents:
                    raise OSError(
                        f"atomic write trusted root does not exist: {root}"
                    ) from None
                candidate.mkdir()
                candidate_stat = candidate.lstat()
            if not stat.S_ISDIR(candidate_stat.st_mode):
                raise OSError(
                    "atomic write trusted-root component must be a regular directory: "
                    f"{candidate}"
                )

    parent = root
    for part in relative.parent.parts:
        parent /= part
        try:
            parent_stat = parent.lstat()
        except FileNotFoundError:
            if not create_parents:
                raise OSError(f"atomic write parent does not exist: {parent}") from None
            parent.mkdir()
            parent_stat = parent.lstat()
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise OSError(
                f"atomic write path component must be a regular directory: {parent}"
            )
    return target, parent


def validate_atomic_write_destination(
    path: str | Path,
    *,
    trusted_root: str | Path,
    allowed_ancestor: str | Path | None = None,
) -> None:
    """Validate an atomic-write path without creating directories or files.

    Initialization uses this as a preflight before its first write. Missing
    components are allowed only when an existing ``allowed_ancestor`` gives the
    caller an explicit creation boundary.
    """
    target = _lexical_absolute(path)
    root = _lexical_absolute(trusted_root)
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise OSError(
            f"atomic write target must be beneath its trusted root: {target}"
        ) from exc
    if relative == Path("."):
        raise OSError(f"atomic write target must be beneath its trusted root: {target}")

    if allowed_ancestor is None:
        ancestor = root
        root_relative = Path(".")
    else:
        ancestor = _lexical_absolute(allowed_ancestor)
        try:
            root_relative = root.relative_to(ancestor)
        except ValueError as exc:
            raise OSError(
                f"atomic write trusted root must be beneath its allowed ancestor: {root}"
            ) from exc

    try:
        ancestor_stat = ancestor.lstat()
    except FileNotFoundError as exc:
        label = "trusted root" if allowed_ancestor is None else "allowed ancestor"
        raise OSError(f"atomic write {label} does not exist: {ancestor}") from exc
    if not stat.S_ISDIR(ancestor_stat.st_mode):
        label = "trusted root" if allowed_ancestor is None else "allowed ancestor"
        raise OSError(
            f"atomic write {label} must be a regular directory: {ancestor}"
        )

    current = ancestor
    for part in (*root_relative.parts, *relative.parent.parts):
        if part == ".":
            continue
        current /= part
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(current_stat.st_mode):
            raise OSError(
                f"atomic write path component must be a regular directory: {current}"
            )
    try:
        target_stat = target.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(target_stat.st_mode):
        raise OSError(f"atomic write target must be a regular file: {target}")


def trusted_persistence_root(path: str | Path) -> Path:
    """Return the lexical root for a configured persistence destination.

    Normal Unrest paths trust the bucket containing `.unrest` and
    `.unrest-runtime`. Standalone MCP-server embeddings supply one exact output
    path, so its already-existing parent is their persistence root.
    """
    target = _lexical_absolute(path)
    for parent in target.parents:
        if parent.name in {".unrest", ".unrest-runtime"}:
            return parent.parent
    return target.parent


def atomic_write_text(
    path: str | Path,
    content: str,
    *,
    trusted_root: str | Path,
    allowed_ancestor: str | Path | None = None,
    mode: int | None = None,
    inventory: Mapping[str, str] | None = None,
    _redact: bool = True,
) -> None:
    redacted = (
        redact_sensitive_value(content, inventory)
        if _redact
        else content
    )
    if not isinstance(redacted, str):
        raise TypeError("canonical text redaction returned a non-text value")
    target, parent = _prepare_atomic_write_destination(
        path,
        trusted_root,
        create_parents=True,
        allowed_ancestor=allowed_ancestor,
    )
    try:
        target_stat = target.lstat()
    except FileNotFoundError:
        target_stat = None
    if target_stat is not None and not stat.S_ISREG(target_stat.st_mode):
        raise OSError(f"atomic write target must be a regular file: {target}")

    target_mode = (
        mode
        if mode is not None
        else stat.S_IMODE(target_stat.st_mode) if target_stat is not None else 0o644
    )
    fd, tmp_name = tempfile.mkstemp(
        dir=parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    replaced = False
    try:
        os.fchmod(fd, target_mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            fd = -1
            stream.write(redacted)
            stream.flush()
            os.fsync(stream.fileno())
        _prepare_atomic_write_destination(
            target,
            trusted_root,
            create_parents=False,
            allowed_ancestor=allowed_ancestor,
        )
        try:
            replacement_stat = target.lstat()
        except FileNotFoundError:
            replacement_stat = None
        if replacement_stat is not None and not stat.S_ISREG(replacement_stat.st_mode):
            raise OSError(f"atomic write target must be a regular file: {target}")
        os.replace(tmp_path, target)
        replaced = True
        try:
            _fsync_directory(parent)
        except OSError:
            # Replacement is already caller- and restart-visible. Reporting
            # rejection here would contradict the accepted target generation.
            pass
    finally:
        if fd >= 0:
            os.close(fd)
        if not replaced:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass


def atomic_write_json(
    path: str | Path,
    payload: object,
    *,
    trusted_root: str | Path,
    allowed_ancestor: str | Path | None = None,
    inventory: Mapping[str, str] | None = None,
) -> None:
    redacted = redact_sensitive_value(payload, inventory)
    atomic_write_text(
        path,
        json.dumps(redacted, indent=2, ensure_ascii=False) + "\n",
        trusted_root=trusted_root,
        allowed_ancestor=allowed_ancestor,
        _redact=False,
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _symlink_components(path: Path) -> list[Path]:
    components: list[Path] = []
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            components.append(current)
    return components


def attempt_to_markdown(handoff: WorkHandoff | ValidateHandoff) -> str:
    lines = ["---"]
    lines.append(f"node_id: {handoff.node_id}")
    if handoff.attempt_id is not None:
        lines.append(f"attempt_id: {handoff.attempt_id}")
    lines.append(f"done: {str(handoff.done).lower()}")
    if isinstance(handoff, ValidateHandoff):
        lines.append(f"passed: {str(handoff.passed).lower()}")
    lines.append(f"request_attention: {str(handoff.request_attention).lower()}")
    lines.append("---")
    lines.append("")
    if isinstance(handoff, ValidateHandoff) and handoff.items:
        lines.append("## Items")
        lines.append("")
        for item in handoff.items:
            lines.append(f"- {item.item_id}: {'passed' if item.passed else 'failed'}")
        lines.append("")
    lines.append("## Report")
    lines.append("")
    if handoff.report:
        lines.append(handoff.report)
    return "\n".join(lines).rstrip() + "\n"


def terminal_review_to_markdown(review: TerminalReviewHandoff) -> str:
    lines = ["---", f"done: {str(review.done).lower()}", "---", "", "## Report", ""]
    if review.report:
        lines.append(review.report)
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttemptRecord:
    spawn_ts: str
    node_id: str
    path: Path


class AttemptValidationError(ValueError):
    """A persisted handoff is not attributable to its expected dispatch."""


# ---------------------------------------------------------------------------
# ProjectStore
# ---------------------------------------------------------------------------


class ProjectStore:
    """All disk I/O for v5 memory_v2.

    Bucket root lives at `$UNREST_HOME/projects/<pid>/`. Callers pass
    `project_id` (and `mission_id` where relevant); the store owns all path
    conventions.
    """

    def __init__(self, config: HarnessConfig):
        self.config = config
        self.inventory: dict[str, str] = {}
        self.refresh_inventory(os.environ)

    def refresh_inventory(self, environment: Mapping[str, str]) -> None:
        """Capture the finite selected-role values at child-creation time."""
        self.inventory = {
            name: value
            for role in ("orchestrator", "worker", "validator", "terminal_reviewer")
            for name, value in self.config.credential_inventory(
                environment,
                role=role,  # type: ignore[arg-type]
            ).items()
        }

    # ------------------------------------------------------------------
    # Bucket path accessors
    # ------------------------------------------------------------------

    def bucket_root(self, project_id: str) -> Path:
        return self.config.bucket_root(project_id)

    def unrest_dir(self, project_id: str) -> Path:
        return self.config.unrest_dir(project_id)

    def unrest_runtime_dir(self, project_id: str) -> Path:
        return self.config.unrest_runtime_dir(project_id)

    def workspace_dir(self, project_id: str) -> Path:
        return Path(self.load_project(project_id).workspace_dir)

    def mission_dir(self, project_id: str, mission_id: str) -> Path:
        """Durable per-mission dir (contract/, attempts/, closeout.md, ...)."""
        return self.unrest_dir(project_id) / "missions" / mission_id

    def mission_runtime_dir(self, project_id: str, mission_id: str) -> Path:
        """Cursor per-mission dir (tasks.json, task-state.json, contract-state.json,
        attempts/*.json)."""
        return self.unrest_runtime_dir(project_id) / "missions" / mission_id

    # ------------------------------------------------------------------
    # Project lifecycle
    # ------------------------------------------------------------------

    def generate_project_id(self, brief: str) -> str:
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        first_line = brief.strip().splitlines()[0] if brief.strip() else "project"
        return f"{ts}-{slugify(first_line, 'project')}"

    def create_project(
        self,
        brief: str,
        workspace_dir: str | Path,
        *,
        project_id: str | None = None,
        worker_model: str | None = None,
        worker_reasoning_effort: str | None = None,
    ) -> ProjectRecord:
        ws = Path(workspace_dir).expanduser().resolve()
        if not ws.exists():
            raise FileNotFoundError(f"workspace_dir does not exist: {ws}")
        pid = project_id or self.generate_project_id(brief)

        unrest = self.unrest_dir(pid)
        runtime = self.unrest_runtime_dir(pid)

        # 1) Durable layout (.unrest/)
        unrest.mkdir(parents=True, exist_ok=True)
        (unrest / "decisions").mkdir(parents=True, exist_ok=True)
        (unrest / "skills").mkdir(parents=True, exist_ok=True)
        (unrest / "missions").mkdir(parents=True, exist_ok=True)

        # 2) Cursor layout (.unrest-runtime/)
        runtime.mkdir(parents=True, exist_ok=True)
        (runtime / "missions").mkdir(parents=True, exist_ok=True)

        # 3) brief.md (atomic; do not overwrite if exists)
        brief_path = unrest / "brief.md"
        if not brief_path.exists():
            atomic_write_text(
                brief_path,
                brief.rstrip() + "\n",
                trusted_root=self.bucket_root(pid),
                inventory=self.inventory,
            )

        # 4) AGENTS.md placeholder
        agents_md = unrest / "AGENTS.md"
        if not agents_md.exists():
            atomic_write_text(
                agents_md,
                "# Project operational guidance\n\n"
                "Edit this file as the project's conventions emerge.\n",
                trusted_root=self.bucket_root(pid),
                inventory=self.inventory,
            )

        # 5) MEMORY.md placeholder
        memory_md = unrest / "MEMORY.md"
        if not memory_md.exists():
            atomic_write_text(
                memory_md,
                "# Project memory\n\n"
                "Record concise reusable mission facts here. Do not paste transcripts.\n",
                trusted_root=self.bucket_root(pid),
                inventory=self.inventory,
            )

        # 6) Import existing repo-native host skills, then seed bundled skills
        #    into the bucket so host-agent native
        #    discovery via the workspace shim has content from day one.
        self._import_workspace_skills(ws, unrest / "skills")
        self._seed_bundled_skills(unrest / "skills")

        # 7) Workspace symlink shims (host-agent native discovery surface).
        self._ensure_symlink_shims(ws, unrest)

        # 8) project.json (orchestrator-only cursor)
        record = ProjectRecord(
            id=pid,
            workspace_dir=str(ws),
            created_at=utc_now_iso(),
            worker_model=worker_model,
            worker_reasoning_effort=worker_reasoning_effort,
        )
        atomic_write_json(
            runtime / "project.json", record.model_dump(mode="json"),
            trusted_root=self.bucket_root(pid),
            inventory=self.inventory,
        )
        return record

    def load_project(self, project_id: str) -> ProjectRecord:
        path = self.unrest_runtime_dir(project_id) / "project.json"
        if not path.exists():
            raise FileNotFoundError(f"project not found: {project_id}")
        return ProjectRecord.model_validate_json(path.read_text(encoding="utf-8"))

    def save_project(self, record: ProjectRecord) -> None:
        atomic_write_json(
            self.unrest_runtime_dir(record.id) / "project.json",
            record.model_dump(mode="json"),
            trusted_root=self.bucket_root(record.id),
            inventory=self.inventory,
        )

    def sync_workspace_skill_surfaces(self, project_id: str) -> None:
        """Refresh workspace-native skill dirs from the project skill bucket.

        Real user-authored host skill directories are preserved; missing bucket
        skills are copied into them. Bootstrap-only host skill directories are
        still converted to symlinks by the same rules used at project creation.
        """
        record = self.load_project(project_id)
        ws = Path(record.workspace_dir).expanduser().resolve()
        unrest = self.unrest_dir(project_id)
        target_skills = unrest / "skills"
        self._import_workspace_skills(ws, target_skills)
        self._seed_bundled_skills(target_skills)
        self._ensure_symlink_shims(ws, unrest)

    def list_projects(self) -> list[ProjectRecord]:
        if not self.config.projects_dir.exists():
            return []
        result: list[ProjectRecord] = []
        for entry in sorted(self.config.projects_dir.iterdir()):
            project_json = entry / ".unrest-runtime" / "project.json"
            if not project_json.exists():
                continue
            try:
                result.append(
                    ProjectRecord.model_validate_json(
                        project_json.read_text(encoding="utf-8")
                    )
                )
            except Exception:
                continue
        result.sort(key=lambda r: r.created_at, reverse=True)
        return result

    # ------------------------------------------------------------------
    # ProjectState (cursor)
    # ------------------------------------------------------------------

    def load_state(self, project_id: str) -> ProjectState | None:
        path = self.unrest_runtime_dir(project_id) / "state.json"
        if not path.exists():
            return None
        from pydantic import TypeAdapter

        return TypeAdapter(ProjectState).validate_json(
            path.read_text(encoding="utf-8")
        )

    def save_state(self, project_id: str, state: ProjectState) -> None:
        atomic_write_json(
            self.unrest_runtime_dir(project_id) / "state.json",
            state.model_dump(mode="json"),
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory,
        )

    # ------------------------------------------------------------------
    # Mission DAG + contract
    # ------------------------------------------------------------------

    def generate_mission_id(self, sequence: int) -> str:
        return f"mission-{sequence:03d}"

    def list_missions(self, project_id: str) -> list[str]:
        d = self.unrest_runtime_dir(project_id) / "missions"
        if not d.exists():
            return []
        return sorted(p.name for p in d.iterdir() if p.is_dir())

    def load_task_list(self, project_id: str, mission_id: str) -> TaskList:
        path = self.mission_runtime_dir(project_id, mission_id) / "tasks.json"
        if not path.exists():
            raise FileNotFoundError(f"tasks.json missing for {project_id}/{mission_id}")
        return TaskList.model_validate_json(path.read_text(encoding="utf-8"))

    def save_task_list(self, project_id: str, mission_id: str, tl: TaskList) -> None:
        atomic_write_json(
            self.mission_runtime_dir(project_id, mission_id) / "tasks.json",
            tl.model_dump(mode="json"),
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory,
        )

    def contract_dir(self, project_id: str, mission_id: str) -> Path:
        return self.mission_dir(project_id, mission_id) / "contract"

    def ensure_contract_dir(self, project_id: str, mission_id: str) -> Path:
        d = self.contract_dir(project_id, mission_id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def list_contract_assertions(
        self, project_id: str, mission_id: str
    ) -> list[str]:
        from .task_validation import parse_contract_dir

        ids, _ = parse_contract_dir(self.contract_dir(project_id, mission_id))
        return sorted(ids)

    def contract_assertion_path(
        self, project_id: str, mission_id: str, assertion_id: str
    ) -> Path:
        return self.contract_dir(project_id, mission_id) / f"{assertion_id}.md"

    def load_contract_assertion(
        self, project_id: str, mission_id: str, assertion_id: str
    ) -> str | None:
        path = self.contract_assertion_path(project_id, mission_id, assertion_id)
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8")

    # task-state / contract-state cursors (runtime scope)

    def load_task_state(self, project_id: str, mission_id: str) -> TaskStateFile:
        path = self.mission_runtime_dir(project_id, mission_id) / "task-state.json"
        if not path.exists():
            return TaskStateFile()
        return TaskStateFile.model_validate_json(path.read_text(encoding="utf-8"))

    def save_task_state(
        self, project_id: str, mission_id: str, task_state: TaskStateFile
    ) -> None:
        atomic_write_json(
            self.mission_runtime_dir(project_id, mission_id) / "task-state.json",
            task_state.model_dump(mode="json"),
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory,
        )

    def load_contract_state(
        self, project_id: str, mission_id: str
    ) -> ContractStateFile:
        path = (
            self.mission_runtime_dir(project_id, mission_id) / "contract-state.json"
        )
        if not path.exists():
            return ContractStateFile()
        return ContractStateFile.model_validate_json(
            path.read_text(encoding="utf-8")
        )

    def save_contract_state(
        self, project_id: str, mission_id: str, contract_state: ContractStateFile
    ) -> None:
        atomic_write_json(
            self.mission_runtime_dir(project_id, mission_id)
            / "contract-state.json",
            contract_state.model_dump(mode="json"),
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory,
        )

    # ------------------------------------------------------------------
    # Attempts
    #   - JSON handoff   → .unrest-runtime/missions/<mid>/attempts/ (orchestrator cursor)
    #   - MD mirror      → .unrest/missions/<mid>/attempts/         (durable, agent-readable)
    # ------------------------------------------------------------------

    def attempts_dir(self, project_id: str, mission_id: str) -> Path:
        """Durable attempt mirrors (agent-readable markdown)."""
        return self.mission_dir(project_id, mission_id) / "attempts"

    def attempts_runtime_dir(self, project_id: str, mission_id: str) -> Path:
        """Orchestrator-only attempt handoffs (worker-written JSON cursors)."""
        return self.mission_runtime_dir(project_id, mission_id) / "attempts"

    def attempt_path(
        self,
        project_id: str,
        mission_id: str,
        spawn_ts: str,
        node_id: str,
    ) -> Path:
        """JSON handoff path — written by the worker MCP server (UNREST_HANDOFF_PATH)
        and polled by the coordinator. Lives in the runtime cursor tree
        (.unrest-runtime/), not the durable .unrest/ record."""
        return (
            self.attempts_runtime_dir(project_id, mission_id)
            / f"{spawn_ts}__{node_id}.json"
        )

    def attempt_report_path(
        self,
        project_id: str,
        mission_id: str,
        spawn_ts: str,
        node_id: str,
    ) -> Path:
        """Agent-readable markdown mirror (durable .unrest/ record)."""
        return self.attempts_dir(project_id, mission_id) / f"{spawn_ts}__{node_id}.md"

    def save_attempt(
        self,
        project_id: str,
        mission_id: str,
        spawn_ts: str,
        node_id: str,
        handoff: WorkHandoff | ValidateHandoff,
        *,
        inventory: Mapping[str, str] | None = None,
    ) -> Path:
        handoff = handoff.model_copy(update={"attempt_id": spawn_ts})
        json_path = self.attempt_path(project_id, mission_id, spawn_ts, node_id)
        atomic_write_json(
            json_path,
            handoff.model_dump(mode="json"),
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory if inventory is None else inventory,
        )
        md_path = self.attempt_report_path(project_id, mission_id, spawn_ts, node_id)
        atomic_write_text(
            md_path,
            attempt_to_markdown(handoff),
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory if inventory is None else inventory,
        )
        return json_path

    def read_attempt(
        self,
        project_id: str,
        mission_id: str,
        spawn_ts: str,
        node_id: str,
    ) -> WorkHandoff | ValidateHandoff | None:
        path = self.attempt_path(project_id, mission_id, spawn_ts, node_id)
        if not path.exists():
            return None
        handoff = self._parse_attempt(path)
        if handoff.node_id != node_id:
            raise AttemptValidationError("attempt node_id does not match running task")
        if handoff.attempt_id != spawn_ts:
            raise AttemptValidationError("attempt_id does not match running generation")
        return handoff

    def list_attempts(
        self,
        project_id: str,
        mission_id: str,
        node_id: str | None = None,
    ) -> list[AttemptRecord]:
        d = self.attempts_runtime_dir(project_id, mission_id)
        if not d.exists():
            return []
        results: list[AttemptRecord] = []
        for entry in sorted(d.glob("*.json")):
            stem = entry.stem
            if "__" not in stem:
                continue
            ts, nid = stem.split("__", 1)
            if node_id is not None and nid != node_id:
                continue
            results.append(AttemptRecord(spawn_ts=ts, node_id=nid, path=entry))
        return results

    @staticmethod
    def _parse_attempt(path: Path) -> WorkHandoff | ValidateHandoff:
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise AttemptValidationError("attempt payload must be an object")
            if "items" in data or "passed" in data:
                return ValidateHandoff.model_validate(data)
            return WorkHandoff.model_validate(data)
        except AttemptValidationError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise AttemptValidationError(
                f"attempt payload is malformed ({type(exc).__name__})"
            ) from exc

    # ------------------------------------------------------------------
    # Regression ledger (validator-owned, appended via Write tool)
    # ------------------------------------------------------------------

    def regressions_dir(self, project_id: str, mission_id: str) -> Path:
        return self.mission_dir(project_id, mission_id) / "regressions"

    def regression_path(
        self, project_id: str, mission_id: str, assertion_id: str
    ) -> Path:
        return self.regressions_dir(project_id, mission_id) / f"{assertion_id}.md"

    def regression_entry_count(
        self, project_id: str, mission_id: str, assertion_id: str
    ) -> int:
        """Count top-level (`## `) markdown headings as entries."""
        path = self.regression_path(project_id, mission_id, assertion_id)
        if not path.exists():
            return 0
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return 0
        return sum(1 for line in text.splitlines() if line.startswith("## "))

    # ------------------------------------------------------------------
    # Attention queue (cursor scope — orchestrator-only)
    # ------------------------------------------------------------------

    def load_attention(self, project_id: str) -> list[AttentionItemInternal]:
        path = self.unrest_runtime_dir(project_id) / "attention.json"
        if not path.exists():
            return []
        return AttentionFile.model_validate_json(
            path.read_text(encoding="utf-8")
        ).items

    def save_attention(
        self, project_id: str, items: list[AttentionItemInternal]
    ) -> None:
        atomic_write_json(
            self.unrest_runtime_dir(project_id) / "attention.json",
            AttentionFile(items=items).model_dump(mode="json"),
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory,
        )

    def clear_attention(self, project_id: str) -> None:
        self.save_attention(project_id, [])

    # ------------------------------------------------------------------
    # Decisions audit
    # ------------------------------------------------------------------

    def decisions_dir(self, project_id: str) -> Path:
        return self.unrest_dir(project_id) / "decisions"

    def next_decision_number(self, project_id: str) -> int:
        d = self.decisions_dir(project_id)
        if not d.exists():
            return 1
        max_n = 0
        for entry in d.glob("*.md"):
            try:
                num = int(entry.stem.split("-", 1)[0])
                max_n = max(max_n, num)
            except (ValueError, IndexError):
                continue
        return max_n + 1

    def append_decision_record(
        self,
        project_id: str,
        decisions: list[Decision],
        items: list[AttentionItemInternal],
        *,
        summary: str = "",
    ) -> Path:
        d = self.decisions_dir(project_id)
        d.mkdir(parents=True, exist_ok=True)
        n = self.next_decision_number(project_id)
        slug = slugify(summary or decisions[0].action if decisions else "decision")
        path = d / f"{n:03d}-{slug}.md"
        parts: list[str] = []
        parts.append(f"# Decision {n:03d}: {summary or 'decide_attention'}")
        parts.append("")
        parts.append(f"- Timestamp: {utc_now_iso()}")
        parts.append("")
        parts.append("## Resolved attention items")
        item_by_id = {it.id: it for it in items}
        for dec in decisions:
            it = item_by_id.get(dec.item_id)
            parts.append(f"### {dec.item_id} — action={dec.action}")
            if it is not None:
                parts.append("- report:")
                parts.append("```")
                parts.append(it.report)
                parts.append("```")
            if dec.justification:
                parts.append(f"- justification: {dec.justification}")
            if dec.patch is not None and not dec.patch.is_empty:
                parts.append("- patch:")
                parts.append("```json")
                parts.append(
                    json.dumps(dec.patch.model_dump(mode="json", by_alias=True), indent=2)
                )
                parts.append("```")
            parts.append("")
        atomic_write_text(
            path,
            "\n".join(parts).rstrip() + "\n",
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory,
        )
        return path

    # ------------------------------------------------------------------
    # Terminal review
    #   - JSON handoff   -> .unrest-runtime/missions/<mid>/terminal-reviews/
    #   - MD mirror      -> .unrest/missions/<mid>/terminal-reviews/
    # ------------------------------------------------------------------

    def terminal_reviews_dir(self, project_id: str, mission_id: str) -> Path:
        """Durable terminal-review mirrors (agent-readable markdown)."""
        return self.mission_dir(project_id, mission_id) / "terminal-reviews"

    def terminal_reviews_runtime_dir(self, project_id: str, mission_id: str) -> Path:
        """Orchestrator-only terminal-review handoffs (reviewer-written JSON cursors)."""
        return self.mission_runtime_dir(project_id, mission_id) / "terminal-reviews"

    def terminal_review_path(
        self, project_id: str, mission_id: str, spawn_ts: str
    ) -> Path:
        """JSON path — written by the terminal-reviewer MCP server and polled by
        the coordinator. Lives in the runtime cursor tree (.unrest-runtime/),
        not the durable .unrest/ record."""
        return self.terminal_reviews_runtime_dir(project_id, mission_id) / f"{spawn_ts}.json"

    def terminal_review_report_path(
        self, project_id: str, mission_id: str, spawn_ts: str
    ) -> Path:
        """Agent-readable markdown mirror."""
        return self.terminal_reviews_dir(project_id, mission_id) / f"{spawn_ts}.md"

    def terminal_review_config_path(self, project_id: str, mission_id: str) -> Path:
        return self.mission_runtime_dir(project_id, mission_id) / "terminal-review-config.json"

    def load_terminal_review_config(
        self, project_id: str, mission_id: str
    ) -> TerminalReviewConfig:
        path = self.terminal_review_config_path(project_id, mission_id)
        if not path.exists():
            return TerminalReviewConfig()
        return TerminalReviewConfig.model_validate_json(path.read_text(encoding="utf-8"))

    def save_terminal_review_config(
        self, project_id: str, mission_id: str, config: TerminalReviewConfig
    ) -> Path:
        path = self.terminal_review_config_path(project_id, mission_id)
        atomic_write_json(
            path,
            config.model_dump(mode="json"),
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory,
        )
        return path

    def resolve_terminal_review_roots(
        self, project_id: str, mission_id: str, roots: list[str]
    ) -> list[str]:
        workspace = self.workspace_dir(project_id).resolve()
        mission = self.mission_dir(project_id, mission_id).resolve()
        evidence = mission / "evidence"
        projects = self.config.projects_dir.resolve()
        forbidden_workspace = [
            projects,
            workspace / ".git",
            workspace / ".unrest",
            workspace / ".unrest-runtime",
            workspace / ".agents",
            workspace / ".claude",
            workspace / ".codex",
            workspace / "AGENTS.md",
        ]
        resolved: list[str] = []
        for raw in roots:
            if any(ord(char) < 32 or ord(char) == 127 for char in raw):
                raise ValueError("terminal-review deliverable path contains control characters")
            lexical_candidate = Path(raw).expanduser()
            if not lexical_candidate.is_absolute():
                lexical_candidate = workspace / lexical_candidate
            lexical_candidate = Path(os.path.abspath(lexical_candidate))
            try:
                candidate = lexical_candidate.resolve(strict=True)
            except FileNotFoundError as exc:
                raise ValueError(f"terminal-review deliverable does not exist: {raw}") from exc
            except (OSError, RuntimeError) as exc:
                raise ValueError(
                    f"terminal-review deliverable cannot be resolved safely: {raw}"
                ) from exc
            if any(ord(char) < 32 or ord(char) == 127 for char in str(candidate)):
                raise ValueError("terminal-review deliverable path contains control characters")

            # Ancestor aliases outside an allowed surface are path spellings, such
            # as macOS /var -> /private/var. A symlink originating inside an
            # authorization or control surface must not cross that boundary.
            for link in _symlink_components(lexical_candidate):
                try:
                    link_location = link.parent.resolve(strict=True) / link.name
                    link_target = link.resolve(strict=True)
                except FileNotFoundError as exc:
                    raise ValueError(
                        f"terminal-review deliverable contains a broken symlink: {link}"
                    ) from exc
                except (OSError, RuntimeError) as exc:
                    raise ValueError(
                        f"terminal-review deliverable contains an unsafe symlink: {link}"
                    ) from exc
                in_forbidden_workspace = any(
                    link_location == item or _is_relative_to(link_location, item)
                    for item in forbidden_workspace[1:]
                )
                in_project_control = _is_relative_to(
                    link_location, projects
                ) and not _is_relative_to(link_location, evidence)
                crosses_workspace_surface = (
                    _is_relative_to(link_location, workspace)
                    and not _is_relative_to(link_location, projects)
                    and not (
                        _is_relative_to(link_target, workspace)
                        and not _is_relative_to(link_target, projects)
                    )
                )
                crosses_mission_surface = _is_relative_to(
                    link_location, mission
                ) and not (
                    _is_relative_to(link_location, evidence)
                    and _is_relative_to(link_target, evidence)
                )
                if (
                    in_forbidden_workspace
                    or in_project_control
                    or crosses_mission_surface
                    or crosses_workspace_surface
                ):
                    raise ValueError(
                        "terminal-review deliverable must be inside the normal workspace "
                        f"product surface or current mission evidence subtree: {raw}"
                    )

            in_evidence = _is_relative_to(candidate, evidence)
            in_workspace = (
                _is_relative_to(candidate, workspace)
                and not _is_relative_to(candidate, projects)
            )
            if not (in_evidence or in_workspace):
                raise ValueError(
                    "terminal-review deliverable must be inside the normal workspace "
                    f"product surface or current mission evidence subtree: {raw}"
                )
            if in_workspace:
                for item in forbidden_workspace:
                    if (
                        candidate == item
                        or _is_relative_to(candidate, item)
                        or (candidate.is_dir() and _is_relative_to(item, candidate))
                    ):
                        raise ValueError(
                            "terminal-review deliverable is a forbidden workspace "
                            f"artifact: {raw}"
                        )
            if candidate.is_dir():
                for nested in candidate.rglob("*"):
                    if not nested.is_symlink():
                        continue
                    try:
                        link_target = nested.resolve(strict=True)
                    except FileNotFoundError as exc:
                        raise ValueError(
                            f"terminal-review deliverable contains a broken symlink: {nested}"
                        ) from exc
                    except (OSError, RuntimeError) as exc:
                        raise ValueError(
                            "terminal-review deliverable contains an unsafe symlink: "
                            f"{nested}"
                        ) from exc
                    if not _is_relative_to(link_target, candidate):
                        raise ValueError(
                            "terminal-review deliverable contains a symlink outside its "
                            f"declared root: {nested}"
                        )
            value = str(candidate)
            if value not in resolved:
                resolved.append(value)
        return sorted(resolved)

    def save_terminal_review(
        self,
        project_id: str,
        mission_id: str,
        spawn_ts: str,
        review: TerminalReviewHandoff,
        *,
        inventory: Mapping[str, str] | None = None,
    ) -> Path:
        # JSON: fallback only (acp_runner's MCP server normally writes this).
        json_path = self.terminal_review_path(project_id, mission_id, spawn_ts)
        if not json_path.exists():
            atomic_write_json(
                json_path,
                review.model_dump(mode="json"),
                trusted_root=self.bucket_root(project_id),
                inventory=self.inventory if inventory is None else inventory,
            )
        md_path = self.terminal_review_report_path(project_id, mission_id, spawn_ts)
        atomic_write_text(
            md_path,
            terminal_review_to_markdown(review),
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory if inventory is None else inventory,
        )
        return md_path

    # ------------------------------------------------------------------
    # Mission seal
    # ------------------------------------------------------------------

    def seal_mission(
        self,
        project_id: str,
        mission_id: str,
        *,
        status: str,
        body: str,
    ) -> Path:
        path = self.mission_dir(project_id, mission_id) / "closeout.md"
        header = (
            f"# Mission {mission_id} closeout\n\n"
            f"- status: {status}\n"
            f"- sealed_at: {utc_now_iso()}\n\n"
        )
        atomic_write_text(
            path,
            header + body.rstrip() + "\n",
            trusted_root=self.bucket_root(project_id),
            inventory=self.inventory,
        )
        return path

    # ------------------------------------------------------------------
    # Workspace symlink shims
    # ------------------------------------------------------------------

    def _ensure_symlink_shims(self, workspace: Path, unrest: Path) -> None:
        """Install the four host-agent discovery shims at the workspace root.

        - `<ws>/.agents/skills` → `<unrest>/skills`
        - `<ws>/.claude/skills` → `<unrest>/skills`
        - `<ws>/.codex/skills`  → `<unrest>/skills`
        - `<ws>/AGENTS.md`      → `<unrest>/AGENTS.md`

        Idempotent: skill surfaces are merged or retargeted by
        `_ensure_skills_surface`; `AGENTS.md` is created only when the
        workspace does not already have one.
        """
        target_skills = unrest / "skills"
        target_agents_md = unrest / "AGENTS.md"
        target_skills.mkdir(parents=True, exist_ok=True)
        for host in (".agents", ".claude", ".codex"):
            host_dir = workspace / host
            host_dir.mkdir(parents=True, exist_ok=True)
            self._ensure_skills_surface(host_dir / "skills", target_skills)
        self._ensure_agents_surface(workspace / "AGENTS.md", target_agents_md)

    def _ensure_skills_surface(self, link: Path, target: Path) -> None:
        """Expose aggregate bucket skills without replacing real repo skill dirs."""
        target_abs = target.resolve() if target.exists() else target
        if link.is_symlink():
            try:
                if not link.exists():
                    link.unlink()
                    link.symlink_to(target_abs)
                    return
                if link.resolve() == target_abs:
                    return
                return
            except OSError:
                return
        if link.exists():
            if link.is_dir():
                if self._is_bootstrap_skill_dir(link):
                    shutil.rmtree(link)
                    link.symlink_to(target_abs)
                    return
                self._copy_missing_tree(target_abs, link)
            return
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target_abs)

    @staticmethod
    def _ensure_agents_surface(link: Path, target: Path) -> None:
        """Create the AGENTS.md shim only when the workspace has no AGENTS.md."""
        if os.path.lexists(link):
            return
        target_abs = target.resolve() if target.exists() else target
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target_abs)

    def _is_bootstrap_skill_dir(self, path: Path) -> bool:
        """True when a real host skill dir only contains Unrest-seeded skills.

        `unrest init` has to create real skill directories before a project
        bucket exists. Once `start_project` creates the bucket, those bootstrap
        directories should become symlinks so project-authored skills added later
        are visible through `.agents/skills`, `.claude/skills`, and
        `.codex/skills`. Directories containing user-authored or edited content
        are left in place by `_ensure_skills_surface`.
        """
        if not path.is_dir() or path.is_symlink():
            return False
        bundled = self.config.bundled_dir / "skills"
        if not bundled.exists():
            return False
        for src in sorted(path.rglob("*")):
            rel = src.relative_to(path)
            bundled_peer = bundled / rel
            if src.is_symlink():
                return False
            if src.is_dir():
                if not bundled_peer.is_dir():
                    return False
                continue
            if src.is_file():
                if not bundled_peer.is_file():
                    return False
                if src.read_bytes() != bundled_peer.read_bytes():
                    return False
                continue
            return False
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _import_workspace_skills(self, workspace: Path, target: Path) -> None:
        target.mkdir(parents=True, exist_ok=True)
        for host in (".agents", ".claude", ".codex"):
            source = workspace / host / "skills"
            if source.is_dir() and not source.is_symlink():
                self._copy_missing_tree(source, target)

    def _seed_bundled_skills(self, target: Path) -> None:
        """Copy bundled `SKILL.md` files into the bucket if not already
        present. Idempotent and non-overwriting per skill."""
        bundled_skills = self.config.bundled_dir / "skills"
        if not bundled_skills.exists():
            return
        target.mkdir(parents=True, exist_ok=True)
        for skill_dir in sorted(bundled_skills.iterdir()):
            if not skill_dir.is_dir():
                continue
            src = skill_dir / "SKILL.md"
            if not src.exists():
                continue
            dest_dir = target / skill_dir.name
            dest = dest_dir / "SKILL.md"
            if dest.exists():
                continue
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

    @staticmethod
    def _copy_missing_tree(source: Path, target: Path) -> None:
        if not source.is_dir():
            return
        for src in sorted(source.rglob("*")):
            rel = src.relative_to(source)
            dest = target / rel
            if os.path.lexists(dest):
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            if src.is_symlink():
                dest.symlink_to(os.readlink(src))
            elif src.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            elif src.is_file():
                shutil.copy2(src, dest)


__all__ = [
    "ProjectStore",
    "AttemptRecord",
    "utc_now_iso",
    "utc_now_filesafe",
    "slugify",
    "atomic_write_text",
    "atomic_write_json",
    "trusted_persistence_root",
    "AttemptValidationError",
    "attempt_to_markdown",
    "terminal_review_to_markdown",
]
