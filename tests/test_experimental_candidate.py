from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import zlib

import pytest

from unrest_harness import experimental_candidate as candidate
from unrest_harness.experimental_candidate import (
    CandidateInputError, observe_candidate_inputs, verify_candidate_inputs,
)


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["/usr/bin/git", *args], cwd=root, text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(root), "LC_ALL": "C",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
             "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000"},
        stderr=subprocess.DEVNULL,
    ).strip()


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path.resolve() / "repository"
    root.mkdir()
    git(root, "init", "--initial-branch=main", "--object-format=sha1")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    for name in ("lane_b.txt", "lane_a.txt"):
        (root / name).write_bytes(b"base\n")
    git(root, "add", ".")
    git(root, "commit", "-m", "base")
    base = git(root, "rev-parse", "HEAD")
    (root / "lane_a.txt").write_bytes(b"A\n")
    (root / "lane_b.txt").write_bytes(b"B\n")
    git(root, "add", ".")
    git(root, "commit", "-m", "candidate")
    commit = git(root, "rev-parse", "HEAD")
    (root / "extra.txt").write_bytes(b"extra\n")
    (root / "out").mkdir()
    return root, base, commit


def observe(repo: tuple[Path, str, str]) -> candidate.CandidateManifest:
    return observe_candidate_inputs(*repo, ["extra.txt"], ["out"], ["VAL-B", "VAL-A"])


def test_literal_manifest_and_independent_oracle(repo: tuple[Path, str, str]) -> None:
    root, base, commit = repo
    manifest = observe(repo)
    # Independent SHA256 values and literal canonical encoding, not the product serializer.
    a = "06f961b802bc46ee168555f066d28f4f0e9afdf3f88174c1ee6f9de004fc30a0"
    b = "c0cde77fa8fef97d476c10aad3d2d54fcc2f336140d073651c2dcccf1e379fd6"
    assert hashlib.sha256(b"A\n").hexdigest() == a
    assert hashlib.sha256(b"B\n").hexdigest() == b
    extra = hashlib.sha256(b"extra\n").hexdigest()
    tree = git(root, "rev-parse", "HEAD^{tree}")
    literal = (
        f'{{"base_oid":"{base}","candidate_commit_oid":"{commit}",'
        f'"candidate_tree_oid":"{tree}","extra_input_files":["extra.txt"],'
        f'"extra_inputs":[{{"mode":"100644","path":"extra.txt","sha256":"{extra}","size":6}}],'
        '"output_directories":["out"],"schema":"experimental-candidate-inputs.v1",'
        '"targets":["VAL-A","VAL-B"],"tracked_inputs":['
        f'{{"mode":"100644","path":"lane_a.txt","sha256":"{a}","size":2}},'
        f'{{"mode":"100644","path":"lane_b.txt","sha256":"{b}","size":2}}]}}\n'
    ).encode()
    assert manifest.canonical_bytes == literal
    assert manifest.digest == "sha256:" + hashlib.sha256(
        b"unrest.experimental-candidate-inputs.v1\0" + literal).hexdigest()
    assert manifest.digest != "sha256:" + hashlib.sha256(b"other-domain\0" + literal).hexdigest()
    verify_candidate_inputs(root, manifest)
    assert observe(repo) == manifest


def test_immutable_binding_and_failed_observation(repo: tuple[Path, str, str]) -> None:
    root, base, commit = repo
    extra, outputs, targets = ["extra.txt"], ["out"], ["VAL-A"]
    original = observe_candidate_inputs(root, base, commit, extra, outputs, targets)
    raw, digest = original.canonical_bytes, original.digest
    extra.clear()
    outputs.append("lane_a.txt")
    targets.clear()
    with pytest.raises(FrozenInstanceError):
        original.targets = ()  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        original.tracked_inputs[0].path = "out"  # type: ignore[misc]
    for changed in (replace(original, targets=("VAL-B",)),
                    replace(original, output_directories=("other",)),
                    replace(original, extra_input_files=()),
                    replace(original, candidate_tree_oid="0" * 40)):
        assert changed.digest != digest
    (root / "extra.txt").write_bytes(b"changed")
    with pytest.raises(CandidateInputError):
        verify_candidate_inputs(root, original)
    with pytest.raises(CandidateInputError):
        observe_candidate_inputs(root, base, commit, [], ["out"], ["VAL-A"])
    assert original.canonical_bytes == raw and original.digest == digest
    with pytest.raises(TypeError):
        verify_candidate_inputs(root, original, targets=[])  # type: ignore[call-arg]


@pytest.mark.parametrize("mutation", ["content", "delete", "mode", "staged", "index-delete",
                                      "index-add", "assume", "skip", "intent", "unmerged",
                                      "extra", "extra-delete", "untracked", "ignored"])
def test_input_changes_refuse(repo: tuple[Path, str, str], mutation: str) -> None:
    root, _, _ = repo
    original = observe(repo)
    tracked = root / "lane_a.txt"
    if mutation == "content":
        tracked.write_bytes(b"changed\n")
    elif mutation == "delete":
        tracked.unlink()
    elif mutation == "mode":
        git(root, "config", "core.filemode", "false")
        tracked.chmod(0o755)
    elif mutation == "staged":
        tracked.write_bytes(b"staged\n")
        git(root, "add", "lane_a.txt")
    elif mutation == "index-delete":
        git(root, "rm", "--cached", "lane_a.txt")
    elif mutation == "index-add":
        git(root, "add", "extra.txt")
    elif mutation in {"assume", "skip"}:
        git(root, "update-index", "--assume-unchanged" if mutation == "assume"
            else "--skip-worktree", "lane_a.txt")
        tracked.write_bytes(b"hidden\n")
    elif mutation == "intent":
        git(root, "add", "-N", "extra.txt")
    elif mutation == "unmerged":
        index = root / ".git/index"
        raw = bytearray(index.read_bytes())
        raw[72:74] = struct.pack("!H", 0x1000 | len("lane_a.txt"))
        raw[-20:] = hashlib.sha1(raw[:-20]).digest()
        index.write_bytes(raw)
    elif mutation == "extra":
        (root / "extra.txt").write_bytes(b"changed\n")
    elif mutation == "extra-delete":
        (root / "extra.txt").unlink()
    elif mutation == "untracked":
        (root / "unknown").write_bytes(b"unknown\n")
    else:
        (root / ".git/info/exclude").write_text("unknown\n")
        (root / "unknown").write_bytes(b"ignored\n")
    with pytest.raises(CandidateInputError):
        verify_candidate_inputs(root, original)


@pytest.mark.parametrize("location", ["tracked/output", "extra/output", "tracked/tracked",
                                      "input/outside", "output/outside"])
def test_hardlinks_refuse(repo: tuple[Path, str, str], location: str) -> None:
    root, _, _ = repo
    source = root / ("extra.txt" if location == "extra/output" else "lane_a.txt")
    if location == "tracked/tracked":
        target = root / "lane_b.txt"
        target.unlink()
    elif location.endswith("outside"):
        target = root.parent / "outside"
        if location == "output/outside":
            source = root / "out/result"
            source.write_bytes(b"result")
    else:
        target = root / "out/result"
    os.link(source, target)
    with pytest.raises(CandidateInputError, match="file_alias"):
        observe(repo)


def test_equal_independent_files_and_outputs(repo: tuple[Path, str, str]) -> None:
    root, _, _ = repo
    original = observe(repo)
    (root / "out/same").write_bytes(b"A\n")
    (root / "out/nested").mkdir()
    (root / "out/nested/result").write_bytes(b"variable")
    verify_candidate_inputs(root, original)
    (root / "out/nested/result").write_bytes(b"different")
    verify_candidate_inputs(root, original)


@pytest.mark.parametrize("declaration", ["../escape", "/absolute", "./out", "out/", "a//b",
                                         "a/../b", "*.txt", ".git", "a/.GiT/x", ".unrest/x",
                                         "a\\b", "trailing.", "é", "a\n"])
def test_noncanonical_declarations(repo: tuple[Path, str, str], declaration: str) -> None:
    with pytest.raises(CandidateInputError):
        observe_candidate_inputs(*repo, [], [declaration], [])


@pytest.mark.parametrize("extras,outputs", [(["extra.txt", "extra.txt"], ["out"]),
                                           (["lane_a.txt"], ["out"]),
                                           (["extra.txt"], ["extra.txt"]),
                                           (["extra.txt"], ["lane_a.txt/sub"]),
                                           (["extra.txt"], ["out", "out/sub"]),
                                           (["extra.txt"], ["out", "OUT"])])
def test_overlap(repo: tuple[Path, str, str], extras: list[str], outputs: list[str]) -> None:
    with pytest.raises(CandidateInputError):
        observe_candidate_inputs(*repo, extras, outputs, [])


@pytest.mark.parametrize("mutation", ["input-symlink", "output-symlink", "output-leaf-symlink",
                                      "fifo", "nested", "alias", "missing-output", "output-file"])
def test_unsafe_files(repo: tuple[Path, str, str], mutation: str) -> None:
    root, _, _ = repo
    if mutation == "input-symlink":
        (root / "lane_a.txt").unlink()
        (root / "lane_a.txt").symlink_to(root / "lane_b.txt")
    elif mutation == "output-symlink":
        (root / "out").rmdir()
        (root / "out").symlink_to(root.parent)
    elif mutation == "output-leaf-symlink":
        (root / "out/link").symlink_to(root / "lane_a.txt")
    elif mutation == "fifo":
        os.mkfifo(root / "out/fifo")
    elif mutation == "nested":
        (root / "out/.git").mkdir()
    elif mutation == "alias":
        (root / "out/A").write_text("a")
        (root / "out/a").write_text("a")
        if len(list((root / "out").iterdir())) == 1:
            # Case-insensitive hosts still refuse aliased declarations independently.
            with pytest.raises(CandidateInputError):
                observe_candidate_inputs(*repo, ["extra.txt", "EXTRA.TXT"], ["out"], [])
            return
    elif mutation == "missing-output":
        (root / "out").rmdir()
    else:
        (root / "out").rmdir()
        (root / "out").write_text("file")
    with pytest.raises(CandidateInputError):
        observe(repo)


def test_symlink_ancestor_and_git_indirection(repo: tuple[Path, str, str]) -> None:
    root, base, commit = repo
    link = root.parent / "link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(CandidateInputError, match="root_ancestor"):
        observe((link, base, commit))
    shutil.move(root / ".git", root.parent / "git-dir")
    (root / ".git").write_text("gitdir: ../git-dir\n")
    with pytest.raises(CandidateInputError, match="git_directory"):
        observe(repo)


@pytest.mark.parametrize("key,value", [
    ("filter.canary.clean", "CANARY"), ("filter.canary.smudge", "CANARY"),
    ("diff.canary.textconv", "CANARY"), ("diff.external", "CANARY"),
    ("core.fsmonitor", "CANARY"), ("core.hooksPath", "CANARY"),
    ("credential.helper", "CANARY"), ("remote.origin.url", "ext::CANARY"),
    ("remote.origin.uploadpack", "CANARY"), ("include.path", "CANARY"),
    ("extensions.partialclone", "origin"), ("remote.origin.promisor", "true"),
    ("core.sparsecheckout", "true"), ("extensions.objectformat", "sha256"),
])
def test_config_canaries_never_called(repo: tuple[Path, str, str], key: str, value: str,
                                     monkeypatch: pytest.MonkeyPatch) -> None:
    root, _, _ = repo
    marker = root.parent / "called"
    helper = root.parent / "canary"
    helper.write_text(f"#!/bin/sh\nprintf invoked > '{marker}'\n")
    helper.chmod(0o755)
    git(root, "config", key, value.replace("CANARY", str(helper)))
    calls: list[object] = []
    real = subprocess.Popen
    def spy(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        calls.append(args)
        return real(*args, **kwargs)  # type: ignore[call-overload,no-any-return]
    monkeypatch.setattr(subprocess, "Popen", spy)
    with pytest.raises(CandidateInputError, match="git_config"):
        observe(repo)
    assert not calls and not marker.exists()


def test_ambient_overrides_scrubbed(repo: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    root, _, _ = repo
    original = observe(repo)
    marker = root.parent / "called"
    helper = root.parent / "git"
    helper.write_text(f"#!/bin/sh\nprintf invoked > '{marker}'\n")
    helper.chmod(0o755)
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_SYSTEM", "GIT_EXEC_PATH", "GIT_SSH", "GIT_SSH_COMMAND",
                "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXTERNAL_DIFF", "HOME", "XDG_CONFIG_HOME",
                "PATH"):
        monkeypatch.setenv(key, str(helper))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(helper))
    verify_candidate_inputs(root, original)
    assert not marker.exists()


@pytest.mark.parametrize("path", ["shallow", "objects/info/alternates", "objects/info/http-alternates",
                                   "objects/pack/pack-x.promisor", "objects/pack/pack-x.pack",
                                   "refs/replace/replaced", "info/grafts", "commondir",
                                   "hooks/pre-commit", "config.worktree"])
def test_metadata_refusal_before_git(repo: tuple[Path, str, str], path: str,
                                     monkeypatch: pytest.MonkeyPatch) -> None:
    root, _, _ = repo
    target = root / ".git" / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("unsupported\n")
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Git called for unsupported metadata")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises(CandidateInputError, match="unsupported_git_metadata"):
        observe(repo)


def test_wrong_ids_types_and_unrelated_history(repo: tuple[Path, str, str]) -> None:
    root, base, commit = repo
    tree = git(root, "rev-parse", "HEAD^{tree}")
    blob = git(root, "rev-parse", "HEAD:lane_a.txt")
    for wrong in ("0" * 40, tree, blob, "HEAD", base[:12], base.upper()):
        with pytest.raises(CandidateInputError):
            observe((root, wrong, commit))
        with pytest.raises(CandidateInputError):
            observe((root, base, wrong))
    other = git(root, "commit-tree", tree, "-m", "unrelated")
    with pytest.raises(CandidateInputError, match="unrelated_base"):
        observe((root, other, commit))
    assert observe((root, commit, commit)).base_oid == commit


@pytest.mark.parametrize("kind", ["candidate", "base", "tree", "blob", "ancestry"])
@pytest.mark.parametrize("corruption", ["wrong-content", "wrong-type", "missing", "truncated"])
def test_raw_object_integrity(repo: tuple[Path, str, str], kind: str, corruption: str) -> None:
    root, base, commit = repo
    if kind == "ancestry":
        # Current base is the candidate, forcing independent traversal of its parent.
        oid = base
        repo = root, commit, commit
    else:
        oid = {"candidate": commit, "base": base,
               "tree": git(root, "rev-parse", "HEAD^{tree}"),
               "blob": git(root, "rev-parse", "HEAD:lane_a.txt")}[kind]
    path = root / ".git/objects" / oid[:2] / oid[2:]
    path.chmod(0o644)
    raw = zlib.decompress(path.read_bytes())
    if corruption == "missing":
        path.unlink()
    elif corruption == "truncated":
        path.write_bytes(path.read_bytes()[:4])
    elif corruption == "wrong-type":
        path.write_bytes(zlib.compress(b"tag 2\0x\n"))
    else:
        header, body = raw.split(b"\0", 1)
        # Valid zlib and Git header/length, wrong content under the expected full name.
        body = body[:-1] + bytes([body[-1] ^ 1])
        path.write_bytes(zlib.compress(header + b"\0" + body))
    with pytest.raises(CandidateInputError):
        observe(repo)


def test_object_size_count_aggregate_deadlines(repo: tuple[Path, str, str],
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    root, _, commit = repo
    for constant, value in (("MAX_OBJECTS", 1), ("MAX_TOTAL_BYTES", 1),
                            ("COMMAND_SECONDS", 0), ("OBSERVATION_SECONDS", 0)):
        with monkeypatch.context() as scoped:
            scoped.setattr(candidate, constant, value)
            with pytest.raises(CandidateInputError):
                observe(repo)
    path = root / ".git/objects" / commit[:2] / commit[2:]
    path.chmod(0o644)
    body = b"x" * (candidate.MAX_FILE_BYTES + 1)
    path.write_bytes(zlib.compress(f"commit {len(body)}\0".encode() + body))
    with pytest.raises(CandidateInputError, match="object_size"):
        observe(repo)


def snapshot(root: Path) -> dict[str, tuple[int, bytes]]:
    return {p.relative_to(root).as_posix(): (p.stat().st_mode, p.read_bytes())
            for p in sorted(root.rglob("*")) if p.is_file()}


def test_observer_leaves_all_repository_bytes_and_modes_unchanged(repo: tuple[Path, str, str]) -> None:
    root, _, _ = repo
    before = snapshot(root)
    original = observe(repo)
    verify_candidate_inputs(root, original)
    assert snapshot(root) == before
    (root / "lane_a.txt").write_bytes(b"changed")
    before = snapshot(root)
    with pytest.raises(CandidateInputError):
        verify_candidate_inputs(root, original)
    assert snapshot(root) == before


@pytest.mark.parametrize("mode", ["120000", "160000"])
def test_unsupported_tree_entries(repo: tuple[Path, str, str], mode: str) -> None:
    root, base, _ = repo
    oid = base if mode == "160000" else git(root, "rev-parse", "HEAD:lane_a.txt")
    git(root, "update-index", "--add", "--cacheinfo", f"{mode},{oid},unsupported")
    git(root, "commit", "-m", "unsupported")
    commit = git(root, "rev-parse", "HEAD")
    with pytest.raises(CandidateInputError, match="tree_mode"):
        observe((root, base, commit))


def test_manifest_constructor_cannot_retain_mutable_values(repo: tuple[Path, str, str]) -> None:
    manifest = observe(repo)
    with pytest.raises(CandidateInputError):
        replace(manifest, targets=["VAL-A"])  # type: ignore[arg-type]
    with pytest.raises(CandidateInputError):
        replace(manifest.tracked_inputs[0], path=[])  # type: ignore[arg-type]
    with pytest.raises(CandidateInputError, match="manifest_changed"):
        verify_candidate_inputs(repo[0], replace(manifest, candidate_tree_oid="0" * 40))


@pytest.mark.parametrize("mutation", ["mode", "checksum", "version", "extension", "missing"])
def test_index_independent_refusals(repo: tuple[Path, str, str], mutation: str) -> None:
    index = repo[0] / ".git/index"
    raw = bytearray(index.read_bytes())
    if mutation == "missing":
        index.unlink()
    else:
        if mutation == "mode":
            raw[36:40] = struct.pack("!I", 0o100755)
        elif mutation == "checksum":
            raw[12] ^= 1
        elif mutation == "version":
            raw[4:8] = struct.pack("!I", 3)
        else:
            raw[-20:-20] = b"sdir\0\0\0\0"
        if mutation != "checksum":
            raw[-20:] = hashlib.sha1(raw[:-20]).digest()
        index.write_bytes(raw)
    with pytest.raises(CandidateInputError):
        observe(repo)


def test_nested_bare_repository_refuses(repo: tuple[Path, str, str]) -> None:
    nested = repo[0] / "out/bare"
    nested.mkdir()
    (nested / "HEAD").write_text("ref: refs/heads/main\n")
    (nested / "objects").mkdir()
    (nested / "refs").mkdir()
    with pytest.raises(CandidateInputError, match="nested_repository"):
        observe(repo)


def test_executable_tracked_file_and_nested_extra(repo: tuple[Path, str, str]) -> None:
    root, base, _ = repo
    (root / "lane_a.txt").chmod(0o755)
    git(root, "add", "lane_a.txt")
    git(root, "commit", "-m", "executable")
    commit = git(root, "rev-parse", "HEAD")
    (root / "inputs").mkdir()
    (root / "extra.txt").rename(root / "inputs/extra.txt")
    manifest = observe_candidate_inputs(root, base, commit, ["inputs/extra.txt"], ["out"], [])
    assert manifest.tracked_inputs[0].mode == "100755"
    verify_candidate_inputs(root, manifest)
    (root / "inputs/extra.txt").unlink()
    (root / "inputs").rmdir()
    (root / "inputs").symlink_to(root.parent)
    with pytest.raises(CandidateInputError):
        verify_candidate_inputs(root, manifest)


def shared_empty_tree(observation: candidate._Observation, depth: int) -> str:
    raw = b""
    for _ in range(depth + 1):
        oid = hashlib.sha1(f"tree {len(raw)}\0".encode() + raw).hexdigest()
        observation.objects[oid] = ("tree", raw)
        raw = b"40000 a\0" + bytes.fromhex(oid) + b"40000 b\0" + bytes.fromhex(oid)
    return oid


def test_shared_empty_tree_counts_expanded_directories(tmp_path: Path,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    observation = candidate._Observation(tmp_path)
    oid = shared_empty_tree(observation, 14)
    monkeypatch.setattr(candidate, "MAX_ENTRIES", 20)
    with pytest.raises(CandidateInputError, match="^tree_count$"):
        observation.tree(oid)
    assert observation.tree_entries == 21
    assert len(observation.objects) == 15


def test_expired_cached_empty_tree(tmp_path: Path) -> None:
    observation = candidate._Observation(tmp_path)
    oid = shared_empty_tree(observation, 0)
    observation.deadline = 0
    with pytest.raises(CandidateInputError, match="^observation_deadline$"):
        observation.tree(oid)


@pytest.mark.parametrize("worktree", [False, True])
@pytest.mark.parametrize("existing", [0, 2])
def test_directory_admission_stops_before_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, worktree: bool, existing: int,
) -> None:
    from types import SimpleNamespace

    consumed = 0
    closed = False

    class Guarded:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            nonlocal closed
            closed = True

        def __iter__(self):
            nonlocal consumed
            for i in range(100):
                consumed += 1
                assert consumed <= 4 - existing, "enumeration exhausted the guarded input"
                yield SimpleNamespace(name=f"entry-{i}")

    monkeypatch.setattr(candidate.os, "scandir", lambda _: Guarded())
    monkeypatch.setattr(candidate, "MAX_ENTRIES", 3)
    observation = candidate._Observation(tmp_path)
    observation.entries = existing
    with pytest.raises(CandidateInputError, match="^entry_count$"):
        observation.walk(tmp_path, worktree=worktree)
    assert consumed == 4 - existing
    assert closed


def test_directory_enumeration_checks_deadline(tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    observation = candidate._Observation(tmp_path)

    class Expiring:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def __iter__(self):
            observation.deadline = 0
            yield SimpleNamespace(name="first")
            pytest.fail("enumeration continued after deadline")

    monkeypatch.setattr(candidate.os, "scandir", lambda _: Expiring())
    with pytest.raises(CandidateInputError, match="^observation_deadline$"):
        observation.walk(tmp_path)
    assert observation.entries == 0


def test_declarations_reject_custom_containers(repo: tuple[Path, str, str]) -> None:
    class Hostile(list):
        def __len__(self):
            pytest.fail("custom length executed")

        def __iter__(self):
            pytest.fail("custom iteration executed")

    with pytest.raises(CandidateInputError, match="^declarations$"):
        observe_candidate_inputs(*repo, Hostile(), [], [])


def test_declaration_deadline_starts_before_validation(repo: tuple[Path, str, str],
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    now = 0.0
    original = candidate._path
    calls = 0

    def expiring(value):
        nonlocal now, calls
        calls += 1
        now = 61.0
        return original(value)

    monkeypatch.setattr(candidate.time, "monotonic", lambda: now)
    monkeypatch.setattr(candidate, "_path", expiring)
    with pytest.raises(CandidateInputError, match="^observation_deadline$"):
        observe_candidate_inputs(*repo, ["a", "b"], [], [])
    assert calls == 1


def test_overlap_loop_checks_deadline(repo: tuple[Path, str, str],
                                      monkeypatch: pytest.MonkeyPatch) -> None:
    original = candidate._overlap
    calls = 0
    monotonic = candidate.time.monotonic

    def expiring(left, right):
        nonlocal calls
        calls += 1
        monkeypatch.setattr(candidate.time, "monotonic", lambda: monotonic() + 61)
        return original(left, right)

    monkeypatch.setattr(candidate, "_overlap", expiring)
    with pytest.raises(CandidateInputError, match="^observation_deadline$"):
        observe(repo)
    assert calls == 1


def test_observation_and_verification_create_no_object_read_children(
    repo: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = observe(repo)
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("candidate object observation launched a process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert observe(repo) == original
    verify_candidate_inputs(repo[0], original)
