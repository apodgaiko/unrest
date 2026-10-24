"""Nonpersistent input identity for stable, controller-owned disposable repositories."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import time
import zlib

from .canonical_identity import canonical_json_bytes, verify_canonical_json_bytes


DOMAIN = b"unrest.experimental-candidate-inputs.v1\0"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_OBJECTS = 512
COMMAND_SECONDS = 5.0
OBSERVATION_SECONDS = 60.0
_OID = re.compile(r"[0-9a-f]{40}")
_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+")
_CONTROL = {".git", ".unrest", ".unrest-runtime"}


class CandidateInputError(ValueError):
    """Refusal code only: never include file bodies or command stderr."""


@dataclass(frozen=True, slots=True)
class InputFile:
    path: str
    mode: str
    size: int
    sha256: str

    def __post_init__(self) -> None:
        _require(all(type(v) is str for v in (self.path, self.mode, self.sha256))
                 and type(self.size) is int, "manifest_file")


@dataclass(frozen=True, slots=True)
class CandidateManifest:
    base_oid: str
    candidate_commit_oid: str
    candidate_tree_oid: str
    tracked_inputs: tuple[InputFile, ...]
    extra_inputs: tuple[InputFile, ...]
    extra_input_files: tuple[str, ...]
    output_directories: tuple[str, ...]
    targets: tuple[str, ...]

    def __post_init__(self) -> None:
        # Frozen fields alone would still permit caller-supplied mutable lists.
        for values in (self.tracked_inputs, self.extra_inputs):
            _require(type(values) is tuple and all(type(v) is InputFile for v in values),
                     "manifest_inventory")
        for declarations in (self.extra_input_files, self.output_directories, self.targets):
            _require(type(declarations) is tuple and all(type(v) is str for v in declarations),
                     "manifest_declarations")
        _require(all(type(v) is str for v in
                     (self.base_oid, self.candidate_commit_oid, self.candidate_tree_oid)),
                 "manifest_identity")

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes({"schema": "experimental-candidate-inputs.v1", **asdict(self)})

    @property
    def digest(self) -> str:
        raw = self.canonical_bytes
        verify_canonical_json_bytes(raw)
        return "sha256:" + hashlib.sha256(DOMAIN + raw).hexdigest()


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CandidateInputError(code)


def _path(value: str) -> str:
    _require(type(value) is str and 0 < len(value) <= 512, "path")
    parts = value.split("/")
    _require(len(parts) <= 32 and all(
        _COMPONENT.fullmatch(part) is not None and part not in {".", ".."}
        and not part.endswith(".") and part.casefold() not in _CONTROL
        for part in parts
    ), "path")
    return value


def _declarations(values: list[str] | tuple[str, ...], observation: _Observation, *, paths: bool) -> tuple[str, ...]:
    observation.tick()
    _require(type(values) in {list, tuple} and len(values) <= MAX_ENTRIES, "declarations")
    result = tuple(values)
    for value in result:
        observation.tick()
        if paths:
            _path(value)
        else:
            _require(type(value) is str and len(value) <= 128 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",
                                                       value) is not None, "target")
    _require(len(set(result)) == len(result), "duplicate_declaration")
    ordered = tuple(sorted(result))
    observation.tick()
    return ordered


def _overlap(left: str, right: str) -> bool:
    a, b = left.casefold(), right.casefold()
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


class _Observation:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.deadline = time.monotonic() + OBSERVATION_SECONDS
        self.total = 0
        self.entries = 0
        self.worktree_entries = 0
        self.tree_entries = 0
        self.objects: dict[str, tuple[str, bytes]] = {}

    def tick(self) -> None:
        _require(time.monotonic() < self.deadline, "observation_deadline")

    def read(self, path: Path) -> bytes:
        self.tick()
        size = path.lstat().st_size
        _require(size <= MAX_FILE_BYTES, "file_size")
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        _require(len(raw) == size and len(raw) <= MAX_FILE_BYTES, "file_size")
        self.account(len(raw))
        return raw

    def account(self, size: int) -> None:
        self.tick()
        self.total += size
        _require(self.total <= MAX_TOTAL_BYTES, "aggregate_size")

    def object(self, oid: str, kind: str) -> bytes:
        self.tick()
        _require(_OID.fullmatch(oid) is not None, "oid")
        if oid not in self.objects:
            _require(len(self.objects) < MAX_OBJECTS, "object_count")
            # No packed/promisor/alternate storage is admitted. Missing objects fail locally.
            location = self.root / ".git" / "objects" / oid[:2] / oid[2:]
            _require(location.is_file(), "missing_object")
            deadline = min(self.deadline, time.monotonic() + COMMAND_SECONDS)
            _require(time.monotonic() < deadline, "git_deadline")
            compressed = self.read(location)
            decoder = zlib.decompressobj()
            try:
                expanded = decoder.decompress(compressed, MAX_FILE_BYTES + 65)
            except zlib.error:
                raise CandidateInputError("git_object") from None
            _require(not decoder.unconsumed_tail and len(expanded) <= MAX_FILE_BYTES + 64,
                     "object_size")
            _require(decoder.eof and not decoder.unused_data, "git_object")
            header, separator, raw = expanded.partition(b"\0")
            _require(bool(separator) and len(header) <= 64, "git_object")
            encoded_kind, space, size = header.partition(b" ")
            _require(encoded_kind == kind.encode("ascii"), "object_type")
            _require(bool(space) and size == str(len(raw)).encode("ascii"), "git_object")
            _require(len(raw) <= MAX_FILE_BYTES, "object_size")
            _require(hashlib.sha1(expanded).hexdigest() == oid, "object_hash")
            self.account(len(raw))
            _require(time.monotonic() < deadline, "git_deadline")
            self.objects[oid] = (kind, raw)
        observed_kind, raw = self.objects[oid]
        _require(observed_kind == kind, "object_type")
        return raw

    def children(self, directory: Path, *, worktree: bool) -> list[Path]:
        # Path.iterdir may materialize the entire directory before yielding.
        admitted: list[Path] = []
        self.tick()
        with os.scandir(directory) as stream:
            for entry in stream:
                self.tick()
                self.entries += 1
                _require(self.entries <= MAX_ENTRIES, "entry_count")
                if worktree:
                    self.worktree_entries += 1
                    _require(self.worktree_entries <= MAX_ENTRIES, "entry_count")
                admitted.append(directory / entry.name)
        self.tick()
        admitted.sort()
        self.tick()
        return admitted

    def walk(self, root: Path, *, worktree: bool = False) -> list[tuple[str, os.stat_result]]:
        found: list[tuple[str, os.stat_result]] = []
        pending = [root]
        while pending:
            self.tick()
            directory = pending.pop()
            for path in self.children(directory, worktree=worktree):
                self.tick()
                if worktree and directory == self.root and path.name == ".git":
                    continue
                info = path.lstat()
                _require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "file_kind")
                found.append((path.relative_to(root).as_posix(), info))
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
        ordered = sorted(found)
        self.tick()
        return ordered

    def metadata(self) -> None:
        git = self.root / ".git"
        _require(stat.S_ISDIR(git.lstat().st_mode), "git_directory")
        entries = self.walk(git)
        files = {name for name, info in entries if stat.S_ISREG(info.st_mode)}
        _require({"HEAD", "config", "index"} <= files, "git_metadata")
        for name, info in entries:
            self.tick()
            parts = name.split("/")
            if stat.S_ISDIR(info.st_mode):
                allowed = name in {"branches", "objects", "objects/info", "objects/pack", "refs",
                                   "refs/heads", "refs/tags", "logs", "logs/refs",
                                   "logs/refs/heads", "hooks", "info"}
                allowed |= bool(re.fullmatch(r"objects/[0-9a-f]{2}", name))
                allowed |= name.startswith(("refs/heads/", "refs/tags/", "logs/refs/heads/"))
            else:
                _require(info.st_size <= MAX_FILE_BYTES, "metadata_size")
                allowed = name in {"HEAD", "config", "index", "description", "COMMIT_EDITMSG",
                                   "ORIG_HEAD", "info/exclude", "logs/HEAD"}
                allowed |= bool(re.fullmatch(r"objects/[0-9a-f]{2}/[0-9a-f]{38}", name))
                allowed |= (len(parts) == 2 and parts[0] == "hooks"
                            and parts[1].endswith(".sample"))
                allowed |= name.startswith(("refs/heads/", "refs/tags/", "logs/refs/heads/"))
            _require(allowed, "unsupported_git_metadata")
            _require(all(_COMPONENT.fullmatch(p) and p not in {".", ".."} for p in parts),
                     "git_metadata_path")
        # This intentionally does not implement Git's config language. Anything outside
        # this controller fixture grammar refuses before an affected Git command.
        section = ""
        seen: set[tuple[str, str]] = set()
        for line in self.read(git / "config").decode("ascii").splitlines():
            self.tick()
            line = line.strip()
            if not line:
                continue
            if line in {"[core]", "[user]"}:
                section = line[1:-1]
                continue
            match = re.fullmatch(r"([a-zA-Z]+)\s*=\s*([ -~]+)", line)
            _require(match is not None, "git_config")
            assert match is not None
            key, value = match[1].lower(), match[2]
            _require((section, key) not in seen, "git_config")
            seen.add((section, key))
            allowed_value = (section == "user" and key in {"name", "email"}
                             and re.fullmatch(r"[A-Za-z0-9 @_.+<>-]+", value) is not None)
            allowed_value |= section == "core" and (
                (key == "repositoryformatversion" and value == "0")
                or (key == "bare" and value == "false")
                or (key in {"filemode", "logallrefupdates", "ignorecase", "precomposeunicode"}
                    and value in {"true", "false"}))
            _require(allowed_value, "git_config")
        _require({("core", "repositoryformatversion"), ("core", "bare")} <= seen, "git_config")

    def head(self) -> str:
        head = self.read(self.root / ".git/HEAD").decode("ascii").strip()
        if head.startswith("ref: refs/heads/"):
            ref = head[5:]
            _path(ref)
            head = self.read(self.root / ".git" / ref).decode("ascii").strip()
        _require(_OID.fullmatch(head) is not None, "head")
        return head

    def commit(self, oid: str) -> tuple[str, tuple[str, ...]]:
        raw = self.object(oid, "commit")
        header, separator, _ = raw.partition(b"\n\n")
        _require(bool(separator), "commit_encoding")
        lines = header.split(b"\n")
        _require(lines[0].startswith(b"tree "), "commit_tree")
        tree = lines[0][5:].decode("ascii")
        _require(_OID.fullmatch(tree) is not None, "commit_tree")
        tree_count = 0
        parents: list[str] = []
        for line in lines:
            self.tick()
            tree_count += line.startswith(b"tree ")
            if line.startswith(b"parent "):
                parent = line[7:].decode("ascii")
                _require(_OID.fullmatch(parent) is not None, "commit_parent")
                parents.append(parent)
        _require(tree_count == 1, "commit_tree")
        return tree, tuple(parents)

    def tree(self, oid: str, prefix: str = "") -> dict[str, tuple[str, str, bytes]]:
        raw = self.object(oid, "tree")
        result: dict[str, tuple[str, str, bytes]] = {}
        names: set[str] = set()
        offset = 0
        while offset < len(raw):
            self.tick()
            self.tree_entries += 1
            _require(self.tree_entries <= MAX_ENTRIES, "tree_count")
            end = raw.find(b"\0", offset)
            _require(end >= 0 and end + 21 <= len(raw), "tree_encoding")
            descriptor = raw[offset:end].split(b" ")
            _require(len(descriptor) == 2, "tree_encoding")
            mode, name = (part.decode("ascii") for part in descriptor)
            _require("/" not in name and name not in names, "tree_path")
            names.add(name)
            path = _path(prefix + name)
            child = raw[end + 1:end + 21].hex()
            offset = end + 21
            if mode == "40000":
                result.update(self.tree(child, path + "/"))
            else:
                _require(mode in {"100644", "100755"}, "tree_mode")
                result[path] = (mode, child, self.object(child, "blob"))
        self.tick()
        return result

    def index(self) -> dict[str, tuple[str, str]]:
        raw = self.read(self.root / ".git/index")
        _require(len(raw) >= 32 and raw[:4] == b"DIRC", "index_header")
        _require(hashlib.sha1(raw[:-20]).digest() == raw[-20:], "index_hash")
        version, count = struct.unpack("!II", raw[4:12])
        _require(version == 2 and count <= MAX_ENTRIES, "index_version")
        result: dict[str, tuple[str, str]] = {}
        offset = 12
        for _ in range(count):
            self.tick()
            start = offset
            _require(offset + 62 < len(raw) - 20, "index_encoding")
            mode = struct.unpack("!I", raw[offset + 24:offset + 28])[0]
            oid = raw[offset + 40:offset + 60].hex()
            flags = struct.unpack("!H", raw[offset + 60:offset + 62])[0]
            _require(flags & 0xF000 == 0, "index_flags")
            end = raw.find(b"\0", offset + 62, len(raw) - 20)
            _require(end >= 0, "index_encoding")
            name = _path(raw[offset + 62:end].decode("ascii"))
            _require(flags & 0xFFF == len(name), "index_flags")
            offset = start + ((end - start + 1 + 7) // 8) * 8
            _require(raw[end:offset] == bytes(offset - end), "index_padding")
            _require(name not in result and mode in {0o100644, 0o100755}, "index_entry")
            result[name] = (f"{mode:o}", oid)
        while offset < len(raw) - 20:
            self.tick()
            _require(raw[offset:offset + 4] == b"TREE" and offset + 8 <= len(raw) - 20,
                     "index_extension")
            length = struct.unpack("!I", raw[offset + 4:offset + 8])[0]
            offset += 8 + length
        _require(offset == len(raw) - 20, "index_encoding")
        self.tick()
        return result


def observe_candidate_inputs(
    root: Path, expected_base_oid: str, expected_candidate_commit_oid: str,
    extra_input_files: list[str] | tuple[str, ...], output_directories: list[str] | tuple[str, ...], targets: list[str] | tuple[str, ...],
) -> CandidateManifest:
    """Observe without writes. Caller guarantees stable custody for the whole call."""
    try:
        return _observe(root, expected_base_oid, expected_candidate_commit_oid,
                        extra_input_files, output_directories, targets)
    except (OSError, UnicodeError, struct.error) as error:
        raise CandidateInputError("observation_failed") from error


def _observe(
    root: Path, base: str, candidate: str, extras: list[str] | tuple[str, ...], outputs: list[str] | tuple[str, ...],
    targets: list[str] | tuple[str, ...],
) -> CandidateManifest:
    observation = _Observation(root)
    observation.tick()
    _require(type(base) is str and _OID.fullmatch(base) is not None, "base_oid")
    _require(type(candidate) is str and _OID.fullmatch(candidate) is not None, "candidate_oid")
    root = Path(root)
    observation.root = root
    _require(root.is_absolute() and ".." not in root.parts, "root")
    for ancestor in (*reversed(root.parents), root):
        observation.tick()
        _require(stat.S_ISDIR(ancestor.lstat().st_mode), "root_ancestor")
    extra_paths = _declarations(extras, observation, paths=True)
    output_paths = _declarations(outputs, observation, paths=True)
    target_names = _declarations(targets, observation, paths=False)
    observation.metadata()
    _require(observation.head() == candidate, "candidate_head")
    base_tree, _ = observation.commit(base)
    candidate_tree, _ = observation.commit(candidate)
    pending = [candidate]
    visited: set[str] = set()
    while pending:
        observation.tick()
        oid = pending.pop()
        if oid not in visited:
            visited.add(oid)
            _, parents = observation.commit(oid)
            pending.extend(parents)
    _require(base in visited, "unrelated_base")
    observation.tree(base_tree)
    tracked = observation.tree(candidate_tree)
    _require(observation.index() == {p: (v[0], v[1]) for p, v in tracked.items()}, "index_tree")
    declarations = tuple(tracked) + extra_paths + output_paths
    for i, left in enumerate(declarations):
        observation.tick()
        for right in declarations[i + 1:]:
            observation.tick()
            _require(not _overlap(left, right), "declaration_overlap")
    # Walk separately to exclude only the already inspected root Git metadata.
    entries = observation.walk(root, worktree=True)
    inodes: set[tuple[int, int]] = set()
    aliases: dict[str, str] = {}
    observed: dict[str, InputFile] = {}
    directories: set[str] = set()
    for path, info in sorted(entries):
        observation.tick()
        _path(path)
        alias = path.casefold()
        _require(alias not in aliases, "path_alias")
        aliases[alias] = path
        is_output = False
        for out in output_paths:
            observation.tick()
            if path == out or path.startswith(out + "/"):
                is_output = True
                break
        if stat.S_ISDIR(info.st_mode):
            directories.add(path)
            directory = root / path
            _require(not ((directory / "HEAD").exists() and (directory / "objects").exists()
                          and (directory / "refs").exists()), "nested_repository")
            known_directory = is_output
            if not known_directory:
                for declaration in declarations:
                    observation.tick()
                    if declaration.startswith(path + "/"):
                        known_directory = True
                        break
            _require(known_directory, "unknown_directory")
            continue
        _require(stat.S_ISREG(info.st_mode), "file_kind")
        inode = (info.st_dev, info.st_ino)
        _require(info.st_nlink == 1 and inode not in inodes, "file_alias")
        inodes.add(inode)
        _require(path not in output_paths, "output_directory")
        if is_output:
            continue
        _require(path in tracked or path in extra_paths, "unknown_input")
        raw = observation.read(root / path)
        permissions = stat.S_IMODE(info.st_mode)
        _require(permissions in {0o644, 0o755}, "worktree_mode")
        mode = "100755" if permissions == 0o755 else "100644"
        if path in tracked:
            _require((mode, raw) == (tracked[path][0], tracked[path][2]), "worktree_tree")
        observed[path] = InputFile(path, mode, len(raw), hashlib.sha256(raw).hexdigest())
    _require(set(tracked) | set(extra_paths) == set(observed), "missing_input")
    _require(set(output_paths) <= directories, "missing_output_directory")
    manifest = CandidateManifest(base, candidate, candidate_tree,
                             tuple(observed[p] for p in sorted(tracked)),
                             tuple(observed[p] for p in extra_paths), extra_paths,
                             output_paths, target_names)
    observation.tick()
    return manifest


def verify_candidate_inputs(root: Path, original_manifest: CandidateManifest) -> None:
    """Reobserve with the controller's retained binding, never replacement declarations.

    A content digest is not authentication; caller-supplied rehashed values convey
    no custody, accepted-point, integration, or recovery authority.
    """
    _require(type(original_manifest) is CandidateManifest, "manifest_type")
    observed = observe_candidate_inputs(
        root, original_manifest.base_oid, original_manifest.candidate_commit_oid,
        original_manifest.extra_input_files, original_manifest.output_directories,
        original_manifest.targets,
    )
    _require(observed.canonical_bytes == original_manifest.canonical_bytes, "manifest_changed")
