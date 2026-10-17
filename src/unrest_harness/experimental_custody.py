"""Controller-only Git custody around the restricted flat turn broker."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

from .experimental_candidate import (
    CandidateManifest, InputFile, observe_candidate_inputs, verify_candidate_inputs,
)
from .experimental_lease import Completion, LeaseRefused, TurnBroker


def write_record(path: Path, value: object) -> None:
    """Replace one controller record durably, including the containing directory."""
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    temporary = path.with_suffix('.tmp')
    with temporary.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def git(root: Path, *arguments: str) -> str:
    """Only controller-generated argument templates; no ambient Git helpers."""
    try:
        result = subprocess.run(
            ['/usr/bin/git', '--no-replace-objects', *arguments], cwd=root,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
                 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
                 'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                 'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid',
                 'GIT_AUTHOR_DATE': '2000-01-01T00:00:00+0000',
                 'GIT_COMMITTER_DATE': '2000-01-01T00:00:00+0000'},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5, check=True,
        )
        if len(result.stdout) > 1048576:
            raise LeaseRefused('git_output_bound')
        return result.stdout.decode('ascii').strip()
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise LeaseRefused('git_custody_failed') from None


def flat_digest(root: Path, scope: tuple[str, ...]) -> str:
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    values = []
    try:
        if tuple(sorted(os.listdir(directory))) != scope:
            raise LeaseRefused('broker_inventory_changed')
        for name in scope:
            if '/' in name or name in ('.', '..'):
                raise LeaseRefused('broker_path_invalid')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1048576:
                    raise LeaseRefused('broker_file_invalid')
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    raw = stream.read(1048577)
                if len(raw) != info.st_size:
                    raise LeaseRefused('broker_file_changed')
                values.append((name, hashlib.sha256(raw).hexdigest()))
            finally:
                os.close(fd)
    finally:
        os.close(directory)
    return hashlib.sha256(json.dumps(values, separators=(',', ':')).encode()).hexdigest()


class Custody:
    """Last sealed Git revision stays unchanged while the broker mutates a copy.

    This initial composition supports flat regular text inputs only. Git metadata
    never enters the broker root. Unsupported repositories refuse through the
    existing observer before materialization or any mutating Git command.
    """

    def __init__(self, root: Path, broker_root: Path, record: Path, *, base: str,
                 commit: str, writes: tuple[str, ...], targets: tuple[str, ...],
                 extras: tuple[str, ...] = (), outputs: tuple[str, ...] = ()):
        self.root, self.broker_root, self.record = root, broker_root, record
        if commit != base:
            raise LeaseRefused('initial_candidate_not_base')
        self.manifest = observe_candidate_inputs(root, base, commit, extras, outputs, targets)
        files = self.manifest.tracked_inputs
        if (not writes or tuple(sorted(set(writes))) != writes
                or not set(writes) <= {f.path for f in files}
                or any('/' in f.path or f.mode != '100644' or f.size > 1048576
                       for f in (*files, *self.manifest.extra_inputs))
                or sum(f.size for f in (*files, *self.manifest.extra_inputs)) > 32768):
            raise LeaseRefused('unsupported_custody_structure')
        self.writes = writes
        self._authority = (root, broker_root, record, base, writes, targets, extras, outputs)
        self.resource_digest: str | None = None
        self.broker_root.mkdir(mode=0o700)
        for name in writes:
            (broker_root / name).write_bytes((root / name).read_bytes())
            (broker_root / name).chmod(0o600)
        self.expected = flat_digest(broker_root, writes)
        self._persist()

    def _persist(self) -> None:
        manifest = self.manifest
        digest = manifest.digest
        snapshot = self.record.parent / (self.record.stem + '-' + digest[7:])
        if not snapshot.exists():
            # A new manifest was fully observed by the constructor or seal.
            # Verify the copied bytes against that expectation before publication;
            # preserve unexpected links so verification refuses without following them.
            shutil.copytree(self.root, snapshot, symlinks=True)
        verify_candidate_inputs(snapshot, manifest)
        for directory, directories, files in os.walk(snapshot, topdown=False):
            for name in sorted(files):
                fd = os.open(Path(directory) / name, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        if self.manifest is not manifest:
            raise LeaseRefused('candidate_authority_changed')
        write_record(self.record, {'manifest': asdict(manifest),
                                   'manifest_digest': digest,
                                   'broker_digest': self.expected,
                                   'writes': self.writes, 'snapshot': snapshot.name,
                                   'authority_digest': self._authority_digest(digest),
                                   'resource_digest': self.resource_digest})

    @property
    def authority_digest(self) -> str:
        return self._authority_digest(self.manifest.digest)

    def _authority_digest(self, candidate_digest: str) -> str:
        return hashlib.sha256(json.dumps({
            'candidate': candidate_digest, 'namespace': str(self.root),
            'broker': str(self.broker_root), 'writes': self.writes,
            'resources': self.resource_digest,
        }, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def bind_resources(self, digest: str) -> None:
        if self.resource_digest is not None:
            raise LeaseRefused('resources_already_bound')
        self.resource_digest = digest
        self._persist()

    def verify(self) -> None:
        if (self.root, self.broker_root, self.record, self.manifest.base_oid, self.writes,
                self.manifest.targets, self.manifest.extra_input_files,
                self.manifest.output_directories) != self._authority:
            raise LeaseRefused('candidate_authority_changed')
        verify_candidate_inputs(self.root, self.manifest)

    def context(self) -> str:
        self.verify()
        files = {f.path: (self.root / f.path).read_text('utf-8')
                 for f in (*self.manifest.tracked_inputs, *self.manifest.extra_inputs)
                 if f.path not in self.writes}
        self.verify()
        return json.dumps({'read_only_inputs': files, 'targets': self.manifest.targets},
                          sort_keys=True)

    def seal(self, broker: TurnBroker, completion: Completion) -> CandidateManifest:
        self.verify()
        if (broker._active is not None or completion.identity.role != 'worker'
                or completion.disposition != 'sealed'
                or completion.identity.scope != self.writes
                or broker.completion(completion.identity) != completion):
            raise LeaseRefused('mutation_not_drained')
        bodies = broker.contents(self.writes)
        if broker.verify(self.writes) != completion.sealed_candidate:
            raise LeaseRefused('stale_broker_completion')
        # Every non-scope byte is retained from the last controller seal. Failure
        # before publishing the new record leaves the old record as recovery truth.
        for name, body in bodies.items():
            (self.root / name).write_text(body, encoding='utf-8')
            (self.root / name).chmod(0o644)
        git(self.root, 'add', '--', *self.writes)
        staged = git(self.root, 'diff', '--cached', '--name-only', self.manifest.candidate_commit_oid)
        if not set(staged.splitlines()) <= set(self.writes):
            raise LeaseRefused('staged_scope_changed')
        git(self.root, 'commit', '--allow-empty', '-m', 'sealed candidate')
        commit = git(self.root, 'rev-parse', 'HEAD')
        candidate = observe_candidate_inputs(
            self.root, self.manifest.base_oid, commit, self.manifest.extra_input_files,
            self.manifest.output_directories, self.manifest.targets)
        previous = {f.path: f for f in self.manifest.tracked_inputs if f.path not in self.writes}
        if ({f.path: f for f in candidate.tracked_inputs if f.path not in self.writes} != previous
                or candidate.extra_inputs != self.manifest.extra_inputs):
            raise LeaseRefused('seal_input_changed')
        for f in candidate.tracked_inputs:
            if f.path in bodies and f.sha256 != hashlib.sha256(bodies[f.path].encode()).hexdigest():
                raise LeaseRefused('seal_output_changed')
        self.manifest, self.expected = candidate, completion.sealed_candidate
        self._persist()
        return candidate


def integrate(destination: Path, base: CandidateManifest, lanes: tuple[Custody, ...]) -> CandidateManifest:
    """Serial authored order; caller must establish all-passing evidence first."""
    verify_candidate_inputs(destination, base)
    paths = [name for lane in lanes for name in lane.writes]
    if len(set(paths)) != len(paths):
        raise LeaseRefused('integration_scope_collision')
    current = base
    for lane in lanes:
        lane.verify()
        if lane.manifest.base_oid != base.candidate_commit_oid:
            raise LeaseRefused('integration_base_mismatch')
        verify_candidate_inputs(destination, current)
        expected = {f.path: f for f in current.tracked_inputs}
        source = {f.path: f for f in lane.manifest.tracked_inputs}
        for name in lane.writes:
            body = (lane.root / name).read_bytes()
            if hashlib.sha256(body).hexdigest() != source[name].sha256:
                raise LeaseRefused('integration_source_changed')
            (destination / name).write_bytes(body)
            (destination / name).chmod(0o644)
            expected[name] = source[name]
        git(destination, 'add', '--', *lane.writes)
        if not set(git(destination, 'diff', '--cached', '--name-only',
                       current.candidate_commit_oid).splitlines()) <= set(lane.writes):
            raise LeaseRefused('integration_staged_scope')
        git(destination, 'commit', '--allow-empty', '-m', 'authored lane integration')
        current = observe_candidate_inputs(
            destination, base.base_oid, git(destination, 'rev-parse', 'HEAD'),
            base.extra_input_files, base.output_directories, base.targets)
        if {f.path: f for f in current.tracked_inputs} != expected:
            raise LeaseRefused('integration_bytes_changed')
    return current


def recover_sealed(record: Path, destination: Path) -> CandidateManifest:
    """Materialize only the retained seal into a new root; dirty roots stay quarantined.

    Recovery conveys no dispatch or integration authority. The coordinator state
    and campaign ledger remain consumed and must be inspected independently.
    """
    data = json.loads(record.read_text())
    fields = data['manifest']
    manifest = CandidateManifest(
        fields['base_oid'], fields['candidate_commit_oid'], fields['candidate_tree_oid'],
        tuple(InputFile(**f) for f in fields['tracked_inputs']),
        tuple(InputFile(**f) for f in fields['extra_inputs']),
        tuple(fields['extra_input_files']), tuple(fields['output_directories']), tuple(fields['targets']))
    expected_name = record.stem + '-' + manifest.digest[7:]
    if data['manifest_digest'] != manifest.digest or data['snapshot'] != expected_name:
        raise LeaseRefused('recovery_seal_changed')
    snapshot = record.parent / expected_name
    verify_candidate_inputs(snapshot, manifest)
    shutil.copytree(snapshot, destination)
    verify_candidate_inputs(destination, manifest)
    return manifest
