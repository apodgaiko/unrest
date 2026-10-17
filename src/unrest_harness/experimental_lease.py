"""Local lease primitives; no ordinary dispatch imports or provider admission.

A controller owns this object and its private directories. Capabilities are sent
only in controller-created turn envelopes, never discovered from lane headers.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal


class LeaseRefused(ValueError):
    """Bounded diagnostic safe to return across the experimental boundary."""


@dataclass(frozen=True)
class TurnIdentity:
    lane: str
    role: Literal["worker", "validator"]
    child: str
    handoff: str
    session: str
    process_generation: str
    ordinal: int
    scope: tuple[str, ...]
    candidate: str
    targets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        strings = (self.lane, self.role, self.child, self.handoff, self.session,
                   self.process_generation, self.candidate)
        if (any(type(value) is not str or not value for value in strings)
                or type(self.ordinal) is not int or type(self.scope) is not tuple
                or type(self.targets) is not tuple
                or any(type(target) is not str or not target or len(target) > 128
                       for target in self.targets)
                or tuple(sorted(set(self.targets))) != self.targets
                or any(type(name) is not str for name in self.scope)):
            raise LeaseRefused("invalid_identity")
        if (self.role not in ("worker", "validator") or self.ordinal < 1
                or not all((self.lane, self.child, self.handoff, self.session,
                            self.process_generation)) or len(self.candidate) != 64
                or any(c not in "0123456789abcdef" for c in self.candidate)
                or not self.scope or tuple(sorted(set(self.scope))) != self.scope
                or any(not name or "\x00" in name or name in (".", "..") or "/" in name or "\\" in name
                       for name in self.scope)):
            raise LeaseRefused("invalid_identity")


@dataclass(frozen=True)
class Completion:
    identity: TurnIdentity
    sealed_candidate: str
    disposition: str
    verdicts: tuple[tuple[str, bool], ...] = ()


REAL_PROVIDER = 'codex-0.160.1/acp-1.1.0/gpt-6-astra/medium'


class PilotLedger:
    """One local campaign; existing journals cannot restore send authority.

    Reservations are fsynced before transmission, never refunded, and consume
    allowance even when transport outcome is ambiguous. Only the controller
    may create the journal, reserve turns or record transport outcomes.
    """

    maxima = {"P1": 4, "P2": 6, "P3": 8, "C1": 6}

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.monotonic,
                 capacity: int = 4, provider: str = "local-controlled-only"):
        if type(capacity) is not int or capacity < 1:
            raise LeaseRefused("invalid_capacity")
        if provider not in ("local-controlled-only", REAL_PROVIDER):
            raise LeaseRefused("unsupported_provider")
        self.capacity, self.provider = min(capacity, 4), provider
        self._clock = clock
        self._started = clock()
        self._lock = threading.RLock()
        self._fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self._episode: str | None = None
        self._episode_started = 0.0
        self._counts: dict[str, int] = {}
        self._turns: dict[str, tuple[float, str]] = {}
        self._halted = False
        self._operation_owner: object | None = None
        self._halt_owner: object | None = None
        self._final_count = 0
        self._identities: set[tuple[str, int]] = set()
        self._leases: set[str] = set()
        self._sessions: set[str] = set()
        self._append("campaign", {"provider": provider, "started": self._started,
                                  "capacity": self.capacity, "turn_limit": 24,
                                  "aggregate_seconds": 5400})

    def claim_session(self) -> str:
        with self._lock:
            self._check()
            if len(self._leases) >= 4:
                raise LeaseRefused('retained_session_capacity')
            handle = secrets.token_hex(24)
            self._leases.add(handle)
            return handle

    def release_session(self, handle: str) -> None:
        with self._lock:
            self._leases.remove(handle)

    def accounting(self) -> dict[str, int]:
        """Read consumed reservations even after halt, without restoring authority."""
        with self._lock:
            return {'episode': self._counts.get(self._episode or '', 0),
                    'campaign': sum(self._counts.values()), 'final': self._final_count}

    def bind_session(self, session: str) -> None:
        """Fresh identities remain unique across every role and episode."""
        with self._lock:
            self._check()
            if type(session) is not str or not session or session in self._sessions:
                raise LeaseRefused('reused_or_invalid_session_identity')
            self._append('session_identity', {'sha256': hashlib.sha256(session.encode()).hexdigest()})
            self._sessions.add(session)

    @contextmanager
    def owned_operation(self, owner: object) -> Iterator[None]:
        """Bind a synchronous controller operation, never a whole async turn.

        The lock keeps provenance local to the operation that first halted the
        ledger. A later operation cannot claim an earlier unrelated halt.
        """
        with self._lock:
            previous = self._operation_owner
            self._operation_owner = owner
            try:
                yield
            finally:
                self._operation_owner = previous

    def halted_by(self, owner: object) -> bool:
        with self._lock:
            return self._halted and self._halt_owner is owner

    def _halt_owned_operation(self) -> None:
        if not self._halted:
            self._halt_owner = self._operation_owner
        self._halted = True

    def _append(self, event: str, fields: dict[str, object]) -> None:
        try:
            data = (json.dumps({"event": event, "elapsed_seconds": self._clock() - self._started,
                                **fields}, sort_keys=True) + "\n").encode()
            while data:
                written = os.write(self._fd, data)
                if written <= 0:
                    raise OSError("short journal write")
                data = data[written:]
            os.fsync(self._fd)
        except OSError:
            self._halt_owned_operation()
            raise LeaseRefused("journal_unavailable") from None

    def _check(self) -> None:
        if self._halted or self._clock() - self._started >= 5400:
            raise LeaseRefused("campaign_stopped")
        if self._episode and self._clock() - self._episode_started >= 1800:
            self._halted = True
            raise LeaseRefused("episode_expired")

    def admit(self, episode: str) -> None:
        with self._lock:
            self._check()
            if (episode not in self.maxima or episode in self._counts
                    or self._episode is not None):
                raise LeaseRefused("episode_not_admissible")
            self._append("admit", {"episode": episode, "final_reserved": 2,
                                   "maximum": self.maxima[episode]})
            self._episode, self._episode_started = episode, self._clock()
            self._counts[episode] = 0
            self._final_count = 0

    def turn_deadline(self) -> float:
        """Capture the turn's absolute bound before any provider startup."""
        with self._lock:
            self._check()
            return min(self._clock() + 300, self._started + 5400,
                       self._episode_started + 1800)

    def remaining_until(self, deadline: float) -> float:
        """Recheck the original pre-start cutoff without creating a new allowance."""
        with self._lock:
            remaining = min(self.lifetime_remaining(), deadline - self._clock())
            if remaining <= 0:
                raise LeaseRefused('turn_expired')
            return remaining

    def reserve(self, identity: TurnIdentity, *, final: bool = False,
                deadline: float | None = None) -> str:
        with self._lock:
            self.available(final=final)
            episode = self._episode
            if episode is None or sum(s in ("reserved", "sent") for _, s in self._turns.values()) >= self.capacity:
                raise LeaseRefused("turn_not_admissible")
            identity_key = (identity.process_generation, identity.ordinal)
            if identity_key in self._identities:
                raise LeaseRefused("turn_already_reserved")
            maximum = self.maxima[episode]
            count = self._counts[episode]
            if (count >= maximum or sum(self._counts.values()) >= 24
                    or (not final and count - self._final_count >= maximum - 2)
                    or (final and self._final_count >= 2)):
                raise LeaseRefused("turn_budget")
            if any(s == "final" for _, s in self._turns.values()) and not final:
                raise LeaseRefused("final_phase")
            ticket = secrets.token_hex(24)
            current_bound = self.turn_deadline()
            deadline = current_bound if deadline is None else min(deadline, current_bound)
            if deadline <= self._clock():
                raise LeaseRefused('turn_expired')
            self._append("reserve", {"episode": episode, "ticket": ticket,
                                     "ordinal": count + 1, "final": final,
                                     "identity": asdict(identity), "deadline": deadline,
                                     "provider": self.provider})
            self._counts[episode] += 1
            self._identities.add(identity_key)
            self._turns[ticket] = (deadline, "reserved")
            if final:
                self._final_count += 1
                self._turns["final-phase"] = (deadline, "final")
            return ticket

    def available(self, *, final: bool = False) -> None:
        """Fail before process construction; reserve rechecks atomically before send."""
        with self._lock:
            self._check()
            episode = self._episode
            if episode is None or sum(s in ('reserved', 'sent') for _, s in self._turns.values()) >= self.capacity:
                raise LeaseRefused('turn_not_admissible')
            count = self._counts[episode]
            if (count >= self.maxima[episode] or sum(self._counts.values()) >= 24
                    or (final and self._final_count >= 2)
                    or (not final and count - self._final_count >= self.maxima[episode] - 2)):
                raise LeaseRefused('turn_budget')
            if self._final_count and not final:
                raise LeaseRefused('final_phase')

    def lifetime_remaining(self, *, drain: bool = False) -> float:
        with self._lock:
            if not drain:
                self._check()
            deadline = self._started + 5400
            if self._episode:
                deadline = min(deadline, self._episode_started + 1800)
            if self._fd < 0 or self._clock() >= deadline:
                raise LeaseRefused('campaign_expired')
            return deadline - self._clock()

    def remaining(self, ticket: str, *, drain: bool = False) -> float:
        with self._lock:
            deadline, status = self._turns.get(ticket, (0, "unknown"))
            if not drain or status != 'sent':
                self._check()
            self.lifetime_remaining(drain=drain and status == 'sent')
            if status not in ("reserved", "sent") or self._clock() >= deadline:
                raise LeaseRefused("turn_expired")
            return deadline - self._clock()

    def stop(self, *, quarantine: bool = False) -> None:
        with self._lock:
            self._halted = True
            self._append("quarantine" if quarantine else "stop", {})

    def sent(self, ticket: str) -> None:
        with self._lock:
            self._check()
            deadline, status = self._turns.get(ticket, (0, "unknown"))
            if status != "reserved" or self._clock() >= deadline:
                raise LeaseRefused("send_not_admissible")
            self._append("send", {"ticket": ticket})
            self._turns[ticket] = (deadline, "sent")

    def finish(self, ticket: str, *, ambiguous: bool = False) -> None:
        with self._lock:
            deadline, status = self._turns.get(ticket, (0, "unknown"))
            if status not in ("reserved", "sent"):
                raise LeaseRefused("turn_not_active")
            expired = self._clock() >= deadline
            uncertain = ambiguous or status == "reserved" or expired
            self._append("uncertain" if uncertain else "ack", {"ticket": ticket})
            if not uncertain and self._clock() >= min(
                    deadline, self._episode_started + 1800, self._started + 5400):
                # The ack already reached disk. Publish uncertainty and its first
                # owner before attempting a corrective append; never undo history
                # or let a second I/O failure replace the original late result.
                self._turns[ticket] = (deadline, "uncertain")
                self._halt_owned_operation()
                try:
                    self._append("uncertain", {"ticket": ticket})
                except LeaseRefused as error:
                    raise LeaseRefused("turn_not_acknowledged") from error
                return
            self._turns[ticket] = (deadline, "uncertain" if uncertain else "acked")
            if uncertain:
                self._halt_owned_operation()

    def close_episode(self) -> None:
        with self._lock:
            self._check()
            if self._episode is None or self._final_count != 2 or self._leases or any(s in ("reserved", "sent")
                                            for _, s in self._turns.values()):
                raise LeaseRefused("episode_active")
            self._append("close", {"episode": self._episode})
            self._episode = None
            self._turns.clear()

    def close(self) -> None:
        with self._lock:
            self._halted = True
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1


class TurnBroker:
    """Exclusive mutation/completion authority for a private flat fixture root.

    The candidate directory must be controller-created and inaccessible to any
    other writer. All commits, descriptor closes, revocation and completion
    publication serialize on one lock. This does not confer OS confinement.
    """

    def __init__(self, root: Path, records: Path):
        self._lock = threading.RLock()
        self._root = root
        self._root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._records = records
        try:
            records.mkdir(mode=0o700)  # Refuse restart instead of restoring capabilities.
        except BaseException:
            os.close(self._root_fd)
            raise
        self._record_fd = os.open(records, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._active: tuple[str, TurnIdentity, float] | None = None
        self._seen: set[tuple[str, int]] = set()
        self._generations: dict[str, TurnIdentity] = {}
        self._revoked: set[str] = set()
        self._closed = False
        self._completions: dict[TurnIdentity, Completion] = {}
        self.quarantined = False
        self._expected: dict[str, str] | None = None

    @staticmethod
    def _manifest_digest(manifest: dict[str, str]) -> str:
        return hashlib.sha256(json.dumps(sorted(manifest.items()), separators=(",", ":")).encode()).hexdigest()

    def seal(self, scope: tuple[str, ...], candidate: str) -> str:
        """Bind the controller's initial seal once; subsequent calls only verify."""
        with self._lock:
            if self._expected is None:
                if self.digest(scope) != candidate:
                    raise LeaseRefused("stale_candidate")
                manifest = {name: hashlib.sha256(self._read(name)).hexdigest() for name in scope}
                if self._manifest_digest(manifest) != candidate:
                    raise LeaseRefused("stale_candidate")
                self._expected = manifest
            expected = self.verify(scope)
            if expected != candidate:
                raise LeaseRefused("stale_candidate")
            return expected

    def verify(self, scope: tuple[str, ...]) -> str:
        """Observe equality to retained bytes, never adopt a changed baseline."""
        with self._lock:
            try:
                if self._expected is None or tuple(sorted(self._expected)) != scope:
                    raise LeaseRefused("candidate_not_sealed")
                expected = self._manifest_digest(self._expected)
                if self.digest(scope) != expected:
                    raise LeaseRefused("unexpected_candidate_mutation")
                return expected
            except BaseException:
                self.quarantined = True
                self.park()
                raise

    def contents(self, scope: tuple[str, ...]) -> dict[str, str]:
        """Controller-only bounded context, not an ambient filesystem tool."""
        with self._lock:
            self.verify(scope)
            bodies = {name: self._read(name) for name in scope}
            if {name: hashlib.sha256(body).hexdigest() for name, body in bodies.items()} != self._expected:
                self.quarantined = True
                self.park()
                raise LeaseRefused('unexpected_candidate_mutation')
            if sum(map(len, bodies.values())) > 262144:
                raise LeaseRefused("candidate_context_too_large")
            try:
                result = {name: body.decode('utf-8') for name, body in bodies.items()}
            except UnicodeError:
                raise LeaseRefused("candidate_context_not_text") from None
            self.verify(scope)
            return result

    def _root_check(self) -> None:
        if self._closed or self.quarantined:
            raise LeaseRefused("lease_unavailable")
        try:
            actual = self._root.lstat()
            held = os.fstat(self._root_fd)
            if (actual.st_dev, actual.st_ino) != (held.st_dev, held.st_ino):
                raise LeaseRefused("candidate_replaced")
        except OSError:
            raise LeaseRefused("candidate_unavailable") from None

    def _read(self, name: str) -> bytes:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._root_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1048576:
                raise LeaseRefused("unsafe_candidate_file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                return stream.read(1048577)
        finally:
            os.close(fd)

    def digest(self, scope: tuple[str, ...]) -> str:
        with self._lock:
            self._root_check()
            if tuple(sorted(os.listdir(self._root_fd))) != scope:
                raise LeaseRefused("candidate_scope_changed")
            try:
                manifest = [(name, hashlib.sha256(self._read(name)).hexdigest()) for name in scope]
            except OSError:
                raise LeaseRefused("unsafe_candidate_file") from None
            return hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()

    def grant(self, identity: TurnIdentity, *, deadline: float) -> str:
        with self._lock:
            self._root_check()
            key = (identity.process_generation, identity.ordinal)
            if self._active or key in self._seen or deadline <= time.monotonic():
                raise LeaseRefused("turn_not_admissible")
            self.seal(identity.scope, identity.candidate)
            previous = self._generations.get(identity.process_generation)
            if previous is not None:
                old = asdict(previous)
                new = asdict(identity)
                for field in ("ordinal", "candidate"):
                    old.pop(field)
                    new.pop(field)
                if old != new or identity.ordinal != previous.ordinal + 1:
                    raise LeaseRefused("continuity_lost")
            elif identity.ordinal != 1:
                raise LeaseRefused("invalid_first_ordinal")
            token = secrets.token_urlsafe(48)
            if hashlib.sha256(token.encode()).hexdigest() in self._revoked:
                raise LeaseRefused("capability_collision")
            # Sealing and token preparation can consume the last available time.
            if deadline <= time.monotonic():
                raise LeaseRefused('turn_not_admissible')
            self._generations[identity.process_generation] = identity
            self._seen.add(key)
            self._active = (token, identity, deadline)
            return token

    def _authorize(self, token: str, identity: TurnIdentity) -> TurnIdentity:
        self._root_check()
        if (not self._active or not secrets.compare_digest(token, self._active[0])
                or identity != self._active[1] or time.monotonic() >= self._active[2]):
            raise LeaseRefused("turn_authority_denied")
        return self._active[1]

    def replace(self, token: str, identity: TurnIdentity, name: str, content: str) -> str:
        with self._lock:
            identity = self._authorize(token, identity)
            if identity.role != "worker" or name not in identity.scope:
                raise LeaseRefused("write_scope_denied")
            data = content.encode()
            if len(data) > 1048576:
                raise LeaseRefused("write_too_large")
            try:
                self.verify(identity.scope)
                assert self._expected is not None
                expected = {**self._expected, name: hashlib.sha256(data).hexdigest()}
                temporary = ".lease-" + secrets.token_hex(16)
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self._root_fd)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.rename(temporary, name, src_dir_fd=self._root_fd, dst_dir_fd=self._root_fd)
                    os.fsync(self._root_fd)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=self._root_fd)
                    except FileNotFoundError:
                        pass
                # Only this authorized replacement changes the expectation. Do
                # not incorporate concurrently observed writes to other files.
                predicted = self._manifest_digest(expected)
                if self.digest(identity.scope) != predicted:
                    raise LeaseRefused("unexpected_candidate_mutation")
                self._expected = expected
                return predicted
            except BaseException:
                # A rename may already be durable. Revocation is not rollback.
                self.quarantined = True
                self.park()
                raise

    def complete(self, token: str, identity: TurnIdentity, sealed_candidate: str,
                 disposition: str, verdicts: dict[str, bool] | None = None) -> Completion:
        with self._lock:
            identity = self._authorize(token, identity)
            allowed = {"sealed"} if identity.role == "worker" else {
                "pass", "reproducible_product_defect", "conflict", "missing_authority",
                "scope_expansion", "unknown", "malformed_handoff"}
            try:
                if disposition not in allowed or sealed_candidate != self.verify(identity.scope):
                    raise LeaseRefused("completion_attention")
                values = {} if verdicts is None else verdicts
                if (type(values) is not dict or any(type(v) is not bool for v in values.values())
                        or set(values) != (set(identity.targets) if identity.role == 'validator' else set())
                        or identity.role == 'validator' and identity.targets
                        and (disposition == 'pass') != all(values.values())):
                    raise LeaseRefused('target_verdicts_invalid')
                result = Completion(identity, sealed_candidate, disposition, tuple(sorted(values.items())))
                data = (json.dumps(asdict(result), sort_keys=True) + "\n").encode()
                name = hashlib.sha256(json.dumps(asdict(identity), sort_keys=True).encode()).hexdigest()
                temporary = ".completion-" + secrets.token_hex(16)
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                             dir_fd=self._record_fd)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.link(temporary, name + ".json", src_dir_fd=self._record_fd,
                            dst_dir_fd=self._record_fd, follow_symlinks=False)
                    os.fsync(self._record_fd)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=self._record_fd)
                    except FileNotFoundError:
                        pass
                self._completions[identity] = result
                return result
            except BaseException:
                self.quarantined = True
                raise
            finally:
                self.park()

    def completion(self, identity: TurnIdentity) -> Completion:
        with self._lock:
            self._root_check()
            result = self._completions.get(identity)
            if result is None or self.verify(identity.scope) != result.sealed_candidate:
                raise LeaseRefused("completion_missing_or_stale")
            return result

    def park(self) -> None:
        with self._lock:
            if self._active:
                self._revoked.add(hashlib.sha256(self._active[0].encode()).hexdigest())
                self._active = None

    def close(self) -> None:
        with self._lock:
            self.park()
            if not self._closed:
                os.close(self._root_fd)
                os.close(self._record_fd)
                self._closed = True


def correction_allowed(completion: Completion, expected: TurnIdentity) -> bool:
    return (completion.identity == expected and expected.role == "validator"
            and completion.sealed_candidate == expected.candidate
            and completion.disposition == "reproducible_product_defect")


def require_provider(provider: str, *, trusted_process: bool = False,
                     controls: bool = False, ledger: PilotLedger | None = None,
                     final: bool = False) -> None:
    """Opt-in is necessary; actual construction also pins all owned executables."""
    if provider != "codex":
        raise LeaseRefused("unsupported_provider")
    if trusted_process is not True:
        raise LeaseRefused("trusted_process_opt_in_required")
    if controls is not True or ledger is None:
        raise LeaseRefused("retained_controls_unavailable")
    ledger.available(final=final)
