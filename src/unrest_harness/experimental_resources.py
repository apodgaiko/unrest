"""Conservative resource admission for disposable experimental lanes.

This is an observation boundary, not a lock manager or an OS sandbox. Existing
resources must be resolved before admission; conflicting lanes are refused.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import ipaddress
import os
from pathlib import Path
import re
import stat
import time
from typing import Literal

from .experimental_lease import LeaseRefused
from .experimental_provider_config import CommonInputs


@dataclass(frozen=True)
class Resource:
    kind: Literal['path', 'service']
    identity: str
    device: int = 0
    inode: int = 0
    directory: bool = False

    @classmethod
    def path(cls, path: Path) -> Resource:
        """Reject unresolved paths and links, including links in ancestors."""
        if not path.is_absolute() or '..' in path.parts:
            raise LeaseRefused('unresolved_resource')
        try:
            for parent in (*reversed(path.parents), path):
                info = parent.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise LeaseRefused('resource_alias')
            info = path.lstat()
            directory = stat.S_ISDIR(info.st_mode)
            if not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise LeaseRefused('unsupported_resource')
            return cls('path', os.path.normcase(str(path.resolve(strict=True))),
                       info.st_dev, info.st_ino, directory)
        except OSError:
            raise LeaseRefused('unresolved_resource') from None

    @classmethod
    def service(cls, transport: str, host: str, port: int) -> Resource:
        # No DNS: localhost and all loopback addresses share one local namespace.
        # Wildcard listeners conservatively conflict with every local endpoint.
        if transport not in ('tcp', 'udp') or type(port) is not int or not 1 <= port <= 65535:
            raise LeaseRefused('unresolved_resource')
        try:
            address = ipaddress.ip_address('127.0.0.1' if host == 'localhost' else host)
        except ValueError:
            raise LeaseRefused('unresolved_resource') from None
        if not (address.is_loopback or address.is_unspecified):
            raise LeaseRefused('unsupported_resource')
        return cls('service', f'{transport}:local:{port}')

    def overlaps(self, other: Resource) -> bool:
        if self.kind != other.kind:
            return False
        if self.kind == 'service':
            return self.identity == other.identity
        if (self.device, self.inode) == (other.device, other.inode):
            return True
        # Case folding deliberately refuses potentially aliased names even on a
        # case-sensitive volume; admission is narrower than filesystem support.
        left, right = self.identity.casefold(), other.identity.casefold()
        return (left == right or self.directory and right.startswith(left.rstrip('/') + '/')
                or other.directory and left.startswith(right.rstrip('/') + '/'))

    def verify(self) -> None:
        if self.kind == 'path' and Resource.path(Path(self.identity)) != self:
            raise LeaseRefused('resource_replaced')


@dataclass(frozen=True)
class Access:
    resource: Resource
    mode: Literal['read', 'write']
    purpose: Literal['candidate', 'broker', 'owned', 'input', 'output', 'cache', 'service']

    def __post_init__(self) -> None:
        if self.mode not in ('read', 'write') or self.purpose not in (
                'candidate', 'broker', 'owned', 'input', 'output', 'cache', 'service'):
            raise LeaseRefused('invalid_resource_access')


class ResourceAdmission:
    """A sealed footprint; later observed conflicts permanently stop admission.

    All cross-lane shared resources refuse, including read/read declarations:
    a declaration cannot establish that a shared cache or service is immutable.
    Candidate, broker materialization and owned-process storage are separate.
    """

    def __init__(self, lanes: dict[str, tuple[Access, ...]], *, common: CommonInputs | None = None):
        self.lanes = dict(lanes)
        self.common = common
        self._common_digest = None if common is None else common.expected
        self.stopped = False
        self.inputs: dict[Resource, str] = {}
        self._declarations = self._declaration_digest()
        self._permissions = {
            a.resource: stat.S_IMODE(Path(a.resource.identity).stat().st_mode)
            for accesses in self.lanes.values() for a in accesses if a.resource.kind == 'path'}
        if not 1 <= len(lanes) <= 2 or any(
                re.fullmatch(r'[A-Za-z0-9_-]{1,64}', lane) is None for lane in lanes):
            raise LeaseRefused('invalid_lanes')
        for accesses in self.lanes.values():
            if type(accesses) is not tuple or len(accesses) > 128:
                raise LeaseRefused('invalid_resource_footprint')
            owned = [a for a in accesses if a.purpose in ('candidate', 'broker', 'owned')]
            if sorted(a.purpose for a in owned) != ['broker', 'candidate', 'owned']:
                raise LeaseRefused('missing_owned_resources')
            if any(a.mode != 'write' or not a.resource.directory for a in owned):
                raise LeaseRefused('invalid_owned_resources')
            if any(a.resource.overlaps(b.resource)
                   for i, a in enumerate(owned) for b in owned[i + 1:]):
                raise LeaseRefused('owned_resource_collision')
            for access in accesses:
                if access.mode == 'read' or access.purpose == 'input':
                    if access.resource.kind != 'path':
                        raise LeaseRefused('unobservable_input')
                    self.inputs[access.resource] = _input_digest(access.resource)
        self.verify()

    def _declaration_digest(self) -> str:
        return hashlib.sha256(json.dumps(
            {name: [asdict(a) for a in accesses] for name, accesses in self.lanes.items()},
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    @property
    def digest(self) -> str:
        self.verify()
        return hashlib.sha256(json.dumps({
            'declarations': self._declarations,
            'permissions': sorted((r.identity, mode) for r, mode in self._permissions.items()),
            'inputs': sorted((r.identity, digest) for r, digest in self.inputs.items()),
            'common_inputs': self._common_digest,
        }, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def verify(self) -> None:
        if self.stopped:
            raise LeaseRefused('resource_admission_stopped')
        try:
            if (None if self.common is None else self.common.expected) != self._common_digest:
                raise LeaseRefused('common_inputs_substituted')
            if self.common is not None:
                self.common.verify()
            if self._declaration_digest() != self._declarations:
                raise LeaseRefused('resource_declaration_changed')
            for resource, mode in self._permissions.items():
                if stat.S_IMODE(Path(resource.identity).stat().st_mode) != mode:
                    raise LeaseRefused('resource_permissions_changed')
            for accesses in self.lanes.values():
                for access in accesses:
                    access.resource.verify()
            for resource, expected in self.inputs.items():
                if _input_digest(resource) != expected:
                    raise LeaseRefused('declared_input_changed')
            footprints = list(self.lanes.values())
            for i, left in enumerate(footprints):
                for right in footprints[i + 1:]:
                    if any(a.resource.overlaps(b.resource) for a in left for b in right):
                        raise LeaseRefused('cross_lane_resource_conflict')
        except BaseException:
            self.stopped = True
            raise


def _input_digest(resource: Resource) -> str:
    """Bounded observation of explicitly declared external regular inputs."""
    root = Path(resource.identity)
    digest = hashlib.sha256()
    pending = [root]
    entries = total = 0
    deadline = time.monotonic() + 5
    while pending:
        path = pending.pop()
        entries += 1
        if entries > 4096 or time.monotonic() >= deadline:
            raise LeaseRefused('resource_observation_bound')
        info = path.lstat()
        digest.update(str(path.relative_to(root)).encode() + b'\0')
        digest.update(str(stat.S_IMODE(info.st_mode)).encode() + b'\0')
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as stream:
                children: list[Path] = []
                for child in stream:
                    if len(children) + entries + len(pending) >= 4096:
                        raise LeaseRefused('resource_observation_bound')
                    children.append(Path(child.path))
            pending.extend(reversed(sorted(children)))
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1048576:
            raise LeaseRefused('unsupported_input')
        total += info.st_size
        if total > 64 * 1048576:
            raise LeaseRefused('resource_observation_bound')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(1048577)
            if len(raw) != info.st_size:
                raise LeaseRefused('declared_input_changed')
            digest.update(hashlib.sha256(raw).digest())
        finally:
            os.close(fd)
    return digest.hexdigest()
