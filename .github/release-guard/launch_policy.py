"""Finite launch rendering; successful matching is not execution authority.

The observer must authenticate the policy, original source owner, case, parameter
values and acquired root generations independently. No value may be inferred
from an untrusted launch vector merely to make this matcher accept that vector.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath

from content_manifest import Refused

MAX_ARGUMENTS = 256
MAX_TEXT_BYTES = 131_071
MAX_VECTOR_BYTES = 2 * 1024 * 1024
MAX_FIELDS = 1024
MAX_DECLARATION_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class Rule:
    id: str
    owner: str
    cases: tuple[str, ...]
    executable: str
    executable_sha256: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    cwd: str
    payload_kind: str
    payload_sha256: str | None = None  # Required only for external script/module content.


@dataclass(frozen=True)
class Expected:
    rule: str
    owner: str
    case: str
    executable: str
    executable_sha256: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    cwd: str
    payload_kind: str
    payload_sha256: str

    def wire(self) -> dict:
        """Closed JSON primitives; tuple-valued policy state stays internal."""
        return {'rule': self.rule, 'owner': self.owner, 'case': self.case,
                'executable': self.executable, 'executable_sha256': self.executable_sha256,
                'argv': list(self.argv), 'environment': [list(pair) for pair in self.environment],
                'cwd': self.cwd, 'payload_kind': self.payload_kind, 'payload_sha256': self.payload_sha256}


@dataclass(frozen=True)
class Observation:
    executable: str
    executable_sha256: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    cwd: str
    payload_kind: str
    payload_sha256: str


def _text(value: object) -> str:
    if type(value) is not str or "\x00" in value:
        raise Refused("policy_text")
    try:
        if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
            raise Refused("policy_text_bound")
    except UnicodeError:
        raise Refused("policy_text_encoding") from None
    return value


def _absolute(value: str) -> str:
    if (not value.startswith("/") or value.startswith("//")
            or str(PurePosixPath(value)) != value or ".." in PurePosixPath(value).parts):
        raise Refused("policy_absolute_path")
    return value


class _Budget:
    def __init__(self):
        self.fields, self.bytes = 0, 0

    def text(self, value: object) -> str:
        self.fields += 1
        if self.fields > MAX_FIELDS:
            raise Refused('policy_field_bound')
        result = _text(value)
        self.bytes += len(result.encode('utf-8'))
        if self.bytes > MAX_DECLARATION_BYTES:
            raise Refused('policy_declaration_bound')
        return result


def _argv(value, budget):
    if type(value) is not tuple or not 0 < len(value) <= MAX_ARGUMENTS:
        raise Refused('policy_argv')
    result = tuple(budget.text(item) for item in value)
    if sum(len(item.encode('utf-8')) + 1 for item in result) > MAX_VECTOR_BYTES:
        raise Refused('policy_argv_bound')
    return result


def _environment(value, budget):
    if type(value) is not tuple or len(value) > MAX_ARGUMENTS:
        raise Refused('policy_environment')
    result = []
    for pair in value:
        if type(pair) is not tuple or len(pair) != 2:
            raise Refused('policy_environment')
        key, item = budget.text(pair[0]), budget.text(pair[1])
        if not key or '=' in key:
            raise Refused('policy_environment_key')
        result.append((key, item))
    if len({key for key, _ in result}) != len(result):
        raise Refused('policy_duplicate_environment')
    if sum(len(key.encode()) + len(item.encode()) + 2 for key, item in result) > MAX_VECTOR_BYTES:
        raise Refused('policy_environment_bound')
    return tuple(sorted(result))


def _sha(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _payload(argv: tuple[str, ...], kind: str, reference: str | None,
             executable_sha256: str) -> tuple[int | None, str]:
    if kind in {"native", "expected-exec-failure"}:
        if reference is not None:
            raise Refused("policy_native_payload_reference")
        return None, executable_sha256
    if kind not in {"python-command", "python-module", "python-script"}:
        raise Refused("policy_payload_kind")
    index = 1
    flags = {"-I", "-S", "-B", "-E", "-s", "-u", "-q", "-O", "-OO", "-b", "-bb"}
    while index < len(argv) and argv[index] in flags:
        index += 1
    if index >= len(argv):
        raise Refused("policy_python_payload_missing")
    actual = {"-c": "python-command", "-m": "python-module"}.get(argv[index], "python-script")
    if actual != kind:
        raise Refused("policy_payload_mode_mismatch")
    index += int(actual != "python-script")
    if index >= len(argv):
        raise Refused("policy_python_payload_missing")
    if kind == "python-command":
        if reference is not None:
            raise Refused("policy_inline_payload_reference")
        return index, hashlib.sha256(argv[index].encode("utf-8")).hexdigest()
    if kind == "python-script":
        _absolute(argv[index])
    elif not all(part.isidentifier() for part in argv[index].split(".")):
        raise Refused("policy_module_name")
    if reference is None or not _sha(reference):
        raise Refused("policy_external_payload_reference")
    return index, reference


def render(rule: Rule, case: str, owner: str, values: dict,
           roots: dict[str, str]) -> Expected:
    """Validate one literal rule; its builder must authenticate dynamic inputs."""
    if (type(rule) is not Rule or type(rule.cases) is not tuple
            or len(rule.cases) > MAX_FIELDS or type(rule.payload_kind) is not str
            or not _sha(rule.executable_sha256)
            or rule.payload_kind not in {"python-script", "python-command", "python-module",
                                         "native", "expected-exec-failure"}):
        raise Refused("policy_rule")
    if type(values) is not dict or type(roots) is not dict or values or roots:
        raise Refused('policy_unused_context')
    budget = _Budget()
    for item in (rule.id, rule.owner, case, owner, *rule.cases):
        if not budget.text(item):
            raise Refused('policy_rule')
    if owner != rule.owner or case not in rule.cases or len(set(rule.cases)) != len(rule.cases):
        raise Refused('policy_rule')
    executable = _absolute(budget.text(rule.executable))
    argv = _argv(rule.argv, budget)
    cwd = _absolute(budget.text(rule.cwd))
    environment = _environment(rule.environment, budget)
    _, payload_sha256 = _payload(argv, rule.payload_kind, rule.payload_sha256, rule.executable_sha256)
    return Expected(rule.id, owner, case, executable, rule.executable_sha256, argv,
                    environment, cwd, rule.payload_kind, payload_sha256)


def match(expected: tuple[Expected, ...], observed: Observation,
          owner: str, case: str) -> Expected:
    """Compare complete observations; provenance must be established by the caller."""
    _text(owner)
    _text(case)
    if (type(expected) is not tuple or not expected or len(expected) > MAX_FIELDS
            or any(type(item) is not Expected for item in expected)
            or type(observed) is not Observation or not _sha(observed.executable_sha256)
            or not _sha(observed.payload_sha256) or type(observed.payload_kind) is not str):
        raise Refused("policy_observation")
    executable = _absolute(_text(observed.executable))
    cwd = _absolute(_text(observed.cwd))
    budget = _Budget()
    argv = _argv(observed.argv, budget)
    environment = _environment(observed.environment, budget)
    reference = (observed.payload_sha256
                 if observed.payload_kind in {"python-script", "python-module"} else None)
    _, payload_sha256 = _payload(argv, observed.payload_kind, reference,
                                 observed.executable_sha256)
    if observed.payload_sha256 != payload_sha256:
        raise Refused("policy_observation_payload")
    found = [item for item in expected if item.owner == owner and item.case == case
             and item.executable == executable and item.executable_sha256 == observed.executable_sha256
             and item.argv == argv and item.environment == tuple(sorted(environment))
             and item.cwd == cwd and item.payload_kind == observed.payload_kind
             and item.payload_sha256 == payload_sha256]
    if len(found) != 1:
        raise Refused("policy_match_cardinality")
    return found[0]
