"""Finite launch rendering; successful matching is not execution authority.

The observer must authenticate the policy, original source owner, case, parameter
values and acquired root generations independently. No value may be inferred
from an untrusted launch vector merely to make this matcher accept that vector.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
from typing import TypeAlias, cast

from content_manifest import Refused

MAX_ARGUMENTS = 256
MAX_TEXT_BYTES = 131_071
MAX_VECTOR_BYTES = 2 * 1024 * 1024
MAX_TERMS = 1024
MAX_DEPTH = 16
MAX_DECLARATION_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class Choice:
    slot: str
    choices: tuple[str, ...]


@dataclass(frozen=True)
class Integer:
    slot: str
    minimum: int
    maximum: int


@dataclass(frozen=True)
class OwnedPath:
    root: str
    parts: tuple[Term, ...] = ()


@dataclass(frozen=True)
class Concat:
    parts: tuple[Term, ...]


@dataclass(frozen=True)
class Program:
    parts: tuple[str | Integer | Quoted, ...]


@dataclass(frozen=True)
class Quoted:
    value: Term
    encoding: str  # Only Python repr and JSON string encoding are defined.


Term: TypeAlias = str | Choice | Integer | OwnedPath | Concat | Quoted | Program


@dataclass(frozen=True)
class Splice:
    slot: str
    choices: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class Rule:
    id: str
    owner: str
    cases: tuple[str, ...]
    executable: Term
    executable_sha256: str
    argv: tuple[Term | Splice, ...]
    environment: tuple[tuple[str, Term], ...]
    cwd: Term
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


class _Renderer:
    def __init__(self, values: dict, roots: dict[str, str]):
        if (type(values) is not dict or type(roots) is not dict
                or len(values) > MAX_TERMS or len(roots) > MAX_TERMS):
            raise Refused("policy_context")
        self.values, self.roots = values, roots
        self.used_values: set[str] = set()
        self.used_roots: set[str] = set()
        self.terms = 0
        self.input_bytes = 0
        for key in (*values, *roots):
            if not self.text(key):
                raise Refused("policy_context_key")

    def visit(self) -> None:
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise Refused("policy_term_bound")

    def text(self, value: object) -> str:
        self.visit()
        result = _text(value)
        self.input_bytes += len(result.encode("utf-8"))
        if self.input_bytes > MAX_DECLARATION_BYTES:
            raise Refused("policy_declaration_bound")
        return result

    def join(self, values: tuple[str, ...]) -> str:
        result = bytearray()
        for value in values:
            block = value.encode("utf-8")
            if len(result) + len(block) > MAX_TEXT_BYTES:
                raise Refused("policy_text_bound")
            result.extend(block)
        return result.decode("utf-8")

    def take(self, slot: str) -> object:
        if not self.text(slot) or slot not in self.values:
            raise Refused("policy_slot_missing")
        self.used_values.add(slot)
        return self.values[slot]

    def term(self, value: Term, depth: int = 0) -> str:
        self.visit()
        if depth > MAX_DEPTH:
            raise Refused("policy_term_bound")
        if type(value) is str:
            return self.text(value)
        if type(value) is Choice:
            if (type(value.choices) is not tuple or not value.choices
                    or len(value.choices) > MAX_TERMS
                    or any(type(item) is not str for item in value.choices)):
                raise Refused("policy_choices")
            for item in value.choices:
                self.text(item)
            if len(set(value.choices)) != len(value.choices):
                raise Refused("policy_choices")
            selected = self.take(value.slot)
            if type(selected) is not str or selected not in value.choices:
                raise Refused("policy_choice_value")
            return self.text(selected)
        if type(value) is Integer:
            selected = self.take(value.slot)
            if (type(selected) is not int or type(value.minimum) is not int
                    or type(value.maximum) is not int
                    or not -(2**63) <= value.minimum <= value.maximum < 2**63
                    or not value.minimum <= selected <= value.maximum):
                raise Refused("policy_integer_value")
            return _text(str(selected))
        if type(value) is OwnedPath:
            if not self.text(value.root) or value.root not in self.roots:
                raise Refused("policy_root_missing")
            self.used_roots.add(value.root)
            root = _absolute(self.text(self.roots[value.root]))
            parts = self.parts(value.parts, depth)
            if any(not item or item in {".", ".."} or "/" in item or "\\" in item
                   for item in parts):
                raise Refused("policy_relative_path")
            return self.join((root.rstrip("/"), *("/" + part for part in parts))) or "/"
        if type(value) is Concat:
            return self.join(self.parts(value.parts, depth))
        if type(value) is Program:
            if (type(value.parts) is not tuple
                    or any(type(part) not in (str, Integer, Quoted) for part in value.parts)):
                raise Refused("policy_unquoted_program_hole")
            return self.join(self.parts(value.parts, depth))
        if type(value) is Quoted:
            rendered = self.term(value.value, depth + 1)
            if type(value.encoding) is not str:
                raise Refused("policy_quote_encoding")
            if value.encoding == "python":
                return _text(repr(rendered))
            if value.encoding == "json":
                return _text(json.dumps(rendered, ensure_ascii=True))
            raise Refused("policy_quote_encoding")
        raise Refused("policy_term_type")

    def parts(self, values: tuple[Term, ...], depth: int) -> tuple[str, ...]:
        if type(values) is not tuple or len(values) > MAX_TERMS:
            raise Refused("policy_parts")
        return tuple(self.term(value, depth + 1) for value in values)

    def argv(self, values: tuple[Term | Splice, ...]) -> tuple[tuple[str, ...], list[object]]:
        if type(values) is not tuple or not values or len(values) > MAX_ARGUMENTS:
            raise Refused("policy_argv")
        result: list[str] = []
        origins: list[object] = []
        for value in values:
            if type(value) is Splice:
                if (type(value.choices) is not tuple or not value.choices
                        or len(value.choices) > MAX_TERMS
                        or any(type(row) is not tuple or len(row) > MAX_ARGUMENTS
                               for row in value.choices)
                        or sum(len(row) for row in value.choices) > MAX_TERMS):
                    raise Refused("policy_splice")
                for row in value.choices:
                    for item in row:
                        self.text(item)
                selected = self.take(value.slot)
                if (type(selected) is not tuple or len(selected) > MAX_ARGUMENTS
                        or any(type(item) is not str for item in selected)
                        or len(set(value.choices)) != len(value.choices)
                        or selected not in value.choices):
                    raise Refused("policy_splice_value")
                result.extend(selected)
                origins.extend([None] * len(selected))
            else:
                result.append(self.term(cast(Term, value)))
                origins.append(value)
        if (len(result) > MAX_ARGUMENTS
                or sum(len(item.encode("utf-8")) + 1 for item in result) > MAX_VECTOR_BYTES):
            raise Refused("policy_argv_bound")
        return tuple(result), origins


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
    """Render a trusted rule with separately authenticated source-derived inputs."""
    if (type(rule) is not Rule or type(rule.cases) is not tuple
            or len(rule.cases) > MAX_TERMS or type(rule.payload_kind) is not str
            or not _sha(rule.executable_sha256)
            or rule.payload_kind not in {"python-script", "python-command", "python-module",
                                         "native", "expected-exec-failure"}):
        raise Refused("policy_rule")
    renderer = _Renderer(values, roots)
    for item in (rule.id, rule.owner, case, owner, *rule.cases):
        if not renderer.text(item):
            raise Refused("policy_rule")
    if (owner != rule.owner or case not in rule.cases
            or len(set(rule.cases)) != len(rule.cases)):
        raise Refused("policy_rule")
    executable = _absolute(renderer.term(rule.executable))
    argv, origins = renderer.argv(rule.argv)
    cwd = _absolute(renderer.term(rule.cwd))
    if type(rule.environment) is not tuple or len(rule.environment) > MAX_ARGUMENTS:
        raise Refused("policy_environment")
    environment = []
    for pair in rule.environment:
        if type(pair) is not tuple or len(pair) != 2:
            raise Refused("policy_environment")
        key = renderer.text(pair[0])
        if not key or "=" in key:
            raise Refused("policy_environment_key")
        environment.append((key, renderer.term(pair[1])))
    if len({key for key, _ in environment}) != len(environment):
        raise Refused("policy_duplicate_environment")
    if sum(len(k.encode()) + len(v.encode()) + 2 for k, v in environment) > MAX_VECTOR_BYTES:
        raise Refused("policy_environment_bound")
    payload_index, payload_sha256 = _payload(argv, rule.payload_kind, rule.payload_sha256,
                                           rule.executable_sha256)
    if rule.payload_kind == "python-command":
        if payload_index is None or type(origins[payload_index]) not in (str, Program):
            raise Refused("policy_program_position")
    if (renderer.used_values != set(values) or renderer.used_roots != set(roots)):
        raise Refused("policy_unused_context")
    return Expected(rule.id, owner, case, executable, rule.executable_sha256, argv,
                    tuple(sorted(environment)), cwd, rule.payload_kind,
                    payload_sha256)


def match(expected: tuple[Expected, ...], observed: Observation,
          owner: str, case: str) -> Expected:
    """Compare complete observations; provenance must be established by the caller."""
    _text(owner)
    _text(case)
    if (type(expected) is not tuple or not expected or len(expected) > MAX_TERMS
            or any(type(item) is not Expected for item in expected)
            or type(observed) is not Observation or not _sha(observed.executable_sha256)
            or not _sha(observed.payload_sha256) or type(observed.payload_kind) is not str):
        raise Refused("policy_observation")
    executable = _absolute(_text(observed.executable))
    cwd = _absolute(_text(observed.cwd))
    if type(observed.argv) is not tuple or any(type(item) is not str for item in observed.argv):
        raise Refused("policy_observation_argv")
    renderer = _Renderer({}, {})
    argv, _ = renderer.argv(observed.argv)
    if type(observed.environment) is not tuple or len(observed.environment) > MAX_ARGUMENTS:
        raise Refused("policy_observation_environment")
    environment = []
    for pair in observed.environment:
        if type(pair) is not tuple or len(pair) != 2:
            raise Refused("policy_observation_environment")
        key, value = _text(pair[0]), _text(pair[1])
        if not key or "=" in key:
            raise Refused("policy_observation_environment")
        environment.append((key, value))
    if (len({key for key, _ in environment}) != len(environment)
            or sum(len(k.encode()) + len(v.encode()) + 2 for k, v in environment) > MAX_VECTOR_BYTES):
        raise Refused("policy_observation_environment")
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
