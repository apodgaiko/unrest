"""Finite literal launch rendering; declarations are not execution authority.

The observer must select the finite case, parameter values and acquired root
generations independently; metadata labels confer no execution authority. No value may be inferred
from an untrusted launch vector merely to make a declaration accept that vector.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath

from content_manifest import Refused, is_sha256

MAX_ARGUMENTS = 256
MAX_TEXT_BYTES = 131_071
MAX_VECTOR_BYTES = 2 * 1024 * 1024
MAX_FIELDS = 1024
MAX_DECLARATION_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class Expected:
    rule: str
    case: str
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
        if '=' in key:
            raise Refused('policy_environment_key')
        result.append((key, item))
    if len({key for key, _ in result}) != len(result):
        raise Refused('policy_duplicate_environment')
    if sum(len(key.encode()) + len(item.encode()) + 2 for key, item in result) > MAX_VECTOR_BYTES:
        raise Refused('policy_environment_bound')
    return tuple(sorted(result))


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
    if reference is None or not is_sha256(reference):
        raise Refused("policy_external_payload_reference")
    return index, reference


def build_expected(rule: str, case: str, executable: str, executable_sha256: str,
                   argv: tuple[str, ...], environment: tuple[tuple[str, str], ...],
                   cwd: str, payload_kind: str, reference: str | None = None) -> Expected:
    """Validate the observer-selected declaration without an intermediate policy."""
    if not is_sha256(executable_sha256) or type(payload_kind) is not str:
        raise Refused('policy_rule')
    budget = _Budget()
    for item in (rule, case):
        if not budget.text(item):
            raise Refused('policy_rule')
    executable = _absolute(budget.text(executable))
    argv = _argv(argv, budget)
    cwd = _absolute(budget.text(cwd))
    environment = _environment(environment, budget)
    _, payload_sha256 = _payload(argv, payload_kind, reference, executable_sha256)
    return Expected(rule, case, executable, executable_sha256, argv,
                    environment, cwd, payload_kind, payload_sha256)



def source_unit(checkout: Path,path: str,pin: str,owners=()):
    body=(checkout/path).read_bytes()
    if hashlib.sha256(body).hexdigest()!=pin:
        raise Refused('original source bytes')
    unit=ast.parse(body)
    for name in owners:
        rows=[node for node in unit.body if isinstance(node,(ast.ClassDef,ast.FunctionDef)) and node.name==name]
        if len(rows)!=1:
            raise Refused('sole original source owner')
        unit=rows[0]
    return unit


def assignment(unit,name):
    rows=[node.value for node in unit.body if isinstance(node,ast.Assign) and len(node.targets)==1
          and isinstance(node.targets[0],ast.Name) and node.targets[0].id==name]
    if len(rows)!=1:
        raise Refused('sole original source assignment')
    return rows[0]


def literal(unit,name):
    value=assignment(unit,name)
    if not isinstance(value,ast.Constant) or type(value.value) is not str:
        raise Refused('original string literal')
    return value.value
