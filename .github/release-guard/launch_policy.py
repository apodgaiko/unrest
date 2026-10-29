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

@dataclass(frozen=True)
class Expected:
    case: str
    executable: str
    executable_sha256: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    cwd: str
    payload_kind: str
    payload_sha256: str

def _absolute(value: str) -> str:
    if (not value.startswith("/") or value.startswith("//")
            or str(PurePosixPath(value)) != value or ".." in PurePosixPath(value).parts):
        raise Refused("policy_absolute_path")
    return value


def _payload(argv: tuple[str, ...], kind: str, reference: str | None,
             executable_sha256: str) -> tuple[int | None, str]:
    if kind in {"native", "expected-exec-failure"}:
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
        return index, hashlib.sha256(argv[index].encode("utf-8")).hexdigest()
    if reference is None or not is_sha256(reference):
        raise Refused("policy_external_payload_reference")
    return index, reference


def build_expected(case: str, executable: str, executable_sha256: str,
                   argv: tuple[str, ...], environment: tuple[tuple[str, str], ...],
                   cwd: str, payload_kind: str, reference: str | None = None) -> Expected:
    """Derive the trusted builder descriptor; input validation lives at ingress."""
    _, payload_sha256 = _payload(argv, payload_kind, reference, executable_sha256)
    return Expected(case, executable, executable_sha256, argv,
                    tuple(sorted(environment)), cwd, payload_kind, payload_sha256)



def source_unit(checkout: Path,path: str,pin: str,owners=()):
    body=(checkout/path).read_bytes()
    if hashlib.sha256(body).hexdigest()!=pin:
        raise Refused('original source bytes')
    unit=ast.parse(body)
    for name in owners:
        rows=[node for node in unit.body if isinstance(node,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and node.name==name]
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


def render_string(node,substitutions):
    parts=node.values if isinstance(node,ast.JoinedStr) else (node,)
    result=[]
    index=0
    for part in parts:
        if isinstance(part,ast.Constant) and type(part.value) is str:
            result.append(part.value)
        elif (isinstance(part,ast.FormattedValue) and part.format_spec is None
                and index<len(substitutions)
                and (ast.unparse(part.value),part.conversion)==substitutions[index][:2]):
            result.append(substitutions[index][2])
            index+=1
        else:
            raise Refused('closed string template substitution')
    if index!=len(substitutions):
        raise Refused('closed string template incomplete')
    return ''.join(result)


def admit_expected(host,actor,raw,value,role,vector,script_pin=None,*,fields=None,**options):
    """Finalize an independently reconstructed declaration; never infer one."""
    if raw['argv']!=list(value.argv) or raw['environment']!=dict(value.environment) or raw['cwd']!=value.cwd:
        raise Refused('original launch operands differ from declaration')
    answer=host.admit_launch(actor,value,role,vector,script_pin,**options)
    if answer is None:
        return None
    if fields is not None:
        host.intents[answer['ticket']].update(fields)
    return {**answer,'translated':vector}
