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

from content_manifest import Refused, is_sha256, refuse_if

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
    refuse_if(kind not in {"python-command", "python-module", "python-script"}, "policy_payload_kind")
    index = 1
    flags = {"-I", "-S", "-B", "-E", "-s", "-u", "-q", "-O", "-OO", "-b", "-bb"}
    while index < len(argv) and argv[index] in flags:
        index += 1
    refuse_if(index >= len(argv), "policy_python_payload_missing")
    actual = {"-c": "python-command", "-m": "python-module"}.get(argv[index], "python-script")
    refuse_if(actual != kind, "policy_payload_mode_mismatch")
    index += int(actual != "python-script")
    refuse_if(index >= len(argv), "policy_python_payload_missing")
    if kind == "python-command":
        return index, hashlib.sha256(argv[index].encode("utf-8")).hexdigest()
    refuse_if(reference is None or not is_sha256(reference), "policy_external_payload_reference")
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
    refuse_if(hashlib.sha256(body).hexdigest()!=pin, 'original source bytes')
    unit=ast.parse(body)
    for name in owners:
        unit=next(node for node in unit.body if isinstance(node,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and node.name==name)
    return unit


def assignment(unit,name):
    return next(node.value for node in unit.body if isinstance(node,ast.Assign) and len(node.targets)==1
                and isinstance(node.targets[0],ast.Name) and node.targets[0].id==name)


def literal(unit,name):
    return assignment(unit,name).value


def pinned_body(argv,pin):
    if len(argv)<3 or argv[1]!='-c' or hashlib.sha256(argv[2].encode('utf-8')).hexdigest()!=pin:
        raise Refused('declared inline body bytes')
    return argv[2]


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
    refuse_if(index!=len(substitutions), 'closed string template incomplete')
    return ''.join(result)


def check_expected(raw,value):
    if raw['argv']!=list(value.argv) or raw['environment']!=dict(value.environment) or raw['cwd']!=value.cwd:
        raise Refused('original launch operands differ from declaration')


def admit_expected(host,actor,raw,value,role,vector,script_pin=None,*,fields=None,**options):
    """Finalize an independently reconstructed declaration; never infer one."""
    check_expected(raw,value)
    answer=host.admit_launch(actor,value,role,vector,script_pin,**options)
    if answer is None:
        return None
    if fields is not None:
        host.intents[answer['ticket']].update(fields)
    return {**answer,'translated':vector}
