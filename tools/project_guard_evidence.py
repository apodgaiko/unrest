"""Project an already-decrypted guard ``source-private.tar`` into closed diagnostic JSON.

Offline operator tooling for release triage. It is not enforcement, release
evidence or a product command: nothing in the guard, product or workflow invokes
it, and its output always carries ``release_assessment: not_evaluated``.

Every fact is reported by the supplied bundle and is not authenticated. Layers
are listed in a fixed display order, which is not a causal order: the tool never
elects a root cause, and the violated inventory condition stays
``cause_unavailable`` because the guard does not record it. Output contains only
fixed schema keys, closed enums, exact integers, booleans and null. Input bytes,
member names, paths, node ids, exception messages and log lines are never echoed,
including on errors.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import math
import os
import re
import stat
import sys
import tarfile
from typing import Any, NoReturn

SCHEMA = "unrest.guard-evidence-projection.v1"
ERROR_SCHEMA = "unrest.guard-evidence-projection-error.v1"
RESULT_SCHEMA = "unrest.bootstrap-source-result.v5"

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 64  # logical members returned by tarfile, not raw 512-byte headers
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_AGGREGATE_BYTES = 32 * 1024 * 1024
MAX_HEADER_SPAN = 8 * 1024
MAX_DECODED_OUTPUT = 1024 * 1024
MAX_OUTPUT_BASE64 = 4 * ((MAX_DECODED_OUTPUT + 2) // 3)
MAX_JSON_DEPTH = 64
MAX_PROJECTION_BYTES = 16 * 1024
MAX_STATUS_INT = 2**32 - 1
MAX_CLEANUP_ROWS = 32
MAX_CASES = 20_000

PREFIX = "source-private"
# Members written by .github/release-guard/source_host.py and
# prepared_distribution.py. Projected members are parsed; the others are known
# writer outputs that are counted but never read.
PROJECTED = (
    "namespace-failure.txt",
    "observer-parent-wait.json",
    "worker-failure.txt",
    "source-result.json",
    "collected-cases.json",
    "held-source-cleanup.json",
    "namespace-fallback-cleanup.json",
    "fallback-cleanup.json",
)
KNOWN_UNPROJECTED = ("dependency-bytecode.log", "package-inputs.json", "package-preparation.log")

USAGE = (
    "usage: project_guard_evidence.py DECRYPTED_SOURCE_PRIVATE_TAR\n"
    "Writes one closed-schema JSON projection to stdout. Exit 0 complete, 1 partial,\n"
    "2 rejected (closed error JSON on stderr). Release assessment: not_evaluated.\n"
)

# Exact final-line texts recognised in host-written tracebacks and in the
# subject's INTERNALERROR block. A match is a reported hint, never a proven cause.
REFUSALS = {
    "inventory finite nodes": "inventory_finite_nodes",
    "full source ambiguous case references": "ambiguous_case_references",
    "full source requires successful pytest and original uv waits": "full_source_wait_refusal",
}
WRAPPERS = {
    "RuntimeError: original source integration failed; encrypted diagnostics retained":
        "namespace_integration_failed",
    "RuntimeError: namespace child failed": "namespace_child_failed",
}
_REFUSAL_LINE = re.compile(r"(?:content_manifest\.)?Refused: (?P<code>[a-z ]+)")
_COLLECTION_FRAME = re.compile(r'  File "[^"\n]*", line [0-9]+, in pytest_collection_finish')
_INTERNALERROR = "INTERNALERROR> "


class Rejected(Exception):
    """Whole-input rejection carrying only a closed error code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Invalid(Exception):
    """Layer-level rejection carrying only a closed reason code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("json_duplicate_key")
        result[key] = value
    return result


def _nonfinite_constant(_: str) -> NoReturn:
    raise Invalid("json_nonfinite")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise Invalid("json_nonfinite")
    return value


def _depth_ok(value: Any) -> bool:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            return False
        if type(current) is dict:
            stack.extend((child, depth + 1) for child in current.values())
        elif type(current) is list:
            stack.extend((child, depth + 1) for child in current)
    return True


def _json(body: bytes) -> Any:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise Invalid("encoding_invalid") from None
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates,
                           parse_constant=_nonfinite_constant, parse_float=_finite_float)
    except Invalid:
        raise
    except RecursionError:
        raise Invalid("json_depth") from None
    except ValueError:
        raise Invalid("json_invalid") from None
    if not _depth_ok(value):
        raise Invalid("json_depth")
    return value


def _status(value: Any, nullable: bool = True) -> int | None:
    if value is None and nullable:
        return None
    if type(value) is not int or not 0 <= value <= MAX_STATUS_INT:
        raise Invalid("schema_mismatch")
    return value


def _final_line(lines: list[str]) -> str | None:
    for line in reversed(lines):
        if line:
            return line
    return None


def _refusal_hint(line: str | None) -> str:
    if line is None:
        return "unrecognised"
    match = _REFUSAL_LINE.fullmatch(line)
    if match is None:
        return "unrecognised"
    return REFUSALS.get(match.group("code"), "unrecognised")


def _text_lines(body: bytes) -> list[str]:
    try:
        return body.decode("utf-8").split("\n")
    except UnicodeDecodeError:
        raise Invalid("encoding_invalid") from None


def _namespace_failure(body: bytes) -> dict[str, Any]:
    final = _final_line(_text_lines(body))
    return {"final_line_hint": WRAPPERS.get(final or "", "unrecognised")}


def _worker_failure(body: bytes) -> dict[str, Any]:
    return {"final_line_hint": _refusal_hint(_final_line(_text_lines(body)))}


def _wait_record(body: bytes) -> dict[str, Any]:
    value = _json(body)
    if type(value) is not dict or set(value) != {"actual_parent_wait"}:
        raise Invalid("schema_mismatch")
    return {"actual_parent_wait": _status(value["actual_parent_wait"])}


def _cleanup_rows(body: bytes) -> dict[str, Any]:
    value = _json(body)
    if type(value) is not list or len(value) > MAX_CLEANUP_ROWS:
        raise Invalid("schema_mismatch")
    for row in value:
        if (type(row) is not dict
                or set(row) != {"pid", "actual_wait", "original_parent_wait_proven"}
                or row["original_parent_wait_proven"] is not False):
            raise Invalid("schema_mismatch")
        _status(row["pid"], nullable=False)
        _status(row["actual_wait"])
    return {"adopted_count": len(value)}


def _collected_cases(body: bytes) -> dict[str, Any]:
    value = _json(body)
    if (type(value) is not dict or set(value) != {"cases", "source", "dependency"}
            or type(value["cases"]) is not list or len(value["cases"]) > MAX_CASES
            or any(type(row) is not str for row in value["cases"])
            or type(value["source"]) is not str or type(value["dependency"]) is not str):
        raise Invalid("schema_mismatch")
    count = len(value["cases"])
    # An empty list is also the host's pre-collection seal: never zero-test evidence.
    evidence = "bundle_reported_nonempty" if count else "not_established"
    return {"case_count": count, "collection_evidence": evidence}


def _source_result(body: bytes) -> tuple[dict[str, Any], Any]:
    value = _json(body)
    if type(value) is not dict:
        raise Invalid("schema_mismatch")
    if value.get("schema") != RESULT_SCHEMA:
        raise Invalid("schema_unrecognised")
    required = ("source_checkpoint_ready", "completed", "outcomes", "result", "failure",
                "output_base64")
    if any(name not in value for name in required):
        raise Invalid("schema_mismatch")
    result = value["result"]
    if (type(value["source_checkpoint_ready"]) is not bool
            or type(value["completed"]) is not list or type(value["outcomes"]) is not list
            or not (result is None or type(result) is dict)
            or not (value["failure"] is None or type(value["failure"]) is str)):
        raise Invalid("schema_mismatch")
    root_wait = None
    if result is not None:
        if "root_parent_wait_raw" not in result:
            raise Invalid("schema_mismatch")
        root_wait = _status(result["root_parent_wait_raw"])
    facts = {
        "source_checkpoint_ready_reported": value["source_checkpoint_ready"],
        "completed_count": len(value["completed"]),
        "outcomes_count": len(value["outcomes"]),
        "failure_recorded": value["failure"] is not None,
        "trace_result_recorded": result is not None,
        "root_parent_wait_raw": root_wait,
    }
    return facts, value["output_base64"]


def _pytest_output(encoded: Any) -> dict[str, Any]:
    if type(encoded) is not str:
        raise Invalid("schema_mismatch")
    if len(encoded) > MAX_OUTPUT_BASE64:
        raise Invalid("output_too_large")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise Invalid("base64_invalid") from None
    if len(raw) > MAX_DECODED_OUTPUT:
        raise Invalid("output_too_large")
    # Subject output is arbitrary bytes; undecodable bytes never match a pattern.
    lines = raw.decode("utf-8", errors="replace").split("\n")
    block = [line[len(_INTERNALERROR):] for line in lines if line.startswith(_INTERNALERROR)]
    reported = bool(block)
    frame = None
    final = None
    if reported:
        hit = any(_COLLECTION_FRAME.fullmatch(line) for line in block)
        frame = "pytest_collection_finish" if hit else "unrecognised"
        final = _refusal_hint(_final_line(block))
    return {
        "decoded_bytes": len(raw),
        "internalerror_reported": reported,
        "internalerror_frame_hint": frame,
        "internalerror_final_line_hint": final,
    }


def _read_input(path: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Rejected("input_unreadable") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise Rejected("input_not_regular")
        if info.st_size > MAX_ARCHIVE_BYTES:
            raise Rejected("input_too_large")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_ARCHIVE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise Rejected("input_too_large")
        return b"".join(chunks)
    except OSError:
        raise Rejected("input_unreadable") from None
    finally:
        os.close(descriptor)


def _members(data: bytes) -> dict[str, bytes]:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except (tarfile.TarError, EOFError, OSError, ValueError, UnicodeError, RecursionError):
        raise Rejected("archive_corrupt") from None
    with archive:
        infos = []
        try:
            while True:
                info = archive.next()
                if info is None:
                    break
                infos.append(info)
                if len(infos) > MAX_MEMBERS:
                    raise Rejected("too_many_members")
            end = archive.offset
        except Rejected:
            raise
        except (tarfile.TarError, EOFError, OSError, ValueError, UnicodeError, RecursionError):
            raise Rejected("archive_corrupt") from None
        # tarfile treats a damaged later header as end-of-archive; require that
        # everything after the last member is the zero end-of-archive padding.
        tail = data[end:]
        if len(tail) < 1024 or tail.count(0) != len(tail):
            raise Rejected("archive_trailing_data")
        allowed = set(PROJECTED) | set(KNOWN_UNPROJECTED)
        seen: set[str] = set()
        aggregate = 0
        for info in infos:
            if info.offset_data - info.offset > MAX_HEADER_SPAN:
                raise Rejected("header_span_too_large")
            name = info.name
            if name in seen:
                raise Rejected("member_duplicate")
            seen.add(name)
            if name == PREFIX:
                if info.type != tarfile.DIRTYPE:
                    raise Rejected("member_type_rejected")
                continue
            head, separator, leaf = name.partition("/")
            if head != PREFIX or not separator or not leaf or "/" in leaf or "\\" in leaf:
                raise Rejected("member_name_rejected")
            if info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or info.sparse is not None:
                raise Rejected("member_type_rejected")
            if leaf not in allowed:
                raise Rejected("member_unknown")
            if not 0 <= info.size <= MAX_MEMBER_BYTES:
                raise Rejected("member_too_large")
            aggregate += info.size
            if aggregate > MAX_AGGREGATE_BYTES:
                raise Rejected("aggregate_too_large")
        # Contiguous accounting after parsing: each logical member's headers start
        # exactly where the previous member's data blocks end, beginning at offset 0,
        # and the end-of-archive marker follows the last member. Global PAX headers
        # and any other unaccounted header or gap are rejected. This does not bound
        # the work tarfile already did while parsing extension headers.
        expected = 0
        for info in infos:
            if info.offset != expected:
                raise Rejected("header_accounting_gap")
            expected = info.offset_data
            if info.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
                expected += -(-info.size // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
        if end != expected:
            raise Rejected("header_accounting_gap")
        bodies: dict[str, bytes] = {}
        for info in infos:
            if info.name == PREFIX:
                continue
            leaf = info.name.partition("/")[2]
            try:
                stream = archive.extractfile(info)
                body = b"" if stream is None else stream.read(info.size + 1)
            except (tarfile.TarError, EOFError, OSError, ValueError):
                raise Rejected("archive_corrupt") from None
            if len(body) != info.size:
                raise Rejected("archive_corrupt")
            bodies[leaf] = body
    return bodies


def _layer(name: str, source: str, state: str, reason: str | None,
           facts: dict[str, Any] | None) -> dict[str, Any]:
    return {"layer": name, "source": source, "state": state, "reason": reason, "facts": facts}


def project(data: bytes) -> tuple[dict[str, Any], int]:
    """Return (projection, exit status) for archive bytes, or raise ``Rejected``."""
    if len(data) > MAX_ARCHIVE_BYTES:
        raise Rejected("input_too_large")
    bodies = _members(data)
    layers: list[dict[str, Any]] = []
    output_value: Any = None
    result_state = "absent"

    def run(name: str, member: str, source: str, parse: Any) -> Any:
        body = bodies.get(member)
        if body is None:
            layers.append(_layer(name, source, "absent", None, None))
            return None
        try:
            parsed = parse(body)
        except Invalid as error:
            layers.append(_layer(name, source, "invalid", error.reason, None))
            return None
        return parsed

    for name, member, parse in (
        ("namespace_failure", "namespace-failure.txt", _namespace_failure),
        ("observer_parent_wait", "observer-parent-wait.json", _wait_record),
        ("worker_failure", "worker-failure.txt", _worker_failure),
    ):
        facts = run(name, member, "host_written", parse)
        if facts is not None:
            layers.append(_layer(name, "host_written", "present", None, facts))

    parsed = run("source_result", "source-result.json", "host_written", _source_result)
    if parsed is not None:
        facts, output_value = parsed
        result_state = "present"
        layers.append(_layer("source_result", "host_written", "present", None, facts))
    elif "source-result.json" in bodies:
        result_state = "invalid"

    if result_state != "present":
        layers.append(_layer("subject_output", "subject_output", "unavailable",
                             "source_result_unavailable", None))
    else:
        try:
            facts = _pytest_output(output_value)
            layers.append(_layer("subject_output", "subject_output", "present", None, facts))
        except Invalid as error:
            layers.append(_layer("subject_output", "subject_output", "invalid", error.reason, None))

    for name, member, parse in (
        ("collected_cases", "collected-cases.json", _collected_cases),
        ("held_source_cleanup", "held-source-cleanup.json", _wait_record),
        ("namespace_fallback_cleanup", "namespace-fallback-cleanup.json", _cleanup_rows),
        ("fallback_cleanup", "fallback-cleanup.json", _cleanup_rows),
    ):
        facts = run(name, member, "host_written", parse)
        if facts is not None:
            layers.append(_layer(name, "host_written", "present", None, facts))

    hints: set[str] = set()
    for layer in layers:
        for key, value in (layer["facts"] or {}).items():
            if key.endswith("final_line_hint") and value not in (None, "unrecognised"):
                hints.add(value)
    partial = result_state != "present" or any(layer["state"] == "invalid" for layer in layers)
    projection = {
        "schema": SCHEMA,
        "status": "partial" if partial else "complete",
        "trust": "bundle_reported_unauthenticated",
        "association": "bundle_reported",
        "hints_basis": "text_match",
        "layer_order": "display_only",
        "causal_election": "not_performed",
        "violated_condition": "cause_unavailable",
        "release_assessment": "not_evaluated",
        "input": {
            "archive_bytes": len(data),
            "regular_members": len(bodies),
            "known_unprojected_members": sum(1 for name in bodies if name in KNOWN_UNPROJECTED),
        },
        "layers": layers,
        "reported_hints": sorted(hints),
    }
    return projection, 1 if partial else 0


def _encode(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def _fail(code: str) -> int:
    sys.stderr.write(_encode({"schema": ERROR_SCHEMA, "error": code,
                              "release_assessment": "not_evaluated"}))
    return 2


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments in (["-h"], ["--help"]):
            sys.stdout.write(USAGE)
            return 0
        if len(arguments) != 1 or not arguments[0] or arguments[0].startswith("-"):
            return _fail("usage")
        projection, status = project(_read_input(arguments[0]))
        text = _encode(projection)
        if len(text.encode("ascii")) > MAX_PROJECTION_BYTES:
            return _fail("output_too_large")
        sys.stdout.write(text)
        return status
    except Rejected as error:
        return _fail(error.code)
    except SystemExit:
        raise
    except BaseException:
        # Never echo exception text, traceback lines or input-derived values.
        return _fail("internal_error")


if __name__ == "__main__":
    raise SystemExit(main())
