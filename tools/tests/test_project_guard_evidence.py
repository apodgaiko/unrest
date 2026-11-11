"""Standalone synthetic tests for tools/project_guard_evidence.py.

Run explicitly: ``uv run pytest -q tools/tests/test_project_guard_evidence.py``.
They sit outside the default ``tests`` collection, run in-process only and use
synthetic in-memory archives; no subprocess, network, key or real bundle.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tomllib

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "project_guard_evidence.py"
SPEC = importlib.util.spec_from_file_location("project_guard_evidence", TOOL)
assert SPEC is not None and SPEC.loader is not None
pge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pge)

SENTINEL = "SENTINEL-7f3a"
ERRORS = {
    "usage", "input_unreadable", "input_not_regular", "input_too_large", "archive_corrupt",
    "archive_trailing_data", "too_many_members", "member_name_rejected", "member_type_rejected",
    "member_duplicate", "member_too_large", "aggregate_too_large", "header_span_too_large",
    "member_unknown", "output_too_large", "internal_error", "header_accounting_gap",
}

PYTEST_OUTPUT = (
    "INTERNALERROR> Traceback (most recent call last):\n"
    'INTERNALERROR>   File "/w/_pytest/main.py", line 289, in wrap_session\n'
    "INTERNALERROR>     session.exitstatus = doit(config, session) or 0\n"
    'INTERNALERROR>   File "/w/support/full_source.py", line 36, in pytest_collection_finish\n'
    "INTERNALERROR>     value=document({'cases':nodes})\n"
    'INTERNALERROR>   File "/w/support/content_manifest.py", line 32, in refuse_if\n'
    "INTERNALERROR>     raise Refused(code)\n"
    "INTERNALERROR> content_manifest.Refused: inventory finite nodes\n"
    "INTERNALERROR> \n"
    "\n1 warning in 8.59s\n"
)
NAMESPACE_FAILURE = (
    "Traceback (most recent call last):\n"
    '  File "/w/support/namespace_supervisor.py", line 63, in run\n'
    "    callback()\n"
    '  File "/w/support/source_host.py", line 358, in supervise\n'
    "RuntimeError: original source integration failed; encrypted diagnostics retained\n"
)
WORKER_FAILURE = (
    "Traceback (most recent call last):\n"
    '  File "/w/support/source_host.py", line 268, in worker\n'
    '  File "/w/support/full_launch.py", line 76, in finished\n'
    '  File "/w/support/content_manifest.py", line 32, in refuse_if\n'
    "content_manifest.Refused: full source requires successful pytest and original uv waits\n"
)
SHA = "a" * 64


def source_result(output: str = PYTEST_OUTPUT, **overrides: object) -> bytes:
    record: dict[str, object] = {
        "schema": "unrest.bootstrap-source-result.v5",
        "wait_evidence": "kernel-original-parent-terminal-wait4-and-explicit-namespace-init-wait",
        "source_checkpoint_ready": False,
        "git_value_provenance_proven": False,
        "release_certified": False,
        "completed": [],
        "result": {"root_parent_wait_raw": 256, "records": [], "poison": None,
                   "source_checkpoint_ready": False},
        "failure": WORKER_FAILURE,
        "metadata": {"checkout": "/w/checkout", "cases": {"path": "/w/p", "sha256": SHA}},
        "kernel": [],
        "controls": [],
        "outcomes": [],
        "network_observations": {},
        "cohort_observations": [],
        "adoptions": [],
        "plan_observations": [],
        "trace_poison": None,
        "output_base64": base64.b64encode(output.encode()).decode(),
    }
    record.update(overrides)
    return json.dumps(record, sort_keys=True).encode()


def ci_shape() -> dict[str, bytes]:
    return {
        "collected-cases.json": json.dumps(
            {"cases": [], "dependency": SHA, "source": SHA}, separators=(",", ":")).encode(),
        "dependency-bytecode.log": b"",
        "fallback-cleanup.json": b"[]",
        "namespace-failure.txt": NAMESPACE_FAILURE.encode(),
        "namespace-fallback-cleanup.json": b"[]",
        "observer-parent-wait.json": b'{"actual_parent_wait": 32000}',
        "package-inputs.json": b'{"x": 1}',
        "package-preparation.log": b"build log\n",
        "source-result.json": source_result(),
        "worker-failure.txt": WORKER_FAILURE.encode(),
    }


def archive(members: dict[str, bytes] | list[tuple[str, bytes]], *, directory: bool = True,
            mutate=None) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as tar:
        if directory:
            info = tarfile.TarInfo("source-private")
            info.type = tarfile.DIRTYPE
            info.mode = 0o700
            info.mtime = 1_700_000_000.25  # float mtime forces PAX headers like the writer
            tar.addfile(info)
        rows = members.items() if isinstance(members, dict) else members
        for name, body in sorted(rows) if isinstance(members, dict) else rows:
            info = tarfile.TarInfo(name if "/" in name else "source-private/" + name)
            info.size = len(body)
            info.mtime = 1_700_000_000.5
            if mutate is not None:
                mutate(info)
            tar.addfile(info, io.BytesIO(body))
    return stream.getvalue()


def run(tmp_path: Path, data: bytes, capsys) -> tuple[int, str, str]:
    path = tmp_path / "bundle.tar"
    path.write_bytes(data)
    code = pge.main([str(path)])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def error_of(code: int, out: str, err: str) -> str:
    assert code == 2 and out == ""
    value = json.loads(err)
    assert set(value) == {"schema", "error", "release_assessment"}
    assert value["schema"] == "unrest.guard-evidence-projection-error.v1"
    assert value["release_assessment"] == "not_evaluated"
    assert value["error"] in ERRORS
    return value["error"]


def layers(projection: dict) -> dict[str, dict]:
    return {layer["layer"]: layer for layer in projection["layers"]}


# VAL-LOG-01 / VAL-LOG-02 -----------------------------------------------------

EXPECTED_CI_SHAPE = {
    "schema": "unrest.guard-evidence-projection.v1",
    "status": "complete",
    "trust": "bundle_reported_unauthenticated",
    "association": "bundle_reported",
    "hints_basis": "text_match",
    "layer_order": "display_only",
    "causal_election": "not_performed",
    "violated_condition": "cause_unavailable",
    "release_assessment": "not_evaluated",
    "reported_hints": ["full_source_wait_refusal", "inventory_finite_nodes",
                       "namespace_integration_failed"],
    "layers": [
        {"layer": "namespace_failure", "source": "host_written", "state": "present",
         "reason": None, "facts": {"final_line_hint": "namespace_integration_failed"}},
        {"layer": "observer_parent_wait", "source": "host_written", "state": "present",
         "reason": None, "facts": {"actual_parent_wait": 32000}},
        {"layer": "worker_failure", "source": "host_written", "state": "present",
         "reason": None, "facts": {"final_line_hint": "full_source_wait_refusal"}},
        {"layer": "source_result", "source": "host_written", "state": "present", "reason": None,
         "facts": {"source_checkpoint_ready_reported": False, "completed_count": 0,
                   "outcomes_count": 0, "failure_recorded": True,
                   "trace_result_recorded": True, "root_parent_wait_raw": 256}},
        {"layer": "subject_output", "source": "subject_output", "state": "present",
         "reason": None,
         "facts": {"decoded_bytes": len(PYTEST_OUTPUT.encode()), "internalerror_reported": True,
                   "internalerror_frame_hint": "pytest_collection_finish",
                   "internalerror_final_line_hint": "inventory_finite_nodes"}},
        {"layer": "collected_cases", "source": "host_written", "state": "present",
         "reason": None, "facts": {"case_count": 0, "collection_evidence": "not_established"}},
        {"layer": "held_source_cleanup", "source": "host_written", "state": "absent",
         "reason": None, "facts": None},
        {"layer": "namespace_fallback_cleanup", "source": "host_written", "state": "present",
         "reason": None, "facts": {"adopted_count": 0}},
        {"layer": "fallback_cleanup", "source": "host_written", "state": "present",
         "reason": None, "facts": {"adopted_count": 0}},
    ],
}


def test_ci_failure_shape_projects_reported_hints_without_cause(tmp_path, capsys):
    data = archive(ci_shape())
    code, out, err = run(tmp_path, data, capsys)
    assert (code, err) == (0, "")
    projection = json.loads(out)
    expected = dict(EXPECTED_CI_SHAPE)
    expected["input"] = {"archive_bytes": len(data), "regular_members": 10,
                         "known_unprojected_members": 3}
    assert projection == expected
    assert out == json.dumps(projection, sort_keys=True, separators=(",", ":")) + "\n"


def test_projection_is_deterministic_and_bounded(tmp_path, capsys):
    data = archive(ci_shape())
    first = run(tmp_path, data, capsys)
    second = run(tmp_path, data, capsys)
    assert first == second
    assert len(first[1].encode()) <= 16 * 1024


def test_successful_shape_has_no_hints_and_never_assesses_release(tmp_path, capsys):
    members = ci_shape()
    for name in ("namespace-failure.txt", "worker-failure.txt"):
        del members[name]
    members["observer-parent-wait.json"] = b'{"actual_parent_wait": 0}'
    members["collected-cases.json"] = json.dumps(
        {"cases": ["tests/test_a.py::test_x"], "dependency": SHA, "source": SHA}).encode()
    members["source-result.json"] = source_result(
        "...\n3 passed in 1.00s\n", failure=None, source_checkpoint_ready=True,
        completed=["a", "b", "c"], result={"root_parent_wait_raw": 0})
    code, out, _ = run(tmp_path, archive(members), capsys)
    projection = json.loads(out)
    assert code == 0 and projection["status"] == "complete"
    assert projection["reported_hints"] == []
    assert projection["release_assessment"] == "not_evaluated"
    assert projection["violated_condition"] == "cause_unavailable"
    view = layers(projection)
    assert view["namespace_failure"]["state"] == "absent"
    assert view["worker_failure"]["state"] == "absent"
    assert view["source_result"]["facts"]["source_checkpoint_ready_reported"] is True
    assert view["source_result"]["facts"]["completed_count"] == 3
    assert view["subject_output"]["facts"]["internalerror_reported"] is False
    assert view["subject_output"]["facts"]["internalerror_frame_hint"] is None
    assert view["collected_cases"]["facts"] == {
        "case_count": 1, "collection_evidence": "bundle_reported_nonempty"}
    assert [layer["layer"] for layer in projection["layers"]] == [
        layer["layer"] for layer in EXPECTED_CI_SHAPE["layers"]]


def test_layer_order_ignores_archive_member_order(tmp_path, capsys):
    rows = sorted(ci_shape().items(), reverse=True)
    _, forward, _ = run(tmp_path, archive(ci_shape()), capsys)
    _, backward, _ = run(tmp_path, archive(rows), capsys)
    assert json.loads(forward)["layers"] == json.loads(backward)["layers"]


@pytest.mark.parametrize(("line", "hint"), [
    ("content_manifest.Refused: inventory finite nodes", "inventory_finite_nodes"),
    ("Refused: full source ambiguous case references", "ambiguous_case_references"),
    ("content_manifest.Refused: inventory finite nodes extra", "unrecognised"),
    ("content_manifest.Refused: inventory total node bytes", "unrecognised"),
    ("other.Refused: inventory finite nodes", "unrecognised"),
    (" content_manifest.Refused: inventory finite nodes", "unrecognised"),
    ("ValueError: inventory finite nodes", "unrecognised"),
])
def test_refusal_patterns_are_exact_and_anchored(tmp_path, capsys, line, hint):
    output = PYTEST_OUTPUT.replace(
        "INTERNALERROR> content_manifest.Refused: inventory finite nodes", "INTERNALERROR> " + line)
    members = ci_shape()
    members["source-result.json"] = source_result(output)
    _, out, _ = run(tmp_path, archive(members), capsys)
    assert layers(json.loads(out))["subject_output"]["facts"][
        "internalerror_final_line_hint"] == hint


def test_collection_frame_hint_needs_exact_frame(tmp_path, capsys):
    output = PYTEST_OUTPUT.replace("in pytest_collection_finish", "in pytest_collection_finished")
    members = ci_shape()
    members["source-result.json"] = source_result(output)
    _, out, _ = run(tmp_path, archive(members), capsys)
    facts = layers(json.loads(out))["subject_output"]["facts"]
    assert facts["internalerror_frame_hint"] == "unrecognised"
    assert facts["internalerror_final_line_hint"] == "inventory_finite_nodes"


def test_namespace_child_failed_wrapper_and_unknown_final_line(tmp_path, capsys):
    members = ci_shape()
    members["namespace-failure.txt"] = b"Traceback\nRuntimeError: namespace child failed\n\n"
    members["worker-failure.txt"] = b"Traceback\nTimeoutError: source observer finite deadline\n"
    _, out, _ = run(tmp_path, archive(members), capsys)
    view = layers(json.loads(out))
    assert view["namespace_failure"]["facts"] == {"final_line_hint": "namespace_child_failed"}
    assert view["worker_failure"]["facts"] == {"final_line_hint": "unrecognised"}


# VAL-LOG-03 ------------------------------------------------------------------

def adversarial_members() -> dict[str, bytes]:
    long_node = "tests/test_" + SENTINEL + ".py::test[" + "x" * 140_000 + "]"
    output = PYTEST_OUTPUT.replace(
        "inventory finite nodes", "inventory finite nodes " + SENTINEL) + (
        f"FAILED {long_node} - AssertionError: token={SENTINEL}\n"
        f"E   Refused: {SENTINEL}\nghp_{SENTINEL}\n")
    return {
        "collected-cases.json": json.dumps(
            {"cases": [long_node], "dependency": SENTINEL, "source": SENTINEL}).encode(),
        "fallback-cleanup.json": b"[]",
        "namespace-failure.txt": f"RuntimeError: {SENTINEL} /home/{SENTINEL}\n".encode(),
        "namespace-fallback-cleanup.json": b"[]",
        "observer-parent-wait.json": b'{"actual_parent_wait": 0}',
        "package-inputs.json": json.dumps({"k": SENTINEL}).encode(),
        "package-preparation.log": SENTINEL.encode(),
        "dependency-bytecode.log": SENTINEL.encode(),
        "source-result.json": source_result(
            output, failure=f"Traceback\nRefused: {SENTINEL}\n",
            metadata={"checkout": f"/{SENTINEL}", "token": SENTINEL},
            completed=[long_node], outcomes=[{SENTINEL: SENTINEL}]),
        "worker-failure.txt": f"content_manifest.Refused: {SENTINEL}\n".encode(),
    }


def test_adversarial_strings_in_every_field_never_reach_output(tmp_path, capsys):
    code, out, err = run(tmp_path, archive(adversarial_members()), capsys)
    assert code == 0
    assert SENTINEL not in out + err and "x" * 64 not in out + err
    projection = json.loads(out)
    assert projection["reported_hints"] == []
    view = layers(projection)
    assert view["subject_output"]["facts"]["internalerror_final_line_hint"] == "unrecognised"
    assert view["namespace_failure"]["facts"]["final_line_hint"] == "unrecognised"


def assert_only_strings_are_closed(value: object) -> None:
    allowed = {
        "unrest.guard-evidence-projection.v1", "complete", "partial",
        "bundle_reported_unauthenticated", "bundle_reported", "text_match", "display_only",
        "not_performed", "cause_unavailable", "not_evaluated", "host_written", "subject_output",
        "present", "absent", "invalid", "unavailable", "unrecognised",
        "namespace_failure", "observer_parent_wait", "worker_failure", "source_result",
        "collected_cases", "held_source_cleanup", "namespace_fallback_cleanup",
        "fallback_cleanup", "pytest_collection_finish", "not_established",
        "bundle_reported_nonempty", "source_result_unavailable",
        *pge.REFUSALS.values(), *pge.WRAPPERS.values(),
        "encoding_invalid", "json_invalid", "json_duplicate_key", "json_nonfinite",
        "json_depth", "schema_mismatch", "schema_unrecognised", "base64_invalid",
        "output_too_large",
    }
    if isinstance(value, dict):
        for item in value.values():
            assert_only_strings_are_closed(item)
    elif isinstance(value, list):
        for item in value:
            assert_only_strings_are_closed(item)
    elif isinstance(value, str):
        assert value in allowed
    else:
        assert value is None or type(value) in (bool, int)


def test_projection_values_are_closed_enums_ints_bools_or_null(tmp_path, capsys):
    for members in (ci_shape(), adversarial_members()):
        _, out, _ = run(tmp_path, archive(members), capsys)
        assert_only_strings_are_closed(json.loads(out))


@pytest.mark.parametrize("argv", [
    [], ["a", "b"], [""], ["--" + SENTINEL], ["-x"], ["--help", SENTINEL],
])
def test_usage_errors_never_echo_arguments(capsys, argv):
    code = pge.main(argv)
    captured = capsys.readouterr()
    assert error_of(code, captured.out, captured.err) == "usage"
    assert SENTINEL not in captured.err


def test_help_is_fixed_text(capsys):
    assert pge.main(["--help"]) == 0
    captured = capsys.readouterr()
    assert captured.out == pge.USAGE and captured.err == ""


def test_missing_input_path_is_not_echoed(tmp_path, capsys):
    code = pge.main([str(tmp_path / ("missing-" + SENTINEL + ".tar"))])
    captured = capsys.readouterr()
    assert error_of(code, captured.out, captured.err) == "input_unreadable"
    assert SENTINEL not in captured.err and str(tmp_path) not in captured.err


def test_unknown_member_name_is_not_echoed(tmp_path, capsys):
    members = ci_shape()
    members[SENTINEL + ".txt"] = b"x"
    code, out, err = run(tmp_path, archive(members), capsys)
    assert error_of(code, out, err) == "member_unknown"
    assert SENTINEL not in err


def test_internal_failure_is_closed(tmp_path, capsys, monkeypatch):
    def explode(_: bytes) -> None:
        raise RuntimeError(SENTINEL)

    monkeypatch.setattr(pge, "project", explode)
    code, out, err = run(tmp_path, archive(ci_shape()), capsys)
    assert error_of(code, out, err) == "internal_error"
    assert SENTINEL not in err and "Traceback" not in err


# VAL-LOG-04 ------------------------------------------------------------------

def test_oversized_archive_rejected_before_read(tmp_path, capsys):
    path = tmp_path / "big.tar"
    with path.open("wb") as stream:
        stream.truncate(32 * 1024 * 1024 + 1)
    code = pge.main([str(path)])
    captured = capsys.readouterr()
    assert error_of(code, captured.out, captured.err) == "input_too_large"


def test_member_count_bound(tmp_path, capsys):
    rows = [("source-private/fallback-cleanup.json", b"[]")] * 65
    code, out, err = run(tmp_path, archive(rows), capsys)
    assert error_of(code, out, err) == "too_many_members"


def test_member_size_bound(tmp_path, capsys):
    members = ci_shape()
    members["package-preparation.log"] = b"x" * (8 * 1024 * 1024 + 1)
    code, out, err = run(tmp_path, archive(members), capsys)
    assert error_of(code, out, err) == "member_too_large"


def test_aggregate_size_bound(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(pge, "MAX_AGGREGATE_BYTES", 1000)
    members = ci_shape()
    members["package-preparation.log"] = b"x" * 900
    members["dependency-bytecode.log"] = b"y" * 900
    code, out, err = run(tmp_path, archive(members), capsys)
    assert error_of(code, out, err) == "aggregate_too_large"


def test_header_span_bound(tmp_path, capsys):
    def big_pax(info: tarfile.TarInfo) -> None:
        info.pax_headers = {"comment": SENTINEL * 1000}

    code, out, err = run(tmp_path, archive(ci_shape(), mutate=big_pax), capsys)
    assert error_of(code, out, err) == "header_span_too_large"
    assert SENTINEL not in err


@pytest.mark.parametrize(("body", "reason"), [
    (b'{"actual_parent_wait": 0, "actual_parent_wait": 1}', "json_duplicate_key"),
    (b'{"actual_parent_wait": NaN}', "json_nonfinite"),
    (b'{"actual_parent_wait": Infinity}', "json_nonfinite"),
    (b'{"actual_parent_wait": 1e999}', "json_nonfinite"),
    (b'{"actual_parent_wait": true}', "schema_mismatch"),
    (b'{"actual_parent_wait": 1.0}', "schema_mismatch"),
    (b'{"actual_parent_wait": -1}', "schema_mismatch"),
    (b'{"actual_parent_wait": 4294967296}', "schema_mismatch"),
    (b'{"actual_parent_wait": ' + b"9" * 5000 + b"}", "json_invalid"),
    (b'{"actual_parent_wait": 0, "extra": 1}', "schema_mismatch"),
    (b"[" * 65 + b"]" * 65, "json_depth"),
    (b"[" * 200_000 + b"]" * 200_000, "json_depth"),
    (b"{not json", "json_invalid"),
    (b'{"actual_parent_wait": 0}\xff', "encoding_invalid"),
])
def test_json_hazards_mark_layer_invalid(tmp_path, capsys, body, reason):
    members = ci_shape()
    members["observer-parent-wait.json"] = body
    code, out, err = run(tmp_path, archive(members), capsys)
    assert (code, err) == (1, "")
    projection = json.loads(out)
    assert projection["status"] == "partial"
    assert layers(projection)["observer_parent_wait"] == {
        "layer": "observer_parent_wait", "source": "host_written", "state": "invalid",
        "reason": reason, "facts": None}


def test_boolean_is_not_a_cleanup_count(tmp_path, capsys):
    members = ci_shape()
    members["fallback-cleanup.json"] = json.dumps(
        [{"pid": True, "actual_wait": 0, "original_parent_wait_proven": False}]).encode()
    _, out, _ = run(tmp_path, archive(members), capsys)
    assert layers(json.loads(out))["fallback_cleanup"]["reason"] == "schema_mismatch"


@pytest.mark.parametrize(("encoded", "reason"), [
    ("!!!not base64", "base64_invalid"),
    ("YWJj\n", "base64_invalid"),
    (base64.b64encode(b"x" * (1024 * 1024 + 1)).decode(), "output_too_large"),
    (7, "schema_mismatch"),
])
def test_subject_output_bounds(tmp_path, capsys, encoded, reason):
    members = ci_shape()
    record = json.loads(source_result())
    record["output_base64"] = encoded
    members["source-result.json"] = json.dumps(record).encode()
    code, out, _ = run(tmp_path, archive(members), capsys)
    view = layers(json.loads(out))
    assert code == 1
    assert view["source_result"]["state"] == "present"
    assert (view["subject_output"]["state"], view["subject_output"]["reason"]) == (
        "invalid", reason)


def test_decoded_output_at_bound_is_accepted(tmp_path, capsys):
    members = ci_shape()
    members["source-result.json"] = source_result("x" * (1024 * 1024))
    code, out, _ = run(tmp_path, archive(members), capsys)
    assert code == 0
    assert layers(json.loads(out))["subject_output"]["facts"]["decoded_bytes"] == 1024 * 1024


# VAL-LOG-05 ------------------------------------------------------------------

@pytest.mark.parametrize(("name", "kind", "error"), [
    ("source-private/held-source-cleanup.json", tarfile.SYMTYPE, "member_type_rejected"),
    ("source-private/held-source-cleanup.json", tarfile.LNKTYPE, "member_type_rejected"),
    ("source-private/held-source-cleanup.json", tarfile.FIFOTYPE, "member_type_rejected"),
    ("source-private/held-source-cleanup.json", tarfile.CHRTYPE, "member_type_rejected"),
    ("source-private/held-source-cleanup.json", tarfile.DIRTYPE, "member_type_rejected"),
    ("/source-private/held-source-cleanup.json", tarfile.REGTYPE, "member_name_rejected"),
    ("source-private/../held-source-cleanup.json", tarfile.REGTYPE, "member_name_rejected"),
    ("source-private/sub/held-source-cleanup.json", tarfile.REGTYPE, "member_name_rejected"),
    ("other/held-source-cleanup.json", tarfile.REGTYPE, "member_name_rejected"),
    ("source-private/..", tarfile.REGTYPE, "member_unknown"),
    ("source-private/cases-" + SHA + ".json", tarfile.REGTYPE, "member_unknown"),
    ("source-private/", tarfile.REGTYPE, "member_name_rejected"),
])
def test_member_policy_rejections(tmp_path, capsys, name, kind, error):
    def special(info: tarfile.TarInfo) -> None:
        if info.name == "source-private/worker-failure.txt":
            info.name = name
            info.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = "/etc/" + SENTINEL
            if kind != tarfile.REGTYPE:
                info.size = 0

    members = ci_shape()
    if kind != tarfile.REGTYPE:
        members["worker-failure.txt"] = b""
    code, out, err = run(tmp_path, archive(members, mutate=special), capsys)
    assert error_of(code, out, err) == error
    assert SENTINEL not in err


def test_prefix_must_be_a_directory(tmp_path, capsys):
    def as_prefix(info: tarfile.TarInfo) -> None:
        if info.name == "source-private/package-inputs.json":
            info.name = "source-private"

    rows = [("source-private/package-inputs.json", b"x"),
            ("source-private/fallback-cleanup.json", b"[]")]
    code, out, err = run(tmp_path, archive(rows, directory=False, mutate=as_prefix), capsys)
    assert error_of(code, out, err) == "member_type_rejected"


def test_duplicate_member_names_rejected(tmp_path, capsys):
    rows = [("source-private/worker-failure.txt", b"a"), ("source-private/worker-failure.txt", b"b")]
    code, out, err = run(tmp_path, archive(rows), capsys)
    assert error_of(code, out, err) == "member_duplicate"


def test_missing_optional_layers_are_absent_not_success(tmp_path, capsys):
    code, out, _ = run(tmp_path, archive({"source-result.json": source_result()}), capsys)
    projection = json.loads(out)
    assert code == 0
    view = layers(projection)
    for name in ("namespace_failure", "observer_parent_wait", "worker_failure",
                 "collected_cases", "held_source_cleanup", "namespace_fallback_cleanup",
                 "fallback_cleanup"):
        assert (view[name]["state"], view[name]["facts"]) == ("absent", None)
    assert projection["input"] == {"archive_bytes": len(archive(
        {"source-result.json": source_result()})), "regular_members": 1,
        "known_unprojected_members": 0}


def test_archive_without_directory_entry_is_accepted(tmp_path, capsys):
    code, out, _ = run(tmp_path, archive(ci_shape(), directory=False), capsys)
    assert code == 0 and json.loads(out)["status"] == "complete"


# VAL-LOG-06 ------------------------------------------------------------------

def test_missing_source_result_is_partial(tmp_path, capsys):
    members = ci_shape()
    del members["source-result.json"]
    code, out, _ = run(tmp_path, archive(members), capsys)
    projection = json.loads(out)
    view = layers(projection)
    assert code == 1 and projection["status"] == "partial"
    assert view["source_result"]["state"] == "absent"
    assert (view["subject_output"]["state"], view["subject_output"]["reason"]) == (
        "unavailable", "source_result_unavailable")
    assert projection["violated_condition"] == "cause_unavailable"


@pytest.mark.parametrize(("body", "reason"), [
    (json.dumps({"schema": "unrest.bootstrap-source-result.v4"}).encode(), "schema_unrecognised"),
    (b"[]", "schema_mismatch"),
    (source_result(completed=True), "schema_mismatch"),
    (source_result(result={"poison": None}), "schema_mismatch"),
    (source_result(result={"root_parent_wait_raw": False}), "schema_mismatch"),
    (source_result(failure=3), "schema_mismatch"),
    (source_result(source_checkpoint_ready=1), "schema_mismatch"),
])
def test_unrecognised_source_result_is_partial(tmp_path, capsys, body, reason):
    members = ci_shape()
    members["source-result.json"] = body
    code, out, _ = run(tmp_path, archive(members), capsys)
    view = layers(json.loads(out))
    assert code == 1
    assert (view["source_result"]["state"], view["source_result"]["reason"]) == ("invalid", reason)
    assert view["subject_output"]["state"] == "unavailable"


def test_invalid_text_encoding_marks_layer_invalid(tmp_path, capsys):
    members = ci_shape()
    members["worker-failure.txt"] = b"\xff\xfe" + WORKER_FAILURE.encode()
    code, out, _ = run(tmp_path, archive(members), capsys)
    view = layers(json.loads(out))
    assert code == 1
    assert (view["worker_failure"]["state"], view["worker_failure"]["reason"]) == (
        "invalid", "encoding_invalid")
    assert json.loads(out)["reported_hints"] == [
        "inventory_finite_nodes", "namespace_integration_failed"]


@pytest.mark.parametrize(("transform", "error"), [
    (lambda data: b"", "archive_corrupt"),
    (lambda data: b"\x00" * 10, "archive_corrupt"),
    (lambda data: b"not a tar archive" * 100, "archive_corrupt"),
    (lambda data: data[: len(data) // 2], None),
    (lambda data: data + b"trailing", "archive_trailing_data"),
])
def test_corrupt_archives_rejected(tmp_path, capsys, transform, error):
    code, out, err = run(tmp_path, transform(archive(ci_shape())), capsys)
    found = error_of(code, out, err)
    assert found == error if error else found in {"archive_corrupt", "archive_trailing_data"}


def test_damaged_later_header_is_not_silent_end_of_archive(tmp_path, capsys):
    data = bytearray(archive(ci_shape()))
    with tarfile.open(fileobj=io.BytesIO(bytes(data)), mode="r:") as tar:
        offset = tar.getmembers()[3].offset
    data[offset + 148:offset + 156] = b"0000000\x00"  # wrong header checksum
    code, out, err = run(tmp_path, bytes(data), capsys)
    assert error_of(code, out, err) == "archive_trailing_data"


def test_gzip_archive_is_not_accepted(tmp_path, capsys):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        info = tarfile.TarInfo("source-private/fallback-cleanup.json")
        info.size = 2
        tar.addfile(info, io.BytesIO(b"[]"))
    code, out, err = run(tmp_path, stream.getvalue(), capsys)
    assert error_of(code, out, err) == "archive_corrupt"


def test_input_is_never_modified(tmp_path, capsys):
    path = tmp_path / "bundle.tar"
    path.write_bytes(archive(ci_shape()))
    path.chmod(0o400)
    before = (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns,
              path.stat().st_mode)
    entries = sorted(tmp_path.iterdir())
    assert pge.main([str(path)]) == 0
    capsys.readouterr()
    assert (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns,
            path.stat().st_mode) == before
    assert sorted(tmp_path.iterdir()) == entries


def test_non_regular_inputs_rejected(tmp_path, capsys):
    target = tmp_path / "bundle.tar"
    target.write_bytes(archive(ci_shape()))
    link = tmp_path / "link.tar"
    link.symlink_to(target)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    for path, error in ((link, "input_unreadable"), (tmp_path, "input_not_regular"),
                        (fifo, "input_not_regular")):
        code = pge.main([str(path)])
        captured = capsys.readouterr()
        assert error_of(code, captured.out, captured.err) == error


# VAL-LOG-07 / VAL-LOG-08 / VAL-LOG-09 (static) -------------------------------

def test_tool_imports_are_stdlib_allowlist_only():
    tree = ast.parse(TOOL.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported == {"__future__", "base64", "binascii", "io", "json", "math", "os", "re",
                        "stat", "sys", "tarfile", "typing"}
    os_uses = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
               and isinstance(node.value, ast.Name) and node.value.id == "os"}
    assert os_uses == {"open", "O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "fstat", "read", "close"}
    calls = {node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not calls & {"open", "exec", "eval", "compile", "__import__", "print", "input"}
    text = TOOL.read_text(encoding="utf-8")
    for forbidden in ("environ", "getenv", "subprocess", "socket", "openssl", "unrest_harness",
                      "extractall", "sys.path"):
        assert forbidden not in text


def test_tool_does_not_extract_or_write(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = archive(ci_shape())
    path = tmp_path / "bundle.tar"
    path.write_bytes(data)
    entries = sorted(tmp_path.iterdir())
    pge.main([str(path)])
    capsys.readouterr()
    assert sorted(tmp_path.iterdir()) == entries


def test_tool_is_outside_default_collection_and_packaging():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["pytest"]["ini_options"]["testpaths"] == ["tests"]
    assert project["tool"]["setuptools"]["packages"]["find"]["where"] == ["src"]
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "project_guard_evidence" not in manifest
    assert "graft tools" not in manifest and "recursive-include tools" not in manifest


def test_guard_product_and_workflows_do_not_reference_tool():
    roots = [ROOT / ".github", ROOT / "src"]
    for root in roots:
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix in {".py", ".yml", ".yaml", ".toml", ".json"}:
                assert b"project_guard_evidence" not in path.read_bytes(), path.name


# Review F6: header accounting, extension chains, sparse members, writer shape -

def insert_before(data: bytes, index: int, chunk: bytes) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        offset = tar.getmembers()[index].offset
    return data[:offset] + chunk + data[offset:]


def pax_header(kind: bytes, comment: str) -> bytes:
    return tarfile.TarInfo._create_pax_generic_header({"comment": comment}, kind, "utf-8")


def gnu_longname(name: str) -> bytes:
    return tarfile.TarInfo._create_gnu_long_header(
        name, tarfile.GNUTYPE_LONGNAME, "utf-8", "strict")


@pytest.mark.parametrize("index", [0, 3])
def test_global_pax_header_before_or_between_members_rejected(tmp_path, capsys, index):
    data = insert_before(archive(ci_shape()), index, pax_header(tarfile.XGLTYPE, SENTINEL))
    code, out, err = run(tmp_path, data, capsys)
    assert error_of(code, out, err) == "header_accounting_gap"
    assert SENTINEL not in err


def test_global_pax_header_after_last_member_rejected(tmp_path, capsys):
    base = archive(ci_shape())
    with tarfile.open(fileobj=io.BytesIO(base), mode="r:") as tar:
        tar.getmembers()  # read to the end-of-archive marker before taking the offset
        end = tar.offset
    data = base[:end] + pax_header(tarfile.XGLTYPE, SENTINEL) + base[end:]
    code, out, err = run(tmp_path, data, capsys)
    # tarfile raises on an extension header followed by the end marker.
    assert error_of(code, out, err) == "archive_corrupt"
    assert SENTINEL not in err


def test_writer_global_pax_headers_rejected(tmp_path, capsys):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT,
                      pax_headers={"comment": SENTINEL}) as tar:
        for name, body in sorted(ci_shape().items()):
            info = tarfile.TarInfo("source-private/" + name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    code, out, err = run(tmp_path, stream.getvalue(), capsys)
    assert error_of(code, out, err) == "header_accounting_gap"
    assert SENTINEL not in err


def test_gap_between_members_rejected(tmp_path, capsys):
    data = insert_before(archive(ci_shape()), 3, b"\x00" * tarfile.BLOCKSIZE)
    code, out, err = run(tmp_path, data, capsys)
    assert error_of(code, out, err) in {"header_accounting_gap", "archive_trailing_data"}


def test_short_pax_chain_is_one_logical_member(tmp_path, capsys):
    # Residual, documented: raw extension headers are not counted against the
    # 64-member limit; a short chain within the 8 KiB span is one logical member.
    chain = pax_header(tarfile.XHDTYPE, SENTINEL) * 3
    code, out, err = run(tmp_path, insert_before(archive(ci_shape()), 3, chain), capsys)
    assert (code, err) == (0, "") and SENTINEL not in out
    assert json.loads(out)["status"] == "complete"


@pytest.mark.parametrize(("chunk", "count", "error"), [
    (pax_header(tarfile.XHDTYPE, SENTINEL), 10, "header_span_too_large"),
    (gnu_longname("source-private/" + SENTINEL), 10, "header_span_too_large"),
    (pax_header(tarfile.XHDTYPE, SENTINEL), 2000, "archive_corrupt"),
    (gnu_longname("source-private/" + SENTINEL), 2000, "archive_corrupt"),
])
def test_extension_header_chains_are_bounded(tmp_path, capsys, chunk, count, error):
    data = insert_before(archive(ci_shape()), 3, chunk * count)
    code, out, err = run(tmp_path, data, capsys)
    assert error_of(code, out, err) == error
    assert SENTINEL not in err


def test_gnu_longname_takes_effect_only_as_logical_member_name(tmp_path, capsys):
    chain = gnu_longname("source-private/" + SENTINEL + ".log") * 2
    code, out, err = run(tmp_path, insert_before(archive(ci_shape()), 3, chain), capsys)
    assert error_of(code, out, err) == "member_unknown"
    assert SENTINEL not in err


def test_gnu_sparse_type_rejected(tmp_path, capsys):
    def sparse(info: tarfile.TarInfo) -> None:
        if info.name == "source-private/held-source-cleanup.json":
            info.type = tarfile.GNUTYPE_SPARSE

    members = ci_shape()
    members["held-source-cleanup.json"] = b'{"actual_parent_wait": 0}'
    code, out, err = run(tmp_path, archive(members, mutate=sparse), capsys)
    assert error_of(code, out, err) == "member_type_rejected"


def test_pax_sparse_regular_member_rejected(tmp_path, capsys):
    name = "source-private/held-source-cleanup.json"
    body = b"1\n0\n5\n".ljust(512, b"\x00") + b"hello"

    def sparse(info: tarfile.TarInfo) -> None:
        if info.name == name:
            info.pax_headers = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0",
                                "GNU.sparse.name": name, "GNU.sparse.realsize": "100"}

    members = ci_shape()
    members["held-source-cleanup.json"] = body
    code, out, err = run(tmp_path, archive(members, mutate=sparse), capsys)
    assert error_of(code, out, err) == "member_type_rejected"


def test_project_rejects_oversized_bytes_directly():
    with pytest.raises(pge.Rejected) as caught:
        pge.project(b"\x00" * (pge.MAX_ARCHIVE_BYTES + 1))
    assert caught.value.code == "input_too_large"


def test_genuine_writer_shaped_archive(tmp_path, capsys):
    raw = tmp_path / "raw"
    raw.mkdir(mode=0o700)
    for name, body in ci_shape().items():
        (raw / name).write_bytes(body)
        os.utime(raw / name, (1_700_000_000.123456, 1_700_000_000.123456))
    packed = tmp_path / "source-private.tar"
    with tarfile.open(packed, "w") as stream:  # mirrors source_host.main
        stream.add(raw, arcname="source-private", recursive=True)
    with tarfile.open(packed, "r:") as tar:
        assert any(member.pax_headers for member in tar.getmembers())
    code = pge.main([str(packed)])
    captured = capsys.readouterr()
    assert (code, captured.err) == (0, "")
    projection = json.loads(captured.out)
    assert projection["layers"] == EXPECTED_CI_SHAPE["layers"]
    assert projection["reported_hints"] == EXPECTED_CI_SHAPE["reported_hints"]
    assert projection["input"]["regular_members"] == 10
