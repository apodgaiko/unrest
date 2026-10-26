"""Finite-policy unit controls, deliberately not process admission proof."""
from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import launch_policy as policy

CASE, OWNER, IMAGE = "tests/test_example.py::test_launch[work]", "source-owner-v1", "a" * 64


def rule(**changes):
    base = policy.Rule("role", OWNER, (CASE,), "/runtime/python", IMAGE,
                       ("python", "-I", "-S", "-c", "print('finite')"),
                       (("MODE", "controlled"),), "/source", "python-command")
    return replace(base, **changes)


def expected(spec=None, values=None, roots=None):
    return policy.render(spec or rule(), CASE, OWNER, values or {}, roots or {})


def observation(value):
    return policy.Observation(value.executable, value.executable_sha256, value.argv,
                              value.environment, value.cwd, value.payload_kind,
                              value.payload_sha256)


def test_literal_exact_match_separates_image_path_and_argv0():
    value = expected()
    assert value.executable == "/runtime/python" and value.argv[0] == "python"
    assert value.payload_sha256 == hashlib.sha256(value.argv[4].encode()).hexdigest()
    assert policy.match((value,), observation(value), OWNER, CASE) == value


def test_finite_program_holes_are_quoted_and_path_root_is_only_lexical():
    program = policy.Program(("path=", policy.Quoted(policy.OwnedPath("work", ("file.py",)), "python"),
                              "; role=", policy.Quoted(policy.Choice("role", ("work", "validate")),
                                                       "json"),
                              "; count=", policy.Integer("count", 1, 3)))
    spec = rule(argv=("python", "-c", program))
    root = "/owned/quote'\n;not_code"
    value = expected(spec, {"role": "work", "count": 2}, {"work": root})
    assert value.argv[2] == f"path={str(Path(root) / 'file.py')!r}; role=\"work\"; count=2"
    assert value.payload_sha256 == hashlib.sha256(value.argv[2].encode()).hexdigest()


def test_splice_and_concat_environment_render_without_interpreting_them():
    spec = rule(argv=("python", policy.Splice("flags", (("-I", "-S"), ("-B",))),
                      "-c", "pass"), environment=(("OPTION", policy.Concat(("role=",
                               policy.Choice("role", ("work", "validate"))))),))
    value = expected(spec, {"flags": ("-B",), "role": "validate"})
    assert value.argv == ("python", "-B", "-c", "pass")
    assert value.environment == (("OPTION", "role=validate"),)


@pytest.mark.parametrize("kind,argv,pin", [
    ("python-script", ("python", "-I", "/source/fixture.py"), "b" * 64),
    ("python-module", ("python", "-m", "unrest_harness.server"), "b" * 64),
    ("native", ("git", "status", "--short"), None),
    ("expected-exec-failure", ("bad-format",), None)])
def test_payload_modes_keep_external_content_and_failed_exec_distinct(kind, argv, pin):
    value = expected(rule(payload_kind=kind, argv=argv, payload_sha256=pin))
    assert value.payload_sha256 == (pin or IMAGE)
    assert policy.match((value,), observation(value), OWNER, CASE) == value


@pytest.mark.parametrize("field,value", [
    ("executable", "/runtime/other"), ("executable_sha256", "b" * 64),
    ("argv", ("python", "-I", "-S", "-c", "different")),
    ("argv", ("python", "-I", "-S", "-c", "print('finite')", "extra")),
    ("environment", (("MODE", "native"),)),
    ("environment", (("MODE", "controlled"), ("EXTRA", "value"))),
    ("environment", (("MODE", "controlled"), ("MODE", "controlled"))),
    ("cwd", "/other"), ("payload_kind", "native"), ("payload_sha256", "c" * 64),
    ("argv", ("python", "-c", policy.Concat(("print('finite')",)))),
    ("environment", (("MODE", False),))])
def test_every_observed_field_is_checked(field, value):
    original = expected()
    with pytest.raises(policy.Refused):
        policy.match((original,), replace(observation(original), **{field: value}), OWNER, CASE)


def test_wrong_owner_case_zero_and_multiple_matches_refuse():
    value = expected()
    for owner, case in (("other", CASE), (OWNER, "other")):
        with pytest.raises(policy.Refused):
            policy.match((value,), observation(value), owner, case)
    with pytest.raises(policy.Refused, match="cardinality"):
        policy.match((value, replace(value, rule="overlap")), observation(value), OWNER, CASE)
    with pytest.raises(policy.Refused):
        policy.match((), observation(value), OWNER, CASE)


@pytest.mark.parametrize("term,values,roots", [
    (policy.Integer("n", 0, 3), {"n": True}, {}),
    (policy.Integer("n", 0, 3), {"n": 4}, {}),
    (policy.Integer("n", 0, 3), {}, {}),
    (policy.Choice("role", ("work",)), {"role": "work; forbidden()"}, {}),
    (policy.Choice("role", ("work", "work")), {"role": "work"}, {}),
    (policy.OwnedPath("work", ("..",)), {}, {"work": "/owned"}),
    (policy.OwnedPath("work", ("a/b",)), {}, {"work": "/owned"}),
    (policy.OwnedPath("work"), {}, {"work": "/owned/../other"}),
    (policy.OwnedPath("work"), {}, {}),
    (policy.Quoted("body", "shell"), {}, {}),
    (policy.Program((policy.OwnedPath("work"),)), {}, {"work": "/owned"}),
    (object(), {}, {})])
def test_invalid_terms_and_context_refuse(term, values, roots):
    with pytest.raises(policy.Refused):
        policy.render(rule(environment=(("VALUE", term),)), CASE, OWNER, values, roots)


@pytest.mark.parametrize("changes", [
    {"environment": (("MODE", "controlled"), ("MODE", "controlled"))},
    {"environment": (("BAD=KEY", "x"),)},
    {"cases": (CASE, CASE)}, {"cases": (CASE, [])},
    {"payload_sha256": "b" * 64},
    {"payload_kind": "python-script"},
    {"argv": ("python", "-c", policy.Concat(("pass",)))},
    {"argv": ("python", "-m", "invalid/module"), "payload_kind": "python-module",
     "payload_sha256": "b" * 64},
    {"argv": ("python", "relative.py"), "payload_kind": "python-script",
     "payload_sha256": "b" * 64}])
def test_invalid_declarations_never_render(changes):
    with pytest.raises(policy.Refused):
        policy.render(rule(**changes), CASE, OWNER, {}, {})


def test_inline_program_cannot_be_an_unquoted_context_slot():
    with pytest.raises(policy.Refused, match="program_position"):
        policy.render(rule(argv=("python", "-c", policy.Choice("code", ("pass",)))),
                      CASE, OWNER, {"code": "pass"}, {})


def test_consistent_changed_inline_body_still_does_not_match_original():
    value = expected()
    changed = "print('different')"
    actual = replace(observation(value), argv=("python", "-c", changed),
                     payload_sha256=hashlib.sha256(changed.encode()).hexdigest())
    with pytest.raises(policy.Refused, match="match_cardinality"):
        policy.match((value,), actual, OWNER, CASE)
    with pytest.raises(policy.Refused, match="observation_payload"):
        policy.match((value,), replace(actual, payload_sha256=value.payload_sha256), OWNER, CASE)


@pytest.mark.parametrize("mode", ["python-module", "python-script", "unknown"])
def test_observed_mode_and_vector_must_agree(mode):
    value = expected()
    with pytest.raises(policy.Refused, match="payload"):
        policy.match((value,), replace(observation(value), payload_kind=mode), OWNER, CASE)


def test_external_payload_reference_and_owned_absolute_root():
    with pytest.raises(policy.Refused, match="external_payload_reference"):
        expected(rule(argv=("python", "/source/script.py"), payload_kind="python-script",
                      payload_sha256="not-a-digest"))
    value = expected(rule(cwd=policy.OwnedPath("work", ("child",))), roots={"work": "/"})
    assert value.cwd == "/child"
    assert expected(rule(cwd=policy.OwnedPath("work")), roots={"work": "/"}).cwd == "/"


def test_splice_duplicate_selected_and_aggregate_bounds(monkeypatch):
    duplicate = policy.Splice("flags", (("-B",), ("-B",)))
    with pytest.raises(policy.Refused, match="splice_value"):
        expected(rule(argv=("python", duplicate, "-c", "pass")), {"flags": ("-B",)})
    with pytest.raises(policy.Refused, match="splice_value"):
        expected(rule(argv=("python", policy.Splice("flags", (("-B",),)), "-c", "pass")),
                 {"flags": ("-B",) * (policy.MAX_ARGUMENTS + 1)})
    choices = tuple(tuple(str(i) for i in range(256)) for _ in range(5))
    with pytest.raises(policy.Refused, match="policy_splice"):
        expected(rule(argv=("python", policy.Splice("flags", choices), "-c", "pass")),
                 {"flags": choices[0]})
    with monkeypatch.context() as context:
        context.setattr(policy, "MAX_DECLARATION_BYTES", 256)
        with pytest.raises(policy.Refused, match="declaration_bound"):
            expected(rule(environment=(("VALUE", policy.Choice("v", ("x" * 100, "y" * 100))),)),
                     {"v": "x" * 100})
    with monkeypatch.context() as context:
        context.setattr(policy, "MAX_TEXT_BYTES", 100)
        with pytest.raises(policy.Refused, match="text_bound"):
            expected(rule(environment=(("VALUE", policy.Concat(("x" * 60, "y" * 60))),)))


def test_extra_context_and_all_finite_bounds_refuse(monkeypatch):
    with pytest.raises(policy.Refused, match="unused_context"):
        expected(values={"extra": "ignored"})
    with pytest.raises(policy.Refused, match="unused_context"):
        expected(roots={"extra": "/owned"})
    for name in ("MAX_ARGUMENTS", "MAX_TEXT_BYTES", "MAX_VECTOR_BYTES", "MAX_TERMS"):
        with monkeypatch.context() as context:
            context.setattr(policy, name, 1)
            with pytest.raises(policy.Refused):
                expected()
    nested = "value"
    for _ in range(policy.MAX_DEPTH + 1):
        nested = policy.Concat((nested,))
    with pytest.raises(policy.Refused, match="term_bound"):
        expected(rule(environment=(("MODE", nested),)))
