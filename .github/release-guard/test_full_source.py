"""Ordinary pytest failures continue; collection-only cannot certify bodies."""

from types import SimpleNamespace

import pytest

from content_manifest import Refused
from full_source import FullCases


def plugin():
    calls = []
    policy = SimpleNamespace(
        profile={"cases": ["tests/test_plain.py::test_one"]},
        poison=False,
        client=SimpleNamespace(request=lambda *args: calls.append(args)),
        case=None,
    )
    proof = FullCases(policy)
    item = SimpleNamespace(nodeid=policy.profile["cases"][0])
    proof.items = (item,)
    return proof, item, calls


def test_real_assertion_failure_is_retained_without_truncating_pytest():
    proof, item, calls = plugin()
    protocol = proof.pytest_runtest_protocol(item, None)
    next(protocol)
    proof.reports[item.nodeid] = {"setup": "passed", "call": "failed", "teardown": "passed"}
    with pytest.raises(StopIteration):
        next(protocol)
    assert proof.completed == [item.nodeid]
    assert calls[-1][1]["outcome"] == "failed"
    proof.pytest_sessionfinish(
        SimpleNamespace(config=SimpleNamespace(option=SimpleNamespace(collectonly=False))), 1
    )
    assert not any(kind == "root-finish" for kind, _ in calls)


def test_caught_forbidden_effect_still_fails_even_if_pytest_reports_pass():
    proof, item, calls = plugin()
    protocol = proof.pytest_runtest_protocol(item, None)
    next(protocol)
    proof.reports[item.nodeid] = {"setup": "passed", "call": "passed", "teardown": "passed"}
    proof.policy.poison = True
    with pytest.raises(Refused, match="forbidden"):
        next(protocol)
    assert not proof.completed
    assert not any(kind == "case-finish" for kind, _ in calls)


def test_collection_only_emits_no_source_checkpoint_completion():
    proof, _, calls = plugin()
    proof.pytest_sessionfinish(
        SimpleNamespace(config=SimpleNamespace(option=SimpleNamespace(collectonly=True))), 0
    )
    assert [kind for kind, _ in calls] == ["collection-finish"]
    assert not proof.completed
