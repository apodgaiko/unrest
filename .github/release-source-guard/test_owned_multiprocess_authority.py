"""Dispatch checks only; kernel custody still requires the finite Linux probe."""

from types import SimpleNamespace

import pytest

import owned_multiprocess_authority as owned
from primary_dependency_authority import DependencySourceAuthority as DependencyAuthority


@pytest.mark.parametrize("kind", ["source-multiprocess-tracker", "source-multiprocess-spawn"])
def test_owned_dispatch_propagates_custody_failure_and_poison(monkeypatch, kind):
    authority = object.__new__(owned.SourceAuthority)
    authority.bound = {42: {"registration": {"class": kind}}}
    poison = []
    authority.supervisor = SimpleNamespace(poison=poison.append)
    trace = SimpleNamespace(poison=[])
    cause = RuntimeError("custody refused")

    def refuse(*args):
        assert args == (authority, trace, 42, ["runtime"], {"env": "value"}, "/case")
        raise cause

    monkeypatch.setattr(owned, "exec_custody", refuse)
    with pytest.raises(RuntimeError) as caught:
        authority.exec_descriptors(trace, 42, ["runtime"], {"env": "value"}, "/case")
    assert caught.value is cause
    assert poison == trace.poison == ["primary_source_multiprocess_custody"]


def test_unrelated_dispatch_retains_original_dependency_chain(monkeypatch):
    authority = object.__new__(owned.DependencySourceAuthority)
    authority.bound = {42: {"registration": {"class": "original-class"}}}
    expected = object()
    calls = []

    def original(*args):
        calls.append(args)
        return expected

    monkeypatch.setattr(owned.OriginalSourceAuthority, "exec_descriptors", original)
    assert issubclass(owned.DependencySourceAuthority, DependencyAuthority)
    assert authority.exec_descriptors("trace", 42, ["runtime"], {}, "/case") is expected
    assert calls == [(authority, "trace", 42, ["runtime"], {}, "/case")]
