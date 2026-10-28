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


@pytest.mark.parametrize("collect", [False, True])
def test_fixed_uv_launcher_binds_collection_only_as_an_explicit_argument(
    tmp_path, monkeypatch, collect
):
    import full_launch
    import hashlib
    from full_source import environment

    meta = {
        "runtime_root": str(tmp_path / "runtime"),
        "owned": str(tmp_path / "owned"),
        "checkout": str(tmp_path / "source"),
    }
    image = tmp_path / "runtime/bin/uv"
    image.parent.mkdir(parents=True)
    content = b"v" * (17 * 1024 * 1024)
    image.write_bytes(content)
    image.chmod(0o755)
    image_pin = hashlib.sha256(content).hexdigest()
    registrations = []
    birth = object()
    host = SimpleNamespace(
        meta=meta,
        launcher=123,
        binding={"collection_only": collect, "uv": {"path": str(image), "sha256": image_pin}},
        ledger=SimpleNamespace(
            current={123: birth},
            process=lambda value: SimpleNamespace(generation=1, parent=None),
            register=lambda *args, **kwargs: registrations.append((args, kwargs)),
        ),
    )
    vector = ["uv", "run", "pytest", "-q", *(["--collect-only"] if collect else [])]
    path = str(tmp_path / "runtime/bin/uv")
    assert full_launch.resolve(host, 123, path, vector, environment(meta), meta["checkout"])
    assert registrations[-1][1]["expected_generation"] == 2
    host.binding["uv"]["sha256"] = "0" * 64
    assert not full_launch.resolve(host, 123, path, vector, environment(meta), meta["checkout"])
    assert len(registrations) == 1
    host.binding["uv"]["sha256"] = image_pin
    assert not full_launch.resolve(
        host, 123, path, [*vector, "--ignore=tests"], environment(meta), meta["checkout"]
    )
