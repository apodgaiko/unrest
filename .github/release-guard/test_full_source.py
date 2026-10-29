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
    finish = proof.pytest_sessionfinish(
        SimpleNamespace(
            exitstatus=1, config=SimpleNamespace(option=SimpleNamespace(collectonly=False))
        ),
        1,
    )
    next(finish)
    with pytest.raises(StopIteration):
        next(finish)
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
    finish = proof.pytest_sessionfinish(
        SimpleNamespace(
            exitstatus=0, config=SimpleNamespace(option=SimpleNamespace(collectonly=True))
        ),
        0,
    )
    next(finish)
    with pytest.raises(StopIteration):
        next(finish)
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
        "selection": [],
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


@pytest.mark.parametrize(
    "mutation", [None, "argv0", "arguments", "path", "environment", "pin", "parent"]
)
def test_native_console_binds_actual_image_separately_from_uv_argv0(
    tmp_path, monkeypatch, mutation
):
    import full_launch
    from full_source import child_environment

    meta = {
        "selection": [],
        "runtime_root": str(tmp_path / "runtime"),
        "owned": str(tmp_path / "owned"),
        "checkout": str(tmp_path / "source"),
    }
    child, parent = object(), SimpleNamespace(pid=123)
    calls = []
    host = SimpleNamespace(
        meta=meta,
        launcher=123,
        binding={"entry": {"sha256": "a" * 64}},
        ledger=SimpleNamespace(
            current={124: child}, process=lambda birth: SimpleNamespace(parent=parent, generation=0)
        ),
        profile=lambda *args: calls.append(args),
        full_started=False,
    )
    path = str(tmp_path / "runtime/bin/pytest")
    vector = ["pytest", "-q"]
    env = child_environment(meta)
    if mutation == "argv0":
        vector[0] = path
    elif mutation == "arguments":
        vector.append("--ignore=tests")
    elif mutation == "path":
        path = str(tmp_path / "other")
    elif mutation == "environment":
        env["EXTRA"] = "forbidden"
    elif mutation == "parent":
        parent.pid = 999
    monkeypatch.setattr(
        full_launch, "native_digest", lambda p: "b" * 64 if mutation == "pin" else "a" * 64
    )
    assert full_launch.resolve(host, 124, path, vector, env, meta["checkout"]) is (mutation is None)
    if mutation is None:
        assert host.root == 124 and host.full_started
        assert calls[0][3] == [path, "-I", "-S", "-m", "pytest", "-q"]
    else:
        assert not calls and not host.full_started


def test_long_original_test_id_keeps_its_case_and_reports_through_compact_reference():
    from case_inventory import identity

    proof, item, calls = plugin()
    item.nodeid = "tests/test_wire.py::test_large[" + "x" * 70000 + "]"
    name = identity(item.nodeid)
    proof.cases = (name,)
    proof.policy.profile["cases"] = [name]
    protocol = proof.pytest_runtest_protocol(item, None)
    next(protocol)
    report = SimpleNamespace(nodeid=item.nodeid, when="setup", outcome="passed", failed=False)
    proof.pytest_runtest_logreport(report)
    report.when = "call"
    proof.pytest_runtest_logreport(report)
    report.when = "teardown"
    proof.pytest_runtest_logreport(report)
    with pytest.raises(StopIteration):
        next(protocol)
    assert proof.completed == [name]
    assert [
        payload["case"] for kind, payload in calls if kind in ("case-start", "case-finish")
    ] == [name, name]


def test_observer_collection_reply_carries_success_and_closed_reference(tmp_path, monkeypatch):
    import hashlib
    import json
    import os
    from pathlib import Path
    import full_launch
    from control_transport import reply, verify_reply, encode, RESPONSE_LIMIT

    import stat

    original_fstat, original_stat = os.fstat, os.stat

    def source_owner(info):
        if not stat.S_ISREG(info.st_mode):
            return info
        row = list(info)
        row[4] = 20000
        return os.stat_result(row)

    monkeypatch.setattr(os, "fstat", lambda fd: source_owner(original_fstat(fd)))
    monkeypatch.setattr(
        os, "stat", lambda *args, **kwargs: source_owner(original_stat(*args, **kwargs))
    )
    reference = {"path": "/profiles/cases-bound.json", "sha256": "c" * 64, "count": 1}
    monkeypatch.setattr(full_launch, "seal", lambda value, directory: dict(reference))
    node = "tests/test_wire.py::test_large[" + "x" * 70000 + "]"
    body = json.dumps(
        {"cases": [node], "source": "a" * 64, "dependency": "b" * 64}
    ).encode()
    path = tmp_path / "collection.json"
    path.write_bytes(body)
    path.chmod(0o444)
    host = SimpleNamespace(
        full=True,
        cases=(),
        directory=Path("/profiles"),
        meta={"owned": str(tmp_path), "source_sha256": "a" * 64, "dependency_sha256": "b" * 64},
        root_only=lambda actor: None,
    )
    payload = {"path": str(path), "sha256": hashlib.sha256(body).hexdigest()}
    answer = full_launch.collection(host, object(), payload)
    request = {"kind": "collection", "payload": payload}
    decoded = verify_reply(reply(request, answer), request)
    assert decoded == {"ok": True, "reference": reference}
    assert decoded["ok"] is True  # Native Client.request requires this before returning.
    assert len(encode(reply(request, answer), RESPONSE_LIMIT)) < 1024
    from case_inventory import identity

    assert host.cases == (identity(node),)
    assert host.meta["cases"] == reference


@pytest.mark.parametrize("collect", [False, True])
def test_late_session_failure_cannot_seal_success(collect):
    proof, item, calls = plugin()
    proof.completed = [] if collect else [item.nodeid]
    manager = pytest.PytestPluginManager()
    manager.register(proof)

    class LateFailure:
        def pytest_sessionfinish(self, session):
            session.exitstatus = 1

    manager.register(LateFailure())
    session = SimpleNamespace(
        exitstatus=0, config=SimpleNamespace(option=SimpleNamespace(collectonly=collect))
    )
    if collect:
        with pytest.raises(Refused, match="collection failed"):
            manager.hook.pytest_sessionfinish(session=session, exitstatus=0)
    else:
        manager.hook.pytest_sessionfinish(session=session, exitstatus=0)
    assert not any(kind in ("root-finish", "collection-finish") for kind, _ in calls)


@pytest.mark.parametrize("collect", [False, True])
def test_raising_session_hook_cannot_seal_success(collect):
    proof, item, calls = plugin()
    proof.completed = [] if collect else [item.nodeid]
    manager = pytest.PytestPluginManager()
    manager.register(proof)

    class BrokenFinalizer:
        def pytest_sessionfinish(self):
            raise RuntimeError("late finalizer failed")

    manager.register(BrokenFinalizer())
    session = SimpleNamespace(
        exitstatus=0, config=SimpleNamespace(option=SimpleNamespace(collectonly=collect))
    )
    with pytest.raises(RuntimeError, match="late finalizer failed"):
        manager.hook.pytest_sessionfinish(session=session, exitstatus=0)
    assert not any(kind in ("root-finish", "collection-finish") for kind, _ in calls)


@pytest.mark.parametrize("selected", [[], ["tests/test_full_source.py::test_one[param space]"]])
@pytest.mark.parametrize("collect", [False, True])
def test_one_suffix_is_shared_by_diagnostic_and_release_console(selected, collect):
    from source_profile import pytest_arguments

    assert pytest_arguments({"selection": selected}, {"collection_only": collect}) == [
        "pytest",
        "-q",
        *selected,
        *(["--collect-only"] if collect else []),
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        ["--ignore=tests/test_one.py"],
        ["full"],
        ["full-collect"],
        ["../tests/test_one.py"],
        ["tests/../test_one.py"],
        ["/tests/test_one.py"],
        ["tests/test_one.txt"],
        ["tests/missing.py"],
        ["tests/test_one.py\0::test_one"],
        ["./tests/test_one.py"],
        ["tests/alias.py"],
    ],
)
def test_diagnostic_selection_cannot_select_flags_escapes_or_aliases(tmp_path, arguments):
    from source_host import selection

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_one.py").write_text("pass")
    (tests / "alias.py").symlink_to(tests / "test_one.py")
    with pytest.raises(RuntimeError):
        selection(arguments, tmp_path)


def test_selection_keeps_node_text_without_granting_launch_permission(tmp_path):
    from source_host import selection, unexcluded

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_one.py").write_text("pass")
    node = "tests/test_one.py::test_original[space ../literal]"
    assert selection([node], tmp_path) == [node]
    assert not unexcluded({"cases": {}, "selection": [node]}, {})
    assert not unexcluded({"cases": {}}, {})
    assert not unexcluded({"cases": {}, "selection": []}, {"collection_only": True})
    assert unexcluded({"cases": {}, "selection": []}, {"collection_only": False})
    assert not unexcluded({"cases": ["archive"], "selection": []}, {})


def test_empty_preparation_inventory_roundtrips_through_actual_receiver(tmp_path,monkeypatch):
    import case_inventory
    import full_launch
    from test_case_inventory import observer_files
    observer_files(monkeypatch)
    monkeypatch.setattr(full_launch,'prepare_uv',lambda metadata:None)
    metadata={'source_sha256':'a'*64,'dependency_sha256':'b'*64}
    prepared=full_launch.prepare({'profiles':str(tmp_path)},metadata)
    assert case_inventory.load(prepared['cases'],tmp_path,'a'*64,'b'*64)=={
        'cases':[],'source':'a'*64,'dependency':'b'*64}
    assert prepared['cases']['count']==0
