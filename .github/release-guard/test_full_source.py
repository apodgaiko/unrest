"""Ordinary pytest failures continue; collection-only cannot certify bodies."""

from types import SimpleNamespace

import pytest

from content_manifest import Refused
from full_source import FullCases


def plugin():
    calls = []
    policy = SimpleNamespace(
        children={},
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
    with pytest.raises(Refused,match="incomplete normal discovery"):
        next(finish)
    assert not calls
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
    assert full_launch.resolve(host, 123, path, vector, environment(meta), meta["checkout"]) is (not collect)
    if collect:
        assert not registrations
        return
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


def test_release_console_has_only_the_full_unexcluded_source_command():
    from source_profile import PYTEST_COMMAND
    assert PYTEST_COMMAND==('pytest','-q')


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
def test_source_invocation_cannot_select_flags_escapes_or_aliases(tmp_path, arguments):
    from source_host import invocation

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_one.py").write_text("pass")
    (tests / "alias.py").symlink_to(tests / "test_one.py")
    with pytest.raises(RuntimeError):
        invocation(arguments)


def test_only_the_full_suite_and_explicit_extracted_archive_domain_remain(tmp_path):
    from source_host import invocation
    assert invocation([]) is None
    assert invocation(['archive15',str(tmp_path)])==tmp_path
    for arguments in (['tests/test_original.py::test_one[param space]'],['--collect-only'],
            ['archive15'],['archive15',str(tmp_path),'tests/test_one.py']):
        with pytest.raises(RuntimeError):
            invocation(arguments)


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


@pytest.mark.parametrize('count,status',((0,0),(2,0),(1,17),(1,0)))
def test_queued_inquiry_fixture_requires_one_actual_parent_handle_and_success(count,status):
    from types import SimpleNamespace
    from source_root import OriginalCases
    from git_policy import FIXTURE_SERVER_INQUIRY as SERVER_INQUIRY
    from content_manifest import Refused
    waits=[]
    requests=[]
    def wait(*,timeout):
        waits.append(timeout)
        return status
    policy=SimpleNamespace(children={index:{'case':SERVER_INQUIRY,'process':SimpleNamespace(wait=wait),'wait_at_case_close':True} for index in range(count)},
        client=SimpleNamespace(request=lambda kind,payload:requests.append((kind,payload))),case=SERVER_INQUIRY)
    policy.children['already-waited-git']={'case':SERVER_INQUIRY,'process':SimpleNamespace(wait=lambda **kwargs:pytest.fail('fixture Git handle is not the queued worker'))}
    cases=OriginalCases(SimpleNamespace(profile={'cases':[]}))
    cases.policy=policy
    if count!=1 or status:
        with pytest.raises(Refused):
            cases.leave(SERVER_INQUIRY,'passed',{})
        assert not requests
    else:
        cases.leave(SERVER_INQUIRY,'passed',{})
        assert waits==[5] and requests==[('case-finish',{'case':SERVER_INQUIRY})]


def test_durable_case_finish_waits_its_actual_child_handle_before_sending_completion():
    import subprocess
    import sys
    from types import SimpleNamespace
    from approval_launch import RUNS
    from source_root import OriginalCases
    child=subprocess.Popen([sys.executable,'-c','pass'],stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    calls=[]
    def request(kind,payload):
        assert child.returncode==0
        calls.append((kind,payload))
    policy=SimpleNamespace(case=RUNS[0],children={child.pid:{'case':RUNS[0],'process':child,'wait_at_case_close':True}},
        client=SimpleNamespace(request=request))
    cases=OriginalCases(SimpleNamespace(profile={'cases':[]}))
    cases.policy=policy
    try:
        cases.leave(RUNS[0],'passed',{})
        assert child.returncode==0 and calls==[('case-finish',{'case':RUNS[0]})]
    finally:
        child.wait(timeout=5)


@pytest.mark.parametrize('phase', ('setup', 'body'))
def test_exact_nested_failure_keeps_outer_temp_policy_and_cleanup(tmp_path, monkeypatch, phase):
    import os
    from pathlib import Path
    import source_entry
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root))
    from tests.test_session_resource_ownership import test_actual_pytest_failure_finalizes_exact_factory

    outer = tmp_path / 'pytest'
    outer.mkdir()
    sentinel = outer / 'outer-sentinel'
    sentinel.write_text('retain outer lifetime')
    case_root = outer / ('ownership-' + phase)
    case_root.mkdir()
    root = Path(__file__).resolve().parents[2]
    case = 'tests/test_session_resource_ownership.py::test_actual_pytest_failure_finalizes_exact_factory[' + phase + ']'
    profile = {'role': 'root', 'cases': ['original-collection'], 'checkout': str(root), 'owned': str(tmp_path)}
    policy = SimpleNamespace(profile=profile, case=case)
    monkeypatch.setattr(source_entry, 'ACTIVE', policy)
    monkeypatch.setenv('PYTEST_PLUGINS', 'full_source')
    monkeypatch.setenv('PYTEST_ADDOPTS', '--basetemp=' + str(outer))
    environment = dict(os.environ)
    test_actual_pytest_failure_finalizes_exact_factory(case_root, monkeypatch, phase)
    assert policy.case == case and policy.profile is profile
    assert profile['cases'] == ['original-collection'] and policy.nested_case == case
    assert sentinel.read_text() == 'retain outer lifetime'
    # pytest itself removes its current-test marker after the inner teardown.
    assert {key: value for key, value in os.environ.items() if key != 'PYTEST_CURRENT_TEST'} == {
        key: value for key, value in environment.items() if key != 'PYTEST_CURRENT_TEST'}


@pytest.mark.parametrize('mutation', ('case', 'argv', 'body', 'basename', 'outside', 'symlink', 'repeated'))
def test_nested_pytest_rejects_every_non_original_invocation(tmp_path, monkeypatch, mutation):
    import ast
    from pathlib import Path
    import full_source
    import source_entry

    root = Path(__file__).resolve().parents[2]
    tree = ast.parse((root / 'tests/test_session_resource_ownership.py').read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'test_actual_pytest_failure_finalizes_exact_factory')
    template = next(node.value for node in ast.walk(function) if isinstance(node, ast.Constant)
                    and isinstance(node.value, str) and node.value.startswith('import pytest\n'))
    outer = tmp_path / 'pytest'
    outer.mkdir()
    source = outer / 'test_owned_failure_setup.py'
    source.write_text(template.replace('PHASE', repr('setup')))
    case = 'tests/test_session_resource_ownership.py::test_actual_pytest_failure_finalizes_exact_factory[setup]'
    policy = SimpleNamespace(profile={'role': 'root', 'cases': ['collected'], 'checkout': str(root), 'owned': str(tmp_path)}, case=case)
    if mutation == 'case':
        policy.case = 'tests/unrelated.py::test_one'
    elif mutation == 'body':
        source.write_text('pass\n')
    elif mutation in ('basename', 'outside'):
        destination = outer / 'other.py' if mutation == 'basename' else tmp_path / source.name
        source.rename(destination)
        source = destination
    elif mutation == 'symlink':
        target = outer / 'body.py'
        source.rename(target)
        source.symlink_to(target)
    elif mutation == 'repeated':
        policy.nested_case = case
    args = ('-c', str(root / 'pyproject.toml'), '-q', str(source))
    if mutation == 'argv':
        args += ('--collect-only',)
    config = SimpleNamespace(invocation_params=SimpleNamespace(args=args), option=SimpleNamespace(basetemp='outer'))
    monkeypatch.setattr(source_entry, 'ACTIVE', policy)
    with pytest.raises(Refused):
        full_source.pytest_configure(config)
    assert config.option.basetemp == 'outer'
