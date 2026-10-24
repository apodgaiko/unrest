"""Exact finite cutoff setup and two-stage wrapper dispatch negatives."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from finite import (
    bootstrap_stdlib as wrapper,
    delayed_bootstrap as route,
    mock_backend_setup as setup,
)

ROOT = Path(__file__).resolve().parents[2]


def fixture(tmp_path):
    target = tmp_path / "owned/fake-app-server"
    target.parent.mkdir()
    target.write_bytes((ROOT / "tests/fixtures/experimental_session_app_server.py").read_bytes())
    interpreter = "/pinned/python"
    argv = [interpreter, "-I", "-S", "-c", wrapper.BODY, str(target), "app-server"]
    binding = {"path": str(ROOT / wrapper.SOURCE), "line": 38, "sha256": wrapper.PIN}
    payload = {
        "class": "source-canonical-stdlib-backend",
        "case": wrapper.CASE,
        "token": "exact",
        "mode": "inline",
        "isolated": True,
        "path0": "",
        "target": wrapper.BODY,
        "orig_argv": argv,
        "sys_argv": ["-c", *argv[5:]],
        "source_binding": binding,
    }
    state = {
        "class": payload["class"],
        "case": wrapper.CASE,
        "phase": "READY",
        "token": "exact",
        "checkout": str(ROOT),
        "owned_root": str(target.parent),
        "runtime": {"paths": [interpreter]},
        "product_pins": {wrapper.SOURCE: wrapper.PIN},
    }
    endpoint = {"token": "exact", "identity": {"pid": os.getpid()}}
    return state, endpoint, payload


@pytest.mark.parametrize(
    "change",
    [
        None,
        "case",
        "class",
        "phase",
        "token",
        "endpoint",
        "pid",
        "body",
        "delay",
        "flags",
        "interpreter",
        "source",
        "line",
        "pin",
        "sys-argv",
        "target-bytes",
        "symlink",
        "owned-root",
        "setup-drift",
    ],
)
def test_only_original_half_second_wrapper_has_stdlib_setup(tmp_path, change):
    state, endpoint, payload = fixture(tmp_path)
    if change in {"case", "class", "phase", "token"}:
        state[change] = "foreign"
    elif change == "endpoint":
        endpoint["token"] = "foreign"
    elif change == "pid":
        endpoint["identity"]["pid"] += 1
    elif change in {"body", "delay"}:
        payload["target"] += "; pass"
    elif change == "flags":
        payload["orig_argv"][1] = "-E"
    elif change == "interpreter":
        payload["orig_argv"][0] = "/foreign"
    elif change in {"source", "line", "pin"}:
        payload["source_binding"][{"source": "path", "line": "line", "pin": "sha256"}[change]] = (
            "foreign"
        )
    elif change == "sys-argv":
        payload["sys_argv"].append("foreign")
    elif change == "target-bytes":
        Path(payload["sys_argv"][1]).write_text("foreign")
    elif change == "symlink":
        target = Path(payload["sys_argv"][1])
        target.rename(target.with_name("other"))
        target.symlink_to(target.with_name("other"))
    elif change == "owned-root":
        state["owned_root"] = str(tmp_path / "other")
    elif change == "setup-drift":
        state["product_pins"][wrapper.SOURCE] = "0" * 64
    before = deepcopy((state, endpoint, payload))
    assert wrapper.inline_eligible(state, endpoint, payload) is (change is None)
    assert (state, endpoint, payload) == before


@pytest.mark.parametrize(
    "change",
    [
        None,
        "repeat",
        "code",
        "caller",
        "globals",
        "payload",
        "namespace",
        "recorded-code",
        "recorded-namespace",
    ],
)
def test_wrapper_dispatch_is_once_only_exact_guard_child_namespace(change):
    guard = ModuleType("guard")
    exec("def child(): pass", vars(guard))
    payload = {"target": wrapper.BODY}
    code = compile(wrapper.BODY, "<string>", "exec", dont_inherit=True)
    namespace = {
        "__name__": "__main__",
        "__package__": None,
        "__spec__": None,
        "__builtins__": guard.child.__builtins__,
    }
    guard._STATE = {"payload_code": code, "payload_globals": namespace}
    frame = SimpleNamespace(
        f_code=guard.child.__code__,
        f_globals=vars(guard),
        f_locals={"payload": payload, "code": code, "namespace": namespace},
    )
    if change == "code":
        code = compile("pass", "<string>", "exec")
    elif change == "caller":
        frame.f_code = (lambda: None).__code__
    elif change == "globals":
        frame.f_globals = {}
    elif change == "payload":
        frame.f_locals["payload"] = dict(payload)
    elif change == "namespace":
        namespace["foreign"] = True
    elif change == "recorded-code":
        guard._STATE["payload_code"] = None
    elif change == "recorded-namespace":
        guard._STATE["payload_globals"] = dict(namespace)
    assert wrapper.wrapper_dispatch(code, frame, guard, payload, change == "repeat") is (
        change is None
    )


def test_cutoff_domains_are_exact_and_original_bootstrap_tests_remain_pinned():
    assert setup.BOOTSTRAP_CUTOFF_CASES == frozenset(route.CUTOFF_CASES)
    assert len(route.CUTOFF_CASES) == 2 and route.CUTOFF_CASES[1] == wrapper.CASE
    assert (
        hashlib.sha256((ROOT / wrapper.SOURCE).read_bytes()).hexdigest() == wrapper.PIN == route.PIN
    )
    assert wrapper.BODY == route.script(0.5)


@pytest.mark.parametrize(
    "mode", ["original", "wrong-wrapper", "wrapper-repeat", "payload-first", "payload-forged"]
)
def test_actual_half_second_runpy_program_obeys_both_sealed_stages(tmp_path, mode):
    import subprocess
    import sys
    import time
    from test_stdlib_backend import RUNNER

    preparation = """
backend=Path.cwd()/'owned/fake-app-server';backend.parent.mkdir()
backend.write_bytes((source/domain.SCRIPT).read_bytes())
body='import runpy,sys,time; p=sys.argv.pop(1); time.sleep(0.5); runpy.run_path(p,run_name="__main__")'
case='tests/test_experimental_bootstrap.py::test_startup_subtracts_from_actual_inference_timeout'
argv=[sys.executable,'-I','-S','-c',body,str(backend),'app-server']
payload={'target':body,'mode':'inline','class':domain.CLASS,'case':case,'token':'exact',
 'isolated':True,'path0':'','orig_argv':argv,'sys_argv':['-c',str(backend),'app-server'],
 'source_binding':{'path':str(source/'tests/test_experimental_bootstrap.py'),'line':38,
 'sha256':'c81fc04a81ef3aa657c16a69627c4c6b80ba1012f9255d2a05b15557934a7383'}}
"""
    script = RUNNER.replace("payload={'target':str(source/domain.SCRIPT)}", preparation)
    child = """
def child(payload):
    code=compile(payload['target'],'<string>','exec',dont_inherit=True)
    namespace={'__name__':'__main__','__package__':None,'__spec__':None}
    _STATE['payload_code']=code;_STATE['payload_globals']=namespace
    exec(code,namespace)
"""
    insert = (
        """
state.update({'class':domain.CLASS,'case':case,'token':'exact','phase':'READY','checkout':str(source),
 'owned_root':str(backend.parent),'runtime':{'paths':[sys.executable]},
 'product_pins':{'tests/test_experimental_bootstrap.py':payload['source_binding']['sha256']}})
guard._STATE=state
guard.append=lambda row:None
"""
        + "exec("
        + repr(child)
        + ",vars(guard))\n"
    )
    script = script.replace(
        "try:domain.install_barrier(state,guard,payload)",
        insert + "try:domain.install_barrier(state,guard,payload)",
    )
    start = script.index("if mode=='path':")
    script = (
        script[:start]
        + """
sys.argv=payload['sys_argv'][:]
if mode=='wrong-wrapper':payload['target']='pass'
if mode=='payload-first':runpy.run_path(str(backend),run_name='__main__')
if mode=='payload-forged':exec(compile('pass',str(backend),'exec'),{})
guard.child(payload)
if mode=='wrapper-repeat':
 sys.argv=payload['sys_argv'][:]
 guard.child(payload)
"""
    )
    path = tmp_path / "two-stage.py"
    path.write_text(script)
    before = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(path), str(ROOT), mode],
        cwd=tmp_path,
        env={
            **os.environ,
            "CODEX_HOME": str(tmp_path),
            "PYTHONPATH": str(tmp_path / "forbidden-site"),
        },
        input='{"id":1,"method":"initialize","params":{}}\n',
        text=True,
        capture_output=True,
        timeout=10,
    )
    if mode == "original":
        assert result.returncode == 0, result.stderr
        assert time.monotonic() - before >= 0.5
        import json

        assert json.loads(result.stdout)["result"] == {"userAgent": "synthetic-only"}
    else:
        assert result.returncode != 0
        assert (
            "stdlib_bootstrap_wrapper_dispatch"
            if mode in {"wrong-wrapper", "wrapper-repeat"}
            else "stdlib_backend_payload_dispatch"
        ) in result.stderr


@pytest.mark.parametrize("kind", ["backend", "wrapper", "acp"])
@pytest.mark.parametrize(
    "change", [None, "case", "class", "flags", "source", "line", "LANG", "LC_ALL", "LC_CTYPE"]
)
def test_cutoff_fixture_postinit_locale_is_exact(kind, change):
    from primary_source_inputs import python_environment
    from finite.mock_backend_setup import SESSION, SESSION_PIN, ACP, ACP_PIN

    binding = (
        {"path": "/source/" + wrapper.SOURCE, "line": 38, "sha256": wrapper.PIN}
        if kind == "wrapper"
        else {"path": "/source/" + ACP, "line": 1, "sha256": ACP_PIN}
        if kind == "acp"
        else {
            "path": "/source/" + SESSION,
            "line": 506,
            "sha256": SESSION_PIN,
            "function": "_open_role_owned",
        }
    )
    row = {
        "class": "source-canonical-stdlib-acp"
        if kind == "acp"
        else "source-canonical-stdlib-backend",
        "case": route.CUTOFF_CASES[1] if kind == "wrapper" else route.CUTOFF_CASES[0],
        "source_binding": binding,
    }
    flags = [1, 1, 0]
    environment = {"CODEX_HOME": "/owned/private"}
    if change in {"case", "class"}:
        row[change] += "-foreign"
    elif change == "flags":
        flags = [0, 0, 0]
    elif change in {"source", "line"}:
        binding["sha256" if change == "source" else "line"] = "foreign"
    elif change in {"LANG", "LC_ALL", "LC_CTYPE"}:
        environment[change] = "C"
    assert python_environment(environment, row, flags) == (
        {**environment, "LC_CTYPE": "C.UTF-8"} if change is None else environment
    )
