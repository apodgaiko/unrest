"""The small reproduction cannot select SOURCE, extra cases or filtered commands."""

import ast
from pathlib import Path

import pytest

from finite.bootstrap_cost_diagnostic import CASES, selected
from primary_policy import TEST_BOOTSTRAP_CUTOFF_CASES, TEST_BOOTSTRAP_CASES
from primary_source_inputs import test_plan as plan


@pytest.mark.parametrize("change", [None, "mode", "case", "extra", "missing", "flags"])
def test_cpu_attribution_is_only_the_exact_diagnostic_selection(change):
    profile = {"source_mode": "TEST-positive", "orig_argv": ["/python", "/pytest", "-q", *CASES]}
    case = CASES[0]
    if change == "mode":
        profile["source_mode"] = "SOURCE"
    elif change == "case":
        case += "-foreign"
    elif change == "extra":
        profile["orig_argv"].append("other")
    elif change == "missing":
        profile["orig_argv"].pop()
    elif change == "flags":
        profile["orig_argv"].insert(3, "-k")
    assert selected(profile, case) is (change is None)


def test_reproduction_retains_complete_original_module_and_full_source_command():
    assert CASES == TEST_BOOTSTRAP_CUTOFF_CASES and set(CASES) < set(TEST_BOOTSTRAP_CASES)
    assert len(TEST_BOOTSTRAP_CASES) == 27
    command = ("env -u CODEX_PATH uv run pytest -q " + " ".join(CASES)).encode()
    proof = plan(command, "diagnostic", "TEST-positive")
    assert not proof["source_checkpoint_ready"] and proof["selected_carrier"] is None
    with pytest.raises(RuntimeError):
        plan(command + b" -k cutoff", "diagnostic", "TEST-positive")
    source = Path(__file__).with_name("primary_source_entry.py").read_bytes()
    tree = ast.parse(source)
    hook = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "pytest_runtest_call"
    )
    scoped = hook.body[0]
    assert isinstance(scoped, ast.If)
    assert "self._start_cost_monitor(profiler.CostProfile)" in ast.unparse(scoped)
    starter = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_start_cost_monitor"
    )
    assert "monitor.start()" in ast.unparse(starter)
    assert "self._finish_cost_monitor()" in source.decode()


@pytest.mark.parametrize("failure", ["stop", "write", "flush", "serialize", "append", None])
def test_interrupted_diagnostic_never_bypasses_original_finalization(failure):
    import hashlib
    import json
    from types import SimpleNamespace

    source = Path(__file__).with_name("primary_source_entry.py").read_bytes()
    tree = ast.parse(source)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Observer")
    names = {"_start_cost_monitor", "_finish_cost_monitor", "pytest_sessionfinish"}
    methods = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(methods) == 3
    captured = {}
    calls = []

    class Monitor:
        def stop(self):
            calls.append("stop")
            if failure == "stop":
                raise RuntimeError("diagnostic only")
            return {"instrumented_cpu_only": True}

    class Stream:
        def write(self, value):
            if failure == "write":
                raise OSError("diagnostic only")

        def flush(self):
            if failure == "flush":
                raise OSError("diagnostic only")

    class Timer:
        def __init__(self, *args):
            pass

        def start(self):
            calls.append("timer-start")

        def cancel(self):
            calls.append("timer-cancel")

    class Output:
        def __init__(self, path):
            self.path = path

        def write_bytes(self, body):
            captured[self.path] = json.loads(body)

    def canonical(value):
        if failure == "serialize" and value.get("instrumented_cpu_only"):
            raise ValueError("diagnostic only")
        return json.dumps(value, sort_keys=True).encode()

    namespace = {
        "sys": SimpleNamespace(__stderr__=Stream()),
        "canonical": canonical,
        "Path": Output,
        "threading": SimpleNamespace(Timer=Timer),
        "hashlib": hashlib,
        "os": SimpleNamespace(
            close=lambda fd: calls.append(("closed", fd)), _exit=lambda code: None
        ),
        "diagnostic_output_identity": lambda fd: "owned",
    }
    module = ast.Module(
        body=[
            ast.ClassDef(
                name="TestObserver", bases=[], keywords=[], body=methods, decorator_list=[]
            )
        ],
        type_ignores=[],
    )
    exec(
        compile(ast.fix_missing_locations(module), "/unit/original-finalization", "exec"), namespace
    )
    observer = namespace["TestObserver"]()
    observer.metadata_case = CASES[0]
    observer.metadata_monitor = Monitor()
    observer.startup_stall_timer = Timer()
    observer.collection_timer = Timer()
    observer.profile = {
        "source_budget": {"drain_seconds": 5},
        "source_mode": "TEST-positive",
        "manifest": "pinned",
    }

    def retain_metadata(row):
        if failure == "append":
            raise OSError("diagnostic only")
        captured["cpu-attribution"] = row

    observer.guard = SimpleNamespace(
        append=retain_metadata,
        observe_summary=lambda manifest: {"events": [{"kind": "ready", "token": "root"}]},
        refuse=lambda reason: (_ for _ in ()).throw(RuntimeError(reason)),
    )
    observer.before = observer.after = list(CASES)
    observer.deselected = 0
    observer.stack_output_fd = 19
    observer.stack_output_identity = "owned"
    session = SimpleNamespace(
        config=SimpleNamespace(invocation_params=SimpleNamespace(args=["-q", *CASES]))
    )
    observer.pytest_sessionfinish(session, 7)
    assert captured["/work/summary.json"]["original_pytest_exit_code"] == 7
    assert captured["/work/source-provenance.json"]["exitstatus"] == 7
    assert captured["/work/source-provenance.json"]["collection_before"] == list(CASES)
    assert ("closed", 19) in calls and calls.count("timer-cancel") == 3
    assert observer.metadata_case is None and observer.stack_output_fd is None
    if failure != "append":
        assert captured["cpu-attribution"]["kind"] == "source_guard_cpu_attribution"
        assert captured["cpu-attribution"]["diagnostic_only"] is True
        assert captured["cpu-attribution"]["eligible_certificate"] is False
        assert captured["cpu-attribution"]["metadata"]["instrumented_cpu_only"] is True
    assert calls.count("stop") == (2 if failure == "stop" else 1)

    class StartFailure:
        def __init__(self, prefix):
            assert prefix == "/guard"

        def start(self):
            raise RuntimeError("diagnostic only")

        def stop(self):
            calls.append("start-failure-cleanup")

    assert observer._start_cost_monitor(StartFailure) is False
    assert calls[-1] == "start-failure-cleanup"
