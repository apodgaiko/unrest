"""Finite source-frame bindings for direct Python routes; private code carrier."""

import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any

_binding_path = Path(__file__).with_name("source_bindings.py")
_binding_bytes = _binding_path.read_bytes()
_BINDING_PIN = "644b859e9362410338423f01b75196fd36b6faa7183f95f9022069fcaa2d4e55"
if hashlib.sha256(_binding_bytes).hexdigest() != _BINDING_PIN:
    raise RuntimeError("finite binding carrier drift")
_binding_namespace: dict[str, Any] = {
    "__file__": str(_binding_path),
    "__name__": "_finite_bindings",
}
exec(compile(_binding_bytes, str(_binding_path), "exec"), _binding_namespace)
DATA = _binding_namespace["DATA"]
B = DATA["bindings"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def support_code(path, state):
    """Cache compilation only; every admission reads exact current carriers."""
    path = Path(path)
    pin = state['direct_support']['files'][str(path)]
    metrics = state.setdefault('direct_support_pure_metrics', {
        'reads': 0, 'compiles': 0, 'read_wall': 0.0, 'read_cpu': 0.0,
        'compile_wall': 0.0, 'compile_cpu': 0.0})
    started, cpu = time.monotonic(), time.process_time()
    def key(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                info.st_mode, info.st_nlink, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError('direct_support_nonregular_carrier')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            body = stream.read()
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (key(before) != key(opened) or key(before) != key(after)
            or key(before) != key(path.lstat())
            or hashlib.sha256(body).hexdigest() != pin):
        raise RuntimeError('direct_support_current_carrier_drift')
    # The resolver is executed again in a fresh namespace by source activation.
    # Keep pure comparison inputs/code on the same guard state so that those
    # repeated executions can reuse compilation without retaining their globals.
    cache = state.setdefault('direct_support_compiled', {})
    metrics['reads'] += 1
    metrics['read_wall'] += time.monotonic() - started
    metrics['read_cpu'] += time.process_time() - cpu
    binding = (key(before), pin, body, sys.flags.optimize,
               sys._getframe().f_code.co_flags)
    previous = cache.get(str(path))
    if previous is not None:
        if previous[0] != binding:
            raise RuntimeError('direct_support_cached_carrier_drift')
        return previous[1]
    started, cpu = time.monotonic(), time.process_time()
    code = compile(body, str(path), 'exec')
    metrics['compiles'] += 1
    metrics['compile_wall'] += time.monotonic() - started
    metrics['compile_cpu'] += time.process_time() - cpu
    cache[str(path)] = (binding, code)
    return code


def frame_for(binding):
    frame = inspect.currentframe()
    try:
        while frame:
            if (
                frame.f_code.co_name == binding["function"]
                and str(Path(frame.f_code.co_filename).resolve()) == binding["path"]
                and frame.f_code.co_firstlineno == binding["line"]
            ):
                if sha(binding["path"]) != binding["sha256"]:
                    raise RuntimeError("finite source-frame drift")
                return frame
            frame = frame.f_back
        return None
    finally:
        del frame


def owned(path):
    p = Path(path)
    return (
        p.is_absolute()
        and ".." not in p.parts
        and p.resolve().is_relative_to(_ACTIVE_STATE["owned_root"])
        and p.resolve() != Path(_ACTIVE_STATE["owned_root"])
    )


def result(name, binding, argv, directory, environment, append, **extra):
    append(
        {
            "kind": "concrete_direct_registration",
            "class": name,
            "source_binding": binding,
            "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
            "cwd": str(directory),
            "environment_sha256": hashlib.sha256(
                json.dumps(environment, sort_keys=True).encode()
            ).hexdigest(),
            **extra,
        }
    )
    return {"class": name, "python": True, "source_binding": binding}


def admit(argv, cwd, env, state, append, refuse):
    global _ACTIVE_STATE
    carrier = Path(__file__).with_name("crash_route.py")
    namespace = {"__file__": str(carrier)}
    exec(support_code(carrier, state), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    _ACTIVE_STATE = state
    cleanup = Path(__file__).with_name("cleanup_routes.py")
    namespace = {}
    exec(support_code(cleanup, state), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    timeout = Path(__file__).with_name("timeout_route.py")
    if str(timeout) in state["direct_support"]["files"]:
        namespace = {"__file__": str(timeout)}
        exec(support_code(timeout, state), namespace)
        selected = namespace["admit"](argv, cwd, env, state, append, refuse)
        if selected is not None:
            return selected
    isolated = Path(__file__).with_name("isolated_refusal.py")
    namespace = {}
    exec(support_code(isolated, state), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    literal = Path(__file__).with_name("literal_source_routes.py")
    namespace = {}
    exec(support_code(literal, state), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    carrier = Path(__file__).with_name("role_routes.py")
    namespace = {}
    exec(support_code(carrier, state), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    configured = Path(__file__).with_name("configured_backend.py")
    if str(configured) in state["direct_support"]["files"]:
        namespace = {}
        exec(support_code(configured, state), namespace)
        selected = namespace["admit"](argv, cwd, env, state, append, refuse)
        if selected is not None:
            return selected
    benchmark = Path(__file__).with_name("benchmark_route.py")
    namespace = {}
    exec(support_code(benchmark, state), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    ordinary = Path(__file__).with_name("ordinary_routes.py")
    namespace = {}
    exec(support_code(ordinary, state), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    storage = Path(__file__).with_name("storage_route.py")
    namespace = {}
    exec(support_code(storage, state), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    directory = Path(cwd or os.getcwd()).resolve()
    environment = dict(os.environ if env is None else env)
    # Three original direct helper bodies, including the finite f-string role
    # barrier. Evaluate only the source-pinned original expression in its exact
    # source frame; no submitted script/digest chooses an implementation.
    helper_path = Path(DATA["checkout"]) / "tests/test_completion_setup.py"
    if sha(helper_path) != state["product_pins"]["tests/test_completion_setup.py"]:
        refuse("completion_helper_source_drift")
    helper_tree = ast.parse(helper_path.read_text())
    for fn in helper_tree.body:
        if not isinstance(fn, ast.FunctionDef) or fn.name not in (
            "test_consumed_marker_survives_recovery_interruption",
            "test_process_dies_during_first_setup",
            "test_real_roles_first_use",
        ):
            continue
        binding = {
            "path": str(helper_path),
            "sha256": sha(helper_path),
            "function": fn.name,
            "line": min([fn.lineno, *(d.lineno for d in fn.decorator_list)]),
        }
        f = frame_for(binding)
        if f is None:
            continue
        local = f.f_locals
        assignment = next(
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "script" for t in n.targets)
        )
        if isinstance(assignment.value, ast.Constant):
            body = ast.literal_eval(assignment.value)
        else:
            body = eval(
                compile(ast.Expression(assignment.value), str(helper_path), "eval"),
                {"__builtins__": {"str": str}},
                {"path": local["path"], "barrier": local["barrier"]},
            )
        if local["script"] != body:
            refuse("completion_helper_body_drift")
        if fn.name == "test_real_roles_first_use":
            role = local["role"]
            if (role, local["targets"]) not in [
                ("work", []),
                ("work", ["VAL-A"]),
                ("validate", ["VAL-A"]),
            ] or local["scenario"] not in (
                "invalid-invalid",
                "valid-invalid",
                "valid-valid",
                "distinct",
            ):
                refuse("completion_role_parameter")
            vectors = [
                [sys.executable, "-c", body, str(i), "--mode", local["mode"]] for i in (0, 1)
            ]
            if argv not in vectors or directory != local["workspace"].resolve():
                refuse("completion_role_vector")
            index = int(argv[3])
            destination = (
                local["other"] if local["scenario"] == "distinct" and index == 1 else local["path"]
            )
            if environment != {**local["env"], "UNREST_HANDOFF_PATH": str(destination)}:
                refuse("completion_role_environment")
        else:
            tail = [str(local["path"])] + ([local["phase"]] if "phase" in local else [])
            if argv != [sys.executable, "-c", body, *tail] or env is not None:
                refuse("completion_helper_vector")
        if not owned(local["path"]):
            refuse("completion_helper_root")
        return result(
            "source-completion-helper:" + fn.name, binding, argv, directory, environment, append
        )
    cli_path = Path(DATA["checkout"]) / "tests/test_stranded_recovery.py"
    cli_binding = {
        "path": str(cli_path),
        "sha256": state["product_pins"]["tests/test_stranded_recovery.py"],
        "function": "test_real_cli_inspection_after_recovery",
        "line": 406,
    }
    f = frame_for(cli_binding)
    if f:
        local = f.f_locals
        if (
            argv
            != [
                sys.executable,
                "-c",
                "from unrest_harness.cli import cli; cli()",
                "inspect-tasks",
                "--project",
                local["pid"],
            ]
            or environment != local["env"]
            or directory != local["tmp_path"].resolve()
            or not owned(directory)
        ):
            refuse("recovery_cli_binding")
        return result("source-recovery-cli", cli_binding, argv, directory, environment, append)
    # Reference reports bind the actual TemporaryDirectory object, tuple, owner,
    # inode and source-selected caller, rather than a report basename wildcard.
    f = frame_for(B["reference"])
    if f:
        local = f.f_locals
        nodes = tuple(local["nodes"])
        report = local["report_path"]
        root = Path(local["raw_dir"])
        expected = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-ra",
            "-p",
            "no:cacheprovider",
            f"--junitxml={report}",
            *nodes,
        ]
        if (
            argv != expected
            or directory != Path(local["repository_root"]).resolve()
            or environment != local["child_env"]
            or not owned(root)
            or root.name[:20] != "unrest-contract-run-"[:20]
            or report != root / "pytest.xml"
            or report.exists()
        ):
            refuse("reference_concrete_binding")
        info = root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            refuse("reference_temp_identity")
        generator = frame_for(B["integrity"])
        lean = frame_for(B["lean"])
        if generator:
            probe = generator.f_locals["probe"]
            variants = [
                (f"{probe}::test_skips",),
                (f"{probe}::test_passes", "-k", "not test_passes"),
                (f"{probe}::test_fails",),
                (f"{probe}::test_waits",),
                (f"{probe}::test_passes",),
            ]
            if (
                not owned(probe)
                or sha(probe) != DATA["integrity_sha256"]
                or nodes not in variants
                or directory != probe.parent.resolve()
            ):
                refuse("reference_integrity_variant")
            name = "reference-integrity:" + nodes[0].rsplit("::", 1)[1]
        elif lean:
            request = lean.f_locals["request"]
            path = str(Path(request.module.__file__).resolve())
            row = next(
                (
                    r
                    for r in DATA["selections"]
                    if str(Path(DATA["checkout"]) / r["module"]) == path
                ),
                None,
            )
            if (
                row is None
                or nodes != tuple(row["external_ordered_nodes"])
                or request.module.SCENARIOS != row["scenarios"]
                or sha(path) != row["source_sha256"]
                or (
                    row["crosswalk"] is not None
                    and sha(row["crosswalk"]["path"]) != row["crosswalk"]["sha256"]
                )
            ):
                refuse("reference_module_selection")
            name = "reference:" + row["module"]
        else:
            refuse("reference_unbound_selection")
        return result(
            name,
            B["reference"],
            argv,
            directory,
            environment,
            append,
            temp_root=str(root),
            report=str(report),
            temp_device=info.st_dev,
            temp_inode=info.st_ino,
            selection_sha256=hashlib.sha256(json.dumps(nodes).encode()).hexdigest(),
        )
    f = frame_for(B["nested"])
    if f:
        if (
            argv[1:] != DATA["pair"]
            or directory != Path(DATA["checkout"])
            or environment != {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        ):
            refuse("nested_pair_binding")
        return result(
            "source-speed-nested-exact", B["nested"], argv, directory, environment, append
        )
    f = frame_for(B["projection"])
    if f:
        local = f.f_locals
        config = local["config"]
        expected = [
            sys.executable,
            "-c",
            DATA["projection_body"],
            str(config.bundled_dir),
            str(config.harness_home),
            str(config.projects_dir),
            local["project_id"],
        ]
        if (
            argv != expected
            or not owned(config.harness_home)
            or not owned(config.projects_dir)
            or Path(config.bundled_dir).resolve()
            != Path(DATA["checkout"]) / "src/unrest_harness/bundled"
            or env is not None
            or directory != Path(DATA["checkout"])
        ):
            refuse("projection_binding")
        return result(
            "source-project-projection", B["projection"], argv, directory, environment, append
        )
    f = frame_for(B["recovery"])
    if f:
        local = f.f_locals
        if (
            argv != [sys.executable, "-c", DATA["recovery_body"]]
            or environment != local["environment"]
            or directory != Path(environment["UNREST_WORKSPACE"]).resolve()
            or not all(
                owned(environment[key])
                for key in (
                    "UNREST_HOME",
                    "UNREST_PROJECTS_DIR",
                    "UNREST_HANDOFF_PATH",
                    "UNREST_WORKSPACE",
                )
            )
            or environment["UNREST_NODE_TYPE"] not in ("work", "validate")
        ):
            refuse("recovery_role_binding")
        return result("source-recovery-role", B["recovery"], argv, directory, environment, append)
    f = frame_for(B["worker"])
    if f:
        local = f.f_locals
        control = local["self"]
        if (
            argv != local["command"]
            or environment != local["worker_environment"]
            or directory != control.project_root.resolve()
            or not owned(directory)
        ):
            refuse("run_worker_concrete_binding")
        if control.executor_ref == "executor_fixture:execute":
            executor = directory / "executor_fixture.py"
            if sha(executor) != DATA["executor_sha256"]:
                refuse("run_worker_executor_bytes")
        elif control.executor_ref == "unrest_harness.runtime_executor:execute":
            # Production executor is a source-bound route, never an arbitrary
            # caller-selected module. Its further launches retain this guard.
            if (
                sha(Path(DATA["checkout"]) / "src/unrest_harness/runtime_executor.py")
                != state["product_pins"]["src/unrest_harness/runtime_executor.py"]
            ):
                refuse("runtime_executor_drift")
        else:
            refuse("run_worker_executor_unknown")
        return result("source-run-worker", B["worker"], argv, directory, environment, append)
    # The generated composed adapter is one literal original source body and
    # trace path pair, not any owned script with an alleged caller digest.
    if len(argv) == 3 and Path(argv[1]).name == ".hermetic-acp-adapter.py":
        script = Path(argv[1])
        trace = Path(argv[2])
        if (
            not owned(script)
            or sha(script) != DATA["adapter_sha256"]
            or trace != script.parent / ".hermetic-acp-trace.jsonl"
            or directory != script.parent.resolve()
        ):
            refuse("composed_adapter_binding")
        return result(
            "source-composed-adapter",
            {
                "path": str(Path(DATA["checkout"]) / "tests/test_server.py"),
                "sha256": B["projection"]["sha256"],
                "line": 3302,
            },
            argv,
            directory,
            environment,
            append,
            script_sha256=sha(script),
        )
    # Original isolated lifecycle/extracted oracle/checker setup is registered
    # now; final archive and installed member identities belong to CERT. These
    # cannot execute until a private byte seal with explicit provenance exists.
    for name in ("lifecycle", "oracle"):
        f = frame_for(B[name])
        if f:
            refuse("source_operation_lineage_unobserved:" + name)
    f = frame_for(B["checker_test"]) or frame_for(B["checked"])
    if f and len(argv) == 3 and argv[1] == "tools/check_distribution.py":
        dist = Path(argv[2])
        if (
            directory == Path(DATA["checkout"])
            and owned(dist)
            and dist.is_dir()
            and not list(dist.iterdir())
            and argv[0] == sys.executable
        ):
            return result(
                "source-checker-empty-archive-control",
                B["checker_test"],
                argv,
                directory,
                environment,
                append,
            )
        refuse("source_operation_lineage_unobserved:checker")
    return None
