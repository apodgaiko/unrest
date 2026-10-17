"""Finite Git callsites: original source argv, source frame and owned cwd."""

import ast
import hashlib
import inspect
import json
import os
import re
from pathlib import Path
import shutil
import types


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def foundation(argv, cwd, env, state, append, refuse):
    sources = {
        str(Path(state["checkout"]) / relative): line
        for relative, line in (
            ("tests/test_foundation_authority.py", 25),
            ("tests/test_foundation_integration.py", 28),
            ("tests/test_improve_adapter.py", 28),
            ("tests/test_project_adapter.py", 31),
            ("tests/test_v04_activation.py", 58),
        )
    }
    frame = inspect.currentframe()
    try:
        while frame and not (
            frame.f_code.co_filename in sources and frame.f_code.co_name == "_git"
        ):
            frame = frame.f_back
        if frame is None:
            return None
        source = Path(frame.f_code.co_filename)
        relative = str(source.relative_to(Path(state["checkout"])))
        line = sources[str(source)]
        pin = state["product_pins"][relative]
        if sha(source) != pin:
            refuse("foundation_git_source_drift")
        code = state["isolated_source_code"](source)
        function = frame.f_globals.get("_git")
        if (
            not isinstance(function, types.FunctionType)
            or function.__globals__ is not frame.f_globals
            or function.__code__ is not frame.f_code
            or function.__code__ != state["isolated_named"](code, "_git")
            or function.__defaults__ is not None
            or function.__kwdefaults__ is not None
        ):
            refuse("foundation_git_helper_identity")
        caller = frame.f_back
        if (
            caller is None
            or caller.f_code.co_filename != str(source)
            or caller.f_globals is not frame.f_globals
        ):
            refuse("foundation_git_caller_identity")
        owner = frame.f_globals.get(caller.f_code.co_name)
        owner = getattr(owner, "__wrapped__", owner)
        if (
            not isinstance(owner, types.FunctionType)
            or owner.__globals__ is not frame.f_globals
            or owner.__code__ is not caller.f_code
            or owner.__code__ != state["isolated_named"](code, caller.f_code.co_name)
        ):
            refuse("foundation_git_callable_identity")
        calls = [
            node
            for node in ast.walk(ast.parse(source.read_bytes()))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_git"
            and node.lineno <= caller.f_lineno <= node.end_lineno
        ]
        if len(calls) != 1:
            refuse("foundation_git_callsite_identity")
        call = calls[0]
        # The unchanged owner has nineteen literal calls, with only its owned
        # repository as a substitution; no command family is inferred.
        arguments = call.args[1:]
        if call.keywords or any(
            not isinstance(arg, ast.Constant) or not isinstance(arg.value, str) for arg in arguments
        ):
            refuse("foundation_git_nonliteral_vector")
        expected = ["git", *(arg.value for arg in arguments)]
        repository = eval(
            compile(ast.Expression(call.args[0]), str(source), "eval"),
            caller.f_globals,
            caller.f_locals,
        )
        directory = Path(cwd or os.getcwd()).resolve()
        if (
            argv != expected
            or frame.f_lineno != line
            or tuple(argv[1:]) != frame.f_locals["arguments"]
            or repository != frame.f_locals["repository"]
            or cwd != repository
            or not directory.is_relative_to(Path(state["owned_root"]))
            or env is not None
            or os.getcwd() != state["checkout"]
        ):
            refuse("foundation_git_vector_cwd_environment")
        binding = {
            "path": str(source),
            "line": line,
            "sha256": pin,
            "caller_line": call.lineno,
            "function": "_git",
            "caller": caller.f_code.co_name,
            "expression_ast_sha256": hashlib.sha256(
                ast.dump(call, include_attributes=False).encode()
            ).hexdigest(),
        }
        append(
            {
                "kind": "concrete_foundation_git_registration",
                "source_binding": binding,
                "argv": expected,
                "cwd": str(directory),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(os.environ), sort_keys=True).encode()
                ).hexdigest(),
                "ready_scope": "authenticated Python owner; native leaf does not emit child READY",
                "lifecycle": "unchanged synchronous run/communicate/wait; outer owner timeout 300 seconds",
            }
        )
        return {
            "class": "source-literal-git:" + relative + ":" + str(call.lineno),
            "python": False,
            "source_binding": binding,
        }
    finally:
        del frame


def coordinator(argv, cwd, env, state, append, refuse):
    source = Path(state["checkout"]) / "src/unrest_harness/coordinator.py"
    vectors = {
        "_isolated_work_supported": (597, ["git", "rev-parse", "--show-toplevel"], "workspace"),
        "_dispatch_isolated_work_batch": (731, ["git", "rev-parse", "HEAD"], "repository"),
        "_validate_integration_tree": (901, ["git", "diff", "--cached", "--check"], "worktree"),
    }
    frame = inspect.currentframe()
    try:
        while frame and not Path(frame.f_code.co_filename).is_relative_to(Path(state["checkout"])):
            frame = frame.f_back
        if (
            frame is None
            or frame.f_code.co_filename != str(source)
            or frame.f_code.co_name not in vectors
        ):
            return None
        name = frame.f_code.co_name
        line, expected, local = vectors[name]
        pin = state["product_pins"]["src/unrest_harness/coordinator.py"]
        if sha(source) != pin:
            refuse("coordinator_git_source_drift")
        cls = frame.f_globals.get("MissionCoordinator")
        function = getattr(cls, name, None)
        if (
            not isinstance(function, types.FunctionType)
            or function.__globals__ is not frame.f_globals
            or function.__code__ is not frame.f_code
            or function.__code__
            != state["isolated_named"](state["isolated_source_code"](source), name)
        ):
            refuse("coordinator_git_callable_drift")
        directory = Path(cwd or os.getcwd()).resolve()
        if (
            frame.f_lineno != line
            or argv != expected
            or cwd != frame.f_locals[local]
            or env is not None
            or not directory.is_relative_to(Path(state["owned_root"]))
            or os.getcwd() != state["checkout"]
        ):
            refuse("coordinator_git_vector_context_drift")
        binding = {"path": str(source), "line": line, "sha256": pin, "function": name}
        append(
            {
                "kind": "concrete_coordinator_git_registration",
                "source_binding": binding,
                "argv": expected,
                "cwd": str(directory),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(os.environ), sort_keys=True).encode()
                ).hexdigest(),
            }
        )
        return {
            "class": "source-coordinator-git:" + name,
            "python": False,
            "source_binding": binding,
        }
    finally:
        del frame


def admit(argv, cwd, env, state, append, refuse):
    if argv[0] not in ("git", "/usr/bin/git", "/opt/homebrew/bin/git"):
        return None
    environment = dict(os.environ if env is None else env)
    resolved = shutil.which(argv[0], path=environment.get("PATH"))
    if resolved not in state["copy_git"] or sha(resolved) != state["copy_git"][resolved]:
        refuse("git_executable_identity")
    crash = Path(state["guard"]).with_name("crash_route.py")
    namespace = {"__file__": str(crash)}
    exec(compile(crash.read_bytes(), str(crash), "exec"), namespace)
    selected = namespace["native"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    source_git = Path(state["guard"]).with_name("source_git.py")
    if sha(source_git) != state["direct_support"]["files"][str(source_git)]:
        refuse("source_git_support_drift")
    namespace = {}
    exec(compile(source_git.read_bytes(), str(source_git), "exec"), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    cleanup = Path(state["guard"]).with_name("cleanup_routes.py")
    if sha(cleanup) != state["direct_support"]["files"][str(cleanup)]:
        refuse("cleanup_support_drift")
    namespace = {}
    exec(compile(cleanup.read_bytes(), str(cleanup), "exec"), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    historical_path = Path(state["guard"]).with_name("historical_git.py")
    historical_pin = state["direct_support"]["files"][str(historical_path)]
    if sha(historical_path) != historical_pin:
        refuse("historical_git_support_drift")
    namespace = {"__file__": str(historical_path), "__name__": "_finite_historical_git"}
    exec(compile(historical_path.read_bytes(), str(historical_path), "exec"), namespace)
    selected = namespace["admit"](argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    selected = coordinator(argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    selected = foundation(argv, cwd, env, state, append, refuse)
    if selected is not None:
        return selected
    directory = Path(cwd or os.getcwd()).resolve()
    if not directory.is_relative_to(Path(state["owned_root"])):
        return None
    frame = inspect.currentframe()
    try:
        while frame:
            source = Path(frame.f_code.co_filename).resolve()
            if (
                state.get("class") == "source-copied-repository-cli"
                and source == directory / "src/unrest_harness/repository_contract.py"
                and frame.f_code.co_name == "find_repository_root"
                and frame.f_code.co_firstlineno == 505
            ):
                relative = "src/unrest_harness/repository_contract.py"
                pin = state["product_pins"][relative]
                if (
                    sha(source) != pin
                    or env is not None
                    or frame.f_locals["start"].resolve() != directory
                    or argv
                    != ["git", "-C", str(frame.f_locals["start"]), "rev-parse", "--show-toplevel"]
                ):
                    refuse("copied_repository_git_binding")
                binding = {
                    "path": str(Path(state["checkout"]) / relative),
                    "line": 507,
                    "sha256": pin,
                    "copied_path": str(source),
                    "function": "find_repository_root",
                }
                append(
                    {
                        "kind": "concrete_git_callsite_registration",
                        "source_binding": binding,
                        "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                        "cwd": str(directory),
                        "environment_sha256": hashlib.sha256(
                            json.dumps(environment, sort_keys=True).encode()
                        ).hexdigest(),
                        "executable_sha256": state["copy_git"][resolved],
                    }
                )
                return {
                    "class": "source-copied-repository-git",
                    "python": False,
                    "source_binding": binding,
                }
            if source.is_relative_to(Path(state["checkout"])):
                relative = str(source.relative_to(Path(state["checkout"])))
                pin = state["product_pins"].get(relative)
                if relative in state["git_callsite_sources"]:
                    if sha(source) != pin:
                        refuse("git_callsite_source_drift")
                    if (
                        relative == "src/unrest_harness/experimental_candidate.py"
                        and frame.f_code.co_name == "git"
                        and frame.f_code.co_firstlineno == 147
                    ):
                        local = frame.f_locals
                        arguments = local["arguments"]
                        expected_env = {
                            "PATH": "/usr/bin:/bin",
                            "LC_ALL": "C",
                            "GIT_CONFIG_NOSYSTEM": "1",
                            "GIT_CONFIG_GLOBAL": "/dev/null",
                            "GIT_OPTIONAL_LOCKS": "0",
                            "GIT_TERMINAL_PROMPT": "0",
                        }
                        if (
                            type(arguments) is not tuple
                            or len(arguments) != 3
                            or arguments[0] != "cat-file"
                            or arguments[1] not in ("-t", "commit", "tree", "blob")
                            or re.fullmatch("[0-9a-f]{40}", arguments[2]) is None
                            or argv != ["/usr/bin/git", "--no-replace-objects", *arguments]
                            or directory != local["self"].root.resolve()
                            or environment != expected_env
                        ):
                            refuse("candidate_object_git_binding")
                        binding = {
                            "path": str(source),
                            "line": 151,
                            "sha256": pin,
                            "function": "_Observation.git",
                            "argument_kind": arguments[1],
                        }
                        append(
                            {
                                "kind": "concrete_git_callsite_registration",
                                "source_binding": binding,
                                "argv_sha256": hashlib.sha256(
                                    json.dumps(argv).encode()
                                ).hexdigest(),
                                "cwd": str(directory),
                                "environment_sha256": hashlib.sha256(
                                    json.dumps(environment, sort_keys=True).encode()
                                ).hexdigest(),
                                "executable_sha256": state["copy_git"][resolved],
                                "lifecycle": "source context manager; bounded wait; exception kill/wait",
                            }
                        )
                        return {
                            "class": "source-candidate-object-git:" + arguments[1],
                            "python": False,
                            "source_binding": binding,
                        }
                    if relative == "src/unrest_harness/evolution.py":
                        instance = frame.f_locals.get("self")
                        function = getattr(type(instance), frame.f_code.co_name, None)
                        if (
                            instance is None
                            or not isinstance(function, types.FunctionType)
                            or function.__globals__ is not frame.f_globals
                            or function.__code__ is not frame.f_code
                            or function.__code__
                            != state["isolated_named"](
                                state["isolated_source_code"](source), frame.f_code.co_name
                            )
                            or not instance.repository.resolve().is_relative_to(
                                Path(state["owned_root"])
                            )
                            or env is not None
                        ):
                            refuse("evolution_git_callable_identity")
                    tree = ast.parse(source.read_bytes())
                    for node in ast.walk(tree):
                        if (
                            not isinstance(node, ast.Call)
                            or not node.lineno <= frame.f_lineno <= node.end_lineno
                        ):
                            continue
                        if (
                            ast.unparse(node.func) == "subprocess.run"
                            and node.args
                            and isinstance(node.args[0], ast.List)
                            and not any(isinstance(a, ast.Starred) for a in node.args[0].elts)
                        ):
                            vector = list(
                                eval(
                                    compile(ast.Expression(node.args[0]), str(source), "eval"),
                                    frame.f_globals,
                                    frame.f_locals,
                                )
                            )
                            if argv == vector and len(vector) > 1 and vector[0] == "git":
                                binding = {"path": str(source), "line": node.lineno, "sha256": pin}
                                append(
                                    {
                                        "kind": "concrete_git_callsite_registration",
                                        "source_binding": binding,
                                        "argv_sha256": hashlib.sha256(
                                            json.dumps(argv).encode()
                                        ).hexdigest(),
                                        "cwd": str(directory),
                                        "executable_sha256": state["copy_git"][resolved],
                                    }
                                )
                                return {
                                    "class": "source-git:" + relative + ":" + str(node.lineno),
                                    "python": False,
                                    "source_binding": binding,
                                }
                        if ast.unparse(node.func) not in ("git", "_git", "self._git", "reader.run"):
                            continue
                        args = node.args
                        if ast.unparse(node.func) in ("git", "_git"):
                            args = args[1:]
                        if (
                            not args
                            or not isinstance(args[0], ast.Constant)
                            or not isinstance(args[0].value, str)
                        ):
                            continue
                        expression = ast.fix_missing_locations(
                            ast.Expression(ast.Tuple(elts=args, ctx=ast.Load()))
                        )
                        expected = list(
                            eval(
                                compile(expression, str(source), "eval"),
                                frame.f_globals,
                                frame.f_locals,
                            )
                        )
                        tail = argv[1:]
                        if tail and tail[0] == "--no-replace-objects":
                            tail = tail[1:]
                        if tail != expected:
                            continue
                        binding = {
                            "path": str(source),
                            "line": node.lineno,
                            "sha256": pin,
                            "expression_ast_sha256": hashlib.sha256(
                                ast.dump(node, include_attributes=False).encode()
                            ).hexdigest(),
                        }
                        append(
                            {
                                "kind": "concrete_git_callsite_registration",
                                "source_binding": binding,
                                "argv_sha256": hashlib.sha256(
                                    json.dumps(argv).encode()
                                ).hexdigest(),
                                "cwd": str(directory),
                                "environment_sha256": hashlib.sha256(
                                    json.dumps(environment, sort_keys=True).encode()
                                ).hexdigest(),
                                "executable_sha256": state["copy_git"][resolved],
                            }
                        )
                        return {
                            "class": "source-git:" + relative + ":" + str(node.lineno),
                            "python": False,
                            "source_binding": binding,
                        }
            frame = frame.f_back
        return None
    finally:
        del frame
