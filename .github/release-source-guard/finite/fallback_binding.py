"""Bind finite fallback vectors to an actual unchanged source call expression."""

import ast
import inspect
import hashlib
import importlib.machinery
import os
from pathlib import Path
import sys


def active_frames():
    frame = inspect.currentframe().f_back
    result = []
    while frame:
        result.append(frame)
        frame = frame.f_back
    module = sys.modules.get("asyncio")
    if module is not None:
        try:
            task = module.current_task()
        except RuntimeError:
            task = None
        coroutine = task.get_coro() if task else None
        seen = set()
        while coroutine is not None and id(coroutine) not in seen:
            seen.add(id(coroutine))
            candidate = getattr(coroutine, "cr_frame", None) or getattr(coroutine, "gi_frame", None)
            if candidate is not None:
                result.append(candidate)
            coroutine = getattr(coroutine, "cr_await", None) or getattr(
                coroutine, "gi_yieldfrom", None
            )
    return result


def syntax(state, source, body):
    key = (str(source), hashlib.sha256(body).hexdigest())
    cache = state.setdefault('fallback_syntax', {})
    if key not in cache:
        cache[key] = ast.parse(body)
    return cache[key]


def prepare(state, paths):
    for source in paths:
        try:
            syntax(state, source, source.read_bytes())
        except (OSError, SyntaxError, ValueError, TypeError):
            # Live source, loader and expression checks still decide admission.
            continue


def matches(registration, argv, cwd, environment, state):
    source = Path(registration["source_binding"]["path"])
    if not source.is_absolute():
        source = Path(state["checkout"]) / source
    sources = {source: None}
    support = registration.get("caller_support_source")
    if support is not None:
        candidate = Path(support["path"])
        if hashlib.sha256(candidate.read_bytes()).hexdigest() == support["sha256"]:
            sources[candidate] = None
    for binding in registration.get("caller_bindings", []):
        candidate = Path(state["checkout"]) / binding["path"]
        if (
            state["product_pins"].get(binding["path"]) == binding["source_sha256"]
            and hashlib.sha256(candidate.read_bytes()).hexdigest() == binding["source_sha256"]
        ):
            sources[candidate] = binding
    payload = state.get("registered_payload")
    if payload is not None and payload["mode"] == "script":
        candidate = Path(payload["target"])
        if (
            candidate == Path(payload["source_binding"]["path"])
            and hashlib.sha256(candidate.read_bytes()).hexdigest()
            == payload["source_binding"]["sha256"]
        ):
            sources[candidate] = None
    frames = active_frames()
    if registration['class'] == 'reference-descendant:ordinary-mock-acp':
        path = Path(state['guard']).with_name('ordinary_mock_binding.py')
        try:
            if hashlib.sha256(path.read_bytes()).hexdigest() != state['direct_support']['files'][str(path)]:
                return None
            namespace = {}
            exec(compile(path.read_bytes(), str(path), 'exec'), namespace)
            if not namespace['matches'](argv, cwd, environment, state, frames):
                return None
        except (OSError, KeyError, AttributeError, TypeError, ValueError):
            return None
    if registration['class'] in {'reference-descendant:terminal-redaction', 'reference-descendant:terminal-environment'}:
        path = Path(state['guard']).with_name('indirect_terminal_binding.py')
        try:
            guard = sys.modules['runtime_guard']
            return guard.checked_source(path, state['direct_support']['files'][str(path)])[
                'matches'](registration, argv, cwd, environment, state, frames)
        except (OSError, KeyError, AttributeError, TypeError, ValueError):
            return None
        finally:
            frames.clear()
    diagnostics = []
    try:
        for frame in frames:
            source = Path(frame.f_code.co_filename)
            inline = (
                payload is not None
                and payload["mode"] == "inline"
                and frame.f_globals is state.get("payload_globals")
            )
            if inline:
                tree = ast.parse(payload["target"])
                source_binding = None
                code = state["payload_code"]
                expected_code = (
                    code
                    if frame.f_code.co_name == "<module>"
                    else state["isolated_named"](code, frame.f_code.co_name)
                )
                module = None
            else:
                if source not in sources:
                    continue
                tree = syntax(state, source, source.read_bytes())
                source_binding = sources[source]
                module = sys.modules.get(frame.f_globals.get("__name__"))
                if module is None or vars(module) is not frame.f_globals:
                    continue
                loader = getattr(module, '__loader__', None)
                from beartype.claw._importlib._clawimpload import BeartypeSourceFileLoader
                if type(loader) in (importlib.machinery.SourceFileLoader, BeartypeSourceFileLoader):
                    specification = getattr(module, '__spec__', None)
                    if (specification is None or specification.loader is not loader
                            or Path(specification.origin).resolve() != source
                            or Path(loader.path).resolve() != source or loader.name != module.__name__):
                        continue
                    # Application imports keep their assertions as CPython
                    # compiles them; pytest rewrites only modules it selects.
                    if type(loader) is BeartypeSourceFileLoader:
                        base_code = BeartypeSourceFileLoader.source_to_code(
                            loader, source.read_bytes(), str(source), _optimize=sys.flags.optimize)
                    else:
                        base_code = compile(source.read_bytes(), str(source), 'exec',
                                            dont_inherit=True, optimize=sys.flags.optimize)
                else:
                    base_code = state["isolated_source_code"](source)
                expected_code = (
                    base_code
                    if frame.f_code.co_name == "<module>"
                    else state["isolated_named"](base_code, frame.f_code.co_name)
                )
            diagnostics.append({'path': str(source), 'function': frame.f_code.co_name,
                                'line': frame.f_lineno, 'code_matches': frame.f_code == expected_code,
                                'loader': type(getattr(module, '__loader__', None)).__module__ + '.' +
                                          type(getattr(module, '__loader__', None)).__name__})
            if frame.f_code != expected_code:
                continue
            for call in ast.walk(tree):
                if (
                    not isinstance(call, ast.Call)
                    or not call.lineno <= frame.f_lineno <= call.end_lineno
                ):
                    continue
                if source_binding is not None and call.lineno != source_binding["line"]:
                    continue
                if ast.unparse(call.func) not in (
                    "subprocess.run",
                    "subprocess.Popen",
                    "subprocess.check_output",
                    "asyncio.create_subprocess_exec",
                ):
                    continue
                try:

                    def evaluate(node):
                        return eval(
                            compile(ast.Expression(node), str(source), "eval"),
                            frame.f_globals,
                            frame.f_locals,
                        )

                    if ast.unparse(call.func) == "asyncio.create_subprocess_exec":
                        vector = []
                        for argument in call.args:
                            if isinstance(argument, ast.Starred):
                                vector.extend(evaluate(argument.value))
                            else:
                                vector.append(evaluate(argument))
                    else:
                        vector = list(evaluate(call.args[0]))
                    keywords = {keyword.arg: evaluate(keyword.value) for keyword in call.keywords}
                    diagnostics.append({'call_line': call.lineno, 'vector_matches': vector == argv,
                                        'cwd_matches': keywords.get('cwd') == cwd,
                                        'environment_matches': keywords.get('env') == environment,
                                        'parent_cwd_matches': os.getcwd() == state['checkout']})
                    if (
                        vector == argv
                        and keywords.get("cwd") == cwd
                        and keywords.get("env") == environment
                        and os.getcwd() == state["checkout"]
                    ):
                        return {
                            "source": str(source),
                            "line": call.lineno,
                            "function": frame.f_code.co_name,
                            "globals_module": module.__name__
                            if module
                            else "authenticated registered inline payload",
                        }
                except (AttributeError, IndexError, KeyError, NameError, TypeError, ValueError):
                    continue
        sys.modules['runtime_guard'].append({'kind': 'finite_fallback_diagnostic',
            'candidate': registration['class'], 'frames': diagnostics,
            'active_source_frames': [{'path': f.f_code.co_filename, 'function': f.f_code.co_name,
                                     'line': f.f_lineno} for f in frames if f.f_code.co_filename.startswith(state['checkout'])]})
        return None
    finally:
        frames.clear()
