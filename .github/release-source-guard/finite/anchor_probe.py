"""Passive exact source/AST observations; these grant no launch authority."""

import ast
import hashlib
import inspect
import sys
from pathlib import Path


def observe(state, directory):
    frames = []
    frame = inspect.currentframe()
    try:
        while frame:
            frames.append(frame)
            frame = frame.f_back
        module = sys.modules.get("asyncio")
        if module is not None:
            try:
                task = module.current_task()
            except RuntimeError:
                task = None
            coroutine = task.get_coro() if task is not None else None
            seen = set()
            while coroutine is not None and id(coroutine) not in seen:
                seen.add(id(coroutine))
                candidate = getattr(coroutine, "cr_frame", None) or getattr(
                    coroutine, "gi_frame", None
                )
                if candidate is not None:
                    frames.append(candidate)
                coroutine = getattr(coroutine, "cr_await", None) or getattr(
                    coroutine, "gi_yieldfrom", None
                )
        rows = []
        checkout = Path(state["checkout"])
        for frame in frames:
            source = Path(frame.f_code.co_filename).resolve()
            if source.is_relative_to(checkout):
                relative = str(source.relative_to(checkout))
            elif (
                state.get("class") == "source-copied-repository-cli"
                and source == directory / "src/unrest_harness/repository_contract.py"
            ):
                relative = "src/unrest_harness/repository_contract.py"
            else:
                continue
            matching = [a for a in state["anchor_inventory"] if a["path"] == relative]
            if not matching:
                continue
            body = source.read_bytes()
            pin = hashlib.sha256(body).hexdigest()
            if any(a["source_sha256"] != pin for a in matching):
                raise RuntimeError("passive_anchor_source_drift")
            cache = state.setdefault("cohort_passive_ASTs", {})
            key = (str(source), pin)
            if key not in cache:
                nodes = [
                    n
                    for n in ast.walk(ast.parse(body))
                    if isinstance(n, ast.Call) and any(a["line"] == n.lineno for a in matching)
                ]
                bound = []
                for anchor in matching:
                    exact = [
                        n
                        for n in nodes
                        if n.lineno == anchor["line"]
                        and hashlib.sha256(
                            ast.dump(n, include_attributes=False).encode()
                        ).hexdigest()
                        == anchor["expression_ast_sha256"]
                    ]
                    if len(exact) != 1:
                        raise RuntimeError("passive_anchor_AST_drift")
                    bound.append((anchor, exact[0].end_lineno))
                cache[key] = bound
            for anchor, end_line in cache[key]:
                if anchor["line"] <= frame.f_lineno <= end_line:
                    row = {
                        **anchor,
                        "observed_source_path": str(source),
                        "function": frame.f_code.co_name,
                        "frame_line": frame.f_lineno,
                        "observation": "actual launch stack or active await chain",
                    }
                    if row not in rows:
                        rows.append(row)
        return sorted(rows, key=lambda r: (r["path"], r["line"], r["route"]))
    finally:
        del frame
        frames.clear()
