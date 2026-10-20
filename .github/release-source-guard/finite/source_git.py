"""Exact local source-regression and immutable historical inventory vectors."""

import hashlib
import json
import os
from pathlib import Path
import sys


def admit(argv, cwd, env, state, append, refuse):
    root = Path(state["checkout"])
    fallback = Path(state["guard"]).with_name("fallback_binding.py")
    namespace = {}
    exec(compile(fallback.read_bytes(), str(fallback), "exec"), namespace)
    frames = namespace["active_frames"]()
    try:
        if state.get('class') == 'original-cli-import:_import_probe':
            guard = sys.modules['runtime_guard']
            path = Path(state['guard']).with_name('repository_probe_git.py')
            try:
                selected = guard.checked_source(path, state['direct_support']['files'][str(path)])['admit'](
                    argv, cwd, env, state, append, refuse, frames)
            except guard.GuardRefusal:
                raise
            except (OSError, RuntimeError, KeyError, AttributeError, TypeError, ValueError):
                refuse('original_import_probe_git_binding_error')
            if selected is not None:
                return selected
        foundation = root / "src/unrest_harness/foundation_tools.py"
        effect = next(
            (
                f
                for f in frames
                if f.f_code.co_filename == str(foundation)
                and f.f_code.co_name == "effect"
                and f.f_lineno == 511
            ),
            None,
        )
        if effect is not None:
            owner = next(
                (
                    f
                    for f in frames
                    if f.f_code.co_filename == str(foundation)
                    and f.f_code.co_name == "open_campaign"
                ),
                None,
            )
            if owner is None:
                return None
            function = effect.f_globals["FoundationTools"].open_campaign
            codes = state["isolated_source_code"](foundation)
            owner_code = state["isolated_named"](codes, "open_campaign")
            effect_code = state["isolated_named"](owner_code, "effect")
            closure = owner.f_locals["effect"]
            pin = state["product_pins"]["src/unrest_harness/foundation_tools.py"]
            repository = effect.f_locals["repository"]
            if (
                hashlib.sha256(foundation.read_bytes()).hexdigest() != pin
                or function.__globals__ is not effect.f_globals
                or owner.f_globals is not effect.f_globals
                or function.__code__ is not owner.f_code
                or owner.f_code != owner_code
                or closure.__globals__ is not effect.f_globals
                or closure.__code__ is not effect.f_code
                or effect.f_code != effect_code
                or argv != ["git", "rev-parse", "HEAD"]
                or cwd != repository
                or env is not None
                or not repository.resolve().is_relative_to(Path(state["owned_root"]))
                or os.getcwd() != state["checkout"]
            ):
                refuse("foundation_effect_identity_drift")
            binding = {
                "path": str(foundation),
                "line": 511,
                "sha256": pin,
                "function": "FoundationTools.open_campaign.effect",
            }
            append({"kind": "exact_foundation_effect_registration", "source_binding": binding})
            return {
                "class": "source-foundation-effect-git",
                "python": False,
                "source_binding": binding,
            }
        choices = [
            ("tests/test_measurement.py", "_source"),
            ("src/unrest_harness/measurement.py", "protected_product_digest"),
            ("src/unrest_harness/measurement.py", "_git"),
            ("tests/contracts/test_lean_evidence_crosswalk.py", "_tag_bytes"),
            ("tests/contracts/test_lean_evidence_crosswalk.py", "_tag_paths"),
        ]
        for relative, name in choices:
            source = root / relative
            frame = next(
                (
                    f
                    for f in frames
                    if f.f_code.co_filename == str(source) and f.f_code.co_name == name
                ),
                None,
            )
            if frame is None:
                continue
            pin = state["product_pins"][relative]
            function = (
                getattr(frame.f_globals["BaselineRunner"], name)
                if relative.startswith("src/") and name == "_git"
                else frame.f_globals[name]
            )
            module = sys.modules.get(function.__module__)
            if (
                hashlib.sha256(source.read_bytes()).hexdigest() != pin
                or module is None
                or vars(module) is not frame.f_globals
                or function.__globals__ is not frame.f_globals
                or function.__code__ is not frame.f_code
                or frame.f_code
                != state["isolated_named"](state["isolated_source_code"](source), name)
            ):
                refuse("source_git_owner_drift")
            local = frame.f_locals
            if relative == "tests/test_measurement.py":
                if not state["case"].startswith(
                    (
                        "tests/test_measurement.py::test_product_digest_excludes_only_results",
                        "tests/test_measurement.py::test_evolution_cases_use_real_public_state_machine_and_cold_state",
                    )
                ):
                    return None
                directory = local["root"]
                vectors = {137: ["git", "init", "-q"], 138: ["git", "add", "."]}
                line = frame.f_lineno
                if line not in vectors:
                    return None
                expected = vectors[line]
            elif name == "protected_product_digest":
                directory = local["source_root"]
                line = 295
                expected = ["git", "ls-files", "-z", "--stage"]
            elif name == "_git":
                directory = local["repository"]
                line = 1017
                vectors = [
                    ("rev-parse", "HEAD"),
                    ("init", "-q"),
                    ("add", ".gitignore", "candidate.txt"),
                    (
                        "-c",
                        "user.name=Unrest Measurement",
                        "-c",
                        "user.email=measurement@invalid",
                        "commit",
                        "-q",
                        "-m",
                        "frozen baseline",
                    ),
                ]
                if local["arguments"] not in vectors:
                    refuse("measurement_git_vector_drift")
                expected = ["git", *local["arguments"]]
            else:
                directory = root
                audit = root / "docs/release/lean-core-v0.2-review-audit.json"
                if (
                    hashlib.sha256(audit.read_bytes()).hexdigest()
                    != state["product_pins"][str(audit.relative_to(root))]
                ):
                    refuse("historical_inventory_drift")
                owner_names = {
                    "test_v02_source_import_dependency_and_hard_cut_inventories_are_historical",
                    "test_v02_package_inventory_is_bound_to_the_v020_tag",
                }
                owner = next(
                    (
                        f
                        for f in frames
                        if f.f_code.co_filename == str(source) and f.f_code.co_name in owner_names
                    ),
                    None,
                )
                if owner is None:
                    return None
                owner_function = owner.f_globals[owner.f_code.co_name]
                if (
                    owner_function.__globals__ is not frame.f_globals
                    or owner_function.__code__ is not owner.f_code
                    or owner.f_code
                    != state["isolated_named"](
                        state["isolated_source_code"](source), owner.f_code.co_name
                    )
                ):
                    refuse("historical_caller_drift")
                if name == "_tag_bytes":
                    if local["relative"] not in [
                        *json.loads(audit.read_bytes())["source_inventory"],
                        "pyproject.toml",
                    ]:
                        refuse("historical_path_drift")
                    line, expected = 22, ["git", "show", "v0.2.0:" + local["relative"]]
                else:
                    if local["root"] not in (
                        "src/unrest_harness",
                        "src/unrest_harness/bundled",
                        ".",
                    ):
                        refuse("historical_root_drift")
                    line, expected = (
                        31,
                        ["git", "ls-tree", "-r", "--name-only", "v0.2.0", "--", local["root"]],
                    )
            if (
                frame.f_lineno != line
                or argv != expected
                or cwd != directory
                or env is not None
                or os.getcwd() != state["checkout"]
                or directory != root
                and not directory.resolve().is_relative_to(Path(state["owned_root"]))
            ):
                refuse("source_git_vector_context_drift")
            binding = {"path": str(source), "line": line, "sha256": pin, "function": name}
            append(
                {
                    "kind": "exact_source_git_registration",
                    "source_binding": binding,
                    "argv": expected,
                    "cwd": str(directory),
                }
            )
            return {
                "class": "source-regression-git:" + relative + ":" + str(line),
                "python": False,
                "source_binding": binding,
            }
        if argv == ["git", "rev-parse", "HEAD"]:
            append(
                {
                    "kind": "unmapped_source_callstack",
                    "frames": [
                        {
                            "path": str(Path(f.f_code.co_filename).relative_to(root)),
                            "function": f.f_code.co_name,
                            "line": f.f_lineno,
                        }
                        for f in frames
                        if Path(f.f_code.co_filename).is_relative_to(root)
                    ],
                }
            )
        return None
    finally:
        frames.clear()
