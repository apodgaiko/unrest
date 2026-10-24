"""Original delayed bootstrap fixture: exact wrapper and live product ownership."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import types

SOURCE = "tests/test_experimental_bootstrap.py"
PIN = "c81fc04a81ef3aa657c16a69627c4c6b80ba1012f9255d2a05b15557934a7383"
CASES = (
    "tests/test_experimental_bootstrap.py::test_actual_thirty_two_second_readiness",
    "tests/test_experimental_bootstrap.py::test_actual_launch_lifetime_and_interruptions[near]",
    "tests/test_experimental_bootstrap.py::test_actual_launch_lifetime_and_interruptions[exhausted]",
    "tests/test_experimental_bootstrap.py::test_actual_launch_lifetime_and_interruptions[cancel]",
    "tests/test_experimental_bootstrap.py::test_actual_launch_lifetime_and_interruptions[stop]",
    "tests/test_experimental_bootstrap.py::test_phases_share_one_deadline_across_tasks",
    "tests/test_experimental_bootstrap.py::test_absolute_ledger_includes_setup_and_cleanup",
    "tests/test_experimental_bootstrap.py::test_capped_body_free_observation_is_pre_cleanup",
    "tests/test_experimental_bootstrap.py::test_turn_reservation_does_not_restart_clock_after_bootstrap",
    "tests/test_experimental_bootstrap.py::test_delayed_turn_uses_only_original_remaining_time",
    "tests/test_experimental_bootstrap.py::test_original_limits_refuse_before_grant_or_send[False-turn]",
    "tests/test_experimental_bootstrap.py::test_original_limits_refuse_before_grant_or_send[False-episode]",
    "tests/test_experimental_bootstrap.py::test_original_limits_refuse_before_grant_or_send[False-campaign]",
    "tests/test_experimental_bootstrap.py::test_original_limits_refuse_before_grant_or_send[True-turn]",
    "tests/test_experimental_bootstrap.py::test_original_limits_refuse_before_grant_or_send[True-episode]",
    "tests/test_experimental_bootstrap.py::test_original_limits_refuse_before_grant_or_send[True-campaign]",
    "tests/test_experimental_bootstrap.py::test_boundary_recheck_blocks_expired_or_stopped_send[expire-reserve]",
    "tests/test_experimental_bootstrap.py::test_boundary_recheck_blocks_expired_or_stopped_send[expire-grant]",
    "tests/test_experimental_bootstrap.py::test_boundary_recheck_blocks_expired_or_stopped_send[expire-send]",
    "tests/test_experimental_bootstrap.py::test_boundary_recheck_blocks_expired_or_stopped_send[expire-serialize]",
    "tests/test_experimental_bootstrap.py::test_boundary_recheck_blocks_expired_or_stopped_send[stop-reserve]",
    "tests/test_experimental_bootstrap.py::test_boundary_recheck_blocks_expired_or_stopped_send[stop-grant]",
    "tests/test_experimental_bootstrap.py::test_boundary_recheck_blocks_expired_or_stopped_send[stop-send]",
    "tests/test_experimental_bootstrap.py::test_boundary_recheck_blocks_expired_or_stopped_send[stop-serialize]",
    "tests/test_experimental_bootstrap.py::test_actual_sequential_initialize_and_session_share_cutoff",
    "tests/test_experimental_bootstrap.py::test_startup_subtracts_from_actual_inference_timeout",
    "tests/test_experimental_bootstrap.py::test_expiry_during_seal_cannot_publish_grant",
)
CLASS = "source-delayed-bootstrap"


def delay_for(case):
    if case not in CASES:
        return None
    name = case.split("::", 1)[1]
    if name in {
        "test_actual_thirty_two_second_readiness",
        "test_delayed_turn_uses_only_original_remaining_time",
    }:
        return 32
    if name.startswith(
        (
            "test_actual_launch_lifetime_and_interruptions[",
            "test_original_limits_refuse_before_grant_or_send[",
        )
    ):
        return 60
    if name == "test_startup_subtracts_from_actual_inference_timeout":
        return 0.5
    return None


def script(delay):
    return (
        "import runpy,sys,time; p=sys.argv.pop(1); "
        f'time.sleep({delay!r}); runpy.run_path(p,run_name="__main__")'
    )


def vector(original, delay):
    return [original[0], "-c", script(delay), *original[1:]]


def select(argv, cwd, environment, state, emit, refuse):
    delay = delay_for(state.get("case"))
    if (
        state.get("case") not in CASES
        or state.get("token") != "root"
        or state.get("class") != "pytest-root"
    ):
        return None
    if delay is not None and (len(argv) < 4 or argv[1] != "-c"):
        return None
    guard = sys.modules["runtime_guard"]

    def checked(name):
        path = Path(state["guard"]).with_name(name)
        return guard.checked_source(path, state["direct_support"]["files"][str(path)])

    source = Path(state["checkout"]) / SOURCE
    if (
        state["product_pins"].get(SOURCE) != PIN
        or hashlib.sha256(source.read_bytes()).hexdigest() != PIN
    ):
        refuse("delayed_bootstrap_source_drift")
    catalog = checked("backend_postimage_catalog.py")
    catalog = {
        **catalog,
        "CASES": {
            case: {
                "script_sha256": "be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53",
                "sources": {
                    "tests/test_experimental_bootstrap.py": "c81fc04a81ef3aa657c16a69627c4c6b80ba1012f9255d2a05b15557934a7383",
                    "tests/test_experimental_session.py": "baca26ee3feb60d74d435becb950db24e8849aa16015cf15e1943cfbc0f3f9e3",
                    "tests/test_experimental_startup_diagnostics.py": "b2b2d05a217dcd4e082e06371c00e9ae91fb99a7c50bfcec15e7e810b2b7d65f",
                    "tools/probe_v046_startup.py": "eb26f43472ce1798d2dd066fa87d6ceb5d58d1a94abc0e9edddeb20b285dd564",
                },
                "filename": "fake-app-server",
            }
            for case in CASES
        },
    }
    binding = checked("fallback_binding.py")
    frames = binding["active_frames"]()
    try:
        if delay is None:
            registration = checked("backend_postimage_route.py")["select"](
                list(argv), cwd, environment, state, frames, catalog
            )
            if registration is None:
                return None
            if binding["matches"](registration, list(argv), cwd, environment, state) is None:
                refuse("bootstrap_original_backend_caller")
            return registration, list(argv)
        compiled = state["isolated_source_code"](source)
        named = state["isolated_named"]
        fixture = named(compiled, "delayed_backend")
        install = named(fixture, "install")
        delayed = named(install, "delayed")
        matches = list(
            {
                id(frame): frame
                for frame in frames
                if frame.f_code == delayed
                and frame.f_code.co_filename == str(source)
                and frame.f_lineno == 38
            }.values()
        )
        if len(matches) != 1:
            refuse("delayed_bootstrap_original_frame")
        frame = matches[0]
        module = sys.modules.get(frame.f_globals.get("__name__"))
        function = getattr(module, "delayed_backend", None)
        underlying = getattr(function, "__wrapped__", None)
        if (
            module is None
            or vars(module) is not frame.f_globals
            or not isinstance(underlying, types.FunctionType)
            or underlying.__globals__ is not frame.f_globals
            or underlying.__code__ != fixture
        ):
            refuse("delayed_bootstrap_fixture_identity")
        import asyncio

        live = asyncio.create_subprocess_exec
        product = sys.modules.get("unrest_harness.experimental_session")
        environment_function = product._SessionOwner._environment if product is not None else None
        expected_environment = named(fixture, "controlled_environment")
        if (
            not isinstance(environment_function, types.FunctionType)
            or environment_function.__globals__ is not frame.f_globals
            or environment_function.__code__ != expected_environment
            or environment_function.__code__.co_freevars != ("environment",)
            or environment_function.__closure__ is None
            or len(environment_function.__closure__) != 1
        ):
            refuse("delayed_bootstrap_environment_function")
        captured_environment = environment_function.__closure__[0].cell_contents
        if not isinstance(captured_environment, types.FunctionType) or not checked(
            "backend_postimage_route.py"
        )["original_function"](
            product,
            captured_environment,
            Path(state["checkout"]) / "src/unrest_harness/experimental_session.py",
            state,
        ):
            refuse("delayed_bootstrap_environment_capture")
        local = frame.f_locals
        if (
            not isinstance(live, types.FunctionType)
            or live.__globals__ is not frame.f_globals
            or live.__code__ is not frame.f_code
            or live.__code__.co_freevars != delayed.co_freevars
            or live.__closure__ is None
            or any(
                cell.cell_contents is not local.get(name)
                for name, cell in zip(live.__code__.co_freevars, live.__closure__, strict=True)
            )
        ):
            refuse("delayed_bootstrap_installed_constructor")
        options = local.get("kwargs")
        if (
            type(options) is not dict
            or local.get("delay") != delay
            or type(local.get("delay")) is not type(delay)
            or local.get("script") != script(delay)
            or list(local.get("args", ())) != list(argv)
            or options.get("cwd") != cwd
            or options.get("env") is not environment
        ):
            refuse("delayed_bootstrap_original_arguments")
        import asyncio.subprocess

        create = asyncio.subprocess.create_subprocess_exec
        if local.get("launch") is not create:
            refuse("delayed_bootstrap_captured_constructor")
        product = sys.modules.get("unrest_harness.experimental_session")
        owners = list(
            {
                id(frame): frame
                for frame in [
                    frame
                    for frame in frames
                    if product is not None
                    and frame.f_code is product._SessionOwner._open_role_owned.__code__
                    and frame.f_globals is vars(product)
                    and frame.f_lineno == 506
                ]
            }.values()
        )
        if len(owners) != 1:
            refuse("delayed_bootstrap_product_owner")
        owner = owners[0].f_locals
        original = owner.get("argv")
        if (
            type(original) is not list
            or len(original) < 3
            or list(argv) != vector(original, delay)
            or type(options.get("stdin")) is not int
            or type(options.get("stdout")) is not int
            or type(options.get("stderr")) is not int
            or options.get("stdin") != asyncio.subprocess.PIPE
            or options.get("stdout") != asyncio.subprocess.PIPE
            or options.get("stderr") != asyncio.subprocess.PIPE
            or set(options)
            != {
                "cwd",
                "env",
                "stdin",
                "stdout",
                "stderr",
                "limit",
                "close_fds",
                "start_new_session",
            }
            or type(product.PREFLIGHT_BYTES) is not int
            or product.PREFLIGHT_BYTES != 262144
            or type(options["limit"]) is not int
            or options["limit"] != 262143
            or options["close_fds"] is not True
            or options["start_new_session"] is not True
        ):
            refuse("delayed_bootstrap_product_vector")
        original_route = checked("backend_postimage_route.py")
        registration = original_route["select"](original, cwd, environment, state, frames, catalog)
        if (
            registration is None
            or binding["matches"](registration, original, cwd, environment, state) is None
        ):
            refuse("delayed_bootstrap_product_binding")
        selected = {
            "class": CLASS,
            "python": True,
            "source_binding": {"path": str(source), "line": 38, "sha256": PIN},
            "product_binding": registration["source_binding"],
            "script_sha256": registration["script_sha256"],
            "delay": delay,
            "case": state["case"],
        }
        emit(
            {
                "kind": "original_delayed_bootstrap_binding",
                "case": state["case"],
                "delay": delay,
                "source_binding": selected["source_binding"],
                "product_binding": selected["product_binding"],
                "argv_sha256": hashlib.sha256(json.dumps(list(argv)).encode()).hexdigest(),
                "original_vector_sha256": hashlib.sha256(json.dumps(original).encode()).hexdigest(),
                "original_delay_and_cleanup_assertions_retained": True,
            }
        )
        return selected, list(argv)
    finally:
        frames.clear()
