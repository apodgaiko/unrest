"""Exact original fresh-storage reader registration; no discovery or launch."""

import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import sys

SOURCE_SHA256 = "68418a6fac8295d675e2ca6f0849b16469a816c114c0b80a523f1b1d8797b20b"
BODY = "import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())"
CALLERS = {
    ("test_failure_preserves_target_and_cleans_unique_temp", 152),
    ("test_directory_fsync_failure_accepts_visible_generation", 181),
    ("test_regular_nested_destinations_remain_atomic", 474),
}


def admit(argv, cwd, env, state, append, refuse):
    source = Path(state["checkout"]) / "tests/test_storage.py"
    frame = inspect.currentframe()
    try:
        while frame:
            if (
                Path(frame.f_code.co_filename).resolve() == source
                and frame.f_code.co_name == "_fresh_process_bytes"
                and frame.f_code.co_firstlineno == 54
            ):
                break
            frame = frame.f_back
        if frame is None:
            return None
        if hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_SHA256:
            refuse("storage_reader_source_drift")
        caller = frame.f_back
        if (
            caller is None
            or Path(caller.f_code.co_filename).resolve() != source
            or (caller.f_code.co_name, caller.f_lineno) not in CALLERS
        ):
            refuse("storage_reader_caller")
        target = frame.f_locals["target"]
        directory = Path(os.getcwd()).resolve()
        resolved = target.resolve()
        owned_root = Path(state["owned_root"]).resolve()
        if (
            argv != [sys.executable, "-c", BODY, str(target)]
            or cwd is not None
            or env is not None
            or not resolved.is_relative_to(owned_root)
            or resolved == owned_root
            or (directory != Path(state["checkout"]) and not directory.is_relative_to(owned_root))
            or not stat.S_ISREG(target.lstat().st_mode)
        ):
            refuse("storage_reader_vector_path_environment")
        binding = {
            "path": str(source),
            "line": 56,
            "function": "_fresh_process_bytes",
            "function_line": 54,
            "sha256": SOURCE_SHA256,
        }
        append(
            {
                "kind": "concrete_storage_reader_registration",
                "source_binding": binding,
                "caller_line": caller.f_lineno,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "inline_sha256": hashlib.sha256(BODY.encode()).hexdigest(),
                "cwd": str(directory),
                "target": str(resolved),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(os.environ), sort_keys=True).encode()
                ).hexdigest(),
                "lifecycle": "original synchronous check_output/communicate/context wait",
            }
        )
        return {"class": "source-storage-fresh-reader", "python": True, "source_binding": binding}
    finally:
        del frame
