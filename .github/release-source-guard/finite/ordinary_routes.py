"""Exact foreign-owner sleep in the unchanged mutation-journal oracle."""

import hashlib
import inspect
import json
import os
from pathlib import Path
import sys


def admit(argv, cwd, env, state, append, refuse):
    source = Path(state["checkout"]) / "tests/test_mutation_journal.py"
    frame = inspect.currentframe()
    try:
        while frame:
            if (
                frame.f_code.co_filename == str(source)
                and frame.f_code.co_name
                == "test_live_foreign_owner_is_busy_and_record_is_unchanged"
            ):
                break
            frame = frame.f_back
        if frame is None:
            return None
        pin = state["product_pins"]["tests/test_mutation_journal.py"]
        if hashlib.sha256(source.read_bytes()).hexdigest() != pin:
            refuse("ordinary_owner_source_drift")
        temporary = frame.f_locals["tmp_path"].resolve()
        if (
            frame.f_lineno != 149
            or argv != [sys.executable, "-c", "import time; time.sleep(10)"]
            or cwd is not None
            or env is not None
            or os.getcwd() != state["checkout"]
            or not temporary.is_relative_to(Path(state["owned_root"]))
        ):
            refuse("ordinary_owner_identity_drift")
        binding = {
            "path": str(source),
            "line": 149,
            "sha256": pin,
            "function": frame.f_code.co_name,
        }
        append(
            {
                "kind": "concrete_foreign_owner_registration",
                "source_binding": binding,
                "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                "cwd": os.getcwd(),
                "environment_sha256": hashlib.sha256(
                    json.dumps(dict(os.environ), sort_keys=True).encode()
                ).hexdigest(),
            }
        )
        return {"class": "source-foreign-journal-owner", "python": True, "source_binding": binding}
    finally:
        del frame
