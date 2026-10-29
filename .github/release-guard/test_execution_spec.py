"""Synthetic exact-spec mutations; native prebody behavior is separately checked."""

from copy import deepcopy
import hashlib

import pytest

from content_manifest import Refused
from execution_spec import admitted, issue, validate


def profile(tmp_path):
    vector = ["/fixed/python", "-I", "-S", "-c", "pass"]
    return {
        "role": "fixed-inline",
        "argv": vector,
        "script": None,
        "execution": issue("fixed-inline", vector, None, None),
    }


@pytest.mark.parametrize(
    "event,arguments",
    [
        ("cpython.run_file", ("pass\n",)),
        ("cpython.run_command", ("foreign\n",)),
        ("cpython.run_command", ("pass\n", "extra")),
    ],
)
def test_actual_entry_event_and_arguments_must_match(tmp_path, event, arguments):
    with pytest.raises(Refused):
        validate(profile(tmp_path), event, arguments, tmp_path)


def test_exact_inline_entry_consumes_without_script_authority(tmp_path):
    validate(profile(tmp_path), "cpython.run_command", ("pass\n",), tmp_path)


def test_script_pin_is_external_and_current_bytes_are_remeasured(tmp_path):
    file = tmp_path / "fixture"
    file.write_bytes(b"pass\n")
    pin = hashlib.sha256(b"pass\n").hexdigest()
    vector = ["/fixed/python", "-I", "-S", str(file)]
    value = {
        "role": "backend",
        "argv": vector,
        "script": str(file),
        "execution": issue("backend", vector, str(file), pin),
    }
    validate(value, "cpython.run_file", (str(file),), tmp_path)
    file.write_bytes(b'print("foreign")\n')
    with pytest.raises(Refused, match="script bytes"):
        validate(value, "cpython.run_file", (str(file),), tmp_path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("token", "foreign"),
        ("case", "foreign"),
        ("role", "backend"),
        ("pid", 124),
        ("consumed", False),
        ("translated", ["/foreign"]),
        ("environment", {"X": "foreign"}),
        ("cwd", "/foreign"),
    ],
)
def test_spec_cannot_borrow_another_admitted_intent(tmp_path, field, value):
    vector = profile(tmp_path)["argv"]
    row = {
        "token": "token",
        "case": "case",
        "role": "fixed-inline",
        "pid": 123,
        "consumed": True,
        "translated": vector,
        "environment": {},
        "cwd": "/owned",
        "script_sha256": "a" * 64,
    }
    assert admitted(
        {1: row}, "fixed-inline", "case", 123, "token", vector, {}, "/owned", None
    ) == issue("fixed-inline", vector, None, None)
    changed = deepcopy(row)
    changed[field] = value
    with pytest.raises(Refused, match="unique admitted intent"):
        admitted({1: changed}, "fixed-inline", "case", 123, "token", vector, {}, "/owned", None)
    with pytest.raises(Refused, match="unique admitted intent"):
        admitted(
            {1: row, 2: deepcopy(row)},
            "fixed-inline",
            "case",
            123,
            "token",
            vector,
            {},
            "/owned",
            None,
        )

