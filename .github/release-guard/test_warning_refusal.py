"""Warning fixture environments remain exact after caller policing retirement."""

from copy import deepcopy
from pathlib import Path

import pytest

from content_manifest import Refused
from controlled_cases import WARNING_REFUSALS
from controlled_startup import expected_entry
from source_observer import Observer

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


@pytest.mark.parametrize("mutation", ["home", "extra", "missing", "value"])
def test_original_warning_environment_is_exact(tmp_path, mutation):
    case = next(iter(WARNING_REFUSALS))
    home = tmp_path / "campaign/owner/worker"
    home.mkdir(parents=True)
    expected, _, pin = expected_entry(case, ROOT, home, "/native/python", "a" * 64, backend=True)
    request = {
        "case": case,
        "original": expected.wire(),
        "translated": ["/native/python", "-I", "-S", *expected.argv[1:]],
        "source_line": 506,
        "script_sha256": pin,
    }
    changed = deepcopy(request)
    environment = changed["original"]["environment"]
    if mutation == "home":
        environment[:] = [
            [key, "/foreign" if key == "HOME" else value] for key, value in environment
        ]
    elif mutation == "extra":
        environment.append(["FOREIGN", "1"])
    elif mutation == "missing":
        environment.pop()
    else:
        environment[0][1] = "foreign"
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = False, []
    observer.case = case
    observer.intents = {}
    with pytest.raises(Refused, match="independent launch reconstruction"):
        observer.admit_launch({}, changed, expected, "backend", 506, request["translated"], pin)
    assert not observer.intents
