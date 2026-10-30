"""Warning fixture environments remain exact after caller policing retirement."""

from copy import deepcopy
from pathlib import Path

import pytest

from content_manifest import Refused
from controlled_cases import WARNING_REFUSALS
from controlled_startup import expected_entry
from source_observer import Observer
from effect_proposals import proposal
from test_proposal_support import operands
from process_ledger import Birth

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


@pytest.mark.parametrize("mutation", ["home", "extra", "missing", "value"])
def test_original_warning_environment_is_exact(tmp_path, monkeypatch, mutation):
    case = next(iter(WARNING_REFUSALS))
    home = tmp_path / "pytest/campaign/owner/worker"
    home.mkdir(parents=True)
    from test_controlled_catalogue import backend as original_backend
    import controlled_cases
    monkeypatch.setattr(controlled_cases,'acquire_backend',lambda case,home:original_backend(case)[0])
    expected, _, _ = expected_entry(case, ROOT, home, "/native/python", "a" * 64, backend=True,variant=2,backend_pin=original_backend(case)[0])
    request = operands(expected)
    changed = deepcopy(request)
    environment = changed["environment"]
    if mutation == "home":
        environment["HOME"] = "/foreign"
    elif mutation == "extra":
        environment["FOREIGN"] = "1"
    elif mutation == "missing":
        environment.pop(next(iter(environment)))
    else:
        environment[next(iter(environment))] = "foreign"
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = False, []
    observer.case = case
    observer.finished,observer.serial=False,0
    observer.root_birth=Birth(1,1,1,1,'boot',20000)
    observer.meta={'mounts':{},'checkout':str(ROOT),'owned':str(tmp_path)}
    observer.binding={'entry':{'path':'/native/python','sha256':'a'*64}}
    observer.intents,observer.actors={},{}
    with pytest.raises(Refused,match='original launch operands differ from declaration'):
        proposal(observer,{'birth':observer.root_birth,'role':'root'},changed)
    assert not observer.intents
    assert proposal(observer,{'birth':observer.root_birth,'role':'root'},request)['ok'] is True
    assert len(observer.intents)==1
