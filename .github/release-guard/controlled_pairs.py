"""Finite owner/role graph for unchanged controlled source cases.

A fixed resource ceiling bounds ordinary controlled pairs. Cohort/crash bounds
remain exact; passing requires every original assertion and actual child wait.
A role pair is a backend followed by its ACP, never a case-wide recent process.
"""
from __future__ import annotations

from pathlib import Path

from content_manifest import Refused as Refused, refuse_if
from controlled_cases import eligible, STARTUP_FAILURE, RUNTIME_DRIFT
from controlled_owners import selection


def limits(case: str) -> int:
    refuse_if(type(case) is not str or not eligible(case), 'controlled pair case')
    selected=selection(case)
    if selected is not None:
        return selected.pairs
    from cohort_cases import CAMPAIGNS
    from cohort_controller import CASES as CRASH
    if case in CAMPAIGNS:
        return CAMPAIGNS[case][0]
    if case in CRASH:
        return 0 if case==CRASH[0] else 1
    if case==RUNTIME_DRIFT:
        return 1
    return 20


def scope(case: str, tag: str, value: object, owned: Path) -> str:
    limits(case)
    refuse_if(type(value) is not str or tag not in ('broker', 'bridge', 'lifetime'), 'controlled listener scope primitives')
    path = Path(value)
    refuse_if(not path.is_absolute() or str(path.resolve()) != value
            or not path.is_relative_to(owned / 'pytest')
            or tag != 'broker' and path.name not in ('worker', 'validator'), 'controlled listener owned role scope')
    return value


def before_spawn(case: str, home: str, role: str, records: list[dict], executed) -> bool:
    maximum = limits(case)
    selected=selection(case)
    refuse_if((case in (STARTUP_FAILURE,RUNTIME_DRIFT) or selected is not None and selected.backend_only) and role != 'backend', 'startup failure has no ACP launch')
    pairs = {row['cwd'] for row in records if row['role'] == 'backend'}
    pair = [row for row in records if row['cwd'] == home]
    if role == 'backend':
        refuse_if(pair or len(pairs) >= maximum, 'controlled fresh backend pair bound')
    else:
        refuse_if(role != 'acp' or len(pair) != 1 or pair[0]['role'] != 'backend', 'controlled ACP original pair backend')
        return executed(pair[0])
    return True
