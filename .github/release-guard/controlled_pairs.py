"""Finite owner/role graph for unchanged controlled source cases.

A fixed resource ceiling bounds ordinary controlled pairs. Cohort/crash bounds
remain exact; passing requires every original assertion and actual child wait.
A role pair is a backend followed by its ACP, never a case-wide recent process.
"""
from __future__ import annotations

from pathlib import Path

from content_manifest import Refused
from controlled_cases import eligible, STARTUP_FAILURE


def limits(case: str) -> int:
    if type(case) is not str or not eligible(case):
        raise Refused('controlled pair case')
    from cohort_cases import CAMPAIGNS
    from cohort_controller import CASES as CRASH
    if case in CAMPAIGNS:
        return CAMPAIGNS[case][0]
    if case in CRASH:
        return 0 if case==CRASH[0] else 1
    return 20


def scope(case: str, tag: str, value: object, owned: Path) -> str:
    limits(case)
    if type(value) is not str or tag not in ('broker', 'bridge', 'lifetime'):
        raise Refused('controlled listener scope primitives')
    path = Path(value)
    if (not path.is_absolute() or str(path.resolve()) != value
            or not path.is_relative_to(owned / 'pytest')
            or tag != 'broker' and path.name not in ('worker', 'validator')):
        raise Refused('controlled listener owned role scope')
    return value


def before_spawn(case: str, home: str, role: str, records: list[dict], executed) -> bool:
    maximum = limits(case)
    if case == STARTUP_FAILURE and role != 'backend':
        raise Refused('startup failure has no ACP launch')
    pairs = {row['cwd'] for row in records if row['role'] == 'backend'}
    pair = [row for row in records if row['cwd'] == home]
    if role == 'backend':
        if pair or len(pairs) >= maximum:
            raise Refused('controlled fresh backend pair bound')
    else:
        if role != 'acp' or len(pair) != 1 or pair[0]['role'] != 'backend':
            raise Refused('controlled ACP original pair backend')
        return executed(pair[0])
    return True
