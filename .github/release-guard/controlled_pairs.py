"""Finite owner/role graph for unchanged controlled source cases.

Bounds follow the original lane histories and two-ordinal rotation. They cap
admission; passing still requires every original assertion and actual child wait.
A role pair is a backend followed by its ACP, never a case-wide recent process.
"""
from __future__ import annotations

from pathlib import Path

from content_manifest import Refused
from controlled_cases import CASES, FRESH, POPULATED, ADMISSION, WARNING_REFUSALS, NOTIFICATION_STARTUP, NOTIFICATION_SIGNALS, ROOT_HTTP, STARTUP_FAILURE


def limits(case: str) -> tuple[int, int]:
    if type(case) is not str or case not in CASES:
        raise Refused('controlled pair case')
    from cohort_cases import CAMPAIGNS
    if case in CAMPAIGNS:
        return CAMPAIGNS[case][0], 0
    from cohort_controller import CASES as CRASH
    if case in CRASH:
        return (0 if case==CRASH[0] else 1),0
    if case in ROOT_HTTP:
        return 1, 0 if 'initialized_owner' in case else 3
    if case == STARTUP_FAILURE or case in (*FRESH,*ADMISSION,*WARNING_REFUSALS,*NOTIFICATION_STARTUP,*NOTIFICATION_SIGNALS):
        return 1, 0
    if case in POPULATED:
        return (1, 3) if case.endswith('-True]') else (2, 13)
    file, name = case.split('::')
    if file.endswith('test_controlled_acp_cancel.py'):
        return 1, 3
    if file.endswith('test_experimental_bridge_shutdown.py'):
        return 1, 0
    if file.endswith('test_controlled_python_acp.py'):
        return (6, 18) if name == 'test_single_c1_fixed_timing_protocol_witness' else (1, 0)
    if file.endswith(('test_experimental_ack_durability.py', 'test_experimental_first_halt.py')):
        return 2, 6
    if file.endswith('test_experimental_drain_retirement.py'):
        return (2, 6) if name == 'test_prior_failure_kept_while_unaffected_sent_sibling_drains' else (3, 9)
    if file.endswith('test_experimental_finite_stops.py'):
        return (3, 9) if 'expiry' in name else (8, 24)
    if file.endswith('test_experimental_finite_orders.py'):
        if name.startswith('test_script_order_boundaries['):
            scripts = name.removesuffix(']').rsplit('-', 1)[1]
            if scripts not in ('PP', 'RP', 'RC', 'RR'):
                raise Refused('controlled finite lane scripts')
            return {'PP': (6, 18), 'RP': (8, 31), 'RC': (10, 37), 'RR': (12, 43)}[scripts]
        return 6, 18
    raise Refused('controlled undeclared pair bound')


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
    maximum, _ = limits(case)
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
