"""Exact original fixture wrappers retaining an already prepared function.

This admits no wrapper-selected command. The original product frame, original
asyncio constructor and complete immutable launch intent remain mandatory.
"""
from __future__ import annotations

import importlib
from pathlib import Path
import types

from content_manifest import Refused
from controlled_cases import PINS
from source_owner import Link, Owner, prepare, _namespace, _safe_code

WRAPPERS = {
    ('create_subprocess_exec', 'tests.test_controlled_acp_cancel', 'methods.<locals>.observed'): 'launch',
    ('create_subprocess_exec', 'tests.test_experimental_session', 'test_cancel_during_registration_retains_handle.<locals>.delayed'): 'original',
    ('create_subprocess_exec', 'tests.test_experimental_session', 'test_registration_after_close_deadline_bounded.<locals>.delayed'): 'original',
    ('start', 'tests.test_controlled_acp_cancel', 'test_owned_cancel_wire_and_cleanup.<locals>.observed_start'): 'bridge_start',
    ('start', 'tests.test_controlled_python_acp', 'test_single_c1_fixed_timing_protocol_witness.<locals>.started'): 'start',
}


def verify(container: object, name: str, original: types.FunctionType, checkout: Path) -> None:
    live = _namespace(container).get(name)
    if live is original:
        return
    if type(live) is not types.FunctionType or type(live.__module__) is not str or type(live.__qualname__) is not str:
        raise Refused('controlled unprepared wrapper function')
    _safe_code(live.__code__)
    key = name, live.__module__, live.__qualname__
    retained = WRAPPERS.get(key)
    if retained is None:
        raise Refused('controlled undeclared original wrapper')
    module = importlib.import_module(live.__module__)
    file = live.__module__.replace('.', '/') + '.py'
    if file not in PINS or live.__globals__ is not vars(module):
        raise Refused('controlled wrapper source module')
    unit = prepare((checkout / file).read_bytes(), str(checkout / file), live.__module__, 'pytest', PINS[file])
    codes = [code for code in unit.codes if code.co_qualname == live.__qualname__]
    cells = live.__closure__ or ()
    values = {key: cell.cell_contents for key, cell in zip(live.__code__.co_freevars,cells,strict=True)}
    if len(codes) != 1 or values.get(retained) is not original:
        raise Refused('controlled wrapper retained original')
    Owner(unit,module,live,live.__qualname__,codes[0].co_firstlineno,(1,100000),
        (Link(container,name,live),),tuple(values[key] for key in live.__code__.co_freevars),cells).verify_binding()
