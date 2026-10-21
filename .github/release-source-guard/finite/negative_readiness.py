"""Exact no-listener readiness probes use the existing non-admitting plan RPC."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import types

SOURCE = 'tests/test_acp_runner.py'
PIN = 'b6f1c200a94c1107d6059baae0eb646dd5a113cc304d7062b29aec8263dd52d0'
OWNER = 'test_readiness_attributes_local_child_and_drains'
CLASS = 'source-cohort2:tests/test_acp_runner.py:70'
BODY = "import time; print('started',flush=True); time.sleep(30)"
CASES = frozenset(SOURCE + '::' + OWNER + '[' + mode + ']' for mode in ('never_ready', 'cancel'))


def plan(guard, payload, request):
    state = guard._STATE
    if (state.get('case') not in CASES or payload.get('class') != CLASS
            or state.get('class') != 'pytest-root' or state.get('token') != 'root'
            or state.get('checkout') != '/source'):
        return
    source = Path('/source') / SOURCE
    if state['product_pins'].get(SOURCE) != PIN or guard.digest(source) != PIN:
        guard.refuse('negative_readiness_source_drift')
    support = Path(state['guard']).with_name('fallback_binding.py')
    frames = guard.checked_source(support, state['direct_support']['files'][str(support)])['active_frames']()
    try:
        code = state['isolated_named'](state['isolated_source_code'](source), OWNER)
        exercise_code = state['isolated_named'](code, 'exercise')
        owners = {id(f): f for f in frames if f.f_code == code and f.f_code.co_filename == str(source)}
        active = {id(f): f for f in frames if f.f_code == exercise_code and f.f_code.co_filename == str(source)}
        if len(owners) != 1 or len(active) != 1:
            guard.refuse('negative_readiness_live_owner')
        owner, caller = next(iter(owners.values())), next(iter(active.values()))
        module = sys.modules.get(owner.f_globals.get('__name__'))
        function = getattr(module, OWNER, None)
        exercise = owner.f_locals.get('exercise')
        mode = owner.f_locals.get('mode')
        binding = {'path': str(source), 'line': 70, 'sha256': PIN,
                   'function': OWNER + '.<locals>.exercise'}
        vector = [sys.executable, '-c', BODY]
        if (module is None or vars(module) is not owner.f_globals
                or caller.f_globals is not owner.f_globals
                or not isinstance(function, types.FunctionType) or function.__code__ is not owner.f_code
                or function.__globals__ is not owner.f_globals
                or not isinstance(exercise, types.FunctionType) or exercise.__code__ is not caller.f_code
                or exercise.__globals__ is not owner.f_globals or not 70 <= caller.f_lineno <= 73
                or mode not in {'never_ready', 'cancel'} or caller.f_locals.get('mode') != mode
                or state['case'] != SOURCE + '::' + OWNER + '[' + mode + ']'
                or payload.get('case') != state['case'] or payload.get('source_binding') != binding
                or payload.get('mode') != 'inline' or payload.get('target') != BODY
                or payload.get('orig_argv') != vector or caller.f_locals.get('body') != BODY
                or os.getcwd() != '/source' or type(payload.get('token')) is not str
                or len(payload['token']) != 32 or any(c not in '0123456789abcdef' for c in payload['token'])):
            guard.refuse('negative_readiness_binding_drift')
        plans = state.setdefault('negative_readiness_plans', set())
        if payload['token'] in plans:
            guard.refuse('negative_readiness_duplicate_plan')
        request('plan', host='127.0.0.1', port=1, child_token=payload['token'],
                argv_sha256=hashlib.sha256(json.dumps(vector).encode()).hexdigest())
        plans.add(payload['token'])
    finally:
        frames.clear()
