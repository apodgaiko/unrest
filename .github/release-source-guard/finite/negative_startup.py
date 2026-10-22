"""Join original negative readiness probes to their exact owned inline child.

A plan never admits network traffic: the existing supervisor returns ECONNREFUSED
while this child has no listener. Complete authenticated guard setup within the
constructor's existing five-second budget before the original .5s probe begins.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import time
import types

SOURCE = 'tests/test_acp_cleanup.py'
PIN = 'f63f37e40e925d409c4f8203ebabe85dcc0bc5d7e9c77feb267c485eacfce321'
OWNER = 'test_startup_failure_attribution_and_owned_cleanup'
CASES = frozenset(SOURCE + '::' + OWNER + '[' + failure + '-' + role + ']'
                  for failure in ('exit', 'deadline', 'cancel')
                  for role in ('work', 'validate', 'terminal_reviewer'))
BODIES = {'exit': "import sys; print('private-startup-body',file=sys.stderr); sys.exit(23)",
          'deadline': 'import time; time.sleep(30)', 'cancel': 'import time; time.sleep(30)'}


def owned_case(state):
    return (state.get('case') in CASES and state.get('token') == 'root'
            and state.get('class') == 'pytest-root' and state.get('checkout') == '/source')


def frames():
    frame = sys._getframe(1)
    result = {}
    while frame is not None:
        result[id(frame)] = frame
        frame = frame.f_back
    import asyncio
    for task in asyncio.all_tasks():
        coroutine, seen = task.get_coro(), set()
        while coroutine is not None and id(coroutine) not in seen:
            seen.add(id(coroutine))
            frame = getattr(coroutine, 'cr_frame', None) or getattr(coroutine, 'gi_frame', None)
            if frame is not None:
                result[id(frame)] = frame
            coroutine = getattr(coroutine, 'cr_await', None) or getattr(coroutine, 'gi_yieldfrom', None)
    return list(result.values())


def fixture_context(guard, payload):
    state = guard._STATE
    if not owned_case(state):
        return None
    source = Path('/source') / SOURCE
    if state['product_pins'].get(SOURCE) != PIN or guard.digest(source) != PIN:
        guard.refuse('negative_startup_source_drift')
    code = state['isolated_named'](state['isolated_source_code'](source), OWNER)
    candidates = frames()
    try:
        owners = [f for f in candidates if f.f_code == code and f.f_code.co_filename == str(source)]
        if len(owners) != 1:
            guard.refuse('negative_startup_owner_missing')
        owner = owners[0]
        module = sys.modules.get(owner.f_globals.get('__name__'))
        local = owner.f_locals
        original = getattr(module, OWNER, None)
        start = local.get('start')
        if (module is None or vars(module) is not owner.f_globals
                or not isinstance(original, types.FunctionType) or original.__code__ != code
                or original.__globals__ is not owner.f_globals
                or not isinstance(start, types.FunctionType) or start.__globals__ is not owner.f_globals
                or start.__code__ != state['isolated_named'](code, 'start')):
            guard.refuse('negative_startup_original_identity')
        active = [f for f in candidates if f.f_code is start.__code__ and f.f_globals is owner.f_globals]
        if len(active) != 1:
            guard.refuse('negative_startup_constructor_context')
        failure, role = local['failure'], local['role']
        expected_case = SOURCE + '::' + OWNER + '[' + failure + '-' + role + ']'
        line = 50 if failure == 'exit' else 51
        vector = payload['orig_argv']
        options = active[0].f_locals['kwargs']
        runner = local['runner']
        if (expected_case != state['case'] or payload['case'] != expected_case
                or payload['class'] != 'inline:test_acp_cleanup.py:' + str(line)
                or payload['source_binding'] != {'path': str(source), 'line': line, 'sha256': PIN}
                or vector != [sys.executable, '-c', BODIES[failure]]
                or payload['mode'] != 'inline' or payload['target'] != BODIES[failure]
                or runner._start_worker_mcp_server is not start
                or runner._start_terminal_reviewer_mcp is not start
                or active[0].f_locals['runner'] is not runner
                or os.getcwd() != '/source' or type(options.get('mcp_port')) is not int
                or not 0 < options['mcp_port'] < 65536):
            guard.refuse('negative_startup_plan_binding')
        return {'port': options['mcp_port'], 'case': expected_case,
                'class': payload['class'], 'token': payload['token'],
                'argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest()}
    finally:
        candidates.clear()


def plan(guard, payload, request):
    if payload.get('class') == 'source-cohort2:tests/test_acp_runner.py:70':
        support = Path(guard._STATE['guard']).with_name('negative_readiness.py')
        return guard.checked_source(
            support, guard._STATE['direct_support']['files'][str(support)])['plan'](guard, payload, request)
    if payload.get('class') not in {'inline:test_acp_cleanup.py:50', 'inline:test_acp_cleanup.py:51'}:
        return
    if not owned_case(guard._STATE):
        return
    context = fixture_context(guard, payload)
    if context is None:
        guard.refuse('negative_startup_unbound_inline')
    plans = guard._STATE.setdefault('negative_startup_plans', {})
    if context['token'] in plans:
        guard.refuse('negative_startup_duplicate_plan')
    request('plan', host='127.0.0.1', port=context['port'],
            child_token=context['token'], argv_sha256=context['argv_sha256'])
    plans[context['token']] = context


def complete(record, state, endpoint_state, token, pid):
    parent = endpoint_state['identity']
    child = record.get('identity', {})
    return (record.get('kind') == 'endpoint_install_complete'
            and record.get('token') == token and record.get('owner_pid') == pid
            and record.get('parent_pid') == os.getpid()
            and record.get('nonce') == endpoint_state['spec']['nonce']
            and record.get('manifest_sha256') == state['pin']
            and record.get('guard_sha256') == state['guard_sha256']
            and child.get('pid') == pid and child.get('ppid') == parent['pid'] == os.getpid()
            and child.get('uid') == parent['uid'] == 20000
            and all(child.get(k) == parent[k] for k in ('boot_id', 'clock_ticks_per_second', 'pgid', 'sid'))
            and type(child.get('start_ticks')) is int and child['start_ticks'] >= parent['start_ticks'])


def observe(guard, endpoint_state, frame, event, value):
    state = guard._STATE
    if (event != 'return' or not owned_case(state)
            or frame.f_globals is not vars(guard)
            or frame.f_code.co_filename != state['guard']
            or frame.f_code.co_name != 'initialize_inner'):
        return
    local = frame.f_locals
    token = local.get('launch_token')
    context = state.get('negative_startup_plans', {}).get(token)
    if context is None:
        return
    expected = state['isolated_named'](compile(Path(state['guard']).read_bytes(),
                                              state['guard'], 'exec', dont_inherit=True), 'initialize_inner')
    if (guard.digest(state['guard']) != state['guard_sha256'] or frame.f_code != expected
            or local.get('state') is not state or local.get('registration', {}).get('class') != context['class']
            or context['case'] != state['case'] or type(local.get('deadline')) is not float
            or local.get('kwargs', {}).get('env') is not None
            or local.get('kwargs', {}).get('cwd') is not None):
        guard.refuse('negative_startup_ready_context')
    pid = local['handle'].pid
    journal = Path(state['events']) / (str(pid) + '.jsonl')
    while True:
        if time.monotonic() >= local['deadline']:
            guard.refuse('negative_startup_authenticated_READY_deadline')
        data = journal.read_bytes() if journal.exists() else b''
        committed = data[:data.rfind(b'\n') + 1]
        records = [json.loads(line) for line in committed.splitlines()]
        if any(complete(row, state, endpoint_state, token, pid) for row in records):
            del state['negative_startup_plans'][token]
            return
        time.sleep(.001)
