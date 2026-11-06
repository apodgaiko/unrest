"""Independent request mutations and immutable-input controls for source entry."""
from __future__ import annotations

from copy import deepcopy
import os
import signal
import sys
import threading
from types import SimpleNamespace

import pytest

from effect_proposals import proposal
from test_proposal_support import operands
from content_manifest import Refused
from controlled_startup import BACKEND_PIN
from test_startup_catalogue import CASES
from launch_policy import build_expected
from process_ledger import Birth
from source_host import inventory
import source_host
from source_entry import Policy
from source_observer import Observer
import test_process_ledger as ledger_rows


def test_private_input_inventory_rejects_aliases_and_writeable_members(tmp_path):
    member = tmp_path / 'module.py'
    member.write_text('value = 1\n')
    member.chmod(0o644)
    original = inventory(tmp_path)
    member.write_text('value = 2\n')
    assert inventory(tmp_path) != original
    member.chmod(0o666)
    with pytest.raises(RuntimeError, match='mutable'):
        inventory(tmp_path)
    member.chmod(0o644)
    (tmp_path / 'alias').symlink_to(member)
    with pytest.raises(RuntimeError, match='custody'):
        inventory(tmp_path)


def test_input_inventory_keeps_legacy_path_order_and_hash_encoding(tmp_path):
    (tmp_path/'a').mkdir()
    for name,body in (('a/b.txt',b'B'),('a.txt',b'A')):
        path=tmp_path/name
        path.write_bytes(body)
        path.chmod(0o644)
    assert inventory(tmp_path)=='15072d2561fd8112985562a33760675f985e164b927d6c4e186adf48326cc670'


def backend_request(tmp_path):
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = False, []
    observer.frames=[]
    observer.root_birth = Birth(1, 1, 1, 1, 'test-boot', 20000)
    observer.finished, observer.case, observer.serial = False, CASES[0], 0
    observer.meta = {'mounts': {}, 'owned': str(tmp_path), 'checkout': str(tmp_path / 'checkout')}
    observer.binding = {'entry': {'path': '/pinned/python', 'sha256': 'a' * 64}}
    observer.intents = {}
    home = tmp_path / 'case' / 'owner' / 'worker'
    home.mkdir(parents=True)
    cwd = str(home)
    native = '/pinned/python'
    expected = build_expected(CASES[0], native, 'a' * 64, (native, str(home.parent / 'fake-app-server'), 'app-server'), tuple(sorted({'HOME': cwd, 'CODEX_HOME': str(home / 'codex'), 'TMPDIR': str(home / 'tmp'),
                      'PATH': '/usr/bin:/bin'}.items())), cwd, 'python-script', BACKEND_PIN)
    request = operands(expected)
    actor = {'birth': observer.root_birth, 'role': 'root'}
    return observer, actor, request


@pytest.mark.parametrize('mutation', ('case', 'site', 'script', 'argv', 'environment', 'cwd', 'owner', 'runtime'))
def test_host_reconstructs_exact_original_launch(tmp_path, mutation):
    observer, actor, request = backend_request(tmp_path)
    changed = deepcopy(request)
    if mutation == 'case':
        changed['case'] = CASES[1]
    elif mutation == 'site':
        changed['source_line'] = 507
    elif mutation == 'script':
        changed['script_sha256'] = 'b' * 64
    elif mutation == 'argv':
        changed['argv'].append('--foreign')
    elif mutation == 'environment':
        changed['environment']['UNDECLARED']='1'
    elif mutation == 'cwd':
        changed['cwd'] = str(tmp_path)
    elif mutation == 'owner':
        changed['owner'] = 'borrowed-source-name'
    else:
        changed['executable_sha256'] = 'b' * 64
    with pytest.raises(Refused):
        proposal(observer, actor, changed)
    assert not observer.intents
    assert proposal(observer, actor, request)['ok'] is True
    assert len(observer.intents) == 1
    with pytest.raises(Refused):
        proposal(observer, actor, request)








@pytest.mark.parametrize('role', ['root', 'fixed-inline', 'mcp', 'desktop', 'archive-checker', 'session-adapter'])
@pytest.mark.parametrize('sig', [signal.SIGTERM, 15])
def test_original_signal_enum_is_normalized_without_signal_substitution(monkeypatch, sig, role):
    import subprocess
    checked, requested = [], []
    def check(pid, number, group):
        checked.append((pid, number, group))
        assert type(number) is int and number == 15
    def request(kind, payload):
        requested.append((kind, payload))
        return {'ok': True, 'live': False}  # Actual terminal evidence forbids delivery.
    policy = SimpleNamespace(profile={'role': role}, case='foreign', local=threading.local(),
        children={123: {'token': 'owned'}},
        client=SimpleNamespace(request=request))
    def refuse(code):
        raise Refused(code)
    policy.refuse = refuse
    for obj, name in ((subprocess.Popen, '__init__'), (subprocess.Popen, 'communicate'), (subprocess._del_safe, 'waitpid'), (os, 'waitpid'), (os, 'kill'), (os, 'killpg')):
        monkeypatch.setattr(obj, name, getattr(obj, name))  # Register restoration before installation.
    Policy.install_process_hooks(policy)
    with pytest.raises(ProcessLookupError):
        os.killpg(123, sig)
    assert checked == []
    assert type(requested[0][1]['signal']) is int
    assert requested == [('custody_signal', {'pid': 123, 'child_token': 'owned', 'signal': 15, 'group': True})]
    with pytest.raises(Refused, match='nonnumeric'):
        os.killpg(123, True)
    assert len(requested) == 1
    with pytest.raises(Refused, match='outside owned children'):
        os.kill(124, signal.SIGTERM)
    assert len(requested) == 1


def test_resumed_signal_uses_separate_observer_admission_without_fabricated_popen(monkeypatch):
    import subprocess
    from composed_cases import PARITY
    requested=[]
    def refuse(code):
        raise Refused(code)
    policy=SimpleNamespace(profile={'role':'mcp'},case=PARITY[0],local=threading.local(),children={},
        refuse=refuse,client=SimpleNamespace(request=lambda kind,payload:requested.append((kind,payload)) or {'ok':True,'live':False}))
    for obj,name in ((subprocess,'run'),(subprocess.Popen,'__init__'),(os,'kill'),(os,'killpg')):
        monkeypatch.setattr(obj,name,getattr(obj,name))
    Policy.install_process_hooks(policy)
    with pytest.raises(ProcessLookupError):
        os.killpg(123,signal.SIGTERM)
    assert requested==[('resumed-signal',{'pid':123,'signal':15,'group':True})]
    assert policy.children=={}


@pytest.mark.skipif(sys.platform != 'linux', reason='actual Linux subreaper ownership')
def test_adopted_parent_drain_rechecks_newly_adopted_descendant():
    import ctypes
    import select
    read, write = os.pipe()
    driver = os.fork()
    if driver == 0:
        os.close(read)
        try:
            assert not source_host.children()
            assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
            ready_read, ready_write = os.pipe()
            parent = os.fork()
            if parent == 0:
                os.close(ready_read)
                descendant = os.fork()
                if descendant == 0:
                    os.write(ready_write, b'R')
                # Finite failure fallback even if the dedicated driver dies.
                __import__('time').sleep(8)
                os._exit(125)
            os.close(ready_write)
            assert select.select([ready_read], [], [], 2)[0] and os.read(ready_read, 1) == b'R'
            os.close(ready_read)
            assert source_host.children() == [parent]
            rows = []
            source_host.drain_owned(rows)
            assert len(rows) == 2 and rows[0]['pid'] == parent
            assert all(row['actual_wait'] == signal.SIGKILL and row['original_parent_wait_proven'] is False for row in rows)
            assert not source_host.children()
            os.write(write, b'OK')
        except BaseException:
            os._exit(125)
        os._exit(0)
    os.close(write)
    try:
        assert select.select([read], [], [], 7)[0] and os.read(read, 3) == b'OK'
        assert source_host.settle(driver) == 0
    finally:
        source_host.settle(driver, terminate=True)
        os.close(read)


@pytest.mark.skipif(sys.platform != 'linux', reason='actual wait and Unix peer birth')
def test_poisoned_cleanup_retains_actual_parent_wait_without_restoring_authority():
    import socket
    import control_transport as transport
    from linux_observation import process_identity
    from process_ledger import Ledger
    ledger = Ledger('cleanup-nonce')
    root_id = process_identity(os.getpid())
    birth = Birth.read(root_id)
    ledger.kernel(0, {'kind': 'kernel_root', 'identity': root_id})
    ledger.register(birth, 'root-token', (('pin', 'a' * 64),), case='case', command_class='bootstrap-root', expected_generation=1)
    ledger.process(birth).generation = 1  # Reducer epoch setup, not kernel-exec evidence.
    held_read, held_write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(held_write)
        os.read(held_read, 1)
        os._exit(17)
    os.close(held_read)
    try:
        child_id = process_identity(child)
        child_birth = Birth.read(child_id)
        ledger.kernel(1, {'kind': 'kernel_child', 'parent': birth.pid, 'child': child, 'event': 1, 'identity': child_id})
        ledger.register(child_birth, 'child-token', (('pin', 'a' * 64),), case='case', command_class='child')
        os.close(held_write)
        held_write = -1
        actual, raw = os.waitpid(child, 0)
        assert actual == child and raw == 17 << 8
        observer = object.__new__(Observer)
        observer.full, observer.outcomes = False, []
        observer.frames=[]
        observer.root_birth, observer.root, observer.ledger, observer.finished = birth, birth.pid, ledger, False
        observer.actors = {child: {'birth': child_birth, 'body_ready': True}}
        payload = {'pid': child, 'requested_pid': child, 'child_token': 'child-token',
                   'raw_status': raw, 'numeric_returncode': os.waitstatus_to_exitcode(raw), 'options': 0}
        request = {'pid': birth.pid, 'nonce': ledger.nonce, 'token': 'root-token', 'generation': 1,
                   'id': 'a' * 32, 'kind': 'drain_child', 'payload': payload}
        left, right = socket.socketpair()
        try:
            frame = transport.Frame(right, transport.REQUEST_LIMIT)
            frame.capture(ledger, birth, 'root-token', os.getgid())
            left.sendall(transport.encode(request, transport.REQUEST_LIMIT))
            assert frame.read() == request
            admission = transport.Admission(ledger, frozenset({'launch-proposal'}))
            with pytest.raises(Refused):
                admission.admit(frame)
            assert not ledger.reaped(child_birth, 'child-token')  # A Python receipt cannot invent kernel joins.
            with pytest.raises(Refused,match='source guard refusal'):
                observer.dispatch({'birth':birth,'role':'root'},{'kind':'guard-refusal','payload':{'code':'preserved source refusal'}})
        finally:
            left.close()
            right.close()
    finally:
        if held_write >= 0:
            os.close(held_write)
        source_host.settle(child, terminate=True)


def test_caught_cleanup_signal_refusal_stays_poisoned(monkeypatch):
    import subprocess
    calls = []
    policy = object.__new__(Policy)
    policy.profile, policy.local, policy.poison = {'role': 'root'}, threading.local(), False
    def reject(*args):
        raise Refused('original cleanup caller')
    def request(kind,payload):
        if kind=='custody_signal':
            raise Refused('observer refused signal')
        calls.append((kind,payload))
    policy.client = SimpleNamespace(request=request)
    policy.children = {123: {'token': 'owned'}}
    for obj, name in ((subprocess.Popen, '__init__'), (subprocess.Popen, 'communicate'), (subprocess._del_safe, 'waitpid'), (os, 'waitpid'), (os, 'kill'), (os, 'killpg')):
        monkeypatch.setattr(obj, name, getattr(obj, name))
    Policy.install_process_hooks(policy)
    with pytest.raises(Refused, match='cleanup signal refused'):
        os.kill(123, signal.SIGTERM)
    assert policy.poison is True
    assert calls == [('guard-refusal', {'code': 'source cleanup signal refused'})]


def test_root_completion_seal_is_bounded_and_requires_all_ordered_completions():
    from source_profile import case_seal
    from control_transport import encode, REQUEST_LIMIT
    cases = tuple('tests/test_large.py::test_case[' + str(index) + ']' for index in range(5077))
    seal = case_seal(cases)
    assert len(encode(seal, REQUEST_LIMIT)) < 128
    observer = object.__new__(Observer)
    observer.full, observer.outcomes = False, []
    observer.frames=[]
    observer.root_birth = Birth(1,1,1,1,'boot',20000)
    observer.finished, observer.case = False, None
    observer.cases, observer.completed = cases, list(cases)
    actor = dict(birth=observer.root_birth,role='root')
    for changed in ({**seal,'count':True},{**seal,'count':5076},{**seal,'cases_sha256':'0'*64}):
        with pytest.raises(Refused, match='completion incomplete'):
            observer.dispatch(actor, {'kind':'root-finish','payload':changed})
    observer.completed = list(reversed(cases))
    with pytest.raises(Refused, match='completion incomplete'):
        observer.dispatch(actor, {'kind':'root-finish','payload':seal})
    observer.completed = list(cases)
    assert observer.dispatch(actor, {'kind':'root-finish','payload':seal}) == {'ok':True}
    assert observer.finished




@pytest.mark.parametrize('consumed', [False, True])
def test_constructor_window_serializes_before_second_intent(tmp_path, consumed):
    observer, actor, request = backend_request(tmp_path)
    observer.intents[10] = {'parent': actor['birth'], 'consumed': consumed, 'case': observer.case, 'role': 'acp'}
    if not consumed:
        assert proposal(observer, actor, request) is None
        assert len(observer.intents) == 1 and observer.serial == 0
    else:
        assert proposal(observer, actor, request)['ok'] is True
        assert len(observer.intents) == 2


@pytest.mark.parametrize('field,value', [
    ('executable', '/runtime/other'), ('executable_sha256', 'b' * 64),
    ('argv', ['/pinned/python', '-c', "print('different')"]),
    ('argv', ['/pinned/python', '-c', "print('finite')", 'extra']),
    ('environment', [['MODE', 'native']]),
    ('environment', [['MODE', 'controlled'], ['EXTRA', 'value']]),
    ('environment', [['MODE', 'controlled'], ['MODE', 'controlled']]),
    ('cwd', '/other'), ('payload_kind', 'native'), ('payload_sha256', 'c' * 64),
    ('argv', ['/pinned/python', '-c', ["print('finite')"]]),
    ('environment', [['MODE', False]]),
])
def test_literal_field_mutations_reach_real_observer_refusal(tmp_path, field, value):
    observer, actor, request = backend_request(tmp_path)
    request[field] = value
    with pytest.raises(Refused):
        proposal(observer, actor, request)
    assert not observer.intents


@pytest.mark.parametrize('body', ['pass', "print('different')"])
def test_consistent_inline_body_and_hash_substitution_refuses_at_real_admission(tmp_path, body):
    import hashlib
    from pathlib import Path
    from inline_leaves import STARTUP
    from test_cleanup_scenario_oracle import inline_input as expected

    observer, actor, _ = backend_request(tmp_path)
    observer.case = next(iter(STARTUP))
    value = expected(observer.case, '/pinned/python', 'a'*64,
        Path(observer.meta['checkout']), observer.meta_environment())
    request = operands(value)
    changed = deepcopy(request)
    changed['argv'][-1] = body
    matching_hash = hashlib.sha256(body.encode()).hexdigest()
    assert matching_hash != value.payload_sha256
    for candidate in (changed, {**changed, 'payload_sha256': matching_hash}):
        with pytest.raises(Refused):
            proposal(observer, actor, candidate)
    assert not observer.intents
    assert proposal(observer, actor, request)['ok'] is True
    assert len(observer.intents) == 1


def test_retired_launch_intent_has_no_control_or_dispatch_authority(tmp_path):
    from source_profile import METHODS
    observer,actor,request=backend_request(tmp_path)
    assert 'launch-intent' not in METHODS
    with pytest.raises(Refused):
        observer.dispatch(actor,{'kind':'launch-intent','payload':request})
    assert not observer.intents


@pytest.mark.parametrize('mutation',('unconsumed','before-exec','unregistered','wrong-token','wrong-case','registered','exited'))
def test_constructor_receipt_is_not_execution_evidence(mutation):
    from types import SimpleNamespace
    from source_observer import Observer
    observer=object.__new__(Observer)
    birth=object()
    intent={'birth':birth,'token':'ticket','case':'case','consumed':mutation!='unconsumed'}
    process=SimpleNamespace(token='other' if mutation=='wrong-token' else 'ticket',
        case='other' if mutation=='wrong-case' else 'case',generation=0 if mutation=='before-exec' else 1,
        registered_generation=0 if mutation=='unregistered' else 1,exit=(1,0) if mutation=='exited' else None)
    observer.ledger=SimpleNamespace(process=lambda selected:process if selected is birth else pytest.fail('foreign birth'))
    assert observer.executed(intent)==(mutation in ('registered','exited'))


@pytest.mark.parametrize('namespace',('mnt','net','pid'))
def test_observer_refuses_a_foreign_namespace_before_consuming_any_launch(monkeypatch,namespace):
    import source_observer
    observer=object.__new__(Observer)
    observer.meta={'network_namespace':'expected-net','pid_namespace':'expected-pid'}
    observer.consume=lambda trace:pytest.fail('foreign namespace reached launch consumption')
    identities={'mnt':'expected-mount','net':'expected-net','pid':'expected-pid'}
    identities[namespace]='foreign'
    monkeypatch.setattr(source_observer,'process_identity',lambda pid:{'namespaces':identities})
    monkeypatch.setattr(source_observer.os,'readlink',lambda path:'expected-mount')
    assert observer.resolve(None,123,'/native',[],{},'/owned') is False


# Ledger event-order contract V3 + amendment 1: case-finish and final-source settlement.

CASE_ID = 'case[one]'


def finishing_observer(ledger, root):
    observer = object.__new__(Observer)
    observer.full, observer.outcomes, observer.frames = False, [], []
    observer.root_birth, observer.finished, observer.case = root, False, CASE_ID
    observer.cases, observer.completed, observer.cohort_observations = (CASE_ID,), [], []
    observer.ledger, observer.intents, observer.actors = ledger, {}, {}
    return observer


def ordinary_actor(observer, birth, token):
    intent = {'ticket': len(observer.intents) + 1, 'birth': birth, 'token': token, 'case': CASE_ID,
              'role': 'sleep', 'consumed': True}
    observer.intents[intent['ticket']] = intent
    observer.actors[birth.pid] = {'birth': birth, 'role': 'sleep', 'case': CASE_ID, 'token': token,
                                  'body_ready': False, 'signals': set(), 'kernel_admitted': True, 'intent': intent}


def waived_actor(observer, birth, monkeypatch):
    """Synthetic stand-in for an approved crash pair: the waiver is patched, not observed."""
    import cohort_controller
    monkeypatch.setattr(cohort_controller, 'CASES', (CASE_ID,))
    monkeypatch.setattr(cohort_controller, 'closeout',
                        lambda host, children: {value['birth'] for value in children if value['role'] == 'backend'})
    observer.actors[birth.pid] = {'birth': birth, 'role': 'backend', 'case': CASE_ID, 'token': str(birth.pid),
                                  'body_ready': True, 'signals': set()}


def finish(observer):
    return observer.dispatch({'birth': observer.root_birth, 'role': 'root'},
                             {'kind': 'case-finish', 'payload': {'case': CASE_ID}})


def closed_leader():
    ledger, root, leader = ledger_rows.setup()
    ledger_rows.terminal(ledger, leader, 0)
    ledger_rows.wait4(ledger, root, leader, 0)
    return ledger, root, leader


def assert_case_refused(observer, text):
    with pytest.raises(Refused, match='^' + text + '$'):
        finish(observer)
    assert observer.completed == [] and observer.outcomes == [] and observer.case == CASE_ID


def synthetic_member_debt(ledger, member):
    process = ledger.process(member)  # synthetic state, defensive only
    process.exit, process.terminal = (90, 0), (91, 256, 1)


def test_case_finish_leader_actor_behaviour_unchanged():
    ledger, root, leader = ledger_rows.setup()
    member = ledger_rows.thread(ledger, 102)
    ledger_rows.terminal(ledger, member, 0)
    ledger_rows.terminal(ledger, leader, 0)
    ledger_rows.wait4(ledger, root, leader, 0)
    observer = finishing_observer(ledger, root)
    ordinary_actor(observer, leader, 'child-token')
    finish(observer)
    assert observer.completed == [CASE_ID] and observer.case is None


def test_case_finish_root_or_unrelated_debt_left_to_final():
    ledger, root, leader = ledger_rows.setup()
    root_thread = Birth.read(ledger_rows.identity(102, 99, tgid=100))
    ledger_rows.emit(ledger, 'kernel_child', parent=100, child=102, event=3, identity=ledger_rows.identity(102, 99, tgid=100))
    ledger_rows.emit(ledger, 'kernel_child', parent=100, child=103, event=1, identity=ledger_rows.identity(103, 100))
    unrelated = ledger_rows.thread(ledger, 104, creator=103, tgid=103)
    ledger_rows.emit(ledger, 'kernel_exit', pid=102, raw=256)
    ledger_rows.reap(ledger, root_thread, 0)
    ledger_rows.emit(ledger, 'kernel_exit', pid=104, raw=0)
    ledger_rows.reap(ledger, unrelated, 256)
    ledger_rows.terminal(ledger, leader, 0)
    ledger_rows.wait4(ledger, root, leader, 0)
    observer = finishing_observer(ledger, root)
    ordinary_actor(observer, leader, 'child-token')
    finish(observer)
    assert observer.completed == [CASE_ID] and not ledger.final_settled()
    ledger_rows.emit(ledger, 'kernel_exit', pid=100, raw=0)
    ledger_rows.emit(ledger, 'kernel_exit', pid=103, raw=256)
    assert ledger.final_settled()


def test_case_finish_synthetic_waived_debt_refuses(monkeypatch):
    ledger, root, leader = ledger_rows.setup()
    member = ledger_rows.thread(ledger, 102)
    ledger_rows.terminal(ledger, leader, 0)
    synthetic_member_debt(ledger, member)
    observer = finishing_observer(ledger, root)
    waived_actor(observer, leader, monkeypatch)
    assert_case_refused(observer, 'source case group status unresolved')


def test_case_finish_actor_self_debt_refuses(monkeypatch):
    ledger, root, leader = ledger_rows.setup()
    member = ledger_rows.thread(ledger, 102)
    ledger_rows.emit(ledger, 'kernel_exit', pid=102, raw=0)
    ledger_rows.reap(ledger, member, 256)
    observer = finishing_observer(ledger, root)
    waived_actor(observer, member, monkeypatch)
    assert_case_refused(observer, 'source case actor group status unresolved')


def test_case_finish_actor_self_supported_terminal_passes(monkeypatch):
    ledger, root, leader = ledger_rows.setup()
    member = ledger_rows.thread(ledger, 102)
    ledger_rows.terminal(ledger, member, 0)
    observer = finishing_observer(ledger, root)
    waived_actor(observer, member, monkeypatch)
    finish(observer)
    assert observer.completed == [CASE_ID]


def test_case_finish_self_check_precedes_member_check(monkeypatch):
    # Amendment 1 (A2): one actor's own debt and another leader actor's member debt.
    ledger, root, leader = ledger_rows.setup()
    member = ledger_rows.thread(ledger, 102)
    ledger_rows.emit(ledger, 'kernel_exit', pid=102, raw=0)
    ledger_rows.reap(ledger, member, 256)
    ledger_rows.emit(ledger, 'kernel_child', parent=100, child=103, event=1, identity=ledger_rows.identity(103, 100))
    other = Birth.read(ledger_rows.identity(103, 100))
    other_member = ledger_rows.thread(ledger, 104, creator=103, tgid=103)
    ledger_rows.terminal(ledger, other, 0)
    synthetic_member_debt(ledger, other_member)
    observer = finishing_observer(ledger, root)
    waived_actor(observer, other, monkeypatch)
    waived_actor(observer, member, monkeypatch)
    assert ledger.debt_of(member) and not ledger.settled((other,))
    assert_case_refused(observer, 'source case actor group status unresolved')


def final_worker(monkeypatch, tmp_path, *, full, debt):
    """Synthetic host: no fork, ptrace or launch; the trace only reports a clean return."""
    import json
    import compartment
    import full_launch
    import full_source
    import console_entries
    import linux_trace
    import source_observer
    ledger, root, leader = ledger_rows.setup()
    member = ledger_rows.thread(ledger, 102)
    ledger_rows.emit(ledger, 'kernel_exit', pid=102, raw=0)
    ledger_rows.reap(ledger, member, 256)
    if not debt:
        ledger_rows.terminal(ledger, leader, 256)
    entry = tmp_path / 'entry'
    entry.write_bytes(b'entry')
    cases = tmp_path / 'cases.json'
    cases.write_bytes(b'{}')
    import hashlib
    metadata = {'cases': {'path': str(cases), 'sha256': hashlib.sha256(b'{}').hexdigest()} if full else [],
                'checkout': str(tmp_path)}

    class Trace:
        def __init__(self, *args, **kwargs):
            self.records, self.poison = [], []

        def run(self):
            return {'root_parent_wait_raw': 0, 'poison': []}

    class FinishedObserver:
        def __init__(self, binding, value, child, output):
            self.full, self.meta, self.ledger = full, value, ledger
            self.finished, self.completed, self.cases, self.frames, self.intents = True, [], (), [], {}
            self.controls, self.outcomes, self.cohort_observations, self.adoptions, self.plan_records = [], [], [], [], []
            self.output = b''

        def consume(self, *args):
            return None

        tick = before_exit = resolve = validate_wait = consume

        def close(self):
            return None

    held = []
    original_pipe = os.pipe

    def pipe():
        pair = original_pipe()
        held.append(pair)
        if len(held) == 2:
            os.write(pair[1], b'R')
        return pair

    monkeypatch.setattr(source_host, 'isolate', lambda value, support, output: value)
    monkeypatch.setattr(compartment, 'credentials', lambda uid: None)
    monkeypatch.setattr(linux_trace, 'OwnedTrace', Trace)
    monkeypatch.setattr(source_observer, 'Observer', FinishedObserver)
    monkeypatch.setattr(full_launch, 'finished', lambda observer: None)
    monkeypatch.setattr(full_source, 'environment', lambda value: {})
    monkeypatch.setattr(console_entries, 'standalone_environment', lambda value: {})
    forks = []

    def fork():
        forks.append(True)
        return 4242

    def forbidden(*args, **kwargs):
        pytest.fail('synthetic host reached a process effect')

    import subprocess
    monkeypatch.setattr(os, 'pipe', pipe)
    monkeypatch.setattr(os, 'fork', fork)
    for name in ('execve', 'execv', 'posix_spawn', 'system', 'kill', 'killpg', 'waitpid'):
        monkeypatch.setattr(os, name, forbidden)
    monkeypatch.setattr(subprocess.Popen, '__init__', forbidden)
    binding = {'support': '/support', 'entry': {'path': str(entry)}, 'checkout': '/checkout'}
    try:
        if debt:
            with pytest.raises(RuntimeError, match='^original source group status unresolved$'):
                source_host.worker(binding, metadata, tmp_path)
        else:
            source_host.worker(binding, metadata, tmp_path)
    finally:
        for descriptor in (held[0][1], held[2][0]):  # start_write and output_read stay with the trace
            os.close(descriptor)
    assert len(forks) == 1
    return json.loads((tmp_path / 'source-result.json').read_text())


@pytest.mark.parametrize('full', (True, False), ids=('full', 'nonfull'))
def test_worker_final_group_status_debt_refuses_source(monkeypatch, tmp_path, full):
    record = final_worker(monkeypatch, tmp_path, full=full, debt=True)
    assert 'original source group status unresolved' in record['failure']
    if full:
        assert record['source_checkpoint_ready'] is False


@pytest.mark.parametrize('full', (True, False), ids=('full', 'nonfull'))
def test_worker_final_group_status_clean_passes_to_existing_checks(monkeypatch, tmp_path, full):
    record = final_worker(monkeypatch, tmp_path, full=full, debt=False)
    assert record['failure'] is None
    if full:
        assert record['source_checkpoint_ready'] is True
