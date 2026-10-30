"""Finite spawn transport controls; synthetic records never prove native custody."""

from copy import deepcopy
import hashlib
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from multiprocess_entry import expected, proposal
CASES=tuple('tests/test_multiprocess_resource_ownership.py::test_original_child_status_is_preserved['+str(status)+']' for status in (0,17))
TARGET=['tests.test_multiprocess_resource_ownership','_exit_with_status']
IPC_CASES=tuple('tests/test_multiprocess_resource_ownership.py::'+name for name in (
    'test_joined_spawn_queue_event_and_value_close_before_summary',
    'test_live_child_refusal_preserves_original_error_and_does_not_kill'))
TRACKER_CASES=tuple('tests/test_multiprocess_resource_ownership.py::'+name for name in (
    'test_parent_feeder_and_both_pipe_endpoints_are_settled',
    'test_altered_stdlib_stop_is_refused_before_launch'))

NATIVE = "/native/python"
TRACK = "from multiprocessing.resource_tracker import main;main(5)"
SPAWN = "from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=6, pipe_handle=8)"


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("kind", ["tracker", "spawn"])
def test_exact_entry_and_payload_are_closed(case, kind):
    argv = [NATIVE, "-S", "-I", "-c", TRACK if kind == "tracker" else SPAWN]
    if kind == "spawn":
        argv.append("--multiprocessing-fork")
    passfds = [2, 5] if kind == "tracker" else [6, 8, 10]
    value, role, fds = expected(
        case, argv, passfds, NATIVE, "a" * 64, "/source", {}
    )
    assert (
        value.argv == tuple(argv)
        and value.payload_sha256 == hashlib.sha256(argv[4].encode()).hexdigest()
    )
    assert role == ("mp-tracker" if kind == "tracker" else "mp-child")
    assert fds == ([5] if kind == "tracker" else [6, 8, 10])


@pytest.mark.parametrize(
    "mutation",
    [
        "case",
        "code",
        "flags",
        "tail",
        "duplicate",
        "missing",
        "boolean",
        "negative",
        "range",
    ],
)
def test_unknown_or_mutated_spawn_entry_refuses(mutation):
    case = CASES[0]
    argv = [NATIVE, "-S", "-I", "-c", SPAWN, "--multiprocessing-fork"]
    fds = [6, 8, 10]
    if mutation == "case":
        case = "foreign"
    elif mutation == "code":
        argv[4] += '; print("foreign")'
    elif mutation == "flags":
        argv[1] = "-E"
    elif mutation == "tail":
        argv[-1] = "foreign"
    elif mutation == "duplicate":
        fds[-1] = 6
    elif mutation == "missing":
        fds.remove(8)
    elif mutation == "boolean":
        fds[-1] = True
    elif mutation == "negative":
        fds[-1] = -1
    else:
        fds[-1] = 1025
    with pytest.raises(Refused):
        expected(case, argv, fds, NATIVE, "a" * 64, "/source", {})


@pytest.fixture
def tracker(monkeypatch):
    import multiprocess_entry as entry

    calls = []
    actor = {"birth": SimpleNamespace(pid=100)}
    environment = {
        "PATH": "/bin:/usr/bin",
        "PYTEST_VERSION": "9.0.2",
        "PYTEST_CURRENT_TEST": CASES[0] + " (call)",
    }
    raw = {
        "case": CASES[0],
        "executable": NATIVE,
        "argv": [NATIVE, "-S", "-I", "-c", TRACK],
        "passfds": [2, 5],
        "cwd": "/source",
        "environment": environment,
    }
    host = SimpleNamespace(
        case=CASES[0],
        meta={"checkout": "/source"},
        binding={"entry": {"path": NATIVE, "sha256": "a" * 64}},
        root_only=lambda value: None,
        executed=lambda row:True,
        meta_environment=lambda: {"PATH": "/bin:/usr/bin"},
        intents={},
    )

    def admit(*args, **kwargs):
        calls.append((args, kwargs))
        host.intents[1] = {
            "case": host.case,
            "role": "mp-tracker",
            "inherited": kwargs["inherited"],
        }
        return {"ok": True, "ticket": 1, "token": "t"}

    host.admit_launch = admit
    monkeypatch.setattr(entry, "fd_record", lambda pid, fd: [fd, 10, 20, 0])
    return host, actor, raw, calls


def test_tracker_requires_original_pipe_and_mints_only_guarded_entry(tracker):
    host, actor, raw, calls = tracker
    answer = proposal(host, actor, raw)
    assert answer["translated"] == [NATIVE, "-I", "-S", "-c", TRACK]
    assert calls[0][1]["inherited"] == [[5, 10, 20, 0]]
    assert calls[0][1]["maximum"] == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("case", "foreign"),
        ("executable", "/foreign"),
        ("cwd", "/foreign"),
        ("environment", {}),
        ("passfds", [5]),
    ],
)
def test_tracker_operand_mutations_never_mint_intent(tracker, field, value):
    host, actor, raw, calls = tracker
    raw = deepcopy(raw)
    raw[field] = value
    with pytest.raises(Refused):
        proposal(host, actor, raw)
    assert not calls


def test_wrong_pipe_direction_refuses_before_intent(tracker, monkeypatch):
    import multiprocess_entry as entry

    host, actor, raw, calls = tracker
    monkeypatch.setattr(entry, "fd_record", lambda pid, fd: [fd, 10, 20, 1])
    with pytest.raises(Refused, match="direction"):
        proposal(host, actor, raw)
    assert not calls


def test_unknown_callback_operands_are_refused_without_comparison():
    class Trap:
        def __eq__(self, other):
            pytest.fail("callback")

    with pytest.raises(Refused):
        expected(
            CASES[0],
            [NATIVE, "-S", "-I", "-c", Trap()],
            [2, 5],
            NATIVE,
            "a" * 64,
            "/source",
            {},
        )


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "sentinel-read",
        "sentinel-bootstrap",
        "sentinel-tracker",
        "tracker-generation",
        "tracker-birth",
        "not-ready",
    ],
)
def test_spawn_requires_distinct_bootstrap_reader_sentinel_writer_and_live_tracker(
    monkeypatch, mutation
):
    import multiprocess_entry as entry
    import linux_observation
    from process_ledger import Birth

    identity = {
        "pid": 101,
        "tgid": 101,
        "ppid": 100,
        "start_ticks": 10100,
        "boot_id": "boot",
        "uids": [20000] * 4,
    }
    birth = Birth.read(identity)
    calls = []
    from pathlib import Path
    import stat
    monkeypatch.setattr(Path, "stat", lambda path: SimpleNamespace(st_mode=stat.S_IFIFO))
    actor = {"birth": SimpleNamespace(pid=100)}
    rows = {
        (100, 6): [6, 10, 20, 1],
        (100, 8): [8, 10, 30, 0],
        (100, 10): [10, 10, 40, 1],
        (101, 5): [5, 10, 20, 0],
    }
    if mutation == "sentinel-read":
        rows[100, 10][-1] = 0
    elif mutation == "sentinel-bootstrap":
        rows[100, 10][2] = 30
    elif mutation == "sentinel-tracker":
        rows[100, 10][2] = 20
    elif mutation == "tracker-generation":
        rows[101, 5][2] = 99
    monkeypatch.setattr(entry, "fd_record", lambda pid, fd: rows[pid, fd])
    monkeypatch.setattr(
        linux_observation,
        "process_identity",
        lambda pid: {**identity, **({"start_ticks": 999} if mutation == "tracker-birth" else {})},
    )
    host = SimpleNamespace(
        case=CASES[0],
        meta={"checkout": "/source"},
        binding={"entry": {"path": NATIVE, "sha256": "a" * 64}},
        root_only=lambda value: None,
        executed=lambda row:True,
        meta_environment=lambda: {"PATH": "/bin:/usr/bin"},
        intents={
            1: {
                "case": CASES[0],
                "role": "mp-tracker",
                "pid": 101,
                "consumed": True,
                "inherited": [[5, 10, 20, 0]],
                "tracker_read": [5, 10, 20, 0],
            }
        },
        actors={101: {"birth": birth, "returned": True, "body_ready": True}},
        ledger=SimpleNamespace(process=lambda value: SimpleNamespace(exit=None, terminal=None)),
    )

    def admit(*args, **kwargs):
        calls.append((args, kwargs))
        host.intents[2] = {}
        return {"ok": True, "ticket": 2, "token": "child"}

    host.admit_launch = admit
    raw = {
        "case": CASES[0],
        "executable": NATIVE,
        "argv": [NATIVE, "-S", "-I", "-c", SPAWN, "--multiprocessing-fork"],
        "passfds": [6, 8, 10],
        "cwd": "/source",
        "environment": {
            "PATH": "/bin:/usr/bin",
            "PYTEST_VERSION": "9.0.2",
            "PYTEST_CURRENT_TEST": CASES[0] + " (call)",
        },
    }
    if mutation == "not-ready":
        host.actors[101]["body_ready"] = False
        assert proposal(host, actor, raw) is None
        assert not calls
    elif mutation is None:
        assert proposal(host, actor, raw)["token"] == "child"
        assert calls[0][1]["inherited"] == [rows[100, fd] for fd in (6, 8, 10)]
        assert calls[0][1]["maximum"] == 5
    else:
        with pytest.raises(Refused):
            proposal(host, actor, raw)
        assert not calls


@pytest.mark.parametrize("mutation", [None, "kcmp", "linked", "uid", "mode", "inode", "access"])
def test_tracker_capture_stderr_is_only_a_kernel_proven_anonymous_alias(monkeypatch, mutation):
    import os
    from pathlib import Path
    import stat
    import multiprocess_entry as entry

    original_stat, original_read = Path.stat, Path.read_text
    mode = stat.S_IFREG | (0o644 if mutation == "mode" else 0o600)

    def metadata(path, *args, **kwargs):
        if str(path) not in ("/proc/100/fd/8", "/proc/100/fd/2"):
            return original_stat(path, *args, **kwargs)
        inode = 99 if mutation == "inode" and path.name == "8" else 20
        return os.stat_result(
            (
                mode,
                inode,
                10,
                1 if mutation == "linked" else 0,
                500 if mutation == "uid" else 20000,
                20000,
                0,
                0,
                0,
                0,
            )
        )

    def reading(path, *args, **kwargs):
        if str(path) == "/proc/100/fdinfo/8":
            return (
                "flags:\t"
                + oct(os.O_CLOEXEC | (os.O_RDONLY if mutation == "access" else os.O_RDWR))[2:]
                + "\n"
            )
        return original_read(path, *args, **kwargs)

    calls = []

    def syscall(*args):
        calls.append(args)
        return -1 if mutation == "kcmp" else 0

    monkeypatch.setattr(Path, "stat", metadata)
    monkeypatch.setattr(Path, "read_text", reading)
    monkeypatch.setattr(
        entry.ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(syscall=syscall)
    )
    if mutation is None:
        assert entry.stderr_record(100, 8) == [8, 10, 20, os.O_RDWR]
        assert calls == [(312, 100, 100, 0, 8, 2)]
    else:
        with pytest.raises(Refused):
            entry.stderr_record(100, 8)


@pytest.mark.parametrize("case", TRACKER_CASES)
def test_tracker_only_cases_do_not_inherit_any_spawn_target_permission(case):
    from multiprocess_entry import expected

    import multiprocess_entry

    if case == multiprocess_entry.ZERO:
        with pytest.raises(Refused):
            expected(
                case,
                [
                    "/fixed/python",
                    "-S",
                    "-I",
                    "-c",
                    "from multiprocessing.resource_tracker import main;main(6)",
                ],
                [2, 6],
                "/fixed/python",
                "a" * 64,
                "/checkout",
                {},
            )
    else:
        value, role, inherited = expected(
            case,
            [
                "/fixed/python",
                "-S",
                "-I",
                "-c",
                "from multiprocessing.resource_tracker import main;main(6)",
            ],
            [2, 6],
            "/fixed/python",
            "a" * 64,
            "/checkout",
            {},
        )
        assert value.case == case and role == "mp-tracker" and inherited == [6]
    if case == multiprocess_entry.ZERO:
        with pytest.raises(Refused):
            expected(case, [NATIVE, '-S', '-I', '-c', SPAWN, '--multiprocessing-fork'],
                     [6, 8, 10], NATIVE, 'a'*64, '/source', {})


@pytest.mark.parametrize('count', range(3,8))
def test_closed_spawn_inventory_size_and_core_order(count):
    fds=[6,*range(11,11+count-3),8,10]
    argv=[NATIVE,'-S','-I','-c',SPAWN,'--multiprocessing-fork']
    assert expected(IPC_CASES[0],argv,fds,NATIVE,'a'*64,'/source',{})[1]=='mp-child'
    for changed in ([6,8], [6,11,12,13,14,15,8,10], [*fds[:-1],6], list(reversed(fds))):
        with pytest.raises(Refused):
            expected(IPC_CASES[0],argv,changed,NATIVE,'a'*64,'/source',{})


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "linked",
        "uid",
        "mode",
        "size",
        "access",
        "flags",
        "nofollow",
        "fifo",
        "directory",
        "socket",
    ],
)
def test_shared_arena_is_one_exact_anonymous_page(monkeypatch, mutation):
    import os
    import stat
    from pathlib import Path
    from multiprocess_entry import arena_record

    kinds = {"fifo": stat.S_IFIFO, "directory": stat.S_IFDIR, "socket": stat.S_IFSOCK}
    mode = kinds.get(mutation, stat.S_IFREG) | (0o644 if mutation == "mode" else 0o600)
    info = os.stat_result(
        (
            mode,
            60,
            1,
            1 if mutation == "linked" else 0,
            500 if mutation == "uid" else 20000,
            20000,
            8192 if mutation == "size" else 4096,
            0,
            0,
            0,
        )
    )
    flags = (
        (os.O_RDONLY if mutation == "access" else os.O_RDWR)
        | os.O_CLOEXEC
        | 0o100000
        | os.O_NOFOLLOW
    )
    if mutation == "flags":
        flags |= os.O_APPEND
    elif mutation == "nofollow":
        flags &= ~os.O_NOFOLLOW
    monkeypatch.setattr(Path, "stat", lambda self: info)
    monkeypatch.setattr(Path, "read_text", lambda self: "flags:\t" + oct(flags)[2:] + "\n")
    if mutation is None:
        assert arena_record(100, 13) == [13, 1, 60, os.O_RDWR, 4096]
    else:
        with pytest.raises(Refused, match="arena"):
            arena_record(100, 13)


def test_child_rechecks_arena_inode_instead_of_trusting_descriptor_number(monkeypatch):
    import multiprocess_entry as entry

    profile = {
        "inherited": [
            [6, 1, 20, 1],
            [11, 1, 50, 0],
            [12, 1, 50, 1],
            [13, 1, 60, 2, 4096],
            [8, 1, 30, 0],
            [10, 1, 40, 1],
        ],
        "role": "mp-child",
        "case": IPC_CASES[0],
    }
    monkeypatch.setattr(
        entry.os, "listdir", lambda path: [str(row[0]) for row in profile["inherited"]]
    )

    def record(pid, fd):
        row = next(row[:] for row in profile["inherited"] if row[0] == fd)
        if fd == 13:
            row[2] = 99
        return row

    monkeypatch.setattr(entry, "spawn_record", record)
    monkeypatch.setattr(entry.fcntl, "fcntl", lambda fd, op: 2 if fd == 13 else 0)
    with pytest.raises(Refused, match="generation"):
        entry.inherited(profile, {"pid": 200})


@pytest.mark.parametrize("case", __import__("test_multiprocess_catalogue").ROUTES)
def test_queue_family_targets_have_exact_counts_order_and_no_extra_permission(case):
    from test_multiprocess_catalogue import ROUTES

    entries = ROUTES[case]
    for target, spec in entries.items():
        fds = [6]
        rows = [[6, 1, 20, 1]]
        next_fd, inode = 11, 50
        for kind in spec.resources:
            if kind == "queue":
                fds.extend([next_fd, next_fd + 1])
                rows.extend([[next_fd, 1, inode, 0], [next_fd + 1, 1, inode, 1]])
                next_fd += 2
            else:
                fds.append(next_fd)
                rows.append([next_fd, 1, inode, 2, 900, inode+1, 1] if kind=='pipe' else [next_fd, 1, inode, 2, 4096])
                next_fd += 1
            inode += 10
        fds.extend([8, 10])
        rows.extend([[8, 1, 30, 0], [10, 1, 40, 1]])
        argv = [NATIVE, "-S", "-I", "-c", SPAWN, "--multiprocessing-fork"]
        assert (
            expected(case, argv, fds, NATIVE, "a" * 64, "/source", {})[1]
            == "mp-child"
        )
        with pytest.raises(Refused):
            expected(case, argv, [6,11,12,13,14,15,8,10], NATIVE, 'a'*64, '/source', {})
        if spec.resources:
            changed = [*fds]
            changed[1], changed[-2] = changed[-2], changed[1]
            with pytest.raises(Refused):
                expected(case, argv, changed, NATIVE, "a" * 64, "/source", {})



@pytest.mark.parametrize('case', [*CASES,*IPC_CASES])
def test_module_scope_uses_no_unattested_target_label(case):
    from multiprocess_entry import eligible
    assert eligible(case)
    assert not eligible('tests/test_unknown.py::test_case')


@pytest.mark.parametrize("status,signal", [(73, None), (-15, 15), (-15, None), (0, None)])
def test_spawn_completion_uses_exact_birth_token_case_and_actual_signal(status, signal):
    from source_observer import Observer
    from process_ledger import Birth

    identity = {
        "pid": 100,
        "tgid": 100,
        "ppid": 10,
        "start_ticks": 200,
        "boot_id": "boot",
        "uids": [20000] * 4,
    }
    birth = Birth.read(identity)
    old = Birth.read({**identity, "start_ticks": 100})
    actor = {
        "birth": birth,
        "token": "current",
        "case": "current-case",
        "role": "mp-child",
        "body_ready": True,
        "signals": set() if signal is None else {signal},
    }

    def row(generation, token="current", case="current-case"):
        return {
            "birth": generation,
            "pid": 100,
            "token": token,
            "case": case,
            "role": "mp-child",
            "consumed": True,
        }

    host = SimpleNamespace(
        intents={
            1: row(old),
            2: row(birth, token="foreign"),
            3: row(birth, case="other-case"),
            4: row(birth),
        },
        ledger=SimpleNamespace(process=lambda value: SimpleNamespace(terminal=(1, 0, status))),
    )
    host.intents[4]['ticket']=4
    actor['intent']=host.intents[4]
    assert Observer.completed_child(host, actor) is (status >= 0 or status == -15 and signal == 15)
    del host.intents[4]
    assert not Observer.completed_child(host, actor)


@pytest.mark.parametrize('role,maximum', [('mp-child',5),('mp-tracker',1)])
def test_process_ceiling_is_case_global_and_consumption_does_not_reset_it(role,maximum):
    from source_observer import Observer
    from launch_policy import build_expected
    value=build_expected(CASES[0],NATIVE,'a'*64,(NATIVE,'-c','pass'),(),'/source','python-command')
    host=SimpleNamespace(case=CASES[0],intents={},serial=0,root_birth='root')
    for index in range(maximum):
        answer=Observer.admit_launch(host,{'birth':'root'},value,role,list(value.argv),None,maximum=maximum)
        assert answer['ticket']==index+1
        host.intents[answer['ticket']]['consumed']=True
    with pytest.raises(Refused,match='independent launch reconstruction'):
        Observer.admit_launch(host,{'birth':'root'},value,role,list(value.argv),None,maximum=maximum)


@pytest.mark.parametrize('kind', ['fifo', 'socket'])
def test_spawn_rechecks_fd_kind_before_using_a_previous_pair_number(monkeypatch, kind):
    from pathlib import Path
    import stat
    import multiprocess_entry as entry
    import multiprocess_pipe

    from process_ledger import Birth
    actor = {'birth': Birth(100,100,1,100,'boot',20000)}
    host = SimpleNamespace(case='current', descriptors={(actor['birth'], 13): 'old-pair'})
    monkeypatch.setattr(Path, 'stat', lambda path: SimpleNamespace(
        st_mode=stat.S_IFIFO if kind=='fifo' else stat.S_IFSOCK))
    calls=[]
    monkeypatch.setattr(entry, 'spawn_record', lambda *args: calls.append('fifo') or [13,1,2,0])
    def socket_record(*args):
        calls.append('socket')
        raise Refused('unknown or stale socket has no pair authority')
    monkeypatch.setattr(multiprocess_pipe, 'parent_record', socket_record)
    if kind=='fifo':
        assert entry.inherited_record(host,actor,13)==[13,1,2,0]
    else:
        with pytest.raises(Refused, match='no pair authority'):
            entry.inherited_record(host,actor,13)
    assert calls==[kind]
