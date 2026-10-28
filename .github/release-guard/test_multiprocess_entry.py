"""Finite spawn transport controls; synthetic records never prove native custody."""

from copy import deepcopy
import hashlib
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from multiprocess_entry import CASES, TARGET, expected, proposal

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
        case, argv, passfds, None if kind == "tracker" else TARGET, NATIVE, "a" * 64, "/source", {}
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
        "target",
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
    target = list(TARGET)
    if mutation == "case":
        case = "foreign"
    elif mutation == "code":
        argv[4] += '; print("foreign")'
    elif mutation == "flags":
        argv[1] = "-E"
    elif mutation == "tail":
        argv[-1] = "foreign"
    elif mutation == "target":
        target[-1] = "foreign"
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
        expected(case, argv, fds, target, NATIVE, "a" * 64, "/source", {})


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
        "target": None,
        "cwd": "/source",
        "environment": environment,
    }
    host = SimpleNamespace(
        case=CASES[0],
        meta={"checkout": "/source"},
        binding={"entry": {"path": NATIVE, "sha256": "a" * 64}},
        root_only=lambda value: None,
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
    monkeypatch.setattr(entry, "counterpart", lambda pid, row: [[6, 10, 20, 1]])
    return host, actor, raw, calls


def test_tracker_requires_original_pipe_and_mints_only_guarded_entry(tracker):
    host, actor, raw, calls = tracker
    answer = proposal(host, actor, raw)
    assert answer["translated"] == [NATIVE, "-I", "-S", "-c", TRACK]
    assert calls[0][1]["inherited"] == [[5, 10, 20, 0]]
    host.intents[1] = {"case": CASES[0], "role": "mp-tracker"}
    with pytest.raises(Refused, match="quota"):
        proposal(host, actor, raw)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("case", "foreign"),
        ("executable", "/foreign"),
        ("cwd", "/foreign"),
        ("environment", {}),
        ("target", TARGET),
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
            None,
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
    monkeypatch.setattr(entry, "counterpart", lambda pid, row: [[99, row[1], row[2], 1 - row[3]]])
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
        return {"ok": True, "ticket": 2, "token": "child"}

    host.admit_launch = admit
    raw = {
        "case": CASES[0],
        "executable": NATIVE,
        "argv": [NATIVE, "-S", "-I", "-c", SPAWN, "--multiprocessing-fork"],
        "passfds": [6, 8, 10],
        "target": list(TARGET),
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


@pytest.mark.parametrize("case", __import__("multiprocess_entry").TRACKER_CASES)
def test_tracker_only_cases_do_not_inherit_any_spawn_target_permission(case):
    from multiprocess_entry import expected, TARGET

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
                None,
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
            None,
            "/fixed/python",
            "a" * 64,
            "/checkout",
            {},
        )
        assert value.case == case and role == "mp-tracker" and inherited == [6]
    with pytest.raises(Refused):
        expected(
            case,
            [
                "/fixed/python",
                "-S",
                "-I",
                "-c",
                "from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=6, pipe_handle=8)",
                "--multiprocessing-fork",
            ],
            [6, 8, 10],
            TARGET,
            "/fixed/python",
            "a" * 64,
            "/checkout",
            {},
        )


@pytest.mark.parametrize("case_index,count", [(0, 6), (1, 3)])
def test_ipc_cases_have_only_their_exact_spawn_inventory(case_index, count):
    from multiprocess_entry import IPC_CASES, TARGETS

    case = IPC_CASES[case_index]
    fds = [6, 11, 12, 13, 8, 10] if count == 6 else [6, 8, 10]
    argv = [NATIVE, "-S", "-I", "-c", SPAWN, "--multiprocessing-fork"]
    assert (
        expected(case, argv, fds, TARGETS[case], NATIVE, "a" * 64, "/source", {})[1] == "mp-child"
    )
    for changed in (fds[:-1], fds + [14], [*fds[:-1], fds[0]], list(reversed(fds))):
        with pytest.raises(Refused):
            expected(case, argv, changed, TARGETS[case], NATIVE, "a" * 64, "/source", {})
    with pytest.raises(Refused):
        expected(case, argv, fds, TARGET, NATIVE, "a" * 64, "/source", {})


@pytest.mark.parametrize(
    "mutation", [None, "direction", "pair", "alias", "order", "arena-order", "extra-arena"]
)
def test_queue_and_arena_are_distinct_exact_posix_resources(mutation):
    from multiprocess_entry import child_custody, IPC_CASES

    fds = [6, 11, 12, 13, 8, 10]
    rows = [
        [6, 1, 20, 1],
        [8, 1, 30, 0],
        [10, 1, 40, 1],
        [11, 1, 50, 0],
        [12, 1, 50, 1],
        [13, 1, 60, 2, 4096],
    ]
    if mutation == "direction":
        rows[3][3], rows[4][3] = 1, 0
    elif mutation == "pair":
        rows[4][2] = 51
    elif mutation == "alias":
        rows[3][2] = rows[4][2] = 20
    elif mutation == "order":
        fds[1], fds[2] = fds[2], fds[1]
    elif mutation == "arena-order":
        fds[1], fds[3] = fds[3], fds[1]
    elif mutation == "extra-arena":
        rows[3] = [11, 1, 50, 2, 4096]
    if mutation is None:
        child_custody(IPC_CASES[0], fds, 6, 8, rows)
        for case in (IPC_CASES[1], CASES[0]):
            with pytest.raises(Refused, match="extra"):
                child_custody(case, fds, 6, 8, rows)
    else:
        with pytest.raises(Refused):
            child_custody(IPC_CASES[0], fds, 6, 8, rows)


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
        "case": entry.IPC_CASES[0],
    }
    monkeypatch.setattr(
        entry.os, "listdir", lambda path: [str(row[0]) for row in profile["inherited"]]
    )

    def record(pid, fd, case):
        row = next(row[:] for row in profile["inherited"] if row[0] == fd)
        if fd == 13:
            row[2] = 99
        return row

    monkeypatch.setattr(entry, "spawn_record", record)
    monkeypatch.setattr(entry.fcntl, "fcntl", lambda fd, op: 2 if fd == 13 else 0)
    with pytest.raises(Refused, match="generation"):
        entry.inherited(profile, {"pid": 200})
