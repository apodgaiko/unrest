"""Finite Git forms retain scoped data operands without Python caller policing."""

from types import SimpleNamespace

import pytest

from content_manifest import Refused
from control_transport import finite
from git_commands import match as match_command
from test_git_vectors import build
from git_proposals import prepare
from git_sites import CASES

REPO = "/owned/pytest/case/project"
REV = "a" * 40
TREE = "b" * 40
DATE = "2026-10-28T00:00:00+00:00"
INPUTS = (TREE, REV, DATE, "c" * 64)


def host_value(**changes):
    fields = dict(
        case=CASES[0],
        repository=REPO,
        location=REPO + "/.unrest-runtime/workspaces/integration-abcdefgh",
        kind="integration-commit",
        value="d" * 40,
        inputs=INPUTS,
    )
    fields.update(changes)
    return SimpleNamespace(**fields)


def wire_git(host,calls):
    from pathlib import Path
    from git_observer import Git
    repositories=host.git.repositories
    host.git=Git(host)
    host.git.repositories=repositories
    host.git.repository=lambda repository,*args:Path(repository)
    host.git.location=lambda *args:None
    host.root_only=lambda actor:None
    host.intents={}
    def admit(actor,expected,role,vector,pin,**options):
        calls.append((expected,role,vector,options))
        host.intents[1]={}
        return {'ok':True,'ticket':1,'token':'t'}
    host.admit_launch=admit


@pytest.mark.parametrize(
    "operation,location,fields",
    [
        ("inside", REPO, {}),
        ("top", REPO, {}),
        ("head", REPO, {}),
        ("head-tree", REPO, {}),
        ("verify-base", REPO, {"revision": REV}),
        (
            "lease-add",
            REPO,
            {"tree": REPO + "/.unrest-runtime/workspaces/trees/one", "revision": REV},
        ),
        (
            "integration-add",
            REPO,
            {"tree": REPO + "/.unrest-runtime/workspaces/integration-abcdefgh", "revision": REV},
        ),
        ("remove-tree", REPO, {"tree": REPO + "/.unrest-runtime/workspaces/trees/one"}),
        ("checkout", REPO + "/.unrest-runtime/workspaces/trees/one", {"revision": REV}),
        ("diff-return", REPO + "/.unrest-runtime/workspaces/trees/one", {"revision": REV}),
        ("date", REPO, {"revision": REV}),
        (
            "apply",
            REPO + "/.unrest-runtime/workspaces/integration-abcdefgh",
            {"patch": REPO + "/.unrest/workspaces/patches/" + "f" * 64 + ".patch"},
        ),
        (
            "update-parent",
            REPO,
            {
                "new": "d" * 40,
                "old": REV,
            },
        ),
        (
            "reset-parent",
            REPO,
            {
                "revision": "d" * 40,
            },
        ),
        (
            "commit-tree",
            REPO + "/.unrest-runtime/workspaces/integration-abcdefgh",
            {
                "tree_id": TREE,
                "revision": REV,
                "date": DATE,
                "leases": (("lease:one", "sha256:" + "f" * 64),),
            },
        ),
    ],
)
def test_complete_vector_matches_exact_template_and_bounded_operands(
    operation, location, fields
):
    original = build(operation, REPO, location, fields, family="workspaces")
    raw = {"stdin": original.stdin, "environment": dict(original.additions)}
    assert match_command(operation,REPO,location,list(original.argv),raw["stdin"],raw["environment"],family="workspaces")==original
    if fields:
        with pytest.raises(Refused):
            match_command(operation,REPO,location,[*original.argv,"foreign"],raw["stdin"],raw["environment"],family="workspaces")


@pytest.mark.parametrize("mutation", ["argv", "cwd", "environment", "stdin", "family"])
def test_proposal_mutation_never_reaches_launch(monkeypatch, mutation):
    import git_observer

    monkeypatch.setattr(git_observer, "image", lambda: "a" * 64)
    calls = []
    host = SimpleNamespace(
        case=CASES[0],
        git=SimpleNamespace(repositories={}),
        binding={"entry": {"path": "/native/python", "sha256": "b" * 64}},
        meta_environment=lambda: {"PATH": "/bin:/usr/bin"},
        launch=lambda actor, payload: calls.append(payload),
    )
    raw = {
        "case": host.case,
        "executable": "/usr/bin/git",
        "argv": ["git", "init", "-b", "main"],
        "cwd": REPO,
        "environment": {
            "PATH": "/bin:/usr/bin",
            "PYTEST_VERSION": "9.0.2",
            "PYTEST_CURRENT_TEST": host.case + " (setup)",
        },
        "stdin": None,
    }
    wire_git(host,calls)
    if mutation == "argv":
        raw["argv"].append("--bare")
    elif mutation == "cwd":
        raw["cwd"] += "/../foreign"
    elif mutation == "environment":
        raw["environment"]["GIT_CONFIG_GLOBAL"] = "/foreign"
    elif mutation == "stdin":
        raw["stdin"] = "foreign"
    else:
        host.case = "foreign"
    with pytest.raises(Refused):
        prepare(host, {}, raw)
    assert not calls


def test_producer_reply_is_recursively_json_finite(monkeypatch):
    import git_observer

    monkeypatch.setattr(git_observer, "image", lambda: "a" * 64)
    host = SimpleNamespace(
        case=CASES[0],
        git=SimpleNamespace(repositories={(CASES[0],REPO): {"path": REPO, "setup": 5}}),
        binding={"entry": {"path": "/native/python", "sha256": "b" * 64}},
        meta_environment=lambda: {"PATH": "/bin:/usr/bin"},
        launch=lambda actor, payload: {"ok": True, "ticket": 1, "token": "t"},
    )
    raw = {
        "case": host.case,
        "executable": "/usr/bin/git",
        "argv": ["git", "head"],
        "cwd": REPO,
        "environment": {
            "PATH": "/bin:/usr/bin",
            "PYTEST_VERSION": "9.0.2",
            "PYTEST_CURRENT_TEST": host.case + " (call)",
        },
        "stdin": None,
    }
    wire_git(host,[])
    # Use the real fixed producer template rather than a fabricated stdout value.
    raw["argv"] = ["git", "rev-parse", "HEAD"]
    answer = prepare(host, {}, raw)
    finite(answer)
    assert "command" not in answer


def test_owned_process_refuses_undeclared_stdin_before_admission():
    from git_sites import OWNED_BODY

    calls = []
    host = SimpleNamespace(
        case=CASES[7],
        git=SimpleNamespace(repositories={(CASES[7],REPO): {"path": REPO, "setup": 5}}),
        binding={"entry": {"path": "/native/python", "sha256": "b" * 64}},
        launch=lambda actor, payload: calls.append(payload),
    )
    raw = {
        "case": host.case,
        "executable": "/native/python",
        "argv": ["/native/python", "-c", OWNED_BODY],
        "cwd": REPO + "/.unrest-runtime/workspaces/trees/process",
        "environment": {},
        "stdin": "undeclared",
    }
    with pytest.raises(Refused, match="owned process scope"):
        prepare(host, {}, raw)
    assert not calls


def test_evolution_uses_shared_workspace_query_after_its_fixture_setup(monkeypatch):
    import git_observer

    monkeypatch.setattr(git_observer, "image", lambda: "a" * 64)
    case = CASES[13]
    calls = []
    host = SimpleNamespace(
        case=case,
        git=SimpleNamespace(repositories={(case,REPO): {"path": REPO, "setup": 5}}),
        binding={"entry": {"path": "/native/python", "sha256": "b" * 64}},
        meta_environment=lambda: {"PATH": "/bin:/usr/bin"},
    )

    wire_git(host,calls)
    raw = {
        "case": case,
        "executable": "/usr/bin/git",
        "argv": ["git", "rev-parse", "--is-inside-work-tree"],
        "cwd": REPO,
        "environment": {
            "PATH": "/bin:/usr/bin",
            "PYTEST_VERSION": "9.0.2",
            "PYTEST_CURRENT_TEST": case + " (call)",
        },
        "stdin": None,
    }
    answer = prepare(host, {}, raw)
    assert answer["translated"] == ['/usr/bin/git',*raw["argv"][1:]]
    assert host.intents[1]["operation"] == "inside"
    assert host.intents[1]["repository"] == REPO
    assert calls[0][0].case == case and calls[0][0].argv == tuple(raw["argv"])
    raw["argv"] = ["git", "commit", "-m", "child self commit"]
    with pytest.raises(Refused):
        prepare(host, {}, raw)
    assert len(calls) == 1


@pytest.mark.parametrize("family", ["workspaces", "evolution"])
@pytest.mark.parametrize(
    "operation", ["inside", "head", "parent-ref", "clean", "top", "verify-base"]
)
def test_shared_repository_operations_exist_for_both_product_families(family, operation):
    from git_sites import OPERATIONS

    fields = {"revision": REV} if operation == "verify-base" else {}
    assert operation in OPERATIONS[family]
    value = build(operation, REPO, REPO, fields, family=family)
    assert match_command(operation,REPO,REPO,list(value.argv),None,{},family=family)==value


@pytest.mark.parametrize('branch',['main','master'])
def test_proposal_update_targets_only_authored_main_or_master(monkeypatch,branch):
    import git_observer
    from git_fixtures import SLOTS

    monkeypatch.setattr(git_observer,'image',lambda:'a'*64)
    case=next(iter(SLOTS))
    calls=[]
    host=SimpleNamespace(case=case,
        git=SimpleNamespace(repositories={(case,REPO):{'path':REPO,'setup':5,'branch':branch}},
                            launch=lambda *args:calls.append(args) or {'ticket':1}),
        binding={'entry':{'path':'/native/python','sha256':'b'*64}},
        meta_environment=lambda:{'PATH':'/bin:/usr/bin'})
    wire_git(host,calls)
    raw={'executable':'/usr/bin/git','argv':['git','update-ref','refs/heads/'+branch,TREE,REV],
         'cwd':REPO,'stdin':None,'environment':{'PATH':'/bin:/usr/bin','PYTEST_VERSION':'9.0.2',
            'PYTEST_CURRENT_TEST':case+' (call)'}}
    assert prepare(host,{},raw)['translated']==['/usr/bin/git',*raw['argv'][1:]]
    raw['argv'][2]='refs/heads/foreign'
    with pytest.raises(Refused):
        prepare(host,{},raw)
    assert len(calls)==1
