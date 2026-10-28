"""Finite Git operands retain causal dependencies without Python caller policing."""

from types import SimpleNamespace

import pytest

from content_manifest import Refused
from control_transport import finite
from git_commands import build
from git_proposals import integration, operands, prepare
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


def test_integration_dependency_is_case_repository_kind_and_value_bound():
    rows = [
        host_value(case="foreign"),
        host_value(repository="/foreign"),
        host_value(kind="commit"),
        host_value(value="e" * 40),
        host_value(),
    ]
    host = SimpleNamespace(case=CASES[0], git=SimpleNamespace(values=SimpleNamespace(values=rows)))
    result = integration(host, REPO, "d" * 40)
    assert result == {"new_location": rows[-1].location, "new_inputs": INPUTS}
    host.git.values.values = rows[:-1]
    with pytest.raises(Refused, match="unique integration producer"):
        integration(host, REPO, "d" * 40)
    host.git.values.values = [host_value(), host_value(location="/foreign")]
    with pytest.raises(Refused, match="unique integration producer"):
        integration(host, REPO, "d" * 40)


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
                "new_location": REPO + "/.unrest-runtime/workspaces/integration-abcdefgh",
                "new_inputs": INPUTS,
            },
        ),
        (
            "reset-parent",
            REPO,
            {
                "revision": "d" * 40,
                "new_location": REPO + "/.unrest-runtime/workspaces/integration-abcdefgh",
                "new_inputs": INPUTS,
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
def test_inverse_template_preserves_exact_command_input_and_requirements(
    operation, location, fields
):
    host = SimpleNamespace(
        case=CASES[0], git=SimpleNamespace(values=SimpleNamespace(values=[host_value()]))
    )
    original = build(operation, REPO, location, fields, family="workspaces")
    raw = {"stdin": original.stdin, "environment": dict(original.additions)}
    recovered = operands(host, operation, list(original.argv[1:]), raw, REPO)
    assert build(operation, REPO, location, recovered, family="workspaces") == original
    if fields:
        with pytest.raises(Refused):
            operands(host, operation, [*original.argv[1:], "foreign"], raw, REPO)


@pytest.mark.parametrize("mutation", ["argv", "cwd", "environment", "stdin", "family"])
def test_proposal_mutation_never_reaches_launch(monkeypatch, mutation):
    import git_proposals

    monkeypatch.setattr(git_proposals, "image", lambda: "a" * 64)
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
        "executable": "git",
        "argv": ["git", "init", "-b", "main"],
        "cwd": REPO,
        "environment": {
            "PATH": "/bin:/usr/bin",
            "PYTEST_VERSION": "9.0.2",
            "PYTEST_CURRENT_TEST": host.case + " (setup)",
        },
        "stdin": None,
    }
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
    import git_proposals

    monkeypatch.setattr(git_proposals, "image", lambda: "a" * 64)
    host = SimpleNamespace(
        case=CASES[0],
        git=SimpleNamespace(repositories={CASES[0]: {"path": REPO, "setup": 5}}),
        binding={"entry": {"path": "/native/python", "sha256": "b" * 64}},
        meta_environment=lambda: {"PATH": "/bin:/usr/bin"},
        launch=lambda actor, payload: {"ok": True, "ticket": 1, "token": "t"},
    )
    raw = {
        "case": host.case,
        "executable": "git",
        "argv": ["git", "head"],
        "cwd": REPO,
        "environment": {
            "PATH": "/bin:/usr/bin",
            "PYTEST_VERSION": "9.0.2",
            "PYTEST_CURRENT_TEST": host.case + " (call)",
        },
        "stdin": None,
    }
    # Use the real fixed producer template rather than a fabricated stdout value.
    raw["argv"] = ["git", "rev-parse", "HEAD"]
    answer = prepare(host, {}, raw)
    finite(answer)
    assert answer["command"] == {"stdin": None, "produces": ["parent", "commit", []]}


def test_owned_process_refuses_undeclared_stdin_before_admission():
    from git_sites import OWNED_BODY

    calls = []
    host = SimpleNamespace(
        case=CASES[7],
        git=SimpleNamespace(repositories={CASES[7]: {"path": REPO, "setup": 5}}),
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
    import git_proposals

    monkeypatch.setattr(git_proposals, "image", lambda: "a" * 64)
    case = CASES[13]
    calls = []
    host = SimpleNamespace(
        case=case,
        git=SimpleNamespace(repositories={case: {"path": REPO, "setup": 5}}),
        binding={"entry": {"path": "/native/python", "sha256": "b" * 64}},
        meta_environment=lambda: {"PATH": "/bin:/usr/bin"},
    )

    def launch(actor, payload):
        calls.append(payload)
        return {"ok": True, "ticket": 1, "token": "t"}

    host.launch = launch
    raw = {
        "case": case,
        "executable": "git",
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
    assert answer["translated"] == raw["argv"]
    assert calls[0]["git"] == {"operation": "inside", "repository": REPO, "fields": {}}
    assert calls[0]["original"]["owner"] == "git:inside"
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
    host = SimpleNamespace()
    recovered = operands(
        host, operation, list(value.argv[1:]), {"stdin": None, "environment": {}}, REPO
    )
    assert build(operation, REPO, REPO, recovered, family=family) == value
