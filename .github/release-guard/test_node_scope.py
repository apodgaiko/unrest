"""Scoped application data cannot change execution or escape its acquired project."""

import json

import pytest

from content_manifest import Refused
from node_environment import baseline, environment, scoped


@pytest.fixture
def data(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    ambient = {"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "HOME": "/owned/home"}
    observed = environment(ambient, home, "p", "original-node", "work", "original-attempt")
    observed["UNREST_NODE_ASSIGNMENT"] = '{"targets":["VAL-ORIGINAL"],"task_type":"work"}'
    return observed, baseline(ambient, home, "p"), home


@pytest.mark.parametrize(
    "mutation",
    (
        "home",
        "project",
        "mission",
        "node",
        "output",
        "traversal",
        "provider",
        "permission",
        "import",
        "loader",
        "extra",
        "missing",
        "role",
        "assignment-role",
        "assignment-shape",
        "assignment-duplicate",
        "assignment-json",
        "assignment-bound",
    ),
)
def test_scoped_data_does_not_supply_execution_authority_or_other_project_paths(data, mutation):
    observed, base, home = data
    if mutation == "home":
        observed["UNREST_HOME"] = str(home.parent / "other")
    elif mutation == "project":
        observed["UNREST_PROJECT_ID"] = "other"
    elif mutation == "mission":
        observed["UNREST_MISSION_ID"] = "other"
    elif mutation == "node":
        observed["UNREST_NODE_ID"] = "other"
    elif mutation == "output":
        observed["UNREST_HANDOFF_PATH"] = str(home.parent / "other.json")
    elif mutation == "traversal":
        observed["UNREST_NODE_ID"] = "../outside"
    elif mutation == "provider":
        observed["UNREST_WORKER_PROVIDER"] = "codex"
    elif mutation == "permission":
        observed["CODEX_CONFIG"] = '{"sandbox_mode":"danger-full-access"}'
    elif mutation == "import":
        observed["PYTHONPATH"] = "/foreign"
    elif mutation == "loader":
        observed["LD_PRELOAD"] = "/foreign"
    elif mutation == "extra":
        observed["UNREST_NODE_ASSIGNMENT_EXTRA"] = "data"
    elif mutation == "missing":
        observed.pop("UNREST_NODE_ASSIGNMENT")
    elif mutation == "role":
        observed["UNREST_NODE_TYPE"] = "validate"
    elif mutation == "assignment-role":
        observed["UNREST_NODE_ASSIGNMENT"] = '{"targets":[],"task_type":"validate"}'
    elif mutation == "assignment-shape":
        observed["UNREST_NODE_ASSIGNMENT"] = '{"targets":{},"task_type":"work"}'
    elif mutation == "assignment-duplicate":
        observed["UNREST_NODE_ASSIGNMENT"] = '{"targets":[],"targets":[],"task_type":"work"}'
    elif mutation == "assignment-json":
        observed["UNREST_NODE_ASSIGNMENT"] = "["
    else:
        observed["UNREST_NODE_ASSIGNMENT"] = "x" * 8193
    if mutation in ("assignment-role", "assignment-shape", "assignment-duplicate", "assignment-json"):
        assert scoped(observed,base,home,"p","work",module=True)==observed
        assert observed["UNREST_NODE_TYPE"]=="work"
    else:
        with pytest.raises(Refused):
            scoped(observed, base, home, "p", "work", module=True)


def test_application_names_attempts_and_targets_are_data_within_the_bound_scope(data):
    observed, base, home = data
    observed.update(
        UNREST_MISSION_ID="another-mission",
        UNREST_NODE_ID="another-node",
        UNREST_HANDOFF_PATH=str(
            home
            / "projects/p/.unrest-runtime/missions/another-mission/attempts/another-attempt__another-node.json"
        ),
        UNREST_NODE_ASSIGNMENT=json.dumps({"targets": ["different-target"], "task_type": "work"}),
    )
    assert scoped(observed, base, home, "p", "work", module=True) == observed


def test_output_symlink_does_not_turn_scoped_data_into_another_root(data, tmp_path):
    observed, base, home = data
    project = home / "projects/p"
    project.parent.mkdir()
    (tmp_path / "outside").mkdir()
    project.symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(Refused, match="outside acquired project"):
        scoped(observed, base, home, "p", "work", module=True)


@pytest.mark.parametrize("terminal", (False, True))
def test_mcp_assignment_and_terminal_review_paths_remain_role_specific(data, terminal):
    _, base, home = data
    role = "terminal_reviewer" if terminal else "validate"
    observed = environment(base, home, "p", "validator", role, "attempt")
    if not terminal:
        observed["UNREST_NODE_ASSIGNMENT"] = '{"targets":[],"task_type":"validate"}'
    assert scoped(observed, base, home, "p", role, module=True) == observed
    observed["UNREST_HANDOFF_PATH" if terminal else "UNREST_TERMINAL_REVIEW_PATH"] = str(
        home / "other.json"
    )
    with pytest.raises(Refused):
        scoped(observed, base, home, "p", role, module=True)
