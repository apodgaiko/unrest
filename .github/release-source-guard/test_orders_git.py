"""Finite native Git custody and fixture transitions; no native command launches."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import types

import pytest

SUPPORT = Path(__file__).parent
ROOT = SUPPORT.parent.parent
sys.path.insert(0, str(SUPPORT))
sys.path.insert(0, str(ROOT))
from finite import orders_git as route  # noqa: E402
import orders_git_custody as native  # noqa: E402
from finite.orders_git_data import PINS, SITES, CASES as SETUP_CASES  # noqa: E402
from finite.backend_postimage_catalog import CASES  # noqa: E402

CASE = next(c for c in CASES if c.startswith(route.ORDERS + "::"))


def selected(tmp_path):
    directory = tmp_path / "pytest/case/cohort/base"
    directory.mkdir(parents=True)
    vector = [
        "/usr/bin/git",
        "--no-replace-objects",
        "init",
        "--initial-branch=main",
        "--object-format=sha1",
    ]
    caller = {
        "path": str(ROOT / "tests/test_experimental_finite_priority.py"),
        "line": 36,
        "sha256": PINS["tests/test_experimental_finite_priority.py"],
        "function": "setup",
    }
    registration = {
        "class": route.CLASS,
        "python": False,
        "case": CASE,
        "owner_pid": 20,
        "token": "exact",
        "source_binding": {
            "path": str(ROOT / route.PRODUCT),
            "line": 38,
            "sha256": PINS[route.PRODUCT],
            "function": "git",
        },
        "caller_binding": caller,
    }
    environment = dict(route.ENVIRONMENT)
    selection = {
        "registration": registration,
        "owner_pid": 20,
        "token": "exact",
        "bootstrap_sha256": None,
        "cwd": str(directory),
        "transformed_argv_sha256": hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
        "environment_sha256": hashlib.sha256(
            json.dumps(environment, sort_keys=True).encode()
        ).hexdigest(),
    }
    manifest = {"owned_root": str(tmp_path), "product_pins": dict(PINS)}
    return selection, vector, environment, str(directory), manifest


@pytest.mark.parametrize(
    "change",
    [
        None,
        "class",
        "case",
        "python",
        "caller-line",
        "caller-source",
        "helper-line",
        "helper-source",
        "owner",
        "token",
        "cwd",
        "argv-pin",
        "env-pin",
        "environment",
        "command",
        "foreign-root",
        "source-pin",
        "bootstrap",
    ],
)
def test_native_consumption_requires_the_exact_original_custody_join(tmp_path, change):
    selection, vector, env, cwd, manifest = selected(tmp_path)
    reg = selection["registration"]
    if change == "class":
        reg["class"] = "generic-git"
    elif change == "case":
        reg["case"] = CASE.replace("finite_orders", "finite_priority")
    elif change == "python":
        reg["python"] = True
    elif change == "caller-line":
        reg["caller_binding"]["line"] = 46
    elif change == "caller-source":
        reg["caller_binding"]["sha256"] = "foreign"
    elif change == "helper-line":
        reg["source_binding"]["line"] = 39
    elif change == "helper-source":
        reg["source_binding"]["sha256"] = "foreign"
    elif change == "owner":
        reg["owner_pid"] = 21
    elif change == "token":
        reg["token"] = "foreign"
    elif change == "cwd":
        selection["cwd"] = str(Path(cwd).parent)
    elif change == "argv-pin":
        selection["transformed_argv_sha256"] = "foreign"
    elif change == "env-pin":
        selection["environment_sha256"] = "foreign"
    elif change == "environment":
        env["GIT_CONFIG_GLOBAL"] = "/foreign"
    elif change == "command":
        vector[2] = "clone"
    elif change == "foreign-root":
        manifest["owned_root"] = "/foreign"
    elif change == "source-pin":
        manifest["product_pins"][route.PRODUCT] = "foreign"
    elif change == "bootstrap":
        selection["bootstrap_sha256"] = "foreign"
    assert native.eligible(selection, vector, env, cwd, manifest, str(ROOT)) is (change is None)


def config(root):
    path = root / ".git/config"
    path.parent.mkdir()
    path.write_text(
        "[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\n"
    )
    return path


@pytest.mark.parametrize(
    "change", [None, "maintenance", "gc", "extra-section", "symlink", "hardlink", "argv", "site"]
)
def test_commits_require_the_unchanged_core_metadata_grammar(tmp_path, change):
    directory = tmp_path / "pytest/case/cohort/z-first-candidate"
    directory.mkdir(parents=True)
    path = config(directory)
    vector = [
        "/usr/bin/git",
        "--no-replace-objects",
        "commit",
        "--allow-empty",
        "-m",
        "sealed candidate",
    ]
    caller = {"function": "seal", "line": 197}
    if change == "maintenance":
        path.write_text(path.read_text() + "[maintenance]\nauto = true\n")
    elif change == "gc":
        path.write_text(path.read_text() + "[gc]\nauto = 1\n")
    elif change == "extra-section":
        path.write_text(path.read_text() + "[credential]\nhelper = foreign\n")
    elif change == "symlink":
        path.rename(path.with_suffix(".original"))
        path.symlink_to(path.with_suffix(".original"))
    elif change == "hardlink":
        path.with_suffix(".copy").hardlink_to(path)
    elif change == "argv":
        vector.append("extra")
    elif change == "site":
        caller["line"] = 193
    assert route.repository_profile(vector, str(directory), str(tmp_path), caller) is (
        change is None
    )


def test_twelve_original_calls_and_thirty_cases_are_closed():
    assert len(SITES) == 16
    assert len([s for s, owner in SITES.items() if owner != "campaign"]) == 12
    assert len([c for c in CASES if c.split("::")[0] == route.ORDERS]) == 30
    for (source, line), owner in SITES.items():
        body = (ROOT / source).read_bytes()
        assert hashlib.sha256(body).hexdigest() == PINS[source]
        calls = [
            n
            for n in ast.walk(ast.parse(body))
            if isinstance(n, ast.Call)
            and n.lineno == line
            and isinstance(n.func, ast.Name)
            and n.func.id == "git"
        ]
        assert len(calls) == 1 and owner in ("setup", "seal", "integrate", "campaign")


def test_changed_fixture_pins_preserve_the_historical_template(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "fixture_transition_control", SUPPORT / "prepare_source.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    template = json.loads((SUPPORT / "finite/source-template.json").read_bytes())
    before = json.loads(json.dumps(template))
    monkeypatch.setattr(module, "ROOT", ROOT)
    module.admit_controlled_fixture_cleanup(template)
    changed = {
        n
        for n in before["product_pins"]
        if before["product_pins"][n] != template["product_pins"][n]
    }
    assert changed == {
        "tests/test_experimental_notifications.py",
    }
    assert template["anchor_inventory"] == before["anchor_inventory"]
    for name in changed:
        assert (
            template["product_pins"][name] == hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        )
    with pytest.raises(RuntimeError, match="controlled_fixture_cleanup_transition"):
        module.admit_controlled_fixture_cleanup(template)


def named(code, name):
    if code.co_name == name:
        return code
    for item in code.co_consts:
        if isinstance(item, types.CodeType):
            value = named(item, name)
            if value is not None:
                return value
    return None


@pytest.mark.parametrize(
    "change",
    [
        None,
        "case",
        "pin",
        "helper-code",
        "helper-line",
        "caller-code",
        "caller-line",
        "caller-globals",
        "env",
        "vector",
        "cwd",
        "missing-frame",
    ],
)
def test_python_admission_joins_real_source_code_and_call_arguments(tmp_path, change):
    import importlib

    product = importlib.import_module("unrest_harness.experimental_custody")
    setup = importlib.import_module("tests.test_experimental_finite_priority")
    selection, vector, env, cwd, manifest = selected(tmp_path)
    directory = Path(cwd)

    def code(path):
        return compile(Path(path).read_bytes(), str(path), "exec", dont_inherit=True)

    caller = SimpleNamespace(
        f_code=named(code(setup.__file__), "setup"),
        f_globals=vars(setup),
        f_lineno=36,
        f_locals={"original": directory},
    )
    helper = SimpleNamespace(
        f_code=named(code(product.__file__), "git"),
        f_globals=vars(product),
        f_lineno=38,
        f_back=caller,
        f_locals={"root": directory, "arguments": tuple(vector[2:])},
    )
    state = {
        "checkout": str(ROOT),
        "owned_root": str(tmp_path),
        "case": CASE,
        "product_pins": dict(PINS),
        "isolated_source_code": code,
        "isolated_named": named,
    }
    data = {"PINS": PINS, "SITES": SITES}
    frames = [helper]
    if change == "case":
        state["case"] = (
            "tests/test_experimental_finite_orders.py::test_parking_admission_never_constructs_owner[0]"
        )
    elif change == "pin":
        state["product_pins"][route.PRODUCT] = "foreign"
    elif change == "helper-code":
        helper.f_code = (lambda: None).__code__
    elif change == "helper-line":
        helper.f_lineno = 39
    elif change == "caller-code":
        caller.f_code = (lambda: None).__code__
    elif change == "caller-line":
        caller.f_lineno = 46
    elif change == "caller-globals":
        caller.f_globals = dict(vars(setup))
    elif change == "env":
        env["GIT_TERMINAL_PROMPT"] = "1"
    elif change == "vector":
        vector.append("extra")
    elif change == "cwd":
        cwd = str(directory.parent)
    elif change == "missing-frame":
        frames = []
    result = route.matches(vector, Path(cwd), env, state, frames, data, SETUP_CASES)
    assert (result is not None) is (change is None)
    if result:
        assert result["caller_binding"] == selection["registration"]["caller_binding"]
        assert result["source_binding"] == selection["registration"]["source_binding"]


@pytest.mark.parametrize(
    "change",
    [
        None,
        "missing-launch",
        "duplicate-launch",
        "missing-caller",
        "duplicate-caller",
        "interleaved-launch",
        "legacy-window",
        "token",
        "binding-environment",
        "binding-bootstrap",
        "after-launch",
        "owner",
        "case",
        "class",
        "python",
        "cwd",
        "argv",
        "source",
        "launch-env",
        "caller-drift",
    ],
)
def test_stopped_image_joins_actual_admitted_shape_to_exact_caller_token(tmp_path, change):
    selection, vector, env, cwd, manifest = selected(tmp_path)
    full = selection["registration"]
    concrete = {
        "kind": "orders_custody_launch_binding",
        **full,
        "argv_sha256": selection["transformed_argv_sha256"],
        "environment_sha256": selection["environment_sha256"],
        "bootstrap_sha256": None,
        "cwd": cwd,
    }
    # runtime_guard's admitted event carries neither python nor caller_binding.
    admitted = {k: v for k, v in full.items() if k not in ("python", "caller_binding")}
    admitted["argv_sha256"] = selection["transformed_argv_sha256"]
    selection = {**selection, "registration": admitted}
    launch = {k: v for k, v in selection.items() if k != "registration"}
    launch["kind"] = "actual_launch_binding"
    events = [concrete, launch]
    if change == "missing-launch":
        events.pop()
    elif change == "duplicate-launch":
        events.append(dict(launch))
    elif change == "missing-caller":
        events.pop(0)
    elif change == "duplicate-caller":
        events.insert(0, dict(concrete))
    elif change == "interleaved-launch":
        events.insert(1, {**launch, "token": "previous"})
    elif change == "legacy-window":
        concrete['kind'] = 'concrete_orders_custody_git'
        concrete.pop('token')
    elif change == "token":
        concrete['token'] = 'crossed'
    elif change == "binding-environment":
        concrete['environment_sha256'] = 'foreign'
    elif change == "binding-bootstrap":
        concrete['bootstrap_sha256'] = 'foreign'
    elif change == "after-launch":
        events.reverse()
    elif change in ("owner", "case", "class", "python", "cwd", "argv", "source"):
        name = {"owner": "owner_pid", "argv": "argv_sha256", "source": "source_binding"}.get(
            change, change
        )
        concrete[name] = "foreign"
    elif change == "launch-env":
        launch["environment_sha256"] = "foreign"
    elif change == "caller-drift":
        concrete["caller_binding"] = {**concrete["caller_binding"], "line": 46}
    snapshot = json.dumps(selection, sort_keys=True)
    joined = native.join_registration(selection, events)
    accepted = joined is not None and native.eligible(joined, vector, env, cwd, manifest, str(ROOT))
    assert accepted is (change in (None, 'interleaved-launch'))
    assert json.dumps(selection, sort_keys=True) == snapshot


def test_admitted_record_has_the_original_frozen_projection():
    tree = ast.parse((SUPPORT / "finite/runtime_guard.py").read_bytes())
    records = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        and any(
            isinstance(k, ast.Constant)
            and k.value == "kind"
            and isinstance(v, ast.Constant)
            and v.value == "admitted"
            for k, v in zip(node.keys, node.values)
        )
    ]
    assert len(records) == 1
    assert {k.value for k in records[0].keys} == {
        "kind",
        "token",
        "class",
        "argv_sha256",
        "source_binding",
    }


@pytest.mark.parametrize(
    "site,message,args",
    [
        (("setup", 40), "finite fixture", ["commit", "-m", "finite fixture"]),
        (("campaign", 571), "base", ["commit", "-m", "base"]),
        (("seal", 197), "sealed candidate", ["commit", "--allow-empty", "-m", "sealed candidate"]),
        (
            ("integrate", 239),
            "authored lane integration",
            ["commit", "--allow-empty", "-m", "authored lane integration"],
        ),
    ],
)
@pytest.mark.parametrize(
    "change",
    [
        None,
        "site",
        "argv",
        "cwd",
        "parent-env",
        "child-env",
        "head",
        "object",
        "author",
        "message",
        "extra-zlib",
    ],
)
def test_stock_housekeeping_requires_the_exact_original_commit(
    tmp_path, site, message, args, change
):
    import zlib
    import orders_git_maintenance as maintenance

    root = tmp_path / "repository"
    git = root / ".git"
    (git / "refs/heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    body = (
        b"tree " + b"0" * 40 + b"\nauthor Fixture <fixture@example.invalid> 946684800 +0000\n"
        b"committer Fixture <fixture@example.invalid> 946684800 +0000\n\n"
        + message.encode()
        + b"\n"
    )
    if change == "author":
        body = body.replace(b"author Fixture", b"author Foreign")
    elif change == "message":
        body += b"foreign\n"
    raw = b"commit " + str(len(body)).encode() + b"\0" + body
    oid = hashlib.sha1(raw).hexdigest()
    path = git / "objects" / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True)
    path.write_bytes(zlib.compress(raw) + (b"foreign" if change == "extra-zlib" else b""))
    (git / "refs/heads/main").write_text(oid + "\n")
    parent = {
        "argv": ["/usr/bin/git", "--no-replace-objects", *args],
        "cwd": str(root),
        "environment": dict(route.ENVIRONMENT),
        "orders_registration": {"caller_binding": {"function": site[0], "line": site[1]}},
    }
    env = {
        **route.ENVIRONMENT,
        "PATH": "/usr/lib/git-core:/usr/bin:/bin",
        "GIT_EXEC_PATH": "/usr/lib/git-core",
        "GIT_PREFIX": "",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_AUTHOR_DATE": "@946684800 +0000",
    }
    if change == "site":
        parent["orders_registration"]["caller_binding"]["line"] = 38
    elif change == "argv":
        parent["argv"].append("foreign")
    elif change == "cwd":
        parent["cwd"] = str(tmp_path)
    elif change == "parent-env":
        parent["environment"]["GIT_CONFIG_GLOBAL"] = "/foreign"
    elif change == "child-env":
        env["GIT_CONFIG_GLOBAL"] = "/foreign"
    elif change == "head":
        (git / "HEAD").write_text("ref: refs/heads/foreign\n")
    elif change == "object":
        path.write_bytes(zlib.compress(raw + b"foreign"))
    assert maintenance.metadata(parent, env, str(root)) is (change is None)


def test_housekeeping_other_vectors_do_not_consult_or_grant_authority():
    import orders_git_maintenance as maintenance

    for vector in ([], ["/usr/bin/git", "maintenance"], maintenance.VECTOR + ["foreign"]):
        assert (
            maintenance.resolve(
                None, None, 123, vector[0] if vector else "", vector, {}, "/foreign"
            )
            is False
        )


@pytest.mark.parametrize("case", sorted(c for c in SETUP_CASES if not SETUP_CASES[c].startswith("campaign/")))
def test_original_setup_cases_have_only_their_exact_owned_root(tmp_path, case):
    selection, argv, env, cwd, manifest = selected(tmp_path)
    selection["registration"]["case"] = case
    root_name = SETUP_CASES[case]
    directory = Path(cwd).parent.with_name(root_name) / "base"
    directory.mkdir(parents=True, exist_ok=True)
    selection["cwd"] = str(directory)
    assert native.eligible(selection, argv, env, str(directory), manifest, str(ROOT))
    foreign = directory.parent.with_name("combined" if root_name == "cohort" else "cohort") / "base"
    foreign.mkdir(parents=True, exist_ok=True)
    selection["cwd"] = str(foreign)
    assert not native.eligible(selection, argv, env, str(foreign), manifest, str(ROOT))


def test_closed_shared_setup_inventory_preserves_negative_cases():
    from collections import Counter

    counts = Counter(c.split("::")[0].split("/")[-1] for c in SETUP_CASES)
    assert counts == {
        "test_experimental_finite_orders.py": 30,
        "test_experimental_finite_priority.py": 25,
        "test_experimental_finite_stops.py": 12,
        "test_experimental_finite_ttl.py": 3,
        "test_experimental_first_halt.py": 15,
        "test_experimental_drain_retirement.py": 13,
        "test_experimental_ack_durability.py": 20,
        "test_experimental_startup_diagnostics.py": 1,
        "test_controlled_python_acp.py": 1,
    }
    assert all(
        SETUP_CASES[c] == ("combined" if "finite_priority.py::" in c else "cohort")
        for c in SETUP_CASES if not SETUP_CASES[c].startswith("campaign/")
    )
    assert not any("parking_admission" in c for c in SETUP_CASES)
    assert not any("PRIORITY-66" in c for c in SETUP_CASES)


CAMPAIGN_CASE = 'tests/test_experimental_startup_diagnostics.py::test_coordinator_persists_startup_and_separate_cleanup_failure'
CAMPAIGN = 'src/unrest_harness/experimental_cohort.py'
CAMPAIGN_CALLS = {567: ['init', '--initial-branch=main', '--object-format=sha1'],
                  570: ['add', '.'], 571: ['commit', '-m', 'base'], 572: ['rev-parse', 'HEAD']}

@pytest.mark.parametrize('line', sorted(CAMPAIGN_CALLS))
@pytest.mark.parametrize('change', [None, 'case', 'root', 'episode', 'directory', 'site',
    'callable', 'globals', 'argv', 'environment', 'source-pin', 'foreign-caller'])
def test_one_startup_failure_campaign_joins_original_four_calls(tmp_path, line, change):
    import importlib
    product = importlib.import_module('unrest_harness.experimental_custody')
    cohort = importlib.import_module('unrest_harness.experimental_cohort')
    directory = tmp_path / 'pytest/case/campaign/P1/base'
    directory.mkdir(parents=True)
    if line != 567:
        git = directory / '.git'
        git.mkdir()
        (git / 'config').write_text('[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\n')
    def code(path):
        return compile(Path(path).read_bytes(), str(path), 'exec', dont_inherit=True)
    caller = SimpleNamespace(f_code=named(code(cohort.__file__), 'campaign'),
        f_globals=vars(cohort), f_lineno=line, f_locals={'original': directory})
    arguments = CAMPAIGN_CALLS[line]
    helper = SimpleNamespace(f_code=named(code(product.__file__), 'git'), f_globals=vars(product),
        f_lineno=38, f_back=caller, f_locals={'root': directory, 'arguments': tuple(arguments)})
    vector = ['/usr/bin/git', '--no-replace-objects', *arguments]
    environment = dict(route.ENVIRONMENT)
    state = {'checkout': str(ROOT), 'owned_root': str(tmp_path), 'case': CAMPAIGN_CASE,
        'product_pins': dict(PINS), 'isolated_source_code': code, 'isolated_named': named}
    if change == 'case':
        state['case'] = CASE
    elif change in {'root', 'episode', 'directory'}:
        parts = {'root': ('campaign', 'other'), 'episode': ('P1', 'P2'), 'directory': ('base', 'candidate-0')}
        old, new = parts[change]
        directory = Path(str(directory).replace('/' + old, '/' + new))
        directory.mkdir(parents=True, exist_ok=True)
        caller.f_locals['original'] = helper.f_locals['root'] = directory
    elif change == 'site':
        caller.f_lineno += 1
    elif change == 'callable':
        caller.f_code = (lambda: None).__code__
    elif change == 'globals':
        caller.f_globals = dict(vars(cohort))
    elif change == 'argv':
        vector.append('--extra')
    elif change == 'environment':
        environment['GIT_CONFIG_GLOBAL'] = '/foreign'
    elif change == 'source-pin':
        state['product_pins'][CAMPAIGN] = '0' * 64
    elif change == 'foreign-caller':
        caller.f_code = named(code(cohort.__file__), 'controller_io')
    selected = route.matches(vector, directory, environment, state, [helper],
        {'PINS': PINS, 'SITES': SITES}, SETUP_CASES)
    assert (selected is not None) is (change is None)
    if selected is not None:
        registration = {**selected, 'owner_pid': 20, 'token': 'exact'}
        launch = {'registration': registration, 'owner_pid': 20, 'token': 'exact', 'cwd': str(directory),
            'bootstrap_sha256': None, 'transformed_argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
            'environment_sha256': hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()}
        assert native.eligible(launch, vector, environment, str(directory),
            {'owned_root': str(tmp_path), 'product_pins': dict(PINS)}, str(ROOT))


def test_campaign_caller_and_root_inventory_is_only_the_original_four_calls():
    assert {s: owner for s, owner in SITES.items() if owner == 'campaign'} == {
        (CAMPAIGN, line): 'campaign' for line in CAMPAIGN_CALLS}
    assert {c: root for c, root in SETUP_CASES.items() if root == 'campaign/P1'} == {CAMPAIGN_CASE: 'campaign/P1'}
