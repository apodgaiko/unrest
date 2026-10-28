"""The desktop leaf grants one stdio server and one self-only ps query."""
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
import desktop_launch as desktop
from effect_proposals import proposal
from source_observer import Observer

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(desktop, "OWNER", os.getuid())
    monkeypatch.setattr(desktop, "image", lambda path: "b" * 64)
    resolve = Path.resolve
    monkeypatch.setattr(Path, "resolve", lambda self, *a, **kw: Path("/usr/bin/ps") if str(self)=="/bin/ps" else resolve(self, *a, **kw))
    root = tmp_path / "pytest" / "test_actual_stdio_response_bin0" / "desktop"
    root.mkdir(parents=True, mode=0o700)
    root.parent.chmod(0o700)
    calls = []
    host = SimpleNamespace(
        case=desktop.CASE, finished=False,
        meta={"checkout": str(ROOT), "owned": str(tmp_path)},
        binding={"entry": {"path": "/native/python", "sha256": "a" * 64}},
        fixture_roots={}, intents={},
        root_only=lambda actor: None,
        launch_owner=lambda actor: None,
    )
    def admit(actor, expected, role, vector, reference):
        calls.append((expected, role, vector, reference))
        host.intents[len(host.intents)] = {
            "case": desktop.CASE, "role": role, "pid": 123, "token": "owned",
            "consumed": True, "birth": SimpleNamespace(pid=123),
        }
        return {"ok": True, "ticket": len(host.intents)-1, "token": "owned"}
    host.admit_launch = admit
    raw = {"case": desktop.CASE, "stdin": None, "executable": "/native/python",
           "argv": ["/native/python", "-I", str(ROOT / desktop.TOOL), "serve", "--root", str(root)],
           "cwd": str(root), "environment": {"HOME": str(root / "user"), "PATH": "/usr/bin:/bin"}}
    return host, calls, raw, root


def test_exact_original_fixture_script_and_self_query(tmp_path, monkeypatch):
    host, calls, raw, root = setup(tmp_path, monkeypatch)
    assert hashlib.sha256((ROOT / desktop.TOOL).read_bytes()).hexdigest() == desktop.PIN
    result = proposal(host, {"role": "root"}, raw)
    assert result["translated"] == ["/native/python", "-I", "-S", *raw["argv"][2:]]
    assert calls[0][1] == "desktop" and calls[0][3] == desktop.PIN
    actor = {"role": "desktop", "case": desktop.CASE, "birth": SimpleNamespace(pid=123), "token": "owned", "body_ready": True}
    raw = {**raw, "executable": "/bin/ps", "argv": ["/bin/ps", "-p", "123", "-o", "lstart="],
           "environment": {"HOME": str(root / "user"), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                           "UNREST_HOME": str(root / "home"), "UNREST_PROJECTS_DIR": str(root / "home/projects"),
                           "PYTHONDONTWRITEBYTECODE": "1"}}
    result = proposal(host, actor, raw)
    assert result["translated"] == ["/bin/ps", "-p", "123", "-o", "lstart="]
    assert calls[-1][1] == "ps" and calls[-1][0].executable_sha256 == "b" * 64
    assert calls[-1][0].executable == raw["executable"] == "/bin/ps"
    with pytest.raises(Refused, match="sole responding"):
        proposal(host, actor, raw)
    assert len(calls) == 2


@pytest.mark.parametrize("mutation", ["argv", "extra-env", "cwd", "alias", "mode", "second-server", "input"])
def test_server_deviations_refuse_before_admission(tmp_path, monkeypatch, mutation):
    host, calls, raw, root = setup(tmp_path, monkeypatch)
    if mutation == "argv":
        raw["argv"].append("--mode=worker")
    elif mutation == "extra-env":
        raw["environment"]["TOKEN"] = "forbidden"
    elif mutation == "cwd":
        raw["cwd"] = str(root.parent)
    elif mutation == "alias":
        root.rename(root.with_name("real"))
        root.symlink_to(root.with_name("real"), target_is_directory=True)
    elif mutation == "mode":
        root.chmod(0o777)
    elif mutation == "second-server":
        host.intents[1] = {"case": desktop.CASE, "role": "desktop"}
    else:
        raw["stdin"] = "undeclared"
    with pytest.raises(Refused):
        proposal(host, {"role": "root"}, raw)
    assert not calls


def test_replaced_fixture_generation_is_not_retained(tmp_path, monkeypatch):
    host, calls, raw, root = setup(tmp_path, monkeypatch)
    proposal(host, {"role": "root"}, raw)
    root.rename(root.with_name("old"))
    root.mkdir(mode=0o700)
    with pytest.raises(Refused, match="generation"):
        desktop.retained(host)
    assert len(calls) == 1


def test_desktop_cannot_inherit_other_case_launch_authority():
    host = SimpleNamespace(case="other", finished=False)
    with pytest.raises(Refused, match="owner"):
        Observer.launch_owner(host, {"role": "desktop", "case": "other"})


@pytest.mark.parametrize("mutation", ["pid", "birth", "token", "ready", "argv", "environment", "alias"])
def test_query_rejects_foreign_or_changed_process_operands(tmp_path, monkeypatch, mutation):
    host, calls, raw, root = setup(tmp_path, monkeypatch)
    proposal(host, {"role": "root"}, raw)
    actor = {"role": "desktop", "case": desktop.CASE, "birth": SimpleNamespace(pid=123), "token": "owned", "body_ready": True}
    raw = {**raw, "executable": "/bin/ps", "argv": ["/bin/ps", "-p", "123", "-o", "lstart="],
           "environment": {"HOME": str(root / "user"), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                           "UNREST_HOME": str(root / "home"), "UNREST_PROJECTS_DIR": str(root / "home/projects"),
                           "PYTHONDONTWRITEBYTECODE": "1"}}
    if mutation == "pid":
        actor["birth"].pid = 456
    elif mutation == "birth":
        actor["birth"].generation = "different"
    elif mutation == "token":
        actor["token"] = "foreign"
    elif mutation == "ready":
        actor["body_ready"] = False
    elif mutation == "argv":
        raw["argv"][2] = "456"
    elif mutation == "environment":
        raw["environment"]["EXTRA"] = "forbidden"
    else:
        resolve = Path.resolve
        monkeypatch.setattr(Path, "resolve", lambda self, *a, **kw: Path("/other/ps") if str(self)=="/bin/ps" else resolve(self, *a, **kw))
    with pytest.raises(Refused):
        proposal(host, actor, raw)
    assert len(calls) == 1
