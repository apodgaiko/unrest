"""Prepared artifacts are byte-bound inputs, never completed test observations."""
import hashlib
import json
from types import SimpleNamespace

from content_manifest import capture
import prepared_distribution as prepared


def binding(tmp_path, monkeypatch):
    source=tmp_path/"source"
    source.mkdir()
    (source/"pyproject.toml").write_text("candidate source")
    runtime=tmp_path/"runtime"
    (runtime/"bin").mkdir(parents=True)
    (runtime/"bin/uv").write_bytes(b"stock uv")
    dependencies=tmp_path/"dependencies"
    root=dependencies/prepared.NAME
    for name in ("backend", "archives", "installed", "extracted"):
        (root/name).mkdir(parents=True)
        (root/name/"member").write_bytes(name.encode())
    source_manifest=capture(source,["pyproject.toml"])
    receipt={"schema":"unrest.prepared-distribution.v1", "source":source_manifest,
             "uv":hashlib.sha256(b"stock uv").hexdigest(), "runtime":"a"*64,
             **{name:prepared.tree(root/name) for name in ("backend","archives","installed","extracted")}}
    (root/"receipt.json").write_bytes(json.dumps(receipt,sort_keys=True).encode())
    (root/"receipt.json").chmod(0o644)
    policy=SimpleNamespace(profile={"dependencies":str(dependencies),"checkout":str(source),
                                  "runtime_root":str(runtime),"runtime_sha256":"a"*64},
                           pins={"pyproject.toml":source_manifest["files"][0]["sha256"]})
    return policy,root,source,runtime


def test_sealed_generation_selects_only_fixed_prepared_paths(tmp_path, monkeypatch):
    policy,root,_,_=binding(tmp_path,monkeypatch)
    result=prepared.inputs(policy.profile)
    assert result=={"dist":root/"archives","installed_site":root/"installed","dependency_site":root.parent,"extracted":root/"extracted"}
    assert not {"checker_output","returncode","passed","restart_oracle"}&result.keys()
