"""Prepared artifacts are byte-bound inputs, never completed test observations."""
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from content_manifest import Refused, capture
import prepared_distribution as prepared


def binding(tmp_path, monkeypatch):
    monkeypatch.setattr(prepared, "OWNER", os.getuid())
    source=tmp_path/"source"
    source.mkdir()
    (source/"pyproject.toml").write_text("candidate source")
    runtime=tmp_path/"runtime"
    (runtime/"bin").mkdir(parents=True)
    (runtime/"bin/uv").write_bytes(b"stock uv")
    dependencies=tmp_path/"dependencies"
    root=dependencies/prepared.NAME
    for name in ("backend", "archives", "installed"):
        (root/name).mkdir(parents=True)
        (root/name/"member").write_bytes(name.encode())
    source_manifest=capture(source,["pyproject.toml"])
    receipt={"schema":"unrest.prepared-distribution.v1", "source":source_manifest,
             "uv":hashlib.sha256(b"stock uv").hexdigest(), "runtime":"a"*64,
             **{name:capture(root/name,["member"]) for name in ("backend","archives","installed")}}
    (root/"receipt.json").write_bytes(json.dumps(receipt,sort_keys=True).encode())
    (root/"receipt.json").chmod(0o644)
    policy=SimpleNamespace(profile={"dependencies":str(dependencies),"checkout":str(source),
                                  "runtime_root":str(runtime),"runtime_sha256":"a"*64},
                           pins={"pyproject.toml":source_manifest["files"][0]["sha256"]})
    return policy,root,source,runtime


def test_real_content_measurements_select_only_fixed_prepared_paths(tmp_path, monkeypatch):
    policy,root,_,_=binding(tmp_path,monkeypatch)
    result=prepared.inputs(policy)
    assert result=={"dist":root/"archives","installed_site":root/"installed","dependency_site":root.parent}
    assert not {"checker_output","returncode","passed","restart_oracle"}&result.keys()


@pytest.mark.parametrize("mutation", ["source", "pins", "tool", "runtime", "backend", "archives", "installed", "extra", "link", "receipt"])
def test_modified_or_unrelated_inputs_are_not_reused(tmp_path,monkeypatch,mutation):
    policy,root,source,runtime=binding(tmp_path,monkeypatch)
    if mutation=="source":
        (source/"pyproject.toml").write_text("changed")
    elif mutation=="pins":
        policy.pins={}
    elif mutation=="tool":
        (runtime/"bin/uv").write_bytes(b"foreign uv")
    elif mutation=="runtime":
        policy.profile["runtime_sha256"]="b"*64
    elif mutation in ("backend","archives","installed"):
        (root/mutation/"member").write_bytes(b"changed")
    elif mutation=="extra":
        (root/"installed/foreign").write_bytes(b"extra")
    elif mutation=="link":
        (root/"installed/foreign").symlink_to(source/"pyproject.toml")
    else:
        document=json.loads((root/"receipt.json").read_bytes())
        document["checker_output"]="fabricated success"
        (root/"receipt.json").write_bytes(json.dumps(document,sort_keys=True).encode())
    with pytest.raises(Refused):
        prepared.inputs(policy)
