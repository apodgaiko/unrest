from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import size_budget as budget


def tree(tmp_path, values):
    root = tmp_path.resolve()
    for name, body in values.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    return root, list(values)


def test_old_new_policy_workflows_and_blank_lines_all_count(tmp_path):
    root, paths = tree(
        tmp_path,
        {
            ".github/release-source-guard/old.py": b"# old\n\nx=1\n",
            ".github/release-guard/new.py": b"# new\nx=2\n",
            ".github/release-guard/policy.json": b'{\n"rule": "closed"\n}\n',
            ".github/workflows/ci.yml": b"name: CI\nrun: enforcement\n",
            ".github/release-source-guard/test_old.py": b"# preserved test\nassert True\n",
            "src/product.py": b"# unrelated product\n",
        },
    )
    report = budget.measure(root, paths)
    assert report["enforcement_lines"] == 10
    assert report["test_lines"] == 2
    assert report["within_budget"] is True
    assert report["dependency_closure_verified"] is False
    assert report["release_certified"] is False


def test_relocated_helpers_and_test_named_runtime_support_count(tmp_path, monkeypatch):
    root, paths = tree(
        tmp_path,
        {".github/release-guard/runtime.py": b"one\n", "tools/test_support.py": b"two\nthree\n"},
    )
    monkeypatch.setattr(budget, "LIMIT", 2)
    report = budget.measure(root, paths, ["tools/test_support.py"])
    assert report["enforcement_lines"] == 3
    assert report["test_lines"] == 0
    assert report["within_budget"] is False
    with pytest.raises(budget.Refused, match="support_outside_inventory"):
        budget.measure(root, paths, ["missing.py"])


def test_opaque_payload_and_duplicate_inventory_refuse(tmp_path):
    root, paths = tree(tmp_path, {".github/release-guard/packed.bin": b"\xff"})
    with pytest.raises(budget.Refused, match="opaque_guard_payload"):
        budget.measure(root, paths)
    with pytest.raises(budget.Refused, match="duplicate_budget_path"):
        budget.measure(root, paths + paths)


def test_external_distribution_oracle_always_counts_inside_release_budget(tmp_path,monkeypatch):
    root,paths=tree(tmp_path,{'.github/release-guard/runtime.py':b'policy\n',
                            'tools/check_distribution.py':b'original oracle\nretained assertions\n'})
    monkeypatch.setattr(budget,'LIMIT',1)
    report=budget.measure(root,paths,['tools/check_distribution.py'])
    assert report['enforcement_lines']==3 and not report['within_budget']
    assert all(row['category']=='enforcement' for row in report['files'])
    with pytest.raises(TypeError):
        budget.measure(root,paths,test_support=['tools/check_distribution.py'])
