"""Conservative guard footprint: every .github file, tests reported separately.

An external dependency-closure review remains mandatory: this counter cannot
decide whether a product helper secretly implements enforcement for its caller.
Both legacy and replacement implementation count until legacy files are removed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Sequence, TypedDict

from content_manifest import Refused, capture, encode, measure_lines

LIMIT = 10_000
# This existing oracle checks release results; it grants no execution authority.
# Its optional process-transport seam and complete bytes remain in the report.
RETAINED_TEST_SUPPORT = frozenset({'tools/check_distribution.py'})


class Row(TypedDict):
    path: str
    category: str
    lines: int
    sha256: str


def measure(root: Path, inventory: Sequence[str], extra_support: Sequence[str] = (),
            test_support: Sequence[str] = ()) -> dict:
    """Measure all supplied .github files plus explicitly audited external support."""
    if (len(set(inventory)) != len(inventory) or len(set(extra_support)) != len(extra_support)
            or len(set(test_support)) != len(test_support)):
        raise Refused("duplicate_budget_path")
    if not set(test_support)<=RETAINED_TEST_SUPPORT or set(test_support)&set(extra_support):
        raise Refused('unreviewed_or_conflicting_test_support')
    selected = sorted(set(name for name in inventory if name.startswith(".github/"))
                      | set(extra_support) | set(test_support))
    if not (set(extra_support) | set(test_support)) <= set(inventory):
        raise Refused("support_outside_inventory")
    manifest, counts = measure_lines(root, selected)
    rows: list[Row] = []
    for member in manifest["files"]:
        is_test = (Path(member["path"]).name.startswith("test_")
                   and Path(member["path"]).suffix == ".py")
        # External helpers are enforcement even when their filename says test.
        category = "test" if is_test and member["path"] not in extra_support else "enforcement"
        if member['path'] in test_support:
            category='test-support'
        rows.append({"path": member["path"], "category": category,
                     "lines": counts[member["path"]], "sha256": member["sha256"]})
    if capture(root, selected) != manifest:
        raise Refused("budget_snapshot_drift")
    implementation = sum(row["lines"] for row in rows if row["category"] == "enforcement")
    retained=sum(row['lines'] for row in rows if row['category']=='test-support')
    return {"schema": "unrest.guard-size.v2", "limit": LIMIT,
            "enforcement_lines": implementation,
            'retained_test_support_lines':retained,
            'combined_enforcement_and_test_support_lines':implementation+retained,
            "test_lines": sum(row["lines"] for row in rows if row["category"] == "test"),
            "within_budget": implementation <= LIMIT,
            "dependency_closure_verified": False, "release_certified": False,
            "content_sha256": hashlib.sha256(encode(manifest)).hexdigest(), "files": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--support", action="append", default=[])
    parser.add_argument('--test-support',action='append',choices=sorted(RETAINED_TEST_SUPPORT),default=[])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    result = subprocess.run(["git", "-C", str(root), "ls-files", "--cached", "--others",
                             "--exclude-standard", "-z"], check=True, capture_output=True)
    names = [name.decode("utf-8") for name in result.stdout.split(b"\0") if name]
    report = measure(root, names, args.support,args.test_support)
    print(json.dumps(report, sort_keys=True, indent=2))
    return int(args.check and not report["within_budget"])


if __name__ == "__main__":
    raise SystemExit(main())
