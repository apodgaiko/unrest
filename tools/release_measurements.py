"""Deterministic static measurements for the Lean Core release report."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from pathlib import Path


C901 = re.compile(
    r"^(?P<path>.+?):(?P<line>\d+):\d+: C901 `(?P<name>[^`]+)` is too complex "
    r"\((?P<complexity>\d+) > 0\)$"
)


def _as_int(value: object) -> int:
    if not isinstance(value, int):
        raise TypeError(f"expected integer measurement, got {value!r}")
    return value


def python_inventory(root: Path, directories: tuple[str, ...]) -> list[dict[str, object]]:
    files = sorted(
        (path for directory in directories for path in (root / directory).rglob("*.py")),
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "lines": len(path.read_bytes().splitlines()),
        }
        for path in files
        if path.is_file() and not path.is_symlink()
    ]


def largest_functions(root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted((root / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                assert node.end_lineno is not None
                rows.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "line": node.lineno,
                        "name": node.name,
                        "lines": node.end_lineno - node.lineno + 1,
                    }
                )
    rows.sort(
        key=lambda row: (-_as_int(row["lines"]), str(row["path"]), _as_int(row["line"]))
    )
    return rows[:5]


def c901(root: Path) -> list[dict[str, object]]:
    completed = subprocess.run(
        (
            "uv",
            "run",
            "ruff",
            "check",
            "--output-format",
            "concise",
            "--select",
            "C901",
            "--config",
            "lint.mccabe.max-complexity=0",
            str(root / "src"),
        ),
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    rows: list[dict[str, object]] = []
    for line in completed.stdout.splitlines():
        match = C901.match(line)
        if match is None:
            continue
        path = Path(match.group("path"))
        relative = path.relative_to(root) if path.is_absolute() else path
        rows.append(
            {
                "path": relative.as_posix(),
                "line": int(match.group("line")),
                "name": match.group("name"),
                "complexity": int(match.group("complexity")),
            }
        )
    rows.sort(
        key=lambda row: (
            -_as_int(row["complexity"]),
            str(row["path"]),
            _as_int(row["line"]),
        )
    )
    if len(rows) < 5:
        raise RuntimeError(f"C901 analyzer returned only {len(rows)} rows: {completed.stderr}")
    return rows[:5]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    production = python_inventory(root, ("src",))
    maintained = python_inventory(root, ("src", "tests", "tools"))
    result = {
        "root": str(root),
        "production_inventory": production,
        "production_lines": sum(_as_int(row["lines"]) for row in production),
        "maintained_inventory": maintained,
        "maintained_lines": sum(_as_int(row["lines"]) for row in maintained),
        "largest_functions": largest_functions(root),
        "c901_top_five": c901(root),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
