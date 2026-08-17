"""Generate legacy handoff fixtures through a tracked reference checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


REFERENCE_COMMIT = "93c59e4378407f3d7cfb918cf86c8bdc81daa141"
REFERENCE_TREE = "35152a4a8c56198664f519691ec952ec9ca519f4"
GENERATOR_COMMAND = (
    "uv run python tools/generate_legacy_handoff_fixtures.py "
    "--reference-checkout <reference-checkout> --output-dir <output-dir>"
)
INPUTS: tuple[dict[str, Any], ...] = (
    {
        "filename": "legacy-work-handoff.json",
        "environment": {"UNREST_NODE_ID": "w1", "UNREST_NODE_TYPE": "work"},
        "arguments": {"done": True, "report": "ok"},
    },
    {
        "filename": "legacy-validation-handoff.json",
        "environment": {"UNREST_NODE_ID": "v1", "UNREST_NODE_TYPE": "validate"},
        "arguments": {
            "done": True,
            "report": "audited",
            "items": [{"item_id": "VAL-001", "passed": True}],
            "passed": True,
        },
    },
)


def _git(reference: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(reference), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _generate(reference: Path, output: Path) -> None:
    script = r'''
import asyncio
import json
import os
from pathlib import Path

import unrest_harness.models as models_module
import unrest_harness.server as server_module
from unrest_harness.server import create_worker_server

output = Path(os.environ["UNREST_FIXTURE_OUTPUT"])
inputs = json.loads(os.environ["UNREST_FIXTURE_INPUTS"])
reference = Path(os.environ["UNREST_REFERENCE_CHECKOUT"])
assert Path(models_module.__file__).resolve() == reference / "src/unrest_harness/models.py"
assert Path(server_module.__file__).resolve() == reference / "src/unrest_harness/server.py"

async def main():
    server = create_worker_server()
    for item in inputs:
        os.environ.update(item["environment"])
        os.environ["UNREST_HANDOFF_PATH"] = str(output / item["filename"])
        await server.call_tool("end_node", item["arguments"])

asyncio.run(main())
'''
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(reference / "src")
    environment["UNREST_FIXTURE_OUTPUT"] = str(output)
    environment["UNREST_FIXTURE_INPUTS"] = json.dumps(INPUTS, separators=(",", ":"))
    environment["UNREST_REFERENCE_CHECKOUT"] = str(reference)
    subprocess.run(
        [sys.executable, "-c", script],
        cwd=reference,
        env=environment,
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-checkout", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reference = args.reference_checkout.resolve(strict=True)
    commit = _git(reference, "rev-parse", "HEAD")
    tree = _git(reference, "rev-parse", "HEAD^{tree}")
    dirty = _git(reference, "status", "--porcelain", "--untracked-files=no")
    if (commit, tree, dirty) != (REFERENCE_COMMIT, REFERENCE_TREE, ""):
        raise SystemExit(
            "reference checkout identity mismatch: "
            f"commit={commit!r} tree={tree!r} tracked_status={dirty!r}"
        )

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    _generate(reference, output)

    files = {
        item["filename"]: {
            "bytes": (path := output / item["filename"]).stat().st_size,
            "sha256": _sha256(path),
        }
        for item in INPUTS
    }
    transcript = {
        "schema_version": 1,
        "generator_command": GENERATOR_COMMAND,
        "reference": {
            "commit": commit,
            "tree": tree,
            "tracked_status": "clean",
            "models_path": "src/unrest_harness/models.py",
            "producer_path": "src/unrest_harness/server.py:create_worker_server/end_node",
        },
        "inputs": list(INPUTS),
        "outputs": files,
    }
    transcript_path = output / "generation-transcript.json"
    transcript_path.write_text(
        json.dumps(transcript, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(transcript, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
