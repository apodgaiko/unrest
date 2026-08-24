#!/usr/bin/env python3
"""Deterministic ACP fixture for the genuine FM-010 Mission test path."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _reply(request_id: object, result: object) -> None:
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)


def _handoff() -> None:
    path = Path(os.environ["UNREST_HANDOFF_PATH"])
    node_id = os.environ["UNREST_NODE_ID"]
    node_type = os.environ["UNREST_NODE_TYPE"]
    attempt_id = path.stem.split("__", 1)[0]
    if node_type == "work":
        workspace = Path.cwd()
        if node_id == "p1-work":
            (workspace / "artifact.txt").write_text("unrest baseline p1\n")
        elif node_id == "p2-initial-work":
            (workspace / "artifact.txt").write_text("p2: rejected\n")
        elif node_id == "p2-corrected-work":
            (workspace / "artifact.txt").write_text("unrest baseline p2\n")
        payload = {
            "attempt_id": attempt_id,
            "done": True,
            "node_id": node_id,
            "report": "measurement work complete",
            "request_attention": False,
        }
    else:
        passed = node_id != "p2-initial-validate"
        item_id = "VAL-MEASURE-REJECT" if node_id == "p2-initial-validate" else "VAL-MEASURE"
        payload = {
            "attempt_id": attempt_id,
            "done": True,
            "items": [{"item_id": item_id, "passed": passed}],
            "node_id": node_id,
            "passed": passed,
            "report": "measurement validator fixture",
            "request_attention": False,
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def main() -> None:
    for line in sys.stdin:
        message = json.loads(line)
        request_id = message.get("id")
        method = message.get("method")
        if method == "initialize":
            _reply(request_id, {"protocolVersion": 1, "agentCapabilities": {}, "authMethods": []})
        elif method == "session/new":
            _reply(request_id, {"sessionId": "measurement-fixture"})
        elif method == "session/set_mode":
            _reply(request_id, {})
        elif method == "session/prompt":
            _handoff()
            _reply(
                request_id,
                {
                    "stopReason": "end_turn",
                    "usage": {
                        "cacheStatus": "disabled",
                        "inputTokens": 1,
                        "model": "local-fixture",
                        "outputTokens": 1,
                        "reportedCostUsd": 0.0,
                    },
                },
            )
        else:
            _reply(request_id, {})


if __name__ == "__main__":
    main()
