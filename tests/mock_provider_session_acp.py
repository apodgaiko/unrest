#!/usr/bin/env python3
"""Hermetic ACP adapter used by provider-session boundary tests."""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def _response(request_id: object, result: object) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        stopped_path = Path(sys.argv[2])

        def record_stop(_signum: int, _frame: object) -> None:
            stopped_path.write_text("stopped", encoding="utf-8")
            raise SystemExit(0)

        signal.signal(signal.SIGTERM, record_stop)
        while True:
            time.sleep(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--child-pid-path")
    parser.add_argument("--child-stop-path")
    parser.add_argument("--echo-credential")
    parser.add_argument("--invalid", action="store_true")
    parser.add_argument("--payload-size", type=int, default=0)
    parser.add_argument("--sleep", type=float, default=0)
    parser.add_argument("--stderr-size", type=int, default=0)
    parser.add_argument("--stop-reason", default="end_turn")
    args = parser.parse_args()

    child: subprocess.Popen[bytes] | None = None
    if args.child_pid_path:
        if not args.child_stop_path:
            raise ValueError("--child-stop-path is required with --child-pid-path")
        child = subprocess.Popen(
            [sys.executable, __file__, "--child", args.child_stop_path],
        )
        Path(args.child_pid_path).write_text(str(child.pid), encoding="utf-8")

    try:
        for line in sys.stdin:
            message = json.loads(line)
            request_id = message.get("id")
            method = message.get("method")
            if method == "initialize":
                result: object = {
                    "protocolVersion": 1,
                    "agentCapabilities": {"loadSession": False},
                    "authMethods": [],
                }
            elif method == "session/new":
                result = {"sessionId": "private-session-id"}
            elif method == "session/prompt":
                if args.sleep:
                    time.sleep(args.sleep)
                if args.stderr_size:
                    sys.stderr.write("s" * args.stderr_size)
                    sys.stderr.flush()
                if args.invalid:
                    output = "not-json"
                else:
                    answer = "x" * args.payload_size
                    if args.echo_credential:
                        answer = os.environ.get(args.echo_credential, "missing")
                    output = json.dumps({"answer": answer})
                midpoint = max(1, len(output) // 2)
                for chunk in (output[:midpoint], output[midpoint:]):
                    update = {
                        "jsonrpc": "2.0",
                        "method": "session/update",
                        "params": {
                            "sessionId": "private-session-id",
                            "update": {
                                "sessionUpdate": "agent_message_chunk",
                                "messageId": "answer",
                                "content": [{"type": "text", "text": chunk}],
                            },
                        },
                    }
                    sys.stdout.write(json.dumps(update) + "\n")
                result = {"stopReason": args.stop_reason}
            else:
                result = {}
            sys.stdout.write(json.dumps(_response(request_id, result)) + "\n")
            sys.stdout.flush()
    finally:
        if child is not None and child.poll() is None:
            child.terminate()


if __name__ == "__main__":
    main()
