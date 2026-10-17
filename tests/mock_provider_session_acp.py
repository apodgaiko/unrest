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
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--oversize-credential", action="store_true")
    parser.add_argument("--payload-size", type=int, default=0)
    parser.add_argument("--sleep", type=float, default=0)
    parser.add_argument("--stderr-size", type=int, default=0)
    parser.add_argument("--stop-reason", default="end_turn")
    args = parser.parse_args()

    owner: _ChildOwner | None = None
    if args.child_pid_path:
        if not args.child_stop_path:
            raise ValueError("--child-stop-path is required with --child-pid-path")
        owner = _ChildOwner()
        signal.signal(signal.SIGTERM, owner.handle_sigterm)
        owner.child = subprocess.Popen(
            [sys.executable, __file__, "--child", args.child_stop_path],
        )
        if owner.termination_requested:
            owner.cleanup()
        Path(args.child_pid_path).write_text(str(owner.child.pid), encoding="utf-8")

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
                if args.progress:
                    progress = {
                        "jsonrpc": "2.0",
                        "method": "session/update",
                        "params": {
                            "sessionId": "private-session-id",
                            "update": {
                                "sessionUpdate": "agent_message_chunk",
                                "messageId": "progress",
                                "content": [{"type": "text", "text": "Inspecting the source.\n"}],
                            },
                        },
                    }
                    sys.stdout.write(json.dumps(progress) + "\n")
                midpoint = max(1, len(output) // 2)
                chunks = (output[:midpoint], output[midpoint:])
                if args.oversize_credential:
                    secret = os.environ.get("ANTHROPIC_API_KEY", "missing")
                    chunks = (output, " ".join([secret] * 700))
                for chunk in chunks:
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
        if owner is not None:
            owner.cleanup()


class _ChildOwner:
    """Retain one reap sequence even when SIGTERM interrupts ordinary cleanup."""

    def __init__(self, child: subprocess.Popen[bytes] | None = None) -> None:
        self.child = child
        self.cleaning = False
        self.waited = False
        self.termination_requested = False

    def handle_sigterm(self, _signum: int, _frame: object) -> None:
        # Ignore subsequent signals before any potentially interruptible wait.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        self.termination_requested = True
        if self.child is not None:
            self.cleanup()

    def cleanup(self) -> None:
        if self.cleaning or self.child is None:
            return
        self.cleaning = True
        try:
            if not self.waited:
                try:
                    self.child.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    try:
                        self.child.terminate()
                    except ProcessLookupError:
                        pass  # Exit raced with terminate; the owned handle still needs a wait.
                    try:
                        self.child.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        try:
                            self.child.kill()
                        except ProcessLookupError:
                            pass
                        self.child.wait(timeout=0.5)
                self.waited = True
        finally:
            self.cleaning = False
        if self.termination_requested:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            os.kill(os.getpid(), signal.SIGTERM)


if __name__ == "__main__":
    main()
