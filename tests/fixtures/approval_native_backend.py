"""Controlled native backend. No model, external provider, approval marker or action execution."""

import json
import os
from pathlib import Path
import sys
import time

MODE = os.environ.get("CONTROLLED_APPROVAL_MODE", "success")
TRACE = os.environ.get("CONTROLLED_APPROVAL_TRACE")
turn = 0
pending_turn = None
queued = False


def send(value):
    print(json.dumps(value), flush=True)


def note(method):
    if TRACE:
        with Path(TRACE).open("a") as stream:
            stream.write(json.dumps({"method": method, "pid": os.getpid(), "turn": turn}) + "\n")


def event(status, suffix="1"):
    value = {
        "threadId": "thread-1",
        "turnId": "turn-" + str(turn),
        "reviewId": "review-" + suffix,
        "startedAtMs": 1,
        "targetItemId": None,
        "review": {
            "status": status,
            "riskLevel": "low",
            "userAuthorization": "low",
            "rationale": "private-rationale-CANARY",
        },
        "action": {
            "type": "command",
            "source": "shell",
            "command": "printf approval-CANARY",
            "cwd": "/private/tmp",
        },
    }
    if status != "inProgress":
        value.update(completedAtMs=2, decisionSource="agent")
    return value


for line in sys.stdin:
    frame = json.loads(line)
    method = frame.get("method")
    note(method)
    params = frame.get("params", {})
    result = {}
    if method == "initialize":
        result = {"userAgent": "controlled-no-provider"}
    elif method == "account/read":
        result = {"account": None, "requiresOpenaiAuth": False}
    elif method in ("model/list", "skills/list", "mcpServerStatus/list"):
        result = {"data": [], "nextCursor": None}
        if method == "model/list":
            result["data"] = [
                {
                    "id": "controlled",
                    "model": "controlled",
                    "displayName": "Controlled",
                    "description": "No provider",
                    "isDefault": True,
                    "defaultReasoningEffort": "medium",
                    "supportedReasoningEfforts": [
                        {"reasoningEffort": "medium", "description": "Controlled"}
                    ],
                }
            ]
    elif method == "config/read":
        result = {"config": {}, "origins": {}, "layers": []}
    elif method == "configRequirements/read":
        result = {"requirements": None}
    elif method == "thread/start":
        result = {
            "thread": {"id": "thread-1"},
            "model": "controlled",
            "modelProvider": "controlled",
            "reasoningEffort": "medium",
        }
        send({"method": "thread/started", "params": {"thread": {"id": "thread-1"}}})
    elif method == "turn/start":
        assert params["threadId"] == "thread-1"
        turn += 1
        pending_turn = "turn-" + str(turn)
        result = {"turn": {"id": pending_turn}}
        send({"id": frame["id"], "result": result})
        send(
            {
                "method": "turn/started",
                "params": {"threadId": "thread-1", "turn": {"id": pending_turn}},
            }
        )
        if turn == 1 or MODE == "re_denied":
            send({"method": "item/autoApprovalReview/started", "params": event("inProgress")})
            send({"method": "item/autoApprovalReview/completed", "params": event("denied")})
            if MODE == "outstanding":
                send({"id": "unresolved-callback", "method": "controlled/callback", "params": {}})
            if MODE == "multiple":
                send(
                    {
                        "method": "item/autoApprovalReview/started",
                        "params": event("inProgress", "2"),
                    }
                )
                send(
                    {"method": "item/autoApprovalReview/completed", "params": event("denied", "2")}
                )
        else:
            assert queued
            note("ordered-handler-completed")
            if MODE == "continuation_hold":
                continue
            send(
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": pending_turn, "status": "completed", "error": None},
                    },
                }
            )
            pending_turn = None
        continue
    elif method == "turn/interrupt":
        if MODE == "failed_interrupt":
            send({"id": frame["id"], "error": {"code": -1, "message": "controlled"}})
            continue
        if MODE == "delayed_interrupt":
            time.sleep(0.2)
        if pending_turn is not None:
            send(
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": pending_turn, "status": "interrupted", "error": None},
                    },
                }
            )
            pending_turn = None
    elif method == "thread/approveGuardianDeniedAction":
        assert not pending_turn and not queued
        assert params == {
            "threadId": "thread-1",
            "event": {
                "id": "review-1",
                "turn_id": "turn-1",
                "started_at_ms": 1,
                "completed_at_ms": 2,
                "status": "denied",
                "risk_level": "low",
                "user_authorization": "low",
                "rationale": "private-rationale-CANARY",
                "decision_source": "agent",
                "action": {
                    "type": "command",
                    "source": "shell",
                    "command": "printf approval-CANARY",
                    "cwd": "/private/tmp",
                },
            },
        }
        if MODE == "crash_after_send":
            os._exit(17)
        if MODE == "late_ack":
            time.sleep(6)
        if MODE == "drop_ack":
            continue
        send({"id": frame["id"], "result": {}})
        # Native ACK precedes processing. The serialized handler completes
        # before the next queued TurnInput; this is not execution evidence.
        time.sleep(0.15)
        queued = True
        note("override-handler-completed")
        continue
    if "id" in frame:
        send({"id": frame["id"], "result": result})
