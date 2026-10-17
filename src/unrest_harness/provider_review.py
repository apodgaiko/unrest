"""Private, bounded Guardian capture for the Codex ACP 1.1.0 transport.

This is a denial latch, never an authorization or native-appeal implementation.
Only the transport reader feeds it; tool results and prose are not traversed.
"""
from __future__ import annotations

import re
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from .models import ValidateHandoff, WorkHandoff

ReviewStatus = Literal["inProgress", "approved", "denied", "timedOut", "aborted"]
BlockReason = Literal["denied", "invalid_context", "persistence_unavailable", "interrupted"]
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
MAX_REVIEWS = 64
EXPLANATION = (
    "Provider review blocked this attempt. Recorded prose consent is not a provider override. "
    "Native exact-action recovery is unavailable pending supported appeal integration. "
    "Continue, retry and steering do not authorize replay. Independent repair work may be "
    "planned while preserving this block."
)


def identity(value: object) -> str:
    if not isinstance(value, str) or IDENTITY.fullmatch(value) is None:
        raise ValueError("invalid review identity")
    return value


def _valid_action(action: Any) -> bool:
    if not isinstance(action, dict):
        return False
    kind = action.get("type")
    layouts = {
        "command": ({"source", "command", "cwd"}, {"command", "cwd"}, set(), set()),
        "execve": ({"source", "program", "argv", "cwd"}, {"program", "cwd"}, {"argv"}, set()),
        "writeStdin": ({"approvalId", "processId", "stdin", "cwd"},
                       {"approvalId", "processId", "stdin", "cwd"}, set(), set()),
        "applyPatch": ({"cwd", "files"}, {"cwd"}, {"files"}, set()),
        "networkAccess": ({"target", "host", "protocol", "port"},
                          {"target", "host", "protocol"}, set(), set()),
        "mcpToolCall": ({"server", "toolName", "connectorId", "connectorName", "toolTitle"},
                        {"server", "toolName"}, set(), {"connectorId", "connectorName", "toolTitle"}),
        "requestPermissions": ({"reason", "permissions"}, set(), set(), {"reason"}),
    }
    if not isinstance(kind, str) or kind not in layouts:
        return False
    keys, strings, arrays, nullable = layouts[kind]
    if set(action) != keys | {"type"}:
        return False
    if any(not isinstance(action[key], str) for key in strings):
        return False
    if any(action[key] is not None and not isinstance(action[key], str) for key in nullable):
        return False
    if any(not isinstance(action[key], list)
           or any(not isinstance(item, str) for item in action[key]) for key in arrays):
        return False
    if kind in ("command", "execve") and action["source"] not in ("shell", "unifiedExec"):
        return False
    if kind == "networkAccess":
        return (action["protocol"] in ("http", "https", "socks5Tcp", "socks5Udp")
                and type(action["port"]) is int and 0 <= action["port"] <= 65535)
    if kind == "requestPermissions":
        permissions = action["permissions"]
        if not isinstance(permissions, dict) or set(permissions) != {"network", "fileSystem"}:
            return False
        network = permissions["network"]
        if network is not None and (
            not isinstance(network, dict) or set(network) != {"enabled"}
            or (network["enabled"] is not None and type(network["enabled"]) is not bool)
        ):
            return False
        filesystem = permissions["fileSystem"]
        if filesystem is not None:
            if (not isinstance(filesystem, dict) or not {"read", "write"} <= set(filesystem)
                    or set(filesystem) - {"read", "write", "globScanMaxDepth", "entries"}):
                return False
            for key in ("read", "write"):
                value = filesystem[key]
                if value is not None and (
                    not isinstance(value, list) or any(not isinstance(item, str) for item in value)
                ):
                    return False
            if "globScanMaxDepth" in filesystem and (
                type(filesystem["globScanMaxDepth"]) is not int or filesystem["globScanMaxDepth"] < 0
            ):
                return False
            if "entries" in filesystem:
                if not isinstance(filesystem["entries"], list):
                    return False
                for entry in filesystem["entries"]:
                    if (not isinstance(entry, dict) or set(entry) != {"path", "access"}
                            or entry["access"] not in ("read", "write", "deny")
                            or not _valid_filesystem_path(entry["path"])):
                        return False
    return True


def _valid_filesystem_path(path: Any) -> bool:
    if not isinstance(path, dict):
        return False
    kind = path.get("type")
    if kind in ("path", "glob_pattern"):
        key = "path" if kind == "path" else "pattern"
        return set(path) == {"type", key} and isinstance(path[key], str)
    if kind != "special" or set(path) != {"type", "value"}:
        return False
    value = path["value"]
    if not isinstance(value, dict):
        return False
    special = value.get("kind")
    if special in ("root", "minimal", "tmpdir", "slash_tmp"):
        return set(value) == {"kind"}
    if special == "project_roots":
        return set(value) == {"kind", "subpath"} and (
            value["subpath"] is None or isinstance(value["subpath"], str)
        )
    if special == "unknown":
        return set(value) == {"kind", "path", "subpath"} and isinstance(value["path"], str) and (
            value["subpath"] is None or isinstance(value["subpath"], str)
        )
    return False


@dataclass(frozen=True)
class ReviewIdentity:
    thread_id: str
    turn_id: str
    review_id: str


@dataclass(frozen=True)
class ProviderReviewBlock:
    reason: BlockReason
    review: ReviewIdentity | None = None


@dataclass
class ProviderReviewCapture:
    """A single fresh prompt bound to an already-created provider session."""

    session_id: str
    publish: Callable[[ProviderReviewBlock], None]
    credentials: tuple[str, ...] = field(default=(), repr=False)
    blocked: ProviderReviewBlock | None = None
    _reviews: dict[str, tuple[ReviewIdentity, str]] = field(default_factory=dict)
    _turn_id: str | None = None
    _signatures: dict[str, tuple[str, str]] = field(default_factory=dict)

    def _block(self, reason: BlockReason, review: ReviewIdentity | None = None) -> None:
        if self.blocked is not None:
            return
        self.blocked = ProviderReviewBlock(reason, review)
        try:
            self.publish(self.blocked)
        except Exception:  # persistence failure must not escape into a swallowed observer
            self.blocked = ProviderReviewBlock("persistence_unavailable", review)

    def transport_invalid(self) -> None:
        self._block("invalid_context")

    def _recognizes(self, update: Any) -> bool:
        if not isinstance(update, dict):
            return False
        call_id = update.get("toolCallId")
        prefixed = isinstance(call_id, str) and call_id.startswith("guardian_assessment:")
        titled = update.get("kind") == "think" and update.get("title") == "Guardian Review"
        direct = any(isinstance(update.get(key), dict)
                     and {"reviewId", "review"} <= update[key].keys()
                     for key in ("rawInput", "rawOutput"))
        # Wrappers carry untrusted tool data. Conflicting direct managed signals,
        # however, must reach validation rather than taking this exclusion.
        raw_input = update.get("rawInput")
        raw_output = update.get("rawOutput")
        wrapper = (isinstance(raw_input, dict)
                   and set(raw_input) == {"server", "tool", "arguments"}) or (
                       isinstance(raw_output, dict) and set(raw_output) == {"result", "error"})
        if wrapper and not titled and not direct:
            return False
        known = isinstance(call_id, str) and call_id in self._reviews
        ordinary_creation = (update.get("sessionUpdate") == "tool_call"
                             and update.get("kind") == "other"
                             and update.get("title") != "Guardian Review"
                             and isinstance(raw_input, dict))
        return titled or direct or ((known or prefixed) and not ordinary_creation)

    def consume_frame(self, frame: dict[str, Any]) -> bool:
        """Recognize only fixed protocol positions, before RPC correlation."""
        params = frame.get("params")
        update = params.get("update") if isinstance(params, dict) else None
        if not self._recognizes(update):
            # Misplaced envelopes retain provenance only at these shallow positions.
            if self._recognizes(params) or self._recognizes(frame) or self._recognizes(
                frame.get("update")
            ):
                self._block("invalid_context")
                return True
            return False
        if (frame.get("jsonrpc") != "2.0" or frame.get("method") != "session/update"
                or any(key in frame for key in ("id", "result", "error"))):
            self._block("invalid_context")
        else:
            self.consume(params)
        return True

    def consume(self, params: Any) -> None:
        if not isinstance(params, dict):
            return
        update = params.get("update")
        if not isinstance(update, dict) or not self._recognizes(update):
            return
        kind = update.get("sessionUpdate")
        call_id = update.get("toolCallId")
        prefixed = isinstance(call_id, str) and call_id.startswith("guardian_assessment:")
        event = update.get("rawInput" if kind == "tool_call" else "rawOutput")
        try:
            if kind not in ("tool_call", "tool_call_update"):
                raise ValueError
            if kind == "tool_call_update" and (
                not isinstance(call_id, str) or call_id not in self._reviews
            ):
                raise ValueError
            if kind == "tool_call_update" and (
                ("kind" in update and update["kind"] != "think")
                or ("title" in update and update["title"] != "Guardian Review")
            ):
                raise ValueError
            if "rawInput" in update and kind == "tool_call_update":
                raise ValueError
            if "rawOutput" in update and kind == "tool_call":
                raise ValueError
            if not isinstance(call_id, str) or not prefixed:
                raise ValueError
            if kind == "tool_call" and (
                update.get("kind") != "think" or update.get("title") != "Guardian Review"
            ):
                raise ValueError
            if not isinstance(event, dict):
                raise ValueError
            if params.get("sessionId") != self.session_id:
                raise ValueError
            review_id = identity(event.get("reviewId"))
            thread_id = identity(event.get("threadId"))
            turn_id = identity(event.get("turnId"))
            if thread_id != self.session_id or call_id != f"guardian_assessment:{review_id}":
                raise ValueError
            supplied = (thread_id, turn_id, review_id)
            if any(secret and secret in item for secret in self.credentials for item in supplied):
                raise ValueError
            if self._turn_id is not None and self._turn_id != turn_id:
                raise ValueError
            required = {"threadId", "turnId", "reviewId", "startedAtMs", "targetItemId",
                        "review", "action"}
            completed = "completedAtMs" in event
            if completed:
                required |= {"completedAtMs", "decisionSource"}
            if set(event) != required:
                raise ValueError
            for name in ("startedAtMs", "completedAtMs") if completed else ("startedAtMs",):
                if type(event[name]) is not int or not 0 <= event[name] <= 2**53 - 1:
                    raise ValueError
            if completed and (event["decisionSource"] != "agent"
                              or event["completedAtMs"] < event["startedAtMs"]):
                raise ValueError
            if event["targetItemId"] is not None:
                identity(event["targetItemId"])
            review = event["review"]
            if not isinstance(review, dict) or set(review) != {
                "status", "riskLevel", "userAuthorization", "rationale"
            }:
                raise ValueError
            status = review["status"]
            if status not in ("inProgress", "approved", "denied", "timedOut", "aborted"):
                raise ValueError
            if completed == (status == "inProgress"):
                raise ValueError
            if review["riskLevel"] not in (None, "low", "medium", "high", "critical"):
                raise ValueError
            if review["userAuthorization"] not in (None, "unknown", "low", "medium", "high"):
                raise ValueError
            if review["rationale"] is not None and not isinstance(review["rationale"], str):
                raise ValueError
            action = event["action"]
            if not _valid_action(action):
                raise ValueError
            expected = "in_progress" if status == "inProgress" else (
                "completed" if status == "approved" else "failed"
            )
            if update.get("status") != expected:
                raise ValueError
            binding = ReviewIdentity(thread_id, turn_id, review_id)
            previous = self._reviews.get(call_id)
            if previous is not None and (
                previous[0] != binding or previous[1] not in ("inProgress", status)
            ):
                raise ValueError
            if previous is None and len(self._reviews) >= MAX_REVIEWS:
                raise ValueError
            # Ephemeral digests detect conflicting deliveries without retaining
            # action bodies in memory records or publishing payload-derived metadata.
            immutable = {key: event[key] for key in (
                "threadId", "turnId", "reviewId", "startedAtMs", "targetItemId", "action"
            )}
            origin_digest = hashlib.sha256(json.dumps(immutable, sort_keys=True).encode()).hexdigest()
            event_digest = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
            prior_signature = self._signatures.get(call_id)
            if prior_signature is not None and (
                prior_signature[0] != origin_digest
                or (previous is not None and previous[1] != "inProgress"
                    and prior_signature[1] != event_digest)
            ):
                raise ValueError
            self._signatures[call_id] = (origin_digest, event_digest)
            self._turn_id = turn_id
            self._reviews[call_id] = (binding, status)
            if status == "denied":
                self._block("denied", binding)
        except (ValueError, TypeError, KeyError):
            self._block("invalid_context")


def blocked_handoff(
    handoff: "WorkHandoff | ValidateHandoff", block: ProviderReviewBlock, attempt_id: str
) -> "WorkHandoff | ValidateHandoff":
    from .models import ValidateHandoff

    fields: dict[str, Any] = {
        "done": False, "request_attention": True, "attempt_id": attempt_id,
        "report": f"{EXPLANATION}\nReview outcome: {block.reason}.",
    }
    if isinstance(handoff, ValidateHandoff):
        fields.update(items=[], passed=False)
    return handoff.model_copy(update=fields)
