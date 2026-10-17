"""Private rust-v0.160.1 denial binding and conversion. Never a public RPC API."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import json
import re
import shlex
from typing import Any

from .provider_review import ProviderReviewCapture

MAX_EVENT_BYTES = 16384
MAX_DISPLAY_BYTES = 8192
# Bodies containing control characters are displayed with JSON escaping. Bidi
# controls are refused because an exact byte string can still mislead a viewer.
BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
SECRET = re.compile(
    r"(?i)(?:bearer\s+\S+|(?:password|passwd|secret|token|api[_-]?key)\s*[:=]|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-[A-Za-z0-9_-]{16,}|://[^/\s]+:[^/@\s]+@)"
)
CREDENTIAL_NAME = re.compile(
    r"(?i)(?:password|passwd|passphrase|secret|token|credential|"
    r"api[_-]?key|access[_-]?key|authorization|authentication|cookie)"
)
USER_OPTION = re.compile(r"(?i)^-+(?:user|username|proxy-user|login)(?:=|$)")


# This is a display grammar, not a general shell or credential detector. Unknown
# tools/options are refused: their operands may carry tool-specific credentials.
STATIC_OPTIONS: dict[str, tuple[str, frozenset[str]]] = {
    "echo": ("neE", frozenset()),
    "cat": ("bnsvETu", frozenset({"--number", "--show-all"})),
    "ls": ("alhRtdrS1", frozenset({"--all", "--human-readable"})),
    "pwd": ("LP", frozenset()),
    "curl": ("sSfLI", frozenset({"--silent", "--show-error", "--fail", "--location", "--head"})),
}
LOCALE_ASSIGNMENT = re.compile(r"^(?:LANG|LC_ALL)=(?:C|POSIX|C\.UTF-8|en_US\.UTF-8)$")
CREDENTIAL_SOURCE = re.compile(r"(?i)^(?:pass|env|file|fd|stdin):")
STATIC_URL = re.compile(r"^https?://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[^?#\s]*)?$")


def reviewable_words(words: list[str], *, shell_assignments: bool = False) -> bool:
    if not words or any(
        CREDENTIAL_NAME.search(word)
        or USER_OPTION.search(word)
        or CREDENTIAL_SOURCE.search(word)
        or re.search(r"://[^/\s]*@", word)
        for word in words
    ):
        return False
    while shell_assignments and words and LOCALE_ASSIGNMENT.fullmatch(words[0]):
        words = words[1:]
    if not words:
        return False
    program = words[0].rsplit("/", 1)[-1]
    arguments = words[1:]
    if program in ("true", "false"):
        return not arguments
    if program == "printf":
        # printf operands are literal format/values, not another program's CLI.
        # Option-like formats require an explicit end-of-options marker.
        return bool(arguments) and (arguments[0] == "--" or not arguments[0].startswith("-"))
    grammar = STATIC_OPTIONS.get(program)
    if grammar is None:
        return False
    short, long = grammar
    operands: list[str] = []
    options = True
    for argument in arguments:
        if options and argument == "--":
            options = False
        elif options and argument.startswith("--"):
            if argument not in long:
                return False
        elif options and argument.startswith("-") and argument != "-":
            # All admitted switches take no argument. Thus every character of
            # a cluster must be known; attached/separate credential options and
            # unknown argument-taking switches cannot hide an opaque operand.
            if any(character not in short for character in argument[1:]):
                return False
        else:
            operands.append(argument)
    if program == "curl":
        return bool(operands) and all(STATIC_URL.fullmatch(word) for word in operands)
    if program == "pwd":
        return not operands
    return True


def reviewable_shell(command: str) -> bool:
    # No expansion, nested evaluation, redirection, comments or multiline shell
    # grammar: quote removal is used only to inspect static simple commands.
    if any(character in command for character in ("$", "`", "\n", "\r", "#")):
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        segment: list[str] = []
        for word in lexer:
            if word in ("|", "&&", "||", ";"):
                if not reviewable_words(segment, shell_assignments=True):
                    return False
                segment = []
            elif any(character in word for character in "<>()&;"):
                return False
            else:
                segment.append(word)
        return reviewable_words(segment, shell_assignments=True)
    except ValueError:
        return False


class ApprovalUnavailable(ValueError):
    def __init__(self) -> None:
        super().__init__("approval recovery unavailable")


def serialized(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True, allow_nan=False
        ).encode()
    except (ValueError, TypeError, RecursionError):
        raise ApprovalUnavailable() from None


def native_event(event: dict[str, Any]) -> dict[str, Any]:
    """TUI protocol_requests.rs mapping; unsupported actions fail closed.

    Only command and execve provide complete action data in this notification.
    Patch contents and MCP arguments are absent; input/permission/path conversion
    requires additional provenance, so those variants cannot be appealed here.
    """
    capture = ProviderReviewCapture(event.get("threadId", ""), lambda _: None)
    capture.consume(
        {
            "sessionId": event.get("threadId"),
            "update": {
                "sessionUpdate": "tool_call",
                "toolCallId": "guardian_assessment:" + str(event.get("reviewId", "")),
                "kind": "think",
                "title": "Guardian Review",
                "status": "failed",
                "rawInput": event,
            },
        }
    )
    if capture.blocked is None or capture.blocked.reason != "denied":
        raise ApprovalUnavailable()
    if len(serialized(event)) > MAX_EVENT_BYTES:
        raise ApprovalUnavailable()
    action = deepcopy(event["action"])
    if action["type"] not in ("command", "execve"):
        raise ApprovalUnavailable()
    # Both supported native cwd representations require a local absolute path.
    # Never localize a remote URI or guess a relative path against another cwd.
    if not action["cwd"].startswith("/") or "\x00" in action["cwd"]:
        raise ApprovalUnavailable()
    if action["source"] == "unifiedExec":
        action["source"] = "unified_exec"
    result = {
        "id": event["reviewId"],
        "turn_id": event["turnId"],
        "started_at_ms": event["startedAtMs"],
        "completed_at_ms": event["completedAtMs"],
        "status": "denied",
        "decision_source": "agent",
        "action": action,
    }
    # The TUI deliberately omits target_item_id and optional plugin/model fields.
    for native, wire in (
        ("risk_level", "riskLevel"),
        ("user_authorization", "userAuthorization"),
        ("rationale", "rationale"),
    ):
        if event["review"][wire] is not None:
            result[native] = event["review"][wire]
    return result


def human_display(event: dict[str, Any], credentials: tuple[str, ...]) -> str:
    native_event(event)
    context = {key: event[key] for key in ("threadId", "turnId", "reviewId", "targetItemId")}
    value = {"action": event["action"], "context": context}
    raw = serialized(value)
    if len(raw) > MAX_DISPLAY_BYTES:
        raise ApprovalUnavailable()
    text = raw.decode()

    # Check the unescaped representation too, including credentials crossing
    # JSON field boundaries only where an actual single captured string exists.
    def safe(item: Any) -> bool:
        if isinstance(item, str):
            return not (
                BIDI.search(item)
                or SECRET.search(item)
                or any(secret and secret in item for secret in credentials)
                or any(ord(c) < 32 and c not in "\n\r\t" for c in item)
            )
        if isinstance(item, list):
            return all(safe(part) for part in item)
        if isinstance(item, dict):
            return all(safe(part) for part in item.values())
        return True

    if not safe(value):
        raise ApprovalUnavailable()
    action = event["action"]
    if action["type"] == "command":
        reviewable = reviewable_shell(action["command"])
    else:
        # Native execve argv includes argv[0]. Refuse a missing/mismatched
        # executable name rather than guess argument offsets. No shell wrapper
        # is admitted; literal operands keep their original JSON boundaries.
        argv = action["argv"]
        program = action["program"].rsplit("/", 1)[-1]
        reviewable = bool(argv) and argv[0].rsplit("/", 1)[-1] == program
        reviewable = reviewable and reviewable_words([action["program"], *argv[1:]])
    if not reviewable:
        raise ApprovalUnavailable()
    return (
        "Review this exact provider-denied action and original context (JSON strings are escaped):\n"
        + text
        + "\nConfirm ONE native submission and at most ONE continuation in this same "
        "thread, still subject to provider review. Acknowledgement does not prove execution."
    )


@dataclass
class NativeBinding:
    """Fed exclusively by the original backend's reader, never ACP/tool content."""

    thread_id: str | None = None
    turn_id: str | None = None
    settled: bool = False
    invalid: bool = False
    event: dict[str, Any] | None = field(default=None, repr=False)
    _started: dict[str, bytes] = field(default_factory=dict, repr=False)
    _count: int = 0

    def consume(self, frame: dict[str, Any]) -> None:
        method = frame.get("method")
        params = frame.get("params")
        if not isinstance(params, dict):
            return
        try:
            if method == "thread/started":
                thread = params["thread"]["id"]
                if self.thread_id is not None and thread != self.thread_id:
                    raise ApprovalUnavailable()
                self.thread_id = thread
            elif method == "turn/started":
                if params["threadId"] != self.thread_id or not self.settled and self.turn_id:
                    raise ApprovalUnavailable()
                self.turn_id = params["turn"]["id"]
                self.settled = False
            elif method == "turn/completed":
                if params["threadId"] != self.thread_id or params["turn"]["id"] != self.turn_id:
                    raise ApprovalUnavailable()
                self.settled = True
            elif method in ("item/autoApprovalReview/started", "item/autoApprovalReview/completed"):
                if "id" in frame or "result" in frame or "error" in frame:
                    raise ApprovalUnavailable()
                if params["threadId"] != self.thread_id or params["turnId"] != self.turn_id:
                    raise ApprovalUnavailable()
                event = deepcopy(params)
                # Existing closed ACP validator also validates native notification
                # shape; its event payload is identical in the pinned adapter.
                capture = ProviderReviewCapture(self.thread_id or "", lambda _: None)
                status = event["review"]["status"]
                capture.consume(
                    {
                        "sessionId": self.thread_id,
                        "update": {
                            "sessionUpdate": "tool_call",
                            "kind": "think",
                            "title": "Guardian Review",
                            "toolCallId": "guardian_assessment:" + event["reviewId"],
                            "status": "in_progress"
                            if status == "inProgress"
                            else "completed"
                            if status == "approved"
                            else "failed",
                            "rawInput": event,
                        },
                    }
                )
                if capture.blocked is not None and capture.blocked.reason != "denied":
                    raise ApprovalUnavailable()
                immutable = serialized(
                    {
                        key: event[key]
                        for key in (
                            "threadId",
                            "turnId",
                            "reviewId",
                            "startedAtMs",
                            "targetItemId",
                            "action",
                        )
                    }
                )
                if len(serialized(event)) > MAX_EVENT_BYTES:
                    raise ApprovalUnavailable()
                key = event["reviewId"]
                if method.endswith("/started"):
                    if status != "inProgress" or key in self._started or len(self._started) >= 64:
                        raise ApprovalUnavailable()
                    self._started[key] = immutable
                else:
                    if self._started.pop(key, None) != immutable or status == "inProgress":
                        raise ApprovalUnavailable()
                    if status == "denied":
                        self._count += 1
                        if self._count != 1:
                            raise ApprovalUnavailable()
                        native_event(event)
                        self.event = event
        except (KeyError, TypeError, ValueError, RecursionError):
            self.invalid = True
            self.erase()

    def erase(self) -> None:
        self.event = None
        self._started.clear()
