"""Inert continuation value types and their closed canonical value codec v1.

The module defines three immutable values and a closed wire profile over the
unchanged foundation Canonical JSON v1 grammar.  It has no importers, reads no
clock, touches no file, and grants no custody, admission, or budget authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, cast

from .canonical_identity import (
    FoundationValidationError,
    canonical_json_bytes,
    verify_canonical_json_bytes,
)


DURATION_MS_MAX: Final[int] = 9_223_372_036_854_775_807
VALUE_MAX_BYTES: Final[int] = 1024
CODES: Final[frozenset[str]] = frozenset(
    {
        "invalid_type",
        "out_of_range",
        "invalid_epoch_id",
        "invalid_event_id",
        "duration_overflow",
        "epoch_mismatch",
        "clock_regression",
        "invalid_input_type",
        "input_too_large",
        "invalid_json",
        "non_canonical",
        "invalid_shape",
        "kind_mismatch",
        "unsupported_version",
        "invalid_decimal",
    }
)

_EPOCH_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_EVENT_ID: Final = re.compile(r"del-[0-9a-f]{64}")
_DECIMAL: Final = re.compile(r"0|[1-9][0-9]{0,18}")
_DECIMAL_MAX_DIGITS: Final = 19
_MISSING: Final = object()

_DURATION_KIND: Final = "duration_ms"
_CLOCK_KIND: Final = "clock_ms"
_EVENT_KIND: Final = "delivery_event_id_v1"
_SCHEMA_VERSION: Final = 1
_DURATION_KEYS: Final = frozenset({"kind", "schema_version", "value"})
_CLOCK_KEYS: Final = frozenset({"elapsed_ms", "epoch_id", "kind", "schema_version"})
_EVENT_KEYS: Final = frozenset({"kind", "schema_version", "value"})


class ContinuationValueError(ValueError):
    """A closed, input-free continuation value failure; ``str(error) == code``."""

    code: str

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in CODES:
            # Programmer misuse: a constant message, never the rejected value.
            raise ValueError("invalid_error_code")
        super().__init__(code)
        self.code = code


# Field checks return a closed code instead of raising so that every public
# error is raised outside any handler and never chains module or foundation
# context (only a caller's own active exception may become ``__context__``).


def _ms_code(value: object) -> str | None:
    if value is _MISSING or type(value) is not int:
        return "invalid_type"
    if value < 0 or value > DURATION_MS_MAX:
        return "out_of_range"
    return None


def _epoch_code(value: object) -> str | None:
    if value is _MISSING:
        return "invalid_type"
    if type(value) is not str or _EPOCH_ID.fullmatch(value) is None:
        return "invalid_epoch_id"
    return None


def _event_code(value: object) -> str | None:
    if value is _MISSING:
        return "invalid_type"
    if type(value) is not str or _EVENT_ID.fullmatch(value) is None:
        return "invalid_event_id"
    return None


def _clock_fields_code(epoch_id: object, elapsed_ms: object) -> str | None:
    return _epoch_code(epoch_id) or _ms_code(elapsed_ms)


@dataclass(frozen=True, slots=True)
class DurationMs:
    """A non-negative native int64 duration in milliseconds."""

    value: int

    def __post_init__(self) -> None:
        code = _ms_code(self.value)
        if code is not None:
            raise ContinuationValueError(code)


@dataclass(frozen=True, slots=True)
class ClockReadingMs:
    """An opaque caller epoch token and the milliseconds elapsed within it."""

    epoch_id: str
    elapsed_ms: int

    def __post_init__(self) -> None:
        code = _clock_fields_code(self.epoch_id, self.elapsed_ms)
        if code is not None:
            raise ContinuationValueError(code)


@dataclass(frozen=True, slots=True)
class EventId:
    """A delivery event identifier: exactly ``del-`` and 64 lowercase hex digits."""

    value: str

    def __post_init__(self) -> None:
        code = _event_code(self.value)
        if code is not None:
            raise ContinuationValueError(code)


# Public boundaries revalidate the exact class and every field: frozen
# dataclasses can still be bypassed with ``object.__setattr__``,
# ``object.__new__`` or a subclass.  ``getattr`` with a sentinel reads an empty
# slot without an exception handler.


def _duration_code(value: object) -> str | None:
    if type(value) is not DurationMs:
        return "invalid_type"
    return _ms_code(getattr(value, "value", _MISSING))


def _clock_code(value: object) -> str | None:
    if type(value) is not ClockReadingMs:
        return "invalid_type"
    return _clock_fields_code(
        getattr(value, "epoch_id", _MISSING), getattr(value, "elapsed_ms", _MISSING)
    )


def _event_id_code(value: object) -> str | None:
    if type(value) is not EventId:
        return "invalid_type"
    return _event_code(getattr(value, "value", _MISSING))


def add_durations(a: DurationMs, b: DurationMs) -> DurationMs:
    """Return the exact sum; refuse an int64 overflow instead of saturating."""
    code = _duration_code(a) or _duration_code(b)
    if code is None:
        total = a.value + b.value
        if total <= DURATION_MS_MAX:
            return DurationMs(total)
        code = "duration_overflow"
    raise ContinuationValueError(code)


def elapsed_between(earlier: ClockReadingMs, later: ClockReadingMs) -> DurationMs:
    """Return the exact elapsed time within one epoch; never clamp a regression."""
    code = _clock_code(earlier) or _clock_code(later)
    if code is None:
        if earlier.epoch_id != later.epoch_id:
            code = "epoch_mismatch"
        elif later.elapsed_ms < earlier.elapsed_ms:
            code = "clock_regression"
        else:
            return DurationMs(later.elapsed_ms - earlier.elapsed_ms)
    raise ContinuationValueError(code)


def encode_value(value: DurationMs | ClockReadingMs | EventId) -> bytes:
    """Encode one revalidated value as its closed canonical wire envelope."""
    if type(value) is DurationMs:
        code = _duration_code(value)
        if code is None:
            return canonical_json_bytes(
                {
                    "kind": _DURATION_KIND,
                    "schema_version": _SCHEMA_VERSION,
                    "value": str(value.value),
                }
            )
    elif type(value) is ClockReadingMs:
        code = _clock_code(value)
        if code is None:
            return canonical_json_bytes(
                {
                    "elapsed_ms": str(value.elapsed_ms),
                    "epoch_id": value.epoch_id,
                    "kind": _CLOCK_KIND,
                    "schema_version": _SCHEMA_VERSION,
                }
            )
    elif type(value) is EventId:
        code = _event_id_code(value)
        if code is None:
            return canonical_json_bytes(
                {
                    "kind": _EVENT_KIND,
                    "schema_version": _SCHEMA_VERSION,
                    "value": value.value,
                }
            )
    else:
        code = "invalid_type"
    raise ContinuationValueError(code)


def _envelope(data: object, kind: str, keys: frozenset[str]) -> dict[str, object] | str:
    """Return the verified envelope, or the first closed failure code."""
    if type(data) is not bytes:
        return "invalid_input_type"
    if len(data) > VALUE_MAX_BYTES:
        return "input_too_large"
    parsed: object = None
    failure: str | None = None
    # Only the foundation verifier is contained.  Its messages carry input key
    # paths and it may raise a raw RecursionError on deep input, so only the
    # closed code survives and the public error is raised after the handler.
    try:
        parsed = verify_canonical_json_bytes(data)
    except FoundationValidationError as error:
        failure = "non_canonical" if error.code == "non_canonical_bytes" else "invalid_json"
    except (ValueError, RecursionError, TypeError):
        failure = "invalid_json"
    if failure is not None:
        return failure
    if type(parsed) is not dict or "kind" not in parsed or "schema_version" not in parsed:
        return "invalid_shape"
    found_kind = parsed["kind"]
    if type(found_kind) is not str or found_kind != kind:
        return "kind_mismatch"
    version = parsed["schema_version"]
    if type(version) is not int or version != _SCHEMA_VERSION:
        return "unsupported_version"
    if frozenset(parsed) != keys:
        return "invalid_shape"
    return parsed


def _decimal(text: object) -> int | str:
    """Parse one wire decimal string, or return its closed failure code.

    The decoders tell the two results apart with ``isinstance``; that is safe
    only because the int is always the native result of ``int()`` here.
    """
    if (
        type(text) is not str
        or len(text) > _DECIMAL_MAX_DIGITS
        or _DECIMAL.fullmatch(text) is None
    ):
        return "invalid_decimal"
    value = int(text)
    if value > DURATION_MS_MAX:
        return "out_of_range"
    return value


def decode_duration_ms(data: bytes) -> DurationMs:
    """Decode exactly one canonical ``duration_ms`` v1 envelope."""
    envelope = _envelope(data, _DURATION_KIND, _DURATION_KEYS)
    if isinstance(envelope, str):
        code = envelope
    else:
        value = _decimal(envelope["value"])
        if isinstance(value, int):
            return DurationMs(value)
        code = value
    raise ContinuationValueError(code)


def decode_clock_reading_ms(data: bytes) -> ClockReadingMs:
    """Decode exactly one canonical ``clock_ms`` v1 envelope (epoch first)."""
    envelope = _envelope(data, _CLOCK_KIND, _CLOCK_KEYS)
    if isinstance(envelope, str):
        code = envelope
    else:
        epoch_id = envelope["epoch_id"]
        epoch_failure = _epoch_code(epoch_id)
        if epoch_failure is not None:
            code = epoch_failure
        else:
            elapsed = _decimal(envelope["elapsed_ms"])
            if isinstance(elapsed, int):
                return ClockReadingMs(cast(str, epoch_id), elapsed)
            code = elapsed
    raise ContinuationValueError(code)


def decode_event_id(data: bytes) -> EventId:
    """Decode exactly one canonical ``delivery_event_id_v1`` v1 envelope."""
    envelope = _envelope(data, _EVENT_KIND, _EVENT_KEYS)
    if isinstance(envelope, str):
        code = envelope
    else:
        value = envelope["value"]
        event_failure = _event_code(value)
        if event_failure is None:
            return EventId(cast(str, value))
        code = event_failure
    raise ContinuationValueError(code)


__all__ = [
    "CODES",
    "DURATION_MS_MAX",
    "VALUE_MAX_BYTES",
    "ClockReadingMs",
    "ContinuationValueError",
    "DurationMs",
    "EventId",
    "add_durations",
    "decode_clock_reading_ms",
    "decode_duration_ms",
    "decode_event_id",
    "elapsed_between",
    "encode_value",
]
