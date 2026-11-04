"""VAL-050-S2A: inert continuation value types and the closed value codec v1."""

from __future__ import annotations

import ast
import builtins
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from decimal import Decimal
import enum
import hashlib
import importlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import traceback
from typing import Any, cast

import pytest

import unrest_harness
from unrest_harness import continuation_types as ct
from unrest_harness.canonical_identity import FoundationValidationError, canonical_json_bytes
from unrest_harness.continuation_types import (
    CODES,
    DURATION_MS_MAX,
    VALUE_MAX_BYTES,
    ClockReadingMs,
    ContinuationValueError,
    DurationMs,
    EventId,
    add_durations,
    decode_clock_reading_ms,
    decode_duration_ms,
    decode_event_id,
    elapsed_between,
    encode_value,
)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/unrest_harness/continuation_types.py"
MODULE_NAME = "unrest_harness.continuation_types"
MAX = 9_223_372_036_854_775_807
HEX64 = "0123456789abcdef" * 4
EVENT = "del-" + HEX64
DAY_MS = 86_400_000

D0 = b'{"kind":"duration_ms","schema_version":1,"value":"0"}\n'
D53M = b'{"kind":"duration_ms","schema_version":1,"value":"9007199254740991"}\n'
D53 = b'{"kind":"duration_ms","schema_version":1,"value":"9007199254740992"}\n'
DMAX = b'{"kind":"duration_ms","schema_version":1,"value":"9223372036854775807"}\n'
CMAX = (
    b'{"elapsed_ms":"9223372036854775807","epoch_id":"epoch1",'
    b'"kind":"clock_ms","schema_version":1}\n'
)
EV = (
    b'{"kind":"delivery_event_id_v1","schema_version":1,"value":"del-'
    b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    b'"}\n'
)

# Values are built lazily so a domain regression fails tests instead of collection.
GOLDEN: tuple[tuple[str, Callable[[], object], bytes, int, str], ...] = (
    (
        "duration-0",
        lambda: DurationMs(0),
        D0,
        54,
        "b9221be8432448d4e4b54699f631801049178fb47e590f922bb04b5d64359922",
    ),
    (
        "duration-2^53-1",
        lambda: DurationMs(2**53 - 1),
        D53M,
        69,
        "6fb61399013654eea7ab00ce4b21cb9d2f5dc7bf4b3a2de3b4c71e19ff8f0fc1",
    ),
    (
        "duration-2^53",
        lambda: DurationMs(2**53),
        D53,
        69,
        "5155313e0dece392369e6af40929572dc1979e85b6955f10017b29d10416a6c7",
    ),
    (
        "duration-max",
        lambda: DurationMs(MAX),
        DMAX,
        72,
        "f62ffbd2ab71ebf0a75828b820679474b79220400d015ee4b597dda09e7d3d42",
    ),
    (
        "clock-max",
        lambda: ClockReadingMs("epoch1", MAX),
        CMAX,
        94,
        "5ca21cd0719150d39968c3036181cb9220f251bcf4f343479ee7a5098be11748",
    ),
    (
        "event",
        lambda: EventId(EVENT),
        EV,
        130,
        "ab49b3ca05fce11decc7b8213dfb8d3a93a3b6293705386b50c62f0caaa8bb65",
    ),
)

DECODERS: dict[str, Callable[[bytes], object]] = {
    "duration": decode_duration_ms,
    "clock": decode_clock_reading_ms,
    "event": decode_event_id,
}


class Int(int):
    pass


class Color(enum.IntEnum):
    RED = 5


class Str(str):
    pass


class Bytes(bytes):
    pass


def K(value: object) -> bytes:
    return canonical_json_bytes(value)


def duration(**changes: object) -> bytes:
    payload: dict[str, object] = {"kind": "duration_ms", "schema_version": 1, "value": "0"}
    payload.update(changes)
    return K(payload)


def clock(**changes: object) -> bytes:
    payload: dict[str, object] = {
        "elapsed_ms": "5",
        "epoch_id": "epoch1",
        "kind": "clock_ms",
        "schema_version": 1,
    }
    payload.update(changes)
    return K(payload)


def event(**changes: object) -> bytes:
    payload: dict[str, object] = {
        "kind": "delivery_event_id_v1",
        "schema_version": 1,
        "value": EVENT,
    }
    payload.update(changes)
    return K(payload)


def without(data: bytes, key: str) -> bytes:
    payload = json.loads(data)
    del payload[key]
    return K(payload)


def raises(call: Callable[[], object]) -> ContinuationValueError:
    """Run ``call`` outside any handler and return its public error.

    Every API error checked through this helper also proves the closed error
    surface: exact class, closed code, ``str``/``args``, and no chaining.
    """
    error: BaseException | None = None
    try:
        call()
    except BaseException as caught:  # noqa: BLE001 - the exact class is asserted below
        error = caught
    assert error is not None, "expected ContinuationValueError, got a result"
    assert type(error) is ContinuationValueError, repr(error)
    assert error.code in CODES
    assert str(error) == error.code
    assert error.args == (error.code,)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert not hasattr(error, "__notes__")
    return error


def code(call: Callable[[], object]) -> str:
    return raises(call).code


def mutated(value: object, field: str, replacement: object) -> Any:
    object.__setattr__(value, field, replacement)
    return value


# --------------------------------------------------------------------------- VAL01


NON_NATIVE_INTS: tuple[object, ...] = (
    True,
    False,
    Int(5),
    Color.RED,
    5.0,
    "5",
    None,
    Decimal(5),
)


@pytest.mark.parametrize("raw", NON_NATIVE_INTS, ids=repr)
def test_val01_constructors_accept_only_native_int(raw: object) -> None:
    assert code(lambda: DurationMs(cast(int, raw))) == "invalid_type"
    assert code(lambda: ClockReadingMs("epoch1", cast(int, raw))) == "invalid_type"


@pytest.mark.parametrize("raw", (-1, MAX + 1, -(2**63), 2**64))
def test_val01_constructor_range_is_out_of_range(raw: int) -> None:
    assert code(lambda: DurationMs(raw)) == "out_of_range"
    assert code(lambda: ClockReadingMs("epoch1", raw)) == "out_of_range"


@pytest.mark.parametrize("raw", (0, 1, 2**53 - 1, 2**53, MAX))
def test_val01_constructor_accepts_the_full_int64_range(raw: int) -> None:
    assert type(DurationMs(raw).value) is int and DurationMs(raw).value == raw
    reading = ClockReadingMs("epoch1", raw)
    assert type(reading.elapsed_ms) is int and reading.elapsed_ms == raw


@pytest.mark.parametrize("raw", (*NON_NATIVE_INTS, -1, MAX + 1, 0, 5), ids=repr)
def test_val01_raw_non_instances_at_boundaries_are_invalid_type(raw: object) -> None:
    value = cast(Any, raw)
    reading = ClockReadingMs("epoch1", 0)
    assert code(lambda: encode_value(value)) == "invalid_type"
    assert code(lambda: add_durations(value, DurationMs(0))) == "invalid_type"
    assert code(lambda: add_durations(DurationMs(0), value)) == "invalid_type"
    assert code(lambda: elapsed_between(value, reading)) == "invalid_type"
    assert code(lambda: elapsed_between(reading, value)) == "invalid_type"


# --------------------------------------------------------------------------- VAL02


def test_val02_event_id_is_exactly_del_and_64_lowercase_hex() -> None:
    value = EventId(EVENT)
    assert len(value.value) == 68
    assert encode_value(value) == EV
    assert decode_event_id(EV) == value
    assert encode_value(decode_event_id(EV)) == EV
    for digit in "0123456789abcdef":
        assert EventId("del-" + digit * 64).value == "del-" + digit * 64


INVALID_EVENT_IDS: tuple[object, ...] = (
    "del-" + "0" * 63,
    "del-" + "0" * 65,
    "del-" + "A" * 64,
    "del-" + HEX64.upper(),
    "del1-" + "0" * 64,
    "DEL-" + "0" * 64,
    "del-" + "0" * 63 + " ",
    " del-" + "0" * 64,
    "del-" + "0" * 64 + "\n",
    "del-\u00e9" + "0" * 63,
    "del-" + "\uff10" * 64,
    "del_" + "0" * 64,
    "",
    "x",
    1,
    None,
    EVENT.encode(),
    Str(EVENT),
)


@pytest.mark.parametrize("raw", INVALID_EVENT_IDS, ids=repr)
def test_val02_event_id_constructor_refuses_everything_else(raw: object) -> None:
    assert code(lambda: EventId(cast(str, raw))) == "invalid_event_id"


def test_val02_module_has_no_event_id_derivation() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    derivation = {"hashlib", "sha256", "blake2b", "hexdigest", "digest", "uuid4", "token_hex"}
    assert not (names | attributes) & derivation


# --------------------------------------------------------------------------- VAL03


@pytest.mark.parametrize(
    "epoch_id",
    ("", "a" * 129, "-a", ".a", "a\n", "\u00e9", "e\u0301", " a", "a b", 1, None, Str("e")),
    ids=repr,
)
def test_val03_epoch_id_refusals(epoch_id: object) -> None:
    assert code(lambda: ClockReadingMs(cast(str, epoch_id), 0)) == "invalid_epoch_id"


def test_val03_epoch_id_bounds_and_field_order() -> None:
    assert ClockReadingMs("a" * 128, 0).epoch_id == "a" * 128
    assert ClockReadingMs("A9._:-", 0).epoch_id == "A9._:-"
    assert code(lambda: ClockReadingMs("e", cast(int, True))) == "invalid_type"
    assert code(lambda: ClockReadingMs("e", -1)) == "out_of_range"
    assert code(lambda: ClockReadingMs("", cast(int, True))) == "invalid_epoch_id"
    assert code(lambda: ClockReadingMs("", -1)) == "invalid_epoch_id"


@pytest.mark.parametrize(
    ("start", "end"),
    ((0, 0), (0, MAX), (7, 7), (5, 12 * DAY_MS + 5), (0, 365 * DAY_MS), (MAX - 1, MAX)),
)
def test_val03_elapsed_between_is_exact_within_one_epoch(start: int, end: int) -> None:
    result = elapsed_between(ClockReadingMs("boot-1", start), ClockReadingMs("boot-1", end))
    assert type(result) is DurationMs and result == DurationMs(end - start)
    assert type(result.value) is int


def test_val03_twelve_days_and_one_year_are_ordinary_values() -> None:
    assert 12 * DAY_MS == 1_036_800_000
    year = DurationMs(365 * DAY_MS)
    assert add_durations(DurationMs(12 * DAY_MS), year) == DurationMs(377 * DAY_MS)


def test_val03_epochs_and_regressions_are_refused_never_clamped() -> None:
    assert (
        code(lambda: elapsed_between(ClockReadingMs("a", 1), ClockReadingMs("b", 2)))
        == "epoch_mismatch"
    )
    assert (
        code(lambda: elapsed_between(ClockReadingMs("a", 5), ClockReadingMs("a", 4)))
        == "clock_regression"
    )
    assert (
        code(lambda: elapsed_between(ClockReadingMs("a", 5), ClockReadingMs("b", 4)))
        == "epoch_mismatch"
    )


def test_val03_add_durations_is_exact_and_refuses_overflow() -> None:
    assert add_durations(DurationMs(MAX), DurationMs(0)) == DurationMs(MAX)
    assert add_durations(DurationMs(0), DurationMs(MAX)) == DurationMs(MAX)
    assert add_durations(DurationMs(MAX - 3), DurationMs(3)) == DurationMs(MAX)
    assert code(lambda: add_durations(DurationMs(MAX), DurationMs(1))) == "duration_overflow"
    assert code(lambda: add_durations(DurationMs(MAX), DurationMs(MAX))) == "duration_overflow"


def test_val03_first_invalid_argument_wins() -> None:
    bad_a = mutated(DurationMs(1), "value", -1)
    assert code(lambda: add_durations(bad_a, cast(Any, "x"))) == "out_of_range"
    assert code(lambda: add_durations(cast(Any, "x"), bad_a)) == "invalid_type"
    bad_earlier = mutated(ClockReadingMs("e", 1), "epoch_id", "")
    assert code(lambda: elapsed_between(bad_earlier, cast(Any, 5))) == "invalid_epoch_id"
    assert code(lambda: elapsed_between(cast(Any, 5), bad_earlier)) == "invalid_type"


# --------------------------------------------------------------------------- VAL04


@pytest.mark.parametrize(
    ("make", "literal", "length", "digest"),
    [row[1:] for row in GOLDEN],
    ids=[row[0] for row in GOLDEN],
)
def test_val04_golden_bytes_are_exact(
    make: Callable[[], object], literal: bytes, length: int, digest: str
) -> None:
    value = make()
    assert len(literal) == length
    assert hashlib.sha256(literal).hexdigest() == digest
    assert encode_value(cast(Any, value)) == literal
    decoded = DECODERS[
        {DurationMs: "duration", ClockReadingMs: "clock", EventId: "event"}[type(value)]
    ](literal)
    assert decoded == value and type(decoded) is type(value)
    assert encode_value(cast(Any, decoded)) == literal
    if isinstance(decoded, DurationMs):
        assert type(decoded.value) is int
    if isinstance(decoded, ClockReadingMs):
        assert type(decoded.elapsed_ms) is int


@pytest.mark.parametrize("raw", (0, 1, 9, 10, 2**31, 2**53 - 1, 2**53, 2**53 + 1, MAX - 1, MAX))
def test_val04_round_trip_decimal_strings(raw: int) -> None:
    for value in (DurationMs(raw), ClockReadingMs("e", raw)):
        data = encode_value(value)
        assert str(raw).encode() in data
        decoded = (
            decode_duration_ms(data) if type(value) is DurationMs else decode_clock_reading_ms(data)
        )
        assert decoded == value
        assert encode_value(decoded) == data


# --------------------------------------------------------------------------- VAL04/05 table §8.2

INVALID_JSON: tuple[tuple[str, str, bytes], ...] = (
    ("bom", "duration", b"\xef\xbb\xbf" + D0),
    ("invalid-utf8", "duration", b'{"kind":"duration_ms","schema_version":1,"value":"\xff"}\n'),
    (
        "duplicate-kind",
        "duration",
        b'{"kind":"duration_ms","kind":"duration_ms","schema_version":1,"value":"0"}\n',
    ),
    ("version-float", "duration", b'{"kind":"duration_ms","schema_version":1.0,"value":"0"}\n'),
    ("nan", "duration", b'{"kind":"duration_ms","schema_version":1,"value":NaN}\n'),
    ("null-value", "duration", b'{"kind":"duration_ms","schema_version":1,"value":null}\n'),
    (
        "version-2^53",
        "duration",
        b'{"kind":"duration_ms","schema_version":9007199254740992,"value":"0"}\n',
    ),
    (
        "value-2^53",
        "duration",
        b'{"kind":"duration_ms","schema_version":1,"value":9007199254740992}\n',
    ),
    ("value-1e3", "duration", b'{"kind":"duration_ms","schema_version":1,"value":1e3}\n'),
    (
        "lone-surrogate",
        "duration",
        b'{"kind":"duration_ms","schema_version":1,"value":"\\ud800"}\n',
    ),
    (
        "non-nfc-epoch",
        "clock",
        b'{"elapsed_ms":"5","epoch_id":"e\xcc\x81","kind":"clock_ms","schema_version":1}\n',
    ),
    (
        "non-nfc-epoch-escape",
        "clock",
        b'{"elapsed_ms":"5","epoch_id":"e\\u0301","kind":"clock_ms","schema_version":1}\n',
    ),
    (
        "non-nfc-event",
        "event",
        b'{"kind":"delivery_event_id_v1","schema_version":1,"value":"del-e\xcc\x81"}\n',
    ),
    (
        "null-event",
        "event",
        b'{"kind":"delivery_event_id_v1","schema_version":1,"value":null}\n',
    ),
    ("empty", "duration", b""),
    ("truncated", "duration", D0[:-3] + b"\n"),
)

NON_CANONICAL: tuple[tuple[str, bytes], ...] = (
    ("space-after-colon", b'{"kind": "duration_ms","schema_version":1,"value":"0"}\n'),
    ("key-order", b'{"schema_version":1,"kind":"duration_ms","value":"0"}\n'),
    ("no-lf", D0[:-1]),
    ("two-lf", D0 + b"\n"),
    ("negative-zero", b'{"kind":"duration_ms","schema_version":1,"value":-0}\n'),
)


@pytest.mark.parametrize("decoder", sorted(DECODERS))
@pytest.mark.parametrize(
    "data",
    (bytearray(D0), memoryview(D0), D0.decode(), Bytes(D0), None, 0, [D0]),
    ids=("bytearray", "memoryview", "str", "bytes-subclass", "none", "int", "list"),
)
def test_val05_row1_only_exact_bytes(decoder: str, data: object) -> None:
    assert code(lambda: DECODERS[decoder](cast(bytes, data))) == "invalid_input_type"


@contextmanager
def verify_spy(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[int]]:
    calls: list[int] = []
    original = ct.verify_canonical_json_bytes

    def spy(source: bytes) -> object:
        calls.append(len(source))
        return original(source)

    with monkeypatch.context() as patch:
        patch.setattr(ct, "verify_canonical_json_bytes", spy)
        yield calls


@pytest.mark.parametrize("decoder", sorted(DECODERS))
def test_val05_row2_oversize_is_refused_before_parsing(
    decoder: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with verify_spy(monkeypatch) as calls:
        assert code(lambda: DECODERS[decoder](b" " * 1025)) == "input_too_large"
        assert code(lambda: DECODERS[decoder](D0 + b" " * (1025 - len(D0)))) == (
            "input_too_large"
        )
    assert calls == []


def test_val05_row3_exactly_the_limit_is_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    data = duration(value="a" * 971)
    assert len(data) == VALUE_MAX_BYTES == 1024
    with verify_spy(monkeypatch) as calls:
        assert code(lambda: decode_duration_ms(data)) == "invalid_decimal"
    assert calls == [1024]


@pytest.mark.parametrize(
    ("decoder", "data"), [row[1:] for row in INVALID_JSON], ids=[row[0] for row in INVALID_JSON]
)
def test_val05_row4_foundation_refusals_are_invalid_json(decoder: str, data: bytes) -> None:
    assert code(lambda: DECODERS[decoder](data)) == "invalid_json"


@pytest.mark.parametrize("data", [row[1] for row in NON_CANONICAL], ids=[r[0] for r in NON_CANONICAL])
def test_val05_row5_non_canonical_bytes(data: bytes) -> None:
    assert code(lambda: decode_duration_ms(data)) == "non_canonical"


@pytest.mark.parametrize(
    "data",
    (
        K([]),
        K("duration_ms"),
        K(1),
        K({}),
        K(True),
        without(D0, "kind"),
        without(D0, "schema_version"),
    ),
    ids=("list", "string", "int", "empty-object", "true", "no-kind", "no-version"),
)
def test_val05_row6_top_level_shape(data: bytes) -> None:
    for decoder in DECODERS.values():
        assert code(lambda: decoder(data)) == "invalid_shape"


@pytest.mark.parametrize(
    "kind",
    ("clock_ms", "Duration_ms", "duration_ms ", "", 1, ["duration_ms"], {"a": 1}, True),
    ids=repr,
)
def test_val05_row7_kind_mismatch(kind: object) -> None:
    assert code(lambda: decode_duration_ms(duration(kind=kind))) == "kind_mismatch"


def test_val05_row7_foreign_envelopes_are_kind_mismatch() -> None:
    assert code(lambda: decode_duration_ms(CMAX)) == "kind_mismatch"
    assert code(lambda: decode_duration_ms(EV)) == "kind_mismatch"
    assert code(lambda: decode_clock_reading_ms(D0)) == "kind_mismatch"
    assert code(lambda: decode_clock_reading_ms(EV)) == "kind_mismatch"
    assert code(lambda: decode_event_id(D0)) == "kind_mismatch"
    assert code(lambda: decode_event_id(CMAX)) == "kind_mismatch"


@pytest.mark.parametrize("version", (True, False, "1", 2, 0, -1, [1], {"v": 1}), ids=repr)
def test_val05_row8_unsupported_version(version: object) -> None:
    assert code(lambda: decode_duration_ms(duration(schema_version=version))) == (
        "unsupported_version"
    )
    assert code(lambda: decode_clock_reading_ms(clock(schema_version=version))) == (
        "unsupported_version"
    )
    assert code(lambda: decode_event_id(event(schema_version=version))) == "unsupported_version"


def test_val05_row9_closed_key_set() -> None:
    assert code(lambda: decode_duration_ms(duration(x=1))) == "invalid_shape"
    assert code(lambda: decode_duration_ms(duration(x={"y": 1}))) == "invalid_shape"
    assert code(lambda: decode_duration_ms(without(D0, "value"))) == "invalid_shape"
    assert code(lambda: decode_clock_reading_ms(clock(elapsed_ns="5"))) == "invalid_shape"
    assert code(lambda: decode_clock_reading_ms(without(CMAX, "epoch_id"))) == "invalid_shape"
    assert code(lambda: decode_clock_reading_ms(without(CMAX, "elapsed_ms"))) == "invalid_shape"
    assert code(lambda: decode_event_id(event(x=1))) == "invalid_shape"
    assert code(lambda: decode_event_id(without(EV, "value"))) == "invalid_shape"


@pytest.mark.parametrize("value", (0, 1, -1, 9_007_199_254_740_991), ids=repr)
def test_val04_row10_json_numbers_are_not_milliseconds(value: int) -> None:
    assert code(lambda: decode_duration_ms(duration(value=value))) == "invalid_decimal"
    assert code(lambda: decode_clock_reading_ms(clock(elapsed_ms=value))) == "invalid_decimal"


INVALID_DECIMALS: tuple[object, ...] = (
    "00",
    "01",
    "+1",
    "-0",
    "-1",
    " 1",
    "1 ",
    "1.0",
    "1e3",
    "0x1",
    "\u0661",
    "\uff11",
    "1\uff12",
    "",
    "1" * 20,
    "0" * 19,
    "1_000",
    True,
    ["0"],
    {"v": "0"},
)


@pytest.mark.parametrize("value", INVALID_DECIMALS, ids=repr)
def test_val04_row11_decimal_grammar(value: object) -> None:
    assert code(lambda: decode_duration_ms(duration(value=value))) == "invalid_decimal"
    assert code(lambda: decode_clock_reading_ms(clock(elapsed_ms=value))) == "invalid_decimal"


@pytest.mark.parametrize("value", ("9223372036854775808", "9999999999999999999"))
def test_val04_row12_decimal_above_int64_is_out_of_range(value: str) -> None:
    assert code(lambda: decode_duration_ms(duration(value=value))) == "out_of_range"
    assert code(lambda: decode_clock_reading_ms(clock(elapsed_ms=value))) == "out_of_range"


def test_val05_row13_precedence_kind_version_keys_fields() -> None:
    assert code(lambda: decode_duration_ms(duration(kind="clock_ms", schema_version=2))) == (
        "kind_mismatch"
    )
    assert code(lambda: decode_duration_ms(duration(schema_version=2, x=1))) == (
        "unsupported_version"
    )
    assert code(lambda: decode_duration_ms(duration(x=1, value="01"))) == "invalid_shape"
    assert code(lambda: decode_clock_reading_ms(clock(kind=1, schema_version=True, x=1))) == (
        "kind_mismatch"
    )


@pytest.mark.parametrize(
    "epoch_id", ("", "a" * 129, ".a", "a\n", "\u00e9", " a", 1, ["e"], {"e": 1}, True), ids=repr
)
def test_val05_row14_clock_epoch_refusals(epoch_id: object) -> None:
    assert code(lambda: decode_clock_reading_ms(clock(epoch_id=epoch_id))) == "invalid_epoch_id"


def test_val05_row15_row16_clock_elapsed_and_field_order() -> None:
    assert code(lambda: decode_clock_reading_ms(clock(elapsed_ms="01"))) == "invalid_decimal"
    assert code(lambda: decode_clock_reading_ms(clock(elapsed_ms=5))) == "invalid_decimal"
    assert code(lambda: decode_clock_reading_ms(clock(elapsed_ms="9223372036854775808"))) == (
        "out_of_range"
    )
    assert code(lambda: decode_clock_reading_ms(clock(epoch_id="", elapsed_ms="01"))) == (
        "invalid_epoch_id"
    )
    assert code(
        lambda: decode_clock_reading_ms(clock(epoch_id="", elapsed_ms="9223372036854775808"))
    ) == "invalid_epoch_id"


@pytest.mark.parametrize(
    "value",
    (
        "del-" + "A" * 64,
        "del-" + "0" * 63,
        "del-" + "0" * 65,
        "del1-" + "0" * 64,
        "DEL-" + "0" * 64,
        "del-" + "0" * 64 + "\n",
        "del-\u00e9" + "0" * 63,
        "",
        1,
        True,
        [EVENT],
    ),
    ids=repr,
)
def test_val05_row17_event_value_refusals(value: object) -> None:
    assert code(lambda: decode_event_id(event(value=value))) == "invalid_event_id"


def test_val05_row18_accepted_boundaries_round_trip() -> None:
    data = clock(epoch_id="a" * 128, elapsed_ms="0")
    assert decode_clock_reading_ms(data) == ClockReadingMs("a" * 128, 0)
    assert encode_value(decode_clock_reading_ms(data)) == data
    data = duration(value="9223372036854775807")
    assert data == DMAX
    assert decode_duration_ms(data) == DurationMs(MAX)
    for _, make, literal, _, _ in GOLDEN:
        assert encode_value(cast(Any, make())) == literal


LEGACY: tuple[tuple[str, bytes, str, str], ...] = (
    ("ns-string-no-envelope", b'{"elapsed_ns":"1","epoch_id":"e"}\n', "clock", "invalid_shape"),
    ("ns-number-no-envelope", b'{"elapsed_ns":1,"epoch_id":"e"}\n', "clock", "invalid_shape"),
    (
        "ns-in-envelope",
        b'{"elapsed_ns":"1","epoch_id":"e","kind":"clock_ms","schema_version":1}\n',
        "clock",
        "invalid_shape",
    ),
    (
        "ns-in-envelope-as-duration",
        b'{"elapsed_ns":"1","epoch_id":"e","kind":"clock_ms","schema_version":1}\n',
        "duration",
        "kind_mismatch",
    ),
)


@pytest.mark.parametrize(
    ("data", "decoder", "expected"), [row[1:] for row in LEGACY], ids=[row[0] for row in LEGACY]
)
def test_val05_legacy_literals_are_refused_not_migrated(
    data: bytes, decoder: str, expected: str
) -> None:
    assert code(lambda: DECODERS[decoder](data)) == expected


def _nested_object(depth: int) -> bytes:
    return b'{"a":' * depth + b"{}" + b"}" * depth + b"\n"


def _deepest_object() -> int:
    depth = 1
    while len(_nested_object(depth + 1)) <= VALUE_MAX_BYTES:
        depth += 1
    return depth


@pytest.mark.parametrize("depth", (1, 2, 64, 255, 400, 450, 500, 511))
def test_val05_depth_corpus_top_level_arrays(depth: int) -> None:
    data = b"[" * depth + b"]" * depth + b"\n"
    assert len(data) <= VALUE_MAX_BYTES
    for decoder in DECODERS.values():
        assert code(lambda: decoder(data)) in {"invalid_json", "invalid_shape"}


def test_val05_depth_corpus_objects_without_kind() -> None:
    deepest = _deepest_object()
    assert len(_nested_object(deepest)) <= VALUE_MAX_BYTES < len(_nested_object(deepest + 1))
    for depth in (1, 2, 32, 100, deepest):
        data = _nested_object(depth)
        for decoder in DECODERS.values():
            assert code(lambda: decoder(data)) in {"invalid_json", "invalid_shape"}


@pytest.mark.parametrize("field", ("value", "kind", "epoch_id", "elapsed_ms"))
@pytest.mark.parametrize("depth", (1, 64, 300, 440))
def test_val05_depth_corpus_inside_fields_never_raises_raw(field: str, depth: int) -> None:
    nested = json.loads("[" * depth + "]" * depth)
    builders = {
        "value": (duration, event),
        "kind": (duration, clock, event),
        "epoch_id": (clock,),
        "elapsed_ms": (clock,),
    }
    for builder in builders[field]:
        data = builder(**{field: nested})
        assert len(data) <= VALUE_MAX_BYTES
        for decoder in DECODERS.values():
            assert code(lambda: decoder(data)) in CODES


# --------------------------------------------------------------------------- VAL06


REACH: tuple[tuple[str, Callable[[], object]], ...] = (
    ("invalid_type", lambda: DurationMs(cast(int, True))),
    ("out_of_range", lambda: DurationMs(-1)),
    ("invalid_epoch_id", lambda: ClockReadingMs("", 0)),
    ("invalid_event_id", lambda: EventId("x")),
    ("duration_overflow", lambda: add_durations(DurationMs(MAX), DurationMs(1))),
    (
        "epoch_mismatch",
        lambda: elapsed_between(ClockReadingMs("a", 1), ClockReadingMs("b", 2)),
    ),
    (
        "clock_regression",
        lambda: elapsed_between(ClockReadingMs("a", 2), ClockReadingMs("a", 1)),
    ),
    ("invalid_input_type", lambda: decode_duration_ms(cast(bytes, bytearray(D0)))),
    ("input_too_large", lambda: decode_duration_ms(b" " * 1025)),
    ("invalid_json", lambda: decode_duration_ms(b"\xef\xbb\xbf" + D0)),
    (
        "non_canonical",
        lambda: decode_duration_ms(b'{"kind": "duration_ms","schema_version":1,"value":"0"}\n'),
    ),
    ("invalid_shape", lambda: decode_duration_ms(K([]))),
    ("kind_mismatch", lambda: decode_duration_ms(CMAX)),
    ("unsupported_version", lambda: decode_duration_ms(duration(schema_version=True))),
    ("invalid_decimal", lambda: decode_duration_ms(duration(value="01"))),
)


@pytest.mark.parametrize(("expected", "call"), REACH, ids=[row[0] for row in REACH])
def test_val06_every_code_outside_a_handler_has_no_context(
    expected: str, call: Callable[[], object]
) -> None:
    assert code(call) == expected


@pytest.mark.parametrize(("expected", "call"), REACH, ids=[row[0] for row in REACH])
def test_val06_every_code_inside_a_caller_handler_keeps_only_caller_context(
    expected: str, call: Callable[[], object]
) -> None:
    caller = RuntimeError("caller")
    error: BaseException | None = None
    try:
        raise caller
    except RuntimeError:
        try:
            call()
        except BaseException as caught:  # noqa: BLE001 - asserted exactly below
            error = caught
    assert type(error) is ContinuationValueError
    assert error.code == expected
    assert str(error) == expected and error.args == (expected,)
    assert error.__cause__ is None
    assert error.__context__ is caller
    assert not hasattr(error, "__notes__")


def _canary() -> str:
    return "cnry" + secrets.token_hex(16)


def _assert_private(error: ContinuationValueError, canary: str) -> None:
    rendered = "".join(traceback.format_exception(error))
    assert canary not in rendered
    assert canary not in str(error) and canary not in repr(error)
    assert all(canary not in str(arg) for arg in error.args)
    assert not hasattr(error, "__notes__")
    assert error.__cause__ is None and error.__context__ is None


def test_val06_canary_is_never_rendered() -> None:
    canary = _canary()
    key = canary.encode()
    cases: tuple[tuple[Callable[[], object], str], ...] = (
        (lambda: decode_duration_ms(b'{"' + key + b'":9007199254740992}\n'), "invalid_json"),
        (lambda: decode_duration_ms(b'{"' + key + b'":null}\n'), "invalid_json"),
        (lambda: decode_duration_ms(b'{"' + key + b'": 1}\n'), "non_canonical"),
        (lambda: decode_duration_ms(K({canary: 1})), "invalid_shape"),
        (lambda: decode_duration_ms(duration(**{canary: 1})), "invalid_shape"),
        (lambda: decode_duration_ms(duration(kind=canary)), "kind_mismatch"),
        (lambda: decode_duration_ms(duration(schema_version=canary)), "unsupported_version"),
        (lambda: decode_duration_ms(duration(value=canary)), "invalid_decimal"),
        (lambda: decode_clock_reading_ms(clock(elapsed_ms=canary)), "invalid_decimal"),
        (lambda: decode_clock_reading_ms(clock(epoch_id="." + canary)), "invalid_epoch_id"),
        (lambda: decode_event_id(event(value=canary)), "invalid_event_id"),
        (lambda: decode_duration_ms(key * 40), "input_too_large"),
        (lambda: decode_duration_ms(cast(bytes, canary)), "invalid_input_type"),
        (lambda: EventId(canary), "invalid_event_id"),
        (lambda: ClockReadingMs("." + canary, 0), "invalid_epoch_id"),
        (lambda: DurationMs(cast(int, canary)), "invalid_type"),
        (lambda: encode_value(mutated(EventId(EVENT), "value", canary)), "invalid_event_id"),
        (
            lambda: encode_value(mutated(ClockReadingMs("e", 0), "epoch_id", "." + canary)),
            "invalid_epoch_id",
        ),
    )
    for call, expected in cases:
        error = raises(call)
        assert error.code == expected
        _assert_private(error, canary)


def test_val06_foundation_messages_would_leak_without_containment() -> None:
    """Rationale guard: the foundation verifier names input keys in its message."""
    canary = _canary()
    try:
        ct.verify_canonical_json_bytes(b'{"' + canary.encode() + b'":null}\n')
    except FoundationValidationError as error:
        assert canary in str(error)
    else:  # pragma: no cover - the foundation contract changed
        pytest.fail("foundation accepted null")


# --------------------------------------------------------------------------- VAL07


def _injected(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    def verify(source: bytes) -> object:
        raise error

    monkeypatch.setattr(ct, "verify_canonical_json_bytes", verify)


@pytest.mark.parametrize("decoder", sorted(DECODERS))
@pytest.mark.parametrize(
    ("factory", "expected"),
    (
        (lambda c: FoundationValidationError("non_canonical_bytes", "$." + c), "non_canonical"),
        (lambda c: FoundationValidationError("duplicate_key", "$." + c), "invalid_json"),
        (lambda c: FoundationValidationError("unsafe_integer", "$." + c), "invalid_json"),
        (lambda c: ValueError(c), "invalid_json"),
        (lambda c: RecursionError(c), "invalid_json"),
        (lambda c: TypeError(c), "invalid_json"),
    ),
    ids=("non-canonical", "duplicate-key", "unsafe-integer", "value", "recursion", "type"),
)
def test_val07_contained_foundation_failures_become_closed_codes(
    decoder: str,
    factory: Callable[[str], BaseException],
    expected: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = _canary()
    _injected(monkeypatch, factory(canary))
    error = raises(lambda: DECODERS[decoder](D0))
    assert error.code == expected
    _assert_private(error, canary)


@pytest.mark.parametrize("decoder", sorted(DECODERS))
@pytest.mark.parametrize(
    "factory", (RuntimeError, KeyError, AttributeError, OSError), ids=lambda f: f.__name__
)
def test_val07_uncontained_failures_propagate_unchanged(
    decoder: str, factory: type[BaseException], monkeypatch: pytest.MonkeyPatch
) -> None:
    injected = factory("injected")
    _injected(monkeypatch, injected)
    with pytest.raises(factory) as info:
        DECODERS[decoder](D0)
    assert info.value is injected


# --------------------------------------------------------------------------- VAL08


class PropertyDuration(DurationMs):
    __slots__ = ()

    @property
    def value(self) -> int:
        return 5


class PropertyClock(ClockReadingMs):
    __slots__ = ()

    @property
    def epoch_id(self) -> str:
        return "epoch1"

    @property
    def elapsed_ms(self) -> int:
        return 5


class PropertyEvent(EventId):
    __slots__ = ()

    @property
    def value(self) -> str:
        return EVENT


class SubDuration(DurationMs):
    __slots__ = ()


class SubClock(ClockReadingMs):
    __slots__ = ()


class SubEvent(EventId):
    __slots__ = ()


def _partial_clock(**fields: object) -> Any:
    value = object.__new__(ClockReadingMs)
    for name, field_value in fields.items():
        object.__setattr__(value, name, field_value)
    return value


def _forged_property(cls: type) -> Any:
    forged: Any = object.__new__(cls)
    assert type(forged) is cls and type(forged) not in (DurationMs, ClockReadingMs, EventId)
    return forged


DURATION_FORGERIES: tuple[tuple[str, Callable[[], Any], str], ...] = (
    ("setattr-true", lambda: mutated(DurationMs(1), "value", True), "invalid_type"),
    ("setattr-str", lambda: mutated(DurationMs(1), "value", "1"), "invalid_type"),
    ("setattr-int-subclass", lambda: mutated(DurationMs(1), "value", Int(1)), "invalid_type"),
    ("setattr-negative", lambda: mutated(DurationMs(1), "value", -1), "out_of_range"),
    ("setattr-above-max", lambda: mutated(DurationMs(1), "value", MAX + 1), "out_of_range"),
    ("new-empty-slot", lambda: object.__new__(DurationMs), "invalid_type"),
    ("property-subclass", lambda: _forged_property(PropertyDuration), "invalid_type"),
    ("ordinary-subclass", lambda: SubDuration(5), "invalid_type"),
)

CLOCK_FORGERIES: tuple[tuple[str, Callable[[], Any], str], ...] = (
    ("epoch-empty", lambda: mutated(ClockReadingMs("e", 1), "epoch_id", ""), "invalid_epoch_id"),
    ("epoch-int", lambda: mutated(ClockReadingMs("e", 1), "epoch_id", 1), "invalid_epoch_id"),
    ("elapsed-true", lambda: mutated(ClockReadingMs("e", 1), "elapsed_ms", True), "invalid_type"),
    ("elapsed-negative", lambda: mutated(ClockReadingMs("e", 1), "elapsed_ms", -1), "out_of_range"),
    (
        "both-invalid",
        lambda: mutated(mutated(ClockReadingMs("e", 1), "epoch_id", ""), "elapsed_ms", True),
        "invalid_epoch_id",
    ),
    ("new-empty-slots", lambda: object.__new__(ClockReadingMs), "invalid_type"),
    ("epoch-slot-empty", lambda: _partial_clock(elapsed_ms=1), "invalid_type"),
    ("elapsed-slot-empty", lambda: _partial_clock(epoch_id="e"), "invalid_type"),
    ("elapsed-slot-empty-bad-epoch", lambda: _partial_clock(epoch_id=""), "invalid_epoch_id"),
    ("property-subclass", lambda: _forged_property(PropertyClock), "invalid_type"),
    ("ordinary-subclass", lambda: SubClock("e", 5), "invalid_type"),
)

EVENT_FORGERIES: tuple[tuple[str, Callable[[], Any], str], ...] = (
    ("setattr-x", lambda: mutated(EventId(EVENT), "value", "x"), "invalid_event_id"),
    ("setattr-upper", lambda: mutated(EventId(EVENT), "value", EVENT.upper()), "invalid_event_id"),
    ("setattr-bytes", lambda: mutated(EventId(EVENT), "value", EVENT.encode()), "invalid_event_id"),
    ("new-empty-slot", lambda: object.__new__(EventId), "invalid_type"),
    ("property-subclass", lambda: _forged_property(PropertyEvent), "invalid_type"),
    ("ordinary-subclass", lambda: SubEvent(EVENT), "invalid_type"),
)


@pytest.mark.parametrize(
    ("make", "expected"),
    [row[1:] for row in DURATION_FORGERIES],
    ids=[row[0] for row in DURATION_FORGERIES],
)
def test_val08_duration_boundaries_revalidate(make: Callable[[], Any], expected: str) -> None:
    assert code(lambda: encode_value(make())) == expected
    assert code(lambda: add_durations(make(), DurationMs(0))) == expected
    assert code(lambda: add_durations(DurationMs(0), make())) == expected


@pytest.mark.parametrize(
    ("make", "expected"), [row[1:] for row in CLOCK_FORGERIES], ids=[row[0] for row in CLOCK_FORGERIES]
)
def test_val08_clock_boundaries_revalidate(make: Callable[[], Any], expected: str) -> None:
    valid = ClockReadingMs("e", 1)
    assert code(lambda: encode_value(make())) == expected
    assert code(lambda: elapsed_between(make(), valid)) == expected
    assert code(lambda: elapsed_between(valid, make())) == expected


@pytest.mark.parametrize(
    ("make", "expected"), [row[1:] for row in EVENT_FORGERIES], ids=[row[0] for row in EVENT_FORGERIES]
)
def test_val08_event_boundary_revalidates(make: Callable[[], Any], expected: str) -> None:
    assert code(lambda: encode_value(make())) == expected


def test_val08_value_objects_are_frozen_slotted_and_exact() -> None:
    value = DurationMs(5)
    with pytest.raises(FrozenInstanceError):
        value.value = 6  # type: ignore[misc]
    for item in (value, ClockReadingMs("e", 1), EventId(EVENT)):
        assert not hasattr(item, "__dict__")
    assert DurationMs(5) == DurationMs(5) and hash(DurationMs(5)) == hash(DurationMs(5))
    assert SubDuration(5) != DurationMs(5)
    assert ClockReadingMs("e", 1) != ClockReadingMs("f", 1)
    with pytest.raises(TypeError):
        _ = DurationMs(1) < DurationMs(2)  # type: ignore[operator]
    with pytest.raises(TypeError):
        _ = DurationMs(1) + DurationMs(2)  # type: ignore[operator]


# --------------------------------------------------------------------------- VAL09

ALLOWED_IMPORTS = {"__future__", "dataclasses", "re", "typing"}
FOUNDATION_NAMES = {
    "FoundationValidationError",
    "canonical_json_bytes",
    "verify_canonical_json_bytes",
}


def test_val09_import_allowlist_and_no_effectful_calls() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    foundation: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 1 and node.module == "canonical_identity":
                foundation.update(alias.name for alias in node.names)
            else:
                assert node.level == 0, ast.dump(node)
                imported.add(cast(str, node.module))
    assert imported <= ALLOWED_IMPORTS
    assert foundation == FOUNDATION_NAMES
    called = {
        node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    forbidden = {
        "load_identity_catalog",
        "construct_identity",
        "verify_identity",
        "strict_parse_json",
        "open",
        "print",
        "eval",
        "exec",
        "__import__",
        "import_module",
        "getenv",
    }
    assert not called & forbidden
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert not names & {"os", "sys", "time", "pathlib", "json", "logging", "pydantic", "subprocess",
                        "socket", "hashlib", "pickle", "threading", "signal"}


def test_val09_module_has_only_the_inert_state_importer() -> None:
    importers = [
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "src/unrest_harness").rglob("*.py"))
        if path != MODULE_PATH and "continuation_types" in path.read_text(encoding="utf-8")
    ]
    assert importers == ["src/unrest_harness/continuation_state.py"]


def test_val09_fresh_import_has_no_effects_and_restores_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = sys.modules[MODULE_NAME]
    foundation = sys.modules["unrest_harness.canonical_identity"]
    assert original is ct and unrest_harness.continuation_types is original
    attempts: list[str] = []

    def forbidden(name: str) -> Callable[..., object]:
        def refuse(*args: object, **kwargs: object) -> object:
            attempts.append(name)
            raise AssertionError(f"forbidden effect during fresh import: {name}")

        return refuse

    with monkeypatch.context() as patch:
        # Restoration of the package attribute is registered before the fresh
        # import; registering it afterwards would record the fresh module.
        patch.setattr(unrest_harness, "continuation_types", original)
        patch.delitem(sys.modules, MODULE_NAME)
        patch.setattr(sys, "dont_write_bytecode", True)
        for owner, attribute in (
            (builtins, "open"),
            (os, "open"),
            (time, "time"),
            (time, "monotonic"),
            (time, "monotonic_ns"),
            (subprocess, "Popen"),
            (socket, "socket"),
        ):
            patch.setattr(owner, attribute, forbidden(f"{owner.__name__}.{attribute}"))
        fresh = importlib.import_module(MODULE_NAME)
        assert fresh is not original
        assert sys.modules["unrest_harness.canonical_identity"] is foundation
        assert fresh.encode_value(fresh.DurationMs(MAX)) == DMAX
        assert fresh.decode_clock_reading_ms(CMAX) == fresh.ClockReadingMs("epoch1", MAX)
        assert fresh.decode_event_id(EV) == fresh.EventId(EVENT)
        assert fresh.add_durations(fresh.DurationMs(1), fresh.DurationMs(2)) == fresh.DurationMs(3)
        assert fresh.elapsed_between(
            fresh.ClockReadingMs("e", 1), fresh.ClockReadingMs("e", 4)
        ) == fresh.DurationMs(3)
        with pytest.raises(fresh.ContinuationValueError) as info:
            fresh.decode_duration_ms(b"\xef\xbb\xbf" + D0)
        assert info.value.code == "invalid_json"
        with pytest.raises(fresh.ContinuationValueError):
            fresh.encode_value(DurationMs(1))  # the original class is foreign to the fresh one
    assert attempts == []
    assert unrest_harness.continuation_types is sys.modules[MODULE_NAME] is original
    assert sys.modules["unrest_harness.canonical_identity"] is foundation
    with pytest.raises(ContinuationValueError):
        DurationMs(-1)


def test_val09_identity_is_still_the_original_in_a_later_test() -> None:
    assert unrest_harness.continuation_types is sys.modules[MODULE_NAME] is ct
    from unrest_harness.continuation_types import DurationMs as Later

    assert Later is DurationMs


# --------------------------------------------------------------------------- VAL10


def test_val10_component_and_index_registration() -> None:
    document = json.loads((ROOT / "docs/architecture/component-map.json").read_text("utf-8"))
    records = [item for item in document["components"] if item["id"] == "COMP-CONTINUATION"]
    assert records == [
        {
            "decisions": [],
            "id": "COMP-CONTINUATION",
            "invariants": [],
            "paths": [
                "src/unrest_harness/continuation_reservations.py",
                "src/unrest_harness/continuation_state.py",
                "src/unrest_harness/continuation_types.py",
            ],
            "specifications": [
                "docs/architecture/continuation-reservations.md",
                "docs/architecture/continuation-state.md",
                "docs/architecture/continuation-types.md",
            ],
            "tests": [
                "tests/test_continuation_reservations.py",
                "tests/test_continuation_state.py",
                "tests/test_continuation_types.py",
            ],
        }
    ]
    index = (ROOT / "docs/architecture/index.md").read_text(encoding="utf-8")
    assert index.count("(continuation-types.md)") == 1


# --------------------------------------------------------------------------- VAL11

EXPECTED_CODES = frozenset(
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


def test_val11_closed_public_surface() -> None:
    assert CODES == EXPECTED_CODES and len(CODES) == 15
    assert type(CODES) is frozenset
    assert DURATION_MS_MAX == 2**63 - 1 and VALUE_MAX_BYTES == 1024
    assert sorted(ct.__all__) == sorted(
        {
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
        }
    )
    assert len(ct.__all__) == 13


def test_val11_every_code_is_reachable_by_its_named_case() -> None:
    assert len(REACH) == 15
    assert {expected for expected, _ in REACH} == EXPECTED_CODES
    for expected, call in REACH:
        assert code(call) == expected


@pytest.mark.parametrize("valid", sorted(EXPECTED_CODES))
def test_val11_error_class_accepts_closed_codes(valid: str) -> None:
    error = ContinuationValueError(valid)
    assert error.code == valid and error.args == (valid,) and str(error) == valid
    assert isinstance(error, ValueError)


@pytest.mark.parametrize(
    "misuse",
    ("bogus", "", "INVALID_TYPE", 1, None, b"invalid_type", Str("invalid_type")),
    ids=repr,
)
def test_val11_misuse_of_the_error_class_is_a_constant_value_error(misuse: object) -> None:
    with pytest.raises(ValueError) as info:
        ContinuationValueError(cast(Any, misuse))
    assert type(info.value) is ValueError
    assert str(info.value) == "invalid_error_code"
    assert info.value.args == ("invalid_error_code",)
