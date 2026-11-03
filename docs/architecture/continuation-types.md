# Continuation value types and value codec v1

`continuation_types` defines three immutable values and one closed canonical
wire profile for them. It is an inert leaf module: nothing in the product
imports it, and it reads no clock, file, environment, process or network
state. A value or its bytes is not a custody record, authorization, admission,
budget account or delivery acknowledgement; those surfaces need their own
accepted contracts.

## Values

- `DurationMs(value)` — a non-negative duration in milliseconds.
- `ClockReadingMs(epoch_id, elapsed_ms)` — milliseconds elapsed within one
  caller-supplied epoch. `epoch_id` is an opaque token; it does not prove a
  boot, process or host identity.
- `EventId(value)` — exactly `del-` followed by 64 lowercase hexadecimal
  digits. The module does not generate, derive or hash event identifiers and
  does not claim global uniqueness or remote deduplication.

Millisecond fields are native Python `int` only (`type(x) is int`), in the
range `0..2**63-1` (`DURATION_MS_MAX`). `bool`, `int` subclasses, `IntEnum`,
floats, strings and decimals are refused rather than normalized. `epoch_id`
must fully match `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` and the event value must
fully match `del-[0-9a-f]{64}`; both must be exact `str` instances. A clock
reading checks `epoch_id` before `elapsed_ms` in its constructor, at every
public boundary and in the decoder.

The values are frozen, slotted dataclasses with field equality and hashing, no
ordering and no arithmetic operators. Because frozen dataclasses can still be
bypassed (`object.__setattr__`, `object.__new__`, subclasses), every public
function revalidates the exact class and every field of each argument, in
argument order, before using it. An empty slot or a foreign class is
`invalid_type`.

## Operations

- `add_durations(a, b)` returns the exact sum or refuses `duration_overflow`;
  it never saturates.
- `elapsed_between(earlier, later)` returns the exact difference within one
  epoch. Different epochs are `epoch_mismatch` (checked first); a lower later
  reading is `clock_regression`. There is no clamp, default or uncertainty
  flag.

## Wire profile v1

Each value encodes to exactly one flat Canonical JSON v1 object produced by the
unchanged foundation encoder (sorted keys, one trailing LF):

```text
{"kind":"duration_ms","schema_version":1,"value":"<dec>"}
{"elapsed_ms":"<dec>","epoch_id":"<epoch>","kind":"clock_ms","schema_version":1}
{"kind":"delivery_event_id_v1","schema_version":1,"value":"del-<64 hex>"}
```

Milliseconds are always decimal strings matching `0|[1-9][0-9]{0,18}` (ASCII
digits only, no sign, no leading zero) and at most `2**63-1`, so values above
`2**53-1` survive JSON consumers unchanged. `schema_version` is the JSON
integer `1`. Accepted bytes re-encode to identical bytes. Legacy nanosecond or
unversioned forms are refused, never read or migrated.

Each typed decoder accepts only exact `bytes` and checks, in order: input
type, size at most `VALUE_MAX_BYTES` (1024) before parsing, the foundation
`verify_canonical_json_bytes`, a top-level object with `kind` and
`schema_version`, the expected `kind`, `schema_version == 1`, the exact key
set, then the fields.

## Errors

Every refusal is `ContinuationValueError` with one code from the closed public
set `CODES`: `invalid_type`, `out_of_range`, `invalid_epoch_id`,
`invalid_event_id`, `duration_overflow`, `epoch_mismatch`,
`clock_regression`, `invalid_input_type`, `input_too_large`, `invalid_json`,
`non_canonical`, `invalid_shape`, `kind_mismatch`, `unsupported_version` and
`invalid_decimal`. `str(error)` and `args` contain only the code. Constructing
the error with anything else raises a plain `ValueError("invalid_error_code")`.

Errors carry no input: the cause is always empty, and the module's own or the
foundation's exceptions never become the error context. A caller's active
exception may become the context, as Python does for any raise inside a
handler. Frame locals in a traceback are outside this guarantee.

Only the foundation verifier is contained, and only for
`FoundationValidationError`, `ValueError`, `RecursionError` and `TypeError`.
Its `non_canonical_bytes` becomes `non_canonical`; every other contained
failure becomes `invalid_json`. Other exceptions propagate unchanged.

The code is a deterministic function of the input, with one exception: input
nested deeply enough to reach the interpreter recursion limit may yield either
`invalid_json` or the structural code it would otherwise produce, depending on
the caller's stack depth. It never escapes as a raw exception. Input above
1024 bytes is refused deterministically before parsing.

## Verification

`tests/test_continuation_types.py` covers literal golden bytes and their
SHA-256, the input-to-code tables, legacy literals, the depth corpus,
revalidation bypasses, error privacy in and outside a caller's handler,
containment by fault injection, the import allowlist with zero product
importers, and an effect-free fresh import that restores module identity.
Linux CI, release-guard collection and the full source suite are separate
release obligations.
