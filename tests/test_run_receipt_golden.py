"""Run receipt constructor compatibility with the v0.4.7 base (ADR-0500, R7).

Pending terminal receipts are adopted by digest, so the run_receipt.v1 bytes
must stay identical to b307cc6 for the same prefix. The pinned digests were
computed by the b307cc6 constructor and bundled catalogue from literal inputs
only; no clock, temporary path or process identity contributes.
"""
from __future__ import annotations

from typing import cast

import pytest

import unrest_harness.run_control as runs


RUN_ID = "run:" + "a1" * 32
ISSUER = "sha256:" + "11" * 32
RUN_IDENTITY = "sha256:" + "22" * 32
SEQUENCE = 5
OBSERVED_AT = "2026-11-03T12:00:00.000Z"

# Computed from a `git archive b307cc619cc0` snapshot of src/ (module provenance
# outside this checkout) with the same literal inputs.
GOLDEN_B307CC6 = {
    "partial": "sha256:391bb642a4f5afb1dffe8e4343c3f3a4c575846489306350317f016b28665836",
    "cancelled": "sha256:e45d07f007e1c53db80e896753ae2edf9234e679b81b8ebaced91acdef2bb0b4",
    "failed": "sha256:8904cc939b1f870ccaf18aa70c8a907e36d572b407141c95b174caebfcccbdbc",
    "succeeded": "sha256:0f8e62c09b1ca403cdf4eed7b3a3b43c421dc316f94cb15b1b2d6a0e128442b8",
}


class _LiteralEvents:
    def _load_events(self, run_id: str) -> tuple[runs._Event, ...]:
        assert run_id == RUN_ID
        return tuple(
            runs._Event(index, "queued", OBSERVED_AT, "sha256:" + f"{index:064x}", None, {})
            for index in range(1, SEQUENCE)
        )


def _request() -> runs._Request:
    return runs._Request(
        run_id=RUN_ID,
        operation="start_project",
        arguments={},
        idempotency_key="golden",
        resource_key="workspace:golden",
        project_id=None,
        created_at=OBSERVED_AT,
        run_identity_digest=RUN_IDENTITY,
        control_identity_digest="sha256:" + "33" * 32,
        issuer_identity_digest=ISSUER,
        generation=1,
    )


@pytest.mark.parametrize("outcome", sorted(GOLDEN_B307CC6))
def test_run_receipt_digest_matches_b307cc6_constructor(outcome: str) -> None:
    # The constructor only reads the event prefix; a literal stub replaces storage.
    stub = cast(runs.RunControl, _LiteralEvents())
    receipt = runs.RunControl._construct_run_receipt(stub, _request(), outcome)
    assert receipt.digest == GOLDEN_B307CC6[outcome]
    assert receipt.record["receipt_id"] == f"receipt:run_receipt.v1:{'a1' * 32}:{SEQUENCE}"
    assert receipt.record["observed_at"] == OBSERVED_AT


def test_four_candidates_are_exactly_the_pending_receipt_outcomes() -> None:
    assert tuple(runs._RECEIPT_TERMINALS) == ("partial", "cancelled", "failed", "succeeded")
    assert set(GOLDEN_B307CC6) == set(runs._RECEIPT_TERMINALS)
    assert len(set(GOLDEN_B307CC6.values())) == 4
