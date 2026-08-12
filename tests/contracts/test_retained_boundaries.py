"""Compact executable manifest for the five review-named retained boundaries."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


SINK_NODES = (
    (
        "SEC-SINK-CALLBACK-RESULT",
        "tests/test_capability_policy.py::test_callback_result_error_and_workspace_write_redact_inventory",
    ),
    (
        "SEC-SINK-CALLBACK-ERROR",
        "tests/test_capability_policy.py::test_callback_result_error_and_workspace_write_redact_inventory",
    ),
    (
        "SEC-SINK-PROGRESS",
        "tests/test_capability_policy.py::test_progress_redaction_spans_chunks_callbacks_and_message_ids",
    ),
    (
        "SEC-SINK-ADAPTER-STDERR",
        "tests/test_acp_runner.py::test_adapter_stderr_and_log_sink_redact_before_emission",
    ),
    (
        "SEC-SINK-TERMINAL-SNAPSHOT",
        "tests/test_capability_policy.py::test_raw_acp_terminal_protocol_redacts_credential_values",
    ),
    (
        "SEC-SINK-ACP-WIRE",
        "tests/test_capability_policy.py::test_callback_result_error_and_workspace_write_redact_inventory",
    ),
    (
        "SEC-SINK-WORK-HANDOFF",
        "tests/test_server.py::test_mcp_handoff_is_redacted_before_tool_return",
    ),
    (
        "SEC-SINK-VALIDATE-HANDOFF",
        "tests/test_server.py::test_redacted_mcp_handoffs_survive_restart_and_mirroring",
    ),
    (
        "SEC-SINK-TERMINAL-HANDOFF",
        "tests/test_server.py::test_mcp_handoff_is_redacted_before_tool_return",
    ),
    (
        "SEC-SINK-DURABLE-MIRROR",
        "tests/test_server.py::test_redacted_mcp_handoffs_survive_restart_and_mirroring",
    ),
    (
        "SEC-SINK-RUNTIME-CURSOR",
        "tests/test_lean_provider_security_runtime.py::test_store_snapshot_redacts_attempt_cursor_and_mirror",
    ),
    (
        "SEC-SINK-CLI",
        "tests/test_cli.py::test_lifecycle_commands_ignore_stale_dispatch_provider_and_abort_redacts",
    ),
    (
        "SEC-SINK-LOG",
        "tests/test_acp_runner.py::test_adapter_stderr_and_log_sink_redact_before_emission",
    ),
    (
        "SEC-SINK-BOOTSTRAP",
        "tests/test_cli.py::test_bootstrap_writer_redacts_exact_credential_before_persistence",
    ),
    (
        "SEC-SINK-WORKSPACE-WRITE",
        "tests/test_capability_policy.py::test_callback_result_error_and_workspace_write_redact_inventory",
    ),
    (
        "SEC-SINK-CODEX-CONFIG",
        "tests/test_capability_policy.py::test_codex_structured_config_drops_exact_aliases_and_preserves_config",
    ),
    (
        "SEC-SINK-DIAGNOSTIC",
        "tests/test_lean_provider_security_runtime.py::test_tool_error_message_and_details_use_explicit_inventory",
    ),
)

SCENARIOS = (
    (
        "VAL-PERMISSION-001",
        "live-permission-handler",
        "tests/test_capability_policy.py::test_permission_request_handler_is_finite_and_fail_closed",
    ),
    *(
        ("VAL-REDACT-001", sink_id, node)
        for sink_id, node in SINK_NODES
    ),
    (
        "VAL-REDACT-001",
        "streaming-boundary-matrix",
        "tests/test_lean_provider_security_runtime.py::test_streaming_redactor_handles_empty_flush_overlap_collisions_and_unicode_bytes",
    ),
    (
        "VAL-OBSERVE-001",
        "schema-v2-exact-capture-budgets",
        "tests/test_runtime_observability.py::test_capture_budget_boundaries_are_exact",
    ),
    (
        "VAL-OBSERVE-001",
        "schema-v2-three-retry-exhaustion",
        "tests/test_runtime_observability.py::test_observation_exhausts_exactly_three_changed_snapshot_retries",
    ),
    (
        "VAL-OBSERVE-001",
        "schema-v2-identity-and-fd-inventory",
        "tests/test_runtime_observability.py::test_capture_identity_mutation_and_descriptor_inventory_are_safe",
    ),
    (
        "VAL-PATH-001",
        "atomic-containment-hashes",
        "tests/test_storage.py::TestAtomicWriteText::test_atomic_containment_matrix_preserves_inside_and_outside_hashes",
    ),
    (
        "VAL-SPAWNTS-001",
        "ascii-utc-calendar-grammar",
        "tests/test_runtime_observability.py::test_spawn_timestamp_parser_uses_fixed_ascii_utc_calendar_grammar",
    ),
)


@pytest.mark.parametrize(
    ("assertion_id", "scenario_id", "candidate_node"),
    SCENARIOS,
    ids=[f"{assertion_id}__{scenario_id}" for assertion_id, scenario_id, _ in SCENARIOS],
)
def test_retained_boundary_scenario(
    assertion_id: str,
    scenario_id: str,
    candidate_node: str,
    lean_reference_run,
    repository_root: Path,
) -> None:
    security_contract = (
        repository_root / "docs/proposals/batch-0.5/security-contract.md"
    ).read_text(encoding="utf-8")
    catalog = tuple(
        re.findall(r"^\| (SEC-SINK-[A-Z-]+) \|", security_contract, re.MULTILINE)
    )
    assert len(catalog) == len(set(catalog)) == 17
    assert set(catalog) == {sink_id for sink_id, _node in SINK_NODES}
    assert candidate_node in lean_reference_run.nodes
    assert lean_reference_run.returncode == 0, lean_reference_run.output
