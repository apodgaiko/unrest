from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from unittest.mock import patch
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from unrest_harness import api
from unrest_harness.acp_runner import ACPNodeDispatcher
from unrest_harness.cli import cli
from unrest_harness.config import HarnessConfig
from unrest_harness.dispatcher import DispatchRequest
from unrest_harness.foundation_tools import FoundationToolError
from unrest_harness.measurement import (
    BaselineRunner,
    GLOBAL_REPORTED_COST_USD,
    InvocationOutcome,
    MeasurementError,
    bundled_protocol_path,
    load_protocol,
    measure_baseline,
    protected_product_digest,
    publish_bundle,
    verify_bundle,
)
from unrest_harness.models import Task

ROOT = Path(__file__).resolve().parents[1]
BUNDLED = ROOT / "src" / "unrest_harness" / "bundled"
MOCK_MEASUREMENT_ACP = Path(__file__).with_name("mock_measurement_acp.py")


class TickClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        self.value += 1.0
        return self.value


class FakeProvider:
    def __init__(
        self,
        *,
        fail_invocation: str | None = None,
        cache_status: str = "disabled",
        cost: float | None = 0.01,
        clock: TickClock | None = None,
    ) -> None:
        self.fail_invocation = fail_invocation
        self.cache_status = cache_status
        self.cost = cost
        self.clock = clock
        self.calls: list[tuple[str, Path, Path | None]] = []

    async def invoke(
        self,
        *,
        role: str,
        prompt: str,
        cold_root: Path,
        private_root: Path,
        invocation_id: str,
        timeout_seconds: float,
        project_record_path: Path | None = None,
    ) -> InvocationOutcome:
        del role, prompt, private_root, timeout_seconds
        self.calls.append((invocation_id, cold_root, project_record_path))
        if self.clock is not None:
            ordinal = int(invocation_id.split("-")[1])
            self.clock.value += float((ordinal - 1) % 5)
        if self.fail_invocation == invocation_id:
            return InvocationOutcome(
                status="failed",
                parsed=None,
                provider="fake",
                cache_status=self.cache_status,  # type: ignore[arg-type]
                error_code="seeded_failure",
            )
        if invocation_id.endswith("-rejected"):
            parsed: dict[str, Any] = {"artifact_text": "p2: rejected\n"}
        elif invocation_id.endswith("-rework"):
            parsed = {"artifact_text": "unrest baseline p2\n"}
        elif "-p1-author" in invocation_id:
            parsed = {"artifact_text": "unrest baseline p1\n"}
        elif invocation_id.endswith("-candidate"):
            parsed = {"artifact_text": "setting=improved\n"}
        elif "-e2-" in invocation_id:
            parsed = {"decision": "reject"}
        else:
            parsed = {"decision": "accept"}
        return InvocationOutcome(
            status="completed",
            parsed=parsed,
            provider="fake",
            model="fake-v1",
            route="local-test",
            input_tokens=10,
            output_tokens=5,
            reported_cost_usd=self.cost,
            cache_status=self.cache_status,  # type: ignore[arg-type]
        )


def _config(tmp_path: Path) -> HarnessConfig:
    return HarnessConfig(
        bundled_dir=BUNDLED,
        harness_home=tmp_path / "home",
        projects_dir=tmp_path / "home" / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=f"{sys.executable} {MOCK_MEASUREMENT_ACP}",
        validator_provider_name="claude",
        validator_acp_command=f"{sys.executable} {MOCK_MEASUREMENT_ACP}",
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
    )


def _source(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\n")
    (root / "product.txt").write_text("candidate\n")
    results = root / "docs/v03/measurement/results"
    results.mkdir(parents=True)
    (results / ".gitkeep").write_text("")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    return root


async def _synthetic_case(
    runner: BaselineRunner,
    repetition_id: str,
    case_id: str,
    cold_root: Path,
) -> dict[str, Any]:
    """Fast protocol arithmetic fixture; real state-machine paths are tested below."""

    phases = {
        "P1": ("author", "validator"),
        "P2": ("rejected", "validator-reject", "rework", "validator-accept"),
        "E1": ("candidate", "evaluation", "review"),
        "E2": ("evaluation", "review"),
    }[case_id]
    passed = True
    for phase in phases:
        outcome = await runner._invoke(
            repetition_id,
            case_id,
            phase,
            "fixture",
            "fixture",
            cold_root,
        )
        passed = passed and outcome.status == "completed"
    result: dict[str, Any] = {
        "oracle_passed": passed,
        "failure": None if passed else "oracle_failed",
        "transition_count": len(phases) + 3,
        "rework_count": 1 if case_id == "P2" else 0,
        "artifact_digest": "sha256:" + "0" * 64,
    }
    if case_id == "E2":
        result["promotion_applied"] = False
    return result


def _run(
    tmp_path: Path,
    provider: FakeProvider,
    *,
    clock: TickClock | None = None,
) -> tuple[dict[str, Any], Path, Path]:
    source = _source(tmp_path)
    destination = source / "docs/v03/measurement/results/v0.3.1"
    command = f"{sys.executable} {MOCK_MEASUREMENT_ACP}"
    previous = {
        name: os.environ.get(name)
        for name in ("UNREST_WORKER_ACP_COMMAND", "UNREST_VALIDATOR_ACP_COMMAND")
    }
    os.environ["UNREST_WORKER_ACP_COMMAND"] = command
    os.environ["UNREST_VALIDATOR_ACP_COMMAND"] = command
    try:
        with patch.object(BaselineRunner, "_execute_case", _synthetic_case):
            summary = measure_baseline(
                "fm010-baseline-v1",
                str(destination),
                True,
                config=_config(tmp_path),
                provider=provider,
                source_root=source,
                clock=clock or TickClock(),
            )
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    return summary, source, destination


def test_successful_exact_protocol_publishes_sanitized_recomputable_bundle(
    tmp_path: Path,
) -> None:
    provider = FakeProvider()
    summary, _, destination = _run(tmp_path, provider)

    assert summary == {
        "status": "published",
        "repetition_count": 20,
        "provider_invocation_count": 55,
        "bundle_digest": summary["bundle_digest"],
    }
    bundle_path = destination / "bundle.json"
    bundle = json.loads(bundle_path.read_text())
    assert verify_bundle(bundle)
    assert bundle["bundle_digest"] == summary["bundle_digest"]
    assert [record["case_id"] for record in bundle["repetitions"]] == [
        case for case in ("P1", "P2", "E1", "E2") for _ in range(5)
    ]
    assert {record["rework_count"] for record in bundle["repetitions"][5:10]} == {1}
    assert all(event["parent_repetition_id"] for event in bundle["provider_invocations"])
    assert len({cold_root for _, cold_root, _ in provider.calls}) == 20
    private_root = next((_config(tmp_path).harness_home / "measurement-private").iterdir())
    repetition_roots = sorted(private_root.glob("cold-roots/rep-*/workspace"))
    assert len(repetition_roots) == 20
    assert len({root.parent for root in repetition_roots}) == 20
    public = bundle_path.read_text().lower()
    for private_word in ("prompt", "response_text", "transcript", "source_body"):
        assert private_word not in public
    assert os.stat(private_root).st_mode & 0o077 == 0


def test_evolution_cases_use_real_public_state_machine_and_cold_state(tmp_path: Path) -> None:
    source = _source(tmp_path)
    config = _config(tmp_path)
    provider = FakeProvider()
    runner = BaselineRunner(
        config=config,
        protocol=load_protocol("fm010-baseline-v1", config),
        provider=provider,
        source_root=source,
        clock=TickClock(),
    )
    command = f"{sys.executable} {MOCK_MEASUREMENT_ACP}"
    with patch.dict(
        os.environ,
        {
            "UNREST_WORKER_ACP_COMMAND": command,
            "UNREST_VALIDATOR_ACP_COMMAND": command,
        },
    ):
        records = [
            asyncio.run(runner._run_repetition(index, case_id))
            for index, case_id in ((11, "E1"), (16, "E2"))
        ]
    assert all(record["oracle_passed"] for record in records)
    assert records[1]["promotion_applied"] is False
    assert len(runner.invocations) == 5
    roots = sorted(runner.private_root.glob("cold-roots/rep-*/harness-home/projects"))
    assert len(roots) == 2
    project_names = [next(root.iterdir()).name for root in roots]
    assert len(set(project_names)) == 2
    for invocation_id, _, project_record in provider.calls:
        if invocation_id.endswith("-candidate"):
            assert project_record is None
        else:
            assert project_record is not None and project_record.name.startswith("oracle-")


@pytest.mark.parametrize(
    ("provider", "expected_status"),
    [
        (FakeProvider(fail_invocation="rep-11-e1-candidate"), "invalid"),
        (FakeProvider(cache_status="hit"), "invalid"),
        (FakeProvider(cost=GLOBAL_REPORTED_COST_USD + 1), "invalid"),
    ],
)
def test_oracle_cache_and_cost_fail_closed(
    tmp_path: Path,
    provider: FakeProvider,
    expected_status: str,
) -> None:
    summary, _, destination = _run(tmp_path, provider)
    assert summary["status"] == expected_status
    assert summary["bundle_digest"] is None
    observation = destination / f"{expected_status}-observation.json"
    assert observation.is_file()
    assert json.loads(observation.read_text())["status"] == expected_status
    assert not (destination / "bundle.json").exists()


def test_noise_over_fifteen_percent_is_inconclusive(tmp_path: Path) -> None:
    clock = TickClock()
    summary, _, destination = _run(
        tmp_path,
        FakeProvider(clock=clock),
        clock=clock,
    )
    assert summary["status"] == "inconclusive"
    assert summary["bundle_digest"] is None
    assert (destination / "inconclusive-observation.json").is_file()
    assert not (destination / "bundle.json").exists()


def test_unknown_reported_cost_is_not_collapsed_to_zero(tmp_path: Path) -> None:
    summary, _, destination = _run(tmp_path, FakeProvider(cost=None))
    assert summary["status"] == "invalid"
    assert summary["bundle_digest"] is None
    observation = json.loads((destination / "invalid-observation.json").read_text())
    assert observation["reported_cost_status"] == "unavailable"
    assert observation["reported_cost_usd"] is None
    assert observation["unknown_reported_cost_count"] == 55


def test_prompt_marker_alone_cannot_claim_cache_disabled(tmp_path: Path) -> None:
    config = _config(tmp_path)
    dispatcher = ACPNodeDispatcher(config)
    workspace = tmp_path / "marker-workspace"
    workspace.mkdir()
    project = dispatcher.store.create_project("cache marker", workspace)
    task_payload = BaselineRunner._p1_tasks()[0]
    task_payload["body"] += "\nFM-010-FROZEN-COLD-CACHE"
    task = Task.model_validate(task_payload)
    dispatcher._record_invocation(
        DispatchRequest(
            project_id=project.id,
            mission_id="mission-001",
            task=task,
            spawn_ts="2026-08-24T00-00-00Z",
        ),
        0.01,
    )
    telemetry = next(
        (
            dispatcher.store.unrest_runtime_dir(project.id)
            / "missions/mission-001/provider-invocations"
        ).iterdir()
    )
    assert json.loads(telemetry.read_text())["cache_status"] == "unknown"


def test_confirmation_and_protocol_drift_do_not_invoke_provider(tmp_path: Path) -> None:
    provider = FakeProvider()
    with pytest.raises(MeasurementError, match="MEASUREMENT-000"):
        measure_baseline(
            "fm010-baseline-v1",
            "unused",
            False,
            config=_config(tmp_path),
            provider=provider,
            source_root=_source(tmp_path),
        )
    assert provider.calls == []

    mutated = json.loads(bundled_protocol_path(_config(tmp_path)).read_text())
    mutated["concurrency"] = 2
    protocol = tmp_path / "mutated.json"
    protocol.write_text(json.dumps(mutated))
    with pytest.raises(MeasurementError, match="MEASUREMENT-002"):
        load_protocol(str(protocol), _config(tmp_path))


def test_exact_cli_and_library_result_and_error_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    published = {
        "status": "published",
        "repetition_count": 20,
        "provider_invocation_count": 55,
        "bundle_digest": "sha256:" + "a" * 64,
    }
    monkeypatch.setattr("unrest_harness.measurement.measure_baseline", lambda *args: published)
    result = CliRunner().invoke(
        cli,
        [
            "measure-baseline",
            "--protocol",
            "fm010-baseline-v1",
            "--destination",
            "results",
            "--confirm-provider-work",
        ],
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == published

    monkeypatch.setattr(api, "_measure_baseline", lambda *args: published)
    assert api.measure_baseline("fm010-baseline-v1", "results", True) == published

    def reject(*args: object) -> dict[str, Any]:
        del args
        raise MeasurementError("private detail")

    monkeypatch.setattr(api, "_measure_baseline", reject)
    with pytest.raises(FoundationToolError) as caught:
        api.measure_baseline("fm010-baseline-v1", "results", False)
    assert caught.value.as_envelope() == {
        "error": {"code": "invalid_argument", "message": "invalid argument"}
    }


def test_product_digest_excludes_only_results(tmp_path: Path) -> None:
    source = _source(tmp_path)
    first = protected_product_digest(source)
    result = source / "docs/v03/measurement/results/.gitkeep"
    result.write_text("published material\n")
    assert protected_product_digest(source) == first
    (source / "product.txt").write_text("drift\n")
    assert protected_product_digest(source) != first


def test_publication_rejects_unknown_or_private_fields_and_preserves_existing(
    tmp_path: Path,
) -> None:
    summary, _, destination = _run(tmp_path, FakeProvider())
    original = (destination / "bundle.json").read_bytes()
    bundle = json.loads(original)
    bundle["unknown"] = "prompt-canary"
    unsigned = dict(bundle)
    unsigned.pop("bundle_digest")
    from unrest_harness.measurement import _digest_value

    bundle["bundle_digest"] = _digest_value(unsigned)
    assert not verify_bundle(bundle)
    with pytest.raises(MeasurementError, match="MEASUREMENT-010"):
        publish_bundle(bundle, destination)
    bundle = json.loads(original)
    bundle["provider_invocations"][0]["provider"] = "prompt-canary"
    unsigned = dict(bundle)
    unsigned.pop("bundle_digest")
    bundle["bundle_digest"] = _digest_value(unsigned)
    assert verify_bundle(bundle)
    with pytest.raises(MeasurementError, match="MEASUREMENT-009"):
        publish_bundle(bundle, destination)
    assert (destination / "bundle.json").read_bytes() == original
    assert summary["status"] == "published"


def test_installed_protocol_discovery_and_help_are_cwd_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _config(tmp_path)
    assert load_protocol("fm010-baseline-v1", config)["protocol_id"] == "fm010-baseline-v1"
    result = CliRunner().invoke(cli, ["measure-baseline", "--help"])
    assert result.exit_code == 0
    assert "--confirm-provider-work" in result.output
    assert not (config.harness_home / "measurement-private").exists()
