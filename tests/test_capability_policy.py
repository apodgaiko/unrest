"""Strict role capability policy, provider, ACP, and initialization contracts."""
from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import shutil
import string
import subprocess
import sys
import tarfile
import tomllib
import urllib.parse
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import unrest_harness.capability_policy as capability_policy
from unrest_harness.acp_runner import (
    ACPClient,
    ACPError,
    ACPNodeRunner,
    ACPProgressTracker,
    _acp_subprocess_env,
    _load_redacted_json,
    _redact_json_value,
    _redact_terminal_bytes,
)
from unrest_harness.assets import AssetLoader
from unrest_harness.capability_policy import (
    CAPABILITY_PROFILE_ENV,
    CAPABILITY_VERSION_ENV,
    SAFE_PROFILE,
    UNSAFE_DEVELOPMENT_ENV,
    UNSAFE_DEVELOPMENT_PROFILE,
    CapabilityAccessError,
    CapabilityBoundaryError,
    CapabilityPolicy,
    CapabilityPolicyError,
    StreamingCredentialRedactor,
    build_role_environment,
    classify_environment_value,
    contains_semantic_credential,
    credential_source_values,
    enforce_environment_credential_provenance,
    enforce_persisted_environment_credential_provenance,
    is_credential_source_name,
    load_capability_policy,
    profile_environment,
    redact_credential_values,
    redact_sensitive_value,
    resolve_role_capability,
    sensitive_value_provenance,
    sensitive_values,
    validate_provider_support,
)
from unrest_harness.cli import cli
from unrest_harness.config import HarnessConfig
from unrest_harness.models import Task
from unrest_harness.providers import PROVIDERS, provider_names_for_role
from unrest_harness.storage import ProjectStore

_ROOT = Path(__file__).resolve().parents[1]
_BUNDLED = _ROOT / "src" / "unrest_harness" / "bundled"
_FORBIDDEN_SAFE_SENTINELS = (
    "bypassPermissions",
    "danger-full-access",
    "agent-full-access",
    '"approval_policy":"never"',
    "CODEX_DISABLE_SANDBOX",
)


def _node_ceiling_source(value: str, *, key: str) -> str:
    payload = {
        f"a{index:04d}": f"ordinary-{index:04d}"
        for index in range(2055)
    }
    payload[f"zzzz_{key}"] = value
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _text_ceiling_source(value: str, *, key: str) -> str:
    return json.dumps(
        {
            "padding": "x" * (256 * 1024),
            f"zzzz_{key}": value,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _padding_free_base64(value: str, *, layers: int) -> str:
    for _ in range(layers):
        value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return value


def test_text_ceiling_counts_utf8_bytes_and_reports_bound_plus_one() -> None:
    bound = capability_policy._SEMANTIC_INSPECTION_MAX_TEXT
    exact = "é" * (bound // 2)
    over = exact + "a"

    exact_traversal = capability_policy._bounded_semantic_traversal(exact)
    over_traversal = capability_policy._bounded_semantic_traversal(over)

    assert dict(exact_traversal.resource_usage)["text_bytes"] == bound
    assert not exact_traversal.exhausted
    assert dict(over_traversal.resource_usage)["text_bytes"] == bound + 1
    assert over_traversal.exhaustion_reasons == ("text_bytes",)


def test_structural_depth_and_transform_counters_do_not_alias() -> None:
    value: Any = "ordinary"
    for _ in range(capability_policy._SEMANTIC_INSPECTION_MAX_DEPTH):
        value = [value]
    exact = capability_policy._bounded_semantic_traversal(value)
    over_value = [value]
    over = capability_policy._bounded_semantic_traversal(over_value)

    assert dict(exact.resource_usage)["semantic_depth"] == 24
    assert dict(exact.resource_usage)["transform_count"] == 0
    assert not exact.exhausted
    assert "semantic_depth" in over.exhaustion_reasons
    assert "transform_count" not in over.exhaustion_reasons


@pytest.mark.parametrize("container_kind", ("list", "mapping"))
def test_cyclic_containers_have_stable_value_free_boundary_diagnostics(
    container_kind: str,
) -> None:
    if container_kind == "list":
        value: Any = []
        value.append(value)
    else:
        value = {}
        value["child"] = value

    traversal = capability_policy._bounded_semantic_traversal(value)
    assert traversal.exhaustion_reasons == ("cyclic-container",)
    with pytest.raises(
        CapabilityBoundaryError,
        match=(
            r"^CAP-BOUNDARY-001 classification=cyclic-container: "
            r"output blocked before serialization$"
        ),
    ) as captured:
        redact_sensitive_value(value)
    assert "child" not in str(captured.value)
    with pytest.raises(CapabilityBoundaryError) as acp_captured:
        _redact_json_value(value, {})
    assert str(acp_captured.value) == str(captured.value)


def test_shared_acyclic_container_is_not_misclassified_as_a_cycle() -> None:
    shared = {"model": "ordinary"}
    value = [shared, shared]
    assert redact_sensitive_value(value) == value


def test_canonical_redaction_boundary_is_idempotent_with_explicit_inventory() -> None:
    first = "RAW_ACP_FIRST_CREDENTIAL_79d0b1"
    second = "RAW_ACP_SECOND_CREDENTIAL_f821a4"
    inventory = {
        "OPENAI_API_KEY": second,
        "ZAI_API_KEY": first,
    }
    payload = {
        "output": (
            f"OPENAI_API_KEY={second}\n"
            f"ZAI_API_KEY={first}\n"
            "plain=kept\n"
        )
    }

    redacted = redact_sensitive_value(payload, inventory)

    assert redacted == {
        "output": (
            "OPENAI_API_KEY=<redacted:OPENAI_API_KEY>\n"
            "ZAI_API_KEY=<redacted:ZAI_API_KEY>\n"
            "plain=kept\n"
        )
    }
    assert redact_sensitive_value(redacted, inventory) == redacted


def test_transform_bound_plus_one_preserves_raw_source_provenance() -> None:
    secret = "token=layer25-secret-0123456789abcdef"
    layered = _padding_free_base64(
        secret,
        layers=capability_policy._SEMANTIC_INSPECTION_MAX_TRANSFORMS + 1,
    )

    classification = classify_environment_value(
        "credential",
        layered,
        declared=True,
    )
    redacted = redact_sensitive_value({"credential": layered})

    assert classification.sensitive
    assert classification.fail_closed
    assert redacted != {"credential": layered}
    serialized = json.dumps(redacted, sort_keys=True)
    assert layered not in serialized
    assert "layer25-secret" not in serialized


@pytest.mark.parametrize(
    ("constant_name", "field_name", "bound", "values"),
    (
        (
            "_SEMANTIC_INSPECTION_MAX_DEPTH",
            "semantic_depth",
            1,
            ("ordinary", ["ordinary"], [["ordinary"]]),
        ),
        (
            "_SEMANTIC_INSPECTION_MAX_NODES",
            "semantic_nodes",
            2,
            ("ordinary", ["ordinary"], ["ordinary", 1]),
        ),
        (
            "_SEMANTIC_INSPECTION_MAX_EXPANSIONS",
            "expansion_nodes",
            2,
            ([1], [1, 2], [1, 2, 3]),
        ),
        (
            "_SEMANTIC_INSPECTION_MAX_TEXT",
            "text_bytes",
            2,
            ("a", "é", "éa"),
        ),
        (
            "_SEMANTIC_INSPECTION_MAX_WORK",
            "aggregate_work_bytes",
            2,
            ("!", "!!", "!!!"),
        ),
        (
            "_FORMAT_AST_MAX_DEPTH",
            "format_ast_depth",
            1,
            ("{x}", "{x:{y}}", "{x:{y:{z}}}"),
        ),
    ),
)
def test_independent_resource_counters_accept_exact_bound_and_classify_plus_one(
    monkeypatch: pytest.MonkeyPatch,
    constant_name: str,
    field_name: str,
    bound: int,
    values: tuple[Any, Any, Any],
) -> None:
    monkeypatch.setattr(capability_policy, constant_name, bound)
    traversals = tuple(
        capability_policy._bounded_semantic_traversal(value)
        for value in values
    )
    observations = tuple(
        dict(traversal.resource_usage)[field_name]
        for traversal in traversals
    )

    assert observations == (bound - 1, bound, bound + 1)
    assert field_name not in traversals[0].exhaustion_reasons
    assert field_name not in traversals[1].exhaustion_reasons
    assert field_name in traversals[2].exhaustion_reasons


def test_transform_counter_accepts_exact_bound_and_classifies_plus_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        capability_policy,
        "_SEMANTIC_INSPECTION_MAX_TRANSFORMS",
        2,
    )
    values = []
    for layers in (1, 2, 3):
        value = "ordinary!"
        for _ in range(layers):
            value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        values.append(value)
    traversals = tuple(
        capability_policy._bounded_semantic_traversal(value)
        for value in values
    )
    assert tuple(
        dict(traversal.resource_usage)["transform_count"]
        for traversal in traversals
    ) == (1, 2, 3)
    assert "transform_count" not in traversals[0].exhaustion_reasons
    assert "transform_count" not in traversals[1].exhaustion_reasons
    assert "transform_count" in traversals[2].exhaustion_reasons


def test_decoded_byte_counter_accepts_exact_bound_and_classifies_plus_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        capability_policy,
        "_SEMANTIC_INSPECTION_MAX_DECODED_BYTES",
        9,
    )
    values = tuple(
        base64.urlsafe_b64encode(("!" * size).encode()).decode().rstrip("=")
        for size in (8, 9, 10)
    )
    traversals = tuple(
        capability_policy._bounded_semantic_traversal(value)
        for value in values
    )
    assert tuple(
        dict(traversal.resource_usage)["decoded_bytes"]
        for traversal in traversals
    ) == (8, 9, 10)
    assert "decoded_bytes" not in traversals[0].exhaustion_reasons
    assert "decoded_bytes" not in traversals[1].exhaustion_reasons
    assert "decoded_bytes" in traversals[2].exhaustion_reasons


def _percent_all(value: str) -> str:
    return "".join(f"%{byte:02X}" for byte in value.encode())


def _reversible_alias(value: str, family: str) -> str:
    if family == "raw":
        return value
    if family == "percent":
        return _percent_all(value)
    if family == "double-percent":
        return _percent_all(_percent_all(value))
    if family == "base64":
        return _padding_free_base64(value, layers=2)
    if family == "hex":
        return value.encode().hex().encode().hex()
    if family == "mixed":
        return _padding_free_base64(
            _percent_all(value).encode().hex(),
            layers=2,
        )
    raise AssertionError(family)


def _resolved(
    tmp_path: Path,
    *,
    provider_name: str = "claude",
    role: str = "worker",
    profile: str = SAFE_PROFILE,
):
    workspace = tmp_path / "workspace"
    record = tmp_path / "record"
    workspace.mkdir(exist_ok=True)
    record.mkdir(exist_ok=True)
    policy = load_capability_policy(_BUNDLED)
    return resolve_role_capability(
        PROVIDERS[provider_name],  # type: ignore[index]
        role=role,  # type: ignore[arg-type]
        policy=policy,
        profile=profile,
        workspace=workspace,
        project_record=record,
    )


def _workspace_archive_payloads(
    workspace: Path,
    archive_path: Path,
) -> dict[str, bytes]:
    with tarfile.open(archive_path, "w") as archive:
        for path in sorted(workspace.rglob("*")):
            if path.is_file():
                archive.add(path, arcname=path.relative_to(workspace))
    payloads: dict[str, bytes] = {}
    with tarfile.open(archive_path, "r") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            assert extracted is not None
            payloads[member.name] = extracted.read()
    return payloads


def _sensitivity_taxonomy() -> tuple[tuple[str, str, str, bool, bool], ...]:
    secret = "v18/credential+0123456789abcdef"
    encoded = urllib.parse.quote(secret, safe="")
    double_encoded = urllib.parse.quote(encoded, safe="")
    base64_secret = _padding_free_base64(secret, layers=2)
    deep_alias = _padding_free_base64(secret, layers=26)
    nested_json = urllib.parse.quote(
        json.dumps({"auth": {"token": secret}}, separators=(",", ":")),
        safe="",
    )
    return (
        (
            "userinfo-password",
            "uri-userinfo",
            f"https://user:{encoded}@host.invalid/{{version}}"
            "?password={password}",
            True,
            True,
        ),
        (
            "userinfo-host-adjacent",
            "uri-host-adjacent",
            f"https://token={encoded}@host.invalid/{{version}}",
            True,
            True,
        ),
        (
            "authority-host-adjacent",
            "uri-host-adjacent",
            f"https://host.invalid;token={encoded}/{{version}}",
            True,
            True,
        ),
        (
            "path-assignment",
            "uri-path",
            f"https://host.invalid/{{version}}/token={encoded}"
            "?password={password}",
            True,
            True,
        ),
        (
            "path-alternating",
            "uri-path",
            f"postgresql://host.invalid/{{database}}/password/{encoded}"
            "?password={password}",
            True,
            True,
        ),
        (
            "matrix-parameter",
            "uri-matrix",
            f"https://host.invalid/v1;api_key={encoded}"
            "?password={password}",
            True,
            True,
        ),
        (
            "query",
            "uri-query",
            f"https://host.invalid/{{version}}?password={{password}}"
            f"&token={encoded}",
            True,
            True,
        ),
        (
            "fragment",
            "uri-fragment",
            f"https://host.invalid/{{version}}#token={encoded}",
            True,
            True,
        ),
        (
            "double-percent-path",
            "double-encoding",
            f"https://host.invalid/{{version}}/token={double_encoded}",
            True,
            True,
        ),
        (
            "base64-path",
            "nested-reversible",
            f"https://host.invalid/{{version}}/token={base64_secret}",
            True,
            True,
        ),
        (
            "nested-json-query",
            "nested-container",
            f"https://host.invalid/{{version}}?config={nested_json}",
            True,
            True,
        ),
        (
            "deep-derived-path",
            "deep-alias",
            f"https://host.invalid/{{version}}/token={deep_alias}",
            True,
            False,
        ),
        (
            "mixed-template-concrete",
            "mixed",
            f"postgresql://host.invalid/{{database}}/token={encoded}"
            "?password={password}",
            True,
            True,
        ),
        (
            "literal-surrounded",
            "literal-control",
            "postgresql://host.invalid/{database}"
            "?password=prefix{password}suffix",
            True,
            False,
        ),
        (
            "malformed",
            "malformed-control",
            "postgresql://host.invalid/{database}?password={password",
            True,
            False,
        ),
        (
            "dollar-template",
            "template",
            "postgresql://host.invalid/${database}?password=${password}",
            False,
            False,
        ),
        (
            "double-brace-template",
            "template",
            "postgresql://host.invalid/{{database}}?password={{password}}",
            False,
            False,
        ),
        (
            "single-brace-template",
            "template",
            "postgresql://host.invalid/{database}?password={password}",
            False,
            False,
        ),
        (
            "positional-format-template",
            "template-format",
            "https://host.invalid/{0!s:>8}/{1}?token={2!r}",
            False,
            False,
        ),
        (
            "percent-template",
            "template-percent",
            "https://host.invalid/%7Bversion%7D?password=%7Bpassword%7D",
            False,
            False,
        ),
        (
            "angle-template",
            "template",
            "https://host.invalid/<token>?password=<secret>",
            False,
            False,
        ),
        (
            "ordinary-token-endpoint",
            "ordinary",
            "https://auth.example.invalid/oauth/token",
            False,
            False,
        ),
    )


@pytest.mark.parametrize(
    ("case", "family", "value", "expected_sensitive", "expect_derived"),
    _sensitivity_taxonomy(),
    ids=[row[0] for row in _sensitivity_taxonomy()],
)
def test_sensitivity_pipeline_taxonomy(
    case: str,
    family: str,
    value: str,
    expected_sensitive: bool,
    expect_derived: bool,
) -> None:
    del case, family
    source_name = "PAYMENTS_REGION_DSN_TEMPLATE_URI_V18"
    secret = "v18/credential+0123456789abcdef"
    classification = classify_environment_value(source_name, value)
    inventory = credential_source_values({source_name: value})
    projected = enforce_environment_credential_provenance(
        {
            "LANG": "C.UTF-8",
            "MODEL": value,
            "PATH": f"{os.defpath}:{value}",
        },
        inventory,
    )
    persisted = enforce_persisted_environment_credential_provenance(
        {
            "MODEL": value,
            "PATH": f"{os.defpath}:{value}",
        },
        inventory,
    )

    assert classification.sensitive is expected_sensitive
    assert classification.verdict in (
        ("sensitive", "sensitive-unknown")
        if expected_sensitive
        else ("safe", "template-only")
    )
    if expected_sensitive:
        assert inventory == {source_name: value}
        assert projected == {"LANG": "C.UTF-8"}
        assert persisted == {}
        assert expect_derived == (secret in sensitive_values(inventory))
    else:
        assert inventory == {}
        assert projected["MODEL"] == value
        assert projected["PATH"].endswith(value)
        assert persisted["MODEL"] == value
        assert persisted["PATH"].endswith(value)


def test_sensitivity_taxonomy_names_every_contract_family() -> None:
    families = {row[1] for row in _sensitivity_taxonomy()}
    assert {
        "deep-alias",
        "double-encoding",
        "literal-control",
        "malformed-control",
        "mixed",
        "nested-container",
        "nested-reversible",
        "ordinary",
        "template",
        "template-format",
        "template-percent",
        "uri-fragment",
        "uri-host-adjacent",
        "uri-matrix",
        "uri-path",
        "uri-query",
        "uri-userinfo",
    } <= families


def _uri_boundary_taxonomy() -> tuple[tuple[str, str, str], ...]:
    secret = "v19_authority-less+credential-0123456789abcdef"
    roots = {
        "hierarchical": "custom://host.invalid/v1",
        "empty-authority": "custom:///v1",
        "relative": "../v1",
        "opaque": "custom:v1",
    }
    templates = {
        "dollar": "${password}",
        "double-brace": "{{password}}",
        "single-brace": "{password}",
        "positional": "{0}",
        "percent": "%7Bpassword%7D",
    }
    rows: list[tuple[str, str, str]] = []
    for authority, root in roots.items():
        for component in ("path", "matrix", "query", "fragment"):
            for encoding in (
                "raw",
                "percent",
                "double-percent",
                "base64",
                "hex",
                "mixed",
            ):
                alias = _reversible_alias(secret, encoding)
                for template_name, template in templates.items():
                    if component == "path":
                        value = (
                            f"{root}/credential/{alias}"
                            f"?password={template}"
                        )
                    elif component == "matrix":
                        value = (
                            f"{root};password={alias}"
                            f"?token={template}"
                        )
                    elif component == "query":
                        value = (
                            f"{root}?password={alias}&token={template}"
                        )
                    else:
                        value = (
                            f"{root}?password={template}#token={alias}"
                        )
                    rows.append(
                        (
                            (
                                f"{authority}-{component}-{encoding}-"
                                f"{template_name}"
                            ),
                            value,
                            secret,
                        )
                    )
    return tuple(rows)


@pytest.mark.parametrize(
    ("case", "value", "secret"),
    _uri_boundary_taxonomy(),
    ids=[row[0] for row in _uri_boundary_taxonomy()],
)
def test_uri_boundary_taxonomy_is_authority_neutral(
    case: str,
    value: str,
    secret: str,
) -> None:
    del case
    source_name = "PAYMENTS_REGION_DSN_TEMPLATE_URI_V19"
    classification = classify_environment_value(source_name, value)
    inventory = credential_source_values({source_name: value})
    projected = enforce_environment_credential_provenance(
        {
            "LANG": "C.UTF-8",
            "PATH": f"{os.defpath}:{value}",
        },
        inventory,
    )
    persisted = enforce_persisted_environment_credential_provenance(
        {
            "ANTHROPIC_MODEL": value,
            "PATH": f"{os.defpath}:{value}",
        },
        inventory,
    )

    assert classification.sensitive
    assert classification.verdict in ("sensitive", "sensitive-unknown")
    assert secret in sensitive_values(inventory)
    assert projected == {"LANG": "C.UTF-8"}
    assert persisted == {}


@pytest.mark.parametrize("component", ("path", "matrix", "query", "fragment"))
def test_authority_less_uri_normalization_precedes_depth_ceiling_derivation(
    component: str,
) -> None:
    secret = "v19-authority-less-ceiling-0123456789abcdef"
    alias = _padding_free_base64(secret, layers=23)
    if component == "path":
        value = f"custom:/v1/token/{alias}?password=%7Bpassword%7D"
    elif component == "matrix":
        value = f"custom:/v1;password={alias}?token=%7Btoken%7D"
    elif component == "query":
        value = f"custom:/v1?password={alias}&token=%7Btoken%7D"
    else:
        value = f"custom:/v1?password=%7Bpassword%7D#token={alias}"
    source_name = "PAYMENTS_DSN_TEMPLATE_URI_V19"
    inventory = credential_source_values({source_name: value})

    assert secret in sensitive_values(inventory)
    assert enforce_environment_credential_provenance(
        {"LANG": "C.UTF-8", "PATH": f"{os.defpath}:{secret}"},
        inventory,
    ) == {"LANG": "C.UTF-8"}
    assert enforce_persisted_environment_credential_provenance(
        {"ANTHROPIC_MODEL": value, "PATH": f"{os.defpath}:{secret}"},
        inventory,
    ) == {}


_DELIMITER_HEAVY_TEMPLATE_CONTROLS = (
    pytest.param(
        "https://{user}:{password}@host.invalid/{version}/{token}"
        ";session={session}?api_key={api_key}#jwt={jwt}",
        id="hierarchical",
    ),
    pytest.param(
        "custom:///{version}/{token};session={session}"
        "?api_key={api_key}#jwt={jwt}",
        id="empty-authority",
    ),
    pytest.param(
        "../{version}/{token};session={session}"
        "?api_key={api_key}#jwt={jwt}",
        id="relative",
    ),
    pytest.param(
        "custom:{version}/{token};session={session}"
        "?api_key={api_key}#jwt={jwt}",
        id="opaque",
    ),
    pytest.param(
        "custom:///%257Bversion%257D/%257Btoken%257D"
        ";session=%257Bsession%257D?api_key=%257Bapi_key%257D"
        "#jwt=%257Bjwt%257D",
        id="double-percent-empty-authority",
    ),
    pytest.param(
        "https://${user}:{{password}}@api.invalid/<version>/{0}"
        "?token=%7Btoken%7D#cookie={cookie!s}",
        id="mixed-template-forms",
    ),
    pytest.param(
        json.dumps(
            {
                "connection_template": {
                    "uri": (
                        "postgresql://{user}:{password}@db.invalid/"
                        "{database}"
                    ),
                },
                "model": "tokenizer-policy-v3",
            },
            sort_keys=True,
        ),
        id="structured-template-container",
    ),
)


@pytest.mark.parametrize("value", _DELIMITER_HEAVY_TEMPLATE_CONTROLS)
def test_component_delimiters_do_not_turn_templates_into_cookie_material(
    value: str,
) -> None:
    source_name = "PAYMENTS_REGION_DSN_TEMPLATE_URI_V19"
    classification = classify_environment_value(source_name, value)
    environment = {
        "ANTHROPIC_MODEL": value,
        "PATH": f"{os.defpath}:{value}",
        source_name: value,
    }
    inventory = credential_source_values(environment)

    assert classification.verdict == "template-only"
    assert classification.template_evidence
    assert classification.credential_evidence == ()
    assert inventory == {}
    assert enforce_environment_credential_provenance(
        environment,
        inventory,
    ) == dict(sorted(environment.items()))
    assert enforce_persisted_environment_credential_provenance(
        environment,
        inventory,
    ) == dict(sorted(environment.items()))


_SEMANTIC_CREDENTIAL_FIELD_NAMES = (
    "shared_access_signature",
    "sas_signature",
    "auth_signature",
    "password",
    "api_key",
    "authorization",
    "session_cookie",
)


def _credential_field_uri(
    root: str,
    component: str,
    field_name: str,
    field_value: str,
) -> str:
    template = "{password!r:>12}"
    if component == "path":
        return f"{root}/{field_name}={field_value}?password={template}"
    if component == "matrix":
        return f"{root};{field_name}={field_value}?password={template}"
    if component == "query":
        return f"{root}?{field_name}={field_value}&password={template}"
    if component == "fragment":
        return f"{root}?password={template}#{field_name}={field_value}"
    raise AssertionError(component)


@pytest.mark.parametrize(
    "root",
    (
        "custom://host.invalid/v20",
        "custom:///v20",
        "../v20",
        "custom:v20",
    ),
    ids=("hosted", "empty-authority", "relative", "opaque"),
)
@pytest.mark.parametrize("component", ("path", "matrix", "query", "fragment"))
def test_semantic_field_provenance_survives_every_reversible_derivation(
    root: str,
    component: str,
) -> None:
    secret = "v20-semantic-field-credential-0123456789abcdef"
    source_name = "PAYMENTS_EDGE_DSN_TEMPLATE_URI_V20"
    for field_name in _SEMANTIC_CREDENTIAL_FIELD_NAMES:
        for family in (
            "raw",
            "percent",
            "double-percent",
            "base64",
            "hex",
            "mixed",
        ):
            value = _credential_field_uri(
                root,
                component,
                field_name,
                _reversible_alias(secret, family),
            )
            inventory = credential_source_values({source_name: value})
            derived = tuple(
                item
                for item in sensitive_value_provenance(inventory)
                if item.value == secret
            )

            assert inventory == {source_name: value}, (field_name, family)
            assert derived, (field_name, family)
            assert any(
                reason.startswith("semantic-field:")
                for item in derived
                for reason in item.evidence
            ), (field_name, family)
            assert enforce_environment_credential_provenance(
                {"LANG": "C.UTF-8", "PATH": f"{os.defpath}:{secret}"},
                inventory,
            ) == {"LANG": "C.UTF-8"}, (field_name, family)
            assert enforce_persisted_environment_credential_provenance(
                {"ANTHROPIC_MODEL": value, "PATH": f"{os.defpath}:{secret}"},
                inventory,
            ) == {}, (field_name, family)


_NON_IDENTIFIER_ATTRIBUTE = SimpleNamespace()
setattr(_NON_IDENTIFIER_ATTRIBUTE, "bad-name", "ordinary")


class _EchoFormatSpec:
    def __format__(self, format_spec: str) -> str:
        return f"rendered<{format_spec}>"


_PYTHON_FORMAT_REPLACEMENT_FIELDS = (
    pytest.param(
        "{user[password]!r:>12}",
        {"user": {"password": "ordinary"}},
        id="indexed-string-conversion-width",
    ),
    pytest.param(
        "{users[0]!r:>12}",
        {"users": ["ordinary"]},
        id="indexed-integer-conversion-width",
    ),
    pytest.param(
        "{user.password!s:^12}",
        {"user": SimpleNamespace(password="ordinary")},
        id="attribute-conversion-alignment",
    ),
    pytest.param(
        "{user[password]!r:{width}.{precision}}",
        {
            "precision": 8,
            "user": {"password": "ordinary-value"},
            "width": 20,
        },
        id="indexed-nested-width-precision",
    ),
    pytest.param(
        "{accounts[0].owner.name!a:*^{width}}",
        {
            "accounts": [
                SimpleNamespace(
                    owner=SimpleNamespace(name="ordinary"),
                )
            ],
            "width": 18,
        },
        id="mixed-index-attribute-traversal",
    ),
    pytest.param(
        "{mapping[token:key]!s:=^12}",
        {"mapping": {"token:key": "ordinary"}},
        id="index-string-with-component-delimiter",
    ),
    pytest.param(
        "{mapping[layout}mode]!s:^12}",
        {"mapping": {"layout}mode": "ordinary"}},
        id="index-string-with-closing-brace",
    ),
    pytest.param(
        "{mapping[layout{mode]!s:{width}}",
        {"mapping": {"layout{mode": "ordinary"}, "width": 12},
        id="index-string-with-opening-brace",
    ),
    pytest.param(
        "{value:{layout.width}.{layout.precision}}",
        {
            "layout": SimpleNamespace(width=8, precision=2),
            "value": 1.25,
        },
        id="nested-attribute-format-fields",
    ),
    pytest.param(
        "{user password}",
        {"user password": "ordinary"},
        id="stdlib-nonidentifier-root",
    ),
    pytest.param(
        "{-1}",
        {"-1": "ordinary"},
        id="stdlib-negative-looking-root",
    ),
    pytest.param(
        "{user.bad-name}",
        {"user": _NON_IDENTIFIER_ATTRIBUTE},
        id="stdlib-nonidentifier-attribute",
    ),
)


def _indexed_format_uri(root: str) -> str:
    return (
        f"{root}/account={{accounts[0].owner.name!s:^12}}"
        ";password={user[password]!r:>12}"
        "?token={mapping[token]!s:{width}}"
        "#session={request.session!a}"
    )


def _brace_index_format_uri(root: str) -> str:
    return (
        f"{root}/account="
        "{mapping[layout}mode]!s:^12}"
        ";layout={mapping[layout{mode]!s:{width}}"
        "?region={request.region!a}"
        "#database={database}"
    )


_INDEXED_FORMAT_ARGUMENTS = {
    "accounts": [
        SimpleNamespace(
            owner=SimpleNamespace(name="ordinary"),
        )
    ],
    "mapping": {"token": "ordinary"},
    "request": SimpleNamespace(session="ordinary"),
    "user": {"password": "ordinary"},
    "width": 12,
}


_BRACE_INDEX_FORMAT_ARGUMENTS = {
    "database": "ordinary",
    "mapping": {
        "layout}mode": "ordinary-close",
        "layout{mode": "ordinary-open",
    },
    "request": SimpleNamespace(region="ordinary"),
    "width": 12,
}


@pytest.mark.parametrize(
    ("value", "arguments"),
    _PYTHON_FORMAT_REPLACEMENT_FIELDS,
)
def test_python_format_placeholders_are_atomic_component_tokens(
    value: str,
    arguments: dict[str, Any],
) -> None:
    assert value.format(**arguments)
    source_name = "PAYMENTS_FORMAT_DSN_TEMPLATE_URI_V20"
    environment = {
        "ANTHROPIC_MODEL": value,
        "PATH": f"{os.defpath}:{value}",
        source_name: value,
    }
    classification = classify_environment_value(source_name, value)
    inventory = credential_source_values(environment)

    assert classification.verdict == "template-only"
    assert classification.template_evidence
    assert classification.credential_evidence == ()
    assert inventory == {}
    assert enforce_environment_credential_provenance(
        environment,
        inventory,
    ) == dict(sorted(environment.items()))
    assert enforce_persisted_environment_credential_provenance(
        environment,
        inventory,
    ) == dict(sorted(environment.items()))


@pytest.mark.parametrize(
    "root",
    (
        "https://host.invalid/v21",
        "custom:/v21",
        "../v21",
        "custom:v21",
    ),
    ids=("hosted", "authority-less", "relative", "opaque"),
)
def test_complete_format_fields_are_atomic_across_uri_components(
    root: str,
) -> None:
    value = _indexed_format_uri(root)
    source_name = "PAYMENTS_FORMAT_DSN_TEMPLATE_URI_V21"

    assert value.format(**_INDEXED_FORMAT_ARGUMENTS)
    classification = classify_environment_value(source_name, value)
    inventory = credential_source_values({source_name: value})

    assert classification.verdict == "template-only"
    assert len(classification.template_evidence) == 4
    assert classification.credential_evidence == ()
    assert inventory == {}


@pytest.mark.parametrize(
    "root",
    (
        "https://host.invalid/v22",
        "custom:/v22",
        "../v22",
        "custom:v22",
    ),
    ids=("hosted", "authority-less", "relative", "opaque"),
)
def test_brace_bearing_index_strings_are_atomic_across_uri_components(
    root: str,
) -> None:
    value = _brace_index_format_uri(root)
    source_name = "PAYMENTS_FORMAT_DSN_TEMPLATE_URI_V22"

    assert value.format(**_BRACE_INDEX_FORMAT_ARGUMENTS)
    classification = classify_environment_value(source_name, value)
    inventory = credential_source_values({source_name: value})

    assert classification.verdict == "template-only"
    assert len(classification.template_evidence) == 4
    assert classification.credential_evidence == ()
    assert inventory == {}


@pytest.mark.parametrize("position", ("first", "middle", "last"))
def test_template_path_element_preserves_relative_tool_adjacency(
    position: str,
) -> None:
    template = _brace_index_format_uri("custom:/v22")
    elements = ["relative-tools", "local-bin"]
    elements.insert(
        {"first": 0, "middle": 1, "last": 2}[position],
        template,
    )
    value = os.pathsep.join(elements)
    source_name = "PAYMENTS_PATH_DSN_TEMPLATE_URI_V22"
    environment = {
        "ANTHROPIC_MODEL": template,
        "PATH": value,
        source_name: template,
    }

    assert template.format(**_BRACE_INDEX_FORMAT_ARGUMENTS)
    classification = classify_environment_value(source_name, template)
    inventory = credential_source_values(environment)

    assert classification.verdict == "template-only"
    assert classification.credential_evidence == ()
    assert inventory == {}
    assert enforce_environment_credential_provenance(
        environment,
        inventory,
    ) == dict(sorted(environment.items()))
    assert enforce_persisted_environment_credential_provenance(
        environment,
        inventory,
    ) == dict(sorted(environment.items()))


@pytest.mark.parametrize(
    "container",
    ("path", "comma", "semicolon", "newline", "json", "toml"),
)
@pytest.mark.parametrize("position", ("first", "middle", "last"))
def test_complete_format_fields_survive_every_container_position(
    container: str,
    position: str,
) -> None:
    template = _indexed_format_uri("custom:/v21")
    elements = (
        ["/usr/bin", "/opt/unrest/bin"]
        if container == "path"
        else ["ordinary-first", "ordinary-last"]
    )
    elements.insert(
        {"first": 0, "middle": 1, "last": 2}[position],
        template,
    )
    if container == "json":
        value = json.dumps({"values": elements}, separators=(",", ":"))
    elif container == "toml":
        value = f"values = {json.dumps(elements)}\n"
    else:
        delimiter = {
            "path": os.pathsep,
            "comma": ",",
            "semicolon": ";",
            "newline": "\n",
        }[container]
        value = delimiter.join(elements)
    source_name = "PAYMENTS_CONTAINER_DSN_TEMPLATE_URI_V21"
    environment = {
        "ANTHROPIC_MODEL": value,
        "PATH": value,
        source_name: value,
    }
    classification = classify_environment_value(source_name, value)
    inventory = credential_source_values(environment)

    assert classification.verdict == "template-only"
    assert classification.template_evidence
    assert classification.credential_evidence == ()
    assert inventory == {}
    assert enforce_environment_credential_provenance(
        environment,
        inventory,
    ) == dict(sorted(environment.items()))
    assert enforce_persisted_environment_credential_provenance(
        environment,
        inventory,
    ) == dict(sorted(environment.items()))


@pytest.mark.parametrize(
    "value",
    (
        "custom:/v21;password={user[password]",
        "custom:/v21;password={user[]}",
        "custom:/v21;password={user[password]suffix}",
        "custom:/v21;password={user[password]!x}",
        "custom:/v21;password={user[password]!r:{width}",
        "custom:/v21;password={user:{width:{precision}}}",
        "custom:/v21;password={0:{}}",
        "custom:/v21;password={:{0}}",
        "custom:/v21;password={}?token={0}",
        "custom:/v21;password={0}?token={}",
        "custom:/v21;password=prefix{user[password]!r:>12}suffix",
    ),
    ids=(
        "incomplete-index",
        "empty-index",
        "trailing-field-text",
        "invalid-conversion",
        "incomplete-nested-format-spec",
        "over-nested-format-spec",
        "mixed-numbering-manual-auto-nested",
        "mixed-numbering-auto-manual-nested",
        "mixed-numbering-auto-manual-adjacent",
        "mixed-numbering-manual-auto-adjacent",
        "literal-surrounding-valid-field",
    ),
)
def test_malformed_or_incomplete_format_fields_remain_sensitive(
    value: str,
) -> None:
    source_name = "PAYMENTS_FORMAT_DSN_TEMPLATE_URI_V21"
    classification = classify_environment_value(source_name, value)
    inventory = credential_source_values({source_name: value})

    assert classification.sensitive
    assert classification.credential_evidence
    assert inventory == {source_name: value}


@pytest.mark.parametrize(
    ("value", "args", "kwargs", "stdlib_valid"),
    (
        pytest.param(
            "{mapping[layout}mode]!s:^12}",
            (),
            {"mapping": {"layout}mode": "ordinary"}},
            True,
            id="brace-index-close",
        ),
        pytest.param(
            "{mapping[layout{mode]!s:{width}}",
            (),
            {"mapping": {"layout{mode": "ordinary"}, "width": 12},
            True,
            id="brace-index-open-nested",
        ),
        pytest.param(
            "{0:{}}",
            ("ordinary", 12),
            {},
            False,
            id="manual-auto-nested",
        ),
        pytest.param(
            "{:{0}}",
            ("ordinary", 12),
            {},
            False,
            id="auto-manual-nested",
        ),
        pytest.param(
            "{} {0}",
            ("ordinary",),
            {},
            False,
            id="auto-manual-adjacent",
        ),
        pytest.param(
            "{0} {}",
            ("ordinary",),
            {},
            False,
            id="manual-auto-adjacent",
        ),
    ),
)
def test_format_template_safety_matches_stdlib_numbering_semantics(
    value: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    stdlib_valid: bool,
) -> None:
    try:
        value.format(*args, **kwargs)
    except ValueError:
        rendered = False
    else:
        rendered = True
    contextual = f"custom:/v22;password={value}"
    classification = classify_environment_value(
        "PAYMENTS_FORMAT_DSN_TEMPLATE_URI_V22",
        contextual,
    )

    assert rendered is stdlib_valid
    assert bool(classification.template_evidence) is stdlib_valid
    assert classification.sensitive is not stdlib_valid


@pytest.mark.parametrize(
    "family",
    ("raw", "percent", "base64", "hex", "mixed"),
)
def test_valid_format_fields_recursively_expose_concrete_credentials(
    family: str,
) -> None:
    secret = "v22-format-ast-credential-0123456789abcdef"
    alias = _reversible_alias(secret, family)
    values = (
        (
            f"{{value:password={alias}}}",
            {"value": _EchoFormatSpec()},
        ),
        (
            f"{{value:token={alias};width={{width}}}}",
            {"value": _EchoFormatSpec(), "width": 12},
        ),
        (
            f"{{mapping[password={alias}]!s:^12}}",
            {"mapping": {f"password={alias}": "ordinary"}},
        ),
    )
    source_name = "PAYMENTS_FORMAT_DSN_TEMPLATE_URI_V22"

    for value, arguments in values:
        assert value.format(**arguments)
        classification = classify_environment_value(source_name, value)
        inventory = credential_source_values({source_name: value})

        assert classification.sensitive, (family, value)
        assert classification.template_evidence, (family, value)
        assert classification.credential_evidence, (family, value)
        assert inventory == {source_name: value}, (family, value)
        assert secret in sensitive_values(inventory), (family, value)
        assert enforce_environment_credential_provenance(
            {"LANG": "C.UTF-8", "PATH": f"{os.defpath}:{secret}"},
            inventory,
        ) == {"LANG": "C.UTF-8"}, (family, value)


def test_complete_format_fields_do_not_override_concrete_or_derived_evidence() -> None:
    secret = "v21-format-mixed-credential-0123456789abcdef"
    encoded = _reversible_alias(secret, "mixed")
    value = (
        "custom:/v21;password={user[password]!r:>12}"
        f"?token={encoded}#session={{request.session!a}}"
    )
    source_name = "PAYMENTS_FORMAT_DSN_TEMPLATE_URI_V21"
    classification = classify_environment_value(source_name, value)
    inventory = credential_source_values({source_name: value})

    assert classification.sensitive
    assert classification.template_evidence
    assert classification.credential_evidence
    assert inventory == {source_name: value}
    assert secret in sensitive_values(inventory)
    assert enforce_environment_credential_provenance(
        {
            "LANG": "C.UTF-8",
            "PATH": f"{os.defpath}:{secret}",
        },
        inventory,
    ) == {"LANG": "C.UTF-8"}


@pytest.mark.parametrize(
    "root",
    (
        "https://host.invalid/v20",
        "custom:///v20",
        "../v20",
        "custom:v20",
    ),
    ids=("hosted", "empty-authority", "relative", "opaque"),
)
@pytest.mark.parametrize(
    "family",
    ("raw", "percent", "base64", "hex", "mixed"),
)
def test_placeholder_segments_cannot_consume_the_actual_credential_field(
    root: str,
    family: str,
) -> None:
    secret = "v20-adjacent-credential-leaf-0123456789abcdef"
    placeholder_segment = (
        "{tenant}-${region}-{{database}}-"
        "%7Bpassword%21r%3A%3E12%7D"
    )
    value = (
        f"{root}/{placeholder_segment}/token/"
        f"{_reversible_alias(secret, family)}"
    )
    source_name = "PAYMENTS_EDGE_DSN_TEMPLATE_URI_V20"
    inventory = credential_source_values({source_name: value})

    assert secret in sensitive_values(inventory)
    assert enforce_environment_credential_provenance(
        {"LANG": "C.UTF-8", "PATH": f"{os.defpath}:{secret}"},
        inventory,
    ) == {"LANG": "C.UTF-8"}
    assert enforce_persisted_environment_credential_provenance(
        {"PATH": f"{os.defpath}:{secret}"},
        inventory,
    ) == {}


@pytest.mark.parametrize("container", ("path", "comma", "semicolon", "newline"))
@pytest.mark.parametrize("position", ("first", "middle", "last"))
@pytest.mark.parametrize(
    "family",
    ("raw", "percent", "base64", "hex", "mixed"),
)
def test_derived_semantic_credentials_are_filtered_at_every_container_position(
    container: str,
    position: str,
    family: str,
) -> None:
    secret = "v20-container-derived-credential-0123456789abcdef"
    source_value = _credential_field_uri(
        "custom:/v20",
        "matrix",
        "shared_access_signature",
        _reversible_alias(secret, "mixed"),
    )
    source_name = "PAYMENTS_EDGE_DSN_TEMPLATE_URI_V20"
    inventory = credential_source_values({source_name: source_value})
    alias = _reversible_alias(secret, family)
    delimiter = {
        "path": os.pathsep,
        "comma": ",",
        "semicolon": ";",
        "newline": "\n",
    }[container]
    elements = ["/usr/bin", "/opt/unrest/bin"]
    elements.insert(
        {"first": 0, "middle": 1, "last": 2}[position],
        alias,
    )
    candidate = delimiter.join(elements)

    assert secret in sensitive_values(inventory)
    assert enforce_environment_credential_provenance(
        {"LANG": "C.UTF-8", "PATH": candidate},
        inventory,
    ) == {"LANG": "C.UTF-8"}
    assert enforce_persisted_environment_credential_provenance(
        {"PATH": candidate},
        inventory,
    ) == {}


@pytest.mark.parametrize("layers", (1, 2, 8, 23))
def test_semantic_field_provenance_is_monotonic_to_the_depth_bound(
    layers: int,
) -> None:
    secret = "v20-depth-bounded-credential-0123456789abcdef"
    descendants = [secret]
    for _ in range(layers):
        descendants.append(
            base64.urlsafe_b64encode(descendants[-1].encode())
            .decode()
            .rstrip("=")
        )
    value = _credential_field_uri(
        "custom:/v20",
        "matrix",
        "shared_access_signature",
        descendants[-1],
    )
    inventory = credential_source_values(
        {"PAYMENTS_EDGE_DSN_TEMPLATE_URI_V20": value}
    )

    assert set(descendants).issubset(sensitive_values(inventory))


@pytest.mark.parametrize("family", ("base64", "hex", "mixed"))
@pytest.mark.parametrize("position", ("first", "middle", "last"))
def test_path_container_elements_are_derived_before_the_aggregate(
    family: str,
    position: str,
) -> None:
    secret = "v19-container-credential-0123456789abcdef"
    alias = _reversible_alias(secret, family)
    elements = ["/usr/bin", "/opt/unrest/bin"]
    elements.insert(
        {"first": 0, "middle": 1, "last": 2}[position],
        alias,
    )
    path_value = os.pathsep.join(elements)
    source_name = "DECLARED_CONTAINER_CREDENTIAL"
    inventory = credential_source_values(
        {source_name: secret},
        declared_names=(source_name,),
    )

    assert enforce_environment_credential_provenance(
        {"LANG": "C.UTF-8", "PATH": path_value},
        inventory,
    ) == {"LANG": "C.UTF-8"}
    assert enforce_persisted_environment_credential_provenance(
        {"PATH": path_value},
        inventory,
    ) == {}


def _depth_ceiling_source(value: str) -> str:
    nested: Any = {"credential": value}
    for index in range(26):
        nested = {f"level_{index:02d}": nested}
    return json.dumps(nested, separators=(",", ":"), sort_keys=True)


@pytest.mark.parametrize(
    "source_factory",
    (_node_ceiling_source, _text_ceiling_source, _depth_ceiling_source),
    ids=("node", "text", "depth"),
)
@pytest.mark.parametrize("position", ("first", "middle", "last"))
def test_embedded_mixed_aliases_fail_closed_at_source_ceilings(
    source_factory: Any,
    position: str,
) -> None:
    secret = "v19-ceiling-credential-0123456789abcdef"
    alias = _reversible_alias(secret, "mixed")
    if source_factory is _depth_ceiling_source:
        source_value = source_factory(secret)
    else:
        source_value = source_factory(secret, key="credential")
    source_name = "CREDENTIAL_CACHE_METADATA_V19"
    inventory = credential_source_values({source_name: source_value})
    elements = ["/usr/bin", "/opt/unrest/bin"]
    elements.insert(
        {"first": 0, "middle": 1, "last": 2}[position],
        alias,
    )
    path_value = os.pathsep.join(elements)

    assert inventory == {source_name: source_value}
    assert enforce_environment_credential_provenance(
        {"LANG": "C.UTF-8", "PATH": path_value},
        inventory,
    ) == {"LANG": "C.UTF-8"}
    assert enforce_persisted_environment_credential_provenance(
        {"PATH": path_value},
        inventory,
    ) == {}


def _client(tmp_path: Path, *, role: str = "worker") -> ACPClient:
    policy = _resolved(tmp_path, role=role)
    return ACPClient(
        cast(Any, object()),
        str(tmp_path / "workspace"),
        policy=policy,
        terminal_environment=build_role_environment(
            policy,
            {"PATH": os.environ["PATH"], "LANG": "C"},
        ),
    )


def test_policy_is_strict_versioned_and_round_trips_every_role() -> None:
    policy = load_capability_policy(_BUNDLED)
    assert policy.schema_version == 1
    dumped = policy.model_dump(mode="json", by_alias=True)
    assert CapabilityPolicy.model_validate_json(
        json.dumps(dumped, sort_keys=True)
    ) == policy
    assert set(dumped["profiles"]["safe"]) == {
        "orchestrator",
        "worker",
        "validator",
        "terminal_reviewer",
    }
    for role in dumped["profiles"]["safe"].values():
        assert set(role) == {
            "filesystem",
            "process",
            "network",
            "environment",
            "approvals",
        }


def test_policy_unknown_fields_and_unknown_versions_are_rejected() -> None:
    raw = json.loads(
        (_BUNDLED / "policies" / "role-capabilities.v1.json").read_text()
    )
    raw["ambientFallback"] = True
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CapabilityPolicy.model_validate(raw)
    raw.pop("ambientFallback")
    raw["schema_version"] = 2
    with pytest.raises(ValidationError, match="literal_error"):
        CapabilityPolicy.model_validate(raw)


def test_policy_schema_snapshot_and_document_validate() -> None:
    schema_path = _ROOT / "schemas" / "role-capabilities.schema.json"
    snapshot = json.loads(schema_path.read_text())
    generated = CapabilityPolicy.model_json_schema(by_alias=True)
    generated["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    assert snapshot == generated
    Draft202012Validator.check_schema(snapshot)
    document = json.loads(
        (_BUNDLED / "policies" / "role-capabilities.v1.json").read_text()
    )
    Draft202012Validator(snapshot).validate(document)


def test_role_projection_is_explicit_and_does_not_inherit_worker_policy() -> None:
    policy = load_capability_policy(_BUNDLED)
    worker = policy.role(SAFE_PROFILE, "worker")
    validator = policy.role(SAFE_PROFILE, "validator")
    reviewer = policy.role(SAFE_PROFILE, "terminal_reviewer")
    assert worker != validator != reviewer
    assert any(root.write for root in worker.filesystem if root.name == "workspace")
    assert not any(
        root.write for root in validator.filesystem if root.name == "workspace"
    )
    assert not any(root.write for root in reviewer.filesystem)
    assert "edit" in worker.approvals.tool_kinds
    assert "edit" not in validator.approvals.tool_kinds


def test_provider_support_rejects_unenforceable_network_denial_stably() -> None:
    raw = json.loads(
        (_BUNDLED / "policies" / "role-capabilities.v1.json").read_text()
    )
    raw["profiles"]["safe"]["worker"]["network"]["mode"] = "deny"
    policy = CapabilityPolicy.model_validate(raw)
    with pytest.raises(
        CapabilityPolicyError,
        match=(
            r"provider=codex role=worker version=1 "
            r"capability=network:deny"
        ),
    ):
        validate_provider_support(
            PROVIDERS["codex"],
            role="worker",
            policy=policy,
            profile=SAFE_PROFILE,
        )


@pytest.mark.parametrize("profile", ["unknown", "safe-ish"])
def test_unsupported_profile_has_stable_provider_role_version_error(profile: str) -> None:
    policy = load_capability_policy(_BUNDLED)
    with pytest.raises(CapabilityPolicyError) as caught:
        validate_provider_support(
            PROVIDERS["claude"],
            role="worker",
            policy=policy,
            profile=profile,
        )
    message = str(caught.value)
    assert (
        "provider=claude role=worker version=1 capability=opaque#" in message
    )
    assert profile not in message


def test_unknown_runtime_provider_has_stable_role_version_error(
    tmp_path: Path,
) -> None:
    config = HarnessConfig(
        bundled_dir=_BUNDLED,
        harness_home=tmp_path / "home",
        projects_dir=tmp_path / "home" / "projects",
        orchestrator_provider_name="unknown-provider",
        worker_provider_name="claude",
        worker_acp_command="claude-agent-acp",
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
    )
    with pytest.raises(CapabilityPolicyError) as caught:
        config.validate_capability_support()
    message = str(caught.value)
    assert (
        "provider=opaque#"
        in message
        and "role=orchestrator version=1 capability=provider" in message
    )
    assert "unknown-provider" not in message


def test_safe_codex_subprocess_settings_override_ambient_unrestricted(
    tmp_path: Path,
) -> None:
    resolved = _resolved(tmp_path, provider_name="codex")
    host = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "CODEX_CONFIG": json.dumps(
            {
                "features": {"memories": True},
                "sandbox_mode": "danger-full-access",
                "approval_policy": "never",
            }
        ),
        "CODEX_DISABLE_SANDBOX": "1",
        "DATABASE_URL": "ambient-unrelated",
    }
    env = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=resolved,
        reasoning_effort="medium",
        host_environment=host,
    )
    config = json.loads(env["CODEX_CONFIG"])
    assert config["sandbox_mode"] == "workspace-write"
    assert config["approval_policy"] == "on-request"
    assert config["model_reasoning_effort"] == "medium"
    assert env["INITIAL_AGENT_MODE"] == "agent"
    assert "CODEX_DISABLE_SANDBOX" not in env
    assert "DATABASE_URL" not in env
    serialized = json.dumps(env, sort_keys=True)
    assert not any(sentinel in serialized for sentinel in _FORBIDDEN_SAFE_SENTINELS)


def test_only_explicit_unsafe_profile_emits_unrestricted_provider_settings(
    tmp_path: Path,
) -> None:
    resolved = _resolved(
        tmp_path,
        provider_name="codex",
        profile=UNSAFE_DEVELOPMENT_PROFILE,
    )
    env = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=resolved,
        host_environment={"PATH": os.environ["PATH"]},
    )
    assert env["INITIAL_AGENT_MODE"] == "agent-full-access"
    assert env["CODEX_DISABLE_SANDBOX"] == "1"
    config = json.loads(env["CODEX_CONFIG"])
    assert config["sandbox_mode"] == "danger-full-access"
    assert config["approval_policy"] == "never"


def test_role_environment_is_minimal_deterministic_and_credential_named(
    tmp_path: Path,
) -> None:
    resolved = _resolved(tmp_path)
    first_host = {
        "ZAI_API_KEY": "credential-sentinel",
        "PATH": "/one:/two",
        "LANG": "C",
        "DATABASE_URL": "must-not-forward",
        "RANDOM_HOST_VALUE": "must-not-forward",
    }
    second_host = dict(reversed(tuple(first_host.items())))
    first = build_role_environment(resolved, first_host)
    second = build_role_environment(resolved, second_host)
    assert first == second
    assert tuple(first) == tuple(sorted(first))
    assert first == {
        "LANG": "C",
        "PATH": "/one:/two",
        "ZAI_API_KEY": "credential-sentinel",
    }


@pytest.mark.parametrize("seed", range(24))
def test_persisted_environment_credential_provenance_is_generalized(
    seed: int,
) -> None:
    generator = random.Random(seed)
    token = "".join(
        generator.choice(string.ascii_letters + string.digits)
        for _ in range(32)
    )
    credential = f"VCAP_{token}"
    longer_credential = f"{credential}-suffix"
    prefixed_credential = f"prefix-{credential}"
    ordinary = f"ordinary-{seed}"
    credentials = {
        "ANTHROPIC_API_KEY": prefixed_credential,
        "CODEX_API_KEY": credential,
        "OPENAI_API_KEY": longer_credential,
        "ZAI_API_KEY": credential,
    }
    environment = {
        "ANTHROPIC_BASE_URL": (
            f"https://example.invalid/(<{prefixed_credential}>)/api"
        ),
        "EXACT_ALIAS": credential,
        "GLM_BASE_URL": longer_credential,
        "ORDINARY": ordinary,
        "PATH": f"/usr/bin:<{credential}>:/bin",
        "UV_CACHE_DIR": f"/cache/[{longer_credential}]/objects",
        "ZAI_API_KEY": credential,
        "ZAI_BASE_URL": (
            f"https://example.invalid/?first=<{credential}>"
            f"&second=({longer_credential})"
        ),
    }

    filtered = enforce_persisted_environment_credential_provenance(
        environment,
        credentials,
    )
    reversed_filtered = enforce_persisted_environment_credential_provenance(
        dict(reversed(tuple(environment.items()))),
        dict(reversed(tuple(credentials.items()))),
    )

    assert filtered == {"ORDINARY": ordinary}
    assert reversed_filtered == filtered


_COMMON_CREDENTIAL_SOURCE_NAMES = (
    "APP_AUTHORIZATION",
    "APP_DATABASE_URL_V5",
    "AWS_ACCESS_KEY_ID",
    "BUILD_CREDENTIAL",
    "CI_CLIENT_SECRET",
    "CI_JOB_JWT_V17",
    "DATABASE_PASSWD",
    "DB_PASS",
    "DEPLOY_TOKEN",
    "GH_PAT",
    "JOB_JWT",
    "OBSERVABILITY_DSN_REGION",
    "PACKAGE_APIKEY",
    "PGPASSWORD",
    "RAILS_MASTER_KEY",
    "REGISTRY_AUTH_CONFIG_V3",
    "SECRET_KEY_BASE",
    "SERVICE_PASSWORD",
    "SIGNING_PRIVATE_KEY",
)


@pytest.mark.parametrize("seed", range(96))
def test_credential_source_classifier_recognizes_structural_families(
    seed: int,
) -> None:
    generator = random.Random(seed)
    prefix = "".join(generator.choice(string.ascii_uppercase) for _ in range(7))
    qualifier = "".join(
        generator.choice(string.ascii_uppercase)
        for _ in range(9)
    )
    version = generator.randint(2, 999)
    families = (
        f"{prefix}_SECRET_{qualifier}",
        f"{prefix}_ACCESS_KEY_ID_{qualifier}",
        f"{prefix}_AUTH_CONFIG_V{version}",
        f"{prefix}_JOB_JWT_V{version}",
        f"{prefix}_DATABASE_URL_V{version}",
        f"{prefix}_DSN_{qualifier}",
        f"{prefix}_DB_PASS_{qualifier}",
        f"{prefix}SECRETKEYBASE",
        f"{prefix}AUTHCONFIGV{version}",
        f"{prefix}DATABASEURLV{version}",
        f"{prefix}JWTV{version}",
    )

    assert all(is_credential_source_name(name) for name in families)


@pytest.mark.parametrize("seed", range(64))
def test_credential_source_classifier_preserves_non_secret_name_families(
    seed: int,
) -> None:
    generator = random.Random(seed)
    prefix = "".join(generator.choice(string.ascii_uppercase) for _ in range(6))
    version = generator.randint(2, 999)
    controls = (
        f"{prefix}_PASSWORD_POLICY_V{version}",
        f"{prefix}_TOKENIZER_MODEL_V{version}",
        f"{prefix}_SECRETARY_NAME_V{version}",
        f"{prefix}_PATTERN_CONFIG_V{version}",
        f"{prefix}_MODEL_CONFIG_V{version}",
        f"{prefix}_BASE_URL_V{version}",
        f"{prefix}PASSWORDPOLICYV{version}",
        f"{prefix}TOKENIZERMODELV{version}",
        f"{prefix}SECRETARYNAMEV{version}",
    )

    assert not any(is_credential_source_name(name) for name in controls)


@pytest.mark.parametrize("seed", range(32))
def test_qualified_benign_families_do_not_cancel_stronger_evidence(
    seed: int,
) -> None:
    generator = random.Random(6_000 + seed)
    prefix = "".join(generator.choice(string.ascii_uppercase) for _ in range(8))
    qualifier = "".join(
        generator.choice(string.ascii_uppercase)
        for _ in range(12)
    )
    controls = (
        f"{prefix}_TOKEN_{qualifier}_ENDPOINT_TEMPLATE",
        f"{prefix}_PASSWORD_{qualifier}_POLICY_TEMPLATE",
        f"{prefix}_DATABASE_DSN_{qualifier}_TEMPLATE",
    )
    sensitive = (
        f"{prefix}_CREDENTIAL_{qualifier}_CACHE_METADATA",
        f"{prefix}_AUTH_{qualifier}_CACHE_METADATA",
        f"{prefix}_JWT_{qualifier}_TOKEN_ENDPOINT_TEMPLATE",
        f"{prefix}_PRIVATE_KEY_{qualifier}_PUBLIC_TEMPLATE",
        f"{prefix}_DATABASE_DSN_{qualifier}_TOKEN_ENDPOINT_TEMPLATE",
    )

    assert not any(is_credential_source_name(name) for name in controls)
    assert all(is_credential_source_name(name) for name in sensitive)


@pytest.mark.parametrize("seed", range(48))
def test_credential_source_classifier_aggregates_strong_and_benign_descriptors(
    seed: int,
) -> None:
    generator = random.Random(7_000 + seed)
    prefix = "".join(generator.choice(string.ascii_uppercase) for _ in range(7))
    qualifier = "".join(
        generator.choice(string.ascii_uppercase)
        for _ in range(11)
    )
    version = generator.randint(2, 999)
    families = (
        f"{prefix}_CREDENTIAL_{qualifier}_CACHE_METADATA_V{version}",
        f"{prefix}_AUTH_{qualifier}_CACHE_METADATA_V{version}",
        f"{prefix}_AUTH_CACHE_{qualifier}_TOKEN_ENDPOINT_V{version}",
        f"{prefix}_SESSION_COOKIE_{qualifier}_METADATA_V{version}",
        f"{prefix}_PRIVATE_KEY_{qualifier}_TEMPLATE_V{version}",
        f"{prefix}_JWT_{qualifier}_METADATA_V{version}",
        f"{prefix}_JWT_{qualifier}_TOKEN_ENDPOINT_V{version}",
        f"{prefix}_DATABASE_DSN_{qualifier}_TOKEN_ENDPOINT_V{version}",
    )

    assert all(is_credential_source_name(name) for name in families)


@pytest.mark.parametrize("seed", range(32))
def test_ambient_credential_inventory_is_provider_neutral_and_deterministic(
    seed: int,
) -> None:
    generator = random.Random(seed)
    source_name = generator.choice(_COMMON_CREDENTIAL_SOURCE_NAMES)
    source_value = "VCAP_" + "".join(
        generator.choice(string.ascii_letters + string.digits)
        for _ in range(32)
    )
    environment = {
        "CUSTOM_LOGIN": f"declared-{source_value}",
        "EMPTY_TOKEN": "",
        "PATTERN": "ordinary-pattern",
        "PASSWORD_POLICY": "required",
        "PWD": "/ordinary/current-directory",
        "SECRETARY_NAME": "Marlowe",
        "TOKENIZER_MODEL": "provider-neutral",
        source_name: source_value,
    }

    inventory = credential_source_values(
        environment,
        declared_names=("CUSTOM_LOGIN",),
    )
    reverse = credential_source_values(
        dict(reversed(tuple(environment.items()))),
        declared_names=("CUSTOM_LOGIN",),
    )

    assert inventory == {
        "CUSTOM_LOGIN": f"declared-{source_value}",
        source_name: source_value,
    }
    assert reverse == inventory
    assert is_credential_source_name(source_name)
    assert not any(
        is_credential_source_name(name)
        for name in (
            "PATTERN",
            "PASSWORD_POLICY",
            "PWD",
            "SECRETARY_NAME",
            "TOKENIZER_MODEL",
        )
    )


@pytest.mark.parametrize("seed", range(48))
def test_entropy_only_ordinary_ids_do_not_create_sensitive_provenance(
    seed: int,
) -> None:
    generator = random.Random(10_000 + seed)
    arbitrary_name = (
        "OTEL_TRACE_CONTEXT_"
        + "".join(generator.choice(string.ascii_uppercase) for _ in range(13))
        + f"_V{seed}"
    )
    trace_id = f"{generator.getrandbits(160):040x}"
    environment = {
        arbitrary_name: trace_id,
        "BUILD_COMMIT_SHA": f"{generator.getrandbits(160):040x}",
        "PATH": f"/usr/bin:{trace_id}:/bin",
        "TOKENIZER_MODEL": base64.urlsafe_b64encode(
            f"ordinary-tokenizer-model-{seed}".encode()
        ).decode().rstrip("="),
    }

    inventory = credential_source_values(environment)
    reverse = credential_source_values(
        dict(reversed(tuple(environment.items()))),
    )

    assert inventory == {}
    assert reverse == {}
    assert not is_credential_source_name(arbitrary_name)
    assert enforce_environment_credential_provenance(
        {"PATH": environment["PATH"]},
        inventory,
    ) == {"PATH": environment["PATH"]}


@pytest.mark.parametrize("seed", range(32))
def test_secret_bearing_dsn_wins_over_unrelated_template_evidence(
    seed: int,
) -> None:
    generator = random.Random(15_000 + seed)
    secret = f"dsn-{generator.getrandbits(192):048x}"
    source_name = (
        "RUNTIME_"
        + "".join(generator.choice(string.ascii_uppercase) for _ in range(14))
        + f"_SETTING_V{seed}"
    )
    dsn = (
        f"postgresql://worker:{secret}@db.example.invalid/app"
        "?region=${DEPLOY_REGION}&mode=ordinary"
    )

    inventory = credential_source_values({source_name: dsn})

    assert inventory == {source_name: dsn}
    assert secret in sensitive_values(inventory)
    assert enforce_environment_credential_provenance(
        {
            "LANG": secret,
            "PATH": f"/usr/bin:{dsn}:/bin",
        },
        inventory,
    ) == {}
    redacted = json.dumps(
        _redact_json_value(
            {
                "progress": dsn,
                dsn: {"handoff": secret},
            },
            inventory,
        ),
        sort_keys=True,
    )
    assert secret not in redacted
    assert dsn not in redacted


@pytest.mark.parametrize("seed", range(24))
def test_template_only_payloads_remain_ordinary_without_concrete_credentials(
    seed: int,
) -> None:
    generator = random.Random(17_000 + seed)
    prefix = "".join(generator.choice(string.ascii_uppercase) for _ in range(10))
    environment = {
        f"{prefix}_DATABASE_DSN_TEMPLATE": (
            "postgresql://host.invalid/${DATABASE}"
            "?password=${DATABASE_PASSWORD}"
        ),
        f"{prefix}_HEADER_TEMPLATE": "Authorization: Bearer ${ACCESS_TOKEN}",
        f"{prefix}_SESSION_TEMPLATE": "session={{SESSION_COOKIE}}; Path=/",
    }

    assert credential_source_values(environment) == {}


_SINGLE_BRACE_TEMPLATE_VALUES = (
    pytest.param(
        "postgresql://host.invalid/{database}",
        id="uri-path",
    ),
    pytest.param(
        "postgresql://host.invalid/{database}?password={password}",
        id="query",
    ),
    pytest.param(
        "postgresql://{username}:{password}@host.invalid/{database}",
        id="userinfo",
    ),
    pytest.param(
        "postgresql://{{username}}:{{password}}@host.invalid/{{database}}",
        id="escaped-literal-braces",
    ),
    pytest.param(
        "postgresql://%7Busername%7D:%7Bpassword%7D@host.invalid/"
        "%7Bdatabase%7D?token=%7Btoken%7D",
        id="percent-escaped-braces",
    ),
)


@pytest.mark.parametrize("value", _SINGLE_BRACE_TEMPLATE_VALUES)
@pytest.mark.parametrize("seed", range(12))
def test_conventional_connection_placeholders_are_not_sensitive_sources(
    value: str,
    seed: int,
) -> None:
    generator = random.Random(19_000 + seed)
    qualifier = "".join(
        generator.choice(string.ascii_uppercase)
        for _ in range(14)
    )
    name = f"PAYMENTS_{qualifier}_DSN_TEMPLATE_URI_V{seed}"
    environment = {
        "LANG": "C.UTF-8",
        "PATH": f"/usr/bin:{value}:/bin",
        name: value,
    }

    inventory = credential_source_values(environment)
    reverse = credential_source_values(
        dict(reversed(tuple(environment.items()))),
    )

    assert inventory == {}
    assert reverse == {}
    assert not is_credential_source_name(name)
    assert enforce_environment_credential_provenance(
        environment,
        inventory,
    ) == dict(sorted(environment.items()))
    assert enforce_persisted_environment_credential_provenance(
        environment,
        inventory,
    ) == dict(sorted(environment.items()))


@pytest.mark.parametrize(
    "value",
    (
        pytest.param(
            "postgresql://{username}:concrete-password@host.invalid/{database}"
            "?password={password}",
            id="mixed-userinfo",
        ),
        pytest.param(
            "postgresql://host.invalid/{database}?password={password}"
            "&token=concrete-token",
            id="mixed-query",
        ),
        pytest.param(
            "server=host.invalid; password={password}; token=concrete-token",
            id="mixed-connection-fields",
        ),
        pytest.param(
            "postgresql://host.invalid/{database}?password=literal{password}suffix",
            id="literal-surrounding-braces",
        ),
        pytest.param(
            "postgresql://host.invalid/{database}?password={password",
            id="malformed-open-brace",
        ),
        pytest.param(
            "postgresql://host.invalid/{database}?password=password}",
            id="malformed-close-brace",
        ),
        pytest.param(
            "postgresql://host.invalid/{database}?password={{{password}}}",
            id="malformed-extra-braces",
        ),
    ),
)
def test_template_evidence_does_not_cancel_concrete_connection_credentials(
    value: str,
) -> None:
    source_name = "RANDOMIZED_RUNTIME_CONNECTION_SETTING"
    inventory = credential_source_values({source_name: value})

    assert inventory == {source_name: value}
    assert enforce_environment_credential_provenance(
        {
            "LANG": "C.UTF-8",
            "PATH": f"/usr/bin:{value}:/bin",
        },
        inventory,
    ) == {"LANG": "C.UTF-8"}
    assert enforce_persisted_environment_credential_provenance(
        {
            "CONNECTION_ALIAS": value,
            "LANG": "C.UTF-8",
        },
        inventory,
    ) == {"LANG": "C.UTF-8"}


def test_declared_credential_name_remains_sensitive_with_placeholder_value() -> None:
    name = "DECLARED_CONNECTION_CREDENTIAL"
    value = "postgresql://host.invalid/{database}?password={password}"
    inventory = credential_source_values(
        {name: value},
        declared_names=(name,),
    )

    assert inventory == {name: value}
    assert enforce_environment_credential_provenance(
        {
            name: value,
            "PATH": f"/usr/bin:{value}:/bin",
        },
        inventory,
    ) == {name: value}
    assert enforce_persisted_environment_credential_provenance(
        {
            name: value,
            "PATH": f"/usr/bin:{value}:/bin",
        },
        inventory,
    ) == {}


@pytest.mark.parametrize("seed", range(40))
def test_structural_carriers_derive_sensitive_leaf_provenance(seed: int) -> None:
    generator = random.Random(20_000 + seed)
    prefix = "".join(generator.choice(string.ascii_uppercase) for _ in range(8))
    qualifier = "".join(generator.choice(string.ascii_uppercase) for _ in range(10))
    secret = f"{generator.getrandbits(192):048x}"
    definitions = (
        (f"{prefix}_NETRC_{qualifier}_PATH", f"/tmp/{prefix.lower()}/netrc"),
        (
            f"{prefix}_SESSION_COOKIE_{qualifier}_JAR",
            f"session_id={secret}; Path=/; HttpOnly",
        ),
        (
            f"{prefix}_SSH_IDENTITY_{qualifier}_PEM",
            "-----BEGIN PRIVATE KEY-----\n"
            + base64.b64encode(secret.encode()).decode()
            + "\n-----END PRIVATE KEY-----",
        ),
        (f"{prefix}_KRB5_{qualifier}_CCACHE", f"FILE:/tmp/{secret}"),
        (
            f"{prefix}_AUTH_{qualifier}_CONFIG",
            json.dumps({"auth": {"token": secret}, "endpoint": "https://example.invalid"}),
        ),
        (
            f"{prefix}_DATABASE_{qualifier}_DSN",
            f"postgresql://user:{secret}@db.example.invalid/app",
        ),
    )

    for name, value in definitions:
        inventory = credential_source_values({name: value})
        assert inventory == {name: value}
        assert is_credential_source_name(name)
        projected = enforce_environment_credential_provenance(
            {
                "LANG": secret,
                "PATH": f"/usr/bin:{value}",
            },
            inventory,
        )
        assert "PATH" not in projected
        if secret in sensitive_values(inventory):
            assert "LANG" not in projected


@pytest.mark.parametrize("seed", range(48))
def test_bounded_fixed_point_decodes_random_padding_free_mixed_layers(
    seed: int,
) -> None:
    generator = random.Random(30_000 + seed)
    secret = f"{generator.getrandbits(192):048x}"
    wrapped = secret
    layers = [
        generator.choice(("json", "toml", "percent", "base64"))
        for _ in range(2 + seed % 9)
    ]
    for layer in layers:
        if layer == "json":
            wrapped = json.dumps({"payload": wrapped}, separators=(",", ":"))
        elif layer == "toml":
            wrapped = f"payload = {json.dumps(wrapped)}\n"
        elif layer == "percent":
            wrapped = urllib.parse.quote(wrapped, safe="")
        else:
            wrapped = base64.urlsafe_b64encode(wrapped.encode()).decode().rstrip("=")

    repeated = secret
    for _ in range(20):
        repeated = base64.urlsafe_b64encode(repeated.encode()).decode().rstrip("=")
    benign_controls = (
        "https://api.example.invalid/oauth/token",
        "/tmp/jwt-public-key.pem",
        "postgresql://host.invalid/{database}?password={password}",
        base64.urlsafe_b64encode(
            f"tokenizer-vocabulary-model-{seed}".encode()
        ).decode().rstrip("="),
        urllib.parse.quote(
            f"password_policy=ordinary-{seed}",
            safe="",
        ),
        json.dumps({"secretary": f"ordinary-{seed}"}),
        f'model = "ordinary-model-{seed}"',
    )

    assert contains_semantic_credential(wrapped, (secret,))
    assert contains_semantic_credential(repeated, (secret,))
    assert not any(
        contains_semantic_credential(control, (secret,))
        for control in benign_controls
    )
    assert not contains_semantic_credential(
        "[" + ("x" * (300 * 1024)),
        (secret,),
    )


@pytest.mark.parametrize("seed", range(24))
def test_bounded_unknown_distinguishes_over_limit_credentials_from_ordinary_ids(
    seed: int,
) -> None:
    generator = random.Random(35_000 + seed)
    secret = f"credential-{generator.getrandbits(192):048x}"
    ordinary = f"trace-{generator.getrandbits(192):048x}"
    encoded_secret = secret
    encoded_ordinary = ordinary
    for _ in range(26):
        encoded_secret = base64.urlsafe_b64encode(
            encoded_secret.encode()
        ).decode().rstrip("=")
        encoded_ordinary = base64.urlsafe_b64encode(
            encoded_ordinary.encode()
        ).decode().rstrip("=")

    source_name = (
        "FRESH_CREDENTIAL_"
        + "".join(generator.choice(string.ascii_uppercase) for _ in range(9))
        + f"_CACHE_METADATA_V{seed}"
    )
    inventory = credential_source_values({source_name: encoded_secret})
    sensitive_unknown = json.dumps(
        {"credential": encoded_ordinary},
        separators=(",", ":"),
    )
    ordinary_unknown = json.dumps(
        {"model": encoded_ordinary},
        separators=(",", ":"),
    )
    filtered = enforce_persisted_environment_credential_provenance(
        {
            "ENCODED_CREDENTIAL_ALIAS": encoded_secret,
            "ORDINARY_ENCODED_TRACE": encoded_ordinary,
            "ORDINARY_UNKNOWN_WRAPPER": ordinary_unknown,
            "SENSITIVE_UNKNOWN_WRAPPER": sensitive_unknown,
        },
        inventory,
    )

    assert inventory == {source_name: encoded_secret}
    assert not contains_semantic_credential(encoded_secret, (secret,))
    assert not contains_semantic_credential(encoded_ordinary, (secret,))
    assert not contains_semantic_credential(sensitive_unknown, (secret,))
    assert filtered == {
        "ORDINARY_ENCODED_TRACE": encoded_ordinary,
        "ORDINARY_UNKNOWN_WRAPPER": ordinary_unknown,
    }


@pytest.mark.parametrize(
    "ceiling",
    ("depth", "nodes", "text", "decoded_bytes", "work"),
)
def test_sensitivity_is_monotonic_when_a_later_sibling_reaches_each_ceiling(
    monkeypatch: pytest.MonkeyPatch,
    ceiling: str,
) -> None:
    limits = {
        "_SEMANTIC_INSPECTION_MAX_TEXT": 1_000_000,
        "_SEMANTIC_INSPECTION_MAX_DEPTH": 100,
        "_SEMANTIC_INSPECTION_MAX_NODES": 10_000,
        "_SEMANTIC_INSPECTION_MAX_DECODED_BYTES": 1_000_000,
        "_SEMANTIC_INSPECTION_MAX_WORK": 1_000_000,
    }
    if ceiling == "depth":
        limits["_SEMANTIC_INSPECTION_MAX_DEPTH"] = 3
        later_value = "ordinary-depth-control"
        for _ in range(4):
            later_value = base64.urlsafe_b64encode(
                later_value.encode()
            ).decode().rstrip("=")
    elif ceiling == "nodes":
        limits["_SEMANTIC_INSPECTION_MAX_NODES"] = 4
        later_value = list(range(32))
    elif ceiling == "text":
        limits["_SEMANTIC_INSPECTION_MAX_TEXT"] = 32
        later_value = "[" + ("x" * 64)
    elif ceiling == "decoded_bytes":
        limits["_SEMANTIC_INSPECTION_MAX_DECODED_BYTES"] = 32
        later_value = base64.urlsafe_b64encode(
            ("ordinary-decoded-control-" * 4).encode()
        ).decode().rstrip("=")
    else:
        limits["_SEMANTIC_INSPECTION_MAX_WORK"] = 60
        later_value = "ordinary-work-control-" * 16
    for name, limit in limits.items():
        monkeypatch.setattr(capability_policy, name, limit)

    sensitive_payload = {
        "aaa_password": "concrete-sensitive-marker",
        "zzz_model": later_value,
    }
    ordinary_payload = {
        "aaa_model": "ordinary-marker",
        "zzz_model": later_value,
    }
    sensitive = capability_policy._semantic_credential_decision(
        cast(Any, sensitive_payload),
        ("unrelated-supplied-credential",),
    )
    ordinary = capability_policy._semantic_credential_decision(
        cast(Any, ordinary_payload),
        ("unrelated-supplied-credential",),
    )

    assert not sensitive.matched
    assert sensitive.bounded_unknown
    assert sensitive.concrete_sensitivity_provenance
    assert sensitive.filter_required
    assert not ordinary.matched
    assert ordinary.bounded_unknown
    assert not ordinary.concrete_sensitivity_provenance
    assert not ordinary.filter_required


@pytest.mark.parametrize("boundary", ("nodes", "text"))
@pytest.mark.parametrize("layers", (23, 24, 25, 26, 27))
def test_bounded_alias_fallback_decodes_toward_unvisited_source_leaf(
    boundary: str,
    layers: int,
) -> None:
    secret = f"{boundary}-{layers}-derived-secret-0123456789abcdef"
    alias = _padding_free_base64(secret, layers=layers)
    source = (
        _node_ceiling_source(secret, key="credential")
        if boundary == "nodes"
        else _text_ceiling_source(secret, key="credential")
    )
    source_name = (
        f"FRESH_CREDENTIAL_CACHE_METADATA_{boundary.upper()}_{layers}"
    )
    source_environment = {source_name: source}
    inventory = credential_source_values(source_environment)
    reversed_inventory = credential_source_values(
        dict(reversed(tuple(source_environment.items())))
    )
    candidate_environment = {
        "LANG": "C.UTF-8",
        "PATH": f"/usr/bin:{alias}:/bin",
    }

    assert inventory == {source_name: source}
    assert reversed_inventory == inventory
    assert capability_policy._bounded_sensitive_alias_source(
        alias,
        inventory,
    ) == source_name
    assert enforce_environment_credential_provenance(
        candidate_environment,
        inventory,
    ) == {"LANG": "C.UTF-8"}
    assert enforce_environment_credential_provenance(
        dict(reversed(tuple(candidate_environment.items()))),
        reversed_inventory,
    ) == {"LANG": "C.UTF-8"}
    assert enforce_persisted_environment_credential_provenance(
        candidate_environment,
        inventory,
    ) == {"LANG": "C.UTF-8"}
    assert enforce_environment_credential_provenance(
        candidate_environment,
        inventory,
        inherit_all=True,
    ) == dict(sorted(candidate_environment.items()))


@pytest.mark.parametrize("boundary", ("nodes", "text"))
def test_bounded_sensitive_sources_block_unvisited_aliases_but_controls_survive(
    tmp_path: Path,
    boundary: str,
) -> None:
    secret = f"{boundary}-ceiling-secret-0123456789abcdef"
    ordinary = f"{boundary}-ceiling-trace-fedcba9876543210"
    deep_alias = _padding_free_base64(secret, layers=26)
    source = (
        _node_ceiling_source(secret, key="credential")
        if boundary == "nodes"
        else _text_ceiling_source(secret, key="credential")
    )
    ordinary_source = (
        _node_ceiling_source(ordinary, key="model")
        if boundary == "nodes"
        else _text_ceiling_source(ordinary, key="model")
    )
    deep_ordinary = _padding_free_base64(ordinary, layers=26)
    source_name = f"CREDENTIAL_CACHE_METADATA_{boundary.upper()}"
    source_environment = {
        "LANG": "C.UTF-8",
        "PATH": f"/usr/bin:{deep_alias}:/bin",
        source_name: source,
    }

    inventory = credential_source_values(source_environment)
    reversed_inventory = credential_source_values(
        dict(reversed(tuple(source_environment.items())))
    )
    filtered = enforce_environment_credential_provenance(
        source_environment,
        inventory,
    )
    persisted = enforce_persisted_environment_credential_provenance(
        source_environment,
        inventory,
    )

    assert inventory == {source_name: source}
    assert reversed_inventory == inventory
    assert secret not in sensitive_values(inventory)
    assert filtered == {"LANG": "C.UTF-8"}
    assert persisted == {"LANG": "C.UTF-8"}
    assert deep_alias not in redact_credential_values(
        f"progress {deep_alias}\n",
        inventory,
    )

    ordinary_environment = {
        "ANTHROPIC_BASE_URL": "https://ordinary.invalid/oauth/token",
        "ANTHROPIC_MODEL": deep_ordinary,
        "HIGH_ENTROPY_TRACE": ordinary,
        "LANG": "C.UTF-8",
        "PATH": f"/usr/bin:{ordinary}:/bin",
        "QUALIFIED_PASSWORD_REGION_POLICY_TEMPLATE": (
            "minimum-length=24; rotation=90d"
        ),
        "QUALIFIED_DATABASE_DSN_REGION_TEMPLATE": (
            "postgresql://host/${DATABASE}?password=${DATABASE_PASSWORD}"
        ),
        "QUALIFIED_TOKEN_REGION_ENDPOINT_TEMPLATE": (
            "https://auth.example.invalid/oauth/token"
        ),
        "TEMPLATE_CONTROL": (
            "postgresql://host/${DATABASE}?password=${DATABASE_PASSWORD}"
        ),
        f"ORDINARY_MODEL_METADATA_{boundary.upper()}": ordinary_source,
    }
    ordinary_inventory = credential_source_values(ordinary_environment)
    assert ordinary_inventory == {}
    assert enforce_environment_credential_provenance(
        ordinary_environment,
        ordinary_inventory,
    ) == dict(sorted(ordinary_environment.items()))
    assert enforce_persisted_environment_credential_provenance(
        ordinary_environment,
        ordinary_inventory,
    ) == dict(sorted(ordinary_environment.items()))

    policy = _resolved(tmp_path, provider_name="codex")
    sensitive_surfaces = (
        _acp_subprocess_env(
            PROVIDERS["codex"],
            policy=policy,
            host_environment=source_environment,
        ),
        build_role_environment(
            policy,
            source_environment,
            include_credentials=True,
        ),
        build_role_environment(
            policy,
            source_environment,
            include_credentials=False,
        ),
    )
    ordinary_surfaces = (
        _acp_subprocess_env(
            PROVIDERS["codex"],
            policy=policy,
            host_environment=ordinary_environment,
        ),
        build_role_environment(
            policy,
            ordinary_environment,
            include_credentials=True,
        ),
        build_role_environment(
            policy,
            ordinary_environment,
            include_credentials=False,
        ),
    )
    assert all(
        "PATH" not in environment and environment["LANG"] == "C.UTF-8"
        for environment in sensitive_surfaces
    )
    assert all(
        environment["PATH"] == ordinary_environment["PATH"]
        and environment["LANG"] == "C.UTF-8"
        for environment in ordinary_surfaces
    )


def test_toml_detection_does_not_depend_on_base64_padding() -> None:
    secret = "VCAP_padding_independent_secret_7b218d"
    encoded = secret
    variants: list[str] = []
    for _ in range(5):
        encoded = base64.urlsafe_b64encode(encoded.encode()).decode()
        variants.extend((encoded, encoded.rstrip("=")))

    assert all(
        contains_semantic_credential(value, (secret,))
        for value in variants
    )
    assert not contains_semantic_credential(
        base64.urlsafe_b64encode(b"ordinary-policy-metadata").decode(),
        (secret,),
    )


@pytest.mark.parametrize("seed", range(48))
def test_persisted_provenance_reconstructs_randomized_reversible_wrappers(
    seed: int,
) -> None:
    generator = random.Random(seed)
    secret = (
        'VCAP_"quoted"\\κλειδί_'
        + "".join(
            generator.choice(string.ascii_letters + string.digits)
            for _ in range(24)
        )
    )
    nested_json = json.dumps(
        {"outer": [{"credential": secret}]},
        ensure_ascii=True,
        separators=(",", ":"),
    )
    double_nested_json = json.dumps(nested_json, ensure_ascii=True)
    nested_toml = (
        "payload = "
        + json.dumps(nested_json, ensure_ascii=True)
        + "\n"
    )
    percent_encoded_json = urllib.parse.quote(nested_json, safe="")
    base64_encoded_json = base64.urlsafe_b64encode(
        nested_json.encode("utf-8")
    ).decode("ascii")
    nested_percent_base64 = urllib.parse.quote(
        base64_encoded_json,
        safe="",
    )
    ordinary_json = json.dumps(
        {"outer": [{"mode": f"ordinary-{seed}"}]},
        separators=(",", ":"),
    )
    ordinary_toml = f'mode = "ordinary-{seed}"\n'
    encoded_ordinary_json = base64.urlsafe_b64encode(
        ordinary_json.encode("utf-8")
    ).decode("ascii")
    environment = {
        "BASE64_ENCODED_JSON": base64_encoded_json,
        "DIRECT_PREFIX_SUFFIX": f"prefix{secret}suffix",
        "DOUBLE_NESTED_JSON": double_nested_json,
        "NESTED_JSON": nested_json,
        "NESTED_PERCENT_BASE64": nested_percent_base64,
        "NESTED_TOML": nested_toml,
        "ORDINARY_BASE64_JSON": encoded_ordinary_json,
        "ORDINARY_BASE64_TEXT": base64.urlsafe_b64encode(
            f"ordinary-{seed}".encode("utf-8")
        ).decode("ascii"),
        "ORDINARY_JSON": ordinary_json,
        "ORDINARY_PERCENT_JSON": urllib.parse.quote(ordinary_json, safe=""),
        "ORDINARY_TOML": ordinary_toml,
        "PERCENT_ENCODED_JSON": percent_encoded_json,
    }

    filtered = enforce_persisted_environment_credential_provenance(
        environment,
        {"SERVICE_PASSWORD": secret},
    )
    reverse = enforce_persisted_environment_credential_provenance(
        dict(reversed(tuple(environment.items()))),
        {"SERVICE_PASSWORD": secret},
    )

    assert filtered == {
        "ORDINARY_BASE64_JSON": environment["ORDINARY_BASE64_JSON"],
        "ORDINARY_BASE64_TEXT": environment["ORDINARY_BASE64_TEXT"],
        "ORDINARY_JSON": environment["ORDINARY_JSON"],
        "ORDINARY_PERCENT_JSON": environment["ORDINARY_PERCENT_JSON"],
        "ORDINARY_TOML": environment["ORDINARY_TOML"],
    }
    assert reverse == filtered
    assert contains_semantic_credential(
        nested_toml,
        (secret,),
    )


def test_derived_sensitive_values_are_redacted_from_callbacks_and_persistence() -> None:
    secret = "b6e3d37ca76d41d6b4c36546fc936bc317f7f630"
    source = json.dumps(
        {
            "auth": {
                "token": secret,
                "endpoint": "https://api.example.invalid",
            }
        },
        separators=(",", ":"),
    )
    inventory = credential_source_values({"ARBITRARY_RUNTIME_SETTING": source})
    encoded = secret
    for _ in range(3):
        encoded = base64.urlsafe_b64encode(encoded.encode()).decode().rstrip("=")

    payload = {
        encoded: {
            "metadata": [f"prefix:{encoded}:suffix"],
            "ordinary": "kept",
        }
    }
    redacted = _redact_json_value(payload, inventory)
    serialized = json.dumps(redacted, sort_keys=True)
    assert not contains_semantic_credential(serialized, (secret,))
    assert "ordinary" in serialized

    for split_at in range(len(encoded) + 1):
        redactor = StreamingCredentialRedactor(inventory)
        output = redactor.feed(encoded[:split_at])
        output += redactor.feed(encoded[split_at:])
        output += redactor.finish()
        assert not contains_semantic_credential(output, (secret,))

    assert enforce_persisted_environment_credential_provenance(
        {
            "ENCODED_ALIAS": encoded,
            "LEAF_ALIAS": secret,
            "ORDINARY": "kept",
        },
        inventory,
    ) == {"ORDINARY": "kept"}


@pytest.mark.parametrize(
    "index_template",
    (
        "head}token={alias}",
        "head{token={alias}",
        "token={alias}}tail",
        "token={alias}{tail",
    ),
)
@pytest.mark.parametrize("seed", range(4))
def test_triply_unpadded_urlsafe_base64_in_brace_format_index_is_contained(
    index_template: str,
    seed: int,
) -> None:
    generator = random.Random(f"brace-format-index:{seed}")
    secret = "VCAP_" + "".join(
        generator.choice(string.ascii_letters + string.digits)
        for _ in range(36)
    )
    derivatives = [secret]
    for _ in range(3):
        derivatives.append(
            base64.urlsafe_b64encode(derivatives[-1].encode())
            .decode()
            .rstrip("=")
        )
    index = index_template.replace("{alias}", derivatives[-1])
    source = f"{{mapping[{index}]!s:^12}}"
    assert source.format(mapping={index: "ordinary"}) == "  ordinary  "

    inventory = credential_source_values(
        {"ARBITRARY_RUNTIME_SETTING": source}
    )
    inventoried = set(sensitive_values(inventory))
    assert set(derivatives).issubset(inventoried)

    payload = {
        "callback": derivatives,
        "format": source,
        "ordinary": "kept",
    }
    serialized = json.dumps(
        _redact_json_value(payload, inventory),
        sort_keys=True,
    )
    assert "ordinary" in serialized
    assert all(value not in serialized for value in derivatives)

    redactor = StreamingCredentialRedactor(inventory)
    streamed = redactor.feed("|".join(derivatives))
    streamed += redactor.finish()
    assert all(value not in streamed for value in derivatives)
    assert enforce_persisted_environment_credential_provenance(
        {
            "FORMAT_ALIAS": source,
            "RAW_ALIAS": secret,
            "ORDINARY": "kept",
        },
        inventory,
    ) == {"ORDINARY": "kept"}


def test_declared_format_source_propagates_parent_sensitivity_to_plain_index() -> None:
    secret = "local7"
    aliases = [secret]
    for _ in range(3):
        aliases.append(
            base64.urlsafe_b64encode(aliases[-1].encode())
            .decode()
            .rstrip("=")
        )
    source = f"{{mapping[{aliases[-1]}]!s:^12}}"
    assert source.format(mapping={aliases[-1]: "ordinary"}) == "  ordinary  "

    inventory = credential_source_values(
        {"DECLARED_FORMAT_SOURCE": source},
        declared_names=("DECLARED_FORMAT_SOURCE",),
    )
    assert set(aliases).issubset(sensitive_values(inventory))

    assert redact_sensitive_value(
        {"separate_payload": secret, "ordinary": "kept"},
        inventory,
    ) == {
        "separate_payload": "<redacted:DECLARED_FORMAT_SOURCE>",
        "ordinary": "kept",
    }

    for benign_name in ("RUNTIME_SETTING", "ORDINARY_FORMAT_TEMPLATE"):
        benign_inventory = credential_source_values({benign_name: source})
        assert benign_inventory == {}
        assert sensitive_values(benign_inventory) == ()


def test_semantic_inspection_limits_do_not_suppress_unstructured_or_malformed_values(
) -> None:
    secret = "VCAP_LIMIT_CONTROL_SECRET_31f70d"
    ordinary = {
        "LARGE_UNSTRUCTURED": "x" * (300 * 1024),
        "MALFORMED_BASE64": "not=base64===payload",
        "MALFORMED_PERCENT": "ordinary-%GG-value",
        "MODEL_CONFIG": "ordinary-provider-model",
    }

    assert enforce_persisted_environment_credential_provenance(
        ordinary,
        {"SERVICE_PASSWORD": secret},
    ) == ordinary


def test_embedded_credential_tokens_are_removed_from_every_safe_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "VCAP_EMBEDDED_CREDENTIAL_91f0d7"
    policy = _resolved(tmp_path, provider_name="codex")
    host = {
        "CODEX_CONFIG": json.dumps(
            {
                "authorization": f"Bearer {secret}",
                "endpoint": f"https://user:{secret}@example.invalid/",
                "ordinary": "kept",
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        "HOME": f"/ordinary/prefix/{secret}/suffix",
        "LANG": "C",
        "PATH": os.environ["PATH"],
        "ZAI_API_KEY": secret,
    }

    agent = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=policy,
        host_environment=host,
    )
    terminal = build_role_environment(policy, host, include_credentials=True)
    mcp = build_role_environment(policy, host, include_credentials=False)

    def locations(environment: dict[str, str]) -> list[str]:
        return sorted(
            name for name, value in environment.items() if secret in value
        )

    assert locations(agent) == ["ZAI_API_KEY"]
    assert locations(terminal) == ["ZAI_API_KEY"]
    assert locations(mcp) == []
    assert json.loads(agent["CODEX_CONFIG"])["ordinary"] == "kept"
    assert "authorization" not in json.loads(agent["CODEX_CONFIG"])
    assert "endpoint" not in json.loads(agent["CODEX_CONFIG"])

    for environment, expected in (
        (agent, ["ZAI_API_KEY"]),
        (terminal, ["ZAI_API_KEY"]),
        (mcp, []),
    ):
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import json, os; "
                    f"secret = {secret!r}; "
                    "print(json.dumps(sorted("
                    "name for name, value in os.environ.items() "
                    "if secret in value)))"
                ),
            ],
            check=True,
            capture_output=True,
            env=environment,
            text=True,
        )
        assert json.loads(child.stdout) == expected

    cli_workspace = tmp_path / "cli-workspace"
    cli_workspace.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "cli-home"))
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "unrest-home"))
    monkeypatch.setenv("ZAI_API_KEY", secret)
    monkeypatch.setenv(
        "PATH",
        f"{os.environ['PATH']}{os.pathsep}/ordinary/{secret}/bin",
    )
    monkeypatch.delenv("CODEX_PATH", raising=False)
    result = CliRunner().invoke(
        cli,
        [
            "init",
            "--agent",
            "codex",
            "--workspace-dir",
            str(cli_workspace),
        ],
    )
    assert result.exit_code == 0, result.output
    generated = [
        path
        for path in cli_workspace.rglob("*")
        if path.is_file() and secret in path.read_text(encoding="utf-8")
    ]
    assert generated == []


@pytest.mark.parametrize("provider", ("claude", "codex"))
@pytest.mark.parametrize("unsafe", (False, True))
def test_generated_configs_filter_precedence_and_repeatedly_encoded_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    unsafe: bool,
) -> None:
    generator = random.Random(f"{provider}:{unsafe}")
    source_name = (
        "AMBIENT_"
        + "".join(generator.choice(string.ascii_uppercase) for _ in range(15))
        + "_CREDENTIAL_CACHE_METADATA"
    )
    secret = f"{generator.getrandbits(192):048x}"
    encoded = secret
    for _ in range(4):
        encoded = base64.urlsafe_b64encode(encoded.encode()).decode().rstrip("=")
    deep_credential = secret
    deep_ordinary = f"trace-{generator.getrandbits(192):048x}"
    for _ in range(26):
        deep_credential = base64.urlsafe_b64encode(
            deep_credential.encode()
        ).decode().rstrip("=")
        deep_ordinary = base64.urlsafe_b64encode(
            deep_ordinary.encode()
        ).decode().rstrip("=")
    ordinary_endpoint = "https://api.example.invalid/oauth/token"
    workspace = tmp_path / "generated-workspace"
    workspace.mkdir()

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "unrest-home"))
    monkeypatch.setenv("PATH", f"{os.environ['PATH']}:{secret}")
    monkeypatch.setenv(source_name, secret)
    monkeypatch.setenv(
        f"{source_name}_DEEP_CREDENTIAL_CACHE_METADATA",
        deep_credential,
    )
    monkeypatch.setenv("ANTHROPIC_MODEL", deep_ordinary)
    monkeypatch.setenv("ANTHROPIC_DEFAULT_SONNET_MODEL", encoded)
    monkeypatch.setenv(
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        deep_credential,
    )
    monkeypatch.setenv("ANTHROPIC_BASE_URL", ordinary_endpoint)
    monkeypatch.setenv("OAUTH_TOKEN_ENDPOINT", ordinary_endpoint)
    monkeypatch.delenv("CODEX_PATH", raising=False)

    arguments = [
        "init",
        "--agent",
        provider,
        "--workspace-dir",
        str(workspace),
    ]
    if unsafe:
        arguments.append("--unsafe-development-unrestricted")
    result = CliRunner().invoke(cli, arguments)
    assert result.exit_code == 0, result.output

    if provider == "claude":
        generated = json.loads((workspace / ".mcp.json").read_text())
        environment = generated["mcpServers"]["unrest"]["env"]
    else:
        generated = tomllib.loads(
            (workspace / ".codex" / "config.toml").read_text()
        )
        environment = generated["mcp_servers"]["unrest"]["env"]
    assert environment["ANTHROPIC_BASE_URL"] == ordinary_endpoint
    assert environment["ANTHROPIC_MODEL"] == deep_ordinary
    assert "ANTHROPIC_DEFAULT_SONNET_MODEL" not in environment
    assert "ANTHROPIC_DEFAULT_OPUS_MODEL" not in environment
    assert "PATH" not in environment
    assert not any(
        contains_semantic_credential(value, (secret,))
        for value in environment.values()
    )


@pytest.mark.parametrize("agent", ("claude", "codex"))
@pytest.mark.parametrize("unsafe", (False, True), ids=("safe", "unsafe"))
@pytest.mark.parametrize(
    "template",
    (
        pytest.param(
            "postgresql://host.invalid/{database}?password={password}",
            id="simple-fields",
        ),
        pytest.param(
            _indexed_format_uri("custom:/v21"),
            id="indexed-attribute-nested-fields",
        ),
        pytest.param(
            _brace_index_format_uri("custom:/v22"),
            id="brace-index-nested-fields",
        ),
    ),
)
def test_generated_configs_preserve_complete_connection_templates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent: str,
    unsafe: bool,
    template: str,
) -> None:
    qualifier = f"{agent}_{'unsafe' if unsafe else 'safe'}".upper()
    source_name = f"PAYMENTS_{qualifier}_DSN_TEMPLATE_URI"
    path_value = f"{template}:relative-tools:local-bin"
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "unrest-home"))
    monkeypatch.setenv("ANTHROPIC_MODEL", template)
    monkeypatch.setenv("PATH", path_value)
    monkeypatch.setenv(source_name, template)
    monkeypatch.delenv("CODEX_PATH", raising=False)
    arguments = [
        "init",
        "--agent",
        agent,
        "--workspace-dir",
        str(workspace),
    ]
    if unsafe:
        arguments.append("--unsafe-development-unrestricted")

    first = CliRunner().invoke(cli, arguments)
    assert first.exit_code == 0, first.output
    config_path = (
        workspace / ".mcp.json"
        if agent == "claude"
        else workspace / ".codex" / "config.toml"
    )
    first_bytes = config_path.read_bytes()
    first_artifacts = {
        path.relative_to(workspace): path.read_bytes()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }
    if agent == "claude":
        generated = json.loads(first_bytes)
        environment = generated["mcpServers"]["unrest"]["env"]
    else:
        generated = tomllib.loads(first_bytes.decode())
        environment = generated["mcp_servers"]["unrest"]["env"]

    assert environment["ANTHROPIC_MODEL"] == template
    assert environment["PATH"] == path_value
    assert source_name not in environment

    second = CliRunner().invoke(cli, arguments)
    assert second.exit_code == 0, second.output
    assert config_path.read_bytes() == first_bytes
    assert {
        path.relative_to(workspace): path.read_bytes()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    } == first_artifacts
    archive_payloads = _workspace_archive_payloads(
        workspace,
        tmp_path / "generated-configs.tar",
    )
    assert archive_payloads
    assert any(
        template.encode() in payload
        for payload in archive_payloads.values()
    )


@pytest.mark.parametrize("agent", ("claude", "codex"))
@pytest.mark.parametrize("unsafe", (False, True), ids=("safe", "unsafe"))
def test_generated_configs_filter_credentials_inside_format_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent: str,
    unsafe: bool,
) -> None:
    secret = f"v22-{agent}-{unsafe}-format-ast-credential"
    source_name = (
        f"PAYMENTS_{agent}_{unsafe}_FORMAT_DSN_TEMPLATE_URI_V22"
    ).upper()
    source_value = (
        "custom:/v22"
        f";render={{value:password={secret}}}"
        f"?layout={{mapping[password={secret}]!s:^12}}"
        f"#meta={{value:token={secret};width={{width}}}}"
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "unrest-home"))
    monkeypatch.setenv("ANTHROPIC_MODEL", source_value)
    monkeypatch.setenv("PATH", f"{os.defpath}:{secret}")
    monkeypatch.setenv(source_name, source_value)
    monkeypatch.delenv("CODEX_PATH", raising=False)
    arguments = [
        "init",
        "--agent",
        agent,
        "--workspace-dir",
        str(workspace),
    ]
    if unsafe:
        arguments.append("--unsafe-development-unrestricted")

    first = CliRunner().invoke(cli, arguments)
    assert first.exit_code == 0, first.output
    first_artifacts = {
        path.relative_to(workspace): path.read_bytes()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }
    assert first_artifacts
    assert all(
        secret.encode() not in artifact
        and source_value.encode() not in artifact
        for artifact in first_artifacts.values()
    )

    second = CliRunner().invoke(cli, arguments)
    assert second.exit_code == 0, second.output
    assert {
        path.relative_to(workspace): path.read_bytes()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    } == first_artifacts
    archive_payloads = _workspace_archive_payloads(
        workspace,
        tmp_path / "format-ast-configs.tar",
    )
    assert archive_payloads
    assert all(
        secret.encode() not in payload
        and source_value.encode() not in payload
        for payload in archive_payloads.values()
    )


@pytest.mark.parametrize("agent", ("claude", "codex"))
@pytest.mark.parametrize("unsafe", (False, True), ids=("safe", "unsafe"))
@pytest.mark.parametrize(
    "root",
    (
        "https://api.invalid/v1",
        "custom:///v1",
        "../v1",
        "custom:v1",
    ),
    ids=("hierarchical", "empty-authority", "relative", "opaque"),
)
def test_generated_configs_filter_uri_path_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent: str,
    unsafe: bool,
    root: str,
) -> None:
    secret = f"v18-{agent}-{unsafe}-path-credential-0123456789abcdef"
    source_name = f"PAYMENTS_{agent.upper()}_DSN_TEMPLATE_URI_V18"
    value = f"{root}/credential/{secret}?password={{password}}"
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "unrest-home"))
    monkeypatch.setenv("PATH", f"{os.defpath}:{value}")
    monkeypatch.setenv("ANTHROPIC_MODEL", value)
    monkeypatch.setenv(source_name, value)
    monkeypatch.delenv("CODEX_PATH", raising=False)
    arguments = [
        "init",
        "--agent",
        agent,
        "--workspace-dir",
        str(workspace),
    ]
    if unsafe:
        arguments.append("--unsafe-development-unrestricted")

    first = CliRunner().invoke(cli, arguments)
    assert first.exit_code == 0, first.output
    config_path = (
        workspace / ".mcp.json"
        if agent == "claude"
        else workspace / ".codex" / "config.toml"
    )
    first_artifacts = {
        path.relative_to(workspace): path.read_bytes()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }
    assert first_artifacts
    assert all(
        secret.encode() not in artifact and value.encode() not in artifact
        for artifact in first_artifacts.values()
    )

    second = CliRunner().invoke(cli, arguments)
    assert second.exit_code == 0, second.output
    second_artifacts = {
        path.relative_to(workspace): path.read_bytes()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }
    assert second_artifacts == first_artifacts
    archive_payloads = _workspace_archive_payloads(
        workspace,
        tmp_path / "generated-configs.tar",
    )
    assert all(
        secret.encode() not in payload and value.encode() not in payload
        for payload in archive_payloads.values()
    )
    assert config_path in {
        workspace / path
        for path in first_artifacts
    }


@pytest.mark.parametrize("agent", ("claude", "codex"))
@pytest.mark.parametrize("unsafe", (False, True), ids=("safe", "unsafe"))
@pytest.mark.parametrize("boundary", ("nodes", "text"))
@pytest.mark.parametrize("alias_family", ("base64", "hex", "mixed"))
def test_generated_configs_fail_closed_for_unvisited_bounded_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent: str,
    unsafe: bool,
    boundary: str,
    alias_family: str,
) -> None:
    secret = f"{agent}-{boundary}-init-secret-0123456789abcdef"
    deep_alias = (
        _padding_free_base64(secret, layers=26)
        if alias_family == "base64"
        else _reversible_alias(secret, alias_family)
    )
    source = (
        _node_ceiling_source(secret, key="credential")
        if boundary == "nodes"
        else _text_ceiling_source(secret, key="credential")
    )
    source_name = (
        f"CREDENTIAL_CACHE_METADATA_INIT_{agent.upper()}_{boundary.upper()}"
    )
    endpoint = "https://safe.example.invalid/api"
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "unrest-home"))
    monkeypatch.setenv("ANTHROPIC_BASE_URL", endpoint)
    monkeypatch.setenv("PATH", f"{os.defpath}:{deep_alias}")
    monkeypatch.setenv(source_name, source)
    monkeypatch.delenv("CODEX_PATH", raising=False)
    arguments = [
        "init",
        "--agent",
        agent,
        "--workspace-dir",
        str(workspace),
    ]
    if unsafe:
        arguments.append("--unsafe-development-unrestricted")

    first = CliRunner().invoke(cli, arguments)
    assert first.exit_code == 0, first.output
    config_path = (
        workspace / ".mcp.json"
        if agent == "claude"
        else workspace / ".codex" / "config.toml"
    )
    first_artifacts = {
        path.relative_to(workspace): path.read_bytes()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }
    if agent == "claude":
        generated = json.loads(config_path.read_text(encoding="utf-8"))
        environment = generated["mcpServers"]["unrest"]["env"]
    else:
        generated = tomllib.loads(config_path.read_text(encoding="utf-8"))
        environment = generated["mcp_servers"]["unrest"]["env"]

    assert environment["ANTHROPIC_BASE_URL"] == endpoint
    assert "PATH" not in environment
    assert source_name not in environment
    assert all(
        secret.encode() not in artifact and deep_alias.encode() not in artifact
        for artifact in first_artifacts.values()
    )

    second = CliRunner().invoke(cli, arguments)
    assert second.exit_code == 0, second.output
    second_artifacts = {
        path.relative_to(workspace): path.read_bytes()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }
    assert second_artifacts == first_artifacts


def test_embedded_short_credential_matching_preserves_identifier_text(
    tmp_path: Path,
) -> None:
    policy = _resolved(tmp_path)
    environment = build_role_environment(
        policy,
        {
            "HOME": "/ordinary/MONKEY/KEY-label/.KEY/value",
            "LANG": "KEY",
            "OPENAI_API_KEY": "KEY",
            "PATH": os.environ["PATH"],
        },
    )

    assert environment["HOME"] == "/ordinary/MONKEY/KEY-label/.KEY/value"
    assert environment["OPENAI_API_KEY"] == "KEY"
    assert "LANG" not in environment


_SUPPORTED_PROVIDER_ROLES = (
    ("claude", "orchestrator"),
    ("claude", "worker"),
    ("claude", "validator"),
    ("claude", "terminal_reviewer"),
    ("codex", "orchestrator"),
    ("codex", "worker"),
    ("codex", "validator"),
    ("codex", "terminal_reviewer"),
    ("hermes", "worker"),
    ("hermes", "validator"),
    ("hermes", "terminal_reviewer"),
)


_ROLE_URI_TAXONOMY = tuple(
    (case, value)
    for case, family, value, expected_sensitive, _ in _sensitivity_taxonomy()
    if expected_sensitive
    and family
    in {
        "double-encoding",
        "nested-container",
        "nested-reversible",
        "uri-fragment",
        "uri-host-adjacent",
        "uri-matrix",
        "uri-path",
        "uri-query",
        "uri-userinfo",
    }
)


@pytest.mark.parametrize(("provider_name", "role"), _SUPPORTED_PROVIDER_ROLES)
def test_all_provider_roles_preserve_unsafe_authority_but_filter_safe_aliases(
    tmp_path: Path,
    provider_name: str,
    role: str,
) -> None:
    secret = f"v19-{provider_name}-{role}-container-credential"
    alias = _reversible_alias(secret, "mixed")
    source_name = (
        f"CREDENTIAL_CACHE_{provider_name}_{role}_METADATA_V19"
    ).upper()
    host = {
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "PATH": os.pathsep.join(("/usr/bin", alias, "/bin")),
        source_name: secret,
    }
    safe_policy = _resolved(
        tmp_path,
        provider_name=provider_name,
        role=role,
    )
    unsafe_policy = _resolved(
        tmp_path,
        provider_name=provider_name,
        role=role,
        profile=UNSAFE_DEVELOPMENT_PROFILE,
    )

    safe_environments = (
        _acp_subprocess_env(
            PROVIDERS[provider_name],  # type: ignore[index]
            policy=safe_policy,
            host_environment=host,
        ),
        build_role_environment(safe_policy, host),
    )
    unsafe_environments = (
        _acp_subprocess_env(
            PROVIDERS[provider_name],  # type: ignore[index]
            policy=unsafe_policy,
            host_environment=host,
        ),
        build_role_environment(unsafe_policy, host),
    )

    for environment in safe_environments:
        assert "PATH" not in environment
        child = subprocess.run(
            ["/usr/bin/env", "-0"],
            check=True,
            capture_output=True,
            env=environment,
        )
        assert alias.encode() not in child.stdout
    for environment in unsafe_environments:
        assert environment["PATH"] == host["PATH"]
        child = subprocess.run(
            ["/usr/bin/env", "-0"],
            check=True,
            capture_output=True,
            env=environment,
        )
        assert f"PATH={host['PATH']}".encode() in child.stdout.split(b"\0")


@pytest.mark.parametrize(("provider_name", "role"), _SUPPORTED_PROVIDER_ROLES)
@pytest.mark.parametrize(
    ("case", "value"),
    _ROLE_URI_TAXONOMY,
    ids=[row[0] for row in _ROLE_URI_TAXONOMY],
)
def test_all_safe_role_projections_filter_uri_component_taxonomy(
    tmp_path: Path,
    provider_name: str,
    role: str,
    case: str,
    value: str,
) -> None:
    del case
    source_name = (
        f"PAYMENTS_{provider_name}_{role}_DSN_TEMPLATE_URI_V18"
    ).upper()
    host = {
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "PATH": f"{os.defpath}:{value}",
        source_name: value,
    }
    policy = _resolved(
        tmp_path,
        provider_name=provider_name,
        role=role,
    )
    reversed_host = dict(reversed(tuple(host.items())))

    environments = (
        _acp_subprocess_env(
            PROVIDERS[provider_name],  # type: ignore[index]
            policy=policy,
            host_environment=host,
        ),
        build_role_environment(policy, host, include_credentials=True),
        build_role_environment(policy, host, include_credentials=False),
    )
    reversed_environments = (
        _acp_subprocess_env(
            PROVIDERS[provider_name],  # type: ignore[index]
            policy=policy,
            host_environment=reversed_host,
        ),
        build_role_environment(
            policy,
            reversed_host,
            include_credentials=True,
        ),
        build_role_environment(
            policy,
            reversed_host,
            include_credentials=False,
        ),
    )

    assert reversed_environments == environments
    for environment in environments:
        assert "PATH" not in environment
        assert source_name not in environment
        child = subprocess.run(
            ["/usr/bin/env", "-0"],
            check=True,
            capture_output=True,
            env=environment,
        )
        assert value.encode() not in child.stdout


@pytest.mark.parametrize(("provider_name", "role"), _SUPPORTED_PROVIDER_ROLES)
@pytest.mark.parametrize(
    "template",
    (
        pytest.param(
            "postgresql://host.invalid/{database}?password={password}",
            id="simple-fields",
        ),
        pytest.param(
            _indexed_format_uri("custom:/v21"),
            id="indexed-attribute-nested-fields",
        ),
        pytest.param(
            _brace_index_format_uri("custom:/v22"),
            id="brace-index-nested-fields",
        ),
    ),
)
def test_all_safe_role_projections_preserve_complete_connection_templates(
    tmp_path: Path,
    provider_name: str,
    role: str,
    template: str,
) -> None:
    qualifier = f"{provider_name}_{role}".upper()
    source_name = f"PAYMENTS_{qualifier}_DSN_TEMPLATE_URI"
    host = {
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "PATH": f"{template}:relative-tools:local-bin",
        source_name: template,
    }
    policy = _resolved(
        tmp_path,
        provider_name=provider_name,
        role=role,
    )
    reversed_host = dict(reversed(tuple(host.items())))

    inventory = credential_source_values(host)
    environments = (
        _acp_subprocess_env(
            PROVIDERS[provider_name],  # type: ignore[index]
            policy=policy,
            host_environment=host,
        ),
        build_role_environment(policy, host, include_credentials=True),
        build_role_environment(policy, host, include_credentials=False),
    )
    reversed_environments = (
        _acp_subprocess_env(
            PROVIDERS[provider_name],  # type: ignore[index]
            policy=policy,
            host_environment=reversed_host,
        ),
        build_role_environment(
            policy,
            reversed_host,
            include_credentials=True,
        ),
        build_role_environment(
            policy,
            reversed_host,
            include_credentials=False,
        ),
    )

    assert inventory == {}
    assert reversed_environments == environments
    for environment in environments:
        assert environment["PATH"] == host["PATH"]
        child = subprocess.run(
            ["/usr/bin/env", "-0"],
            check=True,
            capture_output=True,
            env=environment,
        )
        assert f"PATH={host['PATH']}".encode() in child.stdout.split(b"\0")


@pytest.mark.parametrize(("provider_name", "role"), _SUPPORTED_PROVIDER_ROLES)
def test_all_safe_role_projections_filter_credentials_inside_format_fields(
    tmp_path: Path,
    provider_name: str,
    role: str,
) -> None:
    secret = f"v22-{provider_name}-{role}-format-ast-credential"
    source_name = (
        f"PAYMENTS_{provider_name}_{role}_FORMAT_DSN_TEMPLATE_URI_V22"
    ).upper()
    source_value = (
        "custom:/v22"
        f";render={{value:password={secret}}}"
        f"?layout={{mapping[password={secret}]!s:^12}}"
        f"#meta={{value:token={secret};width={{width}}}}"
    )
    host = {
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "PATH": f"{os.defpath}:{secret}",
        source_name: source_value,
    }
    policy = _resolved(
        tmp_path,
        provider_name=provider_name,
        role=role,
    )
    inventory = credential_source_values(host)
    environments = (
        _acp_subprocess_env(
            PROVIDERS[provider_name],  # type: ignore[index]
            policy=policy,
            host_environment=host,
        ),
        build_role_environment(policy, host, include_credentials=True),
        build_role_environment(policy, host, include_credentials=False),
    )

    assert source_name in inventory
    assert secret in sensitive_values(inventory)
    for environment in environments:
        assert "PATH" not in environment
        assert source_name not in environment
        child = subprocess.run(
            ["/usr/bin/env", "-0"],
            check=True,
            capture_output=True,
            env=environment,
        )
        assert secret.encode() not in child.stdout


@pytest.mark.parametrize(("provider_name", "role"), _SUPPORTED_PROVIDER_ROLES)
def test_all_safe_children_apply_strong_over_benign_precedence(
    tmp_path: Path,
    provider_name: str,
    role: str,
) -> None:
    secret = f"VCAP-{provider_name}-{role}-precedence"
    source_name = (
        f"FRESH_CREDENTIAL_{provider_name}_{role}_CACHE_METADATA_V17"
    ).upper()
    dsn = (
        f"postgresql://worker:{secret}@db.example.invalid/app"
        "?region=${DEPLOY_REGION}"
    )
    host = {
        "HOME": str(tmp_path),
        "LANG": "C",
        "PATH": f"/usr/bin:{dsn}:/bin",
        source_name: dsn,
    }
    policy = _resolved(
        tmp_path,
        provider_name=provider_name,
        role=role,
    )

    environments = (
        _acp_subprocess_env(
            PROVIDERS[provider_name],  # type: ignore[index]
            policy=policy,
            host_environment=host,
        ),
        build_role_environment(policy, host, include_credentials=True),
        build_role_environment(policy, host, include_credentials=False),
    )

    for environment in environments:
        assert source_name not in environment
        assert all(secret not in value for value in environment.values())


@pytest.mark.parametrize(("provider_name", "role"), _SUPPORTED_PROVIDER_ROLES)
def test_all_safe_real_children_filter_ambient_common_credential_aliases(
    tmp_path: Path,
    provider_name: str,
    role: str,
) -> None:
    source_name = _COMMON_CREDENTIAL_SOURCE_NAMES[
        sum(ord(character) for character in f"{provider_name}:{role}")
        % len(_COMMON_CREDENTIAL_SOURCE_NAMES)
    ]
    secret = f"VCAP_{provider_name}_{role}_common_credential"
    host = {
        "HOME": str(tmp_path),
        "LANG": "C",
        "PATH": f"/usr/bin:prefix{secret}suffix:/bin",
        source_name: secret,
    }
    policy = _resolved(
        tmp_path,
        provider_name=provider_name,
        role=role,
    )

    agent = _acp_subprocess_env(
        PROVIDERS[provider_name],  # type: ignore[index]
        policy=policy,
        host_environment=host,
    )
    terminal = build_role_environment(
        policy,
        host,
        include_credentials=True,
    )
    mcp_child = build_role_environment(
        policy,
        host,
        include_credentials=False,
    )

    for environment in (agent, terminal, mcp_child):
        assert source_name not in environment
        assert all(secret not in value for value in environment.values())
        child = subprocess.run(
            ["/usr/bin/env", "-0"],
            check=True,
            capture_output=True,
            env=environment,
        )
        assert secret.encode() not in child.stdout


@pytest.mark.parametrize(("provider_name", "role"), _SUPPORTED_PROVIDER_ROLES)
def test_all_safe_role_children_enforce_exact_credential_value_provenance(
    tmp_path: Path,
    provider_name: str,
    role: str,
) -> None:
    unicode_secret = "κλειδί-🔐"
    short_secret = "KEY"
    overlapping_secret = "KEY-long"
    host = {
        "ANTHROPIC_API_KEY": unicode_secret,
        "ANTHROPIC_AUTH_TOKEN": "",
        "CODEX_API_KEY": overlapping_secret,
        "LANG": unicode_secret,
        "LC_ALL": short_secret,
        "OPENAI_API_KEY": short_secret,
        "PATH": os.environ["PATH"],
        "RANDOM_ALIAS": unicode_secret,
        "TEMP": "",
        "TMPDIR": overlapping_secret,
        "ZAI_API_KEY": unicode_secret,
    }
    reversed_host = dict(reversed(tuple(host.items())))
    policy = _resolved(
        tmp_path,
        provider_name=provider_name,
        role=role,
    )

    first = _acp_subprocess_env(
        PROVIDERS[provider_name],  # type: ignore[index]
        policy=policy,
        host_environment=host,
    )
    second = _acp_subprocess_env(
        PROVIDERS[provider_name],  # type: ignore[index]
        policy=policy,
        host_environment=reversed_host,
    )

    assert first == second
    assert tuple(first) == tuple(sorted(first))
    assert first["ANTHROPIC_API_KEY"] == unicode_secret
    assert first["ZAI_API_KEY"] == unicode_secret
    assert first["OPENAI_API_KEY"] == short_secret
    assert first["CODEX_API_KEY"] == overlapping_secret
    assert first["ANTHROPIC_AUTH_TOKEN"] == ""
    assert first["TEMP"] == ""
    assert "LANG" not in first
    assert "LC_ALL" not in first
    assert "TMPDIR" not in first
    assert "RANDOM_ALIAS" not in first

    child = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, os; "
                "value = os.environ['ZAI_API_KEY']; "
                "print(json.dumps(sorted("
                "name for name, item in os.environ.items() if item == value)))"
            ),
        ],
        check=True,
        capture_output=True,
        env=first,
        text=True,
    )
    assert json.loads(child.stdout) == [
        "ANTHROPIC_API_KEY",
        "ZAI_API_KEY",
    ]
    assert unicode_secret not in child.stdout

    mcp_environment = build_role_environment(
        policy,
        host,
        internal={"UNREST_HOME": short_secret},
        include_credentials=False,
    )
    assert mcp_environment == {
        "PATH": os.environ["PATH"],
        "TEMP": "",
    }


def test_codex_structured_config_drops_exact_aliases_and_preserves_config(
    tmp_path: Path,
) -> None:
    unicode_secret = "κλειδί-🔐"
    short_secret = "KEY"
    overlapping_secret = "KEY-long"
    raw_config = {
        unicode_secret: "secret-valued-key-is-not-emitted",
        "empty": "",
        "fallbacks": [
            short_secret,
            "kept",
            {"drop": overlapping_secret, "keep": "ordinary"},
        ],
        "features": {
            "memories": True,
            "secret_alias": unicode_secret,
        },
        "model": unicode_secret,
    }
    host = {
        "ANTHROPIC_API_KEY": unicode_secret,
        "CODEX_API_KEY": overlapping_secret,
        "CODEX_CONFIG": json.dumps(raw_config, ensure_ascii=False),
        "OPENAI_API_KEY": short_secret,
        "PATH": os.environ["PATH"],
    }
    policy = _resolved(tmp_path, provider_name="codex")

    forward = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=policy,
        host_environment=host,
    )
    reversed_host = dict(reversed(tuple(host.items())))
    reversed_host["CODEX_CONFIG"] = json.dumps(
        dict(reversed(tuple(raw_config.items()))),
        ensure_ascii=False,
    )
    reverse = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=policy,
        host_environment=reversed_host,
    )

    assert forward == reverse
    assert unicode_secret not in forward["CODEX_CONFIG"]
    assert short_secret not in forward["CODEX_CONFIG"]
    assert overlapping_secret not in forward["CODEX_CONFIG"]
    assert json.loads(forward["CODEX_CONFIG"]) == {
        "approval_policy": "on-request",
        "empty": "",
        "fallbacks": [
            "kept",
            {"keep": "ordinary"},
        ],
        "features": {"memories": True},
        "model_reasoning_effort": "medium",
        "sandbox_mode": "workspace-write",
    }


@pytest.mark.parametrize(
    "profile",
    [SAFE_PROFILE, UNSAFE_DEVELOPMENT_PROFILE],
)
def test_codex_structured_config_uses_semantic_ambient_inventory(
    tmp_path: Path,
    profile: str,
) -> None:
    secret = 'VCAP_"codex-config"\\κλειδί_f125'
    encoded_json = json.dumps(
        {"outer": [{"credential": secret}]},
        ensure_ascii=True,
        separators=(",", ":"),
    )
    encoded_toml = (
        "payload = "
        + json.dumps(encoded_json, ensure_ascii=True)
        + "\n"
    )
    raw_config = {
        "drop_json": encoded_json,
        "drop_toml": encoded_toml,
        "ordinary": {"nested": ["kept"]},
    }
    host = {
        "CODEX_CONFIG": json.dumps(raw_config, ensure_ascii=True),
        "PATH": os.environ["PATH"],
        "SERVICE_PASSWORD": secret,
    }
    policy = _resolved(
        tmp_path,
        provider_name="codex",
        profile=profile,
    )

    environment = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=policy,
        host_environment=host,
    )
    config = json.loads(environment["CODEX_CONFIG"])

    assert "drop_json" not in config
    assert "drop_toml" not in config
    assert config["ordinary"] == {"nested": ["kept"]}
    assert secret not in environment["CODEX_CONFIG"]
    if profile == UNSAFE_DEVELOPMENT_PROFILE:
        assert environment["SERVICE_PASSWORD"] == secret


def test_credential_redaction_handles_multiple_overlapping_and_empty_values() -> None:
    text = (
        "ZAI_API_KEY stays; long=credential-value; short=credential; "
        "ANTHROPIC_API_KEY stays; unrelated stays"
    )
    redacted = redact_credential_values(
        text,
        {
            "ANTHROPIC_API_KEY": "",
            "OPENAI_API_KEY": "credential",
            "ZAI_API_KEY": "credential-value",
        },
    )
    assert redacted == (
        "ZAI_API_KEY stays; long=<redacted:ZAI_API_KEY>; "
        "short=<redacted:OPENAI_API_KEY>; ANTHROPIC_API_KEY stays; "
        "unrelated stays"
    )


def test_credential_redaction_is_boundary_aware_and_deterministic() -> None:
    credentials = {
        "ANTHROPIC_API_KEY": "",
        "OPENAI_API_KEY": "KEY-long",
        "ZAI_API_KEY": "KEY",
    }
    text = (
        "ZAI_API_KEY=KEY\n"
        "OPENAI_API_KEY=KEY-long\n"
        "short=KEY; duplicate=KEY; "
        "innocent=MONKEY KEY-label .KEY KEY.\n"
    )
    expected = (
        "ZAI_API_KEY=<redacted:ZAI_API_KEY>\n"
        "OPENAI_API_KEY=<redacted:OPENAI_API_KEY>\n"
        "short=<redacted:ZAI_API_KEY>; duplicate=<redacted:ZAI_API_KEY>; "
        "innocent=MONKEY KEY-label .KEY KEY.\n"
    )

    assert redact_credential_values(text, credentials) == expected
    assert redact_credential_values(
        "value=KEY;",
        {"ZAI_API_KEY": "KEY", "OPENAI_API_KEY": "KEY"},
    ) == "value=<redacted:OPENAI_API_KEY>;"
    assert redact_credential_values(
        "KEY=KEY\n",
        {"KEY": "KEY"},
    ) == "KEY=<redacted:KEY>\n"

    for split_at in range(len(text) + 1):
        redactor = StreamingCredentialRedactor(credentials)
        actual = redactor.feed(text[:split_at])
        actual += redactor.feed(text[split_at:])
        actual += redactor.finish()
        assert actual == expected

    per_character = StreamingCredentialRedactor(credentials)
    actual = "".join(per_character.feed(character) for character in text)
    actual += per_character.finish()
    assert actual == expected


def test_streaming_redaction_covers_long_prefix_suffix_aliases() -> None:
    secret = "VCAP_long_embedded_credential_7d91f2"
    text = f"prefix{secret}suffix"
    expected = "prefix<redacted:SERVICE_PASSWORD>suffix"
    credentials = {"SERVICE_PASSWORD": secret}

    for split_at in range(len(text) + 1):
        redactor = StreamingCredentialRedactor(credentials)
        actual = redactor.feed(text[:split_at])
        actual += redactor.feed(text[split_at:])
        actual += redactor.finish()
        assert actual == expected


def test_recursive_json_redaction_covers_keys_values_and_persisted_output(
    tmp_path: Path,
) -> None:
    secret = "JSON_SECRET_密钥_2e71"
    credentials = {
        "OPENAI_API_KEY": "KEY",
        "ZAI_API_KEY": secret,
    }
    payload = {
        "ZAI_API_KEY": "permitted key name remains",
        secret: {
            "value": secret,
            "short": "KEY",
            "innocent": "MONKEY and KEY-label",
        },
        "nested": [
            {
                f"prefix {secret} suffix": f"found {secret};",
                "ZAI_API_KEY": "KEY",
            }
        ],
    }
    expected = {
        "ZAI_API_KEY": "permitted key name remains",
        "<redacted:ZAI_API_KEY>": {
            "value": "<redacted:ZAI_API_KEY>",
            "short": "<redacted:OPENAI_API_KEY>",
            "innocent": "MONKEY and KEY-label",
        },
        "nested": [
            {
                "prefix <redacted:ZAI_API_KEY> suffix": (
                    "found <redacted:ZAI_API_KEY>;"
                ),
                "ZAI_API_KEY": "<redacted:OPENAI_API_KEY>",
            }
        ],
    }

    assert _redact_json_value(payload, credentials) == expected

    persisted = tmp_path / "handoff.json"
    persisted.write_text(json.dumps(payload), encoding="utf-8")
    assert _load_redacted_json(persisted, credentials) == expected
    persisted_text = persisted.read_text(encoding="utf-8")
    assert secret not in persisted_text
    assert json.loads(persisted_text) == expected


def test_recursive_json_redaction_preserves_colliding_keys_deterministically(
    tmp_path: Path,
) -> None:
    unicode_secret = "JSON_COLLISION_密钥🔐_7c29"
    overlap_secret = f"{unicode_secret}-overlap"
    short_secret = "KEY"
    credentials = {
        "GLM_API_KEY": short_secret,
        "OPENAI_API_KEY": overlap_secret,
        "ZAI_API_KEY": unicode_secret,
    }
    zai_placeholder = "<redacted:ZAI_API_KEY>"
    openai_placeholder = "<redacted:OPENAI_API_KEY>"
    shared_candidate = f"{zai_placeholder}{openai_placeholder}"
    first_shared_key = f"{unicode_secret}{openai_placeholder}"
    second_shared_key = f"{zai_placeholder}{overlap_secret}"
    nested_collision = {
        zai_placeholder: "nested innocent placeholder",
        unicode_secret: "nested secret-valued key",
    }
    payload = {
        f"{zai_placeholder}#1": "innocent existing suffix",
        unicode_secret: {
            "sequence": [
                nested_collision,
                {
                    "unicode": unicode_secret,
                    "short": short_secret,
                    "overlap": overlap_secret,
                    "ordinary": "MONKEY and KEY-label",
                },
            ]
        },
        first_shared_key: "first shared candidate",
        second_shared_key: "second shared candidate",
        zai_placeholder: "innocent existing placeholder",
    }

    expected = {
        shared_candidate + "#1": "second shared candidate",
        shared_candidate + "#2": "first shared candidate",
        zai_placeholder: "innocent existing placeholder",
        f"{zai_placeholder}#1": "innocent existing suffix",
        f"{zai_placeholder}#2": {
            "sequence": [
                {
                    zai_placeholder: "nested innocent placeholder",
                    f"{zai_placeholder}#1": "nested secret-valued key",
                },
                {
                    "ordinary": "MONKEY and KEY-label",
                    "overlap": openai_placeholder,
                    "short": "<redacted:GLM_API_KEY>",
                    "unicode": zai_placeholder,
                },
            ]
        },
    }
    redacted = _redact_json_value(payload, credentials)
    assert redacted == expected
    assert len(redacted) == len(payload)
    assert tuple(redacted) == tuple(sorted(redacted))
    assert unicode_secret not in json.dumps(redacted, ensure_ascii=False)
    assert overlap_secret not in json.dumps(redacted, ensure_ascii=False)

    def reverse_mappings(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: reverse_mappings(item)
                for key, item in reversed(tuple(value.items()))
            }
        if isinstance(value, list):
            return [reverse_mappings(item) for item in value]
        return value

    reversed_payload = reverse_mappings(payload)
    reversed_redacted = _redact_json_value(reversed_payload, credentials)
    assert json.dumps(redacted, ensure_ascii=False) == json.dumps(
        reversed_redacted,
        ensure_ascii=False,
    )

    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    first_path.write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )
    second_path.write_text(
        json.dumps(reversed_payload, ensure_ascii=False),
        encoding="utf-8",
    )
    assert _load_redacted_json(first_path, credentials) == expected
    assert _load_redacted_json(second_path, credentials) == expected
    assert first_path.read_bytes() == second_path.read_bytes()


def test_terminal_byte_redaction_handles_unicode_boundaries_and_final_prefixes() -> None:
    secret = "密钥🔐KEY"
    credentials = {"ZAI_API_KEY": secret, "OPENAI_API_KEY": "KEY"}
    prefix = "ZAI_API_KEY=".encode()
    encoded_secret = secret.encode()
    payload = prefix + encoded_secret + b"\nordinary=KEY-label\n"

    for byte_count in range(1, len(encoded_secret) + 1):
        output = _redact_terminal_bytes(
            prefix + encoded_secret[:byte_count],
            credentials,
            incomplete=True,
        )
        assert output == "ZAI_API_KEY="
        assert "\ufffd" not in output

    assert _redact_terminal_bytes(
        payload,
        credentials,
        incomplete=True,
    ) == (
        "ZAI_API_KEY=<redacted:ZAI_API_KEY>\n"
        "ordinary=KEY-label\n"
    )

    partial_secret = "密钥"
    assert _redact_terminal_bytes(
        prefix + partial_secret.encode(),
        credentials,
        incomplete=True,
    ) == "ZAI_API_KEY="
    assert _redact_terminal_bytes(
        prefix + partial_secret.encode(),
        credentials,
        incomplete=False,
    ) == f"ZAI_API_KEY={partial_secret}"


@pytest.mark.asyncio
async def test_progress_redaction_spans_chunks_callbacks_and_message_ids() -> None:
    secret = "PROGRESS_SECRET_密钥_8fd1"

    validator_regression: list[str] = []
    buffered_tracker = ACPProgressTracker(
        callback=validator_regression.append,
        redactor=lambda text: redact_credential_values(
            text,
            {"ZAI_API_KEY": secret},
        ),
    )
    await buffered_tracker.handle_session_update(
        {
            "update": {
                "sessionUpdate": "agent_message_chunk",
                "messageId": "same",
                "content": [{"type": "text", "text": secret[:12]}],
            }
        }
    )
    await buffered_tracker.handle_session_update(
        {
            "update": {
                "sessionUpdate": "agent_message_chunk",
                "messageId": "same",
                "content": [
                    {
                        "type": "text",
                        "text": secret[12:] + " ordinary=kept\n",
                    }
                ],
            }
        }
    )
    assert validator_regression == [
        "Agent: <redacted:ZAI_API_KEY> ordinary=kept"
    ]

    streamed_progress: list[str] = []
    credentials = {
        "OPENAI_API_KEY": secret + "-overlap",
        "ZAI_API_KEY": secret,
    }
    tracker = ACPProgressTracker(
        callback=streamed_progress.append,
        redactor=lambda text: redact_credential_values(text, credentials),
        stream_redactor=StreamingCredentialRedactor(credentials),
    )
    ordinary_prefix = "ordinary progress " * 12
    overlapping_secret = secret + "-overlap"
    await tracker.handle_session_update(
        {
            "update": {
                "sessionUpdate": "agent_message_chunk",
                "messageId": "first",
                "content": [
                    {
                        "type": "text",
                        "text": ordinary_prefix + "value=" + overlapping_secret[:9],
                    }
                ],
            }
        }
    )
    await tracker.handle_session_update(
        {
            "update": {
                "sessionUpdate": "agent_message_chunk",
                "messageId": "second",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            overlapping_secret[9:]
                            + "\nZAI_API_KEY="
                            + secret
                            + "\n"
                        ),
                    }
                ],
            }
        }
    )
    await tracker.flush()

    serialized = json.dumps(
        {
            "callbacks": streamed_progress,
            "diagnostic": tracker.diagnostic_buffer,
        }
    )
    assert secret not in serialized
    assert "ordinary progress" in serialized
    assert "<redacted:OPENAI_API_KEY>" in serialized
    assert "ZAI_API_KEY=<redacted:ZAI_API_KEY>" in serialized


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        (
            {CAPABILITY_PROFILE_ENV: UNSAFE_DEVELOPMENT_PROFILE},
            UNSAFE_DEVELOPMENT_ENV,
        ),
        (
            {
                CAPABILITY_PROFILE_ENV: UNSAFE_DEVELOPMENT_PROFILE,
                UNSAFE_DEVELOPMENT_ENV: "true",
            },
            "exactly '1'",
        ),
        (
            {"UNREST_UNSAFE_DEVELOPEMENT_UNRESTRICTED": "1"},
            "unknown unsafe setting",
        ),
        ({CAPABILITY_VERSION_ENV: "future"}, "must be an integer"),
    ],
)
def test_absent_malformed_and_misspelled_unsafe_settings_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment: dict[str, str],
    message: str,
) -> None:
    for key in (
        CAPABILITY_PROFILE_ENV,
        CAPABILITY_VERSION_ENV,
        UNSAFE_DEVELOPMENT_ENV,
        "UNREST_UNSAFE_DEVELOPEMENT_UNRESTRICTED",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "home"))
    with pytest.raises(CapabilityPolicyError, match=message):
        HarnessConfig.discover()


@pytest.mark.asyncio
async def test_permission_policy_selects_only_declared_allow_once(
    tmp_path: Path,
) -> None:
    worker = _client(tmp_path, role="worker")
    options = [
        {"optionId": "always", "name": "Always", "kind": "allow_always"},
        {"optionId": "once", "name": "Once", "kind": "allow_once"},
        {"optionId": "reject", "name": "Reject", "kind": "reject_once"},
    ]
    allowed = await worker._dispatch(
        "session/request_permission",
        {"toolCall": {"toolCallId": "1", "kind": "edit"}, "options": options},
    )
    assert allowed == {
        "outcome": {"optionId": "once", "outcome": "selected"}
    }


@pytest.mark.asyncio
async def test_permission_policy_denies_forbidden_and_unsupported_options(
    tmp_path: Path,
) -> None:
    validator = _client(tmp_path, role="validator")
    forbidden = await validator._dispatch(
        "session/request_permission",
        {
            "toolCall": {"toolCallId": "1", "kind": "edit"},
            "options": [
                {"optionId": "allow", "name": "Allow", "kind": "allow_once"},
                {"optionId": "reject", "name": "Reject", "kind": "reject_once"},
            ],
        },
    )
    assert forbidden == {
        "outcome": {"optionId": "reject", "outcome": "selected"}
    }
    unsupported = await validator._dispatch(
        "session/request_permission",
        {
            "toolCall": {"toolCallId": "2", "kind": "read"},
            "options": [
                {"optionId": "always", "name": "Always", "kind": "allow_always"}
            ],
        },
    )
    assert unsupported == {"outcome": {"outcome": "cancelled"}}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("role", "kind", "options", "expected"),
    [
        (
            "worker",
            "read",
            [
                {
                    "optionId": "duplicate",
                    "name": "Always",
                    "kind": "allow_always",
                },
                {
                    "optionId": "duplicate",
                    "name": "Once",
                    "kind": "allow_once",
                },
                {
                    "optionId": "reject",
                    "name": "Reject",
                    "kind": "reject_once",
                },
            ],
            {"outcome": {"outcome": "cancelled"}},
        ),
        (
            "validator",
            "edit",
            [
                {
                    "optionId": "duplicate",
                    "name": "Once",
                    "kind": "allow_once",
                },
                {
                    "optionId": "duplicate",
                    "name": "Reject",
                    "kind": "reject_once",
                },
            ],
            {"outcome": {"outcome": "cancelled"}},
        ),
        (
            "worker",
            "read",
            [{"optionId": "", "kind": "allow_once"}],
            {"outcome": {"outcome": "cancelled"}},
        ),
        (
            "worker",
            "read",
            ["not-an-option"],
            {"outcome": {"outcome": "cancelled"}},
        ),
        (
            "worker",
            "read",
            [{"optionId": "once", "kind": "allow_once"}],
            {"outcome": {"outcome": "cancelled"}},
        ),
        (
            "worker",
            "read",
            [{"optionId": "once", "name": "Once", "kind": "unknown"}],
            {"outcome": {"outcome": "cancelled"}},
        ),
        (
            "worker",
            "read",
            [
                {"optionId": "one", "name": "One", "kind": "allow_once"},
                {"optionId": "two", "name": "Two", "kind": "allow_once"},
            ],
            {"outcome": {"outcome": "cancelled"}},
        ),
        (
            "worker",
            "read",
            [
                {
                    "optionId": "always",
                    "name": "Always",
                    "kind": "allow_always",
                },
                {"optionId": "once", "name": "Once", "kind": "allow_once"},
                {
                    "optionId": "reject",
                    "name": "Reject",
                    "kind": "reject_once",
                },
            ],
            {"outcome": {"optionId": "once", "outcome": "selected"}},
        ),
        (
            "validator",
            "edit",
            [
                {"optionId": "once", "name": "Once", "kind": "allow_once"},
                {
                    "optionId": "reject",
                    "name": "Reject",
                    "kind": "reject_once",
                },
            ],
            {"outcome": {"optionId": "reject", "outcome": "selected"}},
        ),
    ],
)
async def test_permission_options_fail_closed_when_malformed_or_ambiguous(
    tmp_path: Path,
    role: str,
    kind: str,
    options: list[Any],
    expected: dict[str, Any],
) -> None:
    client = _client(tmp_path, role=role)
    result = await client._dispatch(
        "session/request_permission",
        {
            "toolCall": {"toolCallId": "regression", "kind": kind},
            "options": options,
        },
    )
    assert result == expected


def test_filesystem_callbacks_enforce_absolute_traversal_symlink_and_read_only(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "inside.txt").write_text("inside")
    (outside / "secret.txt").write_text("outside")
    (workspace / "escape").symlink_to(outside, target_is_directory=True)

    worker = _client(tmp_path, role="worker")
    assert worker._handle_fs_read({"path": "inside.txt"}) == {"content": "inside"}
    with pytest.raises(CapabilityAccessError):
        worker._handle_fs_read({"path": str(outside / "secret.txt")})
    with pytest.raises(CapabilityAccessError):
        worker._handle_fs_read({"path": "../outside/secret.txt"})
    with pytest.raises(CapabilityAccessError):
        worker._handle_fs_read({"path": "escape/secret.txt"})
    with pytest.raises(CapabilityAccessError):
        worker._handle_fs_write({"path": "escape/new/child.txt", "content": "bad"})
    assert not (outside / "new" / "child.txt").exists()

    reviewer = _client(tmp_path, role="terminal_reviewer")
    with pytest.raises(CapabilityAccessError):
        reviewer._handle_fs_write({"path": "reviewer.txt", "content": "bad"})
    assert not (workspace / "reviewer.txt").exists()


def test_filesystem_callback_allows_canonical_in_root_nonexistent_parent(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path)
    client._handle_fs_write(
        {"path": "new/parent/result.txt", "content": "permitted"}
    )
    assert (tmp_path / "workspace" / "new" / "parent" / "result.txt").read_text() == (
        "permitted"
    )


@pytest.mark.asyncio
async def test_terminal_callbacks_enforce_process_cwd_and_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    worker = _client(tmp_path, role="worker")

    with pytest.raises(CapabilityAccessError, match="terminal:environment"):
        await worker._handle_terminal_create(
            {
                "command": sys.executable,
                "args": ["-c", "print('not-started')"],
                "env": [{"name": "DATABASE_URL", "value": "forbidden"}],
            }
        )
    with pytest.raises(CapabilityAccessError, match="filesystem:cwd"):
        await worker._handle_terminal_create(
            {
                "command": sys.executable,
                "args": ["-c", "print('not-started')"],
                "cwd": str(outside),
            }
        )

    created = await worker._handle_terminal_create(
        {
            "command": sys.executable,
            "args": [
                "-c",
                "import os; print(os.getcwd()); print(os.environ.get('LANG'))",
            ],
            "cwd": str(tmp_path / "workspace"),
            "env": [{"name": "LANG", "value": "C"}],
        }
    )
    terminal_id = created["terminalId"]
    result = await worker._handle_terminal_wait({"terminalId": terminal_id})
    output = worker._handle_terminal_output({"terminalId": terminal_id})
    assert result["exitCode"] == 0
    assert str((tmp_path / "workspace").resolve()) in output["output"]
    assert output["output"].rstrip().endswith("C")
    await worker.cleanup(close_main_process=False)

    orchestrator = _client(tmp_path, role="orchestrator")
    started = False

    async def forbidden_start(*args, **kwargs):
        nonlocal started
        started = True
        raise AssertionError("disabled process callback must not spawn")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden_start)
    with pytest.raises(CapabilityAccessError, match="process access is disabled"):
        await orchestrator._handle_terminal_create(
            {"command": sys.executable, "args": ["-c", "print('bad')"]}
        )
    assert started is False


@pytest.mark.asyncio
async def test_terminal_child_drops_permitted_name_with_credential_alias_value(
    tmp_path: Path,
) -> None:
    policy = _resolved(tmp_path)
    secret = "κλειδί-KEY"
    terminal_environment = build_role_environment(
        policy,
        {
            "ANTHROPIC_API_KEY": secret,
            "LANG": "C",
            "PATH": os.environ["PATH"],
            "ZAI_API_KEY": secret,
        },
    )
    client = ACPClient(
        cast(Any, object()),
        str(tmp_path / "workspace"),
        policy=policy,
        terminal_environment=terminal_environment,
    )
    created = await client._handle_terminal_create(
        {
            "command": sys.executable,
            "args": [
                "-c",
                (
                    "import json, os; "
                    "value = os.environ['ZAI_API_KEY']; "
                    "print(json.dumps(sorted("
                    "name for name, item in os.environ.items() if item == value)))"
                ),
            ],
            "cwd": str(tmp_path / "workspace"),
            "env": [{"name": "LANG", "value": secret}],
        }
    )
    terminal_id = created["terminalId"]
    await client._handle_terminal_wait({"terminalId": terminal_id})
    result = client._handle_terminal_output({"terminalId": terminal_id})
    await client.cleanup(close_main_process=False)

    assert json.loads(result["output"]) == [
        "ANTHROPIC_API_KEY",
        "ZAI_API_KEY",
    ]
    assert secret not in result["output"]


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ("nodes", "text"))
async def test_terminal_callback_redacts_alias_from_bounded_sensitive_source(
    tmp_path: Path,
    boundary: str,
) -> None:
    secret = f"{boundary}-callback-secret-0123456789abcdef"
    deep_alias = _padding_free_base64(secret, layers=26)
    source = (
        _node_ceiling_source(secret, key="credential")
        if boundary == "nodes"
        else _text_ceiling_source(secret, key="credential")
    )
    source_name = f"CREDENTIAL_CACHE_METADATA_CALLBACK_{boundary.upper()}"
    host = {
        "LANG": "C.UTF-8",
        "PATH": f"/usr/bin:{deep_alias}:/bin",
        source_name: source,
    }
    policy = _resolved(tmp_path)
    terminal_environment = build_role_environment(
        policy,
        host,
        include_credentials=True,
    )
    inventory = credential_source_values(host)
    client = ACPClient(
        cast(Any, object()),
        str(tmp_path / "workspace"),
        policy=policy,
        terminal_environment=terminal_environment,
    )
    client.set_credential_inventory(inventory)

    assert terminal_environment == {"LANG": "C.UTF-8"}
    created = await client._handle_terminal_create(
        {
            "command": sys.executable,
            "args": [
                "-c",
                "import sys; print('prefix:' + sys.argv[1] + ':suffix')",
                deep_alias,
            ],
            "cwd": str(tmp_path / "workspace"),
        }
    )
    terminal_id = created["terminalId"]
    result = await client._handle_terminal_wait({"terminalId": terminal_id})
    output = client._handle_terminal_output({"terminalId": terminal_id})
    await client.cleanup(close_main_process=False)

    assert result["exitCode"] == 0
    assert deep_alias not in output["output"]
    assert source_name in output["output"]
    redacted = json.dumps(
        _redact_json_value(
            {
                deep_alias: {
                    "error": f"prefix:{deep_alias}:suffix",
                    "result": [deep_alias],
                }
            },
            inventory,
        ),
        sort_keys=True,
    )
    assert deep_alias not in redacted


@pytest.mark.asyncio
@pytest.mark.parametrize("seed", range(8))
async def test_callback_terminal_uses_ambient_common_credential_inventory(
    tmp_path: Path,
    seed: int,
) -> None:
    generator = random.Random(seed)
    source_name = generator.choice(_COMMON_CREDENTIAL_SOURCE_NAMES)
    secret = (
        'VCAP_"callback"\\κλειδί_'
        + "".join(
            generator.choice(string.ascii_letters + string.digits)
            for _ in range(24)
        )
    )
    host = {
        "LANG": "C",
        "PATH": f"/usr/bin:prefix{secret}suffix:/bin",
        source_name: secret,
    }
    policy = _resolved(tmp_path)
    terminal_environment = build_role_environment(
        policy,
        host,
        include_credentials=True,
    )
    client = ACPClient(
        cast(Any, object()),
        str(tmp_path / "workspace"),
        policy=policy,
        terminal_environment=terminal_environment,
    )
    client.set_credential_inventory(credential_source_values(host))

    created = await client._handle_terminal_create(
        {
            "command": sys.executable,
            "args": [
                "-c",
                (
                    "import json, os; "
                    "print(json.dumps(dict(sorted(os.environ.items()))))"
                ),
            ],
            "cwd": str(tmp_path / "workspace"),
            "env": [
                {
                    "name": "LANG",
                    "value": json.dumps(
                        {"nested": [{"credential": secret}]},
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ),
                }
            ],
        }
    )
    terminal_id = created["terminalId"]
    await client._handle_terminal_wait({"terminalId": terminal_id})
    result = client._handle_terminal_output({"terminalId": terminal_id})
    await client.cleanup(close_main_process=False)

    child_environment = json.loads(result["output"])
    assert "LANG" not in child_environment
    assert "PATH" not in child_environment
    assert source_name not in child_environment
    assert secret not in result["output"]


@pytest.mark.asyncio
@pytest.mark.parametrize("source_kind", ("sas", "format-ast"))
async def test_raw_acp_redacts_reversibly_derived_semantic_field_credentials(
    tmp_path: Path,
    source_kind: str,
) -> None:
    secret = "RAW_ACP_SAS_DERIVED_CREDENTIAL_0123456789abcdef"
    if source_kind == "sas":
        encoded = _padding_free_base64(secret, layers=2)
        source_name = "PAYMENTS_EDGE_DSN_TEMPLATE_URI_RAW_ACP"
        source_value = (
            "custom:/v20;shared_access_signature="
            f"{encoded}?password={{password!r:>12}}"
        )
    else:
        source_name = "PAYMENTS_FORMAT_DSN_TEMPLATE_URI_RAW_ACP_V22"
        source_value = (
            "custom:/v22"
            f";render={{value:password={secret}}}"
            f"?layout={{mapping[password={secret}]!s:^12}}"
            f"#meta={{value:token={secret};width={{width}}}}"
        )
    host = {
        "LANG": "C",
        "PATH": f"{os.defpath}:{secret}",
        source_name: source_value,
    }
    resolved = _resolved(tmp_path)
    inventory = credential_source_values(host)
    terminal_environment = build_role_environment(
        resolved,
        host,
        include_credentials=True,
    )
    workspace = tmp_path / "workspace"
    credential_file = workspace / "semantic-derived-output.txt"
    credential_file.write_text(
        f"derived={secret}; plain=kept\n",
        encoding="utf-8",
    )
    requests = [
        {
            "method": "fs/read_text_file",
            "params": {"path": str(credential_file)},
        },
        {
            "method": "terminal/create",
            "params": {
                "command": sys.executable,
                "args": [
                    "-c",
                    "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())",
                    str(credential_file),
                ],
                "cwd": str(workspace),
            },
        },
        {
            "method": "terminal/wait_for_exit",
            "params": {"terminalId": "$terminalId"},
        },
        {
            "method": "terminal/output",
            "params": {"terminalId": "$terminalId"},
        },
    ]
    requests_path = tmp_path / "semantic-requests.json"
    trace_path = tmp_path / "semantic-trace.json"
    requests_path.write_text(json.dumps(requests), encoding="utf-8")
    emitter = _ROOT / "tests" / "fixtures" / "acp_terminal_emitter.py"
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(emitter),
        str(requests_path),
        str(trace_path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(tmp_path),
        env={"LANG": "C", "PATH": os.environ["PATH"]},
    )
    client = ACPClient(
        process,
        str(workspace),
        policy=resolved,
        terminal_environment=terminal_environment,
    )
    client.set_credential_inventory(inventory)
    await client.start()
    await asyncio.wait_for(process.wait(), timeout=20)
    assert process.stderr is not None
    stderr = (await process.stderr.read()).decode("utf-8", errors="replace")
    await client.cleanup(close_main_process=False)

    assert secret in sensitive_values(inventory)
    assert terminal_environment == {"LANG": "C"}
    assert process.returncode == 0, stderr
    raw_trace = trace_path.read_text(encoding="utf-8")
    assert secret not in raw_trace
    trace = json.loads(raw_trace)
    assert trace[0]["response"]["result"]["content"] == (
        f"derived=<redacted:{source_name}>; plain=kept\n"
    )
    assert f"<redacted:{source_name}>" in (
        trace[3]["response"]["result"]["output"]
    )


@pytest.mark.asyncio
async def test_raw_acp_preserves_complete_python_format_templates(
    tmp_path: Path,
) -> None:
    env_command = Path("/usr/bin/env")
    if not env_command.is_file():
        pytest.skip("/usr/bin/env is required for the raw template probe")

    template = _brace_index_format_uri("custom:/v22")
    source_name = "PAYMENTS_RAW_ACP_DSN_TEMPLATE_URI_V22"
    host = {
        "LANG": "C",
        "PATH": f"{template}:relative-tools:local-bin",
        source_name: template,
    }
    resolved = _resolved(tmp_path)
    inventory = credential_source_values(host)
    terminal_environment = build_role_environment(
        resolved,
        host,
        include_credentials=True,
    )
    workspace = tmp_path / "workspace"
    template_file = workspace / "format-template-output.txt"
    template_file.write_text(
        f"template={template}; plain=kept\n",
        encoding="utf-8",
    )
    requests = [
        {
            "method": "fs/read_text_file",
            "params": {"path": str(template_file)},
        },
        {
            "method": "terminal/create",
            "params": {
                "command": str(env_command),
                "args": ["-0"],
                "cwd": str(workspace),
            },
        },
        {
            "method": "terminal/wait_for_exit",
            "params": {"terminalId": "$terminalId"},
        },
        {
            "method": "terminal/output",
            "params": {"terminalId": "$terminalId"},
        },
    ]
    requests_path = tmp_path / "format-template-requests.json"
    trace_path = tmp_path / "format-template-trace.json"
    requests_path.write_text(json.dumps(requests), encoding="utf-8")
    emitter = _ROOT / "tests" / "fixtures" / "acp_terminal_emitter.py"
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(emitter),
        str(requests_path),
        str(trace_path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(tmp_path),
        env={"LANG": "C", "PATH": os.environ["PATH"]},
    )
    client = ACPClient(
        process,
        str(workspace),
        policy=resolved,
        terminal_environment=terminal_environment,
    )
    client.set_credential_inventory(inventory)
    await client.start()
    await asyncio.wait_for(process.wait(), timeout=20)
    assert process.stderr is not None
    stderr = (await process.stderr.read()).decode("utf-8", errors="replace")
    await client.cleanup(close_main_process=False)

    assert inventory == {}
    assert terminal_environment["PATH"] == host["PATH"]
    assert process.returncode == 0, stderr
    raw_trace = trace_path.read_text(encoding="utf-8")
    assert template in raw_trace
    assert "<redacted:" not in raw_trace
    trace = json.loads(raw_trace)
    assert trace[0]["response"]["result"]["content"] == (
        f"template={template}; plain=kept\n"
    )
    output = trace[3]["response"]["result"]["output"]
    assert f"PATH={host['PATH']}" in output.split("\0")


@pytest.mark.asyncio
async def test_raw_acp_terminal_protocol_redacts_credential_values(
    tmp_path: Path,
) -> None:
    env_command = Path("/usr/bin/env")
    if not env_command.is_file():
        pytest.skip("/usr/bin/env is required for the raw terminal environment probe")

    resolved = _resolved(tmp_path)
    first_secret = "RAW_ACP_FIRST_CREDENTIAL_79d0b1"
    second_secret = "RAW_ACP_SECOND_CREDENTIAL_f821a4"
    terminal_environment = build_role_environment(
        resolved,
        {
            "ANTHROPIC_API_KEY": "",
            "LANG": "C",
            "OPENAI_API_KEY": second_secret,
            "PATH": os.environ["PATH"],
            "ZAI_API_KEY": first_secret,
        },
    )
    workspace = tmp_path / "workspace"
    credential_file = workspace / "credential-output.txt"
    credential_file.write_text(
        f"file={first_secret}; plain=file-kept\n",
        encoding="utf-8",
    )
    direct_output = (
        "import os,sys,time;"
        "first=os.environ['ZAI_API_KEY'];"
        "second=os.environ['OPENAI_API_KEY'];"
        "sys.stdout.write('plain=kept\\nZAI_API_KEY='+first[:11]);"
        "sys.stdout.flush();"
        "time.sleep(2);"
        "sys.stdout.write(first[11:]+'\\nOPENAI_API_KEY='+second+"
        "'\\nANTHROPIC_API_KEY='+os.environ.get('ANTHROPIC_API_KEY','unset')+"
        "'\\nplain=end\\n');"
        "sys.stdout.flush()"
    )
    requests = [
        {
            "method": "terminal/create",
            "params": {
                "command": str(env_command),
                "args": [],
                "cwd": str(workspace),
            },
        },
        {
            "method": "terminal/wait_for_exit",
            "params": {"terminalId": "$terminalId"},
        },
        {
            "method": "terminal/output",
            "params": {"terminalId": "$terminalId"},
        },
        {
            "method": "fs/read_text_file",
            "params": {"path": str(credential_file)},
        },
        {
            "method": "terminal/create",
            "params": {
                "command": sys.executable,
                "args": ["-c", direct_output],
                "cwd": str(workspace),
            },
        },
        {
            "_delay_seconds": 1,
            "method": "terminal/output",
            "params": {"terminalId": "$terminalId"},
        },
        {
            "method": "terminal/wait_for_exit",
            "params": {"terminalId": "$terminalId"},
        },
        {
            "method": "terminal/output",
            "params": {"terminalId": "$terminalId"},
        },
    ]
    requests_path = tmp_path / "requests.json"
    trace_path = tmp_path / "trace.json"
    requests_path.write_text(json.dumps(requests), encoding="utf-8")
    emitter = _ROOT / "tests" / "fixtures" / "acp_terminal_emitter.py"
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(emitter),
        str(requests_path),
        str(trace_path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(tmp_path),
        env={"LANG": "C", "PATH": os.environ["PATH"]},
    )
    client = ACPClient(
        process,
        str(workspace),
        policy=resolved,
        terminal_environment=terminal_environment,
    )
    await client.start()
    await asyncio.wait_for(process.wait(), timeout=20)
    assert process.stderr is not None
    stderr = (await process.stderr.read()).decode("utf-8", errors="replace")
    await client.cleanup(close_main_process=False)

    assert process.returncode == 0, stderr
    raw_trace = trace_path.read_text(encoding="utf-8")
    assert first_secret not in raw_trace
    assert second_secret not in raw_trace
    trace = json.loads(raw_trace)

    environment_output = trace[2]["response"]["result"]["output"]
    assert "ZAI_API_KEY=<redacted:ZAI_API_KEY>" in environment_output
    assert "OPENAI_API_KEY=<redacted:OPENAI_API_KEY>" in environment_output
    assert "ANTHROPIC_API_KEY=" in environment_output
    assert "<redacted:ANTHROPIC_API_KEY>" not in environment_output

    file_output = trace[3]["response"]["result"]["content"]
    assert file_output == "file=<redacted:ZAI_API_KEY>; plain=file-kept\n"

    partial_output = trace[5]["response"]["result"]["output"]
    assert partial_output == "plain=kept\nZAI_API_KEY="
    final_output = trace[7]["response"]["result"]["output"]
    assert "plain=kept" in final_output
    assert "ZAI_API_KEY=<redacted:ZAI_API_KEY>" in final_output
    assert "OPENAI_API_KEY=<redacted:OPENAI_API_KEY>" in final_output
    assert "ANTHROPIC_API_KEY=" in final_output
    assert final_output.endswith("plain=end\n")


@pytest.mark.asyncio
async def test_acp_return_metadata_and_errors_redact_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved = _resolved(tmp_path)
    secret = "RAW_ACP_ERROR_CREDENTIAL_e26d8c"
    client = ACPClient(
        cast(Any, object()),
        str(tmp_path / "workspace"),
        policy=resolved,
        terminal_environment=build_role_environment(
            resolved,
            {"PATH": os.environ["PATH"], "ZAI_API_KEY": secret},
        ),
    )

    written: list[dict[str, Any]] = []

    async def failing_dispatch(method: str, params: dict[str, Any]) -> Any:
        raise RuntimeError(f"callback failed with {secret}")

    async def capture_write(message: dict[str, Any]) -> None:
        written.append(message)

    monkeypatch.setattr(client, "_dispatch", failing_dispatch)
    monkeypatch.setattr(client, "_write", capture_write)
    await client._handle_request(
        {"id": 1, "method": "test/failure", "params": {}}
    )
    encoded_error = json.dumps(written)
    assert secret not in encoded_error
    assert "<redacted:ZAI_API_KEY>" in encoded_error

    result_future = asyncio.get_running_loop().create_future()
    client._pending[2] = result_future
    client._handle_response(
        {
            "id": 2,
            "result": {
                "keyName": "ZAI_API_KEY",
                "metadata": {
                    secret: f"result contained {secret}",
                    "<redacted:ZAI_API_KEY>": "innocent placeholder entry",
                    "nested": [{secret: "secret key"}],
                },
            },
        }
    )
    assert await result_future == {
        "keyName": "ZAI_API_KEY",
        "metadata": {
            "<redacted:ZAI_API_KEY>": "innocent placeholder entry",
            "<redacted:ZAI_API_KEY>#1": (
                "result contained <redacted:ZAI_API_KEY>"
            ),
            "nested": [{"<redacted:ZAI_API_KEY>": "secret key"}],
        },
    }

    error_future = asyncio.get_running_loop().create_future()
    client._pending[3] = error_future
    client._handle_response(
        {"id": 3, "error": {"message": f"remote failed with {secret}"}}
    )
    with pytest.raises(ACPError, match="<redacted:ZAI_API_KEY>"):
        await error_future


@pytest.mark.asyncio
async def test_real_terminal_short_credential_preserves_environment_labels(
    tmp_path: Path,
) -> None:
    env_command = Path("/usr/bin/env")
    if not env_command.is_file():
        pytest.skip("/usr/bin/env is required for the environment-label probe")

    resolved = _resolved(tmp_path)
    terminal_environment = build_role_environment(
        resolved,
        {
            "ANTHROPIC_API_KEY": "",
            "LANG": "C",
            "OPENAI_API_KEY": "long-secret-value",
            "PATH": os.environ["PATH"],
            "ZAI_API_KEY": "KEY",
        },
    )
    client = ACPClient(
        cast(Any, object()),
        str(tmp_path / "workspace"),
        policy=resolved,
        terminal_environment=terminal_environment,
    )
    created = await client._handle_terminal_create(
        {
            "command": str(env_command),
            "args": [],
            "cwd": str(tmp_path / "workspace"),
        }
    )
    terminal_id = created["terminalId"]
    await client._handle_terminal_wait({"terminalId": terminal_id})
    result = client._handle_terminal_output({"terminalId": terminal_id})
    await client.cleanup(close_main_process=False)

    output = result["output"]
    assert "ZAI_API_KEY=<redacted:ZAI_API_KEY>" in output
    assert "OPENAI_API_KEY=<redacted:OPENAI_API_KEY>" in output
    assert "ANTHROPIC_API_KEY=" in output
    assert "ZAI_API_<redacted:ZAI_API_KEY>" not in output
    assert "OPENAI_API_<redacted:ZAI_API_KEY>" not in output


def test_cli_safe_init_round_trips_policy_and_never_persists_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    home = tmp_path / "home"
    sentinel = "credential-value-must-not-persist"
    monkeypatch.setenv("UNREST_HOME", str(home))
    monkeypatch.setenv("ZAI_API_KEY", sentinel)
    monkeypatch.setenv("DATABASE_URL", sentinel)
    monkeypatch.setenv("ANTHROPIC_MODEL", sentinel)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://example.invalid/api")

    result = CliRunner().invoke(
        cli,
        ["init", "--workspace-dir", str(workspace), "--agent", "claude"],
    )
    assert result.exit_code == 0, result.output
    settings = json.loads((workspace / ".claude" / "settings.json").read_text())
    assert settings["permissions"]["defaultMode"] == "default"
    mcp = json.loads((workspace / ".mcp.json").read_text())
    generated_env = mcp["mcpServers"]["unrest"]["env"]
    assert generated_env[CAPABILITY_PROFILE_ENV] == SAFE_PROFILE
    assert generated_env[CAPABILITY_VERSION_ENV] == "1"
    assert "ZAI_API_KEY" not in generated_env
    assert "ANTHROPIC_MODEL" not in generated_env
    assert generated_env["ANTHROPIC_BASE_URL"] == "https://example.invalid/api"
    for path in workspace.rglob("*"):
        if path.is_file():
            assert sentinel not in path.read_text(encoding="utf-8", errors="ignore")

    with monkeypatch.context() as isolated:
        for key in tuple(os.environ):
            isolated.delenv(key, raising=False)
        for key, value in generated_env.items():
            isolated.setenv(key, value)
        runtime = HarnessConfig.discover()
        assert runtime.capability_profile == SAFE_PROFILE
        assert runtime.capability_policy_version == 1


def test_cli_round_trips_distinct_role_providers_and_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "home"))
    result = CliRunner().invoke(
        cli,
        [
            "init",
            "--workspace-dir",
            str(workspace),
            "--orchestrator-provider",
            "claude",
            "--worker-provider",
            "codex",
            "--worker-acp-command",
            "codex-worker",
            "--validator-provider",
            "claude",
            "--validator-acp-command",
            "claude-validator",
            "--terminal-reviewer-provider",
            "codex",
            "--terminal-reviewer-acp-command",
            "codex-terminal-reviewer",
        ],
    )
    assert result.exit_code == 0, result.output
    generated_env = json.loads((workspace / ".mcp.json").read_text())[
        "mcpServers"
    ]["unrest"]["env"]
    with monkeypatch.context() as isolated:
        for key in tuple(os.environ):
            isolated.delenv(key, raising=False)
        for key, value in generated_env.items():
            isolated.setenv(key, value)
        runtime = HarnessConfig.discover()
        assert runtime.orchestrator_provider_name == "claude"
        assert runtime.worker_provider_name == "codex"
        assert runtime.resolved_worker_acp_command == "codex-worker"
        assert runtime.validator_provider_name == "claude"
        assert runtime.resolved_validator_acp_command == "claude-validator"
        assert runtime.terminal_reviewer_provider_name == "codex"
        assert (
            runtime.resolved_terminal_reviewer_acp_command
            == "codex-terminal-reviewer"
        )
        runtime.validate_capability_support()


def test_generated_failure_handoff_redacts_credential_sentinels(
    tmp_path: Path,
) -> None:
    config = HarnessConfig(
        bundled_dir=_BUNDLED,
        harness_home=tmp_path / "home",
        projects_dir=tmp_path / "home" / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command="claude-agent-acp",
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
    )
    runner = ACPNodeRunner(config, AssetLoader(config))
    handoff_path = tmp_path / "handoff.json"
    sentinel = "credential-value-must-not-leak"
    task = Task(id="w1", type="work", body="b", targets=[], skill="s")
    handoff = runner._synthesize_and_persist_missing_handoff(
        handoff_path=handoff_path,
        task=task,
        stop_reason=f"agent repeated {sentinel}",
        exit_code=1,
        stderr=f"stderr={sentinel}",
        session_error=f"protocol exposed {sentinel}",
        agent_output=f"agent echoed {sentinel}",
        credentials={"ZAI_API_KEY": sentinel},
    )
    assert sentinel not in handoff.report
    assert sentinel not in handoff_path.read_text(encoding="utf-8")
    assert "<redacted:ZAI_API_KEY>" in handoff.report

    successful_path = tmp_path / "successful-handoff.json"
    successful_path.write_text(
        json.dumps(
            {
                "node_id": "w1",
                "done": True,
                "report": f"agent submitted {sentinel}",
                "request_attention": False,
            }
        )
    )
    successful = runner._parse_handoff_file(
        successful_path,
        task,
        credentials={"ZAI_API_KEY": sentinel},
    )
    assert sentinel not in successful.report
    assert sentinel not in successful_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_cli_unsafe_development_opt_in_is_conspicuous_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent: str,
) -> None:
    workspace = tmp_path / agent
    workspace.mkdir()
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "home"))
    args = [
        "init",
        "--workspace-dir",
        str(workspace),
        "--agent",
        agent,
        "--unsafe-development-unrestricted",
    ]
    first = CliRunner().invoke(cli, args)
    assert first.exit_code == 0, first.output
    if agent == "claude":
        text = (workspace / ".mcp.json").read_text()
        settings = json.loads((workspace / ".claude" / "settings.json").read_text())
        assert settings["permissions"]["defaultMode"] == "bypassPermissions"
    else:
        text = (workspace / ".codex" / "config.toml").read_text()
        parsed = tomllib.loads(text)
        assert parsed["sandbox_mode"] == "danger-full-access"
        assert parsed["approval_policy"] == "never"
    assert UNSAFE_DEVELOPMENT_PROFILE in text
    assert UNSAFE_DEVELOPMENT_ENV in text
    before = text
    second = CliRunner().invoke(cli, args)
    assert second.exit_code == 0, second.output
    path = (
        workspace / ".mcp.json"
        if agent == "claude"
        else workspace / ".codex" / "config.toml"
    )
    assert path.read_text() == before


@pytest.mark.parametrize("agent", ["claude", "codex"])
@pytest.mark.parametrize("unsafe", [False, True], ids=["safe", "unsafe"])
def test_cli_generated_configs_never_persist_randomized_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent: str,
    unsafe: bool,
) -> None:
    generator = random.Random(f"{agent}:{unsafe}")
    credential = "VCAP_" + "".join(
        generator.choice(string.ascii_letters + string.digits)
        for _ in range(36)
    )
    longer_credential = f"{credential}-overlap"
    prefixed_credential = f"prefix-{credential}"
    credentials = {
        "ANTHROPIC_API_KEY": prefixed_credential,
        "CODEX_API_KEY": credential,
        "OPENAI_API_KEY": longer_credential,
        "ZAI_API_KEY": credential,
    }
    for key in tuple(os.environ):
        if (
            key.endswith(("_KEY", "_TOKEN", "_SECRET", "_PASSWORD"))
            or "CREDENTIAL" in key
        ):
            monkeypatch.delenv(key, raising=False)
    for key, value in credentials.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PATH", f"/usr/bin:<{credential}>:/bin")
    monkeypatch.setenv("UV_CACHE_DIR", longer_credential)
    monkeypatch.setenv(
        "ZAI_BASE_URL",
        f"https://example.invalid/(<{prefixed_credential}>)/api",
    )
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://ordinary.invalid/api")

    workspace = tmp_path / f"{agent}-{'unsafe' if unsafe else 'safe'}"
    workspace.mkdir()
    args = ["init", "--workspace-dir", str(workspace), "--agent", agent]
    if unsafe:
        args.append("--unsafe-development-unrestricted")

    first = CliRunner().invoke(cli, args)
    assert first.exit_code == 0, first.output
    assert all(value not in first.output for value in set(credentials.values()))
    first_artifacts = {
        path.relative_to(workspace): path.read_bytes()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }

    config_path = (
        workspace / ".mcp.json"
        if agent == "claude"
        else workspace / ".codex" / "config.toml"
    )
    if agent == "claude":
        parsed = json.loads(config_path.read_text(encoding="utf-8"))
        generated_env = parsed["mcpServers"]["unrest"]["env"]
        mode = json.loads(
            (workspace / ".claude" / "settings.json").read_text(encoding="utf-8")
        )["permissions"]["defaultMode"]
        assert mode == ("bypassPermissions" if unsafe else "default")
    else:
        parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
        generated_env = parsed["mcp_servers"]["unrest"]["env"]
        assert parsed["sandbox_mode"] == (
            "danger-full-access" if unsafe else "workspace-write"
        )
        assert parsed["approval_policy"] == ("never" if unsafe else "on-request")

    assert generated_env["ANTHROPIC_BASE_URL"] == "https://ordinary.invalid/api"
    assert generated_env[CAPABILITY_PROFILE_ENV] == (
        UNSAFE_DEVELOPMENT_PROFILE if unsafe else SAFE_PROFILE
    )
    assert set(generated_env).isdisjoint(
        {"PATH", "UV_CACHE_DIR", "ZAI_BASE_URL"}
    )
    if unsafe:
        assert generated_env[UNSAFE_DEVELOPMENT_ENV] == "1"
    else:
        assert UNSAFE_DEVELOPMENT_ENV not in generated_env

    for path, artifact in first_artifacts.items():
        for value in set(credentials.values()):
            assert value.encode() not in artifact, path

    second = CliRunner().invoke(cli, args)
    assert second.exit_code == 0, second.output
    second_artifacts = {
        path.relative_to(workspace): path.read_bytes()
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }
    assert second_artifacts == first_artifacts


@pytest.mark.parametrize("agent", ["claude", "codex"])
@pytest.mark.parametrize("unsafe", [False, True], ids=["safe", "unsafe"])
def test_cli_generated_configs_semantically_filter_common_credential_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent: str,
    unsafe: bool,
) -> None:
    for name in tuple(os.environ):
        if is_credential_source_name(name):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "host-home"))
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "unrest-home"))
    monkeypatch.setenv(
        "ANTHROPIC_BASE_URL",
        "https://ordinary.invalid/api",
    )

    source_names = (
        "CI_CLIENT_SECRET",
        "DATABASE_PASSWD",
        "GH_PAT",
        "PACKAGE_APIKEY",
        "AWS_ACCESS_KEY_ID",
        "REGISTRY_AUTH_CONFIG_V9",
        "APP_DATABASE_URL_V4",
        "OBSERVABILITY_DSN_REGION",
    )
    for index, source_name in enumerate(source_names):
        generator = random.Random(f"{agent}:{unsafe}:{source_name}")
        secret = (
            'VCAP_"quoted"\\κλειδί_'
            + "".join(
                generator.choice(string.ascii_letters + string.digits)
                for _ in range(24)
            )
        )
        nested_json = json.dumps(
            {"outer": [{"credential": secret}]},
            ensure_ascii=True,
            separators=(",", ":"),
        )
        encoding = index % 6
        if encoding == 0:
            model_value = f'payload = {json.dumps(nested_json, ensure_ascii=True)}\n'
        elif encoding == 1:
            model_value = json.dumps(nested_json, ensure_ascii=True)
        elif encoding == 2:
            model_value = nested_json
        elif encoding == 3:
            model_value = urllib.parse.quote(nested_json, safe="")
        elif encoding == 4:
            model_value = base64.urlsafe_b64encode(
                nested_json.encode("utf-8")
            ).decode("ascii")
        else:
            model_value = urllib.parse.quote(
                base64.urlsafe_b64encode(
                    nested_json.encode("utf-8")
                ).decode("ascii"),
                safe="",
            )
        path_value = (
            f"/usr/bin:prefix{secret}suffix:/bin"
            if index == len(source_names) - 1
            else "/usr/bin:/bin"
        )
        monkeypatch.setenv(source_name, secret)
        monkeypatch.setenv("ANTHROPIC_MODEL", model_value)
        monkeypatch.setenv("PATH", path_value)

        workspace = tmp_path / (
            f"{agent}-{'unsafe' if unsafe else 'safe'}-{index}"
        )
        workspace.mkdir()
        args = ["init", "--workspace-dir", str(workspace), "--agent", agent]
        if unsafe:
            args.append("--unsafe-development-unrestricted")

        first = CliRunner().invoke(cli, args)
        assert first.exit_code == 0, first.output
        first_artifacts = {
            path.relative_to(workspace): path.read_bytes()
            for path in sorted(workspace.rglob("*"))
            if path.is_file()
        }
        if agent == "claude":
            parsed = json.loads(
                (workspace / ".mcp.json").read_text(encoding="utf-8")
            )
            generated_environment = parsed["mcpServers"]["unrest"]["env"]
        else:
            parsed = tomllib.loads(
                (workspace / ".codex" / "config.toml").read_text(
                    encoding="utf-8"
                )
            )
            generated_environment = parsed["mcp_servers"]["unrest"]["env"]

        assert generated_environment["ANTHROPIC_BASE_URL"] == (
            "https://ordinary.invalid/api"
        )
        assert "ANTHROPIC_MODEL" not in generated_environment
        if index == len(source_names) - 1:
            assert "PATH" not in generated_environment
        assert source_name not in generated_environment
        assert all(
            secret.encode() not in artifact
            for artifact in first_artifacts.values()
        )
        assert secret not in first.output

        second = CliRunner().invoke(cli, args)
        assert second.exit_code == 0, second.output
        second_artifacts = {
            path.relative_to(workspace): path.read_bytes()
            for path in sorted(workspace.rglob("*"))
            if path.is_file()
        }
        assert second_artifacts == first_artifacts
        assert secret not in second.output
        monkeypatch.delenv(source_name)


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_unsafe_runtime_inheritance_remains_independent_from_persistence(
    tmp_path: Path,
    agent: str,
) -> None:
    credential = f"runtime-credential-{agent}"
    policy = _resolved(
        tmp_path,
        provider_name=agent,
        profile=UNSAFE_DEVELOPMENT_PROFILE,
    )
    host = {
        "PATH": f"/usr/bin:<{credential}>:/bin",
        "RUNTIME_ALIAS": f"Bearer <{credential}>",
        "ZAI_API_KEY": credential,
    }

    runtime = _acp_subprocess_env(
        PROVIDERS[agent],  # type: ignore[index]
        policy=policy,
        host_environment=host,
    )

    assert runtime["PATH"] == host["PATH"]
    assert runtime["RUNTIME_ALIAS"] == host["RUNTIME_ALIAS"]
    assert runtime["ZAI_API_KEY"] == credential


def test_cli_migrates_only_exact_legacy_claude_setting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "home"))
    managed = tmp_path / "managed"
    managed.mkdir()
    claude_dir = managed / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}, indent=2)
        + "\n"
    )
    result = CliRunner().invoke(
        cli,
        ["init", "--workspace-dir", str(managed), "--agent", "claude"],
    )
    assert result.exit_code == 0, result.output
    migrated = json.loads((claude_dir / "settings.json").read_text())
    assert migrated["permissions"]["defaultMode"] == "default"

    unmanaged = tmp_path / "unmanaged"
    unmanaged.mkdir()
    unmanaged_dir = unmanaged / ".claude"
    unmanaged_dir.mkdir()
    unsafe = {
        "permissions": {"defaultMode": "bypassPermissions"},
        "theme": "dark",
    }
    settings_path = unmanaged_dir / "settings.json"
    settings_path.write_text(json.dumps(unsafe, indent=2) + "\n")
    before = settings_path.read_bytes()
    rejected = CliRunner().invoke(
        cli,
        ["init", "--workspace-dir", str(unmanaged), "--agent", "claude"],
    )
    assert rejected.exit_code != 0
    assert "unmanaged ambient permission mode is not safe" in str(rejected.exception)
    assert settings_path.read_bytes() == before


def test_cli_does_not_advertise_unsupported_hermes_orchestrator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "home"))
    result = CliRunner().invoke(
        cli,
        ["init", "--workspace-dir", str(workspace), "--agent", "hermes"],
    )
    assert result.exit_code != 0
    assert "Invalid value for '--agent': 'hermes'" in result.output
    assert "hermes" not in provider_names_for_role("orchestrator")
    assert "orchestrator" not in PROVIDERS["hermes"].capability_roles
    assert PROVIDERS["hermes"].orchestrator_prompt_output_path is None
    assert list(workspace.iterdir()) == []


@pytest.mark.asyncio
async def test_network_denial_fails_before_mcp_or_agent_child_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundled = tmp_path / "bundled"
    shutil.copytree(_BUNDLED, bundled)
    policy_path = bundled / "policies" / "role-capabilities.v1.json"
    raw = json.loads(policy_path.read_text())
    raw["profiles"]["safe"]["worker"]["network"]["mode"] = "deny"
    policy_path.write_text(json.dumps(raw, indent=2) + "\n")
    harness_home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = HarnessConfig(
        bundled_dir=bundled,
        harness_home=harness_home,
        projects_dir=harness_home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command="must-not-start",
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
    )
    store = ProjectStore(config)
    store.create_project("brief", workspace, project_id="p1")
    runner = ACPNodeRunner(config, AssetLoader(config))
    started = False

    async def forbidden_start(**kwargs):
        nonlocal started
        started = True
        raise AssertionError("capability failure must precede child start")

    monkeypatch.setattr(runner, "_start_worker_mcp_server", forbidden_start)
    task = Task(id="w1", type="work", body="b", targets=[], skill="s")
    with pytest.raises(CapabilityPolicyError, match="capability=network:deny"):
        await runner.run_node(
            "p1",
            "mission-001",
            task,
            "2026-07-24T00-00-00Z",
            store,
        )
    assert started is False


def test_profile_environment_is_the_only_serialized_unsafe_switch() -> None:
    assert profile_environment(SAFE_PROFILE) == {
        CAPABILITY_PROFILE_ENV: SAFE_PROFILE,
        CAPABILITY_VERSION_ENV: "1",
    }
    assert profile_environment(UNSAFE_DEVELOPMENT_PROFILE) == {
        CAPABILITY_PROFILE_ENV: UNSAFE_DEVELOPMENT_PROFILE,
        CAPABILITY_VERSION_ENV: "1",
        UNSAFE_DEVELOPMENT_ENV: "1",
    }


def test_cli_help_explains_safe_default_and_explicit_unsafe_opt_in() -> None:
    result = CliRunner().invoke(cli, ["init", "--help"])
    assert result.exit_code == 0
    assert "Safe default" in result.output
    assert "permissions.defaultMode=default" in result.output
    assert "sandbox_mode=workspace-write" in result.output
    assert "approval_policy=on-request" in result.output
    assert "--unsafe-development-unrestricted" in result.output
    assert "DANGEROUS development-only opt-in" in result.output


def test_server_rejects_unsupported_provider_role_before_dispatcher_or_mock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import unrest_harness.acp_runner as acp_runner_module
    import unrest_harness.server as server_module

    config = HarnessConfig(
        bundled_dir=_BUNDLED,
        harness_home=tmp_path / "home",
        projects_dir=tmp_path / "home" / "projects",
        orchestrator_provider_name="hermes",
        worker_provider_name="hermes",
        worker_acp_command="must-not-start",
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
    )
    constructed = False

    def forbidden_dispatcher(*args, **kwargs):
        nonlocal constructed
        constructed = True
        raise AssertionError("dispatcher must not be constructed")

    monkeypatch.setattr(HarnessConfig, "discover", classmethod(lambda cls: config))
    monkeypatch.setattr(acp_runner_module, "ACPNodeDispatcher", forbidden_dispatcher)
    monkeypatch.setattr(sys, "argv", ["unrest-server", "--mode", "orchestrator"])
    with pytest.raises(
        CapabilityPolicyError,
        match="provider=hermes role=orchestrator version=1 capability=role",
    ):
        server_module.create_orchestrator_server(config)
    with pytest.raises(
        CapabilityPolicyError,
        match="provider=hermes role=orchestrator version=1 capability=role",
    ):
        server_module.main()
    assert constructed is False


def test_server_does_not_fall_back_to_mock_when_acp_construction_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import unrest_harness.acp_runner as acp_runner_module
    import unrest_harness.server as server_module

    config = HarnessConfig(
        bundled_dir=_BUNDLED,
        harness_home=tmp_path / "home",
        projects_dir=tmp_path / "home" / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command="claude-agent-acp",
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
    )

    class BrokenDispatcher:
        def __init__(self, config: HarnessConfig) -> None:
            raise RuntimeError("ACP construction failed")

    monkeypatch.setattr(HarnessConfig, "discover", classmethod(lambda cls: config))
    monkeypatch.setattr(acp_runner_module, "ACPNodeDispatcher", BrokenDispatcher)
    monkeypatch.setattr(sys, "argv", ["unrest-server", "--mode", "orchestrator"])
    with pytest.raises(RuntimeError, match="ACP construction failed"):
        server_module.main()
