from __future__ import annotations

import json
import hmac
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from unrest_harness.cli import cli


def _load_dotenv(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            env[key] = value
    return env


@pytest.mark.skipif(
    os.environ.get("UNREST_RUN_ZAI_SMOKE") != "1",
    reason="set UNREST_RUN_ZAI_SMOKE=1 to run the live Z.ai Claude Code smoke test",
)
def test_zai_claude_code_smoke(workspace: Path, harness_home: Path) -> None:
    dotenv = Path(__file__).resolve().parents[1] / ".env"
    secret_env = _load_dotenv(dotenv)
    api_key = secret_env.get("ZAI_API_KEY") or os.environ.get("ZAI_API_KEY")
    if not api_key:
        pytest.skip("ZAI_API_KEY is not available in .env or environment")
    if shutil.which("claude") is None:
        pytest.skip("claude binary is not available")

    model = os.environ.get("UNREST_ZAI_SMOKE_MODEL", "glm-5.2[1m]")
    base_url = (
        secret_env.get("ZAI_BASE_URL")
        or os.environ.get("ZAI_BASE_URL")
        or "https://api.z.ai/api/anthropic"
    )
    env = {
        **os.environ,
        **secret_env,
        "UNREST_HOME": str(harness_home),
        "ANTHROPIC_AUTH_TOKEN": api_key,
        "ANTHROPIC_BASE_URL": base_url,
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
        "CLAUDE_CODE_SUBAGENT_MODEL": model,
        "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "1000000",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS": "1",
    }

    result = CliRunner().invoke(
        cli,
        ["init", "--workspace-dir", str(workspace), "--agent", "claude"],
        env=env,
    )
    assert result.exit_code == 0, result.output

    mcp_env = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))[
        "mcpServers"
    ]["unrest"]["env"]
    assert mcp_env["ANTHROPIC_BASE_URL"] == base_url
    assert mcp_env["ANTHROPIC_MODEL"] == model
    assert hmac.compare_digest(mcp_env.get("ANTHROPIC_AUTH_TOKEN", ""), api_key)
    assert hmac.compare_digest(mcp_env.get("ZAI_API_KEY", ""), api_key)

    run = subprocess.run(
        [
            "claude",
            "--print",
            "--model",
            model,
            "--output-format",
            "text",
            "--permission-mode",
            "bypassPermissions",
            "--disallowed-tools",
            "WebSearch",
            "WebFetch",
            "--",
            "Reply with exactly OK.",
        ],
        cwd=workspace,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
    assert run.returncode == 0, run.stderr[-1000:]
    assert run.stdout.strip() == "OK"
