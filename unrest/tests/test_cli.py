"""CLI integration tests — init / list-projects / show-project / install-skills."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

from unrest_harness.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def env(harness_home: Path, workspace: Path, monkeypatch) -> dict[str, str]:
    monkeypatch.setenv("UNREST_HOME", str(harness_home))
    monkeypatch.chdir(workspace)
    return {"UNREST_HOME": str(harness_home)}


def _expected_mcp_server_args() -> list[str]:
    return ["--mode", "orchestrator"]


def _expected_server_command() -> str:
    return "unrest-server"


def _tree_snapshot(root: Path) -> dict[str, tuple[str, int, bytes]]:
    snapshot: dict[str, tuple[str, int, bytes]] = {}
    for path in (root, *sorted(root.rglob("*"))):
        relative = str(path.relative_to(root))
        kind = "directory" if path.is_dir() else "file"
        content = b"" if path.is_dir() else path.read_bytes()
        snapshot[relative] = (kind, stat.S_IMODE(path.stat().st_mode), content)
    return snapshot


class TestInit:
    def test_stages_host_agent_surface_only(
        self, runner: CliRunner, workspace: Path, env: dict[str, str]
    ) -> None:
        """`unrest init` writes MCP config + provider agents + orchestrator prompt
        but does NOT create the project bucket or workspace shims — those are
        created by `start_project` at the first MCP call."""
        result = runner.invoke(
            cli, ["init", "--workspace-dir", str(workspace), "--agent", "claude"]
        )
        assert result.exit_code == 0, result.output
        # Workspace stays clean of .unrest/ — bucket lives under UNREST_HOME.
        assert not (workspace / ".unrest").exists()
        # No symlink shims either — start_project handles them.
        assert not (workspace / "AGENTS.md").exists()
        # MCP config + .claude/agents/ are written.
        assert (workspace / ".mcp.json").exists()
        mcp = json.loads((workspace / ".mcp.json").read_text())
        assert "unrest" in mcp["mcpServers"]
        server = mcp["mcpServers"]["unrest"]
        assert server["command"] == _expected_server_command()
        assert server["args"] == _expected_mcp_server_args()

    def test_init_does_not_touch_gitignore(
        self, runner: CliRunner, workspace: Path, env: dict[str, str]
    ) -> None:
        gitignore = workspace / ".gitignore"
        gitignore.write_text("node_modules/\n")
        original = gitignore.read_text()
        r = runner.invoke(
            cli, ["init", "--workspace-dir", str(workspace), "--agent", "claude"]
        )
        assert r.exit_code == 0, r.output
        assert gitignore.read_text() == original

    def test_idempotent(
        self, runner: CliRunner, workspace: Path, env: dict[str, str]
    ) -> None:
        for _ in range(2):
            r = runner.invoke(
                cli, ["init", "--workspace-dir", str(workspace), "--agent", "claude"]
            )
            assert r.exit_code == 0, r.output
        # .mcp.json preserved across reruns.
        assert (workspace / ".mcp.json").exists()

    def test_codex_writes_codex_config(
        self, runner: CliRunner, workspace: Path, env: dict[str, str]
    ) -> None:
        r = runner.invoke(cli, ["init", "--workspace-dir", str(workspace), "--agent", "codex"])
        assert r.exit_code == 0, r.output
        config_path = workspace / ".codex" / "config.toml"
        assert config_path.exists()
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
        server = config["mcp_servers"]["unrest"]
        assert server["command"] == _expected_server_command()
        assert server["args"] == _expected_mcp_server_args()
        assert f"Initialized v5 project workspace at {workspace}" in r.output

    def test_codex_init_is_idempotent_and_migrates_legacy_managed_prefix(
        self, runner: CliRunner, workspace: Path, env: dict[str, str]
    ) -> None:
        config_path = workspace / ".codex" / "config.toml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(
            'developer_instructions = "keep me"\n\n'
            'model = "gpt-5.5"\n'
            'sandbox_mode = "danger-full-access"\n'
            'model_reasoning_effort = "xhigh"\n'
            '[features]\n'
            'memories = true\n'
            '# BEGIN unrest\n'
            '[mcp_servers.unrest]\n'
            'command = "old-uv"\n'
            '# END unrest\n',
            encoding="utf-8",
        )

        for _ in range(2):
            result = runner.invoke(
                cli, ["init", "--workspace-dir", str(workspace), "--agent", "codex"]
            )
            assert result.exit_code == 0, result.output
            parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
            assert parsed["developer_instructions"] == "keep me"
            assert parsed["mcp_servers"]["unrest"]["command"] == _expected_server_command()

        text = config_path.read_text(encoding="utf-8")
        assert text.count("[features]") == 1
        assert text.count("# BEGIN unrest") == 1
        assert "Start your agent from the initialized project workspace" in result.output
        assert (
            "First read .codex/orchestrator_prompt.md and treat it as your primary role, "
            "then use Unrest to run this mission." in result.output
        )

    @pytest.mark.parametrize(
        "existing",
        [
            'model = "user-model"\ndeveloper_instructions = "keep me"\n',
            '[features]\nmemories = false\nweb_search = true\n',
        ],
    )
    def test_codex_init_preserves_valid_unmanaged_host_config(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        existing: str,
    ) -> None:
        config_path = workspace / ".codex" / "config.toml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(existing, encoding="utf-8")

        for _ in range(2):
            result = runner.invoke(
                cli, ["init", "--workspace-dir", str(workspace), "--agent", "codex"]
            )
            assert result.exit_code == 0, result.output
            parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))

        if "user-model" in existing:
            assert parsed["model"] == "user-model"
            assert parsed["developer_instructions"] == "keep me"
        else:
            assert parsed["features"] == {"memories": False, "web_search": True}
        assert parsed["mcp_servers"]["unrest"]["command"] == _expected_server_command()

    def test_codex_init_pins_runtime_executables_and_preserves_role_efforts(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("unrest_harness.cli.shutil.which", lambda name: f"/opt/{name}")
        monkeypatch.setenv("PATH", "/opt/bin:/usr/bin:/bin")
        monkeypatch.setenv("UV_CACHE_DIR", "/tmp/unrest-uv-cache")
        monkeypatch.setenv("UNREST_WORKER_REASONING_EFFORT", "high")
        monkeypatch.setenv("UNREST_VALIDATOR_REASONING_EFFORT", "medium")
        monkeypatch.setenv("UNREST_TERMINAL_REVIEWER_REASONING_EFFORT", "low")

        result = runner.invoke(
            cli, ["init", "--workspace-dir", str(workspace), "--agent", "codex"]
        )

        assert result.exit_code == 0, result.output
        config = tomllib.loads(
            (workspace / ".codex" / "config.toml").read_text(encoding="utf-8")
        )
        server = config["mcp_servers"]["unrest"]
        assert server["command"] == "unrest-server"
        assert server["env"]["PATH"] == "/opt/bin:/usr/bin:/bin"
        assert server["env"]["UV_CACHE_DIR"] == "/tmp/unrest-uv-cache"
        assert server["env"]["CODEX_PATH"] == "/opt/codex"
        assert server["env"]["UNREST_WORKER_REASONING_EFFORT"] == "high"
        assert server["env"]["UNREST_VALIDATOR_REASONING_EFFORT"] == "medium"
        assert server["env"]["UNREST_TERMINAL_REVIEWER_REASONING_EFFORT"] == "low"

    def test_codex_init_writes_explicit_worker_model(
        self, runner: CliRunner, workspace: Path, env: dict[str, str]
    ) -> None:
        result = runner.invoke(
            cli,
            [
                "init",
                "--workspace-dir",
                str(workspace),
                "--agent",
                "codex",
                "--worker-model",
                "gpt-test",
            ],
        )
        assert result.exit_code == 0, result.output
        config = tomllib.loads(
            (workspace / ".codex" / "config.toml").read_text(encoding="utf-8")
        )
        assert config["mcp_servers"]["unrest"]["env"]["UNREST_WORKER_MODEL"] == "gpt-test"

    def test_worker_model_rejected_for_non_codex_worker(
        self, runner: CliRunner, workspace: Path, env: dict[str, str]
    ) -> None:
        result = runner.invoke(
            cli,
            [
                "init",
                "--workspace-dir",
                str(workspace),
                "--agent",
                "claude",
                "--worker-model",
                "gpt-test",
            ],
        )
        assert result.exit_code != 0
        assert "requires a Codex worker" in result.output

    def test_claude_init_writes_reasoning_effort_env(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("UNREST_WORKER_REASONING_EFFORT", "high")
        monkeypatch.setenv("UNREST_VALIDATOR_REASONING_EFFORT", "medium")
        monkeypatch.setenv("UNREST_TERMINAL_REVIEWER_REASONING_EFFORT", "low")

        r = runner.invoke(cli, ["init", "--workspace-dir", str(workspace), "--agent", "claude"])
        assert r.exit_code == 0, r.output

        mcp = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
        server_env = mcp["mcpServers"]["unrest"]["env"]
        assert server_env["UNREST_WORKER_REASONING_EFFORT"] == "high"
        assert server_env["UNREST_VALIDATOR_REASONING_EFFORT"] == "medium"
        assert server_env["UNREST_TERMINAL_REVIEWER_REASONING_EFFORT"] == "low"

    def test_codex_init_writes_reasoning_effort_env(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("UNREST_WORKER_REASONING_EFFORT", "high")
        monkeypatch.setenv("UNREST_VALIDATOR_REASONING_EFFORT", "medium")
        monkeypatch.setenv("UNREST_TERMINAL_REVIEWER_REASONING_EFFORT", "low")

        r = runner.invoke(cli, ["init", "--workspace-dir", str(workspace), "--agent", "codex"])
        assert r.exit_code == 0, r.output

        config = tomllib.loads(
            (workspace / ".codex" / "config.toml").read_text(encoding="utf-8")
        )
        server_env = config["mcp_servers"]["unrest"]["env"]
        assert server_env["UNREST_WORKER_REASONING_EFFORT"] == "high"
        assert server_env["UNREST_VALIDATOR_REASONING_EFFORT"] == "medium"
        assert server_env["UNREST_TERMINAL_REVIEWER_REASONING_EFFORT"] == "low"

    def test_init_reasoning_effort_flags_override_env(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("UNREST_WORKER_REASONING_EFFORT", "xhigh")

        r = runner.invoke(
            cli,
            [
                "init",
                "--workspace-dir",
                str(workspace),
                "--agent",
                "claude",
                "--worker-reasoning-effort",
                "max",
                "--validator-reasoning-effort",
                "medium",
            ],
        )
        assert r.exit_code == 0, r.output

        mcp = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
        server_env = mcp["mcpServers"]["unrest"]["env"]
        # Flag beats the inherited shell env.
        assert server_env["UNREST_WORKER_REASONING_EFFORT"] == "max"
        assert server_env["UNREST_VALIDATOR_REASONING_EFFORT"] == "medium"
        assert "UNREST_TERMINAL_REVIEWER_REASONING_EFFORT" not in server_env

    def test_init_invalid_inherited_effort_env_fails_despite_flag(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Flags override valid inherited settings; a broken env var is still a
        # hard error — the same validation would raise at server launch, so
        # masking it at init would only defer the failure.
        monkeypatch.setenv("UNREST_WORKER_REASONING_EFFORT", "turbo")

        r = runner.invoke(
            cli,
            [
                "init",
                "--workspace-dir",
                str(workspace),
                "--agent",
                "claude",
                "--worker-reasoning-effort",
                "max",
            ],
        )
        assert r.exit_code != 0
        assert isinstance(r.exception, ValueError)
        assert "UNREST_WORKER_REASONING_EFFORT" in str(r.exception)

    def test_claude_init_writes_runtime_validator_env_names(
        self, runner: CliRunner, workspace: Path, env: dict[str, str]
    ) -> None:
        r = runner.invoke(
            cli,
            [
                "init",
                "--workspace-dir",
                str(workspace),
                "--agent",
                "claude",
                "--validator-provider",
                "codex",
                "--validator-acp-command",
                "custom-validator-acp",
            ],
        )
        assert r.exit_code == 0, r.output

        mcp = json.loads((workspace / ".mcp.json").read_text())
        mcp_env = mcp["mcpServers"]["unrest"]["env"]
        assert mcp_env["UNREST_VALIDATOR_PROVIDER"] == "codex"
        assert mcp_env["UNREST_VALIDATOR_ACP_COMMAND"] == "custom-validator-acp"
        assert "UNREST_VALIDATION_WORKER_PROVIDER" not in mcp_env
        assert "UNREST_VALIDATION_WORKER_ACP_COMMAND" not in mcp_env

    def test_claude_init_forwards_only_allowed_model_env(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://api.z.ai/api/anthropic")
        monkeypatch.setenv("ANTHROPIC_MODEL", "glm-5.2[1m]")
        monkeypatch.setenv("ZAI_API_KEY", "zai-test-key")
        monkeypatch.setenv("DATABASE_URL", "postgres://should-not-forward")

        r = runner.invoke(cli, ["init", "--workspace-dir", str(workspace), "--agent", "claude"])
        assert r.exit_code == 0, r.output

        mcp = json.loads((workspace / ".mcp.json").read_text())
        mcp_env = mcp["mcpServers"]["unrest"]["env"]
        assert mcp_env["ANTHROPIC_BASE_URL"] == "https://api.z.ai/api/anthropic"
        assert mcp_env["ANTHROPIC_MODEL"] == "glm-5.2[1m]"
        assert mcp_env["ZAI_API_KEY"] == "zai-test-key"
        assert "DATABASE_URL" not in mcp_env

    @pytest.mark.parametrize("agent", ["claude", "codex", "hermes"])
    def test_explicit_project_scope_matches_default(
        self,
        runner: CliRunner,
        tmp_path: Path,
        env: dict[str, str],
        agent: str,
    ) -> None:
        default_workspace = tmp_path / "default"
        explicit_workspace = tmp_path / "explicit"
        default_workspace.mkdir()
        explicit_workspace.mkdir()

        default_result = runner.invoke(
            cli,
            ["init", "--workspace-dir", str(default_workspace), "--agent", agent],
        )
        explicit_result = runner.invoke(
            cli,
            [
                "init",
                "--scope",
                "project",
                "--workspace-dir",
                str(explicit_workspace),
                "--agent",
                agent,
            ],
        )
        assert default_result.exit_code == 0, default_result.output
        assert explicit_result.exit_code == 0, explicit_result.output

        def files(root: Path) -> dict[str, bytes]:
            return {
                str(path.relative_to(root)): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }

        assert files(default_workspace) == files(explicit_workspace)
        assert default_result.output.replace(str(default_workspace), "<workspace>") == (
            explicit_result.output.replace(str(explicit_workspace), "<workspace>")
        )


@pytest.fixture
def user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    return home


class TestUserScopeInit:
    def test_claude_installs_user_config_and_assets_without_freezing_model(
        self,
        runner: CliRunner,
        workspace: Path,
        user_home: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config_path = user_home / ".claude.json"
        config_path.write_text(
            json.dumps(
                {
                    "theme": "dark",
                    "projects": {"/existing": {"allowedTools": ["Read"]}},
                    "mcpServers": {
                        "other": {"command": "other-server"},
                        "unrest": {"command": "old-unrest"},
                    },
                },
                indent=2,
            )
            + "\n"
        )
        monkeypatch.setenv("ANTHROPIC_MODEL", "must-not-be-persisted")
        monkeypatch.setenv("ZAI_API_KEY", "must-not-be-persisted")

        result = runner.invoke(cli, ["init", "--scope", "user", "--agent", "claude"])
        assert result.exit_code == 0, result.output

        config = json.loads(config_path.read_text())
        assert config["theme"] == "dark"
        assert config["projects"]["/existing"]["allowedTools"] == ["Read"]
        assert config["mcpServers"]["other"]["command"] == "other-server"
        server = config["mcpServers"]["unrest"]
        assert server["command"] == "unrest-server"
        assert server["args"] == _expected_mcp_server_args()
        assert server["env"]["UNREST_ORCHESTRATOR_PROVIDER"] == "claude"
        assert "ANTHROPIC_MODEL" not in server["env"]
        assert "ZAI_API_KEY" not in server["env"]

        claude_root = user_home / ".claude"
        assert (claude_root / "orchestrator_prompt.md").exists()
        assert (claude_root / "agents" / "investigator.md").exists()
        assert (claude_root / "skills" / "engineering-mission-playbook" / "SKILL.md").exists()
        skill = (claude_root / "skills" / "unrest" / "SKILL.md").read_text()
        assert "name: unrest" in skill
        assert str(claude_root / "orchestrator_prompt.md") in skill
        assert "Do not run workspace initialization" in skill
        assert not (workspace / ".mcp.json").exists()
        assert not (workspace / ".claude").exists()
        assert "Restart Claude Code or start a new session" in result.output

        first_config = config_path.read_bytes()
        first_skill = (claude_root / "skills" / "unrest" / "SKILL.md").read_bytes()
        rerun = runner.invoke(cli, ["init", "--scope", "user", "--agent", "claude"])
        assert rerun.exit_code == 0, rerun.output
        assert config_path.read_bytes() == first_config
        assert (claude_root / "skills" / "unrest" / "SKILL.md").read_bytes() == first_skill

    def test_claude_config_dir_override_and_invalid_config_are_safe(
        self,
        runner: CliRunner,
        user_home: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config_root = user_home / "custom claude"
        config_root.mkdir()
        config_path = config_root / ".claude.json"
        original = '{"mcpServers": []}\n'
        config_path.write_text(original)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config_root))

        result = runner.invoke(cli, ["init", "--scope", "user", "--agent", "claude"])
        assert result.exit_code != 0
        assert "mcpServers must be an object" in result.output
        assert config_path.read_text() == original
        assert not (config_root / "skills").exists()
        assert not (config_root / "agents").exists()

        config_path.write_text("not json\n")
        malformed = runner.invoke(
            cli, ["init", "--scope", "user", "--agent", "claude"]
        )
        assert malformed.exit_code != 0
        assert config_path.read_text() == "not json\n"
        assert not (config_root / "skills").exists()

        config_path.write_text('{"theme": "light"}\n')
        success = runner.invoke(cli, ["init", "--scope", "user", "--agent", "claude"])
        assert success.exit_code == 0, success.output
        config = json.loads(config_path.read_text())
        assert config["theme"] == "light"
        assert config["mcpServers"]["unrest"]["command"] == "unrest-server"
        assert (config_root / "skills" / "unrest" / "SKILL.md").exists()
        assert (config_root / "agents" / "investigator.md").exists()

    def test_codex_preserves_preferences_and_adopts_existing_server(
        self,
        runner: CliRunner,
        workspace: Path,
        user_home: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        codex_root = user_home / "custom codex"
        codex_root.mkdir()
        monkeypatch.setenv("CODEX_HOME", str(codex_root))
        monkeypatch.setenv("ANTHROPIC_MODEL", "must-not-be-persisted")
        config_path = codex_root / "config.toml"
        config_path.write_text(
            'model = "user-model"\n'
            'model_reasoning_effort = "low"\n'
            'sandbox_mode = "workspace-write"\n'
            "\n"
            "[features]\n"
            "memories = false\n"
            "\n"
            "[mcp_servers.other]\n"
            'command = "other-server"\n'
            "\n"
            "[mcp_servers.unrest]\n"
            'command = "old-unrest"\n'
            "\n"
            "[mcp_servers.unrest.env]\n"
            'OLD = "value"\n'
        )
        sibling_skill = codex_root / "skills" / "personal" / "SKILL.md"
        sibling_skill.parent.mkdir(parents=True)
        sibling_skill.write_text("personal skill\n")
        sibling_agent = codex_root / "agents" / "personal.toml"
        sibling_agent.parent.mkdir(parents=True)
        sibling_agent.write_text('name = "personal"\n')

        custom_home = user_home / 'state with "quotes" and ünicode'
        result = runner.invoke(
            cli,
            [
                "init",
                "--scope",
                "user",
                "--agent",
                "codex",
                "--unrest-home",
                str(custom_home),
            ],
        )
        assert result.exit_code == 0, result.output

        text = config_path.read_text()
        config = tomllib.loads(text)
        assert config["model"] == "user-model"
        assert config["model_reasoning_effort"] == "low"
        assert config["sandbox_mode"] == "workspace-write"
        assert config["features"]["memories"] is False
        assert config["mcp_servers"]["other"]["command"] == "other-server"
        server = config["mcp_servers"]["unrest"]
        assert server["command"] == "unrest-server"
        assert server["args"] == _expected_mcp_server_args()
        assert server["env"]["UNREST_HOME"] == str(custom_home.resolve())
        assert "ANTHROPIC_MODEL" not in server["env"]
        assert text.count("[mcp_servers.unrest]") == 1
        assert text.count("[mcp_servers.unrest.env]") == 1
        assert 'model = "gpt-5.5"' not in text
        assert 'model_reasoning_effort = "xhigh"' not in text

        assert (codex_root / "orchestrator_prompt.md").exists()
        assert (codex_root / "agents" / "investigator.toml").exists()
        skill_path = codex_root / "skills" / "unrest" / "SKILL.md"
        assert str(codex_root / "orchestrator_prompt.md") in skill_path.read_text()
        assert not (workspace / ".codex").exists()
        assert sibling_skill.read_text() == "personal skill\n"
        assert sibling_agent.read_text() == 'name = "personal"\n'

        first = config_path.read_bytes()
        rerun = runner.invoke(
            cli,
            [
                "init",
                "--scope",
                "user",
                "--agent",
                "codex",
                "--unrest-home",
                str(custom_home),
            ],
        )
        assert rerun.exit_code == 0, rerun.output
        assert config_path.read_bytes() == first

    def test_codex_replaces_valid_managed_block_by_line_and_preserves_mode(
        self,
        runner: CliRunner,
        user_home: Path,
        env: dict[str, str],
    ) -> None:
        codex_root = user_home / ".codex"
        codex_root.mkdir()
        config_path = codex_root / "config.toml"
        config_path.write_text(
            'model = "user-model"\n'
            "\n"
            "[features]\n"
            "memories = false\n"
            "\n"
            "  # BEGIN unrest  \n"
            "[mcp_servers.unrest]\n"
            'command = "old-unrest"\n'
            "\n"
            "[mcp_servers.unrest.env]\n"
            'OLD = "value"\n'
            "\t# END unrest\t\n"
            "\n"
            "[mcp_servers.after]\n"
            'command = "after"\n'
        )
        config_path.chmod(0o640)

        result = runner.invoke(cli, ["init", "--scope", "user", "--agent", "codex"])
        assert result.exit_code == 0, result.output
        first = config_path.read_bytes()
        config = tomllib.loads(first.decode())
        assert config["model"] == "user-model"
        assert config["features"]["memories"] is False
        assert config["mcp_servers"]["unrest"]["command"] == "unrest-server"
        assert config["mcp_servers"]["after"]["command"] == "after"
        assert first.count(b"# BEGIN unrest") == 1
        assert first.count(b"# END unrest") == 1
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o640

        rerun = runner.invoke(cli, ["init", "--scope", "user", "--agent", "codex"])
        assert rerun.exit_code == 0, rerun.output
        assert config_path.read_bytes() == first
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o640

    @pytest.mark.parametrize(
        "unrest_header, env_header",
        [
            ('[mcp_servers."unrest"]', '[mcp_servers."unrest".env]'),
            ("[mcp_servers.unrest] # old server", "[mcp_servers.unrest.env] # old env"),
        ],
    )
    def test_codex_adopts_equivalent_unmanaged_unrest_tables(
        self,
        runner: CliRunner,
        user_home: Path,
        env: dict[str, str],
        unrest_header: str,
        env_header: str,
    ) -> None:
        codex_root = user_home / ".codex"
        codex_root.mkdir()
        config_path = codex_root / "config.toml"
        config_path.write_text(
            'title = "contains # BEGIN unrest but is not a boundary"\n'
            "# # END unrest is part of a longer comment\n\n"
            '[mcp_servers.before]\ncommand = "before"\n\n'
            'marker_text = "prefix # END unrest suffix"\n\n'
            f'{unrest_header}\ncommand = "old"\n\n'
            f'{env_header}\nOLD = "value"\n\n'
            '[mcp_servers.after]\ncommand = "after"\n'
        )
        config_path.chmod(0o600)

        result = runner.invoke(cli, ["init", "--scope", "user", "--agent", "codex"])
        assert result.exit_code == 0, result.output
        text = config_path.read_text()
        config = tomllib.loads(text)
        assert config["title"] == "contains # BEGIN unrest but is not a boundary"
        assert config["mcp_servers"]["before"]["command"] == "before"
        assert config["mcp_servers"]["before"]["marker_text"] == "prefix # END unrest suffix"
        assert config["mcp_servers"]["after"]["command"] == "after"
        assert config["mcp_servers"]["unrest"]["command"] == "unrest-server"
        assert text.count("[mcp_servers.unrest]") == 1
        assert "# # END unrest is part of a longer comment" in text
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600

        first = config_path.read_bytes()
        rerun = runner.invoke(cli, ["init", "--scope", "user", "--agent", "codex"])
        assert rerun.exit_code == 0, rerun.output
        assert config_path.read_bytes() == first
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600

    def test_codex_invalid_toml_does_not_mutate_assets(
        self,
        runner: CliRunner,
        user_home: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        codex_root = user_home / ".codex"
        codex_root.mkdir()
        config_path = codex_root / "config.toml"
        content = "not = [valid\n"
        config_path.write_text(content)
        monkeypatch.setenv("CODEX_HOME", str(codex_root))

        result = runner.invoke(cli, ["init", "--scope", "user", "--agent", "codex"])
        assert result.exit_code != 0
        assert "invalid Codex config" in result.output
        assert config_path.read_text() == content
        assert not (codex_root / "skills").exists()
        assert not (codex_root / "agents").exists()

    @pytest.mark.parametrize(
        "markers",
        [
            pytest.param(("# BEGIN unrest",), id="begin-only"),
            pytest.param(("# END unrest",), id="end-only"),
            pytest.param(("# END unrest", "# BEGIN unrest"), id="reversed"),
            pytest.param(
                ("# BEGIN unrest", "# BEGIN unrest", "# END unrest"),
                id="duplicate-begin",
            ),
            pytest.param(
                ("# BEGIN unrest", "# END unrest", "# END unrest"),
                id="duplicate-end",
            ),
            pytest.param(
                ("# BEGIN unrest", "# END unrest", "# BEGIN unrest", "# END unrest"),
                id="two-blocks",
            ),
            pytest.param(
                ("# BEGIN unrest", "# BEGIN unrest", "# END unrest", "# END unrest"),
                id="nested",
            ),
            pytest.param(
                (
                    "# BEGIN unrest",
                    "# BEGIN unrest",
                    "# END unrest",
                    "# BEGIN unrest",
                    "# END unrest",
                    "# END unrest",
                ),
                id="overlapping",
            ),
        ],
    )
    def test_codex_rejects_malformed_managed_blocks_without_user_tree_mutation(
        self,
        runner: CliRunner,
        user_home: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
        markers: tuple[str, ...],
    ) -> None:
        codex_root = user_home / ".codex"
        codex_root.mkdir()
        config_path = codex_root / "config.toml"
        content = 'theme = "dark"\n' + "\n".join(markers) + "\n# keep me\n"
        config_path.write_text(content)
        config_path.chmod(0o640)
        monkeypatch.setenv("CODEX_HOME", str(codex_root))
        existing_agent = codex_root / "agents" / "personal.toml"
        existing_agent.parent.mkdir()
        existing_agent.write_text('name = "personal"\n')
        existing_skill = codex_root / "skills" / "personal" / "SKILL.md"
        existing_skill.parent.mkdir(parents=True)
        existing_skill.write_text("personal skill\n")
        shared_skill = user_home / ".agents" / "skills" / "personal" / "SKILL.md"
        shared_skill.parent.mkdir(parents=True)
        shared_skill.write_text("shared personal skill\n")
        before = _tree_snapshot(user_home)

        result = runner.invoke(cli, ["init", "--scope", "user", "--agent", "codex"])
        assert result.exit_code != 0
        assert "malformed Unrest managed block" in result.output
        assert _tree_snapshot(user_home) == before

    @pytest.mark.parametrize("order", [("claude", "codex"), ("codex", "claude")])
    def test_claude_and_codex_user_installs_coexist(
        self,
        runner: CliRunner,
        user_home: Path,
        env: dict[str, str],
        order: tuple[str, str],
    ) -> None:
        first = runner.invoke(cli, ["init", "--scope", "user", "--agent", order[0]])
        assert first.exit_code == 0, first.output
        shared_root = user_home / ".agents" / "skills"
        shared_before = {
            str(path.relative_to(shared_root)): path.read_bytes()
            for path in shared_root.rglob("*")
            if path.is_file()
        }

        for agent in order[1:]:
            result = runner.invoke(cli, ["init", "--scope", "user", "--agent", agent])
            assert result.exit_code == 0, result.output

        claude = json.loads((user_home / ".claude.json").read_text())
        codex = tomllib.loads((user_home / ".codex" / "config.toml").read_text())
        assert claude["mcpServers"]["unrest"]["env"]["UNREST_WORKER_PROVIDER"] == "claude"
        assert codex["mcp_servers"]["unrest"]["env"]["UNREST_WORKER_PROVIDER"] == "codex"
        assert (user_home / ".claude" / "skills" / "unrest" / "SKILL.md").exists()
        assert (user_home / ".codex" / "skills" / "unrest" / "SKILL.md").exists()
        assert (user_home / ".agents" / "skills" / "scrutiny-validator" / "SKILL.md").exists()
        shared_after = {
            str(path.relative_to(shared_root)): path.read_bytes()
            for path in shared_root.rglob("*")
            if path.is_file()
        }
        assert shared_after == shared_before

    def test_user_scope_argument_errors_happen_before_writes(
        self,
        runner: CliRunner,
        workspace: Path,
        user_home: Path,
        env: dict[str, str],
    ) -> None:
        conflicting = runner.invoke(
            cli,
            [
                "init",
                "--scope",
                "user",
                "--workspace-dir",
                str(workspace),
                "--agent",
                "codex",
            ],
        )
        assert conflicting.exit_code != 0
        assert "--workspace-dir cannot be used with --scope user" in conflicting.output

        unsupported = runner.invoke(
            cli, ["init", "--scope", "user", "--agent", "hermes"]
        )
        assert unsupported.exit_code != 0
        assert "use --scope project for hermes" in unsupported.output
        assert list(user_home.iterdir()) == []

    def test_registered_command_launches_from_another_workspace(
        self,
        runner: CliRunner,
        user_home: Path,
        env: dict[str, str],
        tmp_path: Path,
    ) -> None:
        result = runner.invoke(cli, ["init", "--scope", "user", "--agent", "codex"])
        assert result.exit_code == 0, result.output
        config = tomllib.loads((user_home / ".codex" / "config.toml").read_text())
        server = config["mcp_servers"]["unrest"]
        unrelated = tmp_path / "unrelated workspace"
        unrelated.mkdir()

        launched = subprocess.run(
            [server["command"], *server["args"], "--help"],
            cwd=unrelated,
            env={**os.environ, **server["env"]},
            text=True,
            capture_output=True,
            check=False,
        )
        assert launched.returncode == 0, launched.stderr
        assert "Unrest MCP Server" in launched.stdout
        assert not (unrelated / ".codex").exists()
        assert not (unrelated / ".unrest").exists()


class TestListProjects:
    def test_empty(self, runner: CliRunner, env: dict[str, str]) -> None:
        r = runner.invoke(cli, ["list-projects"])
        assert r.exit_code == 0
        assert "No projects" in r.output

    def test_after_creation(
        self, runner: CliRunner, workspace: Path, harness_home: Path, env: dict[str, str]
    ) -> None:
        from unrest_harness.config import HarnessConfig
        from unrest_harness.storage import ProjectStore

        ProjectStore(HarnessConfig.discover()).create_project(
            "brief", workspace, project_id="proj-x"
        )
        r = runner.invoke(cli, ["list-projects"])
        assert "proj-x" in r.output


class TestShowProject:
    def test_unknown_id(self, runner: CliRunner, env: dict[str, str]) -> None:
        r = runner.invoke(cli, ["show-project", "ghost"])
        assert r.exit_code != 0
        assert "not found" in r.output.lower()
