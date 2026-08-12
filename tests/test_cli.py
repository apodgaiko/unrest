"""CLI integration tests — init / list-projects / show-project / install-skills."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

import unrest_harness.cli as cli_module
from unrest_harness.cli import cli
from unrest_harness.config import HarnessConfig
from unrest_harness.providers import PROVIDERS, ProviderSelection, provider_names_for_role


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


def _tree_snapshot(root: Path) -> dict[str, tuple[str, int, int, bytes]]:
    snapshot: dict[str, tuple[str, int, int, bytes]] = {}
    for path in (root, *sorted(root.rglob("*"))):
        relative = str(path.relative_to(root))
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            kind = "directory"
            content = b""
        elif stat.S_ISREG(info.st_mode):
            kind = "file"
            content = path.read_bytes()
        elif stat.S_ISLNK(info.st_mode):
            kind = "symlink"
            content = os.fsencode(os.readlink(path))
        else:
            kind = "other"
            content = b""
        snapshot[relative] = (
            kind,
            stat.S_IMODE(info.st_mode),
            info.st_mtime_ns,
            content,
        )
    return snapshot


def _tree_content_inventory(root: Path) -> dict[str, tuple[str, int, bytes]]:
    return {
        path: (kind, mode, content)
        for path, (kind, mode, _mtime, content) in _tree_snapshot(root).items()
    }


def _tree_content_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path, (kind, mode, content) in sorted(_tree_content_inventory(root).items()):
        for field in (path.encode(), kind.encode(), str(mode).encode(), content):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return digest.hexdigest()


def test_bootstrap_writer_redacts_exact_credential_before_persistence(
    workspace: Path,
) -> None:
    sentinel = "bootstrap-persistence-credential-c8e2"
    bootstrap_path = workspace / ".mcp.json"
    selection = ProviderSelection(
        orchestrator=PROVIDERS["claude"],
        worker=PROVIDERS["claude"],
    )
    assert not bootstrap_path.exists()

    cli_module._write_bootstrap_config(
        workspace,
        selection,
        {"UNREST_HOME": str(workspace / ".unrest-home")},
        {
            "UNREST_WORKER_MODEL": sentinel,
            "ORDINARY_BOOTSTRAP_CONTROL": "kept",
        },
        "safe",
        {"ANTHROPIC_API_KEY": sentinel},
    )

    persisted = bootstrap_path.read_bytes()
    assert sentinel.encode() not in persisted
    document = json.loads(persisted)
    environment = document["mcpServers"]["unrest"]["env"]
    assert "UNREST_WORKER_MODEL" not in environment
    assert environment["ORDINARY_BOOTSTRAP_CONTROL"] == "kept"


def test_lifecycle_commands_ignore_stale_dispatch_provider_and_abort_redacts(
    runner: CliRunner,
    env: dict[str, str],
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from unrest_harness.controller import ProjectController
    from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
    from unrest_harness.models import Task, TaskList, TerminalReviewHandoff, WorkHandoff

    config = HarnessConfig.discover()
    controller = ProjectController(
        config,
        MockDispatcher(
            lambda request: WorkHandoff(node_id=request.task.id, done=True, report="ok")
        ),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("stale provider lifecycle", str(workspace))
    project_id = controller.store.list_projects()[0].id
    contract_dir = controller.store.ensure_contract_dir(project_id, "mission-001")
    (contract_dir / "VAL-001.md").write_text("# VAL-001\n")
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[Task(id="w1", type="work", body="body", targets=["VAL-001"], skill="s")]
        ),
    )

    monkeypatch.setenv("UNREST_WORKER_PROVIDER", "removed-provider")
    credentials = {
        name: f"sentinel-{index}-{name.lower()}"
        for index, name in enumerate(
            (
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "CODEX_API_KEY",
                "GLM_API_KEY",
                "OPENAI_API_KEY",
                "ZAI_API_KEY",
            )
        )
    }
    for name, value in credentials.items():
        monkeypatch.setenv(name, value)

    commands = (
        ["list-projects"],
        ["show-project", project_id],
        ["inspect-tasks", "--project", project_id],
        ["abort-project", project_id, "--reason", "|".join(credentials.values())],
    )
    for command in commands:
        result = runner.invoke(cli, command, env=env)
        assert result.exit_code == 0, result.output
        assert "removed-provider" not in result.output
        for value in credentials.values():
            assert value not in result.output

    for path in config.bucket_root(project_id).rglob("*"):
        if path.is_file():
            content = path.read_text(errors="replace")
            for value in credentials.values():
                assert value not in content


def _config_hash(boundary: Path, scope: str, agent: str) -> str:
    if scope == "project":
        path = boundary / (".mcp.json" if agent == "claude" else ".codex/config.toml")
    else:
        path = boundary / (".claude.json" if agent == "claude" else ".codex/config.toml")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestInit:
    def test_help_advertises_only_supported_orchestrators(
        self,
        runner: CliRunner,
    ) -> None:
        result = runner.invoke(cli, ["init", "--help"])

        assert result.exit_code == 0, result.output
        assert "--agent [claude|codex]" in result.output
        assert "--orchestrator-provider [claude|codex]" in result.output
        assert "--worker-provider [claude|codex]" in result.output
        assert provider_names_for_role("orchestrator") == ("claude", "codex")

    def test_invalid_authority_is_value_free_without_traceback(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
    ) -> None:
        invalid = "invalid-profile-sensitive-value"
        result = runner.invoke(
            cli,
            ["init", "--workspace-dir", str(workspace), "--agent", "claude"],
            env={**env, "UNREST_CAPABILITY_PROFILE": invalid},
        )
        assert result.exit_code == 1
        assert "Error: CAP-POLICY-001" in result.output
        assert "unsupported capability profile" in result.output
        assert invalid not in result.output
        assert "Traceback" not in result.output

    @pytest.mark.parametrize(
        "option",
        (
            "--agent",
            "--orchestrator-provider",
            "--worker-provider",
            "--validator-provider",
            "--terminal-reviewer-provider",
            "--worker-reasoning-effort",
            "--validator-reasoning-effort",
            "--terminal-reviewer-reasoning-effort",
            "--scope",
        ),
    )
    def test_precommand_choices_redact_exact_finite_credentials(
        self,
        option: str,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sentinel = "known-cli-choice-sentinel-4c21"
        callback_called = False
        init_command = cli.commands["init"]

        def trap_callback(**_kwargs: object) -> None:
            nonlocal callback_called
            callback_called = True

        monkeypatch.setattr(init_command, "callback", trap_callback)
        result = runner.invoke(
            cli,
            ["init", option, sentinel],
            env={"OPENAI_API_KEY": sentinel},
        )

        assert result.exit_code == 2
        assert sentinel not in result.output
        assert "<redacted:OPENAI_API_KEY>" in result.output
        assert "is not one of" in result.output
        assert callback_called is False

    def test_precommand_choices_retain_ordinary_rejected_context(
        self,
        runner: CliRunner,
    ) -> None:
        ordinary = "ordinary-unsupported-provider"
        result = runner.invoke(cli, ["init", "--worker-provider", ordinary])

        assert result.exit_code == 2
        assert ordinary in result.output
        assert "claude" in result.output
        assert "codex" in result.output

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
        assert text.splitlines().count("# BEGIN unrest") == 1
        assert text.splitlines().count("# BEGIN unrest capability policy v1") == 1
        assert 'sandbox_mode = "danger-full-access"' not in text
        assert 'sandbox_mode = "workspace-write"' in text
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

    @pytest.mark.parametrize(
        ("existing", "expected_sandbox", "expected_approval"),
        [
            (
                'sandbox_mode = "workspace-write"\nmodel = "keep-model"\n',
                "workspace-write",
                "on-request",
            ),
            (
                'sandbox_mode = "read-only"\nmodel = "keep-model"\n',
                "read-only",
                "on-request",
            ),
            (
                'approval_policy = "on-request"\nmodel = "keep-model"\n',
                "workspace-write",
                "on-request",
            ),
            (
                'approval_policy = "untrusted"\nmodel = "keep-model"\n',
                "workspace-write",
                "untrusted",
            ),
        ],
    )
    def test_codex_init_completes_partial_safe_root_settings_idempotently(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        existing: str,
        expected_sandbox: str,
        expected_approval: str,
    ) -> None:
        config_path = workspace / ".codex" / "config.toml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(existing, encoding="utf-8")

        first = runner.invoke(
            cli,
            ["init", "--workspace-dir", str(workspace), "--agent", "codex"],
        )
        assert first.exit_code == 0, first.output
        first_bytes = config_path.read_bytes()
        parsed = tomllib.loads(first_bytes.decode("utf-8"))
        assert parsed["sandbox_mode"] == expected_sandbox
        assert parsed["approval_policy"] == expected_approval
        assert parsed["model"] == "keep-model"

        second = runner.invoke(
            cli,
            ["init", "--workspace-dir", str(workspace), "--agent", "codex"],
        )
        assert second.exit_code == 0, second.output
        assert config_path.read_bytes() == first_bytes

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
        assert "ZAI_API_KEY" not in mcp_env
        assert "DATABASE_URL" not in mcp_env

    @pytest.mark.parametrize("agent", ["claude", "codex"])
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
        assert first.splitlines().count(b"# BEGIN unrest") == 1
        assert first.splitlines().count(b"# BEGIN unrest capability policy v1") == 1
        assert first.splitlines().count(b"# END unrest") == 1
        assert first.splitlines().count(b"# END unrest capability policy v1") == 1
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
            cli, ["init", "--scope", "user", "--agent", "unknown"]
        )
        assert unsupported.exit_code != 0
        assert "Invalid value for '--agent': 'unknown'" in unsupported.output
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


class TestInitManagedRootSafety:
    @pytest.mark.parametrize("scope", ("project", "user"))
    @pytest.mark.parametrize("agent", ("claude", "codex"))
    @pytest.mark.parametrize("root_state", ("absent", "existing"))
    def test_managed_roots_preserve_unrelated_bytes_and_repeat_exactly(
        self,
        runner: CliRunner,
        workspace: Path,
        user_home: Path,
        env: dict[str, str],
        scope: str,
        agent: str,
        root_state: str,
    ) -> None:
        boundary = workspace if scope == "project" else user_home
        root = boundary / f".{agent}"
        unrelated = root / "unrelated" / "keep.bin"
        if root_state == "existing":
            unrelated.parent.mkdir(parents=True)
            unrelated.write_bytes(b"unrelated\x00configuration\n")
            unrelated.chmod(0o600)

        arguments = ["init", "--agent", agent]
        if scope == "project":
            arguments.extend(["--workspace-dir", str(workspace)])
        else:
            arguments.extend(["--scope", "user"])
        first = runner.invoke(cli, arguments)
        assert first.exit_code == 0, first.output
        first_inventory_hash = _tree_content_hash(boundary)
        first_config_hash = _config_hash(boundary, scope, agent)

        second = runner.invoke(cli, arguments)
        assert second.exit_code == 0, second.output
        assert _tree_content_hash(boundary) == first_inventory_hash
        assert _config_hash(boundary, scope, agent) == first_config_hash
        third = runner.invoke(cli, arguments)
        assert (third.exit_code, third.stdout_bytes, third.stderr_bytes) == (
            second.exit_code,
            second.stdout_bytes,
            second.stderr_bytes,
        )
        assert b"Managed orchestrator prompt at " in first.stdout_bytes
        assert b"created=1 repaired=0 verified=0" in first.stdout_bytes
        assert b"created=0 repaired=0 verified=1" in second.stdout_bytes
        if root_state == "existing":
            assert unrelated.read_bytes() == b"unrelated\x00configuration\n"
            assert stat.S_IMODE(unrelated.stat().st_mode) == 0o600

    @pytest.mark.parametrize("scope", ("project", "user"))
    @pytest.mark.parametrize("agent", ("claude", "codex"))
    @pytest.mark.parametrize(
        "asset_kind", ("prompt", "provider-agent", "bundled-skill")
    )
    @pytest.mark.parametrize(
        "mutation", ("absent", "exact", "truncated", "corrupted", "wrong-mode")
    )
    def test_managed_assets_are_truthfully_verified_and_atomically_repaired(
        self,
        runner: CliRunner,
        workspace: Path,
        user_home: Path,
        env: dict[str, str],
        scope: str,
        agent: str,
        asset_kind: str,
        mutation: str,
    ) -> None:
        arguments = ["init", "--agent", agent]
        if scope == "project":
            arguments.extend(["--workspace-dir", str(workspace)])
            boundary = workspace
        else:
            arguments.extend(["--scope", "user"])
            boundary = user_home
        baseline = runner.invoke(cli, arguments)
        assert baseline.exit_code == 0, baseline.output

        root = boundary / f".{agent}"
        if asset_kind == "prompt":
            source = (
                HarnessConfig.discover().bundled_dir
                / "prompts"
                / "orchestrator"
                / "system_prompt.md"
            )
            destination = root / "orchestrator_prompt.md"
            output_label = "Managed orchestrator prompt at "
        elif asset_kind == "provider-agent":
            extension = "md" if agent == "claude" else "toml"
            source = (
                HarnessConfig.discover().bundled_dir
                / "providers"
                / agent
                / "agents"
                / f"investigator.{extension}"
            )
            destination = root / "agents" / source.name
            output_label = f"Managed {agent} subagents at "
        else:
            source = (
                HarnessConfig.discover().bundled_dir
                / "skills"
                / "engineering-mission-playbook"
                / "SKILL.md"
            )
            destination = root / "skills" / "engineering-mission-playbook" / "SKILL.md"
            output_label = "Managed bundled skills at "

        authoritative = source.read_bytes()
        if mutation == "absent":
            destination.unlink()
            expected_outcome = "created"
        elif mutation == "truncated":
            destination.write_bytes(authoritative[: max(1, len(authoritative) // 3)])
            expected_outcome = "repaired"
        elif mutation == "corrupted":
            destination.write_bytes(b"corrupted managed asset\n")
            expected_outcome = "repaired"
        elif mutation == "wrong-mode":
            destination.chmod(0o600)
            expected_outcome = "repaired"
        else:
            expected_outcome = "verified"
        destination_before = destination.stat() if mutation == "exact" else None

        unrelated = root / "unrelated" / "sentinel.bin"
        unrelated.parent.mkdir(parents=True, exist_ok=True)
        unrelated.write_bytes(b"unrelated\x00bytes\n")
        unrelated.chmod(0o600)
        config_before = _config_hash(boundary, scope, agent)

        result = runner.invoke(cli, arguments)
        assert result.exit_code == 0, result.output
        matching_line = next(
            line for line in result.output.splitlines() if line.startswith(output_label)
        )
        assert f"{expected_outcome}=" in matching_line
        if asset_kind == "prompt":
            expected_counts = {
                "created": "created=1 repaired=0 verified=0",
                "repaired": "created=0 repaired=1 verified=0",
                "verified": "created=0 repaired=0 verified=1",
            }
            assert expected_counts[expected_outcome] in matching_line
        else:
            asset_count = 4 if asset_kind == "provider-agent" else 6
            expected_value = 1 if expected_outcome != "verified" else asset_count
            assert f"{expected_outcome}={expected_value}" in matching_line

        assert destination.read_bytes() == authoritative
        assert hashlib.sha256(destination.read_bytes()).hexdigest() == hashlib.sha256(
            authoritative
        ).hexdigest()
        assert stat.S_IMODE(destination.stat().st_mode) == 0o644
        if mutation == "exact":
            assert destination_before is not None
            destination_after = destination.stat()
            assert destination_after.st_ino == destination_before.st_ino
            assert destination_after.st_mtime_ns == destination_before.st_mtime_ns
        assert unrelated.read_bytes() == b"unrelated\x00bytes\n"
        assert stat.S_IMODE(unrelated.stat().st_mode) == 0o600
        assert _config_hash(boundary, scope, agent) == config_before

        verified = runner.invoke(cli, arguments)
        repeated = runner.invoke(cli, arguments)
        assert (repeated.exit_code, repeated.stdout_bytes, repeated.stderr_bytes) == (
            verified.exit_code,
            verified.stdout_bytes,
            verified.stderr_bytes,
        )
        verified_line = next(
            line for line in verified.output.splitlines() if line.startswith(output_label)
        )
        expected_verified = {
            "prompt": 1,
            "provider-agent": 4,
            "bundled-skill": 6,
        }[asset_kind]
        assert f"created=0 repaired=0 verified={expected_verified}" in verified_line

    @pytest.mark.parametrize("scope", ("project", "user"))
    @pytest.mark.parametrize("agent", ("claude", "codex"))
    @pytest.mark.parametrize("unsafe_kind", ("symlink", "directory"))
    def test_unsafe_managed_prompt_targets_fail_before_any_write(
        self,
        runner: CliRunner,
        workspace: Path,
        user_home: Path,
        env: dict[str, str],
        tmp_path: Path,
        scope: str,
        agent: str,
        unsafe_kind: str,
    ) -> None:
        arguments = ["init", "--agent", agent]
        if scope == "project":
            arguments.extend(["--workspace-dir", str(workspace)])
            boundary = workspace
        else:
            arguments.extend(["--scope", "user"])
            boundary = user_home
        baseline = runner.invoke(cli, arguments)
        assert baseline.exit_code == 0, baseline.output

        prompt = boundary / f".{agent}" / "orchestrator_prompt.md"
        prompt.unlink()
        outside = tmp_path / f"outside-{scope}-{agent}-{unsafe_kind}"
        outside.mkdir()
        outside_file = outside / "prompt.md"
        outside_file.write_bytes(b"outside sentinel\n")
        if unsafe_kind == "symlink":
            prompt.symlink_to(outside_file)
        else:
            prompt.mkdir()
        before_boundary = _tree_content_inventory(boundary)
        before_outside = _tree_content_inventory(outside)

        result = runner.invoke(cli, arguments)

        assert result.exit_code != 0
        assert _tree_content_inventory(boundary) == before_boundary
        assert _tree_content_inventory(outside) == before_outside

    @pytest.mark.parametrize(
        "arguments",
        (
            ("init", "--agent", "unknown"),
            ("init", "--scope", "user", "--workspace-dir", "."),
        ),
    )
    def test_invalid_init_output_is_explicit_and_repeatable(
        self,
        runner: CliRunner,
        workspace: Path,
        user_home: Path,
        env: dict[str, str],
        arguments: tuple[str, ...],
    ) -> None:
        first = runner.invoke(cli, arguments)
        second = runner.invoke(cli, arguments)

        assert first.exit_code != 0
        assert (second.exit_code, second.stdout_bytes, second.stderr_bytes) == (
            first.exit_code,
            first.stdout_bytes,
            first.stderr_bytes,
        )
        assert b"Error:" in first.stderr_bytes

    @pytest.mark.parametrize("agent", ("claude", "codex"))
    def test_absent_nested_user_config_override_is_created_beneath_home(
        self,
        runner: CliRunner,
        user_home: Path,
        env: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
        agent: str,
    ) -> None:
        root = user_home / "ordinary" / "nested" / agent
        variable = "CLAUDE_CONFIG_DIR" if agent == "claude" else "CODEX_HOME"
        monkeypatch.setenv(variable, str(root))

        first = runner.invoke(cli, ["init", "--scope", "user", "--agent", agent])
        assert first.exit_code == 0, first.output
        first_inventory = _tree_content_inventory(user_home)
        second = runner.invoke(cli, ["init", "--scope", "user", "--agent", agent])
        assert second.exit_code == 0, second.output
        assert _tree_content_inventory(user_home) == first_inventory
        config_name = ".claude.json" if agent == "claude" else "config.toml"
        assert (root / config_name).is_file()

    @pytest.mark.parametrize("agent", ("claude", "codex"))
    @pytest.mark.parametrize("control", ("root", "parent", "target"))
    def test_project_symlink_controls_fail_before_any_initialization_write(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        tmp_path: Path,
        agent: str,
        control: str,
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        root = workspace / f".{agent}"
        if control == "root":
            root.symlink_to(outside, target_is_directory=True)
        elif control == "parent":
            root.mkdir()
            (root / "skills").symlink_to(outside, target_is_directory=True)
        elif agent == "claude":
            (workspace / ".mcp.json").symlink_to(outside / "config.json")
        else:
            root.mkdir()
            (root / "config.toml").symlink_to(outside / "config.toml")
        before_workspace = _tree_content_inventory(workspace)
        before_outside = _tree_content_inventory(outside)

        result = runner.invoke(
            cli,
            ["init", "--workspace-dir", str(workspace), "--agent", agent],
        )
        assert result.exit_code != 0
        assert _tree_content_inventory(workspace) == before_workspace
        assert _tree_content_inventory(outside) == before_outside

    @pytest.mark.parametrize("agent", ("claude", "codex"))
    def test_user_override_symlink_root_is_not_resolved_or_traversed(
        self,
        runner: CliRunner,
        user_home: Path,
        env: dict[str, str],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        agent: str,
    ) -> None:
        outside = tmp_path / "outside-user-config"
        outside.mkdir()
        root = user_home / f"custom-{agent}"
        root.symlink_to(outside, target_is_directory=True)
        variable = "CLAUDE_CONFIG_DIR" if agent == "claude" else "CODEX_HOME"
        monkeypatch.setenv(variable, str(root))
        before_home = _tree_content_inventory(user_home)
        before_outside = _tree_content_inventory(outside)

        result = runner.invoke(cli, ["init", "--scope", "user", "--agent", agent])
        assert result.exit_code != 0
        assert _tree_content_inventory(user_home) == before_home
        assert _tree_content_inventory(outside) == before_outside

    @pytest.mark.parametrize("agent", ("claude", "codex"))
    def test_non_directory_managed_root_fails_without_touching_boundary(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        agent: str,
    ) -> None:
        root = workspace / f".{agent}"
        root.write_bytes(b"blocking component\n")
        before = _tree_content_inventory(workspace)

        result = runner.invoke(
            cli,
            ["init", "--workspace-dir", str(workspace), "--agent", agent],
        )
        assert result.exit_code != 0
        assert _tree_content_inventory(workspace) == before


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



class TestObserveProject:
    @pytest.mark.parametrize("output_format", ("json", "text"))
    def test_failed_task_anomaly_is_active_only_on_real_cli_surfaces(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
        output_format: str,
    ) -> None:
        from unrest_harness.config import HarnessConfig
        from unrest_harness.models import (
            Aborted,
            Done,
            MissionRunning,
            Task,
            TaskList,
            TaskStateEntry,
            TaskStateFile,
        )
        from unrest_harness.storage import ProjectStore

        store = ProjectStore(HarnessConfig.discover())
        task = Task(
            id="failed-work",
            type="work",
            body="body",
            targets=["VAL-STATUS-001"],
            skill="worker",
        )
        for project_id, state in (
            ("running-status", MissionRunning(mission_id="mission-001")),
            ("done-status", Done()),
            ("aborted-status", Aborted(reason="operator")),
        ):
            record = store.create_project("status", workspace, project_id=project_id)
            record.current_mission_id = "mission-001"
            store.save_project(record)
            store.save_task_list(
                project_id,
                "mission-001",
                TaskList(tasks=[task]),
            )
            store.save_task_state(
                project_id,
                "mission-001",
                TaskStateFile(
                    tasks={"failed-work": TaskStateEntry(status="failed")}
                ),
            )
            store.save_state(project_id, state)

        def codes_for(project_id: str) -> str:
            result = runner.invoke(
                cli,
                ["observe-project", project_id, "--format", output_format],
            )
            assert result.exit_code == 0, result.output
            if output_format == "json":
                return " ".join(json.loads(result.output)["codes"])
            return result.output

        assert "failed_task_without_attention" in codes_for("running-status")
        assert "failed_task_without_attention" not in codes_for("done-status")
        assert "failed_task_without_attention" not in codes_for("aborted-status")

        all_result = runner.invoke(
            cli,
            ["observe-project", "--all", "--strict", "--format", output_format],
        )
        assert all_result.exit_code == 0, all_result.output
        assert all_result.output.count("failed_task_without_attention") == 1

    def test_single_project_schema_v2_json_and_text_are_read_only(
        self,
        runner: CliRunner,
        workspace: Path,
        env: dict[str, str],
    ) -> None:
        from unrest_harness.config import HarnessConfig
        from unrest_harness.storage import ProjectStore

        store = ProjectStore(HarnessConfig.discover())
        store.create_project("observe", workspace, project_id="observe-one")
        before = _tree_snapshot(store.bucket_root("observe-one"))

        result = runner.invoke(
            cli,
            ["observe-project", "observe-one", "--format", "json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert list(payload) == [
            "schema_version",
            "observed_at",
            "project_id",
            "mission_id",
            "persisted_state",
            "derived_state",
            "attention_count",
            "running_task_ids",
            "runnable_task_ids",
            "failed_task_ids",
            "last_runtime_change_age_seconds",
            "codes",
        ]
        assert payload["schema_version"] == 2
        assert payload["project_id"] == "observe-one"
        assert payload["derived_state"] == "draft"
        assert "workspace" not in result.output

        text_result = runner.invoke(cli, ["observe-project", "observe-one"])
        assert text_result.exit_code == 0, text_result.output
        assert text_result.output.startswith("schema_version=2 observed_at=")
        assert " project_id=observe-one mission_id=- persisted_state=draft derived_state=draft " in text_result.output
        assert len(text_result.output.splitlines()) == 1
        assert _tree_snapshot(store.bucket_root("observe-one")) == before

    @pytest.mark.parametrize("output_format", ["json", "text"])
    @pytest.mark.parametrize(
        ("scenario", "default_exit", "strict_exit"),
        [
            ("empty", 0, 0),
            ("success", 0, 0),
            ("mixed", 0, 1),
            ("all_failed", 1, 1),
        ],
    )
    def test_all_exit_matrix_and_failure_isolation(
        self,
        runner: CliRunner,
        workspace: Path,
        harness_home: Path,
        env: dict[str, str],
        output_format: str,
        scenario: str,
        default_exit: int,
        strict_exit: int,
    ) -> None:
        from unrest_harness.config import HarnessConfig
        from unrest_harness.storage import ProjectStore

        store = ProjectStore(HarnessConfig.discover())
        if scenario in {"success", "mixed"}:
            store.create_project("good", workspace, project_id="good-one")
        if scenario in {"mixed", "all_failed"}:
            broken = harness_home / "projects" / "broken-one" / ".unrest-runtime"
            broken.mkdir(parents=True)
            (broken / "project.json").write_text("{PRIVATE_BAD_JSON}", encoding="utf-8")
        if scenario == "empty":
            (harness_home / "projects").mkdir()

        arguments = ["observe-project", "--all", "--format", output_format]
        ordinary = runner.invoke(cli, arguments)
        strict = runner.invoke(cli, [*arguments, "--strict"])
        assert ordinary.exit_code == default_exit, ordinary.output
        assert strict.exit_code == strict_exit, strict.output
        assert "PRIVATE_BAD_JSON" not in ordinary.output
        if output_format == "json":
            payload = json.loads(ordinary.output)
            assert list(payload) == ["schema_version", "observed_at", "projects", "failures"]
            assert [item["project_id"] for item in payload["projects"]] == (
                ["good-one"] if scenario in {"success", "mixed"} else []
            )
            assert [item for item in payload["failures"]] == (
                [{"project_id": "broken-one", "code": "malformed_cursor"}]
                if scenario in {"mixed", "all_failed"}
                else []
            )
        else:
            lines = ordinary.output.splitlines()
            assert sum("project_id=good-one" in line for line in lines) == (
                1 if scenario in {"success", "mixed"} else 0
            )
            assert sum(line == "failure project=broken-one code=malformed_cursor" for line in lines) == (
                1 if scenario in {"mixed", "all_failed"} else 0
            )

    @pytest.mark.parametrize(
        ("arguments", "code"),
        [
            ([], "invalid_project_id"),
            (["one", "--all"], "invalid_project_id"),
            (["../outside"], "invalid_project_id"),
            (["ghost"], "project_not_found"),
            (["--all", "--format", "PRIVATE_FORMAT"], "invalid_format"),
            (["--all", "--stale-after-seconds", "PRIVATE_THRESHOLD"], "invalid_stale_threshold"),
            (["--all", "--stale-after-seconds", "0"], "invalid_stale_threshold"),
        ],
    )
    def test_selector_and_option_errors_are_closed_and_value_free(
        self,
        runner: CliRunner,
        env: dict[str, str],
        arguments: list[str],
        code: str,
    ) -> None:
        result = runner.invoke(cli, ["observe-project", *arguments])
        assert result.exit_code != 0
        assert result.output == f"Error: {code}\n"
        assert "PRIVATE_" not in result.output
        assert "Traceback" not in result.output

    def test_strict_requires_all(
        self,
        runner: CliRunner,
        env: dict[str, str],
    ) -> None:
        result = runner.invoke(cli, ["observe-project", "one", "--strict"])
        assert result.exit_code == 1
        assert result.output == "Error: invalid_project_id\n"
