"""Finite controlled backend argv rendered by the original pinned configuration."""

import hashlib
import inspect
import json
import os
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def admit(argv, cwd, env, state, append, refuse):
    source = Path(state["checkout"]) / "src/unrest_harness/experimental_session.py"
    frames = []
    frame = inspect.currentframe()
    try:
        while frame:
            frames.append(frame)
            frame = frame.f_back
        module = sys.modules.get("asyncio")
        try:
            task = module.current_task() if module is not None else None
        except RuntimeError:
            task = None
        coroutine = task.get_coro() if task is not None else None
        seen = set()
        while coroutine is not None and id(coroutine) not in seen:
            seen.add(id(coroutine))
            selected = getattr(coroutine, "cr_frame", None)
            if selected is not None:
                frames.append(selected)
            coroutine = getattr(coroutine, "cr_await", None)
        for frame in frames:
            if (
                Path(frame.f_code.co_filename).resolve() != source
                or frame.f_code.co_name != "_open_role_owned"
                or frame.f_code.co_firstlineno != 462
            ):
                continue
            local = frame.f_locals
            owner = local["self"]
            if owner.provider_config is None or owner.controlled is not True:
                return None
            if len(argv) < 3 or argv[1] != str(owner.backend_launcher):
                continue
            home = local["home"].resolve()
            config = owner.provider_config
            pin = state["product_pins"]["src/unrest_harness/experimental_session.py"]
            config_source = source.with_name("experimental_provider_config.py")
            if (
                sha(source) != pin
                or sha(config_source)
                != state["product_pins"]["src/unrest_harness/experimental_provider_config.py"]
                or owner.transport is None
                or owner.provider_package is not None
                or not home.is_relative_to(Path(state["owned_root"]))
                or any(
                    not Path(p).resolve().is_relative_to(Path(state["owned_root"]))
                    for p in (config.codex_home, config.user_home, config.inputs.runtime_root)
                )
            ):
                refuse("configured_controlled_backend_source_or_root")
            executable = str(owner.transport.interpreter.resolve())
            expected = [executable, *config.argv(owner.backend_launcher, home)]
            if (
                argv != expected
                or argv != local["argv"]
                or argv[-1] != "app-server"
                or argv[1] != str(owner.backend_launcher)
                or owner.backend_launcher.name != "fake-app-server"
                or sha(owner.backend_launcher)
                != sha(
                    Path(state["checkout"]) / "tests/fixtures/experimental_session_app_server.py"
                )
                or Path(cwd).resolve() != home
                or dict(os.environ if env is None else env) != local["backend_environment"]
            ):
                refuse("configured_controlled_backend_vector_or_environment")
            owner.transport.verify(controlled=True, package=None)
            binding = {
                "path": str(source),
                "line": 501,
                "sha256": pin,
                "function": "_open_role_owned",
                "configuration_source_sha256": sha(config_source),
            }
            append(
                {
                    "kind": "concrete_configured_backend_registration",
                    "source_binding": binding,
                    "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                    "cwd": str(home),
                    "environment_sha256": hashlib.sha256(
                        json.dumps(env, sort_keys=True).encode()
                    ).hexdigest(),
                    "script_sha256": sha(owner.backend_launcher),
                    "explicit_transport": "controlled=True",
                }
            )
            return {"class": "canonical-backend", "python": True, "source_binding": binding}
        return None
    finally:
        del frame
        frames.clear()
