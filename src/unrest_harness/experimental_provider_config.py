"""Pinned provider startup controls and private, body-free context seals.

Authentication stores are deliberately excluded: the existing managed login is
shared operational infrastructure, not copied into role homes. These controls
do not establish OS isolation or effective live-provider compatibility.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import tomllib
from typing import Any, Callable, Iterator, Literal

from .experimental_diagnostics import startup_timeout
from .experimental_lease import LeaseRefused

CATALOGUE_SHA256 = 'fd219bd9f061278275f528939f82f54d2eb97df4b25c23b022adbe48813d920b'
CATALOGUE = Path(__file__).parent / 'provider_data/codex-rust-v0.160.1-models.json'
CONTROLS: dict[str, Any] = {
    'model': 'gpt-6-astra', 'model_reasoning_effort': 'medium',
    'model_provider': 'openai', 'forced_login_method': 'chatgpt',
    'sandbox_mode': 'read-only', 'approval_policy': 'never',
    'project_doc_max_bytes': 0, 'history.persistence': 'none',
    'skills.bundled.enabled': False, 'cloud.skills.enabled': False,
    'memories.generate_memories': False, 'memories.use_memories': False,
    'memories.dedicated_tools': False,
    **{'features.' + name: False for name in (
        'memories', 'external_agent_memory_import', 'context_management', 'token_budget',
        'plugins', 'recommended_plugins', 'hooks', 'apps', 'enable_mcp_apps',
        'shell_tool', 'shell_snapshot', 'shell_snapshot_v2')},
}


# rust-v0.160.1 protocol/v2/config.rs: every other projected requirement is
# nullable, but none is omitted. This projection does not expose all policies.
FORCED_CHATGPT_REQUIREMENTS: dict[str, Any] = {
    **dict.fromkeys((
        'modelProvider modelProviders cliAuthCredentialsStore chatgptBaseUrl '
        'additionalDeveloperInstructions allowedApprovalPolicies allowedApprovalsReviewers '
        'allowedSandboxModes allowedWindowsSandboxImplementations allowedPermissionProfiles '
        'defaultPermissions allowedWebSearchModes allowManagedHooksOnly allowBrowserAndComputerUse '
        'allowAppshots allowRemoteControl computerUse browserUse inAppBrowser featureRequirements '
        'hooks enforceResidency network application autoReview models sqliteHome logDir '
        'modelCatalogJson checkForUpdateOnStartup allowLoginShell feedback').split()),
    'allowedLoginMethods': ['chatgpt'],
}
PREFLIGHT_FRAMES = 32
PREFLIGHT_BYTES = 262144


def _same(left: Any, right: Any) -> bool:
    """JSON equality without Python's bool/int/float aliases, at every depth."""
    if type(left) is not type(right):
        return False
    if isinstance(right, dict):
        return left.keys() == right.keys() and all(_same(left[k], v) for k, v in right.items())
    if isinstance(right, list):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right, strict=True))
    return bool(left == right)


def _frame(raw: bytes | bytearray, *, backend: bool = False) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise LeaseRefused('provider_protocol_json_invalid') from None
    if not isinstance(value, dict):
        raise LeaseRefused('provider_protocol_envelope_fields')
    if 'id' in value and type(value['id']) not in (str, int):
        raise LeaseRefused('provider_protocol_envelope_fields')
    if 'jsonrpc' in value and value['jsonrpc'] != '2.0':
        raise LeaseRefused('provider_protocol_envelope_fields')
    notification = backend and 'method' in value and 'id' not in value
    if 'emittedAtMs' in value:
        stamp = value['emittedAtMs']
        if (not notification or (stamp is not None and
                (type(stamp) is not int or not -(2 ** 63) <= stamp < 2 ** 63))):
            raise LeaseRefused('provider_protocol_envelope_fields')
    if 'method' in value:
        if (type(value['method']) is not str or 'result' in value or 'error' in value
                or set(value) - ({'jsonrpc', 'id', 'method', 'params'}
                                 | ({'emittedAtMs'} if notification else set()))
                or ('params' in value and not isinstance(value['params'], dict))):
            raise LeaseRefused('provider_protocol_envelope_fields')
    elif ('id' not in value or ('result' in value) == ('error' in value)
          or set(value) - {'jsonrpc', 'id', 'result', 'error'}):
        raise LeaseRefused('provider_protocol_envelope_fields')
    if 'error' in value:
        error = value['error']
        if (not isinstance(error, dict) or set(error) - {'code', 'message', 'data'}
                or type(error.get('code')) is not int or type(error.get('message')) is not str):
            raise LeaseRefused('provider_protocol_envelope_fields')
    return value


# Public rust-v0.160.1 AccountUpdatedNotification schema. Optional protocol
# fields do not relax the managed-account admission policy below.
AUTH_MODES = frozenset(('apikey', 'chatgpt', 'chatgptAuthTokens', 'headers',
                       'agentIdentity', 'personalAccessToken', 'bedrockApiKey', 'bedrockAccessKeys'))
PLAN_TYPES = frozenset(('free', 'go', 'plus', 'pro', 'prolite', 'promax', 'team',
    'self_serve_business_prolite', 'self_serve_business_usage_based', 'business', 'ent26',
    'enterprise_cbp_automation', 'enterprise_cbp_usage_based', 'enterprise',
    'edu', 'edu_plus', 'edu_pro', 'unknown'))


def _notification(frame: dict[str, Any]) -> dict[str, Any]:
    """Exact supported startup schemas; strings are data, never instructions."""
    method, params = frame.get('method'), frame.get('params')
    if 'id' in frame:
        raise LeaseRefused('provider_configuration_protocol_invalid')
    if method not in ('account/updated', 'configWarning', 'remoteControl/status/changed'):
        raise LeaseRefused('provider_notification_unsupported')
    if not isinstance(params, dict):
        raise LeaseRefused('provider_notification_invalid')
    valid = False
    if method == 'account/updated':
        valid = not (set(params) - {'authMode', 'planType'})
        for key, choices in (('authMode', AUTH_MODES), ('planType', PLAN_TYPES)):
            value = params.get(key)
            valid &= value is None or (type(value) is str and value in choices)
    elif method == 'configWarning':
        valid = (not (set(params) - {'summary', 'details', 'path', 'range'})
                 and type(params.get('summary')) is str
                 and all(params.get(k) is None or type(params[k]) is str for k in ('details', 'path')))
        span = params.get('range')
        if span is not None:
            valid &= isinstance(span, dict) and set(span) == {'start', 'end'}
            if valid:
                for position in span.values():
                    valid &= (isinstance(position, dict) and set(position) == {'line', 'column'}
                              and all(type(v) is int and 0 <= v < 2 ** 64 for v in position.values()))
    else:
        valid = (not (set(params) - {'status', 'serverName', 'installationId', 'environmentId'})
                 and all(type(params.get(k)) is str for k in ('serverName', 'installationId'))
                 and (params.get('environmentId') is None or type(params['environmentId']) is str)
                 and params.get('status') == 'disabled')
    if not valid:
        raise LeaseRefused('provider_notification_invalid')
    return params


def _never_only(raw: bytes | bytearray) -> bytes:
    # Locate tokens with the JSON decoder after envelope/duplicate validation;
    # rewriting the object would also alter unrelated whitespace and escapes.
    text = bytes(raw).decode('utf-8')
    decoder = json.JSONDecoder()

    def members(start: int) -> list[tuple[str, int, int]]:
        offset = start + 1
        result: list[tuple[str, int, int]] = []
        while True:
            while text[offset].isspace() or text[offset] == ',':
                offset += 1
            if text[offset] == '}':
                return result
            key, offset = decoder.raw_decode(text, offset)
            while text[offset].isspace() or text[offset] == ':':
                offset += 1
            begin = offset
            _, offset = decoder.raw_decode(text, offset)
            result.append((key, begin, offset))

    for key, begin, _ in members(len(text) - len(text.lstrip())):
        if key == 'params':
            for name, start, end in members(begin):
                if name == 'approvalPolicy':
                    return (text[:start] + '"never"' + text[end:]).encode('utf-8')
    raise LeaseRefused('provider_turn_permissions_changed')


def _toml(value: Any) -> str:
    if type(value) in (str, bool, int):
        return json.dumps(value, ensure_ascii=False)
    if type(value) is list:
        return '[' + ','.join(_toml(v) for v in value) + ']'
    if type(value) is dict:
        return '{' + ','.join(json.dumps(k, ensure_ascii=False) + '=' + _toml(v)
                              for k, v in sorted(value.items())) + '}'
    raise LeaseRefused('unsupported_provider_override')


class CommonInputs:
    """Explicit small read footprint; membership, absence, links and modes count.

    Callers supply configuration and contextual roots only, never a whole home
    or an authentication store. Source bodies remain in memory. Errors refuse;
    neither unreadable input nor missing input is silently treated as empty.
    """

    def __init__(self, paths: tuple[Path, ...], *, runtime_root: Path | None = None):
        if any(not p.is_absolute() or '..' in p.parts for p in paths):
            raise LeaseRefused('provider_input_location')
        if runtime_root is not None and (not runtime_root.is_absolute() or '..' in runtime_root.parts):
            raise LeaseRefused('provider_input_location')
        self.paths = tuple(sorted(set(paths)))
        self.runtime_root = runtime_root
        self.expected = self._observe()

    def _runtime_context(self) -> None:
        # Fresh private storage may grow, but it may not become another implicit
        # config/skill source. Check names only; never inspect runtime file bodies.
        if self.runtime_root is None:
            return
        pending = [self.runtime_root]
        count = 0
        deadline = time.monotonic() + 5
        while pending:
            path = pending.pop()
            if time.monotonic() >= deadline:
                raise LeaseRefused('provider_input_bound')
            try:
                mode = path.lstat().st_mode
            except FileNotFoundError:
                if path == self.runtime_root:
                    continue
                raise LeaseRefused('provider_runtime_context_changed') from None
            if not stat.S_ISDIR(mode):
                raise LeaseRefused('unsupported_provider_runtime_context')
            children = []
            with os.scandir(path) as stream:
                for child in stream:
                    count += 1
                    if count > 8192 or time.monotonic() >= deadline:
                        raise LeaseRefused('provider_input_bound')
                    if child.name.casefold() in ('.codex', '.agents', 'config.toml') or child.is_symlink():
                        raise LeaseRefused('undeclared_provider_runtime_context')
                    if child.is_dir(follow_symlinks=False):
                        children.append(Path(child.path))
            pending.extend(reversed(sorted(children)))

    def _observe(self) -> str:
        digest = hashlib.sha256()
        count = size = 0
        deadline = time.monotonic() + 5
        pending: list[tuple[Path, frozenset[Path]]] = [(p, frozenset()) for p in reversed(self.paths)]
        try:
            self._runtime_context()
            if self.runtime_root is not None:
                digest.update(b'no-runtime-context-v1\0' + str(self.runtime_root).encode() + b'\0')
            while pending:
                path, ancestors = pending.pop()
                count += 1
                if count > 8192 or size > 64 * 1048576 or time.monotonic() >= deadline:
                    raise LeaseRefused('provider_input_bound')
                if path.name.casefold() in ('auth.json', 'auth.json.bak', 'credentials.json'):
                    raise LeaseRefused('authentication_store_not_context')
                digest.update(str(path).encode() + b'\0')
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    digest.update(b'absent\0')
                    continue
                digest.update(str(stat.S_IMODE(info.st_mode)).encode() + b'\0')
                if stat.S_ISLNK(info.st_mode):
                    target = path.resolve(strict=True)
                    if target in ancestors:
                        raise LeaseRefused('provider_input_cycle')
                    digest.update(os.readlink(path).encode() + b'\0')
                    pending.append((target, ancestors | {path, target}))
                elif stat.S_ISDIR(info.st_mode):
                    children: list[Path] = []
                    with os.scandir(path) as stream:
                        for child in stream:
                            if count + len(pending) + len(children) >= 8192:
                                raise LeaseRefused('provider_input_bound')
                            children.append(Path(child.path))
                    pending.extend((p, ancestors | {path}) for p in reversed(sorted(children)))
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 1048576:
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    try:
                        before = os.fstat(fd)
                        if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                            raise LeaseRefused('provider_input_changed')
                        with os.fdopen(fd, 'rb', closefd=False) as file:
                            raw = file.read(1048577)
                        after = os.fstat(fd)
                        def stable(value: os.stat_result) -> tuple[int, ...]:
                            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                        if (len(raw) != info.st_size or stable(before) != stable(after)
                                or stable(path.lstat()) != stable(after)):
                            raise LeaseRefused('provider_input_changed')
                        size += len(raw)
                        if size > 64 * 1048576:
                            raise LeaseRefused('provider_input_bound')
                        digest.update(hashlib.sha256(raw).digest())
                    finally:
                        os.close(fd)
                else:
                    raise LeaseRefused('unsupported_provider_input')
        except OSError:
            raise LeaseRefused('provider_input_unreadable') from None
        return digest.hexdigest()

    def verify(self) -> None:
        if self._observe() != self.expected:
            raise LeaseRefused('provider_common_inputs_changed')


class ProviderConfig:
    """Construct startup argv and identical thread overrides without launching.

    Managed/cloud effective layers must be checked by the independent live
    admission probe; they cannot be inferred from the local file observations.
    """

    def __init__(self, *, codex_home: Path, user_home: Path, cwd: Path,
                 ambient: dict[str, Any], system: Path = Path('/private/etc/codex')):
        try:
            if not isinstance(ambient, dict):
                raise LeaseRefused('provider_configuration_unresolved')
            if hashlib.sha256(CATALOGUE.read_bytes()).hexdigest() != CATALOGUE_SHA256:
                raise LeaseRefused('provider_catalogue_mismatch')
            config_paths = [system / 'config.toml', codex_home / 'config.toml']
            config_paths.extend(p / '.codex/config.toml' for p in reversed(cwd.parents))
            config_paths.extend((cwd / '.codex/config.toml', cwd / 'config.toml'))
            roots = [codex_home / 'skills', user_home / '.agents/skills', system / 'skills']
            roots.extend(p / '.agents/skills' for p in (*reversed(cwd.parents), cwd))
            roots.extend(p / '.codex/skills' for p in (*reversed(cwd.parents), cwd))
            paths = [*config_paths, *roots, CATALOGUE,
                     codex_home / 'AGENTS.override.md', codex_home / 'AGENTS.md',
                     codex_home / 'rules', system / 'requirements.toml',
                     system / 'managed_config.toml']
            # The wire projection omits several policy families. Until their
            # sources are supported, sealing an existing file is not admission.
            if any(os.path.lexists(path) for path in
                   (system / 'requirements.toml', system / 'managed_config.toml')):
                raise LeaseRefused('provider_managed_requirements_unresolved')
            self.layer_files = {
                'system': {system / 'config.toml'},
                'user': {codex_home / 'config.toml'},
                'project': {p for p in config_paths[2:] if p.parent.name == '.codex'},
            }
            configs = []
            for path in config_paths:
                try:
                    configs.append((path.parent, tomllib.loads(path.read_text())))
                except FileNotFoundError:
                    continue
            configs.append((codex_home, ambient))
            self.servers: set[str] = set()
            for directory, config in configs:
                self._inspect(config, directory, paths)
            self.inputs = CommonInputs(tuple(paths), runtime_root=cwd)
            self.global_instructions = 'absent'
            for label, filename in (('override', 'AGENTS.override.md'), ('default', 'AGENTS.md')):
                try:
                    raw = (codex_home / filename).read_bytes()
                except FileNotFoundError:
                    continue
                if raw.decode('utf-8', errors='replace').strip():
                    self.global_instructions = label
                    break
            self.skills: set[str] = set()
            pending = list(roots)
            seen: set[Path] = set()
            while pending:
                path = pending.pop()
                resolved = path.resolve()
                if resolved in seen or not path.exists():
                    continue
                seen.add(resolved)
                if path.is_dir():
                    pending.extend(sorted(path.iterdir()))
                elif path.name == 'SKILL.md':
                    self.skills.add(str(resolved))
            self.inputs.verify()
            self.codex_home = codex_home
            self.user_home = user_home
            self.account_digest: str | None = None
            self.effective_digests: dict[str, str] = {}
            self.startup_digests: dict[str, str] = {}
        except (OSError, ValueError) as error:
            if isinstance(error, LeaseRefused):
                raise
            raise LeaseRefused('provider_configuration_unresolved') from None

    def _inspect(self, config: dict[str, Any], directory: Path, paths: list[Path]) -> None:
        registrations = config.get('mcp_servers', {})
        if not isinstance(registrations, dict):
            raise LeaseRefused('provider_mcp_unresolved')
        if 'unrest_turn_broker' in registrations:
            raise LeaseRefused('provider_broker_name_collision')
        self.servers.update(registrations)
        for key in ('model_instructions_file', 'experimental_compact_prompt_file'):
            value = config.get(key)
            if value is not None:
                if type(value) is not str:
                    raise LeaseRefused('provider_instruction_unresolved')
                path = Path(value)
                paths.append(path if path.is_absolute() else directory / path)
        profile = config.get('profile')
        if profile is not None:
            # External profile selection changes the layer stack; do not infer
            # the effective stack from an incomplete local dictionary.
            raise LeaseRefused('provider_profile_unresolved')

    def overrides(self, role_root: Path) -> dict[str, Any]:
        if (self.inputs.runtime_root is None or not role_root.is_absolute() or '..' in role_root.parts
                or not role_root.is_relative_to(self.inputs.runtime_root)):
            raise LeaseRefused('provider_role_outside_declared_runtime')
        self.inputs.verify()
        values = {**CONTROLS, 'sqlite_home': str(role_root / 'sqlite'),
                  'log_dir': str(role_root / 'logs'), 'model_catalog_json': str(CATALOGUE),
                  'skills.config': [{'path': path, 'enabled': False} for path in sorted(self.skills)]}
        # CLI keys split on literal dots; repeated root values replace rather
        # than merge within that layer. Quote server names only inside one RHS.
        values['mcp_servers'] = {name: {'enabled': False} for name in sorted(self.servers)}
        self.startup_digests[str(role_root)] = hashlib.sha256(
            json.dumps(values, sort_keys=True).encode()).hexdigest()
        return values

    def argv(self, executable: Path, role_root: Path) -> list[str]:
        values = self.overrides(role_root)
        return [str(executable), *(part for key, value in sorted(values.items())
                                  for part in ('-c', key + '=' + _toml(value))), 'app-server']

    def thread_config(self, role_root: Path) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in self.overrides(role_root).items():
            table = result
            parts = key.split('.')
            for part in parts[:-1]:
                table = table.setdefault(part, {})
            table[parts[-1]] = value
        return result

    def evidence(self, role_root: Path) -> dict[str, Any]:
        return {'catalogue_sha256': CATALOGUE_SHA256, 'common_inputs_sha256': self.inputs.expected,
                'startup_override_sha256': self.startup_digests.get(str(role_root)),
                'disabled_inherited_mcp_count': len(self.servers),
                'global_instruction_selection': self.global_instructions,
                'managed_auth': 'shared', 'thread_persistence': 'exact_thread_id',
                'effective_live_configuration': 'unverified',
                'native_direct_writes': 'unverified_os_isolation'}

    def verify_effective(self, response: dict[str, Any], requirements: dict[str, Any],
                         account: dict[str, Any], role_root: Path) -> None:
        self.inputs.verify()
        actual = response.get('config')
        expected = self.thread_config(role_root)
        # Only the documented empty vector omission is equivalent to [].
        if (not self.skills and isinstance(actual, dict)
                and isinstance(actual.get('skills'), dict) and 'config' not in actual['skills']):
            expected['skills'].pop('config')
        def matches(left: Any, right: Any) -> bool:
            if isinstance(right, dict):
                return isinstance(left, dict) and all(matches(left.get(k), v) for k, v in right.items())
            return _same(left, right)
        if not matches(actual, expected):
            raise LeaseRefused('provider_effective_configuration_mismatch')
        assert isinstance(actual, dict)
        servers = actual.get('mcp_servers', {})
        if (not isinstance(servers, dict) or set(servers) != self.servers
                or any(not isinstance(v, dict) or v.get('enabled') is not False for v in servers.values())):
            raise LeaseRefused('provider_effective_mcp_unresolved')
        layers = response.get('layers')
        if not isinstance(layers, list) or not layers:
            raise LeaseRefused('provider_effective_layers_unresolved')
        for layer in layers:
            if (not isinstance(layer, dict) or not isinstance(layer.get('name'), dict)
                    or not {'name', 'version', 'config'} <= layer.keys()
                    or set(layer) - {'name', 'version', 'config', 'disabledReason'}
                    or type(layer['version']) is not str
                    or ('disabledReason' in layer and type(layer['disabledReason']) is not str)):
                raise LeaseRefused('provider_effective_layers_unresolved')
            source = layer['name']
            kind = source.get('type')
            shapes = {'sessionFlags': {'type'}, 'system': {'type', 'file'},
                      'user': {'type', 'file', 'profile'}, 'project': {'type', 'dotCodexFolder'}}
            if type(kind) is not str or kind not in shapes or set(source) != shapes[kind]:
                # Packaged defaults are excluded by this API; MDM, enterprise
                # and legacy managed layers have no authorized source here.
                raise LeaseRefused('provider_undeclared_configuration_layer')
            if kind == 'sessionFlags':
                continue
            if kind == 'user' and source['profile'] is not None:
                raise LeaseRefused('provider_profile_unresolved')
            path = source.get('file') if kind != 'project' else source['dotCodexFolder']
            if type(path) is not str or not Path(path).is_absolute() or '..' in Path(path).parts:
                raise LeaseRefused('provider_undeclared_configuration_layer')
            resolved = (Path(path) / 'config.toml' if kind == 'project' else Path(path)).resolve()
            if resolved not in {p.resolve() for p in self.layer_files[kind]}:
                raise LeaseRefused('provider_undeclared_configuration_layer')
        if not _same(requirements, {'requirements': FORCED_CHATGPT_REQUIREMENTS}):
            raise LeaseRefused('provider_managed_requirements_unresolved')
        identity = account.get('account')
        if not isinstance(identity, dict) or identity.get('type') != 'chatgpt':
            raise LeaseRefused('provider_managed_auth_required')
        account_digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        if self.account_digest is not None and self.account_digest != account_digest:
            raise LeaseRefused('provider_account_identity_changed')
        self.account_digest = account_digest
        self.effective_digests[str(role_root)] = hashlib.sha256(
            json.dumps(response, sort_keys=True).encode()).hexdigest()

    async def admit_bridge(self, adapter_reader: asyncio.StreamReader,
                           adapter_writer: asyncio.StreamWriter,
                           backend_reader: asyncio.StreamReader,
                           backend_writer: asyncio.StreamWriter, role_root: Path,
                           phase: Callable[[str], None] | None = None) -> None:
        """Read supported config/account metadata before releasing initialization.

        No prompt is sent, no credentials are read or refreshed, and the original
        initialize response is forwarded byte-for-byte only after admission.
        Responses stay private; only digests can enter controller evidence.
        """
        frames = size = 0
        forwarded: list[bytes] = []
        notifications: list[dict[str, Any]] = []

        async def read(reader: asyncio.StreamReader, *, backend: bool = False,
                       private: bool = False) -> tuple[bytes, dict[str, Any]]:
            nonlocal frames, size
            try:
                raw = await reader.readline()
            except ValueError:
                raise LeaseRefused('provider_configuration_reader_limit') from None
            frames += 1
            size += len(raw)
            if not raw:
                raise LeaseRefused('provider_configuration_eof')
            if not raw.endswith(b'\n'):
                raise LeaseRefused('provider_configuration_unterminated_frame')
            if len(raw) > (PREFLIGHT_BYTES if private else 65536):
                raise LeaseRefused('provider_configuration_frame_bound')
            if frames > PREFLIGHT_FRAMES:
                raise LeaseRefused('provider_configuration_frame_count_bound')
            if size > PREFLIGHT_BYTES:
                raise LeaseRefused('provider_configuration_aggregate_bound')
            frame = _frame(raw, backend=backend)
            if 'method' in frame and len(raw) > 65536:
                raise LeaseRefused('provider_configuration_frame_bound')
            return raw, frame

        async def write(writer: asyncio.StreamWriter, raw: bytes) -> None:
            writer.write(raw)
            await writer.drain()

        async def reply(identifier: str | int, *, private: bool = False) -> tuple[bytes, dict[str, Any]]:
            while True:
                raw, response = await read(backend_reader, backend=True, private=private)
                if 'method' not in response:
                    if not _same(response.get('id'), identifier):
                        raise LeaseRefused('provider_configuration_response_id_mismatch')
                    if 'error' in response:
                        raise LeaseRefused('provider_configuration_error_response')
                    if not isinstance(response.get('result'), dict):
                        raise LeaseRefused('provider_configuration_protocol_invalid')
                    return raw, response['result']
                params = _notification(response)
                if response['method'] == 'account/updated':
                    if params.get('authMode') != 'chatgpt':
                        raise LeaseRefused('provider_managed_auth_required')
                    notifications.append(params)
                forwarded.append(raw)

        async def request(method: str, params: dict[str, Any]) -> dict[str, Any]:
            identifier = 'unrest-preflight-' + method
            await write(backend_writer, (json.dumps({
                'id': identifier, 'method': method, 'params': params}) + '\n').encode())
            _, result = await reply(identifier, private=True)
            return result

        def mark(stage: str) -> None:
            if phase is not None:
                phase(stage)

        async with startup_timeout(None, 'provider_preflight'):
            mark('preflight_initialize')
            mark('initialize_frame_wait')
            raw, initialize = await read(adapter_reader)
            if initialize.get('method') != 'initialize' or 'id' not in initialize:
                raise LeaseRefused('provider_initialize_required')
            mark('initialize_frame_received')
            mark('initialize_write_wait')
            await write(backend_writer, raw)
            mark('initialize_write_complete')
            mark('initialize_response_wait')
            response_raw, _ = await reply(initialize['id'])
            mark('initialize_response_received')
            forwarded.append(response_raw)
            mark('config_read')
            effective = await request('config/read', {'includeLayers': True, 'cwd': str(role_root)})
            mark('requirements_read')
            requirements = await request('configRequirements/read', {})
            mark('account_read')
            account = await request('account/read', {'refreshToken': False})
            mark('effective_verify')
            self.verify_effective(effective, requirements, account, role_root)
            identity = account['account']
            if any(n.get('planType') is not None and n['planType'] != identity.get('planType')
                   for n in notifications):
                raise LeaseRefused('provider_account_changed')
            # Preserve authorized notification/initialize order and bytes; never
            # forward the private preflight replies. Nothing is released on failure.
            mark('initialize_release')
            await write(adapter_writer, b''.join(forwarded))


@dataclass(frozen=True)
class _ConfigSeal:
    digest: str
    cwd: str
    verify: Callable[[], None]


class ThreadObservation:
    """Bounded protocol observations without retaining prompts or response bodies."""

    def __init__(self, config: dict[str, Any] | None = None,
                 broker: dict[str, Any] | None = None) -> None:
        self._adapter = bytearray()
        self._backend = bytearray()
        self._restricted = bytearray()
        self._backend_pending = bytearray()
        self._start_id: str | int | None = None
        self.session: str | None = None
        self.served: dict[str, str] | None = None
        self._config, self._broker = config, broker
        self._seal: _ConfigSeal | None = None
        self._config_state: Literal['unavailable', 'eligible', 'pending', 'spent'] = 'unavailable'
        self._config_id: tuple[type, str | int] | None = None
        self._outstanding: set[tuple[type, str | int]] = set()

    def seal_configuration(self, digest: str, cwd: str, verify: Callable[[], None]) -> None:
        """Called once, only after the complete private admission returns."""
        if self._config_state != 'unavailable' or self._seal is not None or self._start_id is not None:
            self.stop()
            raise LeaseRefused('provider_configuration_protocol_invalid')
        self._seal = _ConfigSeal(digest, cwd, verify)
        self._config_state = 'eligible'

    def stop(self) -> None:
        self._config_state = 'spent'
        self._outstanding.clear()
        for buffer in (self._adapter, self._backend, self._restricted, self._backend_pending):
            buffer.clear()

    def restrict_adapter(self, data: bytes) -> bytes:
        """Tighten the pinned adapter's read-only/on-request turn to never.

        codex-acp 1.1.0 hardcodes on-request in its read-only preset and sends
        that per-turn override after thread creation. Changing the provider's
        startup setting alone cannot pin never. Preserve other frames byte for
        byte and every other turn field; never select a wider sandbox preset.
        """
        self._restricted.extend(data)
        output = bytearray()
        while b'\n' in self._restricted:
            raw, _, remaining = self._restricted.partition(b'\n')
            self._restricted[:] = remaining
            if len(raw) > 65536:
                raise LeaseRefused('provider_protocol_bound')
            frame = _frame(raw)
            if isinstance(frame, dict) and frame.get('method') == 'turn/start':
                params = frame.get('params')
                if not isinstance(params, dict) or params.get('approvalPolicy') not in ('on-request', 'never'):
                    raise LeaseRefused('provider_turn_permissions_changed')
                sandbox = params.get('sandboxPolicy')
                if not _same(sandbox, {'type': 'readOnly', 'networkAccess': False}):
                    raise LeaseRefused('provider_turn_permissions_changed')
                if params['approvalPolicy'] == 'on-request':
                    raw = bytearray(_never_only(raw))
            output.extend(raw + b'\n')
        if len(self._restricted) > 65536:
            raise LeaseRefused('provider_protocol_bound')
        return bytes(output)

    def _frames(self, buffer: bytearray, data: bytes, *, backend: bool = False) -> Iterator[dict[str, Any]]:
        buffer.extend(data)
        while b'\n' in buffer:
            raw, _, remaining = buffer.partition(b'\n')
            pending = backend and self._config_state == 'pending'
            if len(raw) > (PREFLIGHT_BYTES - 1 if pending else 65536):
                raise LeaseRefused('provider_protocol_bound')
            buffer[:] = remaining
            value = _frame(raw, backend=backend)
            matching = ('method' not in value and 'id' in value
                        and (type(value['id']), value['id']) == self._config_id)
            if len(raw) > 65536 and not (pending and matching):
                raise LeaseRefused('provider_protocol_bound')
            yield value
        limit = PREFLIGHT_BYTES - 1 if backend and self._config_state == 'pending' else 65536
        if len(buffer) > limit:
            raise LeaseRefused('provider_protocol_bound')

    def adapter(self, data: bytes) -> None:
        try:
            self._observe_adapter(data)
        except BaseException:
            self.stop()
            raise

    def _observe_adapter(self, data: bytes) -> None:
        for frame in self._frames(self._adapter, data):
            method = frame.get('method')
            params = frame.get('params', {})
            if not isinstance(params, dict):
                raise LeaseRefused('provider_protocol_invalid')
            identifier = frame.get('id')
            key: tuple[type, str | int] | None = None
            if isinstance(identifier, (str, int)) and type(identifier) in (str, int):
                key = (type(identifier), identifier)
            if method is not None and key is not None:
                if key == self._config_id or key in self._outstanding:
                    raise LeaseRefused('provider_configuration_response_id_mismatch')
                if self._start_id is None:
                    if len(self._outstanding) >= PREFLIGHT_FRAMES:
                        raise LeaseRefused('provider_protocol_bound')
                    self._outstanding.add(key)
            if method == 'config/read':
                if (self._config_state != 'eligible' or self._seal is None or key is None
                        or not _same(params, {'includeLayers': True, 'cwd': self._seal.cwd})):
                    raise LeaseRefused('provider_configuration_protocol_invalid')
                self._config_id = key
                self._config_state = 'pending'
            if method == 'thread/start':
                if self._config_state == 'pending':
                    raise LeaseRefused('provider_configuration_protocol_invalid')
                self._config_state = 'spent'
                self._outstanding.clear()
                if self._start_id is not None or self.session is not None:
                    raise LeaseRefused('provider_extra_thread')
                identifier = frame.get('id')
                if type(identifier) not in (str, int):
                    raise LeaseRefused('provider_protocol_invalid')
                self._start_id = identifier
                if self._config is not None:
                    config = params.get('config')
                    if not isinstance(config, dict):
                        raise LeaseRefused('provider_thread_configuration_changed')
                    for name, expected in self._config.items():
                        if name != 'mcp_servers' and not _same(config.get(name), expected):
                            raise LeaseRefused('provider_thread_configuration_changed')
                    # The pinned adapter replaces this thread-level map. The
                    # backend recursively merges it with the individually
                    # disabled registrations already verified at startup.
                    expected_servers = {'unrest_turn_broker': self._broker}
                    if not _same(config.get('mcp_servers'), expected_servers):
                        raise LeaseRefused('provider_thread_mcp_changed')
            elif isinstance(method, str) and method.startswith('thread/') and method != 'thread/unsubscribe':
                raise LeaseRefused('provider_cross_thread_operation')
            if method in ('turn/start', 'thread/unsubscribe'):
                if self.session is None or params.get('threadId') != self.session:
                    raise LeaseRefused('provider_wrong_thread')
            if method == 'turn/start':
                if (params.get('approvalPolicy') != 'never'
                        or not _same(params.get('sandboxPolicy'), {'type': 'readOnly', 'networkAccess': False})):
                    raise LeaseRefused('provider_turn_permissions_changed')

    def restrict_backend(self, data: bytes) -> bytes:
        # A fragment must not reach the adapter before the whole frame has been
        # observed. Bound the pending suffix independently of coalesced frames.
        self._backend_pending.extend(data)
        end = self._backend_pending.rfind(b'\n') + 1
        complete = bytes(self._backend_pending[:end])
        del self._backend_pending[:end]
        # backend() checks this suffix after sequentially consuming complete
        # frames: a config response may retire the allowance in this same read.
        return complete

    def backend(self, data: bytes) -> None:
        try:
            self._observe_backend(data)
            limit = PREFLIGHT_BYTES - 1 if self._config_state == 'pending' else 65536
            if len(self._backend_pending) > limit:
                raise LeaseRefused('provider_protocol_bound')
        except BaseException:
            self.stop()
            raise

    def _observe_backend(self, data: bytes) -> None:
        for frame in self._frames(self._backend, data, backend=True):
            if 'method' not in frame:
                key = (type(frame['id']), frame['id'])
                if self._config_state == 'pending' and key not in self._outstanding:
                    raise LeaseRefused('provider_configuration_response_id_mismatch')
                if key == self._config_id:
                    if self._config_state != 'pending':
                        raise LeaseRefused('provider_configuration_response_id_mismatch')
                    self._config_state = 'spent'
                    result = frame.get('result')
                    if 'error' in frame:
                        raise LeaseRefused('provider_configuration_error_response')
                    if (not isinstance(result, dict) or set(result) != {'config', 'origins', 'layers'}
                            or not isinstance(result['config'], dict)
                            or not isinstance(result['origins'], dict)
                            or not isinstance(result['layers'], list) or not result['layers']):
                        raise LeaseRefused('provider_configuration_protocol_invalid')
                    assert self._seal is not None
                    self._seal.verify()
                    digest = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
                    if digest != self._seal.digest:
                        raise LeaseRefused('provider_effective_configuration_mismatch')
                self._outstanding.discard(key)
            if frame.get('method') in ('configWarning', 'remoteControl/status/changed'):
                _notification(frame)
            if frame.get('method') == 'account/updated':
                raise LeaseRefused('provider_account_changed')
            if self._start_id is None or not _same(frame.get('id'), self._start_id):
                continue
            result = frame.get('result')
            if not isinstance(result, dict):
                raise LeaseRefused('provider_thread_start_failed')
            expected = {'model': 'gpt-6-astra', 'reasoningEffort': 'medium', 'modelProvider': 'openai'}
            if any(result.get(key) != value for key, value in expected.items()):
                raise LeaseRefused('provider_served_model_mismatch')
            thread = result.get('thread')
            session = thread.get('id') if isinstance(thread, dict) else None
            if type(session) is not str or not session or self.session is not None:
                raise LeaseRefused('provider_thread_identity_invalid')
            self.session, self.served = session, expected
