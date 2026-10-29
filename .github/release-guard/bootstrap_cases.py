"""Finite original bootstrap cases and fresh controlled configuration data.

These declarations select no provider and grant no execution on their own.
The host and source adapter separately verify original owners and live inputs.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from content_manifest import Refused

TEST = 'tests/test_experimental_bootstrap.py'
CATALOGUE = 'src/unrest_harness/provider_data/codex-rust-v0.160.1-models.json'
CATALOGUE_PIN = 'fd219bd9f061278275f528939f82f54d2eb97df4b25c23b022adbe48813d920b'


@dataclass(frozen=True)
class Case:
    name: str
    delay: int | float | None
    configured: bool
    children: int

    @property
    def broker_http(self):
        return self.name == 'test_delayed_turn_uses_only_original_remaining_time'

    @property
    def interrupted(self):
        return (self.name.startswith('test_actual_launch_lifetime_and_interruptions[')
                or self.name.startswith('test_original_limits_refuse_before_grant_or_send['))

    @property
    def nodeid(self):
        return TEST + '::' + self.name


DECLARATIONS = (
    Case('test_actual_thirty_two_second_readiness', 32, True, 2),
    Case('test_actual_launch_lifetime_and_interruptions[near]', 60, True, 2),
    Case('test_actual_launch_lifetime_and_interruptions[exhausted]', 60, True, 0),
    Case('test_actual_launch_lifetime_and_interruptions[cancel]', 60, True, 2),
    Case('test_actual_launch_lifetime_and_interruptions[stop]', 60, True, 2),
    Case('test_phases_share_one_deadline_across_tasks', None, False, 0),
    Case('test_absolute_ledger_includes_setup_and_cleanup', None, False, 0),
    Case('test_capped_body_free_observation_is_pre_cleanup', None, False, 0),
    Case('test_turn_reservation_does_not_restart_clock_after_bootstrap', None, False, 0),
    Case('test_delayed_turn_uses_only_original_remaining_time', 32, False, 2),
    *(Case(f'test_original_limits_refuse_before_grant_or_send[{expired}-{limit}]',60,False,0 if expired else 2)
      for expired in (False,True) for limit in ('turn','episode','campaign')),
    *(Case(f'test_boundary_recheck_blocks_expired_or_stopped_send[{action}-{boundary}]',None,False,2)
      for action in ('expire','stop') for boundary in ('reserve','grant','send','serialize')),
    Case('test_actual_sequential_initialize_and_session_share_cutoff', None, False, 2),
    Case('test_startup_subtracts_from_actual_inference_timeout', 0.5, False, 2),
    Case('test_expiry_during_seal_cannot_publish_grant', None, False, 0),
)
BOOTSTRAP = tuple(case.nodeid for case in DECLARATIONS)
BY_CASE = {case.nodeid: case for case in DECLARATIONS}


def declaration(case):
    if type(case) is not str or case not in BY_CASE:
        raise Refused('unknown original bootstrap case')
    return BY_CASE[case]


def wrapper(case):
    delay = declaration(case).delay
    if delay is None:
        return None
    return ('import runpy,sys,time; p=sys.argv.pop(1); '
            f'time.sleep({delay!r}); runpy.run_path(p,run_name="__main__")')


CONTROLS = {
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


def toml(value):
    if type(value) in (str, int, bool):
        return json.dumps(value, ensure_ascii=False)
    if type(value) is list:
        return '[' + ','.join(toml(item) for item in value) + ']'
    if type(value) is dict:
        return '{' + ','.join(json.dumps(key, ensure_ascii=False) + '=' + toml(item) for key, item in sorted(value.items())) + '}'
    raise Refused('closed configuration value')


def configuration(checkout: Path, home: Path, *, servers: tuple[str,...] = (), skills: tuple[str,...] = ()):
    values = {**CONTROLS, 'sqlite_home': str(home / 'sqlite'), 'log_dir': str(home / 'logs'),
              'model_catalog_json': str(checkout / CATALOGUE),
              'skills.config': [{'path':value,'enabled':False} for value in sorted(skills)],
              'mcp_servers': {name:{'enabled':False} for name in sorted(servers)}}
    arguments = [part for key, value in sorted(values.items()) for part in ('-c', key + '=' + toml(value))]
    nested: dict[str, Any] = {}
    for key, value in values.items():
        table = nested
        parts = key.split('.')
        for part in parts[:-1]:
            table = table.setdefault(part, {})
        table[parts[-1]] = value
    return arguments, json.dumps(nested, sort_keys=True)
