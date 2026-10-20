"""Derived mypy storage configuration for the authenticated original duty only."""
from __future__ import annotations

import json
from pathlib import Path
import sys

DUTY = 'Type-check (mypy)'
SETTING = {'MYPY_CACHE_DIR': '/dev/null'}


def configured_environment(initial, script, workflow, supplied):
    from ci_commands import bind_generated
    from primary_policy import plan
    if 'MYPY_CACHE_DIR' in initial:
        raise RuntimeError('type_cache_initial_environment')
    duty = bind_generated(script, workflow)
    if duty['name'] != DUTY:
        return dict(initial)
    expected = plan(script, workflow)
    if (supplied != expected or expected['commands'] != [['uv', 'run', 'mypy', 'src']]
            or expected.get('source_mode') is not None or expected.get('package_mode') is not None):
        raise RuntimeError('type_cache_duty_binding')
    return {**initial, **SETTING}


def runtime_environment(initial, *, source):
    # SOURCE retains its exact environment. Synthetic controls have no /inputs;
    # real primary capsules authenticate these immutable inputs before this call.
    if source or sys.platform != 'linux' or not Path('/inputs').is_dir():
        return initial
    return configured_environment(initial, Path('/inputs/github-script.sh').read_bytes(),
                                  Path('/source/.github/workflows/ci.yml').read_text(),
                                  json.loads(Path('/inputs/plan.json').read_bytes()))
