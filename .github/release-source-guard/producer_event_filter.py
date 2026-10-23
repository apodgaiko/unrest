"""Bind the pure live-record predicate to the already pinned native module."""
from __future__ import annotations

import importlib.util

from profile_gate_build import verify


def load():
    binding = verify()
    specification = importlib.util.spec_from_file_location('profile_gate', binding['module']['path'])
    if specification is None or specification.loader is None:
        raise RuntimeError('producer_event_predicate_loader')
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module.producer_events
