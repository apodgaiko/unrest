"""Observe the selected image using the child's cwd and exact PATH search."""
from __future__ import annotations

import os
from pathlib import Path


def resolve(argv0, cwd, environment):
    directory = Path(os.getcwd() if cwd is None else cwd).absolute()
    if os.path.dirname(argv0):
        candidate = Path(argv0)
        return str(candidate if candidate.is_absolute() else directory / candidate)
    for entry in os.get_exec_path(environment):
        candidate = Path(entry) / argv0
        if not candidate.is_absolute():
            candidate = directory / candidate
        if candidate.is_file() and os.access(candidate, os.F_OK | os.X_OK):
            return str(candidate)
    raise FileNotFoundError('admitted launch image is no longer available')
