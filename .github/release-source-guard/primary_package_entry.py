"""Pre-body finite guard activation for the original PRIMARY archive script."""
from __future__ import annotations

import atexit
import hashlib
import json
import os
from pathlib import Path
import sys
import types


def load(name, path, pin):
    body = Path(path).read_bytes()
    if hashlib.sha256(body).hexdigest() != pin:
        os._exit(86)
    module = types.ModuleType(name)
    module.__file__ = path
    sys.modules[name] = module
    exec(compile(body, path, 'exec', dont_inherit=True), module.__dict__)
    return module


def activate(profile, event, arguments):
    path = profile['manifest']
    body = Path(path).read_bytes()
    if (hashlib.sha256(body).hexdigest() != profile['manifest_sha256']
            or profile['source_role'] != 'package-root'
            or event != 'cpython.run_file' or len(arguments) != 1
            or arguments[0] != '/source/tools/check_distribution.py'
            or hashlib.sha256(Path(arguments[0]).read_bytes()).hexdigest()
            != profile['console_source_sha256']):
        os._exit(86)
    manifest = json.loads(body)
    endpoint = load('endpoint', '/guard/finite/endpoint.py', manifest['endpoint']['sha256'])
    endpoint.early(manifest['endpoint'])
    sys._finite_source_bootstrap_gate = {'active': True}
    guard = load('runtime_guard', manifest['guard'], manifest['guard_sha256'])
    endpoint.attach(guard)
    if manifest['source_case'] not in {'PRIMARY-package-TEST', 'PRIMARY-package-FULL'}:
        os._exit(86)
    guard.install(path, profile['manifest_sha256'], command_class='source-checker',
                  case=manifest['source_case'])
    guard.require_ready('root')

    def finish():
        try:
            guard.require_ready('root')
            summary = guard.observe_summary(path)
            if not summary['ready'] or summary['failures']:
                os._exit(86)
        except BaseException:
            os._exit(86)
    atexit.register(finish)
