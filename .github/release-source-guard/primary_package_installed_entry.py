"""Pre-body guard and byte-bound original installed lifecycle return observer."""
from __future__ import annotations

import atexit
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from dataclasses import replace

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


def corruption_probe():
    # A separate newly owned fixture exercises the installed public library.
    # It never touches mission state, a source checkout, or the original oracle.
    from unrest_harness.config import HarnessConfig
    from unrest_harness.controller import ProjectController
    from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
    from unrest_harness.models import TerminalReviewHandoff
    with tempfile.TemporaryDirectory(prefix='unrest-installed-corruption-') as raw:
        root = Path(raw).resolve()
        if not root.is_relative_to('/work/owned/tmp'):
            raise RuntimeError('package_installed_corruption_owned_root')
        workspace = root / 'workspace'
        workspace.mkdir()
        config = replace(HarnessConfig.discover(), harness_home=root / 'home',
                         projects_dir=root / 'home/projects', max_parallel_nodes=1)
        def unexpected(request):
            raise RuntimeError('package_installed_corruption_unexpected_dispatch')
        def controller():
            return ProjectController(config, MockDispatcher(unexpected),
                                     MockTerminalReviewer(TerminalReviewHandoff(done=True)))
        current = controller()
        result = current.start_project('Installed corruption fixture.', str(workspace))
        path = current.store.unrest_runtime_dir(result.projectId) / 'state.json'
        original = path.read_bytes()
        path.write_bytes(b'{')
        refused = False
        try:
            controller().store.load_state(result.projectId)
        except (ValueError, json.JSONDecodeError):
            refused = True
        if not refused or path.read_bytes() != b'{':
            raise RuntimeError('package_installed_corruption_not_closed')
        path.write_bytes(original)
        if controller().store.load_state(result.projectId) != result.state:
            raise RuntimeError('package_installed_corruption_restore')
    return {'corrupt_state_refused': True, 'original_bytes_restored': True}


def activate(profile, event, arguments):
    path = profile['manifest']
    body = Path(path).read_bytes()
    if (hashlib.sha256(body).hexdigest() != profile['manifest_sha256']
            or profile['source_role'] != 'package-installed-root'
            or event != 'cpython.run_module' or arguments != ('unrest_harness.installed_wheel_check',)):
        os._exit(86)
    manifest = json.loads(body)
    endpoint = load('endpoint', '/guard/finite/endpoint.py', manifest['endpoint']['sha256'])
    endpoint.early(manifest['endpoint'])
    sys._finite_source_bootstrap_gate = {'active': True}
    guard = load('runtime_guard', manifest['guard'], manifest['guard_sha256'])
    endpoint.attach(guard)
    if manifest['source_case'] not in {'PRIMARY-installed-TEST', 'PRIMARY-installed-FULL'}:
        os._exit(86)
    guard.install(path, profile['manifest_sha256'], command_class='primary-installed-root',
                  case=manifest['source_case'])
    guard.require_ready('root')
    source = Path('/source/.wheel-venv/lib/python3.13/site-packages/unrest_harness/installed_wheel_check.py')
    source_body = source.read_bytes()
    source_pin = manifest['product_pins']['src/unrest_harness/installed_wheel_check.py']
    if hashlib.sha256(source_body).hexdigest() != source_pin:
        os._exit(86)
    compiled = compile(source_body, str(source), 'exec', dont_inherit=True)
    expected = next(code for code in compiled.co_consts
                    if isinstance(code, types.CodeType) and code.co_name == 'run_installed_wheel_check')
    previous = sys.getprofile()
    returned = [False]
    def observe(frame, kind, result):
        if previous is not None:
            previous(frame, kind, result)
        if frame.f_code.co_filename != str(source) or frame.f_code.co_name != 'run_installed_wheel_check':
            return
        try:
            module = sys.modules.get(frame.f_globals.get('__name__'))
            function = frame.f_globals.get('run_installed_wheel_check')
            if (frame.f_code != expected or module is None or vars(module) is not frame.f_globals
                    or getattr(function, '__code__', None) is not frame.f_code
                    or hashlib.sha256(source.read_bytes()).hexdigest() != source_pin):
                raise RuntimeError('package_installed_original_code')
            guard.require_ready('root')
            if kind == 'return':
                if returned[0] or type(result) is not dict:
                    raise RuntimeError('package_installed_original_result')
                endpoint.request('primary_package_installed_return', source_sha256=source_pin,
                                 function='run_installed_wheel_check', cwd=os.getcwd(),
                                 module=str(source), result=result)
                effects = corruption_probe()
                endpoint.request('primary_package_installed_corruption', result=effects)
                returned[0] = True
        except BaseException:
            endpoint.refuse('primary_package_installed_observation')
            os._exit(86)
    sys.setprofile(observe)
    def finish():
        try:
            guard.require_ready('root')
            summary = guard.observe_summary(path)
            if not returned[0] or not summary['ready'] or summary['failures']:
                os._exit(86)
        except BaseException:
            os._exit(86)
    atexit.register(finish)
