"""Original UV query/backend bodies under native pre-initialization activation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import types


def load(name, path, pin):
    path = Path(path)
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != pin:
        raise RuntimeError('native producer support drift')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(body, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


def named(code, qualified):
    if code.co_qualname == qualified:
        return code
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            found = named(value, qualified)
            if found is not None:
                return found
    return None


def activate(profile, command):
    path = Path(profile['manifest'])
    if path.parent != Path('/receipts/producers') or path.is_symlink():
        raise RuntimeError('native producer manifest root drift')
    info = path.stat()
    body = path.read_bytes()
    if (info.st_uid != 20001 or info.st_mode & 0o777 != 0o444
            or hashlib.sha256(body).hexdigest() != profile['manifest_sha256']):
        raise RuntimeError('native producer manifest custody drift')
    manifest = json.loads(body)
    support = manifest['direct_support']['files']
    activation = load('operation_activation', '/guard/finite/operation_activation.py',
                      support['/guard/finite/operation_activation.py'])
    inputs = load('isolated_inputs', '/guard/finite/isolated_inputs.py',
                  support['/guard/finite/isolated_inputs.py'])
    interface = load('producer_profile', '/guard/producer_profile.py',
                     profile['profile_support_sha256'])
    spec = interface.consume(profile)
    original = sys.orig_argv[-1]
    # CPython appends this one newline to PyConfig.run_command before its audit
    # event. The original argv string and effective flags remain unchanged.
    if command != original + '\n':
        raise RuntimeError('native CPython command rendering drift')
    role = profile['role']
    if role == 'isolated-uv-query':
        package = interface.query_package(original, spec)
        source = Path(package['path']) / 'python/get_interpreter_info.py'
        helper = 'main'
    else:
        resolver = load('isolated_activation', '/guard/finite/isolated_activation.py',
                        support['/guard/finite/isolated_activation.py'])
        helper = resolver.helper_class(original, spec)
        runtime = inputs.runtime(spec, sys.executable)
        source = Path(runtime['selected_build_meta']['path'])
    endpoint = load('endpoint', '/guard/finite/endpoint.py', manifest['endpoint']['sha256'])
    endpoint.early(manifest['endpoint'])
    sys._finite_source_bootstrap_gate = {'active': True}
    guard = load('runtime_guard', manifest['guard'], manifest['guard_sha256'])
    endpoint.attach(guard)
    guard.install(str(path), profile['manifest_sha256'], profile['token'], role, profile['case'])
    guard.require_ready(profile['token'])
    endpoint.check()
    source_body = source.read_bytes()
    source_pin = hashlib.sha256(source_body).hexdigest()
    expected_body = compile(command, '<string>', 'exec', dont_inherit=True)
    expected_source = compile(source_body, str(source), 'exec', dont_inherit=True)
    entered = [False]
    previous = sys.getprofile()

    def refuse(error):
        try:
            endpoint.refuse('native_producer:' + str(error))
        finally:
            os._exit(86)

    def before_body(event, args):
        if event != 'exec' or args[0].co_filename != '<string>' or entered[0]:
            return
        try:
            if args[0] != expected_body:
                raise RuntimeError('native original command code drift')
            interface.consume(profile)
            guard.require_ready(profile['token'])
            endpoint.check()
            if profile.get('caught_control'):
                import subprocess
                try:
                    subprocess.run([sys.executable, '-c', 'raise AssertionError("unknown child")'])
                except RuntimeError:
                    guard.append({'kind': 'native_producer_caught_refusal', 'role': role})
                guard.require_ready(profile['token'])
                endpoint.check()
            entered[0] = True
            guard.append({'kind': 'query_original_dispatch' if role == 'isolated-uv-query'
                          else 'isolated_original_dispatch', 'helper': helper,
                          'argv_sha256': hashlib.sha256(json.dumps(sys.argv).encode()).hexdigest(),
                          'orig_argv_sha256': hashlib.sha256(json.dumps(sys.orig_argv).encode()).hexdigest(),
                          'flags': [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode],
                          'script_sha256': hashlib.sha256(original.encode()).hexdigest(),
                          'environment_sha256': hashlib.sha256(json.dumps(dict(os.environ), sort_keys=True).encode()).hexdigest(),
                          'cwd': os.getcwd(),
                          'stdio': [sys.stdin.fileno(), sys.stdout.fileno(), sys.stderr.fileno()],
                          'native_preinitialization_activation': True})
        except BaseException as error:
            refuse(error)

    def profile_body(frame, event, value):
        if previous is not None:
            previous(frame, event, value)
        if (role == 'isolated-uv-helper' and spec.get('primary_producer') is not None
                and event == 'return' and frame.f_code == expected_body):
            try:
                guard.require_ready(profile['token'])
                endpoint.check()
                endpoint.request('source_response_output')
            except BaseException as error:
                refuse(error)
            return
        if frame.f_code.co_filename != str(source) or frame.f_code.co_name != helper:
            return
        try:
            if (not entered[0] or hashlib.sha256(source.read_bytes()).hexdigest() != source_pin
                    or named(expected_source, frame.f_code.co_qualname) != frame.f_code):
                raise RuntimeError('native producer function source/code drift')
            module = sys.modules.get(frame.f_globals.get('__name__'))
            if module is None or vars(module) is not frame.f_globals:
                raise RuntimeError('native producer globals drift')
            guard.require_ready(profile['token'])
            endpoint.check()
            if role == 'isolated-uv-query':
                if event == 'call':
                    guard.append({'kind': 'query_actual_main_call', 'source': activation.identity(source)})
                if event == 'return':
                    result = frame.f_locals.get('interpreter_info')
                    if not isinstance(result, dict) or result.get('result') != 'success':
                        raise RuntimeError('query original main did not succeed')
                    guard.append({'kind': 'query_actual_main_return', 'info': result,
                                  'info_sha256': activation.hashed(result),
                                  'original_print_unchanged': True})
            elif event == 'call':
                guard.append({'kind': 'isolated_actual_backend_call', 'helper': helper,
                              'selected_backend': activation.identity(source)})
            elif event == 'return' and helper in ('build_sdist', 'build_wheel'):
                if not isinstance(value, str) or Path(value).name != value:
                    raise RuntimeError('native backend filename return drift')
                artifact = Path(spec['output']) / value
                guard.append({'kind': 'isolated_backend_output', 'helper': helper,
                              'artifact': activation.identity(artifact),
                              'settlement': 'actual backend return; UV parent wait still required'})
            elif (event == 'return' and helper == 'get_requires_for_build_wheel'
                  and os.getcwd() != spec['project']):
                if value != []:
                    raise RuntimeError('unknown dynamic source build requirement')
                files = inputs.record_egg_info_mutation(spec, Path.cwd(), interface.events(spec), os.getppid())
                guard.append({'kind': 'isolated_extraction_mutation', 'root': os.getcwd(), 'files': files,
                              'actual_return': helper})
        except BaseException as error:
            refuse(error)

    def backend_exception(frame, event, value):
        if (role != 'isolated-uv-helper' or frame.f_code.co_filename != str(source)
                or frame.f_code.co_name != helper):
            return None
        if event == 'exception':
            kind, error, _ = value
            guard.append({'kind': 'original_backend_exception', 'helper': helper,
                          'exception_type': kind.__module__ + '.' + kind.__qualname__,
                          'message': str(error), 'errno': getattr(error, 'errno', None)})
        return backend_exception

    if role == 'isolated-uv-helper':
        sys.settrace(backend_exception)
    if role == 'isolated-uv-helper' and os.getcwd() != spec['project']:
        lineage = inputs.extracted_source(spec, Path.cwd(), interface.events(spec), os.getppid())
        guard.append({'kind': 'isolated_actual_extraction_consumption', 'lineage': lineage})
    guard.append({'kind': 'query_startup_consumption' if role == 'isolated-uv-query'
                  else 'isolated_selected_backend', 'helper': helper,
                  'startup_resolution': 'native CPython pre-initialization audit hook; protected finite profile',
                  'original_source_coverage': True})
    sys.setprofile(profile_body)
    sys.addaudithook(before_body)
