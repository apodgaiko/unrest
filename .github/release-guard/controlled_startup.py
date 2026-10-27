"""Source-derived startup declarations for unchanged bootstrap cases.

Trusted bootstrap supplies immutable source units, runtime and owned-root
identity plus authenticated case selection. This module selects intent only;
the kernel stop, native prebody entry, endpoint seal and actual waits remain
separate mandatory boundaries. There is no legacy resolver fallback.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import types
from typing import Any

from bootstrap_cases import BOOTSTRAP, configuration, declaration, wrapper
from content_manifest import Refused, capture
from controlled_cases import CASES as CONTROLLED, PINS as CONTROLLED_PINS, backend as controlled_backend, backend_path
from launch_policy import Expected, Observation, Rule, match, render
from source_owner import Link, Owner, SourceUnit, active_frames, _namespace, _safe_code, frame_fields as frame_locals

SESSION = 'src/unrest_harness/experimental_session.py'
TEST = 'tests/test_experimental_bootstrap.py'
ACP = 'tests/fixtures/controlled_python_acp.py'
SESSION_PIN = '7a3df1d049cd8a72aac48bc376154f7701335397ad8a0e0634cf2d0a9509cbd2'
TEST_PIN = 'c81fc04a81ef3aa657c16a69627c4c6b80ba1012f9255d2a05b15557934a7383'
BACKEND_PIN = 'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53'
ACP_PIN = 'f5134a2d79b348b70b05a66566ff65d0049f102665200a22f3a6fcbd1c4f58be'
CASES = tuple('tests/test_experimental_bootstrap.py::' + name for name in (
    'test_actual_sequential_initialize_and_session_share_cutoff',
    'test_startup_subtracts_from_actual_inference_timeout'))
WRAPPER = 'import runpy,sys,time; p=sys.argv.pop(1); time.sleep(0.5); runpy.run_path(p,run_name="__main__")'
PATH_TYPE = type(Path('/'))


def dictionary(instance: object, cls: type) -> dict:
    descriptor = _namespace(cls).get('__dict__')
    if type(descriptor) is not types.GetSetDescriptorType:
        raise Refused('startup instance dictionary descriptor')
    return _namespace(descriptor.__get__(instance, type(instance)))


def path(value: Any) -> Path:
    if type(value) is not PATH_TYPE or not value.is_absolute() or str(value.resolve()) != str(value):
        raise Refused('startup canonical path')
    return value



@dataclass(frozen=True)
class Intent:
    original: Expected
    translated_argv: tuple[str, ...]
    original_source_line: int
    script_sha256: str | None


def expected_entry(case,checkout,home,native,native_pin,*,backend,relay=None):
    if type(case) is not str or case not in (*BOOTSTRAP,*CONTROLLED) or type(backend) is not bool:
        raise Refused('controlled entry declaration')
    checkout,home = path(checkout),path(home)
    configured = case not in CONTROLLED and declaration(case).configured
    options,config = configuration(checkout,home) if configured else ([],None)
    environment = {'HOME':str(home),'CODEX_HOME':str(home/'codex'),'TMPDIR':str(home/'tmp'),'PATH':'/usr/bin:/bin'}
    if config is not None:
        environment.update(CODEX_HOME=str(home.parent.parent.parent/'subscription'),CODEX_CONFIG=config)
    if backend:
        script = backend_path(case,home.parent) if case in CONTROLLED else home.parent/'fake-app-server'
        pin = controlled_backend(case)[0] if case in CONTROLLED else BACKEND_PIN
        source = (native,str(script),*options,'app-server')
        delay = None if case in CONTROLLED else wrapper(case)
        vector = (native,'-c',delay,*source[1:]) if delay is not None else source
        kind,reference = ('python-command',None) if delay is not None else ('python-script',pin)
    else:
        if (type(relay) is not list or len(relay) != 4
                or any(type(relay[i]) is not int or not 0 < relay[i] <= 65535 for i in (0,2))
                or any(type(relay[i]) is not str or len(relay[i]) != 64
                    or any(char not in '0123456789abcdef' for char in relay[i]) for i in (1,3))):
            raise Refused('controlled entry acquired relay')
        pin = ACP_PIN
        source = vector = (native,str(checkout/ACP),'--controlled-local-acp-v1')
        kind,reference = 'python-script',pin
        environment.update(CODEX_PATH=str(home.parent/'fixed-relay'),INITIAL_AGENT_MODE='read-only',SYNTHETIC_RELAY=json.dumps(relay))
    rule = Rule('controlled-startup:'+('backend' if backend else 'acp'),SESSION+':_open_role_owned',(case,),
        native,native_pin,vector,tuple(sorted(environment.items())),str(home),kind,reference)
    return render(rule,case,rule.owner,{},{}),source,pin

class Startup:
    def __init__(self, session: types.ModuleType, tests: types.ModuleType,
                 session_unit: SourceUnit, test_unit: SourceUnit,
                 checkout: Path, owned: Path, interpreter: Path, interpreter_sha256: str, *, configuration_binding=None, case=None):
        import asyncio
        if (session_unit.source_sha256 != SESSION_PIN or test_unit.source_sha256 != (CONTROLLED_PINS.get(case.split('::')[0]) if case in CONTROLLED else TEST_PIN)
                or session_unit.path != str(checkout / SESSION) or test_unit.path != str(checkout / (case.split('::')[0] if case in CONTROLLED else TEST))
                or session_unit.module != 'unrest_harness.experimental_session'
                or test_unit.module != (case.split('::')[0].removesuffix('.py').replace('/', '.') if case in CONTROLLED else 'tests.test_experimental_bootstrap') or test_unit.mode != 'pytest'):
            raise Refused('startup prepared source authority')
        self.checkout, self.owned = path(checkout), path(owned)
        if type(interpreter) is not PATH_TYPE or not interpreter.is_absolute():
            raise Refused('startup interpreter path')
        self.interpreter_path, self.interpreter = interpreter, path(interpreter.resolve())
        self.root_identity = self.root_key()
        self.configuration = configuration_binding
        self.case = case
        self.runtime_pin = interpreter_sha256
        if hashlib.sha256(interpreter.read_bytes()).hexdigest() != interpreter_sha256:
            raise Refused('startup runtime bytes')
        self.session, self.tests, self.unit, self.test_unit = session, tests, session_unit, test_unit
        namespace = _namespace(session)
        self.base, self.synthetic = namespace['_SessionOwner'], namespace['SyntheticSession']
        self.transport, self.runtime = namespace['ControlledTransport'], namespace['_TRUSTED_TEST_RUNTIME']
        self.bridge, self.lifetime = namespace['Bridge'], namespace['_FixtureLifetime']
        self.runtime_type = namespace['_TrustedTestRuntime']
        self.open = _namespace(self.base)['_open_role_owned']
        self.environment = _namespace(self.base)['_environment']
        self.argv = _namespace(self.transport)['argv']
        self.fixture = _namespace(tests).get('delayed_backend')
        self.fixture_type = type(self.fixture)
        self.fixture_function = dictionary(self.fixture, self.fixture_type)['_fixture_function'] if self.fixture is not None else None
        self.anchors = {'environment': self.environment, 'fixture': self.fixture_function}
        self.constructor = asyncio.subprocess.create_subprocess_exec
        self.constructor_code = self.constructor.__code__
        self.links = (Link(session, '_SessionOwner', self.base), Link(session, 'SyntheticSession', self.synthetic),
                      Link(session, 'ControlledTransport', self.transport), Link(session, '_TRUSTED_TEST_RUNTIME', self.runtime),
                      Link(session, 'Bridge', self.bridge), Link(session, '_FixtureLifetime', self.lifetime),
                      Link(self.transport, '_runtime', self.runtime))

    def root_key(self) -> tuple:
        info = os.stat(self.owned, follow_symlinks=False)
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid

    def function(self, fn, qualified: str, unit: SourceUnit, module: types.ModuleType,
                 links: tuple[Link, ...], *, closure: tuple = ()) -> Owner:
        if type(fn) is not types.FunctionType:
            raise Refused('startup source function')
        codes = [code for code in unit.codes if code.co_qualname == qualified]
        if len(codes) != 1:
            raise Refused('startup lexical function')
        return Owner(unit, module, fn, qualified, codes[0].co_firstlineno, (1, 100000), links,
                     closure, fn.__closure__ or ())

    def binding(self, fn, qualified: str, cls: type, name: str) -> None:
        self.function(fn, qualified, self.unit, self.session,
                      (*self.links, Link(cls, name, fn))).verify_binding()

    def source_file(self, file: Path, expected: str, *, owned: bool) -> None:
        root = self.owned if owned else self.checkout
        file = path(file)
        if not file.is_relative_to(root):
            raise Refused('startup source file root')
        acquired = capture(root, [file.relative_to(root).as_posix()])
        if acquired['files'][0]['sha256'] != expected:
            raise Refused('startup source file bytes')

    def select(self, case: str, observed: Observation) -> Intent:
        if type(case) is not str or case not in (*BOOTSTRAP, *CONTROLLED) or case in CONTROLLED and case != self.case or self.root_key() != self.root_identity or os.getcwd() != str(self.checkout):
            raise Refused('startup case or root generation')
        frames = active_frames()
        try:
            candidates = [frame for frame in frames if frame.f_code is self.open.__code__
                          and frame.f_globals is vars(self.session) and frame.f_lineno in (506, 553)]
            if len(candidates) != 1:
                raise Refused('startup original product caller')
            frame = candidates[0]
            owner = self.function(self.open, '_SessionOwner._open_role_owned', self.unit, self.session,
                                  (*self.links, Link(self.base, '_open_role_owned', self.open)))
            owner.verify(frame)
            local = frame_locals(frame)
            instance = local.get('self')
            if type(instance) not in (self.base, self.synthetic):
                raise Refused('startup owner type')
            values = dictionary(instance, self.base)
            configured = case not in CONTROLLED and declaration(case).configured
            backend_pin, backend_name = controlled_backend(case) if case in CONTROLLED else (BACKEND_PIN, 'fake-app-server')
            if (values.get('controlled') is not True or values.get('provider_package') is not None
                    or not configured and values.get('provider_config') is not None):
                raise Refused('startup controlled owner configuration')
            transport = values.get('transport')
            if type(transport) is not self.transport:
                raise Refused('startup controlled transport')
            transport_values = dictionary(transport, self.transport)
            if type(self.runtime) is not self.runtime_type:
                raise Refused('startup runtime type')
            runtime = dictionary(self.runtime, self.runtime_type)
            if (type(runtime.get('path')) is not PATH_TYPE or runtime['path'] != self.interpreter_path
                    or type(runtime.get('realpath')) is not PATH_TYPE or runtime['realpath'] != self.interpreter
                    or type(runtime.get('sha256')) is not str or runtime['sha256'] != self.runtime_pin):
                raise Refused('startup runtime binding')
            if (transport_values.get('_runtime', _namespace(self.transport).get('_runtime')) is not self.runtime
                    or path(transport_values.get('fixture')) != self.checkout / ACP
                    or type(transport_values.get('interpreter')) is not PATH_TYPE
                    or transport_values['interpreter'] != self.interpreter_path
                    or transport_values['interpreter'].resolve() != self.interpreter):
                raise Refused('startup controlled runtime selection')
            self.binding(self.argv, 'ControlledTransport.argv', self.transport, 'argv')
            root, backend = path(values.get('root')), path(values.get('backend_launcher'))
            if (not root.is_relative_to(self.owned) or backend != (backend_path(case, root) if case in CONTROLLED else root / backend_name)
                    or type(values.get('backend_digest')) is not str or values['backend_digest'] != backend_pin
                    or type(local.get('name')) is not str or local['name'] not in ('worker', 'validator')):
                raise Refused('startup owner paths')
            if configured:
                if self.configuration is None:
                    raise Refused('startup configured source boundary absent')
                self.configuration.check(values.get('provider_config'), root, case)
            home = root / local['name']
            if path(local.get('home')) != home:
                raise Refused('startup role home')
            self.source_file(backend, backend_pin, owned=True)
            self.source_file(self.checkout / ACP, ACP_PIN, owned=False)
            backend_spawn = frame.f_lineno == 506
            relay = None
            if not backend_spawn:
                bridge,lifetime = local.get('bridge'),local.get('lifetime')
                if type(bridge) is not self.bridge or type(lifetime) is not self.lifetime:
                    raise Refused('startup relay objects')
                relay = [local.get('relay_port'),dictionary(bridge,self.bridge).get('nonce'),
                         local.get('port'),dictionary(lifetime,self.lifetime).get('nonce')]
            expected,source_vector,script_pin = expected_entry(case,self.checkout,home,str(self.interpreter),
                self.runtime_pin,backend=backend_spawn,relay=relay)
            vector = local.get('argv' if backend_spawn else 'adapter_argv')
            if (not isinstance(vector, (list, tuple)) or type(vector) is not (list if backend_spawn else tuple)
                    or any(type(arg) is not str for arg in vector)
                    or tuple(vector) != source_vector):
                raise Refused('startup original source vector')
            source_environment = local.get('backend_environment' if backend_spawn else 'environment')
            if type(source_environment) is not dict:
                raise Refused('startup source environment type')
            snapshot = _namespace(source_environment)
            if any(type(value) is not str for value in snapshot.values()) or snapshot != dict(expected.environment):
                raise Refused('startup source environment')
            self.constructor_frame(frames,source_vector,source_environment,home,backend_spawn,case)
            match((expected,),observed,expected.owner,case)
            if self.root_key() != self.root_identity:
                raise Refused('startup owned root replaced')
            return Intent(expected, (expected.argv[0], '-I', '-S', *expected.argv[1:]), frame.f_lineno, script_pin)
        finally:
            del frames

    def constructor_frame(self, frames, original_argv, environment, home, backend, case):
        import asyncio
        if self.constructor.__code__ is not self.constructor_code:
            raise Refused('startup constructor code changed')
        constructors = [frame for frame in frames if frame.f_code is self.constructor_code
                        and frame.f_globals is self.constructor.__globals__]
        if len(constructors) != 1:
            raise Refused('startup actual asyncio constructor')
        values = frame_locals(constructors[0])
        if (type(values.get('program')) is not str or type(values.get('args')) is not tuple
                or any(type(arg) is not str for arg in values['args'])):
            raise Refused('startup actual constructor vector')
        actual_argv = (values['program'], *values['args'])
        expected_argv = original_argv
        delayed_wrapper = None if case in CONTROLLED else wrapper(case)
        if delayed_wrapper is not None:
            if backend:
                expected_argv = (original_argv[0], '-c', delayed_wrapper, *original_argv[1:])
            self.delayed(frames, expected_argv, environment, home, backend, declaration(case).delay)
        else:
            self.binding(self.environment, '_SessionOwner._environment', self.base, '_environment')
            if case in CONTROLLED:
                from controlled_wrappers import verify
                verify(asyncio, 'create_subprocess_exec', self.constructor, self.checkout)
            elif asyncio.create_subprocess_exec is not self.constructor:
                raise Refused('startup unexpected constructor wrapper')
        keywords = values.get('kwds')
        if type(keywords) is not dict:
            raise Refused('startup constructor keyword type')
        keywords = _namespace(keywords)
        if (actual_argv != expected_argv or type(keywords) is not dict
                or set(keywords) != {'cwd', 'env', 'close_fds', 'start_new_session'}
                or type(keywords['cwd']) is not PATH_TYPE or keywords['cwd'] != home or keywords['env'] is not environment
                or keywords['close_fds'] is not True or keywords['start_new_session'] is not True
                or type(values.get('stdin')) is not int or values['stdin'] != -1
                or type(values.get('stdout')) is not int or values['stdout'] != -1
                or type(values.get('stderr')) is not int or values['stderr'] != (-1 if backend else -3)
                or type(values.get('limit')) is not int or values['limit'] != (262143 if backend else 65536)
                or type(_namespace(self.session).get('PREFLIGHT_BYTES')) is not int
                or _namespace(self.session)['PREFLIGHT_BYTES'] != 262144):
            raise Refused('startup original process options')

    def delayed(self, frames, expected_argv, environment, home, backend, delay):
        import asyncio
        if (type(self.fixture) is not self.fixture_type
                or dictionary(self.fixture, self.fixture_type).get('_fixture_function') is not self.fixture_function):
            raise Refused('startup original delayed fixture')
        self.function(self.fixture_function, 'delayed_backend', self.test_unit, self.tests,
                      (Link(self.tests, 'delayed_backend', self.fixture),
                       Link(self.anchors, 'fixture', self.fixture_function))).verify_binding()
        live = _namespace(asyncio).get('create_subprocess_exec')
        if type(live) is not types.FunctionType:
            raise Refused('startup delayed constructor')
        _safe_code(live.__code__)
        qualified = 'delayed_backend.<locals>.install.<locals>.delayed'
        if type(live) is not types.FunctionType or live.__code__.co_qualname != qualified:
            raise Refused('startup delayed constructor')
        cells = live.__closure__ or ()
        values = {name: cell.cell_contents for name, cell in zip(live.__code__.co_freevars, cells, strict=True)}
        if (set(values) != {'delay', 'launch', 'observed'} or type(values['delay']) is not type(delay)
                or values['delay'] != delay or values['launch'] is not self.constructor or type(values['observed']) is not list):
            raise Refused('startup delayed closure')
        binding = self.function(live, qualified, self.test_unit, self.tests,
                                (Link(asyncio, 'create_subprocess_exec', live),),
                                closure=tuple(values[name] for name in live.__code__.co_freevars))
        matches = [frame for frame in frames if frame.f_code is live.__code__]
        if len(matches) != 1 or matches[0].f_lineno != 38:
            raise Refused('startup delayed original callsite')
        binding.verify(matches[0])
        local = frame_locals(matches[0])
        options = local.get('kwargs')
        if type(options) is not dict:
            raise Refused('startup delayed keyword type')
        options = _namespace(options)
        keys = {'cwd', 'env', 'stdin', 'stdout', 'stderr', 'close_fds', 'start_new_session'}
        if backend:
            keys.add('limit')
        if (type(local.get('args')) is not tuple or any(type(arg) is not str for arg in local['args'])
                or local['args'] != expected_argv
                or type(options) is not dict or set(options) != keys
                or type(options['cwd']) is not PATH_TYPE or options['cwd'] != home or options['env'] is not environment
                or options['close_fds'] is not True or options['start_new_session'] is not True
                or type(options['stdin']) is not int or options['stdin'] != -1
                or type(options['stdout']) is not int or options['stdout'] != -1
                or type(options['stderr']) is not int or options['stderr'] != (-1 if backend else -3)
                or backend and (type(options['limit']) is not int or options['limit'] != 262143)):
            raise Refused('startup delayed source options')
        patched = _namespace(self.base).get('_environment')
        if type(patched) is not types.FunctionType or patched.__closure__ is None or len(patched.__closure__) != 1:
            raise Refused('startup delayed environment')
        self.function(patched, 'delayed_backend.<locals>.controlled_environment', self.test_unit, self.tests,
                      (Link(self.base, '_environment', patched),), closure=(self.environment,)).verify_binding()
        self.function(self.environment, '_SessionOwner._environment', self.unit, self.session,
                      (Link(self.anchors, 'environment', self.environment),)).verify_binding()
