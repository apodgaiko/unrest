"""Fixed root entry and once-only sealed fixture bodies; no launch permission."""
from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
import runpy
import sys
import types

from content_manifest import Refused
from bootstrap_cases import wrapper
from controlled_startup import ACP_PIN, BACKEND_PIN
from ordinary_acp import MOCK, PINS
from source_owner import _safe_code
from source_profile import ROOT_COMMAND, digest
from cleanup_inline import body as inline_body


class Bodies:
    def __init__(self, profile: dict):
        self.profile, self.next = profile, 0
        self.run_code = vars(runpy)['_run_code']
        if type(self.run_code) is not types.FunctionType:
            raise Refused('sealed runpy function')
        self.run_code_object = self.run_code.__code__
        self.run_globals = vars(runpy)
        role = profile['role']
        self.codes: tuple[types.CodeType, ...]
        if role == 'root':
            self.codes = (compile(ROOT_COMMAND + '\n', '<string>', 'exec', dont_inherit=True),)
        elif role == 'cleanup-inline':
            importlib.import_module('time')
            self.codes = (compile(inline_body(profile['case']) + '\n', '<string>', 'exec', dont_inherit=True),)
        else:
            names = ('asyncio', 'json', 'os', 'sys') if role == 'acp' else (
                'copy', 'json', 'os', 'pathlib', 'sys', 'signal', 'secrets', 'time', 'tomllib', 'urllib.request')
            for name in (*names, 'runpy', 'pkgutil', 'encodings.ascii', 'encodings.latin_1'):
                importlib.import_module(name)
            fixture = Path(profile['checkout']) / ('tests/fixtures/controlled_python_acp.py'
                if role == 'acp' else MOCK if role == 'mock-acp' else 'tests/fixtures/experimental_session_app_server.py')
            self.pin = ACP_PIN if role == 'acp' else PINS[MOCK] if role == 'mock-acp' else BACKEND_PIN
            if digest(fixture) != self.pin:
                raise Refused('sealed fixture source bytes')
            self.data = fixture.read_bytes()
            if hashlib.sha256(self.data).hexdigest() != self.pin:
                raise Refused('sealed fixture source acquisition')
            script = compile(self.data, profile['script'], 'exec', dont_inherit=True)
            self.codes = ((compile(str(wrapper(profile['case'])) + '\n', '<string>', 'exec', dont_inherit=True), script)
                          if role == 'delayed-backend' else (script,))
        if (type(sys.modules) is not dict or len(sys.modules) > 4096
                or any(type(name) is not str for name in sys.modules)):
            raise Refused('sealed module inventory')
        self.modules = dict(sys.modules)

    def module_bindings(self) -> None:
        if type(sys.modules) is not dict:
            raise Refused('sealed module dictionary')
        for name, value in self.modules.items():
            if name == '__main__' and self.profile['role'] == 'delayed-backend' and self.next == 1:
                continue  # runpy's exact temporary namespace is checked at dispatch.
            if sys.modules.get(name) is not value:
                raise Refused('sealed module replacement')

    def audit(self, event: str, args: tuple) -> bool:
        role = self.profile['role']
        if event == 'import':
            if role != 'root':
                self.module_bindings()
                if (not args or type(args[0]) is not str or args[0] not in self.modules
                        or sys.modules.get(args[0]) is not self.modules[args[0]]):
                    raise Refused('sealed unprepared import')
            return True
        if role == 'root' and self.next:
            # Pytest and its libraries may generate ordinary in-process code.
            # Every privileged effect still requires independent source/host admission.
            return True
        if event == 'compile':
            if self.next >= len(self.codes) or len(args) != 2:
                raise Refused('sealed unexpected compilation')
            expected = self.codes[self.next]
            if args[1] != expected.co_filename:
                raise Refused('sealed compilation filename')
            if expected.co_filename == '<string>':
                data = (ROOT_COMMAND if role == 'root' else inline_body(self.profile['case']) if role == 'cleanup-inline' else str(wrapper(self.profile['case']))) + '\n'
                if type(args[0]) not in (str, bytes) or args[0] not in (data, data.encode()):
                    raise Refused('sealed inline compilation bytes')
            else:
                self.module_bindings()
                if digest(Path(self.profile['script'])) != self.pin:
                    raise Refused('sealed current script bytes')
                if args[0] is not None:
                    raw_source = args[0].encode() if type(args[0]) is str else args[0]
                    if type(raw_source) is not bytes or hashlib.sha256(raw_source).hexdigest() != self.pin:
                        raise Refused('sealed actual compilation bytes')
            return True
        if event != 'exec' or len(args) != 1 or type(args[0]) is not types.CodeType:
            raise Refused('sealed unknown execution event')
        self.module_bindings()
        code = args[0]
        _safe_code(code)
        if self.next >= len(self.codes) or code != self.codes[self.next]:
            raise Refused('sealed unknown Python execution')
        if role != 'root' and code.co_filename != '<string>':
            if digest(Path(self.profile['script'])) != self.pin:
                raise Refused('sealed dispatch script bytes')
            if role == 'delayed-backend':
                frame: types.FrameType | None = sys._getframe(1)
                found = None
                for _ in range(64):
                    if frame is None:
                        break
                    if frame.f_code is self.run_code_object and frame.f_globals is self.run_globals:
                        found = frame
                        break
                    frame = frame.f_back
                main = sys.modules.get('__main__')
                if type(main) is not types.ModuleType:
                    raise Refused('sealed actual main module')
                if (found is None or self.run_code.__code__ is not self.run_code_object
                        or found.f_locals.get('code') is not code
                        or found.f_locals.get('run_globals') is not vars(main)
                        or found.f_locals['run_globals'].get('__file__') != self.profile['script']):
                    raise Refused('sealed exact runpy dispatch')
                self.modules['__main__'] = sys.modules['__main__']
        self.next += 1
        return True
