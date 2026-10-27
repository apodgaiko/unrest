"""Readonly library compilation and explicit schema-code producers.

This is an in-process computation boundary, never effect or launch authority.
The finite entry, kernel process tree and independently mediated process/network
operations remain mandatory. Function clones/hostile native extensions are not
claimed to be a strong Python isolation boundary.
"""
from __future__ import annotations

import __future__
import ast
import hashlib
from importlib import util as _import_util
import os
import marshal
from pathlib import Path
import stat
import sys
import types
from typing import cast

from content_manifest import Refused
from source_owner import _namespace, _safe_code, prepare

PRODUCERS = (
    ('stdlib', 'collections/__init__.py', 'collections', 'namedtuple'),
    ('stdlib', 'typing.py', 'typing', 'ForwardRef.__init__'),
    ('stdlib', 'dataclasses.py', 'dataclasses', '_FuncBuilder.add_fns_to_class'),
    ('stdlib', 'ast.py', 'ast', 'parse'),
    ('dependencies', 'typing_inspection/typing_objects.py', 'typing_inspection.typing_objects', '_compile_identity_check_function'),
    ('dependencies', 'typing_inspection/typing_objects.py', 'typing_inspection.typing_objects', '_compile_isinstance_check_function'),
    ('dependencies', 'attr/_make.py', 'attr._make', '_compile_and_eval'),
    ('dependencies', 'beartype/_util/cache/utilcachecall.py', 'beartype._util.cache.utilcachecall', 'property_cached'),
    ('dependencies', 'beartype/claw/_importlib/_clawimpload.py', 'beartype.claw._importlib._clawimpload', 'BeartypeSourceFileLoader.source_to_code'),
    ('dependencies', 'beartype/_util/func/utilfuncmake.py', 'beartype._util.func.utilfuncmake', 'make_func'),
)
FUTURE_FLAGS = sum(getattr(__future__, name).compiler_flag for name in __future__.all_feature_names)


AST_TYPES = tuple(value for value in vars(ast).values()
                      if type(value) is type and issubclass(value, ast.AST) and value is not ast.AST)
AST_NEW = ast.AST.__new__
AST_DICT = vars(ast.AST)['__dict__']
AST_NAMESPACES = {kind: _namespace(kind) for kind in (*AST_TYPES, ast.AST)}
AST_FIELDS = {kind: (kind._fields, kind._attributes) for kind in AST_TYPES}


def ast_type(kind):
    return any(kind is prepared for prepared in AST_TYPES)


def ast_class(kind):
    for parent in kind.__mro__:
        if parent is object:
            continue
        if not ast_type(parent) and parent is not ast.AST:
            raise Refused('library AST class lineage')
        namespace = _namespace(parent)
        previous = AST_NAMESPACES[parent]
        if set(namespace) != set(previous) or any(namespace[key] is not value for key, value in previous.items()):
            raise Refused('library AST class descriptor changed')


def copy_ast(value, depth=0, budget=None):
    budget = [100000, 16 * 1024 * 1024] if budget is None else budget
    budget[0] -= 1
    if depth > 128 or budget[0] < 0:
        raise Refused('library AST work bound')
    kind = type(value)
    if ast_type(kind):
        ast_class(kind)
        namespace = AST_DICT.__get__(value, kind)
        if type(namespace) is not dict or any(type(key) is not str for key in namespace):
            raise Refused('library AST namespace type')
        fields, attributes = AST_FIELDS[kind]
        if (type(fields) is not tuple or type(attributes) is not tuple
                or any(type(key) is not str for key in (*fields, *attributes))
                or not set(namespace) <= set((*fields, *attributes))):
            raise Refused('library AST fields')
        clone = AST_NEW(kind)
        target = AST_DICT.__get__(clone, kind)
        for key, item in namespace.items():
            target[key] = copy_ast(item, depth + 1, budget)
        return clone
    if kind is list:
        if len(value) > budget[0]:
            raise Refused('library AST width')
        return [copy_ast(item, depth + 1, budget) for item in value]
    if value is None or value is Ellipsis or kind is bool or kind is float or kind is complex:
        budget[1] -= 16
    elif kind is str or kind is bytes:
        budget[1] -= len(value) * (4 if kind is str else 1)
    elif kind is int and value.bit_length() <= 64:
        budget[1] -= 16
    else:
        raise Refused('library AST primitive type')
    if budget[1] < 0:
        raise Refused('library AST byte bound')
    return value


class Computation:
    def __init__(self, roots, entry_script=None, entry_command=None):
        if (type(roots) is not dict or set(roots) != {'source', 'dependencies', 'stdlib'}
                or any(type(name) is not str or type(path) is not str for name, path in roots.items())):
            raise Refused('library immutable root schema')
        self.roots = {name: Path(path) for name, path in roots.items()}
        self.importer = _import_util
        runtime = (sys.abiflags, sys.platform, sys.implementation._multiarch)
        if any(type(value) is not str or len(value) > 128 for value in runtime):
            raise Refused('library native platform identity')
        self.platform_import = '_sysconfigdata_' + '_'.join(runtime)
        if any(not path.is_absolute() or path.resolve(strict=True) != path for path in self.roots.values()):
            raise Refused('library canonical input roots')
        if entry_script is not None and (type(entry_script) is not str or not Path(entry_script).is_absolute()):
            raise Refused('library fixed entry script')
        if entry_command is not None and (type(entry_command) is not str or not 0 < len(entry_command) <= 4 * 1024 * 1024 or entry_script is not None):
            raise Refused('library fixed command entry')
        self.entry_command = entry_command
        self.entry_code = None if entry_command is None else compile(entry_command + '\n', '<string>', 'exec', dont_inherit=True)
        self.entry_dispatched = False
        self.entry_script = entry_script
        self.entry_compiled = False
        self.units, self.generated, self.producer_units = {}, {}, {}
        self.generated_codes: set[types.CodeType] = set()
        self.transformed: dict[str, set[types.CodeType]] = {}
        self.bytes, self.generations = 0, 0
        self.support = str(Path(__file__).parent) + '/'

    def body(self, filename):
        if type(filename) is not str or not filename.startswith('/') or len(filename) > 4096:
            raise Refused('library source filename')
        file = Path(filename)
        if file.resolve(strict=True) != file or not any(file.is_relative_to(root) for root in self.roots.values()):
            raise Refused('library import outside immutable inputs')
        if filename not in self.units:
            before = file.stat(follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= 4 * 1024 * 1024:
                raise Refused('library bounded regular source')
            fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                data = stream.read(4 * 1024 * 1024 + 1)
                after = os.fstat(stream.fileno())
            def identity(value):
                return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                        value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if identity(before) != identity(after) or identity(after) != identity(file.stat(follow_symlinks=False)):
                raise Refused('library source acquisition race')
            if len(self.units) >= 4096 or self.bytes + len(data) > 64 * 1024 * 1024:
                raise Refused('library source inventory bound')
            self.bytes += len(data)
            # The enclosing native profile already verifies the exact readonly
            # mount generation. No successful mutable-path authorization is cached.
            code = compile(data, filename, 'exec', dont_inherit=True, optimize=0)
            self.units[filename] = data, code
        return self.units[filename]

    def producer(self, frame):
        if type(frame) is not types.FrameType:
            raise Refused('library producer frame')
        code = frame.f_code
        _safe_code(code)
        for root, relative, module_name, qualified in PRODUCERS:
            filename = str(self.roots[root] / relative)
            if code.co_filename != filename or code.co_qualname != qualified:
                continue
            module = sys.modules.get(module_name)
            if type(module) is not types.ModuleType or frame.f_globals is not vars(module):
                raise Refused('library producer globals')
            data, _ = self.body(filename)
            if filename not in self.producer_units:
                self.producer_units[filename] = prepare(data, filename, module_name, 'plain', hashlib.sha256(data).hexdigest())
            unit = self.producer_units[filename]
            if code != unit.code(qualified, code.co_firstlineno):
                raise Refused('library producer code changed')
            value = module
            for part in qualified.split('.'):
                if type(value) is not types.ModuleType and type(value) is not type:
                    raise Refused('library producer namespace type')
                namespace = _namespace(value)
                if part not in namespace:
                    raise Refused('library producer live link')
                value = namespace[part]
            if type(value) is not types.FunctionType or value.__code__ is not code or value.__globals__ is not frame.f_globals:
                raise Refused('library producer function replaced')
            return qualified
        raise Refused('library unprepared compiler caller')

    def compilation(self, data, filename, frame):
        if self.entry_command is not None and type(filename) is str and filename == '<string>' and not self.entry_compiled:
            if type(data) not in (str, bytes) or data not in (self.entry_command + '\n', (self.entry_command + '\n').encode()):
                raise Refused('library fixed command bytes')
            self.entry_compiled = True
            return
        if data is None:
            if (type(filename) is not str or filename != self.entry_script or frame is not None
                    or self.entry_compiled):
                raise Refused('library undeclared file parser compilation')
            self.body(filename)
            self.entry_compiled = True
            return
        if ast_type(type(data)):
            return self.transformation(data, filename, frame)
        if (type(data) is not str and type(data) is not bytes) or type(filename) is not str or len(filename) > 4096:
            raise Refused('library compilation primitives')
        raw = data.encode() if type(data) is str else cast(bytes, data)
        if not 0 <= len(raw) <= 4 * 1024 * 1024:
            raise Refused('library compilation byte bound')
        if filename.startswith('/'):
            body, _ = self.body(filename)
            if raw != body:
                raise Refused('library forged source filename')
            return
        self.producer(frame)
        flags = frame.f_code.co_flags & FUTURE_FLAGS
        key = filename, hashlib.sha256(raw).hexdigest(), flags
        if key not in self.generated:
            if self.generations >= 4096 or self.bytes + len(raw) > 64 * 1024 * 1024:
                raise Refused('library generated code bound')
            choices = []
            for mode in ('exec', 'eval', 'single'):
                try:
                    choices.append(compile(raw, filename, mode, flags=flags, dont_inherit=True, optimize=0))
                except SyntaxError:
                    pass
            if not choices:
                raise Refused('library producer emitted invalid source')
            size = len(raw) + sum(len(marshal.dumps(code)) for code in choices)
            if self.bytes + size > 64 * 1024 * 1024:
                raise Refused('library generated code byte bound')
            self.generated[key] = tuple(choices)
            self.generated_codes.update(choices)
            self.bytes += size
            self.generations += 1

    def transformation(self, tree, filename, frame):
        if self.producer(frame) != 'BeartypeSourceFileLoader.source_to_code':
            raise Refused('library undeclared AST compiler')
        local = frame.f_locals
        if filename is not None or frame.f_lineno != 499 or type(local.get('path')) is not str:
            raise Refused('library AST compiler event binding')
        filename = local['path']
        body, _ = self.body(filename)
        if (type(local.get('data')) is not bytes or local['data'] != body
                or type(local.get('path')) is not str or local['path'] != filename
                or local.get('module_ast_beartyped') is not tree
                or type(local.get('_optimize')) is not int or local['_optimize'] not in (-1, 0)):
            raise Refused('library transformed immutable source binding')
        budget = [100000, 16 * 1024 * 1024]
        clone = copy_ast(tree, budget=budget)
        code = compile(clone, filename, 'exec', dont_inherit=True, optimize=0)
        _safe_code(code)
        codes = self.transformed.setdefault(filename, set())
        size = 16 * 1024 * 1024 - budget[1] + len(marshal.dumps(code))
        if len(codes) >= 4 or self.generations >= 4096 or self.bytes + size > 64 * 1024 * 1024:
            raise Refused('library transformed generation bound')
        if code not in codes:
            self.generations += 1
            self.bytes += size
        codes.add(code)


    def execution(self, code):
        if type(code) is not types.CodeType:
            raise Refused('library execution type')
        _safe_code(code)
        if self.entry_code is not None and not self.entry_dispatched:
            if not self.entry_compiled or code != self.entry_code:
                raise Refused('library fixed command dispatch')
            self.entry_dispatched = True
            return
        if code.co_filename.startswith('/'):
            _, original = self.body(code.co_filename)
            if code != original and code not in self.transformed.get(code.co_filename, set()):
                raise Refused('library imported code differs from immutable source')
        elif code not in self.generated_codes:
            raise Refused('library execution without prepared compilation')

    def audit(self, event, args):
        if event == 'compile':
            if type(args) is not tuple or len(args) != 2:
                raise Refused('library compile event schema')
            frame: types.FrameType | None = sys._getframe(1)
            try:
                # Policy forwarding frames grant no producer authority.
                while frame is not None:
                    if type(frame.f_code.co_filename) is not str:
                        raise Refused('library forwarding frame filename type')
                    if not frame.f_code.co_filename.startswith(self.support):
                        break
                    frame = frame.f_back
                self.compilation(args[0], args[1], frame)
            finally:
                del frame
        elif event == 'exec':
            if type(args) is not tuple or len(args) != 1:
                raise Refused('library exec event schema')
            self.execution(args[0])
        elif event == 'import':
            if sys.modules.get('importlib.util') is not self.importer:
                raise Refused('library prepared importer changed')
            if (not args or type(args[0]) is not str or not 0 < len(args[0]) <= 512
                    or not (all(part.isidentifier() for part in args[0].split('.')) or args[0] == self.platform_import)):
                raise Refused('library import name')
            if args[0] == self.platform_import:
                self.body(str(self.roots['stdlib'] / (self.platform_import + '.py')))
            if len(args) > 1 and args[1] is not None:
                filename = args[1]
                if type(filename) is not str or not Path(filename).is_absolute():
                    raise Refused('library extension import filename')
                file = Path(filename)
                if file.resolve(strict=True) != file or not any(file.is_relative_to(root) for root in self.roots.values()):
                    raise Refused('library extension outside immutable inputs')
        else:
            raise Refused('library unknown computation event')
        return True
