"""Prepared code and live owner checks; not a process-launch authority.

Inputs need separate immutable-file/compiler custody and trusted case selection.
No expected value is inferred from a requested launch or PYTEST_CURRENT_TEST.
Bootstrap must retain function/cell identities before mutable test bodies run.
A Python frame cannot distinguish a directly called function clone using the
identical code/globals/freevars; this module does not claim that distinction.
Code is compiled once; live module, globals, closure and function links are not
cached as successful checks. Mutable closure contents need their own verifier.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import importlib.machinery
from pathlib import PurePosixPath
import sys
import types
from typing import Any, cast

from content_manifest import Refused

MAX_FRAMES = 64
MAX_SOURCE = 4 * 1024 * 1024
_ASYNCIO = sys.modules.get('asyncio')


def bind_asyncio():
    global _ASYNCIO
    _ASYNCIO = sys.modules['asyncio']
    if type(_ASYNCIO) is not types.ModuleType:
        raise Refused('prepared asyncio module')


@dataclass(frozen=True)
class SourceUnit:
    path: str
    module: str
    mode: str
    source_sha256: str
    codes: tuple[types.CodeType, ...]
    loader_type: type

    def code(self, qualified: str, line: int | None = None) -> types.CodeType:
        if type(qualified) is not str or line is not None and type(line) is not int:
            raise Refused('lexical code selector type')
        found = [code for code in self.codes
                 if code.co_qualname == qualified and (line is None or code.co_firstlineno == line)]
        if len(found) != 1:
            raise Refused('missing or ambiguous lexical code path')
        return found[0]

    def owner(self, module, function, qualified, links, *, closure=(), defaults=None,
              keyword_defaults=(), default_objects=()) -> Owner:
        if type(function) is not types.FunctionType:
            raise Refused('source owner function type')
        return Owner(self,module,function,qualified,self.code(qualified).co_firstlineno,(1,100000),links,
            closure,function.__closure__ or (),defaults,keyword_defaults,default_objects)


def prepare(body: bytes, path: str, module: str, mode: str,
            expected_sha256: str) -> SourceUnit:
    """Compile already acquired bytes, never execute them or adopt a live code object.

    The caller must pin Python and, for pytest mode, pytest's compiler closure.
    This digest comparison does not establish authority for the expected digest.
    """
    if (type(body) is not bytes or not 0 < len(body) <= MAX_SOURCE
            or type(path) is not str or not path.startswith('/')
            or str(PurePosixPath(path)) != path or '..' in PurePosixPath(path).parts
            or type(module) is not str or not module or type(mode) is not str
            or mode not in ('plain', 'pytest', 'beartype-passive', 'script') or mode == 'script' and module != '__main__' or type(expected_sha256) is not str
            or hashlib.sha256(body).hexdigest() != expected_sha256):
        raise Refused('source unit input refused')
    loader_type: type = importlib.machinery.SourceFileLoader
    if mode == 'beartype-passive':
        from beartype.claw._importlib._clawimpload import BeartypeSourceFileLoader
        loader_type = BeartypeSourceFileLoader
    try:
        tree = ast.parse(body, filename=path)
        if mode == 'pytest':
            from _pytest.assertion.rewrite import AssertionRewritingHook, rewrite_asserts
            loader_type = AssertionRewritingHook
            rewrite_asserts(tree, body, path)
        root = compile(tree, path, 'exec', dont_inherit=True, optimize=0)
    except (ValueError, SyntaxError, RecursionError) as error:
        raise Refused('source compiler refused') from error
    codes: list[types.CodeType] = []
    pending = [(root, 0)]
    while pending:
        code, depth = pending.pop()
        if depth > MAX_FRAMES or len(codes) >= 10000:
            raise Refused('source code catalog bound exceeded')
        codes.append(code)
        pending.extend((value, depth + 1) for value in code.co_consts
                       if type(value) is types.CodeType)
    return SourceUnit(path, module, mode, expected_sha256, tuple(codes), loader_type)


def _safe_code(code: types.CodeType) -> None:
    # CodeType.replace permits arbitrary co_consts. Comparing code objects before
    # checking that graph could execute an injected object's equality method.
    pending: list[tuple[Any, int]] = [(code, 0)]
    work, size = 0, 0
    while pending:
        value, depth = pending.pop()
        work += 1
        if work > 10000 or depth > MAX_FRAMES or size > 16 * 1024 * 1024:
            raise Refused('live code graph bound')
        kind = type(value)
        if kind is types.CodeType:
            if any(type(text) is not str for text in (
                    value.co_filename, value.co_name, value.co_qualname)):
                raise Refused('live code text type')
            for names in (value.co_names, value.co_varnames, value.co_freevars, value.co_cellvars):
                if (type(names) is not tuple or len(names) > 10000 - work
                        or any(type(name) is not str for name in names)):
                    raise Refused('live code name type')
                pending.extend((name, depth + 1) for name in names)
            if type(value.co_consts) is not tuple or len(value.co_consts) > 10000 - work:
                raise Refused('live code constant tuple')
            pending.extend((item, depth + 1) for item in value.co_consts)
            tables = (value.co_code, value.co_linetable, value.co_exceptiontable)
            if any(type(table) is not bytes for table in tables):
                raise Refused('live code table type')
            size += sum(len(table) for table in tables)
        elif kind in (tuple, frozenset):
            if len(value) > 10000 - work:
                raise Refused('live code constant width')
            pending.extend((item, depth + 1) for item in value)
        elif kind in (str, bytes):
            size += len(value) * (4 if kind is str else 1)
        elif kind is int:
            size += (value.bit_length() + 7) // 8
        elif value is None or value is Ellipsis or kind in (bool, float, complex):
            size += 16
        else:
            raise Refused('unsupported live code constant')
    if size > 16 * 1024 * 1024:
        raise Refused('live code graph bytes')


def _literal(value: object, depth: int = 0, budget: list[int] | None = None) -> object:
    budget = [4096, 2 * 1024 * 1024] if budget is None else budget
    budget[0] -= 1
    if depth > 16 or budget[0] < 0:
        raise Refused('default nesting or work bound')
    if value is None or type(value) is bool:
        return value
    if type(value) is int and value.bit_length() <= 64:
        return value
    if type(value) in (str, bytes) and len(cast(str | bytes, value)) <= 131071:
        budget[1] -= len(cast(str | bytes, value)) * (4 if type(value) is str else 1)
        if budget[1] < 0:
            raise Refused('default byte bound')
        return value
    if type(value) is tuple:
        return tuple((type(item), _literal(item, depth + 1, budget)) for item in value)
    raise Refused('mutable or unsupported source default')


def _namespace(container: object) -> dict[str, Any]:
    if type(container) in (types.ModuleType, type):
        values = vars(container)
    elif type(container) is dict:
        values = container
    else:
        raise Refused('namespace container refused')
    if len(values) > 8192:
        raise Refused('namespace size bound')
    result = {}
    for key, value in values.items():
        if type(key) is not str:
            raise Refused('non-string namespace key')
        result[key] = value
    return result


@dataclass(frozen=True)
class Link:
    """An explicit identity relation supplied by trusted bootstrap, not reflection.

    Globals and class attributes use their actual dictionaries, never getattr.
    Cell links refer to an exact function's closure index. An object identity does
    not certify contents of lists, dictionaries or user-defined instances.
    """
    container: object
    key: str | int
    expected: object
    mode: str = 'namespace'

    def check(self) -> None:
        if self.mode == 'cell':
            if (type(self.container) is not types.FunctionType or type(self.key) is not int
                    or self.key < 0 or self.container.__closure__ is None
                    or self.key >= len(self.container.__closure__)):
                raise Refused('closure link refused')
            try:
                actual = self.container.__closure__[self.key].cell_contents
            except ValueError as error:
                raise Refused('empty closure link') from error
        elif self.mode == 'static-function':
            if type(self.container) is not staticmethod or type(self.key) is not str or self.key != '__func__':
                raise Refused('static function link refused')
            actual = self.container.__func__
        elif self.mode == 'partial-function':
            from functools import partial
            if type(self.container) is not partial or type(self.key) is not str or self.key != 'func':
                raise Refused('partial function link refused')
            actual = self.container.func
        elif self.mode == 'frame':
            if type(self.container) is not types.FrameType or type(self.key) is not str:
                raise Refused('frame link refused')
            actual = self.container.f_locals.get(self.key)
        elif self.mode == 'namespace':
            if type(self.key) is not str:
                raise Refused('namespace link refused')
            namespace = _namespace(self.container)
            if self.key not in namespace:
                raise Refused('missing namespace link')
            actual = namespace[self.key]
        else:
            raise Refused('unknown identity link')
        if actual is not self.expected:
            raise Refused('live identity link changed')


def _default_snapshot(value, records, depth=0, budget=None):
    budget = [4096, 2 * 1024 * 1024] if budget is None else budget
    if not records:
        return _literal(value, depth, budget)
    budget[0] -= 1
    if type(records) is not tuple or len(records) > 8 or depth > 16 or budget[0] < 0:
        raise Refused('source default record bound')
    for index, record in enumerate(records):
        if type(record) is not tuple or len(record) != 3:
            raise Refused('source default record schema')
        anchor, cls, fields = record
        if type(cls) is not type or type(anchor) is not cls or type(fields) is not tuple:
            raise Refused('source default record identity')
        if value is anchor:
            actual = tuple(sorted(instance_fields(value).items()))
            if _literal(actual, depth + 1, budget) != _literal(fields, depth + 1, budget):
                raise Refused('source default record fields changed')
            return ('record', index)
    if type(value) is tuple:
        if len(value) > 4096:
            raise Refused('source default tuple bound')
        return ('tuple', tuple(_default_snapshot(item, records, depth + 1, budget) for item in value))
    return ('literal', type(value), _literal(value, depth, budget))


@dataclass(frozen=True)
class Owner:
    unit: SourceUnit
    module: types.ModuleType
    function: types.FunctionType
    qualified: str
    first_line: int
    call_lines: tuple[int, int]
    links: tuple[Link, ...]
    closure: tuple[object, ...] = ()
    cell_anchors: tuple[types.CellType, ...] = ()
    defaults: tuple[object, ...] | None = None
    keyword_defaults: tuple[tuple[str, object], ...] = ()
    default_objects: tuple[tuple[object, type, tuple[tuple[str, object], ...]], ...] = ()

    def verify_binding(self) -> None:
        """Check retained code and binding, without claiming a live caller frame."""
        if (type(self.module) is not types.ModuleType
                or type(self.function) is not types.FunctionType
                or _namespace(sys.modules).get(self.unit.module) is not self.module):
            raise Refused('live source module or function refused')
        namespace = _namespace(self.module)
        loader, spec = namespace.get('__loader__'), namespace.get('__spec__')
        if (type(namespace.get('__file__')) is not str or namespace['__file__'] != self.unit.path
                or type(namespace.get('__name__')) is not str or namespace['__name__'] != self.unit.module):
            raise Refused('live module origin or specification changed')
        if self.unit.mode == 'script':
            if self.unit.module != '__main__' or spec is not None:
                raise Refused('live script entry specification changed')
        elif (type(spec) is not importlib.machinery.ModuleSpec
                or type(spec.name) is not str or spec.name != self.unit.module
                or type(spec.origin) is not str or spec.origin != self.unit.path or spec.loader is not loader):
            raise Refused('live module origin or specification changed')
        if type(loader) is not self.unit.loader_type:
            raise Refused('prepared compiler loader identity changed')
        if self.unit.mode in ('plain', 'beartype-passive', 'script'):
            loader = cast(Any, loader)
            if (type(loader.path) is not str or loader.path != self.unit.path
                    or type(loader.name) is not str or loader.name != self.unit.module):
                raise Refused('plain compiler loader refused')
            if self.unit.mode == 'beartype-passive':
                # This class also serves ordinary untransformed imports. Its
                # inactive configuration delegates to CPython's plain compiler.
                # Active type-checking transformation is a different compiler
                # and remains unprepared; no live generated code is adopted.
                values = _namespace(vars(loader))
                if (values.get('_module_conf', False) is not None
                        or values.get('_module_name', False) is not None):
                    raise Refused('active or changed beartype compiler refused')
        elif self.unit.mode != 'pytest':
            raise Refused('unprepared compiler mode')
        function = self.function
        _safe_code(function.__code__)
        if (function.__globals__ is not vars(self.module)
                or function.__code__ != self.unit.code(self.qualified, self.first_line)
                or type(function.__module__) is not str or function.__module__ != self.unit.module
                or type(function.__qualname__) is not str or function.__qualname__ != self.qualified):
            raise Refused('live source code, globals or callsite changed')
        if not self.links or not any(link.expected is function for link in self.links):
            raise Refused('source owner needs an explicit live identity link')
        for link in self.links:
            link.check()
        cells = function.__closure__ or ()
        if (len(cells) != len(self.closure) or len(cells) != len(self.cell_anchors)
                or any(cell is not anchor for cell, anchor
                       in zip(cells, self.cell_anchors, strict=True))):
            raise Refused('closure layout changed')
        for cell, expected in zip(cells, self.closure, strict=True):
            try:
                actual = cell.cell_contents
            except ValueError as error:
                raise Refused('empty owner closure') from error
            if actual is not expected:
                raise Refused('owner closure changed')
        keyword_defaults = function.__kwdefaults__
        if keyword_defaults is None:
            keyword_defaults = {}
        if type(keyword_defaults) is not dict:
            raise Refused('keyword default dictionary type')
        actual_defaults = (function.__defaults__, tuple(sorted(_namespace(keyword_defaults).items())))
        expected_defaults = (self.defaults, self.keyword_defaults)
        if _default_snapshot(actual_defaults, self.default_objects) != _default_snapshot(expected_defaults, self.default_objects):
            raise Refused('source defaults changed')


    def current(self, frames: tuple[types.FrameType, ...], *, line: int | None = None,
                reason: str = 'source original caller frame') -> types.FrameType:
        if (type(frames) is not tuple or len(frames) > MAX_FRAMES
                or any(type(frame) is not types.FrameType for frame in frames)):
            raise Refused('source frame inventory')
        matches = [frame for frame in frames if frame.f_code is self.function.__code__]
        if len(matches) != 1 or line is not None and matches[0].f_lineno != line:
            raise Refused(reason)
        self.verify(matches[0])
        return matches[0]

    def verify(self, frame: types.FrameType) -> None:
        self.verify_binding()
        if (type(frame) is not types.FrameType or frame.f_code is not self.function.__code__
                or frame.f_globals is not vars(self.module)
                or not self.call_lines[0] <= frame.f_lineno <= self.call_lines[1]):
            raise Refused('live source code, globals or callsite changed')
        if self.closure:
            local = frame_fields(frame)
            for name, expected in zip(self.function.__code__.co_freevars, self.closure, strict=True):
                if name not in local or local[name] is not expected:
                    raise Refused('owner closure changed')


def frame_fields(frame: types.FrameType) -> dict[str, Any]:
    if type(frame) is not types.FrameType:
        raise Refused('source actual frame')
    result: dict[str, Any] = {}
    for key, value in frame.f_locals.items():
        if type(key) is not str or len(result) >= 8192:
            raise Refused('source frame fields')
        result[key] = value
    return result


def instance_fields(value):
    import types
    from source_owner import _namespace
    cls = type(value)
    # Native type descriptors avoid user-defined metaclass and __dict__ access.
    namespace_descriptor = vars(type)['__dict__']
    lineage_descriptor = vars(type)['__mro__']
    for parent in lineage_descriptor.__get__(cls, type(cls)):
        namespace = namespace_descriptor.__get__(parent, type(parent))
        fields: dict[str, Any] = {}
        for key, item in namespace.items():
            if type(key) is not str or len(fields) >= 8192:
                raise Refused('cleanup inline class namespace')
            fields[key] = item
        descriptor = fields.get('__dict__')
        if type(descriptor) not in (types.GetSetDescriptorType, types.MemberDescriptorType):
            continue
        native = cast(types.GetSetDescriptorType | types.MemberDescriptorType, descriptor)
        if native.__objclass__ is parent and native.__name__ == '__dict__':
            result = native.__get__(value, cls)
            _namespace(result)
            return result
    raise Refused('cleanup inline instance dictionary')



def active_frames() -> tuple[types.FrameType, ...]:
    """Current stack then missing await owners, nearest first; caller drops refs."""
    frames: list[types.FrameType] = []
    current: types.FrameType | None = sys._getframe(1)
    try:
        while current is not None:
            if len(frames) >= MAX_FRAMES:
                raise Refused('synchronous owner chain bound')
            frames.append(current)
            current = current.f_back
        if _ASYNCIO is None:
            return tuple(frames)
        asyncio = _ASYNCIO
        try:
            task = asyncio.current_task()
        except RuntimeError:
            task = None
        awaiting: Any = task.get_coro() if type(task) is asyncio.Task else None
        pending = []
        seen: set[int] = set()
        while type(awaiting) in (types.CoroutineType, types.GeneratorType):
            if id(awaiting) in seen or len(seen) >= MAX_FRAMES:
                raise Refused('coroutine owner chain bound')
            seen.add(id(awaiting))
            frame = awaiting.cr_frame if type(awaiting) is types.CoroutineType else awaiting.gi_frame
            if frame is not None:
                pending.append(frame)
            awaiting = awaiting.cr_await if type(awaiting) is types.CoroutineType else awaiting.gi_yieldfrom
        if awaiting is not None:
            raise Refused('unsupported current await owner')
        for frame in reversed(pending):
            if all(frame is not previous for previous in frames):
                frames.append(frame)
        if len(frames) > MAX_FRAMES:
            raise Refused('combined owner chain bound')
        return tuple(frames)
    finally:
        del current


def verify_chain(owners: tuple[Owner, ...], case: str, allowed_cases: tuple[str, ...]) -> None:
    """Authenticate a complete ordered source chain in the current call/await tree.

    `case` must come from separately authenticated pytest selection/parameter
    custody. This routine neither reads nor trusts the ambient test marker.
    """
    if not owners or len(owners) > MAX_FRAMES or case not in allowed_cases:
        raise Refused('source owner case or chain refused')
    paths = {owner.unit.path for owner in owners}
    frames = active_frames()
    try:
        selected = tuple(frame for frame in frames if frame.f_code.co_filename in paths)
        if len(selected) != len(owners):
            raise Refused('source owner chain changed')
        for owner, frame in zip(owners, selected, strict=True):
            owner.verify(frame)
    finally:
        del frames
