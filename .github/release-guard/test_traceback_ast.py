"""AST-only diagnostic parsing does not grant bytecode or a second body."""
import ast
import sys
import traceback

import pytest

from content_manifest import Refused
from traceback_ast import Diagnostics

_ACTIVE = [None]


def _audit(event,args):
    if event == 'compile' and _ACTIVE[0] is not None:
        _ACTIVE[0].allow(args)


sys.addaudithook(_audit)


def test_original_formatter_can_parse_only_its_diagnostic_ast():
    gate = Diagnostics()
    _ACTIVE[0] = gate
    try:
        traceback._extract_caret_anchors_from_line_segment('value[0]')
    finally:
        _ACTIVE[0] = None
    assert gate.count == 1


@pytest.mark.parametrize('method',['compile','parse','changed-formatter','replaced-compiler'])
def test_compilers_outside_original_traceback_ast_refuse(monkeypatch,method):
    gate = Diagnostics()
    if method == 'changed-formatter':
        original = traceback._extract_caret_anchors_from_line_segment
        monkeypatch.setattr(traceback,'_extract_caret_anchors_from_line_segment',lambda text:original(text))
    elif method == 'replaced-compiler':
        import builtins
        original_compile = builtins.compile
        monkeypatch.setattr(builtins,'compile',lambda *args,**kwargs:original_compile(*args,**kwargs))
    _ACTIVE[0] = gate
    try:
        with pytest.raises(Refused):
            if method == 'compile':
                compile('value[0]','<unknown>','exec')
            elif method == 'parse':
                ast.parse('value[0]')
            else:
                traceback._extract_caret_anchors_from_line_segment('value[0]')
    finally:
        _ACTIVE[0] = None


@pytest.mark.parametrize('target',['parser','formatter'])
def test_live_namespace_collisions_refuse_without_callbacks(monkeypatch,target):
    gate = Diagnostics()
    class Trap:
        def __hash__(self):
            return hash('compile' if target == 'parser' else '_extract_caret_anchors_from_line_segment')
        def __eq__(self,other):
            pytest.fail('namespace equality callback')
    if target == 'parser':
        namespace = vars(ast)
        key = Trap()
        namespace[key] = compile
        try:
            with pytest.raises(Refused):
                gate.allow(('value[0]','<unknown>'))
        finally:
            del namespace[key]
    else:
        original = traceback._extract_caret_anchors_from_line_segment
        monkeypatch.delattr(traceback,'_extract_caret_anchors_from_line_segment')
        namespace,key = vars(traceback),Trap()
        namespace[key] = original
        _ACTIVE[0] = gate
        try:
            with pytest.raises(Refused):
                original('value[0]')
        finally:
            _ACTIVE[0] = None
            del namespace[key]
