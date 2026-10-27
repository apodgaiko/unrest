"""Original CPython traceback formatting may parse ASTs, never execute code."""
from __future__ import annotations

import ast
import builtins
import sys
import traceback

from content_manifest import Refused
from source_owner import _namespace, frame_fields

_GETFRAME = sys._getframe


class Diagnostics:
    def __init__(self):
        self.parse,self.parse_code = ast.parse,ast.parse.__code__
        self.compiler = builtins.compile
        self.callers = tuple((container,name,vars(container)[name],vars(container)[name].__code__)
            for container,name in ((traceback,'_extract_caret_anchors_from_line_segment'),
                                   (traceback.StackSummary,'_should_show_carets')))
        self.count = 0

    def allow(self,args):
        if (type(args) is not tuple or len(args) != 2 or type(args[0]) not in (str,bytes)
                or len(args[0].encode() if type(args[0]) is str else args[0]) > 4*1024*1024 or type(args[1]) is not str or args[1] != '<unknown>'
                or self.count >= 32 or ast.parse is not self.parse or self.parse.__code__ is not self.parse_code
                or _namespace(ast).get('compile',self.compiler) is not self.compiler or builtins.compile is not self.compiler):
            raise Refused('sealed traceback AST inputs')
        found_parse,found_caller = False,False
        frame = _GETFRAME(1)
        try:
            for _ in range(64):
                if frame is None:
                    break
                if frame.f_code is self.parse_code and frame.f_globals is self.parse.__globals__:
                    values = frame_fields(frame)
                    if (type(values.get('flags')) is not int or values['flags'] != 1024
                            or type(values.get('source')) is not str
                            or (values['source'].encode() if type(args[0]) is bytes else values['source']) != args[0]
                            or type(values.get('filename')) is not str or values['filename'] != '<unknown>'
                            or type(values.get('mode')) is not str or values['mode'] != 'exec'):
                        raise Refused('sealed traceback requires AST-only compilation')
                    found_parse = True
                for container,name,function,code in self.callers:
                    if frame.f_code is code and frame.f_globals is function.__globals__:
                        if _namespace(container).get(name) is not function or function.__code__ is not code:
                            raise Refused('sealed traceback original formatter')
                        found_caller = True
                frame = frame.f_back
            if not found_parse or not found_caller:
                raise Refused('sealed traceback original AST caller')
            self.count += 1
            return True
        finally:
            del frame
