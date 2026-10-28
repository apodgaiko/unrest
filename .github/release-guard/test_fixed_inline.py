"""Fixed command contracts and unchanged original import-boundary assertions."""
import ast
import hashlib
import json
from pathlib import Path

import pytest

from content_manifest import Refused
from fixed_inline import ARGUMENTS, IMPORT_CASES, PINS, SEQUENCES, TEST, expected, script

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def test_literal_sources_and_exact_call_sites_are_pinned():
    for path,pin in PINS.items():
        assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest() == pin
    tree = ast.parse((ROOT/TEST).read_bytes())
    found = {}
    for function in tree.body:
        if isinstance(function,ast.FunctionDef) and function.name in ('_import_probe','test_mcp_help_does_not_import_repository_modules'):
            calls = [call for call in ast.walk(function) if isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute)
                     and isinstance(call.func.value,ast.Name) and call.func.value.id == 'subprocess' and call.func.attr == 'run']
            assert len(calls) == 1
            found[function.name] = calls[0].lineno
    assert found == {'_import_probe':540,'test_mcp_help_does_not_import_repository_modules':587}
    assert script(ROOT,'help') == script(ROOT,'check') and script(ROOT,'mcp') != script(ROOT,'help')


@pytest.mark.parametrize('case',IMPORT_CASES)
def test_each_fixed_declaration_is_limited_to_its_original_sequence(case):
    for operation in SEQUENCES[case]:
        result = expected(case,operation,'/native/python','a'*64,ROOT,{'PATH':'/usr/bin:/bin'})
        assert result.argv[:2] == ('/native/python','-c') and result.argv[2] == script(ROOT,operation)
        assert result.payload_sha256 == hashlib.sha256(result.argv[2].encode()).hexdigest()
        if operation != 'mcp':
            assert json.loads(result.argv[-1]) == list(ARGUMENTS[operation])
        if operation != 'check':
            with pytest.raises(Refused,match='query scope'):
                expected(case,operation,'/native/python','a'*64,ROOT,{},query=True)
    with pytest.raises(Refused,match='closed'):
        expected(case,'unregistered','/native/python','a'*64,ROOT,{})
