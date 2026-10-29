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


def test_journal_keeps_the_original_sleep_and_no_descendant_authority():
    from fixed_inline import JOURNAL_CASE, JOURNAL_TEST, GROUPS, translated
    tree=ast.parse((ROOT/JOURNAL_TEST).read_bytes())
    owner=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==JOURNAL_CASE.split('::')[-1])
    call=next(node for node in ast.walk(owner) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='Popen')
    body=ast.literal_eval(call.args[0].elts[2])
    value=expected(JOURNAL_CASE,'sleep','/native/python','a'*64,ROOT,{'PATH':'/bin:/usr/bin'})
    assert value.argv==('/native/python','-c',body)
    assert body=='import time; time.sleep(10)'
    assert dict(value.environment)=={'PATH':'/bin:/usr/bin'}
    assert translated(value)==('/native/python','-I','-S','-c',body)
    assert (JOURNAL_CASE,) in GROUPS and SEQUENCES[JOURNAL_CASE]==('sleep',)
    with pytest.raises(Refused,match='no descendants'):
        expected(JOURNAL_CASE,'sleep','/native/python','a'*64,ROOT,{},query=True)


def test_journal_zero_signal_is_one_owned_liveness_probe_not_generic_permission(monkeypatch):
    import source_observer
    from source_observer import Observer
    from fixed_inline import JOURNAL_CASE
    from test_process_ledger import setup
    ledger,root,child=setup()
    host=object.__new__(Observer)
    host.case,host.root_birth,host.finished,host.ledger=JOURNAL_CASE,root,False,ledger
    actor={'role':'root','birth':root}
    target={'role':'fixed-inline','birth':child,'case':JOURNAL_CASE,'token':'child-token','signals':set()}
    host.actors={child.pid:target}
    monkeypatch.setattr(source_observer,'process_identity',lambda pid:ledger.process(child).identity)
    message={'kind':'custody_signal','payload':{'pid':child.pid,'child_token':'child-token','signal':0,'group':False}}
    assert host.dispatch(actor,message)=={'ok':True,'live':True}
    assert target['liveness_probes']==1 and not target['signals']
    with pytest.raises(Refused,match='liveness probe'):
        host.dispatch(actor,message)
    target.pop('liveness_probes')
    host.case=target['case']='foreign-case'
    with pytest.raises(Refused,match='liveness probe'):
        host.dispatch(actor,message)
