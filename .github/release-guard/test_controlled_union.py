"""Closed image/configuration alternatives do not select native transport."""
import os
from pathlib import Path

import pytest

import controlled_cases as live
import test_controlled_catalogue as original
from content_manifest import Refused
from controlled_startup import expected_entry

ROOT=next(path for path in Path(__file__).resolve().parents if (path/'pyproject.toml').is_file())
CASE=next(case for case in original.CASES if 'test_ack_durability[' in case)


@pytest.fixture
def backend(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT))
    from tests.test_experimental_session import session
    owner=session.__wrapped__(tmp_path,None)
    monkeypatch.setattr(live,'SOURCE_UID',os.getuid())
    home=owner.root/'worker'
    home.mkdir(exist_ok=True)
    return home,owner.backend_launcher


def operands(value):
    return {'argv':list(value.argv),'environment':dict(value.environment),'cwd':value.cwd}


def test_original_images_and_protected_exception_sets_remain_exact():
    assert set(live.BACKENDS.items())==set(original.CASES.values())
    assert len(live.BACKENDS)==27 and all(live.eligible(case) for case in original.CASES)
    assert set(live.WARNING_REFUSALS)==set(original.WARNING_REFUSALS)
    assert set(live.NOTIFICATION_SIGNALS)==set(original.NOTIFICATION_SIGNALS)
    assert live.NATIVE_MODULES=={case.split('::')[0] for case in (*original.ADMISSION,*original.NOTIFICATION_STARTUP,*original.NOTIFICATION_SIGNALS,*original.ROOT_HTTP)}
    assert not live.eligible('tests/test_experimental_cohort.py::unapproved')
    assert not live.eligible('tests/foreign.py::unapproved')
    assert not live.eligible(None)


@pytest.mark.parametrize('variant',range(4))
def test_exact_configuration_variant_is_retained_by_the_actual_backend_pair(backend,variant):
    home,_=backend
    pin=live.acquire_backend(CASE,home)
    value,_,_=expected_entry(CASE,ROOT,home,'/native/python','a'*64,backend=True,variant=variant,backend_pin=pin)
    (selected,_,_),actual=live.select_entry(CASE,ROOT,home,'/native/python','a'*64,operands(value),backend=True,relay=None,records=[])
    assert selected==value and actual==variant
    records=[{'cwd':str(home),'role':'backend','controlled_variant':actual}]
    relay=[12345,'b'*64,12346,'c'*64]
    value,_,_=expected_entry(CASE,ROOT,home,'/native/python','a'*64,backend=False,variant=variant,relay=relay)
    assert live.select_entry(CASE,ROOT,home,'/native/python','a'*64,operands(value),backend=False,relay=relay,records=records)[1]==variant
    foreign,_,_=expected_entry(CASE,ROOT,home,'/native/python','a'*64,backend=False,variant=(variant+1)%4,relay=relay)
    with pytest.raises(Refused,match='original launch operands'):
        live.select_entry(CASE,ROOT,home,'/native/python','a'*64,operands(foreign),backend=False,relay=relay,records=records)
    with pytest.raises(Refused,match='configuration pair'):
        live.select_entry(CASE,ROOT,home,'/native/python','a'*64,operands(value),backend=False,relay=relay,records=[])


def test_unknown_bytes_and_file_aliases_do_not_become_controlled_selection(backend):
    home,file=backend
    assert live.acquire_backend(CASE,home)==live.STANDARD[0]
    file.write_bytes(b'unknown executable body')
    with pytest.raises(Refused,match='unknown controlled backend'):
        live.acquire_backend(CASE,home)
    file.unlink()
    file.symlink_to(ROOT/'tests/fixtures/experimental_session_app_server.py')
    with pytest.raises(Refused):
        live.acquire_backend(CASE,home)


def test_cohort_configuration_and_image_do_not_borrow_ordinary_union(backend,monkeypatch):
    from cohort_controller import CASES
    home,_=backend
    case=CASES[1]
    pin=live.acquire_backend(case,home)
    value,_,_=expected_entry(case,ROOT,home,'/native/python','a'*64,backend=True,variant=1,backend_pin=pin)
    with pytest.raises(Refused,match='original launch operands'):
        live.select_entry(case,ROOT,home,'/native/python','a'*64,operands(value),backend=True,relay=None,records=[])
    monkeypatch.setattr(live,'read_regular',lambda *args,**kwargs:(None,None,original.DRAIN[0]))
    with pytest.raises(Refused,match='unknown controlled backend'):
        live.acquire_backend(case,home)


@pytest.mark.parametrize('role',('fixed-inline','git-custody','backend','acp'))
def test_module_eligibility_changes_only_backend_pair_cwd_quotas(role):
    from types import SimpleNamespace
    from launch_policy import build_expected
    from source_observer import Observer
    case='tests/test_controlled_python_acp.py::ordinary-active-node'
    host=SimpleNamespace(case=case,serial=1,root_birth='root',intents={
        1:{'case':case,'role':role,'cwd':'/owned/first','consumed':True}})
    expected=build_expected(case,'/native/python','a'*64,('/native/python','-c','pass'),(),'/owned/second','python-command')
    if role in ('backend','acp'):
        assert Observer.admit_launch(host,{'birth':'root'},expected,role,list(expected.argv),None)['ticket']==2
    else:
        with pytest.raises(Refused,match='independent launch reconstruction'):
            Observer.admit_launch(host,{'birth':'root'},expected,role,list(expected.argv),None)
