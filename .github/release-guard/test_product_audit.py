"""Audit sequencing controls; original native cases prove real product counters."""
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from product_audit import CASES,EVENTS,Order
import product_audit


@pytest.mark.parametrize('event',sorted(EVENTS))
@pytest.mark.parametrize('product_denies',[False,True])
def test_product_denial_precedes_fallback_but_missing_denial_rechecks_native(monkeypatch,event,product_denies):
    policy=SimpleNamespace(case=CASES[1])
    order=Order(policy)
    tails,records=[],[]
    class ProductDenied(RuntimeError):
        pass
    def audit(name,*args):
        if name in EVENTS:
            if order.deferred(name):
                records.append('native-deferred')
            else:
                records.append('native-refused')
                raise Refused('unchanged native policy')
            if product_denies:
                records.append('product-denied')
                raise ProductDenied()
        for tail in tails:
            tail(name,args)
    monkeypatch.setattr(product_audit.sys,'addaudithook',tails.append)
    monkeypatch.setattr(product_audit.sys,'audit',audit)
    order.install()
    order.install()
    assert len(tails)==1 and order.enabled and order.ack
    with pytest.raises(ProductDenied if product_denies else Refused):
        audit(event,b'original argument')
    assert records==['native-deferred','product-denied' if product_denies else 'native-refused']
    assert not getattr(order.local,'recheck',False)


def test_silent_hook_rejection_never_arms_native_deferral(monkeypatch):
    order=Order(SimpleNamespace(case=CASES[0]))
    monkeypatch.setattr(product_audit.sys,'addaudithook',lambda hook:None)
    monkeypatch.setattr(product_audit.sys,'audit',lambda *args:None)
    with pytest.raises(Refused,match='not installed'):
        order.install()
    assert not order.enabled and not order.deferred('os.system')


def test_foreign_case_or_event_and_thread_recheck_keep_native_first():
    policy=SimpleNamespace(case=CASES[0])
    order=Order(policy)
    order.enabled=True
    assert order.deferred('os.system')
    assert not order.deferred('unknown')
    policy.case='foreign'
    assert not order.deferred('os.system')
    policy.case=CASES[0]
    order.local.recheck=True
    assert not order.deferred('os.system')


def test_recheck_state_is_thread_local():
    import threading
    order=Order(SimpleNamespace(case=CASES[0]))
    order.enabled=True
    order.local.recheck=True
    observed=[]
    thread=threading.Thread(target=lambda:observed.append(order.deferred('os.system')))
    thread.start()
    thread.join(2)
    assert not thread.is_alive() and observed==[True]
    assert not order.deferred('os.system')
