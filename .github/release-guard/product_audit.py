"""Let real product denials run before unchanged native effect enforcement."""
import sys
import threading

from content_manifest import Refused, refuse_if
from speed_inline import CASES as CHILD_CASES

CASES=tuple('tests/test_v04_speed_runner.py::test_'+name for name in (
    'closed_socket_is_not_a_preflight_false_positive_and_audit_is_inert_after_exit',
    'audit_and_wrapper_denials_each_count_exactly_once',
    'audit_guard_reaches_worker_threads'))
EVENTS=frozenset(('socket.__new__','socket.getaddrinfo','os.system','subprocess.Popen'))


class Order:
    def __init__(self,policy):
        self.policy,self.local=policy,threading.local()
        self.enabled,self.ack=False,False
        self.probe=object()

    def deferred(self,event):
        return (self.enabled and self.policy.case in (*CASES,*CHILD_CASES) and event in EVENTS
                and not getattr(self.local,'recheck',False))

    def tail(self,event,args):
        if event=='unrest.guard.audit-tail' and len(args)==1 and args[0] is self.probe:
            self.ack=True
        elif self.deferred(event):
            self.local.recheck=True
            try:
                # Native hooks run again, with deferral disabled. An absent
                # product denial therefore reaches the original outer policy.
                sys.audit(event,*args)
            finally:
                self.local.recheck=False

    def install(self):
        if self.enabled:
            return
        sys.addaudithook(self.tail)
        sys.audit('unrest.guard.audit-tail',self.probe)
        refuse_if(not self.ack, 'product audit tail was not installed')
        self.enabled=True


def child():
    from source_entry import ACTIVE
    if ACTIVE is None or ACTIVE.profile['role']!='fixed-inline' or ACTIVE.case not in CHILD_CASES:
        raise Refused('product child audit scope')
    __import__('tools.v04_speed_runner')
    order=Order(ACTIVE)
    order.install()
    ACTIVE.audit_order=order
