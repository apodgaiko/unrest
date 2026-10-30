"""Interpret actual filter instructions; native controls prove kernel behavior."""
import struct

import pytest

from linux_trace import observation_filter


def action(number, family=0, kind=0, protocol=0, *, architecture=0xC000003E):
    data=struct.pack('<IIQQQQQQQ',number,architecture,0,family,kind,protocol,0,0,0)
    rows=observation_filter()
    pc=value=0
    for _ in range(len(rows)):
        code,yes,no,operand=rows[pc]
        if code==0x20:
            value=int.from_bytes(data[operand:operand+4],'little')
        elif code in (0x15,0x35):
            pc+=yes if (value==operand if code==0x15 else value>=operand) else no
        elif code==0x54:
            value&=operand
        elif code==0x06:
            return operand
        else:
            pytest.fail('unknown actual filter instruction')
        pc+=1
    pytest.fail('filter did not terminate')


def test_filter_keeps_only_namespace_contained_socket_classes_and_route_queries():
    for number in (41,53):
        for family in (0,1,2,10,16,17,38,40,0x100000001):
            for kind in (0,1,2,3,5):
                for flags in (0,0x800,0x80000,0x80800,0x100):
                    for protocol in (0,1,6,17,31):
                        allowed=(family in (2,10) and kind in (1,2) and protocol in (0,6,17)
                            or family==1 and kind in (1,2) and protocol==0
                            or family==16 and kind==3 and protocol==0)
                        # Kernel socket arguments are int-sized, like BPF's low words.
                        if family==0x100000001:
                            allowed=kind in (1,2) and protocol==0
                        allowed=allowed and flags!=0x100
                        assert action(number,family,kind|flags,protocol)==(0x7FFF0000 if allowed else 0x7FF00000)


@pytest.mark.parametrize('number',(59,61,322,425,426,427))
def test_exec_wait_and_all_ring_entrypoints_always_stop(number):
    assert action(number)==0x7FF00000


def test_other_syscalls_do_not_add_stops_and_foreign_abis_cannot_bypass():
    for number in (0,1,3,9,42,44,46,49,60,202,231):
        assert action(number)==0x7FFF0000
    assert action(0x40000029,2,1,0)==0x80000000
    assert action(41,2,1,0,architecture=0x40000003)==0x80000000
