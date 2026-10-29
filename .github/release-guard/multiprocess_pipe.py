"""Exact inherited anonymous Unix file descriptions and actual owner births."""

from content_manifest import Refused
from socket_observation import acquire,descriptor


def owner(host,actor,*,body):
    process=host.ledger.process(actor['birth'])
    if (process.token!=actor['token']
            or process.registered_generation!=process.generation or process.case!=actor['case']
            or actor['case']!=host.case or process.exit is not None or process.terminal is not None
            or process.stage not in (('body-ready',) if body else ('core-ready','body-ready'))):
        raise Refused('spawn inherited Pipe current owner')
    return process


def parent_record(host,actor,fd):
    owner(host,actor,body=True)
    birth=actor['birth']
    return [*acquire(birth,fd),birth.pid,birth.ticks]


def local_record(saved):
    fd=saved[0]
    value=[fd,*descriptor(fd,20000),*saved[5:]]
    if value!=saved:
        raise Refused('spawn inherited Pipe file description changed')
    return value


def retained(host,actor,row,*,body):
    process=owner(host,actor,body=body)
    parent=process.parent
    if (actor['role']!='mp-child' or parent is None or (parent.pid,parent.ticks)!=tuple(row[5:])
            or parent.uid!=20000 or acquire(actor['birth'],row[0])!=row[:5]):
        raise Refused('spawn inherited Pipe original parent or file description')
