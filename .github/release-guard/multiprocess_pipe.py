"""A child may inherit one member of an already admitted root-owned Unix pair."""
import fcntl
import os
from pathlib import Path
import socket
import stat
import struct

from content_manifest import Refused
from linux_observation import process_identity
from process_ledger import Birth
from socket_observation import acquire_unix_member,retained_unix_member


def parent_record(host,actor,fd):
    pair=host.descriptors.get((actor['birth'],fd))
    if pair is None or pair.case!=host.case or pair.owner!=host.owner(actor):
        raise Refused('spawn Pipe needs original owned pair')
    member=acquire_unix_member(actor['birth'],fd,pair)
    host.pairs.retained(pair,host.owner(actor),member)
    path=Path('/proc')/str(actor['birth'].pid)/'fd'/str(fd)
    info=path.stat()
    flags=[line.split()[1] for line in (path.parent.parent/'fdinfo'/str(fd)).read_text().splitlines() if line.startswith('flags:')]
    if (member is None or member.state!=1 or member.peer<=0 or not stat.S_ISSOCK(info.st_mode)
            or info.st_uid!=20000 or info.st_ino!=member.inode or len(flags)!=1
            or int(flags[0],8)&~os.O_CLOEXEC!=os.O_RDWR):
        raise Refused('spawn exact Pipe member custody')
    return [fd,info.st_dev,member.inode,os.O_RDWR,member.cookie,member.peer,pair.serial]


def local_record(saved):
    # Query only this inherited file description; child bootstrap gains no
    # netlink or new socket family. The observer separately verifies its peer.
    fd=saved[0]
    info=os.fstat(fd)
    flags=fcntl.fcntl(fd,fcntl.F_GETFL)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid!=20000
            or [info.st_dev,info.st_ino,os.O_RDWR]!=saved[1:4] or flags&~os.O_CLOEXEC!=os.O_RDWR):
        raise Refused('spawn inherited Pipe file identity')
    with socket.socket(fileno=os.dup(fd)) as stream:
        if (stream.getsockopt(socket.SOL_SOCKET,39)!=socket.AF_UNIX
                or stream.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_STREAM
                or struct.unpack('=Q',stream.getsockopt(socket.SOL_SOCKET,57,8))[0]!=saved[4]):
            raise Refused('spawn inherited Pipe cookie or domain')
    after=os.fstat(fd)
    if (info.st_dev,info.st_ino,info.st_uid)!=(after.st_dev,after.st_ino,after.st_uid):
        raise Refused('spawn inherited Pipe changed during query')
    return list(saved)


def retained(host,actor,row,*,body):
    host.endpoints.owner(host.owner(actor),actor['case'],body=body)
    pair=host.pairs.pairs.get(row[6])
    process=host.ledger.process(actor['birth'])
    if (actor['role']!='mp-child' or actor['case']!=host.case or pair is None or pair.case!=host.case
            or process.parent!=pair.owner.birth or process.exit is not None or process.terminal is not None
            or not any((member.inode,member.cookie,member.uid,member.peer)==(row[2],row[4],20000,row[5]) for member in pair.members)):
        raise Refused('spawn inherited Pipe original pair generation')
    birth=actor['birth']
    if Birth.read(process_identity(birth.pid))!=birth:
        raise Refused('spawn inherited Pipe child birth')
    observed=retained_unix_member(birth.pid,row[0],[{'fd':row[0],'inode':row[2],
        'socket_cookie':row[4],'socket_uid':20000,'peer_inode':row[5]}])
    if (observed is None or observed['state'] not in ((1,7) if body else (1,))
            or not body and observed.get('peer_inode')!=row[5]
            or Birth.read(process_identity(birth.pid))!=birth):
        raise Refused('spawn inherited Pipe live member changed')
