"""Network namespace containment; application TCP topology is not certification."""
import os
import fcntl
import socket
import struct
from pathlib import Path
from content_manifest import Refused as Refused, refuse_if


def port_argument(value):
    refuse_if(type(value) is not str or not value.isascii() or not value.isdigit() or not 0<len(value)<=5, 'source literal loopback port argument')
    port=int(value)
    refuse_if(not 1<=port<=65535, 'source literal loopback port argument')
    return port


def isolated(before):
    namespace=os.readlink('/proc/self/ns/net')
    refuse_if(namespace==before or {row.split(':')[0].strip() for row in Path('/proc/self/net/dev').read_text().splitlines()[2:]}!={'lo'}, 'source private loopback namespace')
    ipv4=Path('/proc/net/route').read_text().splitlines()[1:]
    for row in ipv4:
        fields=row.split()
        refuse_if(len(fields)!=11 or fields[0]!='lo' or fields[2]!='00000000', 'source external IPv4 route')
    for row in Path('/proc/net/ipv6_route').read_text().splitlines():
        fields=row.split()
        refuse_if(len(fields)!=10 or fields[-1]!='lo' or fields[4]!='0'*32
                or fields[0]!='0'*31+'1' and not int(fields[8],16)&0x200, 'source external IPv6 route')
    return namespace


def configure(before):
    refuse_if(os.getuid()!=0, 'private network setup requires its trusted root')
    isolated(before)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as control:
        request=struct.pack('16sH14x',b'lo',0)
        current=fcntl.ioctl(control.fileno(),0x8913,request)
        flags=struct.unpack_from('H',current,16)[0]
        fcntl.ioctl(control.fileno(),0x8914,struct.pack('16sH14x',b'lo',flags|1))
        # glibc AI_ADDRCONFIG excludes 127.0.0.1 itself. A second loopback
        # address supplies real IPv4 discovery without another interface/route.
        fcntl.ioctl(control.fileno(),0x8916,struct.pack('16sH2x4s16x',
            b'lo:guard',socket.AF_INET,socket.inet_aton('127.0.0.2')))
    return isolated(before)
