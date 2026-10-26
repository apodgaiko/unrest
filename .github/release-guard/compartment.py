"""Fixed source/observer credentials; no source-side privilege grant."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path

from linux_observation import process_identity

LIBC = ctypes.CDLL(None, use_errno=True)


def prctl(operation: int, value: int) -> None:
    if LIBC.prctl(operation, value, 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'compartment transition refused')


def credentials(uid: int) -> dict:
    if type(uid) is not int or uid not in (20000, 20001) or os.getuid() != 0:
        raise ValueError('fixed root-to-compartment transition required')
    if Path('/proc/sys/kernel/cap_last_cap').read_text().strip() != '40':
        raise RuntimeError('unknown capability ABI')
    capabilities = () if uid == 20000 else (2, 19)
    prctl(8, 1)
    for capability in range(41):
        if capability not in capabilities:
            prctl(24, capability)
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
    header = Header(0x20080522, 0)
    bits = sum(1 << capability for capability in capabilities)
    values = (Data * 2)(Data(bits, bits, 0), Data())
    if LIBC.capset(ctypes.byref(header), values):
        raise OSError(ctypes.get_errno(), 'compartment capability reduction refused')
    prctl(38, 1)
    actual = process_identity(os.getpid())
    if (actual['uids'] != [uid] * 4 or actual['gids'] != [uid] * 4
            or actual['capabilities'] != {'CapInh': 0, 'CapPrm': bits, 'CapEff': bits, 'CapBnd': bits, 'CapAmb': 0}
            or actual['no_new_privs'] != 1):
        raise RuntimeError('actual compartment credentials refused')
    return actual
