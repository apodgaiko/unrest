"""Credential transitions for the private Linux source compartment."""
from __future__ import annotations
import ctypes
import os
from pathlib import Path

SOURCE_UID = 20000
OBSERVER_UID = 20001
LIBC = ctypes.CDLL(None, use_errno=True)

def prctl(operation, value):
    if LIBC.prctl(operation, value, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'finite compartment credential transition')

def source_credentials():
    if int(Path('/proc/sys/kernel/cap_last_cap').read_text()) != 40:
        raise RuntimeError('unknown capability ABI')
    for capability in range(41):
        prctl(24, capability)
    os.setgroups([])
    os.setgid(SOURCE_UID)
    os.setuid(SOURCE_UID)
    prctl(38, 1)

def observer_credentials():
    os.setgroups([])
    os.setgid(OBSERVER_UID)
    prctl(8, 1)
    for capability in range(41):
        if capability not in (2, 19):
            prctl(24, capability)
    os.setuid(OBSERVER_UID)
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                    ('inheritable', ctypes.c_uint32)]
    header = Header(0x20080522, 0)
    bits = (1 << 2) | (1 << 19)
    data = (Data * 2)(Data(bits, bits, 0), Data())
    if LIBC.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), 'observer capability reduction')
    prctl(38, 1)
