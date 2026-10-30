"""Closed source profile consumption, before any candidate body."""
from __future__ import annotations

import os
import fcntl
import hashlib
import json
from pathlib import Path
import sys

from content_manifest import Refused, capture
from linux_observation import credential_identity, process_identity
from process_ledger import Birth, canonical
from postbuild_root import CASES as ARCHIVE_CASES, COMMAND as ARCHIVE_COMMAND

METHODS = frozenset({'collection', 'body-ready', 'case-start', 'case-finish', 'root-finish',
    'archive-snapshot','archive-result','preselected-finish','fixture-root','multiprocess-proposal','launch-proposal',
    'self-group','approval-signal','self-probe','private-unix','custody_signal', 'resumed-signal', 'custody_close', 'self-stop', 'guard-refusal'})


PYTEST_COMMAND=('pytest','-q')


def case_seal(cases):
    return {'count': len(cases), 'cases_sha256': hashlib.sha256(json.dumps(cases, separators=(',', ':')).encode()).hexdigest()}


def digest(path: Path) -> str:
    return capture(path.parent, [path.name])['files'][0]['sha256']


def inherited_descriptor(expected, descriptor, info, flags, uid):
    from socket_observation import pipe_info
    value=pipe_info(info,flags,uid)
    if (type(descriptor) is not int or not 3<=descriptor<=1024
            or expected!=[[descriptor,*value]]):
        raise Refused('source ambient inherited descriptor')
    return [descriptor,*value]


def validate(profile: dict, event: str, arguments: tuple) -> dict:
    full=type(profile['cases']) is dict
    if Path(profile['native']) != Path(profile['runtime_root']) / 'bin/python-unrest-guard-control':
        raise Refused('source native runtime root')
    actual = process_identity(os.getpid())
    filesystem = os.stat('/')
    root = profile.get('filesystem_root')
    if (type(root) is not list or any(type(value) is not int for value in root)
            or root != [filesystem.st_dev, filesystem.st_ino]):
        raise Refused('source private filesystem generation')
    parent, observer = Birth.read(profile['parent']), Birth.read(profile['observer'])
    if (canonical(profile['identity']) != profile['identity'] or canonical(actual) != profile['identity'] or parent.pid != os.getppid()
            or Birth.read(credential_identity(parent.pid)) != parent or observer.uid != 20001
            or (parent.uid != 20000 if full and profile['role']=='root' else parent != observer if profile['role'] == 'root' else parent.uid != 20000)
            or profile['network_namespace']!=os.readlink('/proc/self/ns/net')
            or actual['namespaces']['net']!=profile['network_namespace']
            or actual['namespaces']['mnt']!=profile['mount_namespace']
            or actual['namespaces']['pid']!=profile['pid_namespace']
            or profile['pid_namespace']!=os.readlink('/proc/self/ns/pid')
            or actual['uids'] != [20000] * 4 or actual['gids'] != [20000] * 4
            or any(actual['capabilities'].values()) or actual['no_new_privs'] != 1 or actual['seccomp'] != 2
            or type(profile['generation']) is not int or profile['generation'] != 1
            or [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode, sys.flags.utf8_mode] != [1, 1, 0, 1]
            or (str(Path(profile['runtime_root'])/'bin/pytest') if full and profile['role']=='root' else profile['native']) != sys.executable or digest(Path(sys.executable)) != profile['native_sha256']
            or digest(Path(__file__).with_name('native_entry.py')) != profile['entry_sha256']):
        raise Refused('source actual profile binding')
    if (profile['environment'] != dict(os.environ) or profile['cwd'] != os.getcwd()
            or profile['argv'] != sys.orig_argv):
        raise Refused('source actual request binding')
    inherited = profile['inherited']
    if profile['role'] in ('mp-child','mp-tracker'):
        from multiprocess_entry import inherited as validate_inherited
        validate_inherited(profile,actual)
    else:
        from inline_leaves import STREAM_CASES
        mcp = profile['role']=='mcp' and profile['execution']['event']=='cpython.run_module' and profile['execution']['argument']=='unrest_harness'
        from approval_launch import CASES as APPROVAL
        mcp = mcp or profile['role']=='mcp' and profile['case'] in APPROVAL
        mcp = mcp or profile['role']=='fixed-inline' and profile['case'] in STREAM_CASES
        if (type(inherited) is not list or (not mcp and inherited)
                or mcp and (len(inherited) != 1 or type(inherited[0]) is not list
                    or len(inherited[0]) != 3 or any(type(value) is not int or value <= 0 for value in inherited[0]))):
            raise Refused('source finite inherited inventory')
        seen = []
        for name in os.listdir('/proc/self/fd'):
            descriptor = int(name)
            if descriptor > 2:
                try:
                    info = os.fstat(descriptor)
                except OSError:
                    continue
                seen.append(inherited_descriptor(inherited, descriptor, info,
                                                  fcntl.fcntl(descriptor, fcntl.F_GETFL), actual['uids'][0]))
        if seen != inherited:
            raise Refused('source missing inherited inventory')
    from execution_spec import validate as validate_execution
    validate_execution(profile,event,arguments,Path(__file__).parent.parent/'profiles')
    native = profile['native']
    role, script = profile['role'], profile['script']
    if role == 'root' and not full and tuple(profile['cases'])==ARCHIVE_CASES:
        if (profile['cwd']!=profile['checkout'] or script is not None or event!='cpython.run_command'
                or arguments!=(ARCHIVE_COMMAND+'\n',) or len(profile['argv'])!=6
                or profile['argv'][:5]!=[native,'-I','-S','-c',ARCHIVE_COMMAND]
                or not Path(profile['argv'][5]).is_absolute() or str(Path(profile['argv'][5]).resolve())!=profile['argv'][5]
                or Path(profile['checkout']).is_relative_to(Path(profile['argv'][5]))):
            raise Refused('archive fixed original oracle body')
    elif role == 'root' and not full:
        raise Refused('source unknown root domain')
    return actual
