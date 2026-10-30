"""Finite spawn transport; target labels are metadata, never provenance."""
from pathlib import Path
import os
import stat
import fcntl
import ctypes

from content_manifest import Refused, refuse_if
from launch_policy import build_expected,check_expected,admit_expected
MODULES=frozenset('tests/'+name+'.py' for name in (
    'test_multiprocess_resource_ownership','test_attention','test_patch_transaction',
    'test_project_lock','test_supervision','test_supervision_finalization','test_supervision_nested',
    'test_supervision_paths','test_supervision_transactions','test_terminal_review_report_ordering'))
ZERO='tests/test_multiprocess_resource_ownership.py::test_altered_stdlib_stop_is_refused_before_launch'


def eligible(case):
    return type(case) is str and case!=ZERO and case.partition('::')[0] in MODULES


def fd_record(pid,fd):
    if type(fd) is not int or not 3<=fd<=1024:
        raise Refused('spawn descriptor number')
    path=Path('/proc')/str(pid)/'fd'/str(fd)
    info=path.stat()
    flags=[line.split()[1] for line in (path.parent.parent/'fdinfo'/str(fd)).read_text().splitlines() if line.startswith('flags:')]
    if (len(flags)!=1 or not stat.S_ISFIFO(info.st_mode) or info.st_uid!=20000):
        raise Refused('spawn owned FIFO')
    access=int(flags[0],8)&os.O_ACCMODE
    refuse_if(access not in (os.O_RDONLY,os.O_WRONLY), 'spawn FIFO direction')
    return [fd,info.st_dev,info.st_ino,access]


def arena_record(pid,fd):
    path=Path('/proc')/str(pid)/'fd'/str(fd)
    info=path.stat()
    flags=[line.split()[1] for line in (path.parent.parent/'fdinfo'/str(fd)).read_text().splitlines() if line.startswith('flags:')]
    if (type(fd) is not int or not 3<=fd<=1024 or not stat.S_ISREG(info.st_mode)
            or info.st_uid!=20000 or info.st_nlink!=0 or stat.S_IMODE(info.st_mode)!=0o600
            or info.st_size!=4096 or len(flags)!=1
            or int(flags[0],8)&~(os.O_CLOEXEC|0o100000)!=(os.O_RDWR|os.O_NOFOLLOW)):
        raise Refused('spawn exact anonymous shared arena', {'fd':fd,'mode':info.st_mode,'uid':info.st_uid,
            'links':info.st_nlink,'size':info.st_size,'flags':flags})
    return [fd,info.st_dev,info.st_ino,os.O_RDWR,4096]


def spawn_record(pid,fd):
    try:
        return fd_record(pid,fd)
    except Refused:
        return arena_record(pid,fd)


def stderr_record(pid,fd):
    if type(fd) is not int or not 3<=fd<=1024:
        raise Refused('tracker stderr descriptor')
    path=Path('/proc')/str(pid)/'fd'/str(fd)
    info=path.stat()
    stderr=path.with_name('2').stat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600
            or info.st_uid!=20000 or info.st_nlink!=0
            or (info.st_dev,info.st_ino,info.st_mode)!=(stderr.st_dev,stderr.st_ino,stderr.st_mode)):
        raise Refused('tracker anonymous captured stderr')
    # Linux/x86-64 KCMP_FILE proves the same open file description, not merely
    # another descriptor pointing at the same inode.
    refuse_if(ctypes.CDLL(None,use_errno=True).syscall(312,pid,pid,0,fd,2)!=0, 'tracker stderr open file identity')
    flags=[line.split()[1] for line in (path.parent.parent/'fdinfo'/str(fd)).read_text().splitlines() if line.startswith('flags:')]
    if len(flags)!=1 or int(flags[0],8)&os.O_ACCMODE!=os.O_RDWR:
        raise Refused('tracker stderr access')
    return [fd,info.st_dev,info.st_ino,int(flags[0],8)&~os.O_CLOEXEC]


def expected(case,argv,passfds,native,pin,checkout,environment):
    if (not eligible(case) or type(argv) is not list
            or any(type(arg) is not str for arg in argv) or argv[:4]!=[native,'-S','-I','-c'] or type(passfds) is not list
            or any(type(fd) is not int or not 2<=fd<=1024 for fd in passfds)
            or len(set(passfds))!=len(passfds)):
        raise Refused('spawn finite entry operands')
    prefix='from multiprocessing.resource_tracker import main;main('
    if len(argv)==5 and argv[4].startswith(prefix) and argv[4].endswith(')'):
        value=argv[4][len(prefix):-1]
        if not value.isascii() or not value.isdigit() or str(int(value))!=value or not 3<=int(value)<=1024:
            raise Refused('tracker read descriptor')
        refuse_if(len(passfds)!=2 or int(value) not in passfds, 'tracker descriptor inventory')
        role='mp-tracker'
        descriptors=sorted(fd for fd in passfds if fd>2)
    else:
        prefix='from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd='
        if (len(argv)!=6 or not argv[4].startswith(prefix) or not argv[4].endswith(')')
                or argv[5]!='--multiprocessing-fork'):
            raise Refused('spawn exact command and target declaration')
        parts=argv[4][len(prefix):-1].split(', pipe_handle=')
        refuse_if(len(parts)!=2 or any(not value.isascii() or not value.isdigit() or str(int(value))!=value or not 3<=int(value)<=1024 for value in parts), 'spawn tracker and bootstrap descriptors')
        tracker,reader=map(int,parts)
        if (not 3<=len(passfds)<=7 or tracker==reader
                or not {tracker,reader}<=set(passfds) or 2 in passfds
                or (passfds[0]!=tracker or passfds[-2]!=reader)):
            raise Refused('spawn inherited pipe inventory')
        role='mp-child'
        descriptors=sorted(passfds)
    value=build_expected(case, native, pin, tuple(argv), tuple(sorted(environment.items())), str(checkout), 'python-command')
    return value,role,descriptors


def inherited_record(host,actor,fd):
    # Descriptor numbers can be reused after a prior case closes its pair.
    mode=(Path('/proc')/str(actor['birth'].pid)/'fd'/str(fd)).stat().st_mode
    if stat.S_ISSOCK(mode):
        from multiprocess_pipe import parent_record
        return parent_record(host,actor,fd)
    return spawn_record(actor['birth'].pid,fd)


def proposal(host,actor,raw):
    from source_observer import shape
    host.root_only(actor)
    shape(raw,('case','argv','passfds','executable','cwd','environment'))
    native=host.binding['entry']['path']
    if raw['case']!=host.case or raw['executable']!=native or raw['cwd']!=host.meta['checkout']:
        raise Refused('spawn root identity and directory')
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    value,role,descriptors=expected(host.case,raw['argv'],raw['passfds'],native,
        host.binding['entry']['sha256'],host.meta['checkout'],environment)
    check_expected(raw,value)
    records=[row for row in host.intents.values() if row['case']==host.case]
    tracker=next((row for row in records if row['role']=='mp-tracker'),None)
    if role=='mp-child':
        refuse_if(tracker is None, 'spawn needs owned tracker')
        if not host.executed(tracker):
            return None
    if role=='mp-tracker':
        reader=int(raw['argv'][4].removeprefix('from multiprocessing.resource_tracker import main;main(')[:-1])
        tracker_read=fd_record(actor['birth'].pid,reader)
        inherited=[tracker_read if fd==reader else stderr_record(actor['birth'].pid,fd) for fd in descriptors]
        refuse_if(tracker_read[3]!=os.O_RDONLY, 'tracker read direction')
    else:
        inherited=[]
        for fd in descriptors:
            inherited.append(inherited_record(host,actor,fd))
    if role=='mp-child':
        refuse_if(tracker is None, 'spawn missing owned tracker')
        tracker_fd=int(raw['argv'][4].split('tracker_fd=',1)[1].split(',',1)[0])
        tracked=next(row for row in inherited if row[0]==tracker_fd)
        retained=fd_record(tracker['pid'],tracker['tracker_read'][0])
        from linux_observation import process_identity
        from process_ledger import Birth
        owner=host.actors[tracker['pid']]
        process=host.ledger.process(owner['birth'])
        if (process.exit is not None or process.terminal is not None
                or Birth.read(process_identity(tracker['pid']))!=owner['birth']
                or retained!=tracker['tracker_read']
                or tracked[1:3]!=retained[1:3] or tracked[3]!=os.O_WRONLY):
            raise Refused('spawn tracker generation')
        if not owner['body_ready']:
            return None  # Existing bounded RPC waits for the native READY join.
        reader=int(raw['argv'][4].split('pipe_handle=',1)[1][:-1])
        bootstrap=next(row for row in inherited if row[0]==reader)
        sentinel=next(row for row in inherited if row[0]==raw['passfds'][-1])
        if (bootstrap[3]!=os.O_RDONLY or sentinel[3]!=os.O_WRONLY
                or len({tuple(row[1:3]) for row in (tracked,bootstrap,sentinel)})!=3):
            raise Refused('spawn distinct bootstrap reader and sentinel writer')
    vector=[native,'-I','-S',*raw['argv'][3:]]
    fields={'tracker_read':tracker_read} if role=='mp-tracker' else {}
    return admit_expected(host,actor,raw,value,role,vector,inherited=inherited,
        maximum=5 if role=='mp-child' else 1,fields=fields)


def inherited(profile,actual):
    records=profile['inherited']
    if (type(records) is not list or not ((1<=len(records)<=2) if profile['role']=='mp-tracker' else 3<=len(records)<=7)
            or any(type(row) is not list or len(row) not in (4,5,7) or any(type(value) is not int for value in row) for row in records)
            or profile['role']=='mp-tracker' and any(len(row)!=4 for row in records)):
        raise Refused('spawn profile descriptor schema')
    reader=int(profile['argv'][4].removeprefix('from multiprocessing.resource_tracker import main;main(')[:-1]) if profile['role']=='mp-tracker' else None
    seen=[]
    for name in os.listdir('/proc/self/fd'):
        fd=int(name)
        if fd<=2:
            continue
        try:
            saved=next((row for row in records if row[0]==fd and len(row)==7),None)
            if saved is not None:
                from multiprocess_pipe import local_record
                row=local_record(saved)
            else:
                row=stderr_record(actual['pid'],fd) if reader is not None and fd!=reader else spawn_record(actual['pid'],fd)
        except FileNotFoundError:
            continue
        flags=fcntl.fcntl(fd,fcntl.F_GETFL)
        if (reader is None or fd==reader) and flags&~(os.O_ACCMODE|os.O_CLOEXEC|((0o100000|os.O_NOFOLLOW) if len(row)==5 else 0)):
            raise Refused('spawn descriptor flags')
        seen.append(row)
    refuse_if(sorted(seen)!=sorted(records), 'spawn inherited descriptor generation')
