"""Finite spawn transport; target labels are metadata, never provenance."""
from pathlib import Path
import os
import stat
import fcntl
import ctypes

from content_manifest import Refused
from launch_policy import build_expected
from multiprocess_routes import ROUTES,Spawn,plan as route_plan

CASES=tuple('tests/test_multiprocess_resource_ownership.py::test_original_child_status_is_preserved['+str(status)+']' for status in (0,17))
TRACKER_SMOKE=tuple('tests/test_multiprocess_resource_ownership.py::'+name for name in (
    'test_parent_feeder_and_both_pipe_endpoints_are_settled',
    'test_original_failure_or_cancellation_survives_clean_teardown[error0]',
    'test_original_failure_or_cancellation_survives_clean_teardown[error1]',
))
TRACKER_REMAINING=tuple('tests/test_multiprocess_resource_ownership.py::'+name for name in (
    'test_preexisting_tracker_is_refused_and_left_owned_by_its_parent',
    'test_reused_descriptor_number_has_no_pipe_authority',
    'test_case_drift_refuses_without_releasing_owned_resources',
    'test_unrelated_finalizer_is_not_consumed',
    'test_altered_stdlib_stop_is_refused_before_launch',
))
ZERO=TRACKER_REMAINING[-1]
TRACKER_CASES=(*TRACKER_SMOKE,*TRACKER_REMAINING)
IPC_CASES=tuple('tests/test_multiprocess_resource_ownership.py::'+name for name in (
    'test_joined_spawn_queue_event_and_value_close_before_summary',
    'test_live_child_refusal_preserves_original_error_and_does_not_kill',
))
CHILD_CASES=(*CASES,*IPC_CASES,*ROUTES)
ALL_CASES=(*CHILD_CASES,*TRACKER_CASES)
TARGET=['tests.test_multiprocess_resource_ownership','_exit_with_status']
TARGETS={**dict.fromkeys(CASES,TARGET),IPC_CASES[0]:[TARGET[0],'_publish'],IPC_CASES[1]:[TARGET[0],'_wait']}


def plan(case,target):
    if case in TARGETS:
        if target!=TARGETS[case]:
            raise Refused('spawn original target metadata')
        return Spawn(('queue','arena') if case==IPC_CASES[0] else ())
    return route_plan(case,target)


def count(case):
    if case not in ALL_CASES:
        raise Refused('spawn unknown case count')
    return 0 if case==ZERO else 1 if case in TRACKER_CASES else 1+sum(spec.maximum for spec in ROUTES[case].values()) if case in ROUTES else 2


def fd_record(pid,fd):
    if type(fd) is not int or not 3<=fd<=1024:
        raise Refused('spawn descriptor number')
    path=Path('/proc')/str(pid)/'fd'/str(fd)
    info=path.stat()
    flags=[line.split()[1] for line in (path.parent.parent/'fdinfo'/str(fd)).read_text().splitlines() if line.startswith('flags:')]
    if (len(flags)!=1 or not stat.S_ISFIFO(info.st_mode) or info.st_uid!=20000):
        raise Refused('spawn owned FIFO')
    access=int(flags[0],8)&os.O_ACCMODE
    if access not in (os.O_RDONLY,os.O_WRONLY):
        raise Refused('spawn FIFO direction')
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


def spawn_record(pid,fd,case):
    try:
        return fd_record(pid,fd)
    except Refused:
        if case!=IPC_CASES[0] and not any('arena' in spec.resources for spec in ROUTES.get(case,{}).values()):
            raise
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
    if ctypes.CDLL(None,use_errno=True).syscall(312,pid,pid,0,fd,2)!=0:
        raise Refused('tracker stderr open file identity')
    flags=[line.split()[1] for line in (path.parent.parent/'fdinfo'/str(fd)).read_text().splitlines() if line.startswith('flags:')]
    if len(flags)!=1 or int(flags[0],8)&os.O_ACCMODE!=os.O_RDWR:
        raise Refused('tracker stderr access')
    return [fd,info.st_dev,info.st_ino,int(flags[0],8)&~os.O_CLOEXEC]


def counterpart(pid,record):
    records=[]
    for path in sorted((Path('/proc')/str(pid)/'fd').iterdir()):
        fd=int(path.name)
        if fd<=2 or fd==record[0]:
            continue
        try:
            other=fd_record(pid,fd)
        except (FileNotFoundError,Refused):
            continue
        if other[1:3]==record[1:3] and other[3]!=record[3]:
            records.append(other)
    if not records:
        raise Refused('spawn missing original-parent FIFO counterpart')
    return records


def expected(case,argv,passfds,target,native,pin,checkout,environment):
    if (type(case) is not str or case not in ALL_CASES or case==ZERO or type(argv) is not list
            or any(type(arg) is not str for arg in argv) or argv[:4]!=[native,'-S','-I','-c'] or type(passfds) is not list
            or any(type(fd) is not int or not 2<=fd<=1024 for fd in passfds)
            or len(set(passfds))!=len(passfds)):
        raise Refused('spawn finite entry operands')
    prefix='from multiprocessing.resource_tracker import main;main('
    if len(argv)==5 and argv[4].startswith(prefix) and argv[4].endswith(')'):
        value=argv[4][len(prefix):-1]
        if not value.isascii() or not value.isdigit() or str(int(value))!=value or not 3<=int(value)<=1024:
            raise Refused('tracker read descriptor')
        if len(passfds)!=2 or int(value) not in passfds or target is not None:
            raise Refused('tracker descriptor inventory')
        role='mp-tracker'
        descriptors=sorted(fd for fd in passfds if fd>2)
    else:
        prefix='from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd='
        if (case not in CHILD_CASES or len(argv)!=6 or not argv[4].startswith(prefix) or not argv[4].endswith(')')
                or argv[5]!='--multiprocessing-fork'):
            raise Refused('spawn exact command and target declaration')
        parts=argv[4][len(prefix):-1].split(', pipe_handle=')
        if (len(parts)!=2 or any(not value.isascii() or not value.isdigit() or str(int(value))!=value or not 3<=int(value)<=1024 for value in parts)):
            raise Refused('spawn tracker and bootstrap descriptors')
        tracker,reader=map(int,parts)
        spec=plan(case,target)
        if (len(passfds)!=3+sum(2 if kind=='queue' else 1 for kind in spec.resources) or tracker==reader
                or not {tracker,reader}<=set(passfds) or 2 in passfds
                or (passfds[0]!=tracker or passfds[-2]!=reader)):
            raise Refused('spawn inherited pipe inventory')
        role='mp-child'
        descriptors=sorted(passfds)
    value=build_expected(case, native, pin, tuple(argv), tuple(sorted(environment.items())), str(checkout), 'python-command')
    return value,role,descriptors


def child_custody(case,passfds,tracker_fd,reader,inherited,target=None):
    tracked=next(row for row in inherited if row[0]==tracker_fd)
    bootstrap=next(row for row in inherited if row[0]==reader)
    sentinel=next(row for row in inherited if row[0]==passfds[-1])
    used={tuple(row[1:3]) for row in (tracked,bootstrap,sentinel)}
    if (bootstrap[3]!=os.O_RDONLY or sentinel[3]!=os.O_WRONLY or len(used)!=3):
        raise Refused('spawn distinct bootstrap reader and sentinel writer')
    extras=[row for fd in passfds[1:-2] for row in inherited if row[0]==fd]
    cursor=0
    for kind in plan(case,TARGETS.get(case) if target is None else target).resources:
        width=2 if kind=='queue' else 1
        rows=extras[cursor:cursor+width]
        if kind=='queue':
            if (len(rows)!=2 or any(len(row)!=4 for row in rows) or rows[0][1:3]!=rows[1][1:3]
                    or [row[3] for row in rows]!=[os.O_RDONLY,os.O_WRONLY]):
                raise Refused('spawn exact Queue descriptor custody')
        elif len(rows)!=1 or len(rows[0])!=(7 if kind=='pipe' else 5):
            raise Refused('spawn exact application descriptor custody')
        member=tuple(rows[0][1:3])
        if member in used:
            raise Refused('spawn aliased application descriptor')
        used.add(member)
        cursor+=width
    if cursor!=len(extras) or len(inherited)!=3+cursor:
        raise Refused('spawn unexpected extra descriptors')


def quota(records,role,target,maximum):
    used=sum(row['role']==role and (role!='mp-child' or row['mp_target']==target) for row in records)
    if used>=maximum:
        raise Refused('spawn per-case quota')


def inherited_record(host,actor,fd,resources):
    # Descriptor numbers can be reused after a prior case closes its pair.
    mode=(Path('/proc')/str(actor['birth'].pid)/'fd'/str(fd)).stat().st_mode if 'pipe' in resources else 0
    if stat.S_ISSOCK(mode):
        from multiprocess_pipe import parent_record
        return parent_record(host,actor,fd)
    return spawn_record(actor['birth'].pid,fd,host.case)


def proposal(host,actor,raw):
    from source_observer import shape
    host.root_only(actor)
    shape(raw,('case','argv','passfds','target','executable','cwd','environment'))
    native=host.binding['entry']['path']
    if raw['case']!=host.case or raw['executable']!=native or raw['cwd']!=host.meta['checkout']:
        raise Refused('spawn root identity and directory')
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    value,role,descriptors=expected(host.case,raw['argv'],raw['passfds'],raw['target'],native,
        host.binding['entry']['sha256'],host.meta['checkout'],environment)
    if raw['environment']!=dict(value.environment):
        raise Refused('spawn original environment')
    records=[row for row in host.intents.values() if row['case']==host.case]
    spec=plan(host.case,raw['target']) if role=='mp-child' else None
    quota(records,role,raw['target'],spec.maximum if spec is not None else 1)
    tracker=next((row for row in records if row['role']=='mp-tracker'),None)
    if role=='mp-child':
        if tracker is None:
            raise Refused('spawn needs owned tracker')
        if not host.executed(tracker):
            return None
    if role=='mp-tracker':
        reader=int(raw['argv'][4].removeprefix('from multiprocessing.resource_tracker import main;main(')[:-1])
        tracker_read=fd_record(actor['birth'].pid,reader)
        inherited=[tracker_read if fd==reader else stderr_record(actor['birth'].pid,fd) for fd in descriptors]
        counterpart(actor['birth'].pid,tracker_read)
        if tracker_read[3]!=os.O_RDONLY:
            raise Refused('tracker read direction')
    else:
        if spec is None:
            raise Refused('spawn child declaration absent')
        inherited=[]
        for fd in descriptors:
            inherited.append(inherited_record(host,actor,fd,spec.resources))
    if role=='mp-child':
        if tracker is None:
            raise Refused('spawn missing owned tracker')
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
        for row in inherited:
            if row[0]!=tracker_fd and len(row)==4:
                counterpart(actor['birth'].pid,row)
        child_custody(host.case,raw['passfds'],tracker_fd,reader,inherited,raw['target'])
    vector=[native,'-I','-S',*raw['argv'][3:]]
    answer=host.admit_launch(actor,value,role,vector,None,inherited=inherited,maximum=count(host.case)-1 if role=='mp-child' else 1)
    if answer is None:
        return None
    if role=='mp-tracker':
        host.intents[answer['ticket']]['tracker_read']=tracker_read
    else:
        if spec is None:
            raise Refused('spawn child declaration absent')
        host.intents[answer['ticket']].update(mp_target=raw['target'])
    return {**answer,'translated':vector}


def inherited(profile,actual):
    records=profile['inherited']
    sizes={3+sum(2 if kind=='queue' else 1 for kind in spec.resources) for spec in ROUTES.get(profile['case'],{}).values()} if profile['case'] in ROUTES else {6 if profile['case']==IPC_CASES[0] else 3}
    if (type(records) is not list or len(records) not in ((1,2) if profile['role']=='mp-tracker' else sizes)
            or any(type(row) is not list or len(row) not in (4,5,7) or any(type(value) is not int for value in row) for row in records)):
        raise Refused('spawn profile descriptor schema')
    if any(len(row)==7 for row in records) and (profile['role']!='mp-child'
            or not any('pipe' in spec.resources for spec in ROUTES.get(profile['case'],{}).values())):
        raise Refused('spawn inherited Pipe outside finite case')
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
                row=stderr_record(actual['pid'],fd) if reader is not None and fd!=reader else spawn_record(actual['pid'],fd,profile['case'])
        except FileNotFoundError:
            continue
        flags=fcntl.fcntl(fd,fcntl.F_GETFL)
        if (reader is None or fd==reader) and flags&~(os.O_ACCMODE|os.O_CLOEXEC|((0o100000|os.O_NOFOLLOW) if len(row)==5 else 0)):
            raise Refused('spawn descriptor flags')
        seen.append(row)
    if sorted(seen)!=sorted(records):
        raise Refused('spawn inherited descriptor generation')
