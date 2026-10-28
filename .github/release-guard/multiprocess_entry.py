"""Two finite spawn cases; Python target labels are metadata, never provenance."""
from pathlib import Path
import os
import stat
import fcntl

from content_manifest import Refused
from control_transport import finite
from launch_policy import Rule,render

CASES=tuple('tests/test_multiprocess_resource_ownership.py::test_original_child_status_is_preserved['+str(status)+']' for status in (0,17))
TARGET=['tests.test_multiprocess_resource_ownership','_exit_with_status']


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
    finite({'case':case,'argv':argv,'passfds':passfds,'target':target})
    if (type(case) is not str or case not in CASES or type(argv) is not list
            or any(type(arg) is not str for arg in argv) or argv[:4]!=[native,'-S','-I','-c'] or type(passfds) is not list
            or any(type(fd) is not int or not 2<=fd<=1024 for fd in passfds)
            or len(set(passfds))!=len(passfds)):
        raise Refused('spawn finite entry operands')
    prefix='from multiprocessing.resource_tracker import main;main('
    if len(argv)==5 and argv[4].startswith(prefix) and argv[4].endswith(')'):
        value=argv[4][len(prefix):-1]
        if not value.isascii() or not value.isdigit() or str(int(value))!=value or not 3<=int(value)<=1024:
            raise Refused('tracker read descriptor')
        if sorted(passfds)!=[2,int(value)] or target is not None:
            raise Refused('tracker descriptor inventory')
        role='mp-tracker'
        descriptors=[int(value)]
    else:
        prefix='from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd='
        if (len(argv)!=6 or not argv[4].startswith(prefix) or not argv[4].endswith(')')
                or argv[5]!='--multiprocessing-fork' or target!=TARGET):
            raise Refused('spawn exact command and target declaration')
        parts=argv[4][len(prefix):-1].split(', pipe_handle=')
        if (len(parts)!=2 or any(not value.isascii() or not value.isdigit() or str(int(value))!=value or not 3<=int(value)<=1024 for value in parts)):
            raise Refused('spawn tracker and bootstrap descriptors')
        tracker,reader=map(int,parts)
        if len(passfds)!=3 or tracker==reader or not {tracker,reader}<=set(passfds) or 2 in passfds:
            raise Refused('spawn inherited pipe inventory')
        role='mp-child'
        descriptors=sorted(passfds)
    value=render(Rule(role,role,(case,),native,pin,tuple(argv),tuple(sorted(environment.items())),str(checkout),'python-command'),case,role,{}, {})
    return value,role,descriptors


def proposal(host,actor,raw):
    from source_observer import shape
    host.root_only(actor)
    finite(raw)
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
    if any(row['role']==role for row in records):
        raise Refused('spawn per-case quota')
    tracker=next((row for row in records if row['role']=='mp-tracker'),None)
    if role=='mp-child' and (tracker is None or not tracker['consumed'] or not host.actors[tracker['pid']]['returned']):
        raise Refused('spawn needs returned owned tracker')
    inherited=[fd_record(actor['birth'].pid,fd) for fd in descriptors]
    if role=='mp-tracker':
        counterpart(actor['birth'].pid,inherited[0])
    if role=='mp-tracker' and inherited[0][3]!=os.O_RDONLY:
        raise Refused('tracker read direction')
    if role=='mp-child':
        if tracker is None:
            raise Refused('spawn missing owned tracker')
        tracker_fd=int(raw['argv'][4].split('tracker_fd=',1)[1].split(',',1)[0])
        tracked=next(row for row in inherited if row[0]==tracker_fd)
        retained=fd_record(tracker['pid'],tracker['inherited'][0][0])
        from linux_observation import process_identity
        from process_ledger import Birth
        owner=host.actors[tracker['pid']]
        process=host.ledger.process(owner['birth'])
        if (process.exit is not None or process.terminal is not None
                or Birth.read(process_identity(tracker['pid']))!=owner['birth']
                or retained!=tracker['inherited'][0]
                or tracked[1:3]!=retained[1:3] or tracked[3]!=os.O_WRONLY):
            raise Refused('spawn tracker generation')
        if not owner['body_ready']:
            return None  # Existing bounded RPC waits for the native READY join.
        reader=int(raw['argv'][4].split('pipe_handle=',1)[1][:-1])
        for row in inherited:
            if row[0]!=tracker_fd:
                counterpart(actor['birth'].pid,row)
        bootstrap=next(row for row in inherited if row[0]==reader)
        sentinel=next(row for row in inherited if row[0] not in (tracker_fd,reader))
        if (bootstrap[3]!=os.O_RDONLY or sentinel[3]!=os.O_WRONLY
                or len({tuple(row[1:3]) for row in inherited})!=3):
            raise Refused('spawn distinct bootstrap reader and sentinel writer')
    vector=[native,'-I','-S',*raw['argv'][3:]]
    payload={'case':host.case,'original':value.wire(),'translated':vector,'source_line':0,'script_sha256':None}
    answer=host.admit_launch(actor,payload,value,role,0,vector,None,inherited=inherited)
    if answer is None:
        return None
    return {**answer,'translated':vector}


def inherited(profile,actual):
    records=profile['inherited']
    if (type(records) is not list or len(records)!=(1 if profile['role']=='mp-tracker' else 3)
            or any(type(row) is not list or len(row)!=4 or any(type(value) is not int for value in row) for row in records)):
        raise Refused('spawn profile descriptor schema')
    seen=[]
    for name in os.listdir('/proc/self/fd'):
        fd=int(name)
        if fd<=2:
            continue
        try:
            row=fd_record(actual['pid'],fd)
        except FileNotFoundError:
            continue
        flags=fcntl.fcntl(fd,fcntl.F_GETFL)
        if flags&~(os.O_ACCMODE|os.O_CLOEXEC):
            raise Refused('spawn descriptor flags')
        seen.append(row)
    if sorted(seen)!=sorted(records):
        raise Refused('spawn inherited descriptor generation')
