"""Finite kernel observation of the stdlib Queue tracker, without source cases.

This is diagnostic evidence, never a release registration or missing-wait waiver.
"""
from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import stat
import sys
import time

SUPPORT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def no_network(trace):
    # Linux x86-64 seccomp: reject socket creation and every network payload.
    rows = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E),
            (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    for number in (41, 42, 43, 44, 45, 46, 47, 49, 50, 51, 52, 53, 54, 55, 288, 299, 307):
        rows.extend([(0x15, 0, 1, number), (0x06, 0, 0, 0x00050001)])
    rows.append((0x06, 0, 0, 0x7FFF0000))
    instructions = (trace.FilterInstruction * len(rows))(*(trace.FilterInstruction(*row) for row in rows))
    program = trace.FilterProgram(len(rows), instructions)
    if trace.LIBC.prctl(38, 1, 0, 0, 0) or trace.LIBC.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), 'controlled no-network filter refused')


def controlled_process(output):
    output.put(('controlled', os.getpid()))


def child(root):
    import multiprocessing
    from multiprocessing import resource_tracker, util, spawn, popen_spawn_posix
    path = root / 'launch.json'
    original = util.spawnv_passfds
    source = Path(inspect.getsourcefile(original))
    expected = compile(source.read_bytes(), str(source), 'exec', dont_inherit=True)
    code = next(c for c in expected.co_consts if inspect.iscode(c) and c.co_name == 'spawnv_passfds')
    assert code == original.__code__

    def observe(frame, event, value):
        if event != 'call' or frame.f_code is not original.__code__:
            return
        assert frame.f_globals is vars(util) and original.__globals__ is vars(util)
        local = frame.f_locals
        vector = [os.fsdecode(v) for v in local['args']]
        fds = sorted(local['passfds'])
        assert vector[:3] == [sys.executable, '-B', '-c'] and len(vector) in (4, 5)
        prefix = 'from multiprocessing.resource_tracker import main;main('
        if len(vector) == 4:
            assert vector[3].startswith(prefix) and vector[3].endswith(')')
            fd = int(vector[3][len(prefix):-1])
            assert fds == [2, fd]
            kind = 'tracker'
            declaration_path = path
        else:
            caller = frame.f_back
            assert caller.f_code is popen_spawn_posix.Popen._launch.__code__
            assert caller.f_globals is vars(popen_spawn_posix)
            process = caller.f_locals['process_obj']
            assert process._target is controlled_process
            assert controlled_process.__globals__ is globals()
            fd = caller.f_locals['child_r']
            tracker_fd = resource_tracker._resource_tracker._fd
            expected = spawn.get_command_line(tracker_fd=tracker_fd, pipe_handle=fd)
            assert vector == [os.fsdecode(v) for v in expected]
            assert fds == sorted(caller.f_locals['self']._fds)
            output, = process._args
            assert fds == sorted([tracker_fd, fd, caller.f_locals['child_w'],
                                  output._reader.fileno(), output._writer.fileno()])
            kind = 'spawned-process'
            declaration_path = root / 'spawn.json'
        info = os.fstat(fd)
        assert stat.S_ISFIFO(info.st_mode)
        frames = []
        current = frame
        while current:
            if current.f_code.co_filename.endswith(('multiprocessing/resource_tracker.py',
                                                    'multiprocessing/synchronize.py',
                                                    'multiprocessing/queues.py',
                                                    'multiprocessing/context.py')):
                p = Path(current.f_code.co_filename)
                frames.append({'path': str(p), 'sha256': sha(p), 'function': current.f_code.co_name,
                               'line': current.f_lineno})
            current = current.f_back
        assert kind == 'spawned-process' or any(v['function'] == '_launch' for v in frames)
        declaration_path.write_text(json.dumps({'kind':kind,'root':os.getpid(),'argv':vector,'cwd':os.getcwd(),
            'environment':dict(os.environ),'runtime_sha256':sha(sys.executable),
            'source_sha256':sha(source),'source_code_identity':True,'source_globals_identity':True,
            'fifo':{'fd':fd,'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode},
            'frames':frames},sort_keys=True))
    sys.setprofile(observe)
    queue = multiprocessing.get_context('spawn').Queue()
    process = multiprocessing.get_context('spawn').Process(target=controlled_process, args=(queue,))
    process.start()
    observed = queue.get(timeout=5)
    process.join(10)
    assert process.exitcode == 0 and observed == ('controlled', process.pid)
    sys.setprofile(None)
    owner = resource_tracker._resource_tracker
    assert path.is_file() and owner._pid is not None
    # This is the same point as pytest's pre-interpreter-finalization summary.
    (root / 'pre-finalization.json').write_text(json.dumps({'pid':os.getpid(),
        'tracker_pid':owner._pid,'tracker_fd':owner._fd,'joined_process_pid':process.pid,'monotonic_ns':time.monotonic_ns(),
        'tracker_still_running':True,'explicit_tracker_stop_called':False,
        'stdlib_has_destructor':hasattr(type(owner),'__del__'),
        'tracker_source_sha256':sha(resource_tracker.__file__)},sort_keys=True))
    queue.close()
    # Normal interpreter shutdown owns any actual tracker destructor/wait.


def run(root):
    assert sys.platform == 'linux' and os.uname().machine == 'x86_64'
    root.mkdir(mode=0o700)
    trace = load('linux_trace', SUPPORT / 'linux_trace.py')
    vector = [sys.executable,'-B',str(Path(__file__).resolve()),'--child',str(root)]
    environment = {'PYTHONDONTWRITEBYTECODE':'1'}
    allowed = [{'path':sys.executable,'argv':vector,'sha256':sha(sys.executable),
                'environment':environment,'cwd':str(root)}]
    pid = os.fork()
    if pid == 0:
        try:
            os.chdir(root)
            no_network(trace)
            trace.install_observation_filter()
            trace.trace_me()
            os.execve(sys.executable,vector,environment)
        finally:
            os._exit(127)
    accepted = []
    def resolve(child_pid, path, argv, env, cwd):
        if len(accepted) >= 2:
            return False
        declaration_file = root / ('launch.json' if not accepted else 'spawn.json')
        if not declaration_file.is_file():
            return False
        declaration = json.loads(declaration_file.read_bytes())
        if (path != sys.executable or argv != declaration['argv'] or env != declaration['environment']
                or cwd != declaration['cwd'] or sha(path) != declaration['runtime_sha256']):
            return False
        identity = trace._observation.process_identity(child_pid)
        if identity['ppid'] != pid or declaration['root'] != pid:
            return False
        fd = declaration['fifo']['fd']
        info = Path(f'/proc/{child_pid}/fd/{fd}').stat()
        if (info.st_dev,info.st_ino,info.st_mode) != tuple(declaration['fifo'][k] for k in ('device','inode','mode')):
            return False
        # The child read end and parent's live write end must be one kernel pipe.
        parent_pipes = [p.stat() for p in Path(f'/proc/{pid}/fd').iterdir() if p.exists()]
        if not any((v.st_dev,v.st_ino)==(info.st_dev,info.st_ino) for v in parent_pipes):
            return False
        accepted.append({'pid':child_pid,'parent':pid,'identity':identity,'declaration':declaration})
        return True
    proof = trace.OwnedTrace(pid,allowed,timeout=60,selective=True,resolve_exec=resolve).run()
    (root/'kernel.json').write_text(json.dumps(proof,sort_keys=True))
    (root/'accepted.json').write_text(json.dumps(accepted,sort_keys=True))
    assert proof['root_parent_wait_raw'] == 0 and not proof['poison'] and len(accepted)==2
    summary = json.loads((root/'pre-finalization.json').read_bytes())
    waits = [v for v in proof['records'] if v['kind']=='original_parent_wait4'
             and v['parent']==pid and v['child']==accepted[0]['pid']]
    joined = [v for v in proof['records'] if v['kind']=='original_parent_wait4'
              and v['parent']==pid and v['child']==summary['joined_process_pid']]
    assert len(joined)==1 and joined[0]['normalized']==0
    assert not waits
    result = {'actual_joined_process_original_parent_waits':joined,
              'actual_tracker_original_parent_waits':waits,'pre_finalization':summary,
              'original_source_case_executed':False,'source_route_admission':False}
    (root/'projection.json').write_text(json.dumps(result,sort_keys=True))
    print(json.dumps(result,sort_keys=True))


if __name__ == '__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--child':
        child(Path(sys.argv[2]))
    elif len(sys.argv)==2:
        run(Path(sys.argv[1]))
    else:
        raise SystemExit(2)
