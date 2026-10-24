"""One-shot resolver cost diagnostics; never an authority or acceptance input."""
from contextlib import contextmanager
import cProfile
import hashlib
import json
import sys
import time
import types


@contextmanager
def observe(owner, path, vector):
    from linux_producers import NativeProducers
    producer = getattr(owner, 'producers', None)
    if (type(producer) is not NativeProducers or getattr(owner, '_resolver_cost_attempted', False)
            or sys.getprofile() is not None
            or path != '/usr/bin/git' or type(vector) is not list or len(vector) != 5
            or any(type(value) is not str for value in vector) or vector[0] != path
            or len(vector[4]) != 40 or any(value not in '0123456789abcdef' for value in vector[4])
            or vector[1:3] != ['--no-replace-objects', 'cat-file']
            or vector[3] not in {'-t', 'commit', 'tree', 'blob'}):
        yield
        return
    owner._resolver_cost_attempted = True
    profiler = None
    try:
        started = time.monotonic_ns()
        profiler = cProfile.Profile(timer=time.process_time)
        profiler.enable()
    except BaseException:
        if profiler is not None:
            try:
                profiler.disable()
            except BaseException:
                pass
        profiler = None
    try:
        yield
    finally:
        if profiler is not None:
            try:
                profiler.disable()
                elapsed = time.monotonic_ns() - started
                rows = []
                for entry in sorted(profiler.getstats(), key=lambda entry: entry.totaltime, reverse=True)[:64]:
                    code = entry.code
                    location = ([code.co_filename, code.co_firstlineno, code.co_name]
                                if type(code) is types.CodeType else [str(code)])
                    rows.append({'location_sha256': hashlib.sha256(json.dumps(location).encode()).hexdigest(),
                                 'calls': entry.callcount, 'recursive_calls': entry.reccallcount,
                                 'self_ns': round(entry.inlinetime * 1e9),
                                 'total_ns': round(entry.totaltime * 1e9)})
                producer.records.append({'kind': 'resolver_cost_profile', 'diagnostic_only': True,
                                         'eligible_certificate': False, 'elapsed_ns': elapsed, 'rows': rows})
            except BaseException:
                pass  # Diagnostic failure cannot replace the initiating result.
