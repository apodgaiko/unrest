"""Native pre-body consumption for one primary-script-derived Python operation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def descriptor_inventory():
    actual_descriptors = []
    import fcntl
    # scandir keeps its own directory descriptor alive during the full census.
    # Account for exactly that proc-directory object, then prove its closure.
    directory_info = os.stat('/proc/self/fd')
    enumeration = []
    with os.scandir('/proc/self/fd') as directory:
        for entry in directory:
            descriptor = int(entry.name)
            if descriptor < 3:
                continue
            if len(actual_descriptors) + len(enumeration) >= 4096:
                os._exit(86)
            try:
                info = os.fstat(descriptor)
                access = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
                flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
            except OSError:
                os._exit(86)
            if (info.st_dev == directory_info.st_dev and info.st_ino == directory_info.st_ino
                    and info.st_mode == directory_info.st_mode and info.st_uid == os.getuid()
                    and access == os.O_RDONLY and flags == fcntl.FD_CLOEXEC):
                enumeration.append(descriptor)
            else:
                actual_descriptors.append({'fd': descriptor, 'device': info.st_dev, 'inode': info.st_ino,
                                           'mode': info.st_mode, 'uid': info.st_uid, 'access': access})
    if len(enumeration) != 1:
        os._exit(86)
    try:
        os.fstat(enumeration[0])
    except OSError as error:
        import errno
        if error.errno != errno.EBADF:
            os._exit(86)
    else:
        os._exit(86)
    actual_descriptors.sort(key=lambda row: row['fd'])
    return actual_descriptors


def main(event, arguments):
    path = Path('/receipts/primary-startup') / (str(os.getpid()) + '.json')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (info.st_uid != 20001 or stat.S_IMODE(info.st_mode) != 0o444
                or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536):
            os._exit(86)
        body = os.read(descriptor, 65537)
    finally:
        os.close(descriptor)
    profile = json.loads(body)
    raw = Path('/proc/self/stat').read_text()
    checks = {
        'pid': profile['pid'] == os.getpid(), 'parent': profile['parent'] == os.getppid(),
        'birth': profile['start_ticks'] == int(raw[raw.rfind(')') + 2:].split()[19]),
        'boot': profile['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'environment': profile.get('python_environment', profile['environment']) == dict(os.environ),
        'cwd': profile['cwd'] == os.getcwd(), 'argv': profile['orig_argv'] == sys.orig_argv,
        'event': profile['event'] == event,
        'flags': profile['flags'] == [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode],
        'body': len(arguments) == 1 and hashlib.sha256(str(arguments[0]).encode()).hexdigest() == profile['body_sha256'],
    }
    if not all(checks.values()):
        Path('/work/primary-native-state-' + str(os.getpid()) + '.json').write_text(json.dumps({
            'schema': 'primary-native-binding-refusal-v1', 'pid': os.getpid(), 'checks': checks,
            'exact_locale_coercion': (dict(os.environ) == {**profile['environment'], 'LC_CTYPE': 'C.UTF-8'}
                                      and 'LC_CTYPE' not in profile['environment']),
        }, sort_keys=True))
    if (profile['pid'] != os.getpid() or profile['parent'] != os.getppid()
            or profile['start_ticks'] != int(raw[raw.rfind(')') + 2:].split()[19])
            or profile['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            or profile.get('python_environment', profile['environment']) != dict(os.environ) or profile['cwd'] != os.getcwd()
            or profile['orig_argv'] != sys.orig_argv or profile['event'] != event
            or profile['flags'] != [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode]
            or len(arguments) != 1
            or hashlib.sha256(str(arguments[0]).encode()).hexdigest() != profile['body_sha256']):
        os._exit(86)
    diagnostic = Path('/work') / ('primary-native-state-' + str(os.getpid()) + '.json')
    context = {'schema': 'primary-native-state-v2', 'pid': os.getpid(),
               'source_path_present': '/source/src' in sys.path,
               'venv_site_present': '/source/.venv/lib/python3.13/site-packages' in sys.path,
               'prefix_is_venv': sys.prefix == '/source/.venv',
               'body_failure': None, 'git_status': None, 'git_error_code': None}
    diagnostic.write_text(json.dumps(context, sort_keys=True))
    original_exception = sys.excepthook
    def exception(kind, error, trace):
        known = {'ModuleNotFoundError', 'ImportError', 'PermissionError', 'FileNotFoundError',
                 'RuntimeError', 'AssertionError', 'ValueError', 'TypeError', 'AttributeError'}
        frames = []
        while trace is not None:
            frames.append({'file_sha256': hashlib.sha256(trace.tb_frame.f_code.co_filename.encode()).hexdigest(),
                           'line': trace.tb_lineno})
            trace = trace.tb_next
        name = getattr(error, 'name', None)
        message = str(error)
        codes = {'native_noexec': 'failed to map segment', 'native_symbol': 'undefined symbol',
                 'native_library': 'cannot open shared object', 'import_name': 'cannot import name',
                 'permission': 'Permission denied', 'glibc': 'GLIBC_'}
        detail = next((key for key, marker in codes.items() if marker in message), 'other')
        noexec = False
        location = getattr(error, 'path', None)
        if isinstance(location, str):
            try:
                noexec = bool(os.statvfs(location).f_flag & os.ST_NOEXEC)
            except OSError:
                pass
        context['body_failure'] = {'error_code': kind.__name__ if kind.__name__ in known else 'other',
                                   'missing_module': name if name in {'unrest_harness', 'pydantic', 'click', 'fastmcp', 'yaml'} else 'other',
                                   'frames': frames[-8:], 'detail_code': detail, 'error_path_noexec': noexec}
        diagnostic.write_text(json.dumps(context, sort_keys=True))
        original_exception(kind, error, error.__traceback__)
    sys.excepthook = exception
    # Source cannot inherit a credential, controller socket or unrelated file.
    expected_descriptors = profile.get('source_descriptors', [])
    actual_descriptors = descriptor_inventory()
    if actual_descriptors != expected_descriptors:
        os._exit(86)
    if profile.get('source_role') == 'source-producer-child':
        image = profile['producer_image']
        consumer = profile['producer_consumer']
        header = Path('/receipts/native-startup') / (str(os.getpid()) + '.json')
        source = Path('/guard/native_entry.py')
        data = source.read_bytes()
        if (image['path'] != '/usr/local/bin/python-primary-audit'
                or Path(sys.executable).resolve() != Path(image['path'])
                or hashlib.sha256(Path('/proc/self/exe').read_bytes()).hexdigest() != image['sha256']
                or consumer['path'] != str(source)
                or hashlib.sha256(data).hexdigest() != consumer['sha256']
                or header.is_symlink()
                or hashlib.sha256(header.read_bytes()).hexdigest() != profile['native_profile_sha256']):
            os._exit(86)
        import types
        module = types.ModuleType('native_entry')
        module.__file__ = str(source)
        module.ENTRY_EVENT, module.ENTRY_ARGUMENTS = event, arguments
        sys.modules[module.__name__] = module
        exec(compile(data, str(source), 'exec', dont_inherit=True), module.__dict__)
        return
    if profile.get('source_role') in {'source-root', 'source-bootstrap'}:
        source = Path('/guard/primary_source_entry.py')
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != profile['source_entry_sha256']:
            os._exit(86)
        import types
        module = types.ModuleType('primary_source_entry')
        module.__file__ = str(source)
        sys.modules[module.__name__] = module
        exec(compile(data, str(source), 'exec', dont_inherit=True), module.__dict__)
        module.activate(profile, event, arguments)
        return
    denied = {'subprocess.Popen', 'os.exec', 'os.posix_spawn', 'os.system', 'os.fork',
              'os.forkpty', 'socket.connect', 'socket.bind', 'ctypes.dlopen'}
    console_code = None
    console_started = [False]
    if event == 'cpython.run_file':
        source = Path(arguments[0]).read_bytes()
        if hashlib.sha256(source).hexdigest() != profile['console_source_sha256']:
            os._exit(86)
        console_code = compile(source, str(arguments[0]), 'exec', dont_inherit=True)
    used_git = [False]
    def audit(name, args):
        if name == 'exec' and console_code is not None and args[0].co_filename == console_code.co_filename:
            if console_started[0] or args[0] != console_code:
                os._exit(86)
            console_started[0] = True
        if name == 'import' and len(args) > 1 and isinstance(args[1], str) and args[1].endswith('.so'):
            library = Path(args[1])
            site = Path('/source/.venv/lib/python3.13/site-packages')
            standard = Path('/usr/local/lib/python3.13/lib-dynload')
            if library.resolve().is_relative_to(standard):
                pass
            elif library.resolve().is_relative_to(site):
                mirror = Path('/opt/primary-deps/lib/python3.13/site-packages') / library.relative_to(site)
                if (not mirror.is_file() or hashlib.sha256(library.read_bytes()).digest()
                        != hashlib.sha256(mirror.read_bytes()).digest()):
                    os._exit(86)
            else:
                os._exit(86)
        if name == 'subprocess.Popen' and profile['repository'] and not used_git[0]:
            executable, argv, cwd, environment = args
            frame = sys._getframe(1)
            while frame is not None and frame.f_code.co_name != 'find_repository_root':
                frame = frame.f_back
            source = Path('/source/src/unrest_harness/repository_contract.py')
            if (frame is not None and frame.f_code.co_filename == str(source)
                    and hashlib.sha256(source.read_bytes()).hexdigest() == profile['repository_source_sha256']
                    and executable == 'git' and argv == ['git', '-C', '/source', 'rev-parse', '--show-toplevel']
                    and cwd is None and environment is None):
                module = sys.modules.get('unrest_harness.repository_contract')
                if (module is not None and frame.f_globals is vars(module)
                        and frame.f_code is module.find_repository_root.__code__):
                    used_git[0] = True
                    return
        if name in denied:
            os._exit(86)
    previous_profile = sys.getprofile()
    def observe(frame, kind, value):
        if previous_profile is not None:
            previous_profile(frame, kind, value)
        if (profile['repository'] and kind == 'return'
                and frame.f_code.co_name == 'find_repository_root'
                and frame.f_code.co_filename == '/source/src/unrest_harness/repository_contract.py'):
            process = frame.f_locals.get('process')
            if process is not None and type(process.returncode) is int:
                context['git_status'] = process.returncode
                context['git_error_code'] = ('git_ownership' if 'dubious ownership' in process.stderr
                                             else 'other' if process.returncode else None)
                diagnostic.write_text(json.dumps(context, sort_keys=True))
    if profile['repository']:
        sys.setprofile(observe)
    sys.addaudithook(audit)
    sys._unrest_finite_source_audit = True


main(globals()['ENTRY_EVENT'], globals()['ENTRY_ARGUMENTS'])
