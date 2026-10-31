"""Synthetic native diagnostic consumer; disconnected from production source admission."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

if __name__ == '_release_native_entry':
    sys.path.insert(0, str(Path(__file__).parents[1] / 'support'))
from native_entry import acquire

BODY_READY = False
PRIVATE_COMPARTMENT = False
BODIES = {
    'product-order-positive': 'import os\ntry: os.system("/usr/bin/true")\nexcept RuntimeError as error:\n assert str(error)=="PRODUCT_DENIED"\n print("NATIVE_BODY_OK",flush=True)\nelse: raise AssertionError("product denial absent")',
    'product-order-fallback': 'import os\ntry: os.system("/usr/bin/true")\nexcept ValueError: print("REFUSAL_CAUGHT",flush=True)\nelse: raise AssertionError("native fallback absent")',
    'product-order-resolver-positive': 'import socket\ntry: socket.getaddrinfo("alias-guard.invalid",443)\nexcept RuntimeError as error:\n assert str(error)=="PRODUCT_DENIED"\n print("NATIVE_BODY_OK",flush=True)\nelse: raise AssertionError("product denial absent")',
    'product-order-resolver-fallback': 'import socket\ntry: socket.getaddrinfo("alias-guard.invalid",443)\nexcept ValueError: print("REFUSAL_CAUGHT",flush=True)\nelse: raise AssertionError("native fallback absent")',
    'fastpath-positive': 'import fractions,sys\nsys.settrace(lambda *args: None)\nsys.settrace(None)\nsys.setprofile(lambda *args: None)\nsys.setprofile(None)\nexec(compile("print(\\"NATIVE_BODY_OK\\",flush=True)","<ordinary>","exec"))',
    'compile-bytes': 'import sys\ntry: compile(\'changed\\n\',sys._compile_probe_file,"exec")\nexcept ValueError as error:\n assert str(error)=="source declared script bytes changed"\n print("REFUSAL_CAUGHT",flush=True)',
    'compile-current': 'import sys\ntry: compile(\'pass\\n\',sys._compile_probe_file,"exec")\nexcept ValueError as error:\n assert str(error)=="source declared script bytes changed"\n print("REFUSAL_CAUGHT",flush=True)',
    'positive': 'print("NATIVE_BODY_OK", flush=True)',
    'caught-process': 'import subprocess\ntry: subprocess.run(["/usr/bin/true"])\nexcept RuntimeError: print("REFUSAL_CAUGHT", flush=True)',
    'caught-network': 'import socket\ns=socket.socket()\ntry: s.bind(("127.0.0.1",0))\nexcept RuntimeError: print("REFUSAL_CAUGHT", flush=True)\nfinally: s.close()',
}
BODIES['thread-group-kill'] = """import os,signal,threading,time
ready=[threading.Event(),threading.Event()]
def run(event):
 event.set()
 time.sleep(30)
for event in ready: threading.Thread(target=run,args=(event,),daemon=True).start()
assert all(event.wait(2) for event in ready)
print('NATIVE_BODY_OK',flush=True)
os.kill(os.getpid(),signal.SIGKILL)
"""
SUPPORT_CASES=('support-import-source','support-import-cached')
for name in SUPPORT_CASES:
    BODIES[name]="""import sys,time,json
from pathlib import Path
support=str(Path(sys.executable).parents[2]/'support')+'/'
compiled=[]
def observe(event,args):
 if event=='compile' and len(args)==2 and type(args[1]) is str and args[1].startswith(support):compiled.append(args[1])
sys.addaudithook(observe)
started=time.perf_counter()
import source_entry
elapsed=time.perf_counter()-started
print('SUPPORT_IMPORT='+json.dumps({'seconds':elapsed,'source_compilations':len(compiled)}),flush=True)
print('NATIVE_BODY_OK',flush=True)
"""


BODIES['private-network-positive'] = """
import os,socket,sys
from pathlib import Path
for host,port in (('127.0.0.1',12345),(b'127.0.0.1','12345')):
    rows=socket.getaddrinfo(host,port,socket.AF_INET,socket.SOCK_STREAM,0,socket.AI_PASSIVE|socket.AI_ADDRCONFIG)
    assert rows and all(row[0]==socket.AF_INET and row[4]==('127.0.0.1',12345) for row in rows)
assert {name for _,name in socket.if_nameindex()}=={'lo'}
with socket.socket() as listener:
    listener.bind(('127.0.0.1',0));listener.listen()
    with socket.socket() as client:
        client.connect(listener.getsockname())
        with listener.accept()[0] as peer:
            client.sendall(b'tcp');assert peer.recv(3)==b'tcp'
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver:
    receiver.bind(('127.0.0.1',0));receiver.settimeout(1)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
        sender.sendto(b'udp',receiver.getsockname());assert receiver.recvfrom(3)[0]==b'udp'
left,right=socket.socketpair()
with left,right:
    left.sendall(b'pair');assert right.recv(4)==b'pair'
left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
with left,right:
    left.sendall(b'packet');assert right.recv(6)==b'packet'
control=os.fsencode(Path(sys.executable).parents[2]/'profiles/control.sock')
sys.audit('socket.connect',object(),control)
print('NATIVE_BODY_OK',flush=True)
"""
for name,address in (('path',repr('/tmp/forbidden-native-socket')),('abstract',repr(b'\0forbidden-native-socket'))):
    BODIES['private-unix-'+name] = (
        "import socket\ntry:\n with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream: "
        f"stream.connect({address})\nexcept RuntimeError: print('REFUSAL_CAUGHT',flush=True)")
BODIES['private-unix-prefix'] = (
    "import os,sys\nfrom pathlib import Path\n"
    "control=os.fsencode(Path(sys.executable).parents[2]/'profiles/control.sock')\n"
    "try: sys.audit('socket.connect',object(),control+b'\\0suffix')\n"
    "except RuntimeError: print('REFUSAL_CAUGHT',flush=True)")
BODIES['private-process'] = (
    "import os\ntry: os.system('/usr/bin/true')\n"
    "except RuntimeError: print('REFUSAL_CAUGHT',flush=True)")


def consume(directory, event, arguments):
    global BODY_READY, POLICY, SCRIPT_TARGET, PRIVATE_COMPARTMENT
    root, profile = acquire(directory)
    fields = {'schema', 'case', 'identity', 'observer', 'argv', 'environment', 'cwd', 'flags',
              'native', 'native_sha256', 'entry_sha256', 'nonce', 'token', 'seal', 'generation', 'mount_namespace', 'network_before'}
    if type(profile) is not dict or set(profile) != fields or profile['schema'] != 'unrest.native-control.v1':
        raise ValueError('native profile schema')
    sys.path.insert(0, str(Path(__file__).parent))
    from bootstrap_wire import Client
    from linux_observation import process_identity
    from process_ledger import Birth, canonical

    actual = process_identity(os.getpid())
    claimed = canonical(profile['identity'])
    if claimed != profile['identity']:
        raise ValueError('native profile identity schema')
    if (type(profile['argv']) is not list or any(type(value) is not str for value in profile['argv'])
            or type(profile['environment']) is not dict
            or any(type(key) is not str or type(value) is not str for key, value in profile['environment'].items())
            or type(profile['flags']) is not list or any(type(value) is not int for value in profile['flags'])):
        raise ValueError('native profile primitive records')
    for name in os.listdir('/proc/self/fd'):
        descriptor = int(name)
        if descriptor > 2:
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            raise ValueError('native ambient descriptor inherited')
    case = profile['case']
    if (type(case) is not str or case not in BODIES or event != 'cpython.run_command'
            or type(arguments) is not tuple or len(arguments) != 1 or type(arguments[0]) is not str
            or arguments[0] != BODIES[case] + '\n' or actual['uids'] != [20000] * 4
            or actual['gids'] != [20000] * 4 or any(actual['capabilities'].values())
            or actual['no_new_privs'] != 1 or actual['seccomp'] != 2 or sys.flags.utf8_mode != 1
            or canonical(actual) != claimed
            or os.readlink('/proc/self/ns/mnt') != profile['mount_namespace']
            or profile['argv'] != sys.orig_argv or profile['environment'] != dict(os.environ)
            or profile['cwd'] != os.getcwd() or profile['flags'] != [1, 1, 0]
            or [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode] != [1, 1, 0]
            or profile['argv'] != [profile['native'], '-I', '-S', '-c', BODIES[case]]
            or sys.executable != profile['native'] or type(profile['generation']) is not int or profile['generation'] != 1
            or hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest() != profile['native_sha256']
            or hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != profile['entry_sha256']):
        diagnostic = {
            'environment_matches': profile['environment'] == dict(os.environ),
            'locale_coercion_only': dict(os.environ) == {**profile['environment'], 'LC_CTYPE': 'C.UTF-8'},
            'flags': [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode],
            'argv_matches': profile['argv'] == sys.orig_argv,
            'identity_matches': canonical(actual) == claimed,
            'executable_matches': sys.executable == profile['native'],
            'body_matches': type(case) is str and case in BODIES and arguments == (BODIES[case] + '\n',),
        }
        raise ValueError('native actual execution binding: ' + json.dumps(diagnostic, sort_keys=True))
    for name, size in (('nonce', 64), ('token', 32), ('seal', 64)):
        value = profile[name]
        if type(value) is not str or len(value) != size or any(char not in '0123456789abcdef' for char in value):
            raise ValueError('native profile token')
    observer = Birth.read(profile['observer'])
    if observer.uid != 20001 or observer.pid != os.getppid():
        raise ValueError('native observer parent')
    client = Client(root, profile)
    if client.request('body-ready', {}) != {'ok': True}:
        raise ValueError('native readiness refused')
    if case.startswith('private-'):
        from network_scope import isolated
        isolated(profile['network_before'])
        PRIVATE_COMPARTMENT=True
        SCRIPT_TARGET=None
        def policy(event,args):
            return False
        POLICY=policy
    sys.path.pop(0)
    sys.dont_write_bytecode = True
    if case in ('fastpath-positive','compile-bytes','compile-current'):
        from source_entry import Policy
        from types import SimpleNamespace
        SCRIPT_TARGET=str(root/'compile-filter-fixture.py')
        sys._compile_probe_file=SCRIPT_TARGET
        production=object.__new__(Policy)
        production.poison=False
        production.profile={'script':SCRIPT_TARGET,'execution':{'script_sha256':hashlib.sha256(b'pass\n').hexdigest()}}
        production.client=SimpleNamespace(request=lambda *args:{'ok':True})
        def audit(event,args):
            if event in ('import','exec') or event=='compile' and args[1]!=SCRIPT_TARGET:
                raise RuntimeError('unnecessary Python audit callback')
            return production.audit(event,args)
        POLICY=audit
    if case.startswith('product-order-'):
        from source_entry import Policy
        from product_audit import CASES,Order
        from types import SimpleNamespace
        production=object.__new__(Policy)
        production.case,production.poison=CASES[1],False
        production.profile={'script':None}
        production.client=SimpleNamespace(request=lambda *args:{'ok':True})
        def product(event,args):
            if (event=='os.system' and case=='product-order-positive'
                    or event=='socket.getaddrinfo' and case=='product-order-resolver-positive'):
                raise RuntimeError('PRODUCT_DENIED')
        sys.addaudithook(product)
        production.audit_order=Order(production)
        production.audit_order.install()
        POLICY,SCRIPT_TARGET=production.audit,None
    BODY_READY = True



if __name__ == '_release_native_entry':
    consume(globals()['PROFILE_DIRECTORY'], globals()['ENTRY_EVENT'], globals()['ENTRY_ARGUMENTS'])
