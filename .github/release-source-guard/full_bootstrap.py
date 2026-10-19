"""Host-owned FULL input acquisition; prospective data grants no execution.

The one repository carrier excludes itself only from its input-scope digest.
The ordinary guard definition still includes the complete carrier bytes. Run,
commit and workflow identities belong to the separate private host receipt.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

from checkpoint_decision import expected_identity
from checkpoint_receipt import COMMAND
from primary_custody import exclusive, file_identity, read_regular
from primary_source_inputs import decode, require_full_input
from structured_evidence import canonical, execution_identity, loads, require

SUPPORT = Path(__file__).resolve().parent
REPOSITORY = SUPPORT.parent.parent
CARRIER = '.github/release-source-guard/checkpoint-inputs.json'
PREFIX = 'refs/heads/codex/source-guard-structured-20261018-full-bootstrap-'
REFS = frozenset(PREFIX + f'{epoch:02}' for epoch in range(1, 7))
WORKFLOW = 'apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@'
SCRIPT = COMMAND.encode()
OPERATIONS = {'PREPAREONLY', 'FULL', 'PREFLIGHT'}


def sha(body):
    return hashlib.sha256(body).hexdigest()


def reserved(ref):
    # Reserve the whole family, including malformed suffixes and lookalikes.
    return 'source-guard-structured-20261018-full-bootstrap' in ref


def context(operation):
    require(operation in OPERATIONS and sys.platform == 'linux'
            and os.getuid() not in {0, 20000, 20001}, 'full_host_role')
    ref = os.environ['GITHUB_REF']
    if operation == 'PREFLIGHT':
        from preflight_policy import context as preflight_context
        preflight_context()
    elif operation == 'PREPAREONLY':
        require(ref in REFS
                and os.environ['GITHUB_WORKFLOW'] == 'v0.4.6 source guard readiness'
                and os.environ['GITHUB_WORKFLOW_REF'] == WORKFLOW + ref,
                'full_prepare_workflow')
    else:
        require(not reserved(ref) and os.environ['GITHUB_WORKFLOW'] == 'CI',
                'full_execution_workflow')
    identity = execution_identity(SUPPORT, 'primary-source')
    require(identity['workflow_sha'] == identity['head_sha'], 'full_workflow_head')
    return identity


def semantic_manifest(repository=REPOSITORY):
    """Every tracked input, with precisely one nonrecursive carrier boundary."""
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=repository).decode().split('\0')
    require(len(names) == len(set(names)), 'full_scope_duplicates')
    result = {}
    for name in sorted(filter(None, names)):
        if name == CARRIER:
            continue
        path = repository / name
        require(path.resolve(strict=True) == path, 'full_scope_alias')
        body = read_regular(path, 64 * 1024 * 1024)
        info = path.lstat()
        result[name] = {'sha256': sha(body), 'mode': stat.S_IMODE(info.st_mode)}
    # An untracked support JSON is still a new guard-definition input. It must
    # not disappear merely because the source snapshot is a Git enumeration.
    support = repository / '.github/release-source-guard'
    actual = {str(p.relative_to(repository)) for p in support.rglob('*')
              if p.is_file() and p.suffix in {'.py', '.json', '.pem', '.c'}}
    require(actual <= set(result) | {CARRIER}, 'full_unknown_support')
    return {'schema': 'unrest.v046.semantic-candidate.v1', 'release_version': '0.4.7',
            'inputs': result}


def scope(repository=REPOSITORY):
    return sha(canonical(semantic_manifest(repository)))


def carrier(repository=REPOSITORY):
    body = read_regular(repository / CARRIER, 65536, 0o644)
    value = decode(body)
    require(type(value) is dict and set(value) == {
        'schema', 'operation', 'input_scope_sha256', 'source_carrier_sha256',
        'package_closure_sha256', 'applicability_sha256', 'preparation_sha256'},
        'full_carrier_fields')
    require(value['schema'] == 'unrest.v046.full-readiness-inputs.v1'
            and value['operation'] in OPERATIONS, 'full_carrier_kind')
    for key in ('input_scope_sha256', 'source_carrier_sha256',
                'package_closure_sha256', 'applicability_sha256'):
        require(type(value[key]) is str and re.fullmatch('[0-9a-f]{64}', value[key]),
                'full_carrier_digest')
    require(value['input_scope_sha256'] == scope(repository), 'full_scope_drift')
    proof = value['preparation_sha256']
    require((value['operation'] in {'PREPAREONLY', 'PREFLIGHT'} and proof is None)
            or (value['operation'] == 'FULL' and type(proof) is str
                and re.fullmatch('[0-9a-f]{64}', proof)), 'full_carrier_preparation')
    return value, sha(body)


def private_root(runner, create=False):
    require(runner.resolve(strict=True) == runner and runner.is_dir()
            and runner.lstat().st_uid == os.getuid(), 'full_runner_root')
    root = runner / 'primary-input-custody'
    if create:
        root.mkdir(mode=0o700)
    before = root.lstat()
    require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700
            and before.st_uid == os.getuid() and root.resolve(strict=True) == root,
            'full_private_root')
    return root, file_identity(before)[:6]


def clock():
    return {'wall_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(),
            'boot_sha256': sha(Path('/proc/sys/kernel/random/boot_id').read_bytes())}


def produce(operation):
    identity = context(operation)
    require(subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], cwd=REPOSITORY,
                           check=False).returncode == 0, 'full_checkout_drift')
    definition = expected_identity()
    value, pin = carrier()
    require(operation in {'PREPAREONLY', 'PREFLIGHT'} or value['operation'] == 'FULL', 'full_not_sealed')
    workflow = (REPOSITORY / '.github/workflows/ci.yml').read_text()
    result = {'schema': 'unrest.v046.primary-source-input.v1', 'definition': definition,
              'source_carrier_sha256': value['source_carrier_sha256'],
              'package_closure_sha256': value['package_closure_sha256'],
              'final_closure_sha256': pin, 'source_checkpoint_ready': True,
              'selected_carrier': value['source_carrier_sha256']}
    if operation == 'PREFLIGHT':
        result = {'schema': 'unrest.v046.primary-preflight-input.v1', 'definition': definition,
                  'candidate_sha256': value['input_scope_sha256'],
                  'source_checkpoint_ready': False, 'selected_carrier': None}
    else:
        require_full_input(result, SCRIPT, workflow)
    runner = Path(os.environ['RUNNER_TEMP'])
    root, root_identity = private_root(runner, create=True)
    key = secrets.token_bytes(32)
    exclusive(root / 'candidate.json', canonical(semantic_manifest()))
    exclusive(root / 'key', key)
    destination = runner / 'primary-source-input.json'
    exclusive(destination, canonical(result))
    require(read_regular(destination, 65536, 0o600) == canonical(result), 'full_input_write')
    receipt = {'schema': 'unrest.v046.full-host-input.v1', 'operation': operation,
               'identity': identity, 'definition': definition, 'uid': os.getuid(),
               # Sibling capsule creation can change runner nlink/timestamps.
               'runner_identity': file_identity(runner.lstat())[:5],
               'root_identity': root_identity, 'input_identity': file_identity(destination.lstat()),
               'input_sha256': sha(canonical(result)), 'carrier_sha256': pin,
               'script_sha256': sha(SCRIPT), 'nonce': secrets.token_hex(32), 'clock': clock()}
    signed = {'receipt': receipt, 'mac': hmac.digest(key, canonical(receipt), 'sha256').hex()}
    exclusive(root / 'receipt.json', canonical(signed))
    # Use the actual consumer on the physical file before reporting acquisition.
    consume(operation, SCRIPT)
    return {'schema': 'unrest.v046.full-input-produced.v1', 'operation': operation,
            'input_sha256': sha(canonical(result)), 'carrier_sha256': pin,
            'source_testcase_executed': False, 'eligible_certificate': False}


def consume(operation, script):
    identity = context(operation)
    runner = Path(os.environ['RUNNER_TEMP'])
    root, root_identity = private_root(runner)
    key = read_regular(root / 'key', 32, 0o600)
    receipt_body = read_regular(root / 'receipt.json', 16384, 0o600)
    signed = loads(receipt_body)
    require(type(signed) is dict and set(signed) == {'receipt', 'mac'}, 'full_host_envelope')
    receipt = signed['receipt']
    require(type(receipt) is dict and set(receipt) == {
        'schema', 'operation', 'identity', 'definition', 'uid', 'runner_identity', 'root_identity',
        'input_identity', 'input_sha256', 'carrier_sha256', 'script_sha256', 'nonce', 'clock'}
        and type(receipt['clock']) is dict and set(receipt['clock']) == {
            'wall_ns', 'monotonic_ns', 'boot_sha256'}
        and all(type(receipt['clock'][name]) is int for name in ('wall_ns', 'monotonic_ns'))
        and type(receipt['nonce']) is str and re.fullmatch('[0-9a-f]{64}', receipt['nonce']),
        'full_host_receipt_fields')
    require(len(key) == 32 and type(signed['mac']) is str
            and hmac.compare_digest(signed['mac'], hmac.digest(key, canonical(receipt), 'sha256').hex()),
            'full_host_mac')
    value, pin = carrier()
    candidate = read_regular(root / 'candidate.json', 64 * 1024 * 1024, 0o600)
    require(candidate == canonical(semantic_manifest())
            and sha(candidate) == value['input_scope_sha256'], 'full_semantic_candidate_drift')
    require(operation in {'PREPAREONLY', 'PREFLIGHT'} or value['operation'] == 'FULL', 'full_not_sealed')
    path = runner / 'primary-source-input.json'
    body = read_regular(path, 65536, 0o600)
    now = clock()
    original = receipt['clock']
    wall = now['wall_ns'] - original['wall_ns']
    monotonic = now['monotonic_ns'] - original['monotonic_ns']
    require(now['boot_sha256'] == original['boot_sha256'] and 0 <= wall <= 7200 * 10**9
            and 0 <= monotonic <= 7200 * 10**9 and abs(wall - monotonic) <= 5 * 10**9,
            'full_host_deadline')
    require(receipt['schema'] == 'unrest.v046.full-host-input.v1'
            and receipt['identity'] == identity and receipt['definition'] == expected_identity()
            and receipt['operation'] == operation and receipt['uid'] == os.getuid()
            and receipt['runner_identity'] == list(file_identity(runner.lstat())[:5])
            and receipt['root_identity'] == list(root_identity)
            and receipt['input_identity'] == list(file_identity(path.lstat()))
            and receipt['input_sha256'] == sha(body) and receipt['carrier_sha256'] == pin
            and receipt['script_sha256'] == sha(SCRIPT), 'full_host_binding')
    result = decode(body)
    if operation == 'PREFLIGHT':
        require(result == {'schema': 'unrest.v046.primary-preflight-input.v1',
                          'definition': receipt['definition'],
                          'candidate_sha256': value['input_scope_sha256'],
                          'source_checkpoint_ready': False, 'selected_carrier': None},
                'preflight_input_binding')
    else:
        require(result['definition'] == receipt['definition']
            and result['final_closure_sha256'] == pin
            and result['source_carrier_sha256'] == value['source_carrier_sha256']
            and result['package_closure_sha256'] == value['package_closure_sha256'], 'full_input_binding')
    require(private_root(runner)[1] == root_identity, 'full_private_root_replaced')
    require(read_regular(root / 'key', 32, 0o600) == key
            and read_regular(root / 'receipt.json', 16384, 0o600) == receipt_body
            and read_regular(path, 65536, 0o600) == body
            and list(file_identity(path.lstat())) == receipt['input_identity'],
            'full_host_acquisition_changed')
    # Package scripts use the same SOURCE readiness closure, then their own
    # unchanged script validator. SOURCE must retain the literal original argv.
    if operation != 'PREFLIGHT':
        require_full_input(result, SCRIPT, (REPOSITORY / '.github/workflows/ci.yml').read_text())
    else:
        from preflight_policy import SCRIPT as preflight_script
        from phase_catalog import catalog
        require(script == preflight_script or script in {
            phase.command.rstrip('\n').encode() if '\n' not in phase.command.rstrip('\n')
            else phase.command.encode() for phase in catalog().values()}, 'preflight_actual_script')
    if operation == 'PREPAREONLY':
        require(script == SCRIPT, 'full_prepare_script')
    return result


def main():
    require(len(sys.argv) == 2, 'full_producer_argv')
    print(canonical(produce(sys.argv[1])).decode())


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print(canonical({'schema': 'unrest.v046.full-input-produced.v1', 'status': 'refused',
                         'source_testcase_executed': False, 'eligible_certificate': False}).decode())
        raise SystemExit(125) from None
