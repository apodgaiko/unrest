"""Admit exactly the approved waiting-clock patch without rebasing the oracle.

The original template and 176-owner inventory remain the source of the baseline.
Three passive coordinator observations move only after complete owner AST
equivalence; no command, route, expression or owner is added or broadened.
"""
from __future__ import annotations

import ast
import hashlib
import os
import stat

PRE = {
    'src/unrest_harness/coordinator.py': '85b72c85acbc0ca84d382777b7714f86075d2b88d0c3de985da6d1838e30495d',
    'src/unrest_harness/supervision.py': 'd49691de1244c89dce9a64e216e130a24700cacaa46fd1777efbfc5197c63695',
    'docs/v5/08-mcp-surface.md': '507e48d709fa12fb01f94bb1d7257507ae280fb9a32bb85057a74190aef4b927',
}
POST = {
    'src/unrest_harness/coordinator.py': 'da8db10811775708fd4a0dc1f6bc6ccbe0cfc474ebe3b8c2991804d5a39b9406',
    'src/unrest_harness/supervision.py': '8a6983b504b95748da57305e6bb76f136fd3ad8d752b0657fc0d22669e689d23',
    'docs/v5/08-mcp-surface.md': '16a9ec8c470501f33f20bcbae80c1fffb87121b7498666b6882c92c0c6dc17fd',
    'tests/test_waiting_elapsed.py': 'aedd05b7d39ea23c265dbdb13dc1f37678560fb4d02a4ff428090f8630ea173a',
}
PROTECTED_AST = {
    'coordinator.py': '8d5357110c9fa58637059087cfba9ff851571db55ab6cd021008a204b80ece53',
    'supervision.py': 'dd948ff8d706115b6b5ce8800f011096943758f7debc0d22e6276225b637a3e2',
}
OWNERS = {
    597: ('_isolated_work_supported', '2cead130e9a0b8237cef8e2781bf6cc2d0dc657f3e422044e02949ce74f000e2',
          '3752d23dc0224c280bc9bf7ed23a167ba8f25d3de534dca89686007a2b7ca258'),
    731: ('_dispatch_isolated_work_batch', 'd852f4e4a07f80a375b608ae0dcc008277fa5b955c7ba78ac4014226e8290873',
          'dd35fe7acc88f7d4ff5e24b645a930d11a96996e8940ce9ba8b15d9e08c28117'),
    901: ('_validate_integration_tree', '00e806e0912764984d0c32453222f2d0e0ed1f4cca4bf15ca6bb34cab8739d59',
          '6601cafdfee026fba12cf0470926b364efb42f3b78c8022180d80c95a9dc98d3'),
}


def digest(body):
    return hashlib.sha256(body).hexdigest()


def node_hash(node):
    return digest(ast.dump(node, include_attributes=False).encode())


def read(root, name):
    path = root / name
    before = path.lstat()
    def key(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o644
            or before.st_nlink != 1 or path.resolve(strict=True) != path
            or not os.statvfs(path).f_flag & os.ST_RDONLY):
        raise RuntimeError('clock_source_input_custody')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if key(os.fstat(descriptor)) != key(before):
            raise RuntimeError('clock_source_input_open_race')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(64 * 1024 * 1024 + 1)
        if (len(body) != before.st_size or len(body) > 64 * 1024 * 1024
                or key(os.fstat(descriptor)) != key(before) or key(path.lstat()) != key(before)):
            raise RuntimeError('clock_source_input_read_race')
    finally:
        os.close(descriptor)
    return body


def protected_tree(body, name):
    tree = ast.parse(body)
    removed_function = removed_import = 0
    for node in ast.walk(tree):
        if hasattr(node, 'body') and isinstance(node.body, list):
            retained = []
            for child in node.body:
                if (isinstance(child, ast.FunctionDef) and child.name == (
                        'poll_supervision' if name == 'coordinator.py' else 'save_advisory_snapshot')):
                    removed_function += 1
                else:
                    retained.append(child)
            node.body[:] = retained
        if name == 'coordinator.py' and isinstance(node, ast.ImportFrom):
            retained = [alias for alias in node.names if alias.name != 'save_advisory_snapshot']
            removed_import += len(node.names) - len(retained)
            node.names[:] = retained
    if removed_function != 1 or removed_import != (1 if name == 'coordinator.py' else 0):
        raise RuntimeError('clock_source_patch_shape')
    if node_hash(tree) != PROTECTED_AST[name]:
        raise RuntimeError('clock_source_protected_AST')
    return ast.parse(body)


def admit(manifest, root):
    if any(manifest['product_pins'].get(name) != pin for name, pin in PRE.items()):
        raise RuntimeError('clock_source_baseline_pin')
    regression = root / 'tests/test_waiting_elapsed.py'
    if 'tests/test_waiting_elapsed.py' in manifest['product_pins']:
        raise RuntimeError('clock_source_baseline_rebased')
    bodies = {name: read(root, name) for name in PRE}
    observed = {name: digest(body) for name, body in bodies.items()}
    if observed == PRE:
        if regression.exists() or regression.is_symlink():
            raise RuntimeError('clock_source_mixed_baseline')
        return {'mode': 'original', 'remapped': []}
    if observed != {name: POST[name] for name in PRE}:
        raise RuntimeError('clock_source_unapproved_patch')
    if digest(read(root, 'tests/test_waiting_elapsed.py')) != POST['tests/test_waiting_elapsed.py']:
        raise RuntimeError('clock_source_regression_drift')
    coordinator = protected_tree(bodies['src/unrest_harness/coordinator.py'], 'coordinator.py')
    protected_tree(bodies['src/unrest_harness/supervision.py'], 'supervision.py')
    inventory = manifest['anchor_inventory']
    if len(inventory) != 176:
        raise RuntimeError('clock_source_anchor_count')
    selected = [row for row in inventory if row['path'] == 'src/unrest_harness/coordinator.py']
    if len(selected) != 3 or {row['line'] for row in selected} != set(OWNERS):
        raise RuntimeError('clock_source_anchor_membership')
    remapped = []
    for row in selected:
        name, expression, owner_hash = OWNERS[row['line']]
        if (row['owner'] != name or row['expression_ast_sha256'] != expression
                or row['source_sha256'] != PRE[row['path']]
                or row['route'] != 'subprocess.run' or row['family'] != 'cli-git-and-inline-test-helper'):
            raise RuntimeError('clock_source_anchor_schema')
        owners = [node for node in ast.walk(coordinator)
                  if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(owners) != 1 or node_hash(owners[0]) != owner_hash:
            raise RuntimeError('clock_source_owner_drift')
        calls = [node for node in ast.walk(owners[0])
                 if isinstance(node, ast.Call) and node_hash(node) == expression]
        if len(calls) != 1:
            raise RuntimeError('clock_source_expression_drift')
        remapped.append({'old_line': row['line'], 'new_line': calls[0].lineno,
                         'owner_ast_sha256': owner_hash, 'expression_ast_sha256': expression})
        row.update(line=calls[0].lineno, source_sha256=POST[row['path']])
    manifest['product_pins'].update(POST)
    return {'mode': 'exact-waiting-clock', 'remapped': remapped}
