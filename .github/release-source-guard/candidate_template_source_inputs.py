"""Exact source input transition for the inert legacy Git template repair."""
from __future__ import annotations

import hashlib
import ast

PRE = {
    'src/unrest_harness/experimental_candidate.py': 'ddff1f67abca50f1e8634ba4bffe2e8afeb3d58d54ce3a1774a6c8d1f23d6534',
    'docs/architecture/experimental-candidate.md': '45b9ae329239feb1c729441d7fcd0327cdcf51710d2b96f1d7850f33fef097fe',
}
POST = {
    'src/unrest_harness/experimental_candidate.py': '78e979fbf082e22d0cc1d2ec5f50e2cbb9ca610b13382327563a1e09362e7084',
    'docs/architecture/experimental-candidate.md': '6f07eaeb4e7852c2d962b3bf633467470d5e955540344c80b165bf4700ad5edd',
    'tests/test_experimental_candidate_templates.py': 'fb99101ac7cb3e61cfeb4879fd75bae060749fa98738d04b0dab34d9c259ff1b',
}

SOURCE = 'src/unrest_harness/experimental_candidate.py'
ANCHOR = {'expression_ast_sha256': 'a63fa6d3859859db7ee40f3517ac75b38ff3d9d806e5da13e29e692fddab5c76',
          'family': 'controlled-session-backend-and-owned-lifecycle', 'line': 151,
          'owner': 'git', 'path': SOURCE, 'route': 'subprocess.Popen', 'source_sha256': PRE[SOURCE]}
OWNER_AST = 'cef37191574dcc383fc345438ac524c94c13cba166cb6bdd9314b0df6a4bfa8e'


def admit(manifest, root, read):
    pins = manifest['product_pins']
    if (any(pins.get(name) != pin for name, pin in PRE.items())
            or any(name in pins for name in POST.keys() - PRE.keys())):
        raise RuntimeError('candidate_template_preimage')
    bodies = {name: read(root, name) for name in POST}
    for name, pin in POST.items():
        if hashlib.sha256(bodies[name]).hexdigest() != pin:
            raise RuntimeError('candidate_template_postimage')
    inventory = manifest['anchor_inventory']
    selected = [row for row in inventory if row.get('path') == SOURCE]
    if len(inventory) != 176 or selected != [ANCHOR]:
        raise RuntimeError('candidate_template_anchor_preimage')
    tree = ast.parse(bodies[SOURCE])
    owners = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == '_Observation']
    methods = [node for owner in owners for node in owner.body
               if isinstance(node, ast.FunctionDef) and node.name == 'git']
    if (len(owners) != 1 or len(methods) != 1 or methods[0].lineno != 147
            or hashlib.sha256(ast.dump(methods[0], include_attributes=False).encode()).hexdigest() != OWNER_AST):
        raise RuntimeError('candidate_template_git_owner')
    calls = [node for node in ast.walk(methods[0]) if isinstance(node, ast.Call) and node.lineno == 151]
    if (len(calls) != 1 or hashlib.sha256(ast.dump(calls[0], include_attributes=False).encode()).hexdigest()
            != ANCHOR['expression_ast_sha256']):
        raise RuntimeError('candidate_template_git_expression')
    # No command, owner, expression, route, or line moves; only its file pin changes.
    selected[0]['source_sha256'] = POST[SOURCE]
    pins.update(POST)
