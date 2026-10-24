"""Exact no-child object-reader transition; retire only its removed launch anchor."""
from __future__ import annotations

import hashlib
import ast

PRE = {
    'tests/test_experimental_candidate.py': 'd671843de1005fa76f87599309ad8f96f695a8b3ffffb2ba2ae8369b529cd871',
    'src/unrest_harness/experimental_candidate.py': 'ddff1f67abca50f1e8634ba4bffe2e8afeb3d58d54ce3a1774a6c8d1f23d6534',
    'docs/architecture/experimental-candidate.md': '45b9ae329239feb1c729441d7fcd0327cdcf51710d2b96f1d7850f33fef097fe',
}
POST = {'src/unrest_harness/experimental_candidate.py': '62a7e9fa5e28910995817389625849c21be58b1bd046f49c73a79f375bc33d3a', 'docs/architecture/experimental-candidate.md': '818b597b952889851a238be0abea3cd08c40823400070eec2997c47a01a09440', 'tests/test_experimental_candidate_templates.py': 'fb99101ac7cb3e61cfeb4879fd75bae060749fa98738d04b0dab34d9c259ff1b', 'tests/test_experimental_candidate.py': '4c9898c08322fe7454c5520cfa3a0dc3b3f9bf42dcd1d9fcc96c0213a50acb83', 'tests/test_experimental_candidate_loose.py': 'b3267246d87da8a4bdd01a01a012b742e17d2fa053fa052d578fd98484113c06', 'docs/architecture/release-guard-integration.md': 'a02c47445f28901872cc4a6831ed0873ddd449554568e7e63337eb3d76873ca6'}

SOURCE = 'src/unrest_harness/experimental_candidate.py'
ANCHOR = {'expression_ast_sha256': 'a63fa6d3859859db7ee40f3517ac75b38ff3d9d806e5da13e29e692fddab5c76',
          'family': 'controlled-session-backend-and-owned-lifecycle', 'line': 151,
          'owner': 'git', 'path': SOURCE, 'route': 'subprocess.Popen', 'source_sha256': PRE[SOURCE]}
OWNER_AST = '5c5a7897d559a83eee6e5aebbde13922b2dc8ae5e1255b9822032717e5b4f8c5'

FIXTURE_ANCHOR = {'expression_ast_sha256': '19d96a8bb51033992e626291c4488125832f60d8419386f320419aa917518c05', 'family': 'controlled-session-backend-and-owned-lifecycle', 'line': 21, 'owner': 'git', 'path': 'tests/test_experimental_candidate.py', 'route': 'subprocess.check_output', 'source_sha256': 'd671843de1005fa76f87599309ad8f96f695a8b3ffffb2ba2ae8369b529cd871'}


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
    fixture_rows = [row for row in inventory if row.get('path') == FIXTURE_ANCHOR['path']]
    if fixture_rows != [FIXTURE_ANCHOR]:
        raise RuntimeError('candidate_template_fixture_anchor')
    fixture_calls = [node for node in ast.walk(ast.parse(bodies[FIXTURE_ANCHOR['path']]))
                     if isinstance(node, ast.Call) and node.lineno == FIXTURE_ANCHOR['line']
                     and hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
                     == FIXTURE_ANCHOR['expression_ast_sha256']]
    if len(fixture_calls) != 1:
        raise RuntimeError('candidate_template_fixture_expression')
    tree = ast.parse(bodies[SOURCE])
    owners = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == '_Observation']
    methods = [node for owner in owners for node in owner.body
               if isinstance(node, ast.FunctionDef) and node.name == 'object']
    if (len(owners) != 1 or len(methods) != 1
            or any(isinstance(node, ast.FunctionDef) and node.name == 'git' for node in owners[0].body)
            or hashlib.sha256(ast.dump(methods[0], include_attributes=False).encode()).hexdigest() != OWNER_AST):
        raise RuntimeError('candidate_template_object_owner')
    # The complete source pin proves the old subprocess owner is gone. Retiring
    # its exact historical anchor narrows launch authority; no replacement route.
    inventory.remove(selected[0])
    fixture_rows[0]['source_sha256'] = POST[FIXTURE_ANCHOR['path']]
    pins.update(POST)
