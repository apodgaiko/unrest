"""Exact release-identity transition; historical source/owner oracles stay fixed."""
from __future__ import annotations

import hashlib
import ast

PRE = {'tests/test_acp_cleanup.py': '564d5ec1b8c24680137d0d283f91c38a8ceff6d79b5a25f409edce775ec2aba8', 'CITATION.cff': 'fde9509583b5d1ba08f1ca54cb05015ae8d2ca8b74c997e1f023a9db8405ce21', 'README.md': 'f3fb90c7f0b7801d57d1b134def50add0ae4df5bf3ec91982ce1d309d30d5a09', 'docs/architecture/index.md': 'f6455ebd14abe2e06923252abd36e631d17a0ea5918d297d09e7b1ad8c9bbd54', 'pyproject.toml': '567b3e93e2bd52e63f7f506a6c57df9c036431c0fc99885ce5d42fdd3903a755', 'src/unrest_harness/__init__.py': 'a501511b85d9e09cf1bfb8642657ebdd126358d8ac05a108b726331294502b36', 'tests/test_release_identity.py': 'c7c70b7bb87e611725a9330c761096ac117e6d8eb896fe37660a202d9ec9aff4', 'uv.lock': 'cbaeb11d2f8308251274659e530adbafbfe5e4f054baf71b11eaecd8e1e48750', 'tests/test_v045_release_records.py': '0147b67ca6386282d79dfc988e55120141c46e76a095dec3bab46dda2ef5aef6'}
POST = {'tests/test_acp_cleanup.py': 'f63f37e40e925d409c4f8203ebabe85dcc0bc5d7e9c77feb267c485eacfce321', 'CITATION.cff': '303967989f0b355e1e5bfe3a7c00960d0275b2e01d1e7e74e8e461fc8a1580c2', 'README.md': 'd86720eddf523ccfc411c2f5014f4fe05c4f94b7b894bfecaba45c60a028ed36', 'docs/architecture/index.md': '671c184bdacb41adacd5f9c708debe3f9f035721850cc994ef5e789b329c9e53', 'pyproject.toml': '4df92555d1d341a1c04f1b0bac682e4221c31f91674f017e2e14ed0eedd4415f', 'src/unrest_harness/__init__.py': '74850da5471db9efec89961960c9568c05a8f38787e8e624b3c9f7800e4841fb', 'tests/test_release_identity.py': '3902b5cb8e669ae532cc57301f552d772e1f0119d6f59d667fac87c241313ce1', 'uv.lock': 'd7dcea4ddefcfbe87a58f83edee8be33dd612cb92f6b9dcdc5e11de5982b56d7', 'tests/test_v045_release_records.py': 'be9693d6ad6937f0080f6022d3db602ad8530c0d24f8528b85ebc3ee4c492da4'}


CLEANUP_ANCHORS = [{'expression_ast_sha256': 'c1572b86e076e92120cdd0aeb361561b1017aadd23daf96ed5e053de363748f1',
  'family': 'ordinary-acp-and-role-helper',
  'line': 53,
  'owner': 'start',
  'path': 'tests/test_acp_cleanup.py',
  'route': 'asyncio.create_subprocess_exec',
  'source_sha256': '564d5ec1b8c24680137d0d283f91c38a8ceff6d79b5a25f409edce775ec2aba8'},
 {'expression_ast_sha256': '046228b13172ed098719012bde9c2f6ba517c7261a6bc1b3704706ff1d8094b7',
  'family': 'ordinary-acp-and-role-helper',
  'line': 123,
  'owner': 'test_recorded_transport_failures',
  'path': 'tests/test_acp_cleanup.py',
  'route': 'subprocess.run',
  'source_sha256': '564d5ec1b8c24680137d0d283f91c38a8ceff6d79b5a25f409edce775ec2aba8'},
 {'expression_ast_sha256': '24afffc5076bbf0a2f0afbfa4a58f96d583674bf692b40947c26ab96f737424f',
  'family': 'ordinary-acp-and-role-helper',
  'line': 124,
  'owner': 'test_recorded_transport_failures',
  'path': 'tests/test_acp_cleanup.py',
  'route': 'subprocess.run',
  'source_sha256': '564d5ec1b8c24680137d0d283f91c38a8ceff6d79b5a25f409edce775ec2aba8'},
 {'expression_ast_sha256': '2311ed36ba0a9913fd5a4c0ea97a672af016dc4e5d64f7557be7b8da1e90e9de',
  'family': 'ordinary-acp-and-role-helper',
  'line': 261,
  'owner': 'test_client_cleanup_reaps_main_after_reader_failure',
  'path': 'tests/test_acp_cleanup.py',
  'route': 'asyncio.create_subprocess_exec',
  'source_sha256': '564d5ec1b8c24680137d0d283f91c38a8ceff6d79b5a25f409edce775ec2aba8'},
 {'expression_ast_sha256': '2311ed36ba0a9913fd5a4c0ea97a672af016dc4e5d64f7557be7b8da1e90e9de',
  'family': 'ordinary-acp-and-role-helper',
  'line': 291,
  'owner': 'test_client_exhausts_terminals_pending_and_main',
  'path': 'tests/test_acp_cleanup.py',
  'route': 'asyncio.create_subprocess_exec',
  'source_sha256': '564d5ec1b8c24680137d0d283f91c38a8ceff6d79b5a25f409edce775ec2aba8'}]
CLEANUP_COMMIT_AST = '7180bf0c5f7475f393aeaa0c349c8d1317084adb46782db07ddb4f9f3c29230e'

def admit(manifest, root, read):
    if set(PRE) != set(POST):
        raise RuntimeError('release_identity_membership')
    for name, before in PRE.items():
        if manifest['product_pins'].get(name) != before:
            raise RuntimeError('release_identity_preimage')
        if hashlib.sha256(read(root, name)).hexdigest() != POST[name]:
            raise RuntimeError('release_identity_postimage')
    # The fixture changed only its exact setup argv; retain every original owner,
    # route and line, and never derive permission from arbitrary observed bytes.
    selected = [row for row in manifest['anchor_inventory']
                if row['path'] == 'tests/test_acp_cleanup.py']
    if selected != CLEANUP_ANCHORS:
        raise RuntimeError('cleanup_setup_anchor_preimage')
    calls = [node for node in ast.walk(ast.parse(read(root, 'tests/test_acp_cleanup.py')))
             if isinstance(node, ast.Call) and node.lineno == 124]
    if (len(calls) != 1 or hashlib.sha256(ast.dump(calls[0], include_attributes=False).encode()).hexdigest()
            != CLEANUP_COMMIT_AST):
        raise RuntimeError('cleanup_setup_expression')
    for row in selected:
        row['source_sha256'] = POST['tests/test_acp_cleanup.py']
        if row['line'] == 124:
            row['expression_ast_sha256'] = CLEANUP_COMMIT_AST
    manifest['product_pins'].update(POST)
