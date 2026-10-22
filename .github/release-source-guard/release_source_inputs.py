"""Exact release-identity transition; historical source/owner oracles stay fixed."""
from __future__ import annotations

import hashlib

PRE = {'CITATION.cff': 'fde9509583b5d1ba08f1ca54cb05015ae8d2ca8b74c997e1f023a9db8405ce21', 'README.md': 'f3fb90c7f0b7801d57d1b134def50add0ae4df5bf3ec91982ce1d309d30d5a09', 'docs/architecture/index.md': 'f6455ebd14abe2e06923252abd36e631d17a0ea5918d297d09e7b1ad8c9bbd54', 'pyproject.toml': '567b3e93e2bd52e63f7f506a6c57df9c036431c0fc99885ce5d42fdd3903a755', 'src/unrest_harness/__init__.py': 'a501511b85d9e09cf1bfb8642657ebdd126358d8ac05a108b726331294502b36', 'tests/test_release_identity.py': 'c7c70b7bb87e611725a9330c761096ac117e6d8eb896fe37660a202d9ec9aff4', 'uv.lock': 'cbaeb11d2f8308251274659e530adbafbfe5e4f054baf71b11eaecd8e1e48750', 'tests/test_v045_release_records.py': '0147b67ca6386282d79dfc988e55120141c46e76a095dec3bab46dda2ef5aef6'}
POST = {'CITATION.cff': '303967989f0b355e1e5bfe3a7c00960d0275b2e01d1e7e74e8e461fc8a1580c2', 'README.md': 'd86720eddf523ccfc411c2f5014f4fe05c4f94b7b894bfecaba45c60a028ed36', 'docs/architecture/index.md': '671c184bdacb41adacd5f9c708debe3f9f035721850cc994ef5e789b329c9e53', 'pyproject.toml': '4df92555d1d341a1c04f1b0bac682e4221c31f91674f017e2e14ed0eedd4415f', 'src/unrest_harness/__init__.py': '74850da5471db9efec89961960c9568c05a8f38787e8e624b3c9f7800e4841fb', 'tests/test_release_identity.py': '3902b5cb8e669ae532cc57301f552d772e1f0119d6f59d667fac87c241313ce1', 'uv.lock': 'd7dcea4ddefcfbe87a58f83edee8be33dd612cb92f6b9dcdc5e11de5982b56d7', 'tests/test_v045_release_records.py': 'be9693d6ad6937f0080f6022d3db602ad8530c0d24f8528b85ebc3ee4c492da4'}


def admit(manifest, root, read):
    if set(PRE) != set(POST):
        raise RuntimeError('release_identity_membership')
    for name, before in PRE.items():
        if manifest['product_pins'].get(name) != before:
            raise RuntimeError('release_identity_preimage')
        if hashlib.sha256(read(root, name)).hexdigest() != POST[name]:
            raise RuntimeError('release_identity_postimage')
    manifest['product_pins'].update(POST)
