"""Exact source input transition for the inert legacy Git template repair."""
from __future__ import annotations

import hashlib

PRE = {
    'src/unrest_harness/experimental_candidate.py': 'ddff1f67abca50f1e8634ba4bffe2e8afeb3d58d54ce3a1774a6c8d1f23d6534',
    'docs/architecture/experimental-candidate.md': '45b9ae329239feb1c729441d7fcd0327cdcf51710d2b96f1d7850f33fef097fe',
}
POST = {
    'src/unrest_harness/experimental_candidate.py': '78e979fbf082e22d0cc1d2ec5f50e2cbb9ca610b13382327563a1e09362e7084',
    'docs/architecture/experimental-candidate.md': '6f07eaeb4e7852c2d962b3bf633467470d5e955540344c80b165bf4700ad5edd',
    'tests/test_experimental_candidate_templates.py': 'fb99101ac7cb3e61cfeb4879fd75bae060749fa98738d04b0dab34d9c259ff1b',
}


def admit(manifest, root, read):
    pins = manifest['product_pins']
    if (any(pins.get(name) != pin for name, pin in PRE.items())
            or any(name in pins for name in POST.keys() - PRE.keys())):
        raise RuntimeError('candidate_template_preimage')
    for name, pin in POST.items():
        if hashlib.sha256(read(root, name)).hexdigest() != pin:
            raise RuntimeError('candidate_template_postimage')
    # The original map changes only after every exact, read-only input matched.
    pins.update(POST)
