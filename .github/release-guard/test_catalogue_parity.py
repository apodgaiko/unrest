"""Ordered pre-factoring declarations: data equality, never runtime authority."""
import hashlib
import json

import pytest

import controlled_cases as catalogue

# Frozen before factoring expanded parameter products. Hash the ordered item
# sequence: sorting here would hide a changed execution frontier or case seal.
PINS = {
    'ROOT_HTTP': 'c260f4fd7011dc396081446c107ebdf9397c90a867586b0678308336ce94755c',
    'ADMISSION': 'f18fd2e632e256a09674877d334bd0096368f2bb3d8dcb82400d8a5948f9b268',
    'WARNING_REFUSALS': 'b8318e20ad9bb103fa0262307abceca1f91cf26a10da343f4c7303ddc1adf964',
    'NOTIFICATION_STARTUP': 'c3bda57d18d4a361fed498f892b40f90bc98697a24822c337fbbcc9ea91af360',
    'NOTIFICATION_SIGNALS': '6f58338ebfea5b7cbc3349615d08d6fc0f8e97c662f630a64eddf8cf39b0d3d3',
    'POPULATED': 'c6e88849a9665abcc40f58276457d2828cfb32e53b2a80f6a63ca53230514ac8',
    'FRESH': '9296f8b7380c0d14ce4f30b30e70aa80dd9bc3519435efc59ef351a5dbddcaba',
    'CASES': '297dbc4ffce7118d4c822e403da3c65174526323bd48d015158b60964fd412a8',
    'GROUPS': '59fa1175200c929bf823c41570ae555c7c1710ca34b9a3862680242887bb3f5b',
    'PINS': '4bcf82ff922ebcd5530188724cb800d8f9aac0b090c7129d89d38f689212a17e',
}


@pytest.mark.parametrize('name', PINS)
def test_complete_ordered_mapping_is_identical(name):
    body = json.dumps(list(getattr(catalogue, name).items()), separators=(',', ':')).encode()
    assert hashlib.sha256(body).hexdigest() == PINS[name]


def test_preflight_and_bootstrap_ordered_axes_are_identical():
    from dataclasses import asdict
    from test_preflight_inventory import CASES
    from bootstrap_cases import DECLARATIONS
    snapshots = (
        (CASES, 'decd3ed6e0c3435bfc8ff57adcd5fd28cc51804ad21d9894a47f68d3134088be'),
        ([asdict(value) for value in DECLARATIONS],
         '48fb21f65e272f2f709b5ecc6b9ff98c8be8762b00b34e05c58a56b187fa61cf'),
    )
    for value, pin in snapshots:
        body = json.dumps(value, separators=(',', ':')).encode()
        assert hashlib.sha256(body).hexdigest() == pin
