"""Data-only refusal diagnostics never admit a cache or reveal its values."""
import json
import struct

import pytest

from primary_package_cache_diagnostic import decode, projection, LIMIT


@pytest.mark.parametrize(('body', 'expected'), [
    (b'\xc0', None), (b'\xc2', False), (b'\xc3', True), (b'\x7f', 127),
    (b'\xff', -1), (b'\xe0', -32), (b'\xcc\xff', 255),
    (b'\xcd\x01\x00', 256), (b'\xce\x00\x01\x00\x00', 65536),
    (b'\xcf' + (1 << 40).to_bytes(8, 'big'), 1 << 40),
    (b'\xd0\x80', -128), (b'\xd1\xff\x00', -256),
    (b'\xd2\xff\xff\x00\x00', -65536),
    (b'\xd3' + (-1 << 40).to_bytes(8, 'big', signed=True), -1 << 40),
    (b'\xa3abc', 'abc'), (b'\xd9\x03abc', 'abc'), (b'\xda\x00\x03abc', 'abc'),
    (b'\xdb\x00\x00\x00\x03abc', 'abc'),
    (b'\xc4\x03\x00\x01\xff', b'\x00\x01\xff'),
    (b'\xc5\x00\x03abc', b'abc'), (b'\xc6\x00\x00\x00\x03abc', b'abc'),
    (b'\xca' + struct.pack('>f', 1.5), 1.5), (b'\xcb' + struct.pack('>d', 1.25), 1.25),
    (b'\x92\x01\x02', [1, 2]), (b'\xdc\x00\x02\x01\x02', [1, 2]),
    (b'\xdd\x00\x00\x00\x02\x01\x02', [1, 2]),
    (b'\x81\xa1a\x01', {'a': 1}), (b'\xde\x00\x01\xa1a\x01', {'a': 1}),
    (b'\xdf\x00\x00\x00\x01\xa1a\x01', {'a': 1}),
])
def test_exact_data_vectors(body, expected):
    value = decode(body)
    assert type(value) is type(expected) and value == expected


@pytest.mark.parametrize('body', [b'', b'\xc1', b'\xc7', b'\x01\x02', b'\xd9\x03ab',
                                b'\xa1\xff', b'\x82\xa1a\x01\xa1a\x02',
                                b'\x81\xc2\x01', b'\x81\x90\x01',
                                b'\x91' * 18 + b'\xc0', b'\xdd\xff\xff\xff\xff',
                                b'\xdf\xff\xff\xff\xff', b'\x00' * (LIMIT + 1),
                                b'\xcb' + struct.pack('>d', float('nan'))])
def test_unknown_malformed_or_unbounded_data_cannot_be_projected(body):
    with pytest.raises(ValueError):
        decode(body)


def test_projection_contains_only_shapes_hashes_and_query_field_matches():
    value = ['private-value-canary', b'opaque-canary', {'path/private': 'private-value-canary'}]
    result = projection(value, {'sys_executable': 'private-value-canary'})
    body = json.dumps(result)
    assert 'private-value-canary' not in body and 'opaque-canary' not in body and 'path/private' not in body
    assert result['items'][0]['query_field_matches'] == ['sys_executable']
    assert result['items'][1]['type'] == 'bytes' and result['items'][1]['bytes'] == 13


@pytest.mark.parametrize('mode', ['refusal', 'diagnostic_failure', 'other_error', 'unknown_pid', 'success'])
def test_diagnostic_never_changes_original_cache_outcome(monkeypatch, mode):
    import ast
    from pathlib import Path
    import primary_package_cache_diagnostic as diagnostic
    path = Path(__file__).with_name('primary_package_build.py')
    tree = ast.parse(path.read_bytes())
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'PackageProducers')
    original = RuntimeError('other' if mode == 'other_error' else 'primary_cache_unbound_original_output')
    sentinel = object()
    calls = []

    class Original:
        def completed_cache(self, event, trace):
            if mode == 'success':
                return sentinel
            raise original

    namespace = {'NativeProducers': Original}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
    producers = namespace['PackageProducers']()
    producers.uv = {} if mode == 'unknown_pid' else {12: {'pid': 12}}
    producers.cache_external = {'original'}

    def observe(owner, context):
        assert owner is producers and context is producers.uv[12]
        calls.append(context)
        if mode == 'diagnostic_failure':
            raise ValueError('malformed data')
        return {'authority_granted': False, 'eligible_certificate': False}

    monkeypatch.setattr(diagnostic, 'observe', observe)
    if mode == 'success':
        assert producers.completed_cache({'pid': 12}, object()) is sentinel
    else:
        with pytest.raises(RuntimeError) as raised:
            producers.completed_cache({'pid': 12}, object())
        assert raised.value is original
    assert producers.cache_external == {'original'}
    assert len(calls) == int(mode in {'refusal', 'diagnostic_failure'})
    if mode in {'refusal', 'diagnostic_failure'}:
        assert producers.package_cache_refusal['authority_granted'] is False
        assert producers.package_cache_refusal['eligible_certificate'] is False
    else:
        assert not hasattr(producers, 'package_cache_refusal')
