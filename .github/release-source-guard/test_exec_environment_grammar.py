"""Raw execve grammar preserves empty names without granting any launch."""
from __future__ import annotations

import pytest

from test_startup_phases import load_trace


def invoke(monkeypatch, rows, *, accept):
    module = load_trace()
    trace = module.OwnedTrace.__new__(module.OwnedTrace)
    trace.records, trace.allowed, trace.poison, trace.denied = [], [], [], set()
    seen = []
    def resolve(pid, path, vector, environment, cwd):
        seen.append((pid, path, vector, environment, cwd))
        return accept
    trace.resolve_exec = resolve
    monkeypatch.setattr(module, 'read_string', lambda pid, address: b'/usr/bin/true')
    monkeypatch.setattr(module, 'exec_vector', lambda pid, address: ['/usr/bin/true'] if address == 2 else rows)
    monkeypatch.setattr(module.os, 'readlink', lambda path: '/owned/original-cwd')
    monkeypatch.setattr(module._observation, 'process_identity', lambda pid: {'pid': pid})
    stops = []
    monkeypatch.setattr(module, 'ptrace', lambda *args, **kwargs: stops.append(args))
    value = module.Registers(rdi=1, rsi=2, rdx=3, orig_rax=59)
    trace.admit_exec(123, value)
    return trace, seen, stops, value


def test_legal_empty_name_and_equals_value_reach_exact_normal_resolver(monkeypatch):
    trace, seen, stops, value = invoke(monkeypatch, ['=empty-name', 'VALUE=before=after'], accept=True)
    assert seen == [(123, '/usr/bin/true', ['/usr/bin/true'],
                     {'': 'empty-name', 'VALUE': 'before=after'}, '/owned/original-cwd')]
    assert trace.records[-1]['accepted'] is True
    assert not trace.poison and not stops and value.orig_rax == 59


def test_empty_name_does_not_bypass_unknown_launch_refusal(monkeypatch):
    trace, seen, stops, value = invoke(monkeypatch, ['=empty-name'], accept=False)
    assert seen[0][3] == {'': 'empty-name'}
    assert trace.poison == ['unknown_or_drifted_exec'] and trace.denied == {123}
    assert trace.records[-1]['accepted'] is False
    assert stops == [(13, 123)] and value.orig_rax == (1 << 64) - 1


@pytest.mark.parametrize('rows', [['missing-separator'], ['=first', '=second'],
                                  ['VALUE=first', 'VALUE=second']])
def test_malformed_or_duplicate_names_still_refuse(monkeypatch, rows):
    with pytest.raises(RuntimeError, match='invalid or duplicate exec environment entry'):
        invoke(monkeypatch, rows, accept=True)
