"""Pure native-leaf join negatives; the four original Linux cases prove execution."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest

from finite import native_relative as native
import native_relative_custody as custody
import owned_multiprocess_authority as owned


def fixture():
    case = sorted(native.CASES)[0]
    registration = {'class': native.CLASS, 'python': False,
                    'source_binding': native.binding('/source')}
    options = {'shell': False, 'stdin': None, 'stdout': -3, 'stderr': -3,
               'universal_newlines': False, 'bufsize': 0}
    return registration, list(native.VECTOR), options, case


def test_original_four_cases_and_constructor_options():
    registration, vector, options, case = fixture()
    assert len(native.CASES) == 4
    native.validate(registration, vector, options, case, '/source')


@pytest.mark.parametrize('mutation', ['class', 'python', 'source', 'line', 'pin', 'function',
                                      'argv', 'duration', 'case', 'cwd', 'env', 'shell',
                                      'stdout', 'stderr', 'stdin', 'descriptor', 'executable'])
def test_constructor_refuses_foreign_context(mutation):
    registration, vector, options, case = fixture()
    if mutation in {'class', 'python'}:
        registration[mutation] = 'foreign'
    elif mutation in {'source', 'line', 'pin', 'function'}:
        key = {'source': 'path', 'pin': 'sha256'}.get(mutation, mutation)
        registration['source_binding'][key] = 'foreign'
    elif mutation == 'argv':
        vector[0] = '/bin/sh'
    elif mutation == 'duration':
        vector[1] = '0'
    elif mutation == 'case':
        case = case + '-foreign'
    elif mutation in {'cwd', 'env', 'descriptor', 'executable'}:
        options[{'descriptor': 'pass_fds'}.get(mutation, mutation)] = 'foreign'
    else:
        options[mutation] = 'foreign'
    with pytest.raises(RuntimeError, match='original_fixture'):
        native.validate(registration, vector, options, case, '/source')


def join():
    registration, vector, _, case = fixture()
    registration.update(case=case, token='token', owner_pid=20)
    environment = {'PATH': 'literal format template', 'LANG': 'C'}
    digest = hashlib.sha256(json.dumps(vector).encode()).hexdigest()
    facts = {'cwd': '/source', 'identity': [1, 2, 3], 'mount': {'options': ['ro']},
             'searchable': None, 'readonly': True}
    selected = {'bootstrap_sha256': None, 'registration': registration,
                'cwd': '/source', 'token': 'token', 'owner_pid': 20,
                'transformed_argv_sha256': digest,
                'environment_sha256': hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()}
    row = {'class': native.CLASS, 'source_binding': native.binding('/source'),
           'case': case, 'token': 'token', 'owner_pid': 20, 'original_cwd': None,
           'constructor_cwd': '.', 'argv_sha256': digest,
           'parent_view': {**deepcopy(facts), 'searchable': True}}
    return selected, [row], vector, environment, '/source', '/bin/sleep', '/source', facts


def test_stopped_child_joins_exact_existing_launch_without_environment_rewriting():
    custody.validate(*join())


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'token', 'owner_pid', 'class',
                                      'case', 'source_binding', 'argv_sha256', 'original_cwd',
                                      'constructor_cwd', 'identity', 'mount', 'readonly',
                                      'vector', 'environment', 'cwd', 'path', 'bootstrap'])
def test_stopped_child_refuses_each_changed_custody_link(mutation):
    selected, rows, vector, env, cwd, path, checkout, facts = join()
    if mutation == 'missing':
        rows.clear()
    elif mutation == 'duplicate':
        rows.append(deepcopy(rows[0]))
    elif mutation in {'identity', 'mount', 'readonly'}:
        facts[mutation] = 'foreign'
    elif mutation == 'vector':
        vector[0] = '/bin/sh'
    elif mutation == 'environment':
        env['PATH'] = 'foreign'
    elif mutation == 'cwd':
        cwd = '/work'
    elif mutation == 'path':
        path = '/usr/bin/sleep'
    elif mutation == 'bootstrap':
        selected['bootstrap_sha256'] = 'foreign'
    else:
        rows[0][mutation] = 'foreign'
    with pytest.raises(RuntimeError):
        custody.validate(selected, rows, vector, env, cwd, path, checkout, facts)


@pytest.mark.parametrize('result', [None, True, 'source-bootstrap'])
def test_original_authority_acceptance_and_nonselection_are_not_overridden(monkeypatch, result):
    authority = object.__new__(owned.SourceAuthority)
    def original(*args):
        return result
    monkeypatch.setattr(owned.OriginalSourceAuthority, 'resolve', original)
    assert authority.resolve(None, 1, 'path', [], {}, 'cwd') is result


def test_unknown_native_leaf_does_not_gain_a_fallback():
    authority = SimpleNamespace(bound={42: {'registration': {'class': 'foreign'}}})
    assert custody.resolve(authority, None, 42, '/bin/sleep', native.VECTOR, {}, '/source') is False


def test_exact_test_selection_never_certifies_full():
    from primary_policy import TEST_FORMAT_CASES, plan
    from primary_source_inputs import test_plan as make_test_plan
    from test_primary_source_entry import inputs, COMMAND
    text, source = inputs()
    assert set(TEST_FORMAT_CASES) == native.CASES
    script = (COMMAND + ' ' + ' '.join(TEST_FORMAT_CASES)).encode()
    value = make_test_plan(script, text, 'TEST-positive')
    assert value is not None
    for changed in [script, script + b' --maxfail=1']:
        with pytest.raises(RuntimeError):
            plan(changed, text, source)
    with pytest.raises(RuntimeError):
        make_test_plan((COMMAND + ' ' + TEST_FORMAT_CASES[0]).encode(), text, 'TEST-positive')


@pytest.mark.parametrize('selected_class', [owned.SourceAuthority, owned.DependencySourceAuthority])
@pytest.mark.parametrize('original_result', [None, True, False, 'source-bootstrap'])
def test_native_adapter_calls_original_first_and_only_after_explicit_nonacceptance(monkeypatch, selected_class, original_result):
    authority = object.__new__(selected_class)
    calls = []
    def original(*args):
        calls.append(('original', args))
        return original_result
    def fallback(*args):
        calls.append(('fallback', args))
        return False
    monkeypatch.setattr(owned.OriginalSourceAuthority, 'resolve', original)
    monkeypatch.setattr(custody, 'resolve', fallback)
    result = authority.resolve('trace', 42, '/bin/sleep', native.VECTOR, {}, '/source')
    assert [kind for kind, _ in calls] == (['original', 'fallback'] if original_result is False else ['original'])
    assert result is original_result
    assert all(args == (authority, 'trace', 42, '/bin/sleep', native.VECTOR, {}, '/source') for _, args in calls)


def test_original_resolver_exception_cannot_reach_native_fallback(monkeypatch):
    authority = object.__new__(owned.DependencySourceAuthority)
    cause = RuntimeError('original custody refused')
    def original(*args):
        raise cause
    def fallback(*args):
        pytest.fail('original refusal was intercepted')
    monkeypatch.setattr(owned.OriginalSourceAuthority, 'resolve', original)
    monkeypatch.setattr(custody, 'resolve', fallback)
    with pytest.raises(RuntimeError) as caught:
        authority.resolve('trace', 42, '/bin/sleep', native.VECTOR, {}, '/source')
    assert caught.value is cause


@pytest.mark.parametrize('line', sorted(native.SITES))
def test_seven_closed_original_call_sites_do_not_share_case_or_stdio_authority(line):
    site = native.SITES[line]
    registration = {'class': 'source-cohort2:' + native.SOURCE + ':' + str(line),
                    'python': False, 'source_binding': native.binding('/source', line)}
    options = {'shell': False, 'stdin': None, 'stdout': site['stdio'], 'stderr': site['stdio'],
               'universal_newlines': False, 'bufsize': 0}
    for case in site['cases']:
        native.validate(registration, native.VECTOR, options, case, '/source')
    for case in native.ALL_CASES - set(site['cases']):
        with pytest.raises(RuntimeError):
            native.validate(registration, native.VECTOR, options, case, '/source')
    with pytest.raises(RuntimeError):
        native.validate(registration, native.VECTOR, {**options, 'stdout': -1 if site['stdio'] == -3 else -3}, site['cases'][0], '/source')


def test_seven_site_diagnosis_is_closed_and_noncertifying():
    from primary_policy import TEST_NATIVE_SLEEP_CASES, plan
    from primary_source_inputs import test_plan as make_test_plan
    from test_primary_source_entry import inputs, COMMAND
    assert set(native.SITES) == {544, 632, 1080, 1383, 1843, 2209, 2268}
    assert len(native.ALL_CASES) == 17
    assert set(TEST_NATIVE_SLEEP_CASES) == native.ALL_CASES
    text, source = inputs()
    script = (COMMAND + ' ' + ' '.join(TEST_NATIVE_SLEEP_CASES)).encode()
    value = make_test_plan(script, text, 'TEST-positive')
    assert value['source_checkpoint_ready'] is False and value['selected_carrier'] is None
    with pytest.raises(RuntimeError):
        plan(script, text, source)
    for changed in [script + b' --maxfail=1', (COMMAND + ' ' + ' '.join(TEST_NATIVE_SLEEP_CASES[:-1])).encode()]:
        with pytest.raises(RuntimeError):
            make_test_plan(changed, text, 'TEST-positive')
