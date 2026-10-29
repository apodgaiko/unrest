"""Finite controlled backend postimages from the unchanged source cases.

Each row binds its complete backend bytes; launch authority still requires the
original controlled owner, runtime, role, constructor and owned pair generation.
Configured fixtures are admitted separately and are absent from this catalogue.
"""
from __future__ import annotations

from content_manifest import Refused
from cohort_cases import CAMPAIGNS
from cohort_controller import CASES as CRASH

STARTUP_FAILURE = 'tests/test_experimental_startup_diagnostics.py::test_coordinator_persists_startup_and_separate_cleanup_failure'


INITIALIZED_HTTP = 'tests/test_experimental_startup_diagnostics.py::test_initialized_owner_has_no_http_mutation_authority'
STANDARD = ('be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53', 'fake-app-server')
DRAIN = ('1dc876d29f45800ac9cad82037fdb41e9a584a0c17d39e4eb811edad6f0b8fb1', 'fake-app-server')
DISABLED = ('07c42f10dd54e85cad96ec6abe6b6337ad6c01ea43f278edadd4871cee66ca82', 'fake-app-server')
STARTUP_DISABLED = ('e96085bf9836febd1ffd58e8b2129fb50d2977b20ae00b416671565b308f9bc8', 'fake-app-server')
WARNING = 'tests/test_controlled_acp_warnings.py::test_original_owner_warning_state_and_phase'
NOTIFICATION = 'tests/test_experimental_notifications.py::test_controlled_process_http_revocation_and_warning_privacy'


def entries(node, parameters, backend=STANDARD):
    return {node + '[' + parameter + ']': backend for parameter in parameters}


ROOT_HTTP = {
    **{node + '[' + phase + '-disabled]': STARTUP_DISABLED if phase=='startup' else DISABLED
       for node in (WARNING, NOTIFICATION) for phase in ('before-send','parked','startup')},
    INITIALIZED_HTTP: STANDARD,
}
LARGE = {
    'drift': 'ac3c013153cb15b8bffe3faffe808508d123d0ca5128135de435797bfeefc1b6',
    'eof': '86e9936c23bf9a5904628d87516f6fe8df671a98fd8d56b43928a236cb96ffdc',
    'error': 'af9dfe00e21a60320bc23f431289fa908146acc2182185c7e973e606682e09e1',
    'ready': '518f21e20db36960dfe0f5f5e78f99489aeebebcc09b0e860a7bf57820b2d90e',
}
FRESH = {
    INITIALIZED_HTTP: STANDARD,
    **{f'tests/test_controlled_acp_warnings.py::test_original_private_large_config[{name}]': (pin,'fake-app-server')
       for name,pin in LARGE.items()},
    'tests/test_controlled_python_acp.py::test_programmatic_private_preflight': STANDARD,
    **{f'tests/test_experimental_config_frames.py::test_pinned_adapter_large_private_and_adapter_replies[{name}]': (pin,'fake-app-server')
       for name,pin in LARGE.items()},
    **entries('tests/test_experimental_startup_diagnostics.py::test_bridge_failure_preserved_through_owned_close',
              ('permission','refusal','timeout')),
    'tests/test_experimental_startup_diagnostics.py::test_initialization_probe_real_controlled_path_no_prompt': STANDARD,
}
ADMISSION = {
    'tests/test_experimental_admission_bounds.py::test_owner_adapter_bound_privacy_first_failure_cleanup_no_send[aggregate_bound]': ('c38d9a2ee1052d238ed88ea4c346c79016744bec2a3a42ecc3cfbbe5819f7bf0', 'fake-app-server'),
    'tests/test_experimental_admission_bounds.py::test_owner_adapter_bound_privacy_first_failure_cleanup_no_send[eof]': ('4d0c740614480c5b7b01bfc89da997db653b7182acc4bfffcfb0d41d2930cfa8', 'fake-app-server'),
    'tests/test_experimental_admission_bounds.py::test_owner_adapter_bound_privacy_first_failure_cleanup_no_send[frame_bound]': ('336b73302ee3922ea5d113bf774cdf8808528ac64b0a8f552c25777ad8c72c94', 'fake-app-server'),
    'tests/test_experimental_admission_bounds.py::test_owner_adapter_bound_privacy_first_failure_cleanup_no_send[frame_count_bound]': ('75696a35e28b1c5a27f293c525843ee1f2e20e85bbc7c8604d5f456202ae540a', 'fake-app-server'),
    'tests/test_experimental_admission_bounds.py::test_owner_adapter_bound_privacy_first_failure_cleanup_no_send[reader_limit]': ('5ec2d0a21fbe7dfb072bca8b477bd88bef52a6a28e779c8d79e274a942166d8c', 'fake-app-server'),
    'tests/test_experimental_admission_bounds.py::test_owner_adapter_bound_privacy_first_failure_cleanup_no_send[unterminated_frame]': ('5f4e60fbc40b71443b6608a1fbc6756e8e8638058c8ebba49408d4d60cd898ef', 'fake-app-server'),
}
WARNING_REFUSALS = {
    'tests/test_controlled_acp_warnings.py::test_owned_warning_refusal_and_cleanup[late-cancel]': ('ef53f021de521fdcd51ea74a798cda9acaa88e9bfb7673bf35b751861f2865ca', 'fake-app-server'),
    'tests/test_controlled_acp_warnings.py::test_owned_warning_refusal_and_cleanup[malformed]': ('927d91d15ae5cae209cace517f1183f1a54239b32ac188edd52085d5adbedb9e', 'fake-app-server'),
    'tests/test_controlled_acp_warnings.py::test_owned_warning_refusal_and_cleanup[unsupported]': ('1e29b51c0c55d924bb45674a895c3b7e85f81707a6112307c7d38eaff54bbaa9', 'fake-app-server'),
    'tests/test_controlled_acp_warnings.py::test_owned_warning_refusal_and_cleanup[wrong-callback]': ('ef53f021de521fdcd51ea74a798cda9acaa88e9bfb7673bf35b751861f2865ca', 'fake-app-server'),
}
STARTUP_PINS = {
    'connected': 'de67ffdb73a2e3275d06611496401cf0e785fe60b66ad114aa1b37d0264a369a',
    'connecting': 'af2899c0869c7742a041414460822794be2fa3f940d986321c983c872b36b70f',
    'errored': 'b31549518e4eaddd35c256a74bd823af86f900b8318ee4e2962465f155e62d55',
    'unknown': 'f8dd8e17bf918032054912f64461eea4846e5a4a67adb68adc774be2591628c8',
}
NOTIFICATION_STARTUP = {node + '[startup-' + state + ']': (pin,'fake-app-server')
                        for node in (WARNING,NOTIFICATION) for state,pin in STARTUP_PINS.items()}
SIGNAL_PINS = {
    'connected': '8c907cbdfaeb03b9b0cb47f68e3f9232752076d12ba010e663e35113fd63c0ad',
    'connecting': '9ced77b766af121e55339bca86d34971a76aa58fb31060e98cf338967b3f743c',
    'errored': '3a278c49bfca155cff6c1cceb4cf476c245a31439d6c4f55992ff3b13b583e9f',
    'unknown': '01d855c9d7ae2c91b6055a8e5eec1621714a1f6b84d3ae7bad1f190e70b19d3e',
}
NOTIFICATION_SIGNALS = {
    **{node + '[' + phase + '-disabled]': DISABLED
       for node in (WARNING,NOTIFICATION) for phase in ('before-send','parked')},
    **{node + '[' + phase + '-' + state + ']': (pin,'fake-app-server')
       for node in (WARNING,NOTIFICATION) for phase in ('before-send','parked') for state,pin in SIGNAL_PINS.items()},
}
POPULATED = {
    **{case: backend for case,backend in ROOT_HTTP.items() if case!=INITIALIZED_HTTP},
    **NOTIFICATION_SIGNALS, **NOTIFICATION_STARTUP, **WARNING_REFUSALS, **ADMISSION,
    **entries('tests/test_controlled_acp_warnings.py::test_original_private_configuration',
              (f'{skills}-{servers}' for skills in (False,True) for servers in (False,True))),
    **entries('tests/test_experimental_provider_config.py::test_startup_and_thread_controls_through_actual_owned_adapter',
              (f'{skills}-{servers}' for skills in (False,True) for servers in (False,True))),
}
CASES = {
    **dict.fromkeys((*CAMPAIGNS,*CRASH), STANDARD),
    **POPULATED, **FRESH,
    STARTUP_FAILURE: STANDARD,
    'tests/test_controlled_acp_cancel.py::test_owned_cancel_wire_and_cleanup[pending]':
        ('a10467373bda96d6e702a03e70c96ce5562082b050df668ecbc7638b5b4eaf63','fake-app-server'),
    **entries('tests/test_experimental_ack_durability.py::test_ack_durability',
              (f'{partial}-{status}-{failure}-{operation}' for partial in (False,True)
               for status,failure in ((-1,None),(0,None),(0,'fsync'),(0,'write'),(1,None))
               for operation in ('fsync','write')), DRAIN),
    'tests/test_experimental_bridge_shutdown.py::test_owned_teardown_completes_after_native_drain_failure':
        ('4cb170e8a739a112f1afd88623cb0c92e3f1da6fbcc6c505da4f1a9668394551','controlled.py'),
    **entries('tests/test_experimental_drain_retirement.py::test_original_stop_and_retired_delivery',
              ('original-unchanged','retired-delivery'), DRAIN),
    'tests/test_experimental_drain_retirement.py::test_prior_failure_kept_while_unaffected_sent_sibling_drains': DRAIN,
    **entries('tests/test_experimental_finite_orders.py::test_actual_capacity_and_parking',
              (f'{capacity}-{count}' for capacity in (2,4) for count in (1,2,3,4,8)), DRAIN),
    **entries('tests/test_experimental_finite_orders.py::test_actual_simultaneous_completion_batches',
              (f'validators{v}-workers{w}' for v in (0,1) for w in (0,1)), DRAIN),
    **entries('tests/test_experimental_finite_orders.py::test_script_order_boundaries',
              (f'{order}-{scripts}' for order in ('alternating-first','alternating-second','first','second')
               for scripts in ('PP','RC','RP','RR')), DRAIN),
    **entries('tests/test_experimental_finite_stops.py::test_actual_stop_event_permutations', (
        'completion-expiry-stop',
        'completion-stop-expiry',
        'expiry-completion-stop',
        'expiry-stop-completion',
        'sibling-fail-sibling-pass-stop',
        'sibling-fail-stop-sibling-pass',
        'sibling-pass-sibling-fail-stop',
        'sibling-pass-stop-sibling-fail',
        'stop-completion-expiry',
        'stop-expiry-completion',
        'stop-sibling-fail-sibling-pass',
        'stop-sibling-pass-sibling-fail',
    ), DRAIN),
    **entries('tests/test_experimental_first_halt.py::test_first_owned_halt', (
        'campaign-expiry','closed','cutoff','episode-expiry','fsync',
        'persistent-fsync','persistent-write','unrelated-halt','write'), DRAIN),
    **entries('tests/test_experimental_first_halt.py::test_other_owned_journal_halts',
              (f'{operation}-{boundary}' for operation in ('fsync','write')
               for boundary in ('reserve','send','session_identity')), DRAIN),
    **entries('tests/test_controlled_python_acp.py::test_cancel_at_actual_boundary',
              ('backend_registered','adapter_registered','auth','forwarding')),
    **entries('tests/test_controlled_python_acp.py::test_actual_registration',
              (f'{phase}-{count}' for phase in ('delayed','late') for count in (1,2))),
    'tests/test_controlled_python_acp.py::test_single_c1_fixed_timing_protocol_witness': STANDARD,
}

SERVERS = ('external.with.dots', 'ordinary', 'quote"and\\slash', 'λ😀')


def configuration_items(case, home):
    if case not in POPULATED:
        return (), ()
    context = home.parent.parent.parent
    skills = (str(context/'subscription/skills/example/SKILL.md'),) if case.split('[')[1].startswith('True-') else ()
    return SERVERS, skills


def configured(case):
    if type(case) is not str:
        raise Refused('controlled configuration case type')
    from bootstrap_cases import declaration
    return case in (*FRESH,*POPULATED) if case in CASES else declaration(case).configured


def backend(case):
    if type(case) is not str or case not in CASES:
        raise Refused('controlled finite source case')
    return CASES[case]


def backend_path(case, root):
    _, filename = backend(case)
    return (root.parent if filename == 'controlled.py' else root) / filename
