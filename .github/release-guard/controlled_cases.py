"""Closed controlled Python images and configuration variants, never native selection."""
from content_manifest import Refused, read_regular, refuse_if
from cohort_cases import CAMPAIGNS
from cohort_controller import CASES as CRASH
from controlled_owners import selection, GIT_CASES

SOURCE_UID=20000
STANDARD=('be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53','fake-app-server')
STARTUP_FAILURE='tests/test_experimental_startup_diagnostics.py::test_coordinator_persists_startup_and_separate_cleanup_failure'
RUNTIME_DRIFT='tests/test_controlled_runtime_binding.py::test_runtime_rechecked_at_each_child_boundary[adapter]'
WARNING='tests/test_controlled_acp_warnings.py::test_original_owner_warning_state_and_phase'
NOTIFICATION='tests/test_experimental_notifications.py::test_controlled_process_http_revocation_and_warning_privacy'
WARNING_REFUSALS=tuple('tests/test_controlled_acp_warnings.py::test_owned_warning_refusal_and_cleanup['+value+']'
    for value in ('late-cancel','malformed','unsupported','wrong-callback'))
NOTIFICATION_SIGNALS=(*(node+'['+phase+'-disabled]' for node in (WARNING,NOTIFICATION) for phase in ('before-send','parked')),
    *(node+'['+phase+'-'+state+']' for node in (WARNING,NOTIFICATION) for phase in ('before-send','parked') for state in ('connected','connecting','errored','unknown')))
NATIVE_MODULES=frozenset(('tests/test_controlled_acp_warnings.py','tests/test_experimental_notifications.py',
    'tests/test_experimental_admission_bounds.py','tests/test_experimental_startup_diagnostics.py'))
SERVERS=('external.with.dots','ordinary','quote"and\\slash','λ😀')
MODULES=frozenset(('tests/test_controlled_acp_cancel.py',
 'tests/test_controlled_acp_warnings.py',
 'tests/test_controlled_python_acp.py',
 'tests/test_experimental_ack_durability.py',
 'tests/test_experimental_admission_bounds.py',
 'tests/test_experimental_bridge_shutdown.py',
 'tests/test_experimental_config_frames.py',
 'tests/test_experimental_drain_retirement.py',
 'tests/test_experimental_finite_orders.py',
 'tests/test_experimental_finite_stops.py',
 'tests/test_experimental_first_halt.py',
 'tests/test_experimental_notifications.py',
 'tests/test_experimental_provider_config.py',
 'tests/test_experimental_startup_diagnostics.py'))
BACKENDS={'01d855c9d7ae2c91b6055a8e5eec1621714a1f6b84d3ae7bad1f190e70b19d3e': 'fake-app-server',
 '07c42f10dd54e85cad96ec6abe6b6337ad6c01ea43f278edadd4871cee66ca82': 'fake-app-server',
 '1dc876d29f45800ac9cad82037fdb41e9a584a0c17d39e4eb811edad6f0b8fb1': 'fake-app-server',
 '1e29b51c0c55d924bb45674a895c3b7e85f81707a6112307c7d38eaff54bbaa9': 'fake-app-server',
 '336b73302ee3922ea5d113bf774cdf8808528ac64b0a8f552c25777ad8c72c94': 'fake-app-server',
 '3a278c49bfca155cff6c1cceb4cf476c245a31439d6c4f55992ff3b13b583e9f': 'fake-app-server',
 '4cb170e8a739a112f1afd88623cb0c92e3f1da6fbcc6c505da4f1a9668394551': 'controlled.py',
 '4d0c740614480c5b7b01bfc89da997db653b7182acc4bfffcfb0d41d2930cfa8': 'fake-app-server',
 '518f21e20db36960dfe0f5f5e78f99489aeebebcc09b0e860a7bf57820b2d90e': 'fake-app-server',
 '5ec2d0a21fbe7dfb072bca8b477bd88bef52a6a28e779c8d79e274a942166d8c': 'fake-app-server',
 '5f4e60fbc40b71443b6608a1fbc6756e8e8638058c8ebba49408d4d60cd898ef': 'fake-app-server',
 '75696a35e28b1c5a27f293c525843ee1f2e20e85bbc7c8604d5f456202ae540a': 'fake-app-server',
 '86e9936c23bf9a5904628d87516f6fe8df671a98fd8d56b43928a236cb96ffdc': 'fake-app-server',
 '8c907cbdfaeb03b9b0cb47f68e3f9232752076d12ba010e663e35113fd63c0ad': 'fake-app-server',
 '927d91d15ae5cae209cace517f1183f1a54239b32ac188edd52085d5adbedb9e': 'fake-app-server',
 '9ced77b766af121e55339bca86d34971a76aa58fb31060e98cf338967b3f743c': 'fake-app-server',
 'a10467373bda96d6e702a03e70c96ce5562082b050df668ecbc7638b5b4eaf63': 'fake-app-server',
 'ac3c013153cb15b8bffe3faffe808508d123d0ca5128135de435797bfeefc1b6': 'fake-app-server',
 'af2899c0869c7742a041414460822794be2fa3f940d986321c983c872b36b70f': 'fake-app-server',
 'af9dfe00e21a60320bc23f431289fa908146acc2182185c7e973e606682e09e1': 'fake-app-server',
 'b31549518e4eaddd35c256a74bd823af86f900b8318ee4e2962465f155e62d55': 'fake-app-server',
 'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53': 'fake-app-server',
 'c38d9a2ee1052d238ed88ea4c346c79016744bec2a3a42ecc3cfbbe5819f7bf0': 'fake-app-server',
 'de67ffdb73a2e3275d06611496401cf0e785fe60b66ad114aa1b37d0264a369a': 'fake-app-server',
 'e96085bf9836febd1ffd58e8b2129fb50d2977b20ae00b416671565b308f9bc8': 'fake-app-server',
 'ef53f021de521fdcd51ea74a798cda9acaa88e9bfb7673bf35b751861f2865ca': 'fake-app-server',
 'f8dd8e17bf918032054912f64461eea4846e5a4a67adb68adc774be2591628c8': 'fake-app-server'}


def eligible(case):
    return type(case) is str and (selection(case) is not None or custody(case) and case not in GIT_CASES or case==RUNTIME_DRIFT)


def custody(case):
    return type(case) is str and (case in CAMPAIGNS or case in CRASH or case in GIT_CASES or '::' in case and case.split('::')[0] in MODULES)


def backend_path(case,root):
    return root.parent/'controlled.py' if case=='tests/test_experimental_bridge_shutdown.py::test_owned_teardown_completes_after_native_drain_failure' else root/'fake-app-server'


def acquire_backend(case,home):
    file=backend_path(case,home.parent)
    _,_,pin=read_regular(file,4*1024*1024,uid=SOURCE_UID,forbidden=0o6022)
    refuse_if(not eligible(case) or BACKENDS.get(pin)!=file.name
            or (case in (*CAMPAIGNS,*CRASH,RUNTIME_DRIFT) or selection(case) is not None) and pin!=STANDARD[0], 'unknown controlled backend bytes or layout')
    return pin


def select_entry(case,checkout,home,native,native_pin,raw,*,backend,relay,records):
    from controlled_startup import expected_entry
    from launch_policy import check_expected
    refuse_if(not eligible(case), 'controlled source module')
    pin=acquire_backend(case,home) if backend else None
    selected=selection(case)
    variants=(selected.variant,) if selected is not None else (0,) if case in (*CAMPAIGNS,*CRASH,RUNTIME_DRIFT) else range(4)
    if not backend:
        pairs=[row for row in records if row['cwd']==str(home) and row['role']=='backend']
        refuse_if(len(pairs)!=1 or type(pairs[0].get('controlled_variant')) is not int or pairs[0]['controlled_variant'] not in variants, 'controlled ACP configuration pair')
        variants=(pairs[0]['controlled_variant'],)
    for variant in variants:
        result=expected_entry(case,checkout,home,native,native_pin,backend=backend,relay=relay,variant=variant,backend_pin=pin)
        try:
            check_expected(raw,result[0])
        except Refused:
            continue
        return result,variant
    raise Refused('original launch operands differ from declaration')
