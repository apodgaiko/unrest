"""Four original local-readiness leaves; connect permission never grants payload."""
from content_manifest import Refused
from launch_policy import build_expected,admit_expected,pinned_body

TEST='tests/test_acp_runner.py'
NAME='test_readiness_attributes_local_child_and_drains'
CASES=tuple(TEST+'::'+NAME+'['+mode+']' for mode in ('early_exit','never_ready','ready','cancel'))
READY=CASES[2]
PIN='558010a851595fece4c186cb30b717ff38dad4fa075705dbc316cfd8537910b4'

SESSION='tests/test_experimental_session.py'
SESSION_PIN='baca26ee3feb60d74d435becb950db24e8849aa16015cf15e1943cfbc0f3f9e3'
INLINE={TEST+'::test_adapter_stderr_and_log_sink_redact_before_emission':(TEST,PIN),
        **{SESSION+'::test_'+name:(SESSION,SESSION_PIN) for name in ('late_response_after_cancel_does_not_break_reader',
            'callback_tasks_are_awaited_during_cleanup','sigterm_ignoring_owned_process_is_killed_and_reaped')}}
CASES=(*CASES,*INLINE)
PROGRAM_PINS=dict(zip(CASES,(
    'be24182e30a0033b24f7a71f29c7732f45f27a691b4b29d60bc408a39ac445b0',
    '2e51ded6174107c29ccf8864a0f231f824d5dcc308332438dacf272c4bf04780',
    '8b015d4f2a1a67a06e8ba14774c00ddf82cd8352e608a1b94af76477bb428ed0',
    '2e51ded6174107c29ccf8864a0f231f824d5dcc308332438dacf272c4bf04780',
    '727b2576800c55ac30ac1f785f3d24d830abd993752b20edc4920efb81795e13',
    'd874e36763cdcaf75828e4d010f8a6d39cdb8a4163b39806790c55caa77d813e',
    'e88dc8567953acc3ea76ea1f5a9b6db3d154a25bde3a4fa9c272e184e4355da2',
    'be4c6dff92704046fbff8c740bea609c045b3e0373a6903e8f1613d29b7043d7'),strict=True))


def proposal(host,actor,raw):
    host.root_only(actor)
    if host.case not in CASES or raw['stdin'] is not None:
        raise Refused('readiness original child scope')
    body=pinned_body(raw['argv'],PROGRAM_PINS[host.case])
    native=host.binding['entry']['path']
    env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    value=build_expected(host.case,native,host.binding['entry']['sha256'],
        (native,'-c',body),tuple(sorted(env.items())),host.meta['checkout'],'python-command')
    return admit_expected(host,actor,raw,value,'session-inline' if host.case.endswith('::test_sigterm_ignoring_owned_process_is_killed_and_reaped') else 'fixed-inline',[native,'-I','-S','-c',body])
