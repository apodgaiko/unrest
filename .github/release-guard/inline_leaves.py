"""Closed root-owned inline leaves with one constructor and admission path."""
from pathlib import Path

from content_manifest import Refused as Refused, refuse_if
from launch_policy import source_unit,build_expected,admit_expected,pinned_body
from owned_fixture import acquire,retain
from cleanup_launch import TEST,base_path

OWNER=20000
TERMINAL_TEST='tests/test_capability_policy.py'
RAW=TERMINAL_TEST+'::test_raw_acp_terminal_protocol_redacts_credential_values'
TRANSFORM=tuple(TERMINAL_TEST+'::test_real_terminal_create_excludes_raw_wrappers_and_preserves_transform['+profile+'-'+role+'-'+provider+']'
    for profile in ('safe','unsafe-development-unrestricted') for role in ('worker','validator','terminal_reviewer') for provider in ('claude','codex'))
OPTIONAL=tuple('tests/test_acp_runner.py::test_terminal_create_optional_nulls_use_omission_defaults[params'+str(i)+']' for i in range(2))
TERMINAL_CASES=(RAW,*TRANSFORM,*OPTIONAL)
PROGRAMS={RAW:('f4ce4c072ea2f9aaca39a3fdfbaac6fd245f9af013575da904056ef2114e60a0',{'ZAI_API_KEY':'RAW_ACP_CREDENTIAL_79d0b1'}),
    **dict.fromkeys(TRANSFORM,('52dfcc2a3a4a04e0db1943f3b43a2791d1c3c854d7fb73a05e28bc9c8f0e6295',
        {'SSL_CERT_DIR':'MONKEY','NO_PROXY':'ordinary-equal-free-value','TMP':'dGVybWluYWwtc2VudGluZWwtMS1hbnRocm9waWNfYXV0aF90b2tlbg=='}))}


READINESS_TEST='tests/test_acp_runner.py'
NAME='test_readiness_attributes_local_child_and_drains'
READINESS_CASES=tuple(READINESS_TEST+'::'+NAME+'['+mode+']' for mode in ('early_exit','never_ready','ready','cancel'))
PIN='558010a851595fece4c186cb30b717ff38dad4fa075705dbc316cfd8537910b4'

SESSION='tests/test_experimental_session.py'
SESSION_PIN='baca26ee3feb60d74d435becb950db24e8849aa16015cf15e1943cfbc0f3f9e3'
INLINE={READINESS_TEST+'::test_adapter_stderr_and_log_sink_redact_before_emission':(READINESS_TEST,PIN),
        **{SESSION+'::test_'+name:(SESSION,SESSION_PIN) for name in ('late_response_after_cancel_does_not_break_reader',
            'callback_tasks_are_awaited_during_cleanup','sigterm_ignoring_owned_process_is_killed_and_reaped')}}
READINESS_CASES=(*READINESS_CASES,*INLINE)
PROGRAM_PINS=dict(zip(READINESS_CASES,(
    'be24182e30a0033b24f7a71f29c7732f45f27a691b4b29d60bc408a39ac445b0',
    '2e51ded6174107c29ccf8864a0f231f824d5dcc308332438dacf272c4bf04780',
    '8b015d4f2a1a67a06e8ba14774c00ddf82cd8352e608a1b94af76477bb428ed0',
    '2e51ded6174107c29ccf8864a0f231f824d5dcc308332438dacf272c4bf04780',
    '727b2576800c55ac30ac1f785f3d24d830abd993752b20edc4920efb81795e13',
    'd874e36763cdcaf75828e4d010f8a6d39cdb8a4163b39806790c55caa77d813e',
    'e88dc8567953acc3ea76ea1f5a9b6db3d154a25bde3a4fa9c272e184e4355da2',
    'be4c6dff92704046fbff8c740bea609c045b3e0373a6903e8f1613d29b7043d7'),strict=True))

STREAM_CASES=tuple(READINESS_TEST+'::test_mcp_role_child_oversized_streams_are_bounded_and_singly_drained['+mode+']'
    for mode in ('worker','terminal-reviewer'))
LEASE='tests/test_experimental_lease.py::test_owned_ignoring_child_and_unknown_quarantine'
READINESS_CASES=(*READINESS_CASES,*STREAM_CASES,LEASE)
PROGRAM_PINS[LEASE]='f7616e6e7591ef2471038fa253ec0de2ce8d66d706c63b3a28754c84c406528a'
PROGRAM_PINS.update(dict.fromkeys(STREAM_CASES,'2e72c5f2a12366eb52edf0f0414ddbc2b2b24a539f202bff89417b23589f8ad2'))


SLEEP = 'import time; time.sleep(30)'
EXIT = "import sys; print('private-startup-body',file=sys.stderr); sys.exit(23)"
STARTUP = {TEST + f'::test_startup_failure_attribution_and_owned_cleanup[{variant}-{role}]':
           ('startup', variant, role) for variant in ('exit', 'deadline', 'cancel')
           for role in ('work', 'validate', 'terminal_reviewer')}
CLIENT = {TEST + '::test_client_cleanup_reaps_main_after_reader_failure': ('client', 'reader', None),
          **{TEST + f'::test_client_exhausts_terminals_pending_and_main[{variant}]':
             ('client', variant, None) for variant in ('False', 'True')}}
INFLIGHT = {TEST + f'::test_inflight_terminal_registration_before_inventory[{variant}]':
            ('inflight', variant, None) for variant in ('False', 'True')}
DECLARATIONS = {**STARTUP, **CLIENT, **INFLIGHT}


def declaration(case):
    refuse_if(type(case) is not str or case not in DECLARATIONS, 'cleanup inline finite case')
    return DECLARATIONS[case]


def body(case):
    family, variant, _ = declaration(case)
    return EXIT if family == 'startup' and variant == 'exit' else SLEEP


def child_count(case):
    family, variant, _ = declaration(case)
    return 1 if family == 'startup' or variant == 'reader' else 3


CASES=(*TERMINAL_CASES,*READINESS_CASES,*DECLARATIONS)


def proposal(host,actor,raw):
    host.root_only(actor)
    case=host.case
    refuse_if(case not in CASES or raw['stdin'] is not None, 'inline finite original leaf')
    checkout=Path(host.meta['checkout'])
    native=host.binding['entry']['path']
    executable,pin,kind=native,host.binding['entry']['sha256'],'python-command'
    cwd,env=host.meta['checkout'],{**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    role,maximum,inherited='fixed-inline',1,[]
    if case in DECLARATIONS:
        records=[row for row in host.intents.values() if row['case']==case]
        maximum=child_count(case)
        refuse_if(len(records)>=maximum, 'cleanup inline original child order')
        if any(not host.executed(row) for row in records):
            return None
        if case in INFLIGHT and len(records)==2:
            cwd,env=str(base_path(raw['cwd'],Path(host.meta['owned']))),{}
        code,role=body(case),'cleanup-inline'
        vector=(native,'-c',code)
    elif case in TERMINAL_CASES:
        workspace=Path(raw['cwd'])
        if case in OPTIONAL:
            refuse_if(workspace!=checkout, 'terminal optional-null original checkout cwd')
            from ordinary_acp import TEST as ACP_TEST,PINS
            source_unit(checkout,ACP_TEST,PINS[ACP_TEST],('test_terminal_create_optional_nulls_use_omission_defaults',))
            from git_policy import image
            executable,pin,kind,vector,role='/usr/bin/true',image('/usr/bin/true'),'native',('/usr/bin/true',),'terminal-native'
            env={}
        else:
            refuse_if(workspace.name!='workspace', 'terminal original workspace')
            owned=Path(host.meta['owned'])
            acquire(str(workspace),owned,OWNER)
            retain(host,workspace.parent,OWNER)
            body_pin,env=PROGRAMS[case]
            vector=(native,'-c',pinned_body(raw['argv'],body_pin))
        cwd,env=str(workspace),{'PATH':host.meta_environment()['PATH'],**env}
    else:
        code=pinned_body(raw['argv'],PROGRAM_PINS[case])
        vector=(native,'-c',code)
        if case==LEASE:
            cwd,env=str(retain(host,Path(raw['cwd']),OWNER)),{}
        if case in STREAM_CASES:
            from cleanup_launch import read_pipe
            base=retain(host,Path(raw['cwd']).parent,20000)
            cwd,env=str(base/'workspace'),{'PATH':host.meta_environment()['PATH']}
            if case==STREAM_CASES[0]:
                env['UNREST_NODE_ASSIGNMENT']='{"targets":["VAL-SEC-014"],"task_type":"work"}'
            inherited=[read_pipe(actor['birth'],raw['inventory_fd'])]
        if case==LEASE or case.endswith('::test_sigterm_ignoring_owned_process_is_killed_and_reaped'):
            role='session-inline'
    value=build_expected(case,executable,pin,vector,tuple(sorted(env.items())),cwd,kind)
    translated=list(vector) if kind=='native' else [native,'-I','-S',*vector[1:]]
    return admit_expected(host,actor,raw,value,role,translated,value.payload_sha256 if case in DECLARATIONS else None,
        maximum=maximum,inherited=inherited)
