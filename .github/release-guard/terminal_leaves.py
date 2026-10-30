"""Original terminal redaction, credential transform and omission-default leaves."""
from pathlib import Path

from content_manifest import Refused
from launch_policy import source_unit,build_expected,admit_expected,pinned_body
from owned_fixture import acquire

TEST='tests/test_capability_policy.py'
PIN='ed83ec28c4830354cd4ab0876d6832a0187d211982964d2cf80f449992b46bb6'
RAW=TEST+'::test_raw_acp_terminal_protocol_redacts_credential_values'
TRANSFORM=tuple(TEST+'::test_real_terminal_create_excludes_raw_wrappers_and_preserves_transform['+profile+'-'+role+'-'+provider+']'
    for profile in ('safe','unsafe-development-unrestricted') for role in ('worker','validator','terminal_reviewer') for provider in ('claude','codex'))
OPTIONAL=tuple('tests/test_acp_runner.py::test_terminal_create_optional_nulls_use_omission_defaults[params'+str(i)+']' for i in range(2))
CASES=(RAW,*TRANSFORM,*OPTIONAL)
POLICY='src/unrest_harness/capability_policy.py'
POLICY_PIN='0aaa3eca3a1b891bcf7458832aeed92768489826fda23320ab000ce3d1df3c30'
PROGRAMS={RAW:('f4ce4c072ea2f9aaca39a3fdfbaac6fd245f9af013575da904056ef2114e60a0',{'ZAI_API_KEY':'RAW_ACP_CREDENTIAL_79d0b1'}),
    **dict.fromkeys(TRANSFORM,('52dfcc2a3a4a04e0db1943f3b43a2791d1c3c854d7fb73a05e28bc9c8f0e6295',
        {'SSL_CERT_DIR':'MONKEY','NO_PROXY':'ordinary-equal-free-value','TMP':'dGVybWluYWwtc2VudGluZWwtMS1hbnRocm9waWNfYXV0aF90b2tlbg=='}))}


def proposal(host,actor,raw):
    host.root_only(actor)
    case=host.case
    if case not in CASES or raw['stdin'] is not None:
        raise Refused('terminal finite original leaf')
    checkout,owned=Path(host.meta['checkout']),Path(host.meta['owned'])
    workspace=Path(raw['cwd'])
    if case in OPTIONAL:
        if workspace!=checkout:
            raise Refused('terminal optional-null original checkout cwd')
    else:
        parent,info=acquire(str(workspace.parent),owned,case.split('::')[1].split('[')[0][:30],20000)
        generation=(str(parent),info.st_dev,info.st_ino)
        if workspace!=parent/'workspace' or workspace.resolve()!=workspace or host.fixture_roots.setdefault(('terminal',case),generation)!=generation:
            raise Refused('terminal original workspace generation')
    native=host.binding['entry']['path']
    if case in OPTIONAL:
        from ordinary_acp import TEST as ACP_TEST,PINS
        source_unit(checkout,ACP_TEST,PINS[ACP_TEST],('test_terminal_create_optional_nulls_use_omission_defaults',))
        from git_policy import image
        executable,pin,vector,role,env='/usr/bin/true',image('/usr/bin/true'),['/usr/bin/true'],'terminal-native',{}
    else:
        body_pin,env=PROGRAMS[case]
        body=pinned_body(raw['argv'],body_pin)
        executable,pin,vector,role=native,host.binding['entry']['sha256'],[native,'-c',body],'fixed-inline'
    env={'PATH':host.meta_environment()['PATH'],**env}
    value=build_expected(case,executable,pin,tuple(vector),tuple(sorted(env.items())),str(workspace),
        'native' if case in OPTIONAL else 'python-command')
    translated=vector if case in OPTIONAL else [native,'-I','-S',*vector[1:]]
    return admit_expected(host,actor,raw,value,role,translated)
