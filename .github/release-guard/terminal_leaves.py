"""Original terminal redaction, credential transform and omission-default leaves."""
import ast
import base64
from pathlib import Path

from content_manifest import Refused
from launch_policy import source_unit,assignment,build_expected,admit_expected
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


def program(checkout,case):
    if case==RAW:
        unit=source_unit(checkout,TEST,PIN,(case.split('::')[1],))
        calls=[node for node in ast.walk(unit) if isinstance(node,ast.Dict) and any(isinstance(key,ast.Constant) and key.value=='args' for key in node.keys)]
        if len(calls)!=1:
            raise Refused('terminal original argument dictionary')
        args=ast.literal_eval(calls[0].values[calls[0].keys.index(next(key for key in calls[0].keys if isinstance(key,ast.Constant) and key.value=='args'))])
        return args[1],{'ZAI_API_KEY':'RAW_ACP_CREDENTIAL_79d0b1'}
    unit=source_unit(checkout,TEST,PIN,('test_real_terminal_create_excludes_raw_wrappers_and_preserves_transform',))
    names=ast.literal_eval(assignment(source_unit(checkout,POLICY,POLICY_PIN),'FINITE_CREDENTIAL_NAMES'))
    observed=(*names,*(f'UNRELATED_ALIAS_{i}' for i in range(len(names))),'HOME','TEMP','SSL_CERT_DIR','NO_PROXY','TMP')
    template=assignment(unit,'script')
    if (not isinstance(template,ast.JoinedStr) or len(template.values)!=3
            or not isinstance(template.values[1],ast.FormattedValue)
            or ast.unparse(template.values[1].value)!='observed_names' or template.values[1].conversion!=114):
        raise Refused('terminal sole original repr-only names template')
    body=template.values[0].value+repr(observed)+template.values[2].value
    wrapped=f'terminal-sentinel-1-{names[1].lower()}'
    return body,{'SSL_CERT_DIR':'MONKEY','NO_PROXY':'ordinary-equal-free-value','TMP':base64.urlsafe_b64encode(wrapped.encode()).decode()}


def proposal(host,actor,raw):
    host.root_only(actor)
    case=host.case
    if case not in CASES or raw['stdin'] is not None:
        raise Refused('terminal finite original leaf')
    checkout,owned=Path(host.meta['checkout']),Path(host.meta['owned'])
    workspace=Path(raw['cwd'])
    parent,info=acquire(str(workspace.parent),owned,case.split('::')[1].split('[')[0][:30],20000)
    generation=(str(parent),info.st_dev,info.st_ino)
    if workspace!=parent/'workspace' or workspace.resolve()!=workspace or host.fixture_roots.setdefault(('terminal',case),generation)!=generation:
        raise Refused('terminal original workspace generation')
    native=host.binding['entry']['path']
    if case in OPTIONAL:
        from ordinary_acp import TEST as ACP_TEST,PINS
        source_unit(checkout,ACP_TEST,PINS[ACP_TEST],('test_terminal_create_optional_nulls_use_omission_defaults',))
        from git_observer import image
        executable,pin,vector,role,env='/usr/bin/true',image('/usr/bin/true'),['/usr/bin/true'],'terminal-native',{}
    else:
        body,env=program(checkout,case)
        executable,pin,vector,role=native,host.binding['entry']['sha256'],[native,'-c',body],'fixed-inline'
    env={'PATH':host.meta_environment()['PATH'],**env}
    value=build_expected('terminal:original',case,executable,pin,tuple(vector),tuple(sorted(env.items())),str(workspace),
        'native' if case in OPTIONAL else 'python-command')
    translated=vector if case in OPTIONAL else [native,'-I','-S',*vector[1:]]
    return admit_expected(host,actor,raw,value,role,translated,fields={'merged_output':True})
