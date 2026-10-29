"""Original provider-free measurement source fixtures; no benchmark authority."""
from pathlib import Path
from content_manifest import Refused
from launch_policy import source_unit,build_expected
from git_commands import Command

TEST='tests/test_measurement.py'
PIN='d850dcaf77c4b4ebd08efa87089cbc7b59762d5eb8d7fd0b673a9e043bc3e97f'
SYNTHETIC=('test_successful_exact_protocol_publishes_sanitized_recomputable_bundle',
    *(f'test_oracle_cache_and_cost_fail_closed[provider{index}-invalid]' for index in range(3)),
    'test_noise_over_fifteen_percent_is_inconclusive','test_unknown_reported_cost_is_not_collapsed_to_zero',
    'test_publication_rejects_unknown_or_private_fields_and_preserves_existing')
NAMES=(*SYNTHETIC,'test_evolution_cases_use_real_public_state_machine_and_cold_state',
    'test_project_cases_use_real_run_control_and_nested_acp','test_confirmation_and_protocol_drift_do_not_invoke_provider',
    'test_product_digest_excludes_only_results')
CASES=tuple(TEST+'::'+name for name in NAMES)


def proposal(host,actor,raw):
    host.root_only(actor)
    checkout=Path(host.meta['checkout'])
    source_unit(checkout,TEST,PIN)
    argv=raw['argv']
    arguments=tuple(argv[1:])
    if raw['executable']!='/usr/bin/git' or argv[0]!='git' or raw['stdin'] is not None or arguments not in (
            ('init','-q'),('add','.'),('ls-files','-z','--stage')):
        raise Refused('measurement original source Git command')
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    if arguments==('ls-files','-z','--stage') and host.case.split('::')[1] in SYNTHETIC:
        command=host.binding['entry']['path']+' '+str(checkout/'tests/mock_measurement_acp.py')
        environment.update(UNREST_WORKER_ACP_COMMAND=command,UNREST_VALIDATOR_ACP_COMMAND=command)
    if raw['environment']!=environment:
        raise Refused('measurement original Git environment')
    from git_observer import image
    value=Command(tuple(argv),raw['cwd'])
    expected=build_expected('measurement:git',host.case,'/usr/bin/git',image(),value.argv,
        tuple(sorted(environment.items())),value.cwd,'native')
    answer=host.git.launch(actor,'init' if arguments[0]=='init' else 'measurement-command',value.cwd,value,expected,['/usr/bin/git',*argv[1:]])
    return None if answer is None else {**answer,'translated':['/usr/bin/git',*argv[1:]],'rule':expected.rule}
