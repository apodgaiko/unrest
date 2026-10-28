"""Closed original inline cleanup cases; declarations alone grant no execution."""
from __future__ import annotations


from content_manifest import Refused
from cleanup_launch import TEST

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
NO_LAUNCH = tuple(TEST + f'::test_response_correlation_keeps_numeric_identity[{variant}]'
                  for variant in ('1_0', '1_1', 'None', 'True', '1.0', 'rid5', 'rid6'))
DECLARATIONS = {**STARTUP, **CLIENT, **INFLIGHT}
CASES = (*DECLARATIONS, *NO_LAUNCH)
CLIENT_CASES = (*CLIENT, *INFLIGHT)


def declaration(case):
    if type(case) is not str or case not in CASES:
        raise Refused('cleanup inline finite case')
    return DECLARATIONS.get(case, ('no-launch', None, None))


def body(case):
    family, variant, _ = declaration(case)
    if family == 'no-launch':
        raise Refused('cleanup numeric case has no process authority')
    return EXIT if family == 'startup' and variant == 'exit' else SLEEP


def child_count(case):
    family, variant, _ = declaration(case)
    return 0 if family == 'no-launch' else 1 if family == 'startup' or variant == 'reader' else 3


def source_site(case, terminal=False):
    family, variant, _ = declaration(case)
    if terminal:
        if family != 'inflight':
            raise Refused('cleanup inline terminal outside inflight case')
        return 1034
    if family == 'no-launch':
        raise Refused('cleanup numeric case has no process authority')
    return 61 if family == 'startup' else 429 if family == 'inflight' else 269 if variant == 'reader' else 299


def scheduling_site(case):
    family, variant, _ = declaration(case)
    return 92 if family == 'startup' else 478 if family == 'inflight' else 321 if family == 'client' and variant != 'reader' else None


def expected(case, native, native_pin, checkout, root_environment, *, base=None, terminal=False):
    from launch_policy import Rule, render
    family, _, _ = declaration(case)
    site = source_site(case, terminal)
    if terminal:
        if base is None:
            raise Refused('cleanup inline missing owned fixture')
        cwd, environment = str(base), {}
        owner = 'src/unrest_harness/acp_runner.py:ACPClient._handle_terminal_create'
    else:
        cwd = str(checkout)
        environment = {**root_environment, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'}
        owner = TEST + ':' + ('test_startup_failure_attribution_and_owned_cleanup.<locals>.start'
            if family == 'startup' else case.split('::')[1].split('[')[0])
    rule = Rule('cleanup-inline:' + ('terminal' if terminal else 'initial'), owner, (case,),
                native, native_pin, (native, '-c', body(case)), tuple(sorted(environment.items())),
                cwd, 'python-command', None)
    return render(rule, case, owner, {}, {}), site
