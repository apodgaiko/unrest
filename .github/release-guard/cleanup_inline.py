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
    return 53 if family == 'startup' else 421 if family == 'inflight' else 261 if variant == 'reader' else 291


def scheduling_site(case):
    family, variant, _ = declaration(case)
    return 84 if family == 'startup' else 470 if family == 'inflight' else 313 if family == 'client' and variant != 'reader' else None


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


def options(case, local, *, terminal=False):
    """Validate only primitive constructor fields; values do not select a case."""
    family, _, _ = declaration(case)
    from source_owner import _namespace
    local = _namespace(local)
    kw = _namespace(local.get('kwds'))
    for name in ('stdout', 'limit'):
        if type(local.get(name)) is not int:
            raise Refused('cleanup inline constructor primitives')
    if terminal:
        if (family != 'inflight' or set(kw) != {'cwd', 'env'} or type(kw['cwd']) is not str
                or type(kw['env']) is not dict or dict.__len__(kw['env']) != 0
                or local.get('stdin') is not None or type(local.get('stderr')) is not int
                or local['stderr'] != -2 or local['stdout'] != -1 or local['limit'] != 8 * 1024 * 1024):
            raise Refused('cleanup inline terminal options')
    elif (kw or local['stdout'] != -1 or local['limit'] != 65536
            or family == 'startup' and (local.get('stdin') is not None
                or type(local.get('stderr')) is not int or local['stderr'] != -1)
            or family != 'startup' and (type(local.get('stdin')) is not int
                or local['stdin'] != -1 or local.get('stderr') is not None)):
        raise Refused('cleanup inline initial options')
