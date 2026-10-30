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
DECLARATIONS = {**STARTUP, **CLIENT, **INFLIGHT}


def declaration(case):
    if type(case) is not str or case not in DECLARATIONS:
        raise Refused('cleanup inline finite case')
    return DECLARATIONS[case]


def body(case):
    family, variant, _ = declaration(case)
    return EXIT if family == 'startup' and variant == 'exit' else SLEEP


def child_count(case):
    family, variant, _ = declaration(case)
    return 1 if family == 'startup' or variant == 'reader' else 3


def expected(case, native, native_pin, checkout, root_environment, *, base=None, terminal=False):
    from launch_policy import build_expected
    if terminal and case not in INFLIGHT:
        raise Refused('cleanup inline terminal outside inflight case')
    if terminal:
        if base is None:
            raise Refused('cleanup inline missing owned fixture')
        cwd, environment = str(base), {}
    else:
        cwd = str(checkout)
        environment = {**root_environment, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'}
    return build_expected(
        case,
        native, native_pin,
        (native, '-c', body(case)),
        tuple(sorted(environment.items())),
        cwd, 'python-command', None,
    )
