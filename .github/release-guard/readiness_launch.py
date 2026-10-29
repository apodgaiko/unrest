"""Four original local-readiness leaves; connect permission never grants payload."""
import ast
from pathlib import Path

from content_manifest import Refused
from launch_policy import source_unit,build_expected,admit_expected,literal

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


def proposal(host,actor,raw):
    host.root_only(actor)
    if host.case not in CASES or raw['stdin'] is not None:
        raise Refused('readiness original child scope')
    if host.case in INLINE:
        path,pin=INLINE[host.case]
        unit=source_unit(Path(host.meta['checkout']),path,pin,(host.case.split('::')[1],))
        if path==SESSION:
            body=literal(unit,'code')
        else:
            body="import sys; sys.stderr.write('adapter failed: adapter-stderr-secret-credential'); raise SystemExit(2)"
    else:
        unit=source_unit(Path(host.meta['checkout']),TEST,PIN,(NAME,'exercise'))
        bodies=[ast.literal_eval(node.value) for node in ast.walk(unit) if isinstance(node,ast.Assign)
                and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='body']
        if len(bodies)!=3 or any(type(body) is not str for body in bodies):
            raise Refused('readiness three pinned original literal branches')
        body=bodies[0 if host.case==READY else 1 if host.case==CASES[0] else 2]
    native=host.binding['entry']['path']
    env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    value=build_expected(host.case,native,host.binding['entry']['sha256'],
        (native,'-c',body),tuple(sorted(env.items())),host.meta['checkout'],'python-command')
    return admit_expected(host,actor,raw,value,'session-inline' if host.case.endswith('::test_sigterm_ignoring_owned_process_is_killed_and_reaped') else 'fixed-inline',[native,'-I','-S','-c',body])
