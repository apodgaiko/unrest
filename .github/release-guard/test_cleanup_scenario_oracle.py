"""Historical scenario data oracle, separate from execution admission."""
import json
from cleanup_launch import selection, RUNNER, SAVED, runner_scenario

def scenario(case, base):
    recorded, variant, role = selection(case)
    if case in RUNNER:
        return runner_scenario(case,base)
    if case in SAVED:
        record = {'role': role, 'progress': True, 'receipt': str(base / 'receipt'),
                  'raw': json.dumps({'jsonrpc': '2.0', 'id': [], 'result': {}}) if variant == 'transport' else None}
    elif not recorded:
        record = {'role': role, 'no_handoff': True}
    else:
        raw = (None if variant == 'success' else '[' * 10000 + '0' + ']' * 10000 if variant == 'deep_json'
               else json.dumps({'jsonrpc': '2.0', 'id': [] if variant == 'array_id' else {}, 'result': {}}))
        record = {'raw': raw, 'role': role, 'receipt': str(base / 'receipt')}
    return json.dumps(record).encode()



def inline_input(case,native,native_pin,checkout,ambient,*,base=None,terminal=False):
    """Original operand fixture; this helper grants no process authority."""
    from inline_leaves import STARTUP,SLEEP,EXIT
    from launch_policy import build_expected
    code=EXIT if case in STARTUP and STARTUP[case][1]=='exit' else SLEEP
    env={} if terminal else {**ambient,'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    return build_expected(case,native,native_pin,(native,'-c',code),tuple(sorted(env.items())),
        str(base if terminal else checkout),'python-command')
