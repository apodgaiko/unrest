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

