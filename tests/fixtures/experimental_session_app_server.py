"""Synthetic app-server: stdlib only, no provider, auth, shell or arbitrary URLs."""
import copy
import json
import os
from pathlib import Path
import sys
import signal
import secrets
import time
import tomllib
import urllib.request


def emit(value):
    print(json.dumps(value), flush=True)


def rpc(url, token, method, params):
    if not url.startswith('http://127.0.0.1:') or not url.endswith('/mcp'):
        raise ValueError('nonlocal broker')
    data = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    request = urllib.request.Request(url, data, {
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2025-03-26',
    })
    # An explicit empty proxy map prevents inherited or system proxy routing.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=2) as r:
        body = r.read().decode()
    if body.startswith('event:'):
        body = next(line[6:] for line in body.splitlines() if line.startswith('data: '))
    response = json.loads(body)
    if 'error' in response or response.get('result', {}).get('isError'):
        raise ValueError('broker refused')
    return response['result']


def merge(target, source):
    # config/src/merge.rs: tables merge recursively across configuration layers.
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            merge(target[key], value)
        else:
            target[key] = copy.deepcopy(value)


def cli_layer(arguments):
    # utils/cli/config_override.rs and config/overrides.rs, rust-v0.160.1.
    # Parse only the value; quoting on the LHS has no TOML meaning.
    root = {}
    for argument in arguments:
        key, raw = argument.split('=', 1)
        key, raw = key.strip(), raw.strip()
        if not key:
            raise ValueError('empty override key')
        try:
            value = tomllib.loads('_x_=' + raw)['_x_']
        except tomllib.TOMLDecodeError:
            value = raw.strip("\"'")
        if key == 'use_legacy_landlock':
            key = 'features.use_legacy_landlock'
        table = root
        parts = key.split('.')
        for part in parts[:-1]:
            if not isinstance(table.get(part), dict):
                table[part] = {}
            table = table[part]
        table[parts[-1]] = value
    return root


def typed_config(config):
    # Config's nullable fields are serialized, with additional keys flattened.
    result = dict.fromkeys(('model review_model model_context_window model_auto_compact_token_limit '
        'model_auto_compact_token_limit_scope model_provider approval_policy approvals_reviewer '
        'sandbox_mode sandbox_workspace_write forced_chatgpt_workspace_id forced_login_method '
        'web_search tools instructions developer_instructions compact_prompt model_reasoning_effort '
        'model_reasoning_summary model_verbosity service_tier analytics apps browser_use computer_use desktop').split())
    result.update(copy.deepcopy(config))
    if result.get('skills', {}).get('config') == []:
        del result['skills']['config']
    return result


def requirements(config):
    # Config processor constructs this non-null projection for forced login.
    if config.get('forced_login_method') != 'chatgpt':
        return {'requirements': None}
    result = dict.fromkeys(('modelProvider modelProviders cliAuthCredentialsStore chatgptBaseUrl '
        'additionalDeveloperInstructions allowedApprovalPolicies allowedApprovalsReviewers '
        'allowedSandboxModes allowedWindowsSandboxImplementations allowedPermissionProfiles '
        'defaultPermissions allowedWebSearchModes allowManagedHooksOnly allowBrowserAndComputerUse '
        'allowAppshots allowRemoteControl computerUse browserUse inAppBrowser featureRequirements '
        'hooks enforceResidency network application autoReview models sqliteHome logDir '
        'modelCatalogJson checkForUpdateOnStartup allowLoginShell feedback').split())
    result['allowedLoginMethods'] = ['chatgpt']
    return {'requirements': result}


def main():
    arguments = sys.argv[1:]
    overrides = []
    while arguments[:1] == ['-c']:
        overrides.append(arguments[1])
        arguments = arguments[2:]
    if arguments != ['app-server']:
        raise ValueError('fixture invocation')
    flags = cli_layer(overrides)
    startup = {}
    config_path = Path(os.environ['CODEX_HOME']) / 'config.toml'
    if config_path.exists():
        startup = tomllib.loads(config_path.read_text())
    inherited_layer = copy.deepcopy(startup)
    merge(startup, flags)
    Path('backend.pid').write_text(str(os.getpid()))
    session = 'synthetic-' + secrets.token_hex(24)
    ordinal = 0
    previous = None
    registered = None
    for line in sys.stdin:
        request = json.loads(line)
        method = request.get('method')
        if 'id' not in request:
            continue
        params = request.get('params', {})
        result = {}
        if method == 'initialize':
            result = {'userAgent': 'synthetic-only'}
        elif method == 'account/read':
            assert params.get('refreshToken') is False
            result = {'account': {'type': 'chatgpt', 'email': 'controlled@example.invalid', 'planType': 'plus'} if startup else None,
                      'requiresOpenaiAuth': False}
        elif method in ('skills/list', 'model/list'):
            result = {'data': [], 'nextCursor': None}
            if method == 'model/list':
                result['data'] = [{'id': 'synthetic', 'model': 'synthetic',
                                   'displayName': 'Synthetic', 'description': 'Local fixture',
                                   'isDefault': True, 'defaultReasoningEffort': 'medium',
                                   'supportedReasoningEfforts': [{'reasoningEffort': 'medium',
                                                                 'description': 'Synthetic'}]}]
        elif method == 'config/read':
            result = {'config': typed_config(startup), 'origins': {},
                      'layers': [{'name': {'type': 'sessionFlags'}, 'version': 'controlled',
                                  'config': flags}, {'name': {'type': 'user', 'file': str(config_path),
                                  'profile': None}, 'version': 'controlled', 'config': inherited_layer}]}
        elif method == 'configRequirements/read':
            result = requirements(startup)
        elif method == 'thread/start':
            for key, value in flags.items():
                assert params['config'][key] == value or key == 'mcp_servers'
            effective = {}
            merge(effective, startup)
            merge(effective, params['config'])
            inherited = startup.get('mcp_servers', {})
            assert all(effective['mcp_servers'][name]['enabled'] is False for name in inherited)
            assert set(effective['mcp_servers']) == set(inherited) | {'unrest_turn_broker'}
            registered = params['config']['mcp_servers']['unrest_turn_broker']
            assert registered['url'].startswith('http://127.0.0.1:')
            assert registered['http_headers']['Authorization'].startswith('Bearer ')
            Path('registered-broker.json').write_text(json.dumps({'registered': True}))
            result = {'thread': {'id': session}, 'model': 'gpt-6-astra' if startup else 'synthetic',
                      'reasoningEffort': 'medium', 'modelProvider': 'openai' if startup else 'synthetic'}
        elif method == 'turn/start':
            assert params['threadId'] == session
            assert params['sandboxPolicy']['type'] == 'readOnly'
            if startup:
                assert params['approvalPolicy'] == 'never'
            envelope = json.loads(params['input'][0]['text'])
            with Path('received.jsonl').open('a') as trace:
                trace.write(json.dumps({'method': method, 'session': session,
                                        'ordinal': ordinal + 1}) + '\n')
                trace.flush()
                os.fsync(trace.fileno())
            script = None
            if envelope.get('instruction', '').startswith('fixture:'):
                script = json.loads(envelope['instruction'][8:])
                assert set(script) <= {'writes', 'expected', 'delay'}
                delay = script.get('delay', 0)
                assert type(delay) in (int, float) and 0 <= delay <= 10
                time.sleep(delay)
            assert registered is not None
            assert envelope['url'] == registered['url']
            assert envelope['connection'] == registered['http_headers']['Authorization'][7:]
            ordinal += 1
            assert envelope['turn']['ordinal'] == ordinal
            # Body-free trace proves real adapter traversal, never saves capability.
            with Path('trace.jsonl').open('a') as trace:
                trace.write(json.dumps({'method': method, 'ordinal': ordinal,
                                        'session': session, 'synthetic': True}) + '\n')
            turn = {'id': f'turn-{ordinal}', 'status': 'completed', 'items': [], 'error': None}
            emit({'id': request['id'], 'result': {'turn': turn}})
            emit({'method': 'turn/started', 'params': {'threadId': session, 'turn': turn}})
            if envelope['scenario'] in ('stall', 'ignore_term'):
                if envelope['scenario'] == 'ignore_term':
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                continue
            if envelope['scenario'] != 'missing_completion':
                rpc(envelope['url'], envelope['connection'], 'initialize', {
                    'protocolVersion': '2025-03-26', 'capabilities': {},
                    'clientInfo': {'name': 'synthetic', 'version': '1'}})
                observation = {'ordinal': ordinal, 'replaced': False,
                               'stale_write_refused': False, 'validator_write_refused': False}
                if previous is not None or envelope['turn']['role'] == 'validator':
                    stale_turn, stale_token = ((envelope['turn'], envelope['capability'])
                                               if envelope['turn']['role'] == 'validator' else previous)
                    try:
                        rpc(envelope['url'], envelope['connection'], 'tools/call', {
                            'name': 'replace_file', 'arguments': {
                                'capability': stale_token, 'turn': stale_turn,
                                'name': 'a', 'content': 'forbidden\n'}})
                    except ValueError as error:
                        assert str(error) == 'broker refused'
                        key = ('validator_write_refused' if envelope['turn']['role'] == 'validator'
                               else 'stale_write_refused')
                        observation[key] = True
                    else:
                        raise AssertionError('unauthorized write accepted')
                candidate = envelope['turn']['candidate']
                if envelope['turn']['role'] == 'worker':
                    writes = (script['writes'] if script is not None else
                              {'a': 'corrected\n' if envelope.get('instruction') == 'produce_corrected'
                               or ordinal > 1 else 'defective\n'})
                    for name, content in sorted(writes.items()):
                        response = rpc(envelope['url'], envelope['connection'], 'tools/call', {
                            'name': 'replace_file', 'arguments': {
                                'capability': envelope['capability'], 'turn': envelope['turn'],
                                'name': name, 'content': content}})
                        candidate = response['content'][0]['text']
                    observation['replaced'] = True
                elif script is not None:
                    envelope['disposition'] = ('pass' if envelope['files'] == script['expected']
                                               else 'reproducible_product_defect')
                args = {'capability': envelope['capability'], 'turn': envelope['turn'],
                        'candidate': candidate,
                        'disposition': envelope['disposition'],
                        'verdicts': {target: envelope['disposition'] == 'pass'
                                     for target in envelope['turn'].get('targets', [])}
                                    if envelope['turn']['role'] == 'validator' else {}}
                rpc(envelope['url'], envelope['connection'], 'tools/call', {
                    'name': 'complete_turn', 'arguments': args})
                previous = envelope['turn'], envelope['capability']
                with Path('broker-observations.jsonl').open('a') as trace:
                    trace.write(json.dumps(observation, sort_keys=True) + '\n')
            emit({'method': 'item/agentMessage/delta', 'params': {
                'threadId': session, 'turnId': turn['id'], 'itemId': 'synthetic',
                'delta': 'synthetic'}})
            emit({'method': 'turn/completed', 'params': {'threadId': session, 'turn': turn}})
            continue
        elif method not in ('thread/unsubscribe', 'turn/interrupt', 'skills/extraRoots/set'):
            emit({'id': request['id'], 'error': {'code': -32601, 'message': 'fixture method refused'}})
            continue
        emit({'id': request['id'], 'result': result})
        if method == 'initialize' and startup:
            # Workspace routing is asynchronous: notification precedes the next
            # RPC response, not necessarily the initialize response.
            emit({'method': 'account/updated', 'params': {'authMode': 'chatgpt', 'planType': 'plus'}})


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        Path('backend-error.json').write_text(json.dumps({'type': type(error).__name__}))
        raise
