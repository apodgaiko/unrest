"""Local ACP fixture for cleanup tests; no external provider."""
import asyncio
import json
from pathlib import Path
import sys

scenario = json.loads(Path(sys.argv[1]).read_text())
mcp_url = None


async def complete():
    from fastmcp import Client

    async with Client(mcp_url) as client:
        if scenario['role'] == 'terminal_reviewer':
            reply = await client.call_tool('submit_terminal_review', {
                'done': True, 'report': 'controlled completion'})
        else:
            args = {'done': True, 'report': 'controlled completion'}
            if scenario['role'] == 'validate':
                args.update(items=[{'item_id': 'VAL-CLEANUP', 'passed': True}], passed=True)
            reply = await client.call_tool('end_node', args)
        assert not reply.is_error and reply.data.get('recorded') is True, reply
    Path(scenario['receipt']).write_text('recorded')


for line in sys.stdin:
    request = json.loads(line)
    method = request.get('method')
    result = {}
    if method == 'session/new':
        mcp_url = request['params']['mcpServers'][0]['url']
        result = {'sessionId': 'controlled-session'}
    elif method == 'session/prompt':
        if not scenario.get('no_handoff'):
            asyncio.run(complete())
        if scenario.get('progress'):
            print(json.dumps({'jsonrpc': '2.0', 'method': 'session/update', 'params': {
                'update': {'sessionUpdate': 'agent_message_chunk',
                           'content': {'type': 'text', 'text': 'controlled progress'}}}}),
                flush=True)
        if scenario.get('raw'):
            print(scenario['raw'], flush=True)
        result = {'stopReason': 'end_turn'}
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)
