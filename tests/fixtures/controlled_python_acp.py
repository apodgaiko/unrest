"""Local ACP-to-app-server protocol fixture; native conversion is unverified.

No child launches. The actual owner supplies one authenticated Bridge and lifetime
socket. Completion is performed by the separate backend through the real broker.
"""
import asyncio
import json
import os
import sys


class Adapter:
    def __init__(self):
        self.next_id = 0
        self.pending = {}
        self.prompt = None
        self.session = None
        self.reader = None
        self.writer = None
        self.warnings_closed = False

    def emit(self, value):
        print(json.dumps(value), flush=True)

    async def rpc(self, method, params):
        self.next_id += 1
        identifier = self.next_id
        future = asyncio.get_running_loop().create_future()
        self.pending[identifier] = future
        self.writer.write((json.dumps({'id': identifier, 'method': method,
                                      'params': params}) + '\n').encode())
        await self.writer.drain()
        try:
            return await future
        finally:
            self.pending.pop(identifier, None)

    def notification(self, line):
        # The Bridge validates first. Keep this local converter closed as well.
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate local notification field')
                result[key] = value
            return result
        def invalid(_):
            raise ValueError('invalid local notification value')
        frame = json.loads(line, object_pairs_hook=unique, parse_constant=invalid)
        if (len(line) > 65536 or set(frame) - {'method', 'params', 'emittedAtMs'}
                or not isinstance(frame.get('params'), dict)):
            raise ValueError('invalid local notification envelope')
        stamp = frame.get('emittedAtMs')
        if stamp is not None and (type(stamp) is not int or not -2**63 <= stamp < 2**63):
            raise ValueError('invalid local notification timestamp')
        params = frame['params']
        if frame['method'] == 'remoteControl/status/changed':
            if (set(params) - {'status', 'serverName', 'installationId', 'environmentId'}
                    or params.get('status') != 'disabled'
                    or any(type(params.get(key)) is not str for key in ('serverName', 'installationId'))
                    or (params.get('environmentId') is not None
                        and type(params['environmentId']) is not str)):
                raise ValueError('invalid local remote status')
            return
        if (set(params) - {'summary', 'details', 'path', 'range'}
                or type(params.get('summary')) is not str
                or any(params.get(key) is not None and type(params[key]) is not str
                       for key in ('details', 'path'))):
            raise ValueError('invalid local warning')
        span = params.get('range')
        if span is not None:
            if (not isinstance(span, dict) or set(span) != {'start', 'end'}
                    or any(not isinstance(pos, dict) or set(pos) != {'line', 'column'}
                           or any(type(v) is not int or not 0 <= v < 2**64 for v in pos.values())
                           for pos in span.values())):
                raise ValueError('invalid local warning range')
        if self.warnings_closed:
            raise ValueError('late local warning')
        # Native notify() has no registered session handler before thread creation.
        if self.session is None:
            return
        if type(self.session) is not str or not self.session:
            raise ValueError('invalid local warning session')
        details = '\n\n' + params['details'] if params.get('details') else ''
        self.emit({'jsonrpc': '2.0', 'method': 'session/update', 'params': {
            'sessionId': self.session, 'update': {'sessionUpdate': 'agent_message_chunk',
            'content': {'type': 'text',
                        'text': 'Config warning: ' + params['summary'] + details + '\n\n'}}}})

    async def backend(self):
        while line := await self.reader.readline():
            frame = json.loads(line)
            if 'method' not in frame:
                future = self.pending.get(frame.get('id'))
                if future is None or future.done():
                    raise ValueError('unmatched backend response')
                if 'error' in frame:
                    future.set_exception(ValueError('backend refused'))
                else:
                    future.set_result(frame['result'])
            elif frame['method'] == 'turn/completed':
                params = frame['params']
                if params['threadId'] != self.session or self.prompt is None:
                    raise ValueError('wrong completion')
                self.prompt.set_result(params['turn'])
            elif frame['method'] == 'item/agentMessage/delta':
                params = frame['params']
                if params['threadId'] != self.session:
                    raise ValueError('wrong message session')
                self.emit({'jsonrpc': '2.0', 'method': 'session/update', 'params': {
                    'sessionId': self.session, 'update': {'sessionUpdate': 'agent_message_chunk',
                    'content': {'type': 'text', 'text': params['delta']}}}})
            elif frame['method'] in ('configWarning', 'remoteControl/status/changed'):
                self.notification(line)
            elif frame['method'] not in ('turn/started', 'account/updated'):
                raise ValueError('unsupported local notification')
        raise EOFError('backend closed')

    async def handle(self, request):
        method, params = request['method'], request.get('params', {})
        if method == 'initialize':
            await self.rpc('initialize', {'clientInfo': {'name': 'controlled-python-acp',
                                                       'version': '1'}, 'capabilities': {}})
            return {'protocolVersion': 1, 'agentCapabilities': {},
                    'agentInfo': {'name': 'controlled-python-acp', 'version': 'local-1'}}
        if method == 'session/new':
            if self.session is not None:
                raise ValueError('extra local session')
            config = json.loads(os.environ.get('CODEX_CONFIG', '{}'))
            config['mcp_servers'] = {server['name']: {
                'url': server['url'], 'http_headers': {
                    header['name']: header['value'] for header in server['headers']}}
                for server in params['mcpServers']}
            await self.rpc('account/read', {'refreshToken': False})
            await self.rpc('model/list', {})
            if 'CODEX_CONFIG' in os.environ:
                await self.rpc('config/read', {'includeLayers': True, 'cwd': params['cwd']})
            result = await self.rpc('thread/start', {'cwd': params['cwd'], 'config': config})
            self.session = result['thread']['id']
            return {'sessionId': self.session}
        if method in ('session/prompt', 'session/cancel'):
            if params.get('sessionId') != self.session or self.session is None:
                raise ValueError('wrong local session')
            if method == 'session/cancel':
                self.warnings_closed = True
                if self.prompt is not None:
                    await self.rpc('turn/interrupt', {'threadId': self.session})
                return {}
            if self.prompt is not None:
                raise ValueError('overlapping prompt')
            self.prompt = asyncio.get_running_loop().create_future()
            try:
                await self.rpc('turn/start', {'threadId': self.session,
                    'input': [{'type': 'text', 'text': params['prompt'][0]['text']}],
                    'approvalPolicy': 'never',
                    'sandboxPolicy': {'type': 'readOnly', 'networkAccess': False}})
                turn = await self.prompt
                if turn['status'] != 'completed' or turn['error'] is not None:
                    raise ValueError('backend turn failed')
                return {'stopReason': 'end_turn'}
            finally:
                self.prompt = None
        raise ValueError('unsupported local ACP request')

    async def stdin(self):
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)
        tasks = set()
        async def respond(request):
            result = await self.handle(request)
            if 'id' in request:
                self.emit({'jsonrpc': '2.0', 'id': request['id'], 'result': result})
        reading = asyncio.create_task(reader.readline())
        try:
            while True:
                done, _ = await asyncio.wait(tasks | {reading},
                                             return_when=asyncio.FIRST_COMPLETED)
                for task in done - {reading}:
                    tasks.remove(task)
                    # Observe failures even while the next request is absent.
                    task.result()
                if reading in done:
                    line = reading.result()
                    if not line:
                        return
                    tasks.add(asyncio.create_task(respond(json.loads(line))))
                    # Cancellation must remain readable while turn/start or
                    # turn/completed is pending on the independent backend pipe.
                    reading = asyncio.create_task(reader.readline())
        finally:
            reading.cancel()
            for task in tasks:
                task.cancel()
            await asyncio.gather(reading, *tasks, return_exceptions=True)

    async def run(self):
        if sys.argv[1:] != ['--controlled-local-acp-v1']:
            raise ValueError('local adapter invocation')
        port, nonce, lifetime_port, lifetime_nonce = json.loads(os.environ['SYNTHETIC_RELAY'])
        _, lifetime = await asyncio.open_connection('127.0.0.1', lifetime_port)
        lifetime.write((lifetime_nonce + '\n').encode())
        await lifetime.drain()
        self.reader, self.writer = await asyncio.open_connection('127.0.0.1', port,
                                                               limit=16 * 1024 * 1024)
        self.writer.write((nonce + '\n').encode())
        await self.writer.drain()
        backend = asyncio.create_task(self.backend())
        stdin = asyncio.create_task(self.stdin())
        try:
            done, _ = await asyncio.wait((backend, stdin), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            self.warnings_closed = True
            backend.cancel()
            stdin.cancel()
            await asyncio.gather(backend, stdin, return_exceptions=True)
            self.writer.close()
            await self.writer.wait_closed()
            lifetime.close()
            await lifetime.wait_closed()


if __name__ == '__main__':
    asyncio.run(Adapter().run())
