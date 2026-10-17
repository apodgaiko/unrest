"""Controlled ACP adapter for end-to-end owner tests; not a pinned adapter proof."""

import asyncio
import json
import os
from pathlib import Path
import sys


async def main():
    scenario = json.loads(Path(sys.argv[1]).read_text())
    environment = dict(
        os.environ,
        CONTROLLED_APPROVAL_MODE=scenario["mode"],
        CONTROLLED_APPROVAL_TRACE=scenario["trace"],
    )
    backend = await asyncio.create_subprocess_exec(
        os.environ["CODEX_PATH"],
        "app-server",
        env=environment,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    requests = {}
    native_id = 0
    prompt_id = None
    prompt_count = 0
    ready = asyncio.Event()

    def emit(frame):
        print(json.dumps(frame), flush=True)

    async def native(method, params):
        nonlocal native_id
        native_id += 1
        future = asyncio.get_running_loop().create_future()
        requests[native_id] = future
        backend.stdin.write(
            (json.dumps({"id": native_id, "method": method, "params": params}) + "\n").encode()
        )
        await backend.stdin.drain()
        return await future

    async def read_native():
        while line := await backend.stdout.readline():
            frame = json.loads(line)
            if "method" not in frame:
                future = requests.pop(frame["id"])
                if "error" in frame:
                    future.set_exception(ValueError("controlled interrupt refused"))
                else:
                    future.set_result(frame["result"])
            elif frame["method"] in (
                "item/autoApprovalReview/started",
                "item/autoApprovalReview/completed",
            ):
                body = frame["params"]
                started = frame["method"].endswith("/started")
                update = {
                    "sessionUpdate": "tool_call" if started else "tool_call_update",
                    "toolCallId": "guardian_assessment:" + body["reviewId"],
                    "status": "in_progress" if started else "failed",
                    "rawInput" if started else "rawOutput": body,
                }
                if started:
                    update.update(kind="think", title="Guardian Review")
                emit(
                    {
                        "jsonrpc": "2.0",
                        "method": "session/update",
                        "params": {"sessionId": "thread-1", "update": update},
                    }
                )
                if not started:
                    ready.set()
            elif frame["method"] == "turn/completed":
                if prompt_count > 1 and scenario.get("handoff"):
                    Path(scenario["handoff"]).write_text(
                        json.dumps(
                            {
                                "node_id": "w1",
                                "attempt_id": "attempt-1",
                                "done": True,
                                "report": "controlled continuation complete",
                            }
                        )
                    )
                emit({"jsonrpc": "2.0", "id": prompt_id, "result": {"stopReason": "end_turn"}})

    native_reader = asyncio.create_task(read_native())
    stderr = asyncio.create_task(backend.stderr.read())
    incoming = asyncio.StreamReader()
    await asyncio.get_running_loop().connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(incoming), sys.stdin
    )
    try:
        while True:
            incoming_line = asyncio.create_task(incoming.readline())
            await asyncio.wait({incoming_line, native_reader}, return_when=asyncio.FIRST_COMPLETED)
            if native_reader.done():
                incoming_line.cancel()
                await asyncio.gather(incoming_line, return_exceptions=True)
                break
            line = incoming_line.result()
            if not line:
                break
            frame = json.loads(line)
            method = frame["method"]
            if method == "session/cancel":
                await native("turn/interrupt", {"threadId": "thread-1", "turnId": "turn-1"})
                continue
            if method == "initialize":
                await native("initialize", {})
                result = {"protocolVersion": 1, "agentCapabilities": {}}
            elif method == "session/new":
                await native("thread/start", {})
                result = {"sessionId": "thread-1"}
            elif method == "session/prompt":
                prompt_id = frame["id"]
                prompt_count += 1
                await native("turn/start", {"threadId": "thread-1", "input": []})
                continue
            else:
                result = {}
            emit({"jsonrpc": "2.0", "id": frame["id"], "result": result})
    finally:
        backend.stdin.close()
        try:
            await asyncio.wait_for(backend.wait(), 3)
        except TimeoutError:
            backend.kill()
            await backend.wait()
        native_reader.cancel()
        await asyncio.gather(native_reader, stderr, return_exceptions=True)


asyncio.run(main())
