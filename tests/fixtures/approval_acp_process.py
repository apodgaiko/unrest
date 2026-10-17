"""Controlled ACP wire fixture; never starts a model or external provider."""
import asyncio
import json
import sys
import time
from pathlib import Path

scenario = json.loads(Path(sys.argv[1]).read_text())
mcp_url = None


async def complete_over_mcp():
    from fastmcp import Client

    async with Client(mcp_url) as client:
        reply = await client.call_tool("end_node", {
            "done": True, "report": "controlled passing MCP handoff",
        })
        assert not reply.is_error and reply.data.get("recorded") is True
    handoff = json.loads(Path(scenario["handoff"]).read_text())
    assert handoff["done"] is True
    Path(scenario["mcp_receipt"]).write_text("recorded")


def send(value):
    print(json.dumps(value), flush=True)


for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    result = {}
    if method == "initialize":
        result = {"protocolVersion": 1, "agentCapabilities": {}}
    elif method == "session/new":
        if scenario.get("mcp_receipt"):
            mcp_url = request["params"]["mcpServers"][0]["url"]
        result = {"sessionId": "thread-1"}
    elif method == "session/prompt":
        if scenario.get("mcp_receipt"):
            asyncio.run(complete_over_mcp())
        elif scenario.get("handoff"):
            path = Path(scenario["handoff"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"node_id": "w1", "attempt_id": "attempt-1",
                                       "done": True, "report": "controlled passing handoff"}))
        if scenario.get("frames"):
            frames = scenario["frames"]
            for frame in frames:
                if frame.get("id") == "$prompt_id":
                    frame["id"] = request["id"]
            response = {"jsonrpc": "2.0", "id": request["id"],
                        "result": {"stopReason": "end_turn"}}
            ordering = scenario["ordering"]
            if ordering == "batch_before":
                send([*frames, response])
            elif ordering == "batch_after":
                send([response, *frames])
            else:
                if ordering == "after":
                    send(response)
                for frame in frames:
                    send(frame)
                if ordering == "before":
                    send(response)
            if ordering == "eof":
                break
            continue
        if scenario.get("raw_frame"):
            print(scenario["raw_frame"], flush=True)
        for params in scenario["events"]:
            send({"jsonrpc": "2.0", "method": "session/update", "params": params})
        time.sleep(scenario.get("delay", 0))
        result = {"stopReason": "end_turn"}
    send({"jsonrpc": "2.0", "id": request["id"], "result": result})
