from __future__ import annotations

import copy
import json
import sys
import time
from pathlib import Path
from typing import Any


def _substitute(value: Any, terminal_id: str | None) -> Any:
    if value == "$terminalId":
        if terminal_id is None:
            raise RuntimeError("terminal id requested before terminal/create")
        return terminal_id
    if isinstance(value, list):
        return [_substitute(item, terminal_id) for item in value]
    if isinstance(value, dict):
        return {
            key: _substitute(item, terminal_id)
            for key, item in value.items()
        }
    return value


def main() -> int:
    requests_path = Path(sys.argv[1])
    trace_path = Path(sys.argv[2])
    templates = json.loads(requests_path.read_text(encoding="utf-8"))
    trace: list[dict[str, Any]] = []
    terminal_id: str | None = None

    for request_id, template in enumerate(templates, start=1):
        request = copy.deepcopy(template)
        delay = request.pop("_delay_seconds", 0)
        if delay:
            time.sleep(float(delay))
        request = _substitute(request, terminal_id)
        request.update({"id": request_id, "jsonrpc": "2.0"})
        sys.stdout.write(json.dumps(request, separators=(",", ":")) + "\n")
        sys.stdout.flush()

        response_line = sys.stdin.readline()
        if not response_line:
            raise RuntimeError("ACP parent closed before responding")
        response = json.loads(response_line)
        trace.append({"request": request, "response": response})
        result = response.get("result")
        if isinstance(result, dict) and isinstance(result.get("terminalId"), str):
            terminal_id = result["terminalId"]

    trace_path.write_text(
        json.dumps(trace, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
