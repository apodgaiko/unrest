"""Strict local boundary candidate. Provider admission remains unsupported.

No credentials or external egress are accepted. This module deliberately does
not relax Mach denial to make Codex configuration work.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import threading
from pathlib import Path

from unrest_harness.experimental_lease import LeaseRefused, TurnBroker

ADAPTER_SHA256 = '878d6a3d825725d0a579305a3e206c7bbb5724a95751b4e3e86af8030cdee758'


def check_pin(path: Path, digest: str) -> None:
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise LeaseRefused('executable_pin_mismatch')


def local_profile(executable: Path, reads: tuple[Path, ...], scratch: Path,
                  port: int) -> str:
    """Default-deny research profile, immutable bootstrap outside scratch.

    Exact exec allowance permits same-image reexec; it does not establish ACP
    identity continuity. No inherited writable FDs or mappings may be supplied.
    Mach rights are a separate unresolved boundary, not closed by close_fds.
    """
    if not 1 <= port <= 65535:
        raise LeaseRefused('invalid_broker_port')
    quote = lambda p: json.dumps(str(p.resolve()))  # noqa: E731
    readable = ''.join(f'(subpath {quote(p)})' for p in sorted(reads))
    return (
        '(version 1)(deny default)'
        f'(allow process-exec (literal {quote(executable)}))'
        '(allow sysctl-read)'
        '(allow file-read-metadata)'
        '(allow file-read* (subpath "/System") (subpath "/usr/lib")'
        '(subpath "/usr/share") (literal "/dev/urandom") (literal "/dev/random")'
        f'(literal "/dev/null"){readable}(subpath {quote(scratch)}))'
        f'(allow file-write* (subpath {quote(scratch)}) (literal "/dev/null"))'
        f'(allow network-outbound (remote ip "localhost:{port}"))'
    )


class OwnedProcesses:
    """Own Popen handles, never reload PIDs or infer ownership from a group.

    Use only for trusted launchers or children forbidden to fork by the OS.
    Unknown descendants invalidate the entire boundary; callers must report
    them, and no claim of automatic descendant discovery is made here.
    """

    def __init__(self, broker: TurnBroker):
        self._lock = threading.RLock()
        self._broker = broker
        self._processes: list[subprocess.Popen[bytes]] = []
        self.quarantined = False
        self.closed = False

    def launch_local(self, command: list[str], *, cwd: Path, env: dict[str, str]
                     ) -> subprocess.Popen[bytes]:
        with self._lock:
            if self.closed or self.quarantined:
                raise LeaseRefused('process_owner_closed')
            process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       close_fds=True, start_new_session=True)
            self._processes.append(process)
            return process

    def unknown_child(self) -> None:
        with self._lock:
            self.quarantined = True
            self._broker.quarantined = True
            self._broker.park()

    def close(self, timeout: float = 1.0) -> bool:
        with self._lock:
            self.closed = True
            self._broker.park()
            for process in self._processes:
                try:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=timeout)
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if stream is not None:
                            try:
                                stream.close()
                            except BrokenPipeError:
                                pass  # Child was reaped; flushing a closed peer is harmless.
                except (OSError, subprocess.TimeoutExpired):
                    self.unknown_child()
            return not self.quarantined


def acp_envelope(method: str, session: str, content: str = '') -> dict[str, object]:
    """Controller-only method envelope; never forward model-supplied ACP RPC."""
    if method not in {'session/prompt', 'session/cancel'} or not session:
        raise LeaseRefused('acp_method_denied')
    if method == 'session/cancel':
        return {'sessionId': session}
    if not content.strip() or content.lstrip().startswith('/'):
        raise LeaseRefused('slash_control_denied')
    return {'sessionId': session, 'prompt': [{'type': 'text', 'text': content}]}


def deny_callback(method: str) -> None:
    # Experimental callbacks never delegate to ordinary filesystem/terminal handlers.
    raise LeaseRefused('experimental_callback_denied')

