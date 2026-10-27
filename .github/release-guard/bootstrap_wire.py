"""Process-bound source RPC; permissions stay in the independent observer."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import threading
import time

from content_manifest import Refused
from control_transport import Frame, RESPONSE_LIMIT, finite, peer, verify_reply
from process_ledger import Birth, integer, text


class Client:
    def __init__(self, directory: Path, profile: dict, methods: frozenset[str]):
        if type(methods) is not frozenset or not methods or len(methods) > 64:
            raise Refused('bootstrap RPC methods')
        self.methods = frozenset(text(method) for method in methods)
        self.observer = Birth.read(profile['observer'])
        self.nonce, self.token = text(profile['nonce']), text(profile['token'])
        self.generation = integer(profile['generation'], 1)
        self.path = str(directory / 'control.sock')
        self.lock = threading.RLock()
        from cleanup_launch import ALL_CASES as CLEANUP_CASES, CASES as CLEANUP_SMOKE
        self.seconds = 8 if profile.get('case') in CLEANUP_CASES or tuple(profile.get('cases', ())) in (CLEANUP_CASES, CLEANUP_SMOKE) else 4
        # Payload wrappers must not mediate their own fixed private channel.
        self.socket, self.connect, self.close = socket.socket, socket.socket.connect, socket.socket.close
        self.random, self.pid, self.sleep = os.urandom, os.getpid, time.sleep

    def request(self, kind: str, payload: dict) -> dict:
        if type(kind) is not str or kind not in self.methods or type(payload) is not dict:
            raise Refused('bootstrap RPC operation')
        finite(payload)
        with self.lock:
            request = {'pid': self.pid(), 'nonce': self.nonce, 'token': self.token,
                       'generation': self.generation, 'id': self.random(16).hex(),
                       'kind': kind, 'payload': payload}
            stream = self.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                stream.settimeout(self.seconds)
                self.connect(stream, self.path)
                peer(stream, self.observer, 20001)
                frame = Frame(stream, RESPONSE_LIMIT, [], seconds=self.seconds)
                frame.answer(request)
                while not frame.send():
                    self.sleep(.0001)
                response = None
                while response is None:
                    response = frame.read()
                    self.sleep(.0001)
                peer(stream, self.observer, 20001)
                answer = verify_reply(response, request)
                if answer.get('ok') is not True:
                    raise Refused('bootstrap observer refused operation')
                return answer
            finally:
                self.close(stream)
