"""Process-bound source RPC; permissions stay in the independent observer."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import threading
import time

from content_manifest import Refused as Refused, refuse_if
from control_transport import Frame, RESPONSE_LIMIT, peer, verify_reply
from process_ledger import Birth


class Client:
    def __init__(self, directory: Path, profile: dict):
        self.observer = Birth.read(profile['observer'])
        self.nonce, self.token, self.generation = profile['nonce'], profile['token'], profile['generation']
        self.path = str(directory / 'control.sock')
        self.lock = threading.RLock()
        from cleanup_launch import ALL_CASES as CLEANUP_CASES
        self.seconds = 8 if profile.get('case') in CLEANUP_CASES else 4
        # Payload wrappers must not mediate their own fixed private channel.
        self.socket, self.connect, self.close = socket.socket, socket.socket.connect, socket.socket.close
        self.random, self.pid, self.sleep = os.urandom, os.getpid, time.sleep

    def request(self, kind: str, payload: dict) -> dict:
        with self.lock:
            request = {'pid': self.pid(), 'nonce': self.nonce, 'token': self.token,
                       'generation': self.generation, 'id': self.random(16).hex(),
                       'kind': kind, 'payload': payload}
            from cohort_controller import WAIVED
            from composed_adoption import CLOSEOUT
            seconds=22 if kind=='case-finish' and payload.get('case') in (*WAIVED,*CLOSEOUT) else self.seconds
            stream = self.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                stream.settimeout(seconds)
                self.connect(stream, self.path)
                peer(stream, self.observer, 20001)
                frame = Frame(stream, RESPONSE_LIMIT, seconds=seconds)
                frame.answer(request)
                while not frame.send():
                    self.sleep(.0001)
                response = None
                while response is None:
                    response = frame.read()
                    self.sleep(.0001)
                peer(stream, self.observer, 20001)
                answer = verify_reply(response, request)
                refuse_if(answer.get('ok') is not True, 'bootstrap observer refused operation')
                return answer
            finally:
                self.close(stream)
