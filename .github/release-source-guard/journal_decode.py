"""Reuse validated JSON framing, never current evidence or mutable event values."""
from __future__ import annotations

import json


class JournalDecoder:
    def __init__(self):
        self.frames = {}

    def decode(self, key, text, *, literal_newlines=False):
        key = (key, type(text), literal_newlines)
        empty, newline, opening, closing, comma = ((b'', b'\n', b'[', b']', b',')
                                                   if isinstance(text, bytes)
                                                   else ('', '\n', '[', ']', ','))
        previous = self.frames.get(key)
        if previous is not None and previous[0] == text:
            lines, frame = previous[1:]
        else:
            prefix = empty
            lines = ()
            if previous is not None and previous[0].endswith(newline) and text.startswith(previous[0]):
                prefix, lines = previous[:2]
            tail = text[len(prefix):]
            added = tuple(tail.split(newline)[:-1] if literal_newlines else tail.splitlines())
            # Validate each new original record before introducing array framing:
            # a comma-separated pair on one line is not a valid journal record.
            for line in added:
                json.loads(line)
            lines = (*lines, *added)
            frame = opening + comma.join(lines) + closing
            self.frames[key] = (text, lines, frame)
        try:
            return json.loads(frame)
        except (RecursionError, UnicodeDecodeError, json.JSONDecodeError):
            # Array framing must not reduce the original per-record depth bound.
            return [json.loads(line) for line in lines]
