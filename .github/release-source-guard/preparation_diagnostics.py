"""Closed private preparation facts; exception bodies are never serialized."""
from __future__ import annotations

import hashlib
import json

CODES = frozenset({
    'primary_same_head_controls', 'primary_source_snapshot_drift',
    'primary_support_drift', 'primary_source_prepare',
    'clock_support_custody', 'clock_support_open_race', 'clock_support_byte_drift',
    'clock_source_input_custody', 'clock_source_input_open_race',
    'clock_source_input_read_race', 'clock_source_baseline_pin',
    'clock_source_unapproved_patch', 'clock_source_regression_drift',
    'release_identity_support_drift', 'release_identity_membership',
    'release_identity_preimage', 'release_identity_postimage',
    'ownership_document_preimage', 'ownership_document_postimage',
    'ownership_document_engine',
})
CLASSES = frozenset({'RuntimeError', 'EvidenceRefused', 'OSError', 'PermissionError',
                     'FileNotFoundError', 'KeyError', 'ValueError', 'TypeError',
                     'CalledProcessError', 'TimeoutError'})


def failure(error):
    message = error.args[0] if error.args and type(error.args[0]) is str else None
    code = message if message in CODES else 'unknown'
    if isinstance(message, str) and message.startswith('original source baseline drift: '):
        code = 'source_baseline_drift'
    frame = error.__traceback__
    while frame is not None and frame.tb_next is not None:
        frame = frame.tb_next
    location = None if frame is None else hashlib.sha256(json.dumps({
        'code_sha256': hashlib.sha256(frame.tb_frame.f_code.co_code).hexdigest(),
        'first_line': frame.tb_frame.f_code.co_firstlineno, 'line': frame.tb_lineno},
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'schema': 'unrest.v046.private-preparation-error.v1',
            'exception_class': type(error).__name__ if type(error).__name__ in CLASSES else 'other',
            'code': code, 'location_sha256': location,
            'errno': error.errno if isinstance(error, OSError) else None}
