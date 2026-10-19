"""Finite supplementary CI lane; no source checkpoint or provider authority."""
from __future__ import annotations

REFS = frozenset('refs/heads/codex/release-v047-preflight-20261019-' + f'{epoch:02}'
                 for epoch in range(1, 7))
CASES = (
    'tests/test_controlled_python_acp.py::test_real_local_boundaries[receipts]',
    '.github/release-source-guard/multiprocess_guard_methods.py::test_owned_exit17_keeps_raw_status',
)
SCRIPT = ('env -u CODEX_PATH uv run pytest -q ' + ' '.join(CASES)).encode()


def context():
    import os
    from structured_evidence import require
    require(os.environ.get('GITHUB_WORKFLOW') == 'CI'
            and os.environ.get('GITHUB_EVENT_NAME') == 'push'
            and os.environ.get('GITHUB_REF') in REFS, 'preflight_context')
