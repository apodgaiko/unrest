"""Join the controlled approval MCP's original inventory pipe to exec custody."""
from __future__ import annotations

import hashlib
from pathlib import Path

from finite.approval_routes import selected_mode
from finite.linux_identity import identity

SOURCE = 'src/unrest_harness/acp_runner.py'
PIN = '5698d40663b23bf23f832a3e3f69732fe31004d8b1cf305d5bc5870e11f39a2f'
TEST = 'tests/test_approval_recovery.py'
TEST_PIN = '59f3eb0a28b856081bfd32173e6259f7f916eda711e3911d2ab76843c695efcb'


def binding(authority, pid):
    selected = authority.bound[pid]['registration']
    if selected['class'] != 'source-approval-mcp':
        return None
    pins = authority.manifest['product_pins']
    if (pins.get(SOURCE) != PIN or pins.get(TEST) != TEST_PIN
            or hashlib.sha256(Path('/source', SOURCE).read_bytes()).hexdigest() != PIN
            or hashlib.sha256(Path('/source', TEST).read_bytes()).hexdigest() != TEST_PIN):
        raise RuntimeError('approval_pipe_source_drift')
    parent = identity(pid)['ppid']
    rows = [row for row in authority.supervisor.events()
            if row['kind'] == 'exact_controlled_approval_registration'
            and row['owner_pid'] == parent and row['class'] == selected['class']
            and row['source_binding'] == selected['source_binding']
            and row['argv_sha256'] == selected['argv_sha256']]
    if (len(rows) != 2 or rows[0] != rows[1]
            or selected_mode(rows[0].get('case')) is None
            or rows[0]['source_binding'] != {'path': '/source/' + SOURCE, 'line': 2191, 'sha256': PIN}
            or rows[0]['native_provider'] is not False
            or any(type(rows[0].get(key)) is not int or rows[0][key] < 0
                   for key in ('pipe_device', 'pipe_inode'))):
        raise RuntimeError('approval_pipe_original_registration')
    # The unchanged original exec_descriptors performs the actual pre/post-exec
    # census, pipe identity/UID/access, credential, birth and full-vector checks.
    return rows[0]
