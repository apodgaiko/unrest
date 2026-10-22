"""Reuse exact approval-directory ownership; never change the RunControl env."""
import os
from pathlib import Path
import sys


def control_address(state, address):
    path = Path(state['guard']).with_name('approval_unix.py')
    guard = sys.modules['runtime_guard']
    namespace = guard.checked_source(path, state['direct_support']['files'][str(path)])
    return namespace['owned_address'](str(address), state['owned_root'], os.getuid(), state.get('case'))
