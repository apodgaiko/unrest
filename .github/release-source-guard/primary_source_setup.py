"""Compose existing source setup inputs without changing finite policy bytes."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from primary_policy import PYTHON


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    nonce = sys.argv[1]
    # Both existing producer operations and the original fixture registrations
    # remain enabled in a whole-source process. No new executable registration.
    result = subprocess.run([sys.executable, '-I', '/guard/prepare_source.py', nonce,
                             'producer-contract'], capture_output=True, check=False)
    if result.returncode:
        # Child facts are private stdout for the acquiring host, never public
        # metadata. Preserve them before replacing the subprocess exception.
        sys.stdout.buffer.write(result.stderr)
        raise SystemExit(125)
    prepared = json.loads(result.stdout)
    manifest = prepared['manifest']
    registry = ast.literal_eval(ast.parse(prepared['registry']).body[1].value)
    source = Path('/guard/finite/restart_custody.py')
    function = next(node for node in ast.parse(source.read_bytes()).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'start_custodian')
    target = Path('/guard/finite/custody_process.py')
    registry.append({'class': 'restart-custodian', 'python': True, 'argv': [str(target)],
                     'checkout_cwd': False,
                     'source_binding': {'path': str(source), 'line': function.lineno, 'sha256': sha(source)},
                     'source_function': function.name, 'source_function_line': function.lineno,
                     'source_cwd_local': 'work', 'files': {str(target): sha(target)}})
    text = '"""Finite vectors; unavailable platform images cannot match a byte pin."""\nCOMMANDS = ' + repr(registry) + '\n'
    manifest['registry']['sha256'] = hashlib.sha256(text.encode()).hexdigest()
    manifest['runtime'] = {'paths': ['/source/.venv/bin/python', '/source/.venv/bin/python3',
                                    '/source/.venv/bin/python3.13', PYTHON],
                           'realpath': PYTHON, 'sha256': sha(PYTHON)}
    # Source applicability remains pinned to the original template. The complete
    # current snapshot is a separate custody input, never a rebased baseline.
    manifest['source_selection'] = 'primary-source'
    manifest['source_case'] = 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct'
    manifest['scope'] = 'primary source entry'
    print(json.dumps({'manifest': manifest, 'registry': text}, sort_keys=True))


if __name__ == '__main__':
    main()
