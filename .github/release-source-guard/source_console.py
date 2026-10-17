"""SOURCE-only declared console data; this is not an installed-package proof."""
from __future__ import annotations

import tomllib

INTERPRETER = '/opt/deps/bin/python'
TARGET = '/opt/deps/bin/unrest'


def render(project: bytes) -> bytes:
    scripts = tomllib.loads(project.decode())['project']['scripts']
    if scripts.get('unrest') != 'unrest_harness.cli:cli':
        raise RuntimeError('declared source console entry differs')
    return (f'#!{INTERPRETER}\n'
            'import sys\n'
            'from unrest_harness.cli import cli\n'
            "if __name__ == '__main__':\n"
            '    sys.exit(cli())\n').encode()
