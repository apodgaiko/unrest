"""Closed execution/retention catalog for the primary CI pipeline.

The command registry retains its original byte format. All producers and
reducers consume this joined catalog; the workflow upload block is generated
and checked before an executable duty can bind.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

REGISTRY = Path(__file__).with_name('ci_commands.json')
SOURCE = 'v0.4.7 source suite'
BUILD = 'Build wheel and source distribution'
ARCHIVE = 'Check distribution archives'
INSTALLED = 'Smoke-test installed wheel'
CHECKSUM = 'Generate and verify v0.4.7 build-local checksums'
ORDER = (BUILD, ARCHIVE, INSTALLED, CHECKSUM)


@dataclass(frozen=True)
class Phase:
    command: str
    output: str

    @property
    def encrypted_members(self):
        return tuple(self.output + '/' + name for name in ('evidence.cms', 'safe-provenance.json'))


def catalog():
    commands = json.loads(REGISTRY.read_bytes())
    outputs = {
        'Install dependencies': 'primary-install', 'Import package': 'primary-import',
        'Supported CLI surfaces': 'primary-help', 'Repository contract': 'primary-repository',
        'Lint (ruff)': 'primary-lint', 'Type-check (mypy)': 'primary-types',
        SOURCE: 'primary-source', BUILD: 'primary-package-build',
        ARCHIVE: 'primary-package-archive', INSTALLED: 'primary-package-installed',
        CHECKSUM: 'primary-package-checksum',
    }
    if set(commands) != set(outputs) or len(set(outputs.values())) != len(outputs):
        raise RuntimeError('phase_catalog_membership')
    return {name: Phase(commands[name], output) for name, output in outputs.items()}


def retained_members():
    roots = ('primary-preparation', 'source-readiness', *(phase.output for phase in catalog().values()), 'primary-full')
    return tuple(root + '/' + member for root in roots
                 for member in ('evidence.cms', 'safe-provenance.json')) + (
                     'primary-host-stage.json', 'primary-image-stage.json', 'primary-decision-status.json')


def upload_block():
    return ''.join('            ${{ runner.temp }}/' + name + '\n' for name in retained_members())


def require_retention(workflow):
    marker = '      - name: Preserve encrypted primary phase evidence\n'
    if workflow.count(marker) != 1:
        raise RuntimeError('phase_retention_step')
    block = workflow.split(marker)[1].split('      - ', 1)[0]
    if ('        if: always()\n' not in block
            or 'uses: actions/upload-artifact@v4.6.2\n' not in block
            or block.split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0] != upload_block()):
        raise RuntimeError('phase_retention_catalog_drift')
