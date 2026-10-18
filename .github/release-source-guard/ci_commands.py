"""Bind custom-shell input to the primary workflow's original executable blocks.

The coordinator executes the returned original script bytes. This parser grants
no launch authority and never imports repository product modules on the host.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

REGISTRY = Path(__file__).with_name('ci_commands.json')


def primary_commands(workflow):
    commands = {}
    primary = False
    name = None
    lines = workflow.splitlines(keepends=True)
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith('  primary:'):
            if primary:
                raise RuntimeError('ambiguous primary workflow definition')
            primary = True
        elif primary and line.startswith('  ') and not line.startswith('   ') and line.strip():
            break
        if primary and line.startswith('      - name: '):
            name = line.removeprefix('      - name: ').rstrip('\r\n')
        elif primary and line.startswith('        run: '):
            if name is None or name in commands:
                raise RuntimeError('ambiguous primary executable block')
            value = line.removeprefix('        run: ').rstrip('\r\n')
            if value == '|':
                block = []
                while index + 1 < len(lines) and lines[index + 1].startswith('          '):
                    index += 1
                    block.append(lines[index][10:])
                value = ''.join(block)
            elif value in ('>', '|-', '>-') or value.startswith(('"', "'")):
                raise RuntimeError('unregistered primary script encoding')
            if not value.endswith('\n'):
                value += '\n'
            commands[name] = value
        index += 1
    if not primary:
        raise RuntimeError('primary workflow definition missing')
    return commands


def require_executable_duties(workflow, names):
    primary = False
    step = None
    for line in workflow.splitlines():
        if line == '  primary:':
            primary = True
        elif primary and line.startswith('  ') and not line.startswith('   ') and line.strip():
            break
        if not primary:
            continue
        if line.startswith(('    if:', '    continue-on-error:')):
            raise RuntimeError('conditional primary execution refused')
        if line.startswith('      - name: '):
            step = line.removeprefix('      - name: ')
        if step in names and line.startswith(('        if:', '        continue-on-error:', '        working-directory:')):
            raise RuntimeError('conditional original executable duty refused')


def bind(script, workflow):
    registry = json.loads(REGISTRY.read_bytes())
    actual = primary_commands(workflow)
    require_executable_duties(workflow, registry)
    for name, original in registry.items():
        if actual.get(name) != original:
            raise RuntimeError('original primary executable duty drift: ' + name)
    if not isinstance(script, bytes):
        raise TypeError('actual custom-shell script bytes required')
    matches = [(name, command) for name, command in registry.items()
               if command.encode() == script]
    if len(matches) != 1:
        raise RuntimeError('unregistered actual primary script')
    name, command = matches[0]
    return {'name': name, 'script': script,
            'script_sha256': hashlib.sha256(command.encode()).hexdigest(),
            'full_source': name == 'v0.4.6 source suite'}


def bind_generated(script, workflow):
    """Bind GitHub's wire bytes without changing the file passed to Bash.

    YAML plain scalars have no final newline; literal | blocks retain it. The
    registry stores newline-terminated logical duties, independently checked by
    bind. No alternate rendering of an executable block is accepted.
    """
    registry = json.loads(REGISTRY.read_bytes())
    actual = primary_commands(workflow)
    require_executable_duties(workflow, registry)
    if any(actual.get(name) != original for name, original in registry.items()):
        raise RuntimeError('original primary executable duty drift')
    primary = False
    name = None
    matches = []
    for line in workflow.splitlines():
        if line == '  primary:':
            primary = True
        elif primary and line.startswith('  ') and not line.startswith('   ') and line.strip():
            break
        if primary and line.startswith('      - name: '):
            name = line.removeprefix('      - name: ')
        if primary and name in registry and line.startswith('        run: '):
            value = line.removeprefix('        run: ')
            expected = registry[name] if value == '|' else registry[name].removesuffix('\n')
            if script == expected.encode():
                matches.append(name)
    if len(matches) != 1:
        raise RuntimeError('unregistered generated primary script')
    return {'name': matches[0], 'script': script, 'script_sha256': hashlib.sha256(script).hexdigest(),
            'full_source': matches[0] == 'v0.4.6 source suite'}
