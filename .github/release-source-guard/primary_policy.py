"""Primary script authority, distinct from source-fixture UV registrations."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shlex

from ci_commands import bind_generated

FOCUSED = {'Install dependencies', 'Import package', 'Supported CLI surfaces',
           'Lint (ruff)', 'Type-check (mypy)', 'Repository contract'}
SHELL = '/bin/bash'
SHELL_FLAGS = ['--noprofile', '--norc', '-e', '-o', 'pipefail']
UV = '/opt/source-bootstrap/bin/uv'
PYTHON = '/usr/local/bin/python-primary-audit'


def sha(body):
    return hashlib.sha256(body).hexdigest()


def plan(script, workflow):
    duty = bind_generated(script, workflow)
    if duty['name'] not in FOCUSED:
        # Package-domain and final source-carrier closure are separate data
        # obligations. A focused capsule cannot grant their authority.
        raise RuntimeError('primary_full_or_package_closure_missing')
    commands = [shlex.split(line) for line in script.decode().splitlines()]
    if any(not row or row[0] != 'uv' for row in commands):
        raise RuntimeError('primary_focused_renderer_drift')
    return {'schema': 'unrest.v046.primary-script-plan.v1', 'duty': duty['name'],
            'script_sha256': duty['script_sha256'], 'workflow_sha256': sha(workflow.encode()),
            'shell_argv': [SHELL, *SHELL_FLAGS, '/inputs/github-script.sh'],
            'commands': commands, 'source_checkpoint_ready': False, 'selected_carrier': None,
            'timeout_seconds': 180}


def environment():
    return {'HOME': '/work/home', 'PATH': '/opt/source-bootstrap/bin:/usr/local/bin:/usr/bin:/bin',
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TMPDIR': '/work/tmp',
            'UV_CACHE_DIR': '/work/cache', 'UV_OFFLINE': '1', 'UV_NO_INDEX': '1',
            'UV_FIND_LINKS': '/opt/source-bootstrap/wheelhouse',
            'UV_PYTHON': PYTHON, 'UV_PYTHON_DOWNLOADS': 'never',
            'UV_CONFIG_FILE': '/inputs/uv.toml', 'PYTHONDONTWRITEBYTECODE': '1',
            'SOURCE_DATE_EPOCH': '1700000000', 'GITHUB_WORKSPACE': '/source'}


def command_environment(value, root):
    """Only Bash and pinned UV's documented finite additions are admissible."""
    actual = dict(value)
    virtual = actual.pop('VIRTUAL_ENV', None)
    build = Path(virtual) if isinstance(virtual, str) else None
    if (virtual is not None and virtual != '/source/.venv'
            and not (build.parent == Path('/work/cache/builds-v0') and build.name.startswith('.tmp')
                     and build.resolve() == build)):
        return False
    recursion = actual.pop('UV_RUN_RECURSION_DEPTH', None)
    if recursion not in (None, '1'):
        return False
    for key, allowed in {'PWD': {'/source'}, 'OLDPWD': {'/source'}, 'SHLVL': {'0', '1'},
                         '_': {SHELL, UV}, 'UV': {UV}, 'VIRTUAL_ENV': {'/source/.venv'},
                         'PYTHONIOENCODING': {'utf-8:backslashreplace'}}.items():
        if key in actual and actual.pop(key) not in allowed:
            return False
    path = actual.pop('PATH', None)
    if path not in {root['PATH'], '/source/.venv/bin:' + root['PATH'],
                    (virtual + '/bin:' + root['PATH']) if virtual else root['PATH']}:
        return False
    return actual == {key: value for key, value in root.items() if key != 'PATH'}


def backend_request(script, cache='/work/cache'):
    """Exact pinned UV PEP517 renderer; output paths remain finite owned data."""
    import ast
    try:
        nodes = ast.parse(script).body
        request = nodes[-1].items[0].context_expr.args[0].value
    except (SyntaxError, AttributeError, IndexError):
        return None
    path = Path(request)
    if (path.parent.parent != Path(cache) / 'builds-v0' or not path.parent.name.startswith('.tmp')
            or path.resolve() != path):
        return None
    prefix = ('import sys\n\nif sys.path[0] == "":\n    sys.path.pop(0)\n\n'
              'sys.path = [] + sys.path\n\nimport setuptools.build_meta as backend\n')
    requires = (prefix + '\nimport json\n\nget_requires_for_build = getattr(backend, "get_requires_for_build_editable", None)\n'
                'if get_requires_for_build:\n    requires = get_requires_for_build({})\nelse:\n    requires = []\n\n'
                f'with open("{request}", "w") as fp:\n    json.dump(requires, fp)\n')
    if path.name == 'get_requires_for_build_editable.txt' and script == requires:
        return 'get_requires_for_build_editable'
    # The output directory is a native UV-owned sibling of the response file.
    calls = [node for node in ast.walk(ast.parse(script)) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == 'build_editable']
    if len(calls) != 1 or len(calls[0].args) != 3 or not isinstance(calls[0].args[0], ast.Constant):
        return None
    output = calls[0].args[0].value
    if not isinstance(output, str):
        return None
    target = Path(output)
    if (target.resolve() != target or not target.is_relative_to(cache)
            or not any(target.is_relative_to(Path(cache) / name)
                       for name in ('builds-v0', 'built-wheels-v5'))):
        return None
    build = (prefix + f'\n\nwheel_filename = backend.build_editable("{output}", {{}}, None)\n'
             f'with open("{request}", "w") as fp:\n    fp.write(wheel_filename)\n')
    if path.name == 'build_editable.txt' and script == build:
        return 'build_editable'
    return None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def console(name):
    entries = {'unrest': ('unrest_harness.cli', 'cli'),
               'unrest-server': ('unrest_harness.server', 'main'),
               'mypy': ('mypy.__main__', 'console_entry')}
    module, function = entries[name]
    return ('#!/source/.venv/bin/python\n# -*- coding: utf-8 -*-\n'
            'import sys\nfrom ' + module + ' import ' + function + '\n'
            'if __name__ == "__main__":\n'
            '    if sys.argv[0].endswith("-script.pyw"):\n'
            '        sys.argv[0] = sys.argv[0][:-11]\n'
            '    elif sys.argv[0].endswith(".exe"):\n'
            '        sys.argv[0] = sys.argv[0][:-4]\n'
            '    sys.exit(' + function + '())\n').encode()
