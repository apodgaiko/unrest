"""Actual isolated helper activation seam; original source routes still refuse."""
from __future__ import annotations

import ast
import inspect
import json
import os
from pathlib import Path

from operation_activation import identity, tree, hashed, source_code
from isolated_inputs import runtime


def read_spec(state):
    support = state['isolated_support']
    if identity(support['spec_path'])['sha256'] != support['spec_sha256']:
        raise RuntimeError('isolated_profile_source_drift')
    return json.loads(Path(support['spec_path']).read_text())


def resolve_runtime(state, executable):
    return runtime(read_spec(state), executable)


class IsolatedActivation:
    def __init__(self, state, emit, refuse, ready):
        self.state, self.emit, self.refuse, self.ready = state, emit, refuse, ready
        self.spec = read_spec(state)
        self.record = None

    def validate(self):
        self.ready(self.state['token'])
        query = self.spec.get('query_support')
        if query is not None:
            item = query['interface']
            if identity(item['path']) != item:
                self.refuse('query_interface_source_drift')
            namespace = {'__name__': '_query_interface', '__file__': item['path']}
            exec(compile(Path(item['path']).read_bytes(), item['path'], 'exec', dont_inherit=True), namespace)
            try:
                namespace['validate'](self.spec)
            except RuntimeError as error:
                self.refuse(str(error))
        for expected in self.spec['files']:
            if identity(expected['path']) != expected:
                self.refuse('isolated_parent_input_drift')
        for path, expected in self.spec['trees'].items():
            if tree(path) != expected:
                self.refuse('isolated_parent_membership_drift')

    def __call__(self, record):
        current = inspect.currentframe()
        if current is None or current.f_back is None:
            raise RuntimeError('isolated_activation_frame_missing')
        frame = current.f_back
        operations = self.state['operations']
        if (frame.f_code is not operations.activation.__func__.__code__
                or frame.f_locals.get('self') is not operations or self.record is not record):
            self.refuse('isolated_not_actual_operation_owned')
        self.validate()
        self.emit({'kind': 'isolated_parent_consumption', 'record_sha256': hashed(record),
                   'wheel': identity(self.spec['wheel']),
                   'profile': identity(self.state['isolated_support']['spec_path']),
                   'python_generated_startup': 'STATIC pinned UV renderer plus authenticated wheel',
                   'pre_callback_native_enforcement': 'UNVERIFIED', 'original_source_coverage': False})

    def admit_prototype(self, argv, cwd, environment):
        consumer = self.spec.get('consumer_profile')
        if consumer is not None and argv == consumer['argv']:
            if str(Path(cwd or os.getcwd()).resolve()) != consumer['cwd'] or dict(environment) != consumer['environment']:
                self.refuse('isolated_consumer_vector_drift')
            self.validate()
            support = self.spec['installed_support']
            data = Path(support['path']).read_bytes()
            if identity(support['path'])['sha256'] != support['sha256']:
                self.refuse('isolated_installed_support_drift')
            namespace = {'__name__': '_installed_outputs', '__file__': support['path']}
            exec(compile(data, support['path'], 'exec', dont_inherit=True), namespace)
            mapping = namespace['inspect_install'](Path(self.spec['produced_wheel']), Path(self.spec['installed_site']),
                                                   self.spec['base'], self.spec['expected_entries'])
            if mapping != self.spec['installed_mapping']:
                self.refuse('isolated_installed_consumption_drift')
            self.emit({'kind': 'isolated_installed_consumption', 'mapping_sha256': hashed(mapping),
                       'source_function': 'run_consumer', 'original_source_coverage': False})
            frames = inspect.stack()
            try:
                found = [f.frame for f in frames if f.function == 'run_consumer' and f.filename == self.spec['caller']['path']]
                if len(found) != 1:
                    self.refuse('isolated_consumer_source_owner_missing')
                source_code(found[0], {'path': self.spec['caller']['path'], 'function': 'run_consumer', 'file': self.spec['caller']})
            finally:
                del frames
            return {'class': 'isolated-installed-consumer', 'python': True, 'source_binding': self.spec['caller']}
        if argv[0] != self.spec['uv']['path']:
            return None
        profile = self.spec['profile']
        env = dict(os.environ if environment is None else environment)
        if (argv != profile['argv'] or str(Path(cwd or os.getcwd()).resolve()) != profile['cwd']
                or env != profile['environment']):
            self.refuse('isolated_unknown_operation_vector')
        frames = inspect.stack()
        try:
            function = self.spec.get('caller_function', 'run_uv')
            found = [f.frame for f in frames if f.function == function
                     and f.filename == self.spec['caller']['path']]
            if len(found) != 1:
                self.refuse('isolated_source_owner_missing')
            source_code(found[0], {'path': self.spec['caller']['path'], 'function': function,
                                   'file': self.spec['caller']})
        finally:
            del frames
        self.record = {'operation': self.spec.get('operation', 'isolated-scratch-wheel'), 'argv_sha256': hashed(argv),
                       'environment_sha256': hashed(env), 'caller': self.spec['caller']}
        self.state['operations'].activation(self.record)
        return {'class': self.spec.get('operation', 'isolated-scratch-wheel'), 'python': False, 'source_binding': self.spec['caller']}

    def before_python(self, argv, cwd, environment):
        consumer = self.spec.get('consumer_profile')
        if consumer is not None and argv == consumer['argv']:
            self.validate()
            return
        self.refuse('isolated_unknown_direct_python')

    def generated_helper(self, script):
        try:
            return helper_class(script, self.spec)
        except (RuntimeError, SyntaxError, TypeError, ValueError) as error:
            self.refuse('isolated_generated_helper:' + type(error).__name__)
            raise RuntimeError('refusal callback returned') from error


def helper_class(script, spec):
    nodes = ast.parse(script).body
    try:
        request = nodes[-1].items[0].context_expr.args[0].value
    except (AttributeError, IndexError):
        raise RuntimeError('isolated_unknown_helper') from None
    path = Path(request)
    if (path.parent.parent != Path(spec['cache']) / 'builds-v0'
            or not path.parent.name.startswith('.tmp') or path.resolve() != path):
        raise RuntimeError('isolated_helper_request_lineage')
    prefix = ('import sys\n\nif sys.path[0] == "":\n    sys.path.pop(0)\n\n'
              'sys.path = [] + sys.path\n\nimport setuptools.build_meta as backend\n')
    kinds = ['wheel', 'sdist'] if spec['full_build'] else ['wheel']
    for kind in kinds:
        requires = (prefix + '\nimport json\n\nget_requires_for_build = getattr(backend, "get_requires_for_build_' + kind + '", None)\n'
                    'if get_requires_for_build:\n    requires = get_requires_for_build({})\nelse:\n    requires = []\n\n'
                    f'with open("{request}", "w") as fp:\n    json.dump(requires, fp)\n')
        extra = ', None' if kind == 'wheel' else ''
        build = (prefix + f'\n\n{kind}_filename = backend.build_{kind}("{spec.get("output", spec["root"] + "/dist")}", {{}}{extra})\n'
                 f'with open("{request}", "w") as fp:\n    fp.write({kind}_filename)\n')
        if path.name == f'get_requires_for_build_{kind}.txt' and script == requires:
            return f'get_requires_for_build_{kind}'
        if path.name == f'build_{kind}.txt' and script == build:
            return f'build_{kind}'
    raise RuntimeError('isolated_unknown_helper_renderer')


def create(state, emit, refuse, ready):
    return IsolatedActivation(state, emit, refuse, ready)
