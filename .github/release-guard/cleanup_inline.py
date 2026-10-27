"""Closed original inline cleanup cases; declarations alone grant no execution."""
from __future__ import annotations

from typing import Any, cast

from content_manifest import Refused
from cleanup_launch import TEST, Launches as SharedLaunches

SLEEP = 'import time; time.sleep(30)'
EXIT = "import sys; print('private-startup-body',file=sys.stderr); sys.exit(23)"
STARTUP = {TEST + f'::test_startup_failure_attribution_and_owned_cleanup[{variant}-{role}]':
           ('startup', variant, role) for variant in ('exit', 'deadline', 'cancel')
           for role in ('work', 'validate', 'terminal_reviewer')}
CLIENT = {TEST + '::test_client_cleanup_reaps_main_after_reader_failure': ('client', 'reader', None),
          **{TEST + f'::test_client_exhausts_terminals_pending_and_main[{variant}]':
             ('client', variant, None) for variant in ('False', 'True')}}
INFLIGHT = {TEST + f'::test_inflight_terminal_registration_before_inventory[{variant}]':
            ('inflight', variant, None) for variant in ('False', 'True')}
NO_LAUNCH = tuple(TEST + f'::test_response_correlation_keeps_numeric_identity[{variant}]'
                  for variant in ('1_0', '1_1', 'None', 'True', '1.0', 'rid5', 'rid6'))
DECLARATIONS = {**STARTUP, **CLIENT, **INFLIGHT}
CASES = (*DECLARATIONS, *NO_LAUNCH)


def declaration(case):
    if type(case) is not str or case not in CASES:
        raise Refused('cleanup inline finite case')
    return DECLARATIONS.get(case, ('no-launch', None, None))


def body(case):
    family, variant, _ = declaration(case)
    if family == 'no-launch':
        raise Refused('cleanup numeric case has no process authority')
    return EXIT if family == 'startup' and variant == 'exit' else SLEEP


def child_count(case):
    family, variant, _ = declaration(case)
    return 0 if family == 'no-launch' else 1 if family == 'startup' or variant == 'reader' else 3


def source_site(case, terminal=False):
    family, variant, _ = declaration(case)
    if terminal:
        if family != 'inflight':
            raise Refused('cleanup inline terminal outside inflight case')
        return 1034
    if family == 'no-launch':
        raise Refused('cleanup numeric case has no process authority')
    return 61 if family == 'startup' else 429 if family == 'inflight' else 269 if variant == 'reader' else 299


def scheduling_site(case):
    family, variant, _ = declaration(case)
    return 92 if family == 'startup' else 478 if family == 'inflight' else 321 if family == 'client' and variant != 'reader' else None


def expected(case, native, native_pin, checkout, root_environment, *, base=None, terminal=False):
    from launch_policy import Rule, render
    family, _, _ = declaration(case)
    site = source_site(case, terminal)
    if terminal:
        if base is None:
            raise Refused('cleanup inline missing owned fixture')
        cwd, environment = str(base), {}
        owner = 'src/unrest_harness/acp_runner.py:ACPClient._handle_terminal_create'
    else:
        cwd = str(checkout)
        environment = {**root_environment, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'}
        owner = TEST + ':' + ('test_startup_failure_attribution_and_owned_cleanup.<locals>.start'
            if family == 'startup' else case.split('::')[1].split('[')[0])
    rule = Rule('cleanup-inline:' + ('terminal' if terminal else 'initial'), owner, (case,),
                native, native_pin, (native, '-c', body(case)), tuple(sorted(environment.items())),
                cwd, 'python-command', None)
    return render(rule, case, owner, {}, {}), site


def options(case, local, *, terminal=False):
    """Validate only primitive constructor fields; values do not select a case."""
    family, _, _ = declaration(case)
    from source_owner import _namespace
    local = _namespace(local)
    kw = _namespace(local.get('kwds'))
    for name in ('stdout', 'limit'):
        if type(local.get(name)) is not int:
            raise Refused('cleanup inline constructor primitives')
    if terminal:
        if (family != 'inflight' or set(kw) != {'cwd', 'env'} or type(kw['cwd']) is not str
                or type(kw['env']) is not dict or dict.__len__(kw['env']) != 0
                or local.get('stdin') is not None or type(local.get('stderr')) is not int
                or local['stderr'] != -2 or local['stdout'] != -1 or local['limit'] != 8 * 1024 * 1024):
            raise Refused('cleanup inline terminal options')
    elif (kw or local['stdout'] != -1 or local['limit'] != 65536
            or family == 'startup' and (local.get('stdin') is not None
                or type(local.get('stderr')) is not int or local['stderr'] != -1)
            or family != 'startup' and (type(local.get('stdin')) is not int
                or local['stdin'] != -1 or local.get('stderr') is not None)):
        raise Refused('cleanup inline initial options')


def frame_fields(frame):
    import types
    if type(frame) is not types.FrameType:
        raise Refused('cleanup inline actual frame')
    result: dict[str, Any] = {}
    for key, value in frame.f_locals.items():
        if type(key) is not str or len(result) >= 8192:
            raise Refused('cleanup inline frame fields')
        result[key] = value
    return result


def instance_fields(value):
    import types
    from source_owner import _namespace
    cls = type(value)
    # Native type descriptors avoid user-defined metaclass and __dict__ access.
    namespace_descriptor = vars(type)['__dict__']
    lineage_descriptor = vars(type)['__mro__']
    for parent in lineage_descriptor.__get__(cls, type(cls)):
        namespace = namespace_descriptor.__get__(parent, type(parent))
        fields: dict[str, Any] = {}
        for key, item in namespace.items():
            if type(key) is not str or len(fields) >= 8192:
                raise Refused('cleanup inline class namespace')
            fields[key] = item
        descriptor = fields.get('__dict__')
        if type(descriptor) not in (types.GetSetDescriptorType, types.MemberDescriptorType):
            continue
        native = cast(types.GetSetDescriptorType | types.MemberDescriptorType, descriptor)
        if native.__objclass__ is parent and native.__name__ == '__dict__':
            result = native.__get__(value, cls)
            _namespace(result)
            return result
    raise Refused('cleanup inline instance dictionary')


class Launches(SharedLaunches):
    """Acquire the original caller context once per finite inline launch."""
    def __init__(self, calls):
        super().__init__(calls)
        self.runner_type, self.client_type = self.module.ACPNodeRunner, self.module.ACPClient
        self.terminal_type = self.module.ManagedTerminal
        self.task_type = self.module.Task

    def children(self, values, maximum):
        import asyncio
        if type(values) is not list or len(values) > maximum:
            raise Refused('cleanup inline child list bound')
        for process in values:
            if type(process) is not asyncio.subprocess.Process:
                raise Refused('cleanup inline child type')
            fields = instance_fields(process)
            transport = fields.get('_transport')
            if type(transport) is not self.calls.transport_class:
                raise Refused('cleanup inline child transport')
            pid = fields.get('pid')
            if (type(pid) is not int or pid not in self.calls.policy.children
                    or instance_fields(transport).get('_proc') is not self.calls.policy.children[pid]['process']):
                raise Refused('cleanup inline child generation')

    def startup(self, case, frames, base):
        import types
        from source_owner import Link
        family, variant, role = declaration(case)
        if family != 'startup' or self.module.ACPNodeRunner is not self.runner_type:
            raise Refused('cleanup inline original startup class')
        name = '_run_terminal_review_lifecycle' if role == 'terminal_reviewer' else 'run_node'
        function = vars(self.runner_type)[name]
        owner = self.calls.owner(self.unit, self.module, function, 'ACPNodeRunner.' + name,
                                 (Link(self.module, 'ACPNodeRunner', self.runner_type), Link(self.runner_type, name, function)))
        matches = [frame for frame in frames if frame.f_code is function.__code__]
        if len(matches) != 1 or matches[0].f_lineno != (1969 if role == 'terminal_reviewer' else 1481):
            raise Refused('cleanup inline original startup invocation')
        owner.verify(matches[0])
        caller = frame_fields(matches[0])
        runner = caller.get('self')
        if (type(caller.get('workspace_dir')) is not str or caller['workspace_dir'] != str(base / 'workspace')
                or any(type(caller.get(key)) is not str or caller[key] != value for key, value in (
                    ('project_id', 'project'), ('mission_id', 'mission-001'), ('spawn_ts', 'startup')))):
            raise Refused('cleanup inline startup fixture context')
        if role != 'terminal_reviewer':
            task = caller.get('task')
            if type(task) is not self.task_type or self.module.Task is not self.task_type:
                raise Refused('cleanup inline startup task type')
            task_fields = instance_fields(task)
            if (type(task_fields.get('id')) is not str or task_fields['id'] != 'startup'
                    or type(task_fields.get('type')) is not str or task_fields['type'] != role
                    or type(task_fields.get('targets')) is not list or len(task_fields['targets']) != 0):
                raise Refused('cleanup inline startup task parameters')
        if type(runner) is not self.runner_type:
            raise Refused('cleanup inline startup instance')
        fields = instance_fields(runner)
        start = fields.get('_start_worker_mcp_server')
        if type(start) is not types.FunctionType or fields.get('_start_terminal_reviewer_mcp') is not start:
            raise Refused('cleanup inline exact startup wrapper')
        owner = self.calls.owner(self.calls.test_unit, self.calls.tests, start,
            'test_startup_failure_attribution_and_owned_cleanup.<locals>.start',
            (Link(fields, '_start_worker_mcp_server', start), Link(fields, '_start_terminal_reviewer_mcp', start)))
        matches = [frame for frame in frames if frame.f_code is start.__code__]
        if len(matches) != 1 or matches[0].f_lineno != 61:
            raise Refused('cleanup inline active startup wrapper')
        owner.verify(matches[0])
        values = frame_fields(matches[0])
        if (values.get('runner') is not runner or type(values.get('failure')) is not str
                or values['failure'] != variant):
            raise Refused('cleanup inline startup closure values')
        self.children(values.get('children'), 0)

    def terminal(self, frames):
        import asyncio
        import types
        from source_owner import Link, _namespace
        if self.module.ACPClient is not self.client_type:
            raise Refused('cleanup inline original client class')
        function = vars(self.client_type)['_handle_terminal_create']
        owner = self.calls.owner(self.unit, self.module, function, 'ACPClient._handle_terminal_create',
            (Link(self.module, 'ACPClient', self.client_type), Link(self.client_type, '_handle_terminal_create', function)))
        matches = [frame for frame in frames if frame.f_code is function.__code__]
        if len(matches) != 1 or matches[0].f_lineno != 1034:
            raise Refused('cleanup inline original terminal invocation')
        owner.verify(matches[0])
        local = frame_fields(matches[0])
        client = local.get('self')
        if type(client) is not self.client_type:
            raise Refused('cleanup inline original client instance')
        params = _namespace(local.get('params'))
        if (set(params) != {'command', 'args'} or type(params['command']) is not str
                or params['command'] != self.profile['native'] or type(params['args']) is not list
                or any(type(arg) is not str for arg in params['args']) or params['args'] != ['-c', SLEEP]):
            raise Refused('cleanup inline terminal parameters')
        wrapper = asyncio.create_subprocess_exec
        if type(wrapper) is not types.FunctionType:
            raise Refused('cleanup inline paused constructor type')
        owner = self.calls.owner(self.calls.test_unit, self.calls.tests, wrapper,
            'test_inflight_terminal_registration_before_inventory.<locals>.paused_spawn',
            (Link(asyncio, 'create_subprocess_exec', wrapper),))
        matches = [frame for frame in frames if frame.f_code is wrapper.__code__]
        if len(matches) != 1:
            raise Refused('cleanup inline paused constructor frame')
        owner.verify(matches[0])
        values = frame_fields(matches[0])
        if values.get('spawn') is not self.constructor:
            raise Refused('cleanup inline original retained constructor')
        children = values.get('children')
        self.children(children, 2)
        if type(children) is not list or len(children) != 2:
            raise Refused('cleanup inline initial child membership')
        fields = instance_fields(client)
        terminals = _namespace(fields.get('_terminals'))
        if fields.get('_process') is not children[0] or set(terminals) != {'existing'}:
            raise Refused('cleanup inline client child membership')
        terminal = terminals['existing']
        if (type(terminal) is not self.terminal_type or self.module.ManagedTerminal is not self.terminal_type
                or instance_fields(terminal).get('process') is not children[1]):
            raise Refused('cleanup inline existing terminal membership')

    def select(self, case, audit):
        import os
        import hashlib
        from pathlib import Path
        from controlled_startup import Intent
        from launch_policy import Observation, match
        from source_owner import active_frames, _namespace
        from cleanup_launch import base_path
        executable, vector, cwd, environment = audit
        if (type(executable) is not str or type(vector) is not list or len(vector) != 3
                or any(type(value) is not str for value in vector)):
            raise Refused('cleanup inline vector primitives')
        if type(case) is not str or case != self.calls.policy.case:
            raise Refused('cleanup inline externally selected case')
        family, _, _ = declaration(case)
        self.calls.test_owner.verify_binding()
        frames = active_frames()
        try:
            constructors = [frame for frame in frames if frame.f_code is self.constructor_code
                            and frame.f_globals is self.constructor.__globals__]
            if len(constructors) != 1:
                raise Refused('cleanup inline original asyncio constructor')
            local = frame_fields(constructors[0])
            terminal = family == 'inflight' and cwd is not None
            options(case, local, terminal=terminal)
            fixture = _namespace(self.calls.case_item.funcargs).get('tmp_path')
            if type(fixture) is not type(Path('/')):
                raise Refused('cleanup inline original fixture')
            base = base_path(str(fixture), Path(self.profile['owned']))
            if not terminal:
                import asyncio
                if asyncio.create_subprocess_exec is not self.constructor:
                    raise Refused('cleanup inline original constructor binding')
            if family == 'startup':
                self.startup(case, frames, base)
            elif terminal:
                self.terminal(frames)
            else:
                matches = [frame for frame in frames if frame.f_code is self.calls.test_owner.function.__code__]
                if len(matches) != 1 or matches[0].f_lineno != source_site(case):
                    raise Refused('cleanup inline original direct caller')
                self.calls.test_owner.verify(matches[0])
            result, site = expected(case, self.profile['native'], self.profile['native_sha256'],
                Path(self.profile['checkout']), self.profile['environment'], base=base, terminal=terminal)
            if executable != result.executable or (environment is not None and not terminal):
                raise Refused('cleanup inline executable or inherited environment')
            actual_environment = dict(os.environ) if environment is None else environment
            if type(actual_environment) is not dict or any(type(key) is not str or type(value) is not str for key, value in actual_environment.items()):
                raise Refused('cleanup inline environment primitives')
            actual_cwd = self.profile['checkout'] if cwd is None else cwd
            if type(actual_cwd) is not str:
                raise Refused('cleanup inline cwd primitive')
            match((result,), Observation(executable, result.executable_sha256, tuple(vector),
                tuple(sorted(actual_environment.items())), actual_cwd, 'python-command', hashlib.sha256(vector[2].encode()).hexdigest()), result.owner, case)
            return Intent(result, (executable, '-I', '-S', *vector[1:]), site, result.payload_sha256)
        finally:
            del frames
