"""Prepared original callers for the finite workspace/evolution Git family.

This selector reconstructs commands; the observer still owns launch permission,
filesystem/native custody, original-parent waits and causal value registration.
"""
from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
import subprocess
import sys
import types

from content_manifest import Refused
from git_commands import build, FIELDS, path
from git_sites import CASES, PINS, SITES, OWNED_SITE, OWNED_BODY
from source_calls import TestSources
from source_owner import Link, active_frames, frame_fields, instance_fields

PATH_TYPE = type(Path('/'))


def path_text(value):
    if type(value) not in (str, PATH_TYPE):
        raise Refused('git source path primitive')
    result = str(value)
    path(result)
    return result


class GitCalls(TestSources):
    def __init__(self, policy, item):
        test = item.nodeid.split('::', 1)[0]
        if item.nodeid not in CASES:
            raise Refused('git exact original case')
        super().__init__(policy, item, test, PINS)
        self.family = 'workspaces' if test.endswith('test_workspaces.py') else 'evolution'
        self.repository: str | None = None
        self.sources, self.owners = {}, {}
        self.integrations: dict[str, tuple[str, tuple[str, ...]]] = {}
        self.run = subprocess.run
        self.run_code, self.run_globals = self.run.__code__, self.run.__globals__
        for name in PINS:
            module = self.tests if name == test else None if name.startswith('tests/') else importlib.import_module(name.removeprefix('src/').removesuffix('.py').replace('/', '.'))
            if module is not None:
                self.sources[name] = (module, self.test_unit if module is self.tests else self.unit(name, module, self.mode(module)))
        self.record_types = {}
        for name, typename in (('workspaces', 'WorkspaceLease'), ('workspaces', 'OwnedProcess'), ('evolution', 'PromotionRecord')):
            module = self.sources['src/unrest_harness/' + name + '.py'][0]
            self.record_types[name, typename] = (module, vars(module)[typename])
        for name, qualified, _ in SITES:
            if name in self.sources:
                self.owner_for(name, qualified)
        self.startup = self
        self.pending, self.owned_pid, self.native_pin = None, None, None

    def owner_for(self, name, qualified):
        key = (name, qualified)
        if key in self.owners:
            return self.owners[key]
        module, unit = self.sources[name]
        parts = qualified.split('.')
        container = module if len(parts) == 1 else vars(module)[parts[0]]
        function = vars(container)[parts[-1]]
        links = (Link(container, parts[-1], function),)
        defaults = ()
        if qualified == 'repository':
            fields = instance_fields(function)
            fixture = function
            function = fields['_fixture_function']
            links = (*links, Link(fields, '_fixture_function', function))
            from _pytest.fixtures import FixtureFunctionDefinition
            if type(fixture) is not FixtureFunctionDefinition:
                raise Refused('git original fixture descriptor')
        if len(parts) == 2:
            links = (Link(module, parts[0], container), *links)
        if qualified == 'WorkspaceManager.lease_workspace':
            cls = vars(module)['ResourceBudget']
            if type(function) is not types.FunctionType or type(function.__kwdefaults__) is not dict:
                raise Refused('git original lease defaults')
            anchor = function.__kwdefaults__['resource_budget']
            defaults = ((anchor, cls, (('max_patch_bytes', 10000000), ('max_processes', 0))),)
            links = (*links, Link(module, 'ResourceBudget', cls))
        result = self.owner(unit, module, function, qualified, links, default_objects=defaults)
        self.owners[key] = result
        return result

    def signal(self, pid, sig, group):
        if self.case_item.nodeid != CASES[7] or pid != self.owned_pid or type(pid) is not int or type(sig) is not int or type(group) is not bool or sig not in (0, 9, 15):
            raise Refused('workspace exact owned process signal')
        frames = active_frames()
        try:
            self.test_owner.current(frames)
            module = 'src/unrest_harness/workspaces.py'
            drains = [f for f in frames if f.f_code.co_qualname == 'WorkspaceManager._drain_owned_processes']
            if sig or drains:
                owner = self.owner_for(module, 'WorkspaceManager._drain_owned_processes')
                local = frame_fields(owner.current(frames))
                process = self.record(local.get('process'), 'workspaces', 'OwnedProcess')
                if process['pid'] != pid or process['process_group_id'] != pid:
                    raise Refused('workspace signal registry binding')
                if sig and (not group or instance_fields(local['self'])['_live_processes'].get(pid) is not self.policy.children[pid]['process']):
                    raise Refused('workspace original live process handle')
            elif group:
                raise Refused('workspace probe group signal')
        finally:
            del frames

    def listener(self):
        raise Refused('git selector has no listener authority')

    def select(self, case, arguments):
        from controlled_startup import Intent
        from git_observer import image
        from launch_policy import Rule, render
        if type(case) is not str or case != self.case_item.nodeid:
            raise Refused('git selected launch case')
        executable, vector, cwd, environment = arguments
        owned = vector == [self.profile['native'], '-c', OWNED_BODY]
        if owned:
            site, fields, command = OWNED_SITE, {}, None
            frames = active_frames()
            try:
                self.test_owner.current(frames)
                local = frame_fields(self.owner_for(*OWNED_SITE[:2]).current(frames, line=OWNED_SITE[2]))
                lease = self.record(local.get('lease'), 'workspaces', 'WorkspaceLease')
                if case != CASES[7] or self.owned_pid is not None or path_text(cwd) != self.repository + '/.unrest-runtime/workspaces/trees/process' or lease['worktree_path'] != path_text(cwd):
                    raise Refused('workspace original owned launch')
                constructors = [f for f in frames if f.f_code is self.policy.constructor_code and f.f_globals is self.policy.constructor_globals]
                if len(constructors) != 1:
                    raise Refused('workspace original process constructor')
                options = frame_fields(constructors[0])
                if (any(type(options.get(k)) is not int or options[k] != -3 for k in ('stdin', 'stdout', 'stderr'))
                        or options.get('start_new_session') is not True or options.get('shell') is not False
                        or options.get('preexec_fn') is not None or options.get('pass_fds') != ()):
                    raise Refused('workspace exact owned process options')
            finally:
                del frames
            argv, native, pin, kind, body_pin = tuple(vector), self.profile['native'], self.profile['native_sha256'], 'python-command', hashlib.sha256(OWNED_BODY.encode()).hexdigest()
            phase = 'call'
        else:
            site, operation, fields, command = self.select_command()
            if vector != list(command.argv) or path_text(cwd) != command.cwd or executable != 'git':
                raise Refused('git exact audited command')
            if self.native_pin is None:
                self.native_pin = image()
            argv, native, pin, kind, body_pin = command.argv, '/usr/bin/git', self.native_pin, 'native', None
            phase = 'setup' if site[1] == 'repository' else 'call'
        env = {**self.profile['environment'], 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (' + phase + ')', **({} if owned else dict(command.additions))}
        if environment is not None and (type(environment) is not dict or any(type(k) is not str or type(v) is not str for k, v in environment.items()) or environment != env):
            raise Refused('git exact audited environment')
        owner = site[0] + ':' + site[1] + ':' + str(site[2])
        rule = Rule('workspace:owned' if owned else 'git:' + operation, owner, (case,), native, pin, argv, tuple(sorted(env.items())), path_text(cwd), kind, body_pin)
        expected = render(rule, case, owner, {}, {})
        wire_fields = {k: [list(row) for row in v] if k == 'leases' else list(v) if k == 'new_inputs' else v for k, v in fields.items()}
        self.pending = ({'site': list(site), 'repository': self.repository, 'fields': wire_fields}, command)
        translated = (argv[0], '-I', '-S', *argv[1:]) if owned else argv
        return Intent(expected, translated, site[2], body_pin)

    def select_command(self):
        if type(self.policy.case) is not str or self.policy.case != self.case_item.nodeid:
            raise Refused('git current selected case')
        frames = active_frames()
        try:
            matches = [(site, operation, frame) for site, operation in SITES.items()
                if site[:2] in self.owners for frame in frames
                if frame.f_code is self.owners[site[:2]].function.__code__ and frame.f_lineno == site[2]]
            if len(matches) != 1:
                raise Refused('git unique original callsite')
            site, operation, frame = matches[0]
            name, qualified, line = site
            self.owners[site[:2]].verify(frame)
            local = frame_fields(frame)
            fixture = qualified == 'repository'
            if fixture:
                root, temporary = path_text(local.get('root')), path_text(local.get('tmp_path'))
                if root != str(Path(temporary) / 'project') or not Path(temporary).is_relative_to(Path(self.profile['owned']) / 'pytest'):
                    raise Refused('git original fixture owned root')
                if self.repository is None and operation == 'init':
                    self.repository = root
                if self.repository != root:
                    raise Refused('git fixture repository generation')
            else:
                self.test_owner.current(frames)
            if self.repository is None:
                raise Refused('git fixture root not established')
            # The original helper's source and arguments are checked separately
            # from the caller that supplies the operation's dynamic operands.
            helper = None
            if name.startswith('tests/'):
                helper = self.owner_for(name, '_git').current(frames, line=31 if self.family == 'workspaces' else 35)
                cwd = path_text(frame_fields(helper).get('repository'))
            elif qualified not in ('WorkspaceManager._inventory', 'WorkspaceManager._build_integration_commit',
                                    'EvolutionManager._restore_exact_predecessor', '_validate_git_index') or line not in (1002, 650, 1889, 386):
                helper_name = 'WorkspaceManager._git' if name.endswith('workspaces.py') else 'EvolutionManager._git'
                helper = self.owner_for(name, helper_name).current(frames, line=222 if name.endswith('workspaces.py') else 1064)
                values = frame_fields(helper)
                instance = values.get('self')
                cls = vars(self.sources[name][0])[helper_name.split('.')[0]]
                if type(instance) is not cls or path_text(instance_fields(instance).get('repository')) != self.repository:
                    raise Refused('git original manager repository')
                selected_cwd = values.get('cwd')
                if selected_cwd is not None and type(selected_cwd) is not PATH_TYPE:
                    raise Refused('git helper cwd type')
                cwd = path_text(instance_fields(instance)['repository'] if selected_cwd is None else selected_cwd)
            else:
                cwd = path_text(local.get('worktree') if operation in ('inventory', 'check-index') else local.get('integration_tree') if operation == 'commit-tree' else self.repository)
            fields = self.operands(operation, local)
            command = build(operation, self.repository, cwd, fields, family=self.family)
            run_frame = [f for f in frames if f.f_code is self.run_code and f.f_globals is self.run_globals]
            if len(run_frame) != 1 or subprocess.run is not self.run:
                raise Refused('git original subprocess run')
            self.check_run(frame_fields(run_frame[0]), name, line, command)
            return site, operation, fields, command
        finally:
            del frames

    def record(self, value, module, name):
        source, cls = self.record_types[module, name]
        if (type(source) is not types.ModuleType or sys.modules.get(source.__name__) is not source
                or vars(source).get(name) is not cls or type(value) is not cls):
            raise Refused('git original typed record')
        return instance_fields(value)

    def operands(self, operation, local):
        result = {}
        lease = self.record(local['lease'], 'workspaces', 'WorkspaceLease') if 'lease' in local else {}
        promotion = self.record(local['promotion'], 'evolution', 'PromotionRecord') if 'promotion' in local else {}
        for key in FIELDS[operation]:
            if key == 'revision':
                value = promotion.get('predecessor_revision') if operation.startswith('rollback-') else lease.get('base_revision') if operation == 'diff-return' else local.get('base_revision') if operation in ('verify-base', 'lease-add', 'checkout') else local.get('commit') if operation == 'reset-parent' else local.get('predecessor')
            elif key == 'tree':
                value = local.get('worktree') if 'worktree' in local else local.get('integration_tree') if 'integration_tree' in local else local.get('tree')
                value = path_text(value)
            elif key == 'patch':
                patch = lease.get('patch_digest')
                if type(patch) is not str or not patch.startswith('sha256:'):
                    raise Refused('git original patch digest')
                value = self.repository + '/.unrest/workspaces/patches/' + patch[7:] + '.patch'
            elif key == 'tree_id':
                value = local.get('tree')
            elif key == 'date':
                value = local.get('predecessor_time')
            elif key == 'leases':
                ordered = local.get('ordered')
                if type(ordered) not in (tuple, list) or not 0 < len(ordered) <= 128:
                    raise Refused('git original ordered leases')
                value = tuple((self.record(item, 'workspaces', 'WorkspaceLease').get('lease_id'), self.record(item, 'workspaces', 'WorkspaceLease').get('patch_digest')) for item in ordered)
            elif key in ('new', 'old'):
                value = promotion.get('predecessor_revision' if key == 'new' else 'accepted_revision') if operation == 'rollback-update' else local.get('commit' if key == 'new' else 'predecessor')
            else:
                commit = local.get('commit')
                if type(commit) is not str or commit not in self.integrations:
                    raise Refused('git exact integration result')
                location, inputs = self.integrations[commit]
                value = location if key == 'new_location' else inputs
            result[key] = value
        return result

    def check_run(self, local, source, line, command):
        arguments, kwargs = local.get('popenargs'), local.get('kwargs')
        if type(arguments) is not tuple or len(arguments) != 1 or type(arguments[0]) is not list or any(type(v) is not str for v in arguments[0]) or tuple(arguments[0]) != command.argv:
            raise Refused('git original run argv')
        if type(kwargs) is not dict or any(type(k) is not str for k in kwargs):
            raise Refused('git run keyword primitives')
        direct_bytes = line in (1002, 1889, 386)
        product_helper = source.startswith('src/') and line not in (1002, 650, 1889, 386)
        expected = {'cwd': kwargs.get('cwd'), 'stdout': -1, 'stderr': -1}
        if not direct_bytes:
            expected['text'] = True
        if product_helper:
            expected.update(encoding='utf-8', errors='strict')
            if source.endswith('workspaces.py'):
                expected['env'] = None
        if line == 650:
            expected['stdin'] = -1
            expected['env'] = {**self.profile['environment'], 'PYTEST_VERSION': '9.0.2',
                'PYTEST_CURRENT_TEST': self.case_item.nodeid + ' (call)', **dict(command.additions)}
        check = line not in (662, 713, 719, 1072, 1889, 386)
        if (set(kwargs) != set(expected) or path_text(kwargs.get('cwd')) != command.cwd
                or local.get('capture_output') is not True or local.get('timeout') is not None
                or type(local.get('check')) is not bool or local['check'] != check
                or type(local.get('input')) is not type(command.stdin) or local['input'] != command.stdin):
            raise Refused('git exact original run options')
        for key in expected.keys() - {'cwd', 'env'}:
            if type(kwargs[key]) is not type(expected[key]) or kwargs[key] != expected[key]:
                raise Refused('git exact run option value')
        if line == 650 and (type(kwargs['env']) is not dict
                or any(type(k) is not str or type(v) is not str for k, v in kwargs['env'].items())
                or kwargs['env'] != expected['env']):
            raise Refused('git exact integration environment')
        if 'env' in kwargs and line != 650 and kwargs['env'] is not None:
            raise Refused('git unexpected environment override')
