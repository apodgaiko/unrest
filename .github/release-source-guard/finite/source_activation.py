"""Exact original Operations callers; no arbitrary root/interpreter exemption."""

from __future__ import annotations
import inspect
import ast
import json
import os
from pathlib import Path
import sys
from isolated_activation import IsolatedActivation
from operation_activation import identity, hashed, tree
import zipfile

CONSUMERS = frozenset(
    {
        "source-checker",
        "source-extracted-oracle",
        "source-installed-provenance",
        "source-installed-lifecycle",
        "source-cli-matrix",
        "source-installed-provider-matrix",
    }
)

# These are existing resolver outputs, not executable or class-prefix grants.
# Each still needs its original resolver and the live guard consumption frame.
ORDINARY_DIRECT = frozenset({
    "canonical-backend", "source-cleanup-adapter", "source-crash-controller",
    "source-session-child", "source-session-helper:timeout",
    "source-isolated-precaptured-refusal", "source-seeded-environment-helper",
    "source-owned-role:worker", "source-owned-role:validator",
    "source-owned-role:terminal-reviewer",
    "source-benchmark-five-run", "source-foreign-journal-owner",
    "source-storage-fresh-reader", "source-recovery-cli", "source-recovery-role",
    "source-run-worker", "source-composed-adapter", "source-speed-nested-exact",
    "source-project-projection", "source-checker-empty-archive-control",
    "source-completion-helper:test_consumed_marker_survives_recovery_interruption",
    "source-completion-helper:test_process_dies_during_first_setup",
    "source-completion-helper:test_real_roles_first_use",
    "source-cohort2:ownership-stdio", "source-cohort2:mock-agent",
    "source-cohort3:mock-agent", "source-cohort4:desktop-stdio",
    "source-copied-repository-cli", "source-registered-workspace-cli",
    "source-approval-mcp", "source-approval-adapter", "source-approval-relay",
    "source-approval-python-backend",
})


class SourceActivation(IsolatedActivation):
    def __init__(self, *args):
        super().__init__(*args)
        self.direct = None
        self.cache_after_build = None
        self.python_consumed = set()

    def produced(self, record):
        if record["operation"] == "source-build":
            self.cache_after_build = self.cache_tree()
            self.emit(
                {
                    "kind": "source_build_cache_output",
                    "source_build_token": record["token"],
                    "cache": self.cache_after_build,
                    "native_writer": "STATIC trusted/UNVERIFIED",
                }
            )

    def cache_tree(self):
        root = Path(self.spec["cache"])
        rows = []
        links = [p for p in root.rglob("*") if p.is_symlink()]
        if len(links) != 1:
            self.refuse("source_cache_link_cardinality")
        link = links[0]
        parts = link.relative_to(root).parts
        target = link.resolve()
        if (
            len(parts) != 5
            or parts[:2] != ("wheels-v6", "index")
            or parts[3:] != ("setuptools", "84.0.0-py3-none-any")
            or target.parent != root / "archive-v0"
            or target.is_symlink()
        ):
            self.refuse("source_cache_unknown_link")
        with zipfile.ZipFile(self.spec["wheel"]) as archive:
            payload = {n: archive.read(n) for n in archive.namelist() if not n.endswith("/")}
        actual = {
            p.relative_to(target).as_posix(): p.read_bytes()
            for p in target.rglob("*")
            if p.is_file()
        }
        if actual != payload:
            self.refuse("source_cache_selected_wheel_drift")
        fixed = {
            ".gitignore": b"*",
            ".lock": b"",
            "CACHEDIR.TAG": b"Signature: 8a477f597d28d172789f06886806bc55",
            "sdists-v9/.git": b"",
            "sdists-v9/.gitignore": b"",
        }
        for p in sorted(root.rglob("*")):
            name = p.relative_to(root).as_posix()
            if p.is_symlink():
                rows.append({"path": str(p), "target": str(target), "inode": p.lstat().st_ino})
            elif p.is_dir():
                info = p.lstat()
                rows.append({"path": str(p), "directory": [info.st_dev, info.st_ino, info.st_mode]})
            else:
                if not p.is_relative_to(target):
                    components = p.relative_to(root).parts
                    permitted = (
                        len(components) == 3
                        and components[0] == "interpreter-v4"
                        and p.suffix == ".msgpack"
                    ) or name == str(link.relative_to(root)) + ".rev"
                    if name in fixed:
                        if p.read_bytes() != fixed[name]:
                            self.refuse("source_cache_metadata_drift")
                    elif not permitted:
                        self.refuse("source_cache_unknown_member")
                rows.append(identity(p))
        return rows

    def shared(self):
        self.ready(self.state["token"])
        for item in self.spec["shared_files"]:
            if identity(item["path"]) != item:
                self.refuse("source_shared_startup_file_drift")
        for path, expected in self.spec["shared_trees"].items():
            if tree(path) != expected:
                self.refuse("source_shared_startup_membership_drift")
        for path in self.spec["shared_absent"]:
            if Path(path).exists() or Path(path).is_symlink():
                self.refuse("source_shared_unknown_startup")
        link = self.spec["shared_python_link"]
        path = Path(link["path"])
        if (
            not path.is_symlink()
            or str(path.resolve()) != link["target"]
            or path.lstat().st_ino != link["inode"]
        ):
            self.refuse("source_shared_interpreter_link_drift")
        self.state["operations"].inputs()

    def __call__(self, record):
        current = inspect.currentframe()
        if current is None or current.f_back is None:
            self.refuse("source_activation_frame_missing")
            raise RuntimeError("refusal callback returned")
        frame = current.f_back
        operations = self.state["operations"]
        if (
            frame.f_code is not operations.activation.__func__.__code__
            or frame.f_locals.get("self") is not operations
            or frame.f_locals.get("record") is not record
        ):
            self.refuse("source_activation_not_owned")
        origin = frame.f_back
        if origin is None or origin.f_code not in (
            operations.make.__func__.__code__,
            operations.registration.__func__.__code__,
        ):
            self.refuse("source_activation_not_resolved")
            raise RuntimeError("refusal callback returned")
        local = origin.f_locals
        if record["inputs"] != operations.inputs():
            self.refuse("source_activation_input_binding_drift")
        operation = record["operation"]
        if operation == "source-build":
            if self.spec.get('native_preinit'):
                if (origin.f_code is not operations.make.__func__.__code__
                        or local['record'] is not record
                        or record['binding']['function'] != 'built_distribution'
                        or record['binding']['path'] not in {
                            self.spec['project'] + '/tests/contracts/conftest.py',
                            self.spec['project'] + '/tests/test_distribution_check.py'}):
                    self.refuse('native_original_producer_binding_drift')
                # These parameters come from the already source/code/caller/AST-
                # checked Operations.make frame, not a payload-supplied profile.
                profile = {'argv': list(local['argv']), 'cwd': str(local['directory']),
                           'environment': dict(local['environment'])}
                self.spec['profile'] = profile
                self.spec['output'] = str(local['output'])
                self.spec['source_binding'] = record['binding']
                record['native_profile'] = {**profile, 'output': self.spec['output'],
                                             'source_binding': record['binding']}
            profile = self.spec["profile"]
            if (
                origin.f_code is not operations.make.__func__.__code__
                or local["argv"] != profile["argv"]
                or str(local["directory"]) != profile["cwd"]
                or local["environment"] != profile["environment"]
                or str(local["output"]) != self.spec["output"]
                or local["record"] is not record
                or record["binding"] != self.spec["source_binding"]
            ):
                self.refuse("source_activation_original_producer_drift")
            if operations.spec["backend_distribution"] != self.spec["backend_distribution"]:
                self.refuse("source_backend_selection_drift")
            self.validate()
            self.record = record
            self.emit(
                {
                    "kind": "isolated_parent_consumption",
                    "record_sha256": hashed(record),
                    "wheel": identity(self.spec["wheel"]),
                    "profile": identity(self.state["isolated_support"]["spec_path"]),
                    "binding": record["binding"],
                    "operation_token": record["token"],
                    "original_source_coverage": True,
                    "pre_callback_native_enforcement": "UNVERIFIED",
                }
            )
        elif operation == "source-install":
            if self.spec.get('native_preinit'):
                record['native_profile'] = {
                    'argv': list(local['argv']), 'cwd': str(local['directory']),
                    'environment': dict(local['environment']), 'output': str(local['output']),
                    'source_binding': record['binding']}
            # The producing source operation must already have actually returned
            # and waited its UV handle. Cache is captured from that settled build.
            build = operations.require(self.spec["output"], "source-build")
            self.shared()
            snapshot = self.cache_tree()
            if self.cache_after_build is None:
                self.refuse("source_cache_producer_return_missing")
            if snapshot != self.cache_after_build:
                self.refuse("source_install_produced_cache_drift")
            self.emit(
                {
                    "kind": "source_install_startup_consumption",
                    "source_build_token": build["token"],
                    "record_sha256": hashed(record),
                    "cache_sha256": hashed(snapshot),
                    "selected_python": self.spec["query_python"],
                    "native_internal_query_cache": "STATIC trusted/UNVERIFIED",
                }
            )
        elif operation in CONSUMERS:
            if origin.f_code is not operations.registration.__func__.__code__:
                self.refuse("source_consumer_not_registered")
            self.shared()
            self.direct = (list(local["argv"]), str(local["directory"]), dict(local["environment"]))
            self.emit(
                {
                    "kind": "source_consumer_startup_consumption",
                    "operation": operation,
                    "binding": record["binding"],
                    "argv_sha256": record["argv_sha256"],
                    "shared_startup_seal": True,
                    "original_source_coverage": True,
                }
            )
        else:
            self.refuse("source_unknown_operation")

    def admit_prototype(self, argv, cwd, environment):
        profiles = [p for p in self.spec.get("console_profiles", []) if p["argv"] == argv]
        if not profiles:
            return None
        if len(profiles) != 1:
            self.refuse("console_profile_cardinality")
        profile = profiles[0]
        if (
            str(Path(cwd or os.getcwd()).resolve()) != profile["cwd"]
            or dict(environment) != profile["environment"]
        ):
            self.refuse("console_profile_drift")
        caller = self.spec["console_caller"]
        frames = inspect.stack()
        try:
            found = [
                f.frame
                for f in frames
                if f.function == "run_console" and f.filename == caller["path"]
            ]
            if len(found) != 1:
                self.refuse("console_caller_missing")
            from operation_activation import source_code

            source_code(
                found[0], {"path": caller["path"], "function": "run_console", "file": caller}
            )
        finally:
            del frames
        self.shared()
        install = self.state["operations"].require(self.spec["console_site"], "source-install")
        item = self.spec["query_support"]["interface"]
        if identity(item["path"]) != item:
            self.refuse("console_interface_drift")
        namespace = {"__name__": "_query_interface", "__file__": item["path"]}
        exec(
            compile(Path(item["path"]).read_bytes(), item["path"], "exec", dont_inherit=True),
            namespace,
        )
        namespace["validate"](self.spec, child=True)
        self.emit(
            {
                "kind": "source_console_prelaunch",
                "source_install_token": install["token"],
                "argv_sha256": hashed(argv),
                "startup_seal": True,
                "caller": caller,
            }
        )
        return {"class": "source-generated-console", "python": False, "source_binding": caller}

    def python_launch(self, argv, cwd, environment, registration):
        """Consume this callback only from the current, byte-bound guard frame."""
        guard = sys.modules.get('runtime_guard')
        current = inspect.currentframe()
        frame = current.f_back.f_back if current is not None and current.f_back else None
        path = Path(self.state['guard'])
        if (guard is None or frame is None or frame.f_globals is not vars(guard)
                or guard._STATE is not self.state
                or guard.digest(path) != self.state['guard_sha256']):
            self.refuse('source_python_guard_owner_drift')
        expected = self.state['isolated_named'](
            compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), 'initialize_inner')
        local = frame.f_locals
        if (frame.f_code != expected or local.get('state') is not self.state
                or local.get('activation') is not self
                or local.get('registration') is not registration
                or local.get('argv') is not argv
                or cwd != local['kwargs'].get('cwd')
                or environment != local['kwargs'].get('env')):
            self.refuse('source_python_not_current_launch')
        token = local.get('launch_token')
        if (not isinstance(token, str) or len(token) != 32
                or any(c not in '0123456789abcdef' for c in token)
                or token in self.python_consumed):
            self.refuse('source_python_duplicate_consumption')
        if guard.digest(local['manifest']) != local['pin']:
            self.refuse('source_python_manifest_drift')
        sealed = json.loads(Path(local['manifest']).read_bytes())
        if (any(self.state[key] != sealed[key] for key in (
                'owned_root', 'checkout', 'registry', 'direct_support', 'product_pins'))
                or any(self.state['runtime'][key] != sealed['runtime'][key]
                       for key in ('realpath', 'sha256'))):
            self.refuse('source_python_root_runtime_drift')
        self.ready(self.state['token'])
        self.python_consumed.add(token)
        return guard, local

    def ordinary_python(self, guard, launch, argv, cwd, environment, registration):
        """Re-resolve an existing ordinary source registration, never a producer."""
        name = registration['class']
        registry = self.state['registry']
        original = guard.checked_source(registry['path'], registry['sha256'])['COMMANDS']
        members = [r for r in self.state['commands'] if r is registration]
        if members:
            if not registration.get('python') or registration not in original:
                self.refuse('source_ordinary_registry_drift')
            runtime = self.state['runtime']
            directory = Path(cwd or os.getcwd()).resolve()
            source = Path(registration['source_binding']['path'])
            if not source.is_absolute():
                source = Path(self.state['checkout']) / source
            if (argv[0] not in runtime['paths']
                    or str(Path(argv[0]).resolve()) != runtime['realpath']
                    or guard.digest(argv[0]) != runtime['sha256']
                    or len(argv[1:]) != len(registration['argv'])
                    or not all(guard.match_arg(a, b) for a, b in zip(
                        argv[1:], registration['argv'], strict=True))
                    or not (directory.is_relative_to(Path(self.state['owned_root']))
                            or registration['checkout_cwd']
                            and directory == Path(self.state['checkout']))
                    or guard.digest(source) != registration['source_binding']['sha256']
                    or any(guard.digest(p) != pin for p, pin in registration.get('files', {}).items())
                    or 'script_sha256' in registration
                    and guard.digest(argv[1]) != registration['script_sha256']):
                self.refuse('source_ordinary_profile_drift')
            # HTTP admission already consumed its thread/frame port token. Do
            # not recreate it or rerun that destructive selector. Re-evaluate
            # the original source expression/code/globals against this vector.
            path = Path(self.state['guard']).with_name('fallback_binding.py')
            binding = guard.checked_source(path, self.state['direct_support']['files'][str(path)])
            if binding['matches'](registration, argv, cwd, environment, self.state) is None:
                self.refuse('source_ordinary_caller_drift')
        else:
            names = set(ORDINARY_DIRECT)
            path = Path(self.state['guard']).with_name('source_bindings.py')
            data = guard.checked_source(path, self.state['direct_support']['files'][str(path)])['DATA']
            names.update('reference:' + row['module'] for row in data['selections'])
            for cohort in (2, 3, 4):
                filename = 'cohort_routes.py' if cohort == 2 else f'cohort{cohort}_routes.py'
                path = Path(self.state['guard']).with_name(filename)
                pin = self.state['direct_support']['files'].get(str(path))
                if pin is None:
                    continue
                if guard.digest(path) != pin:
                    self.refuse('source_ordinary_resolver_drift')
                sites = next(ast.literal_eval(n.value) for n in ast.parse(path.read_bytes()).body
                             if isinstance(n, ast.Assign)
                             and any(isinstance(t, ast.Name) and t.id == 'SITES' for t in n.targets))
                names.update(f'source-cohort{cohort}:{relative}:{line}'
                             for relative, lines in sites.items() for line in lines)
            if name not in names:
                self.refuse('source_unknown_python_registration')
            path = Path(self.state['guard']).with_name('fallback_binding.py')
            frames = guard.checked_source(
                path, self.state['direct_support']['files'][str(path)])['active_frames']()
            try:
                bound = registration['source_binding']
                source = Path(bound['path'])
                if not source.is_absolute():
                    source = Path(self.state['checkout']) / source
                owned = False
                for frame in frames:
                    payload = self.state.get('registered_payload')
                    if (payload is not None and payload['mode'] == 'inline'
                            and frame.f_globals is self.state.get('payload_globals')
                            and payload['source_binding']['path'] == str(source)
                            and payload['source_binding']['sha256'] == bound['sha256']):
                        code = self.state['payload_code']
                    elif Path(frame.f_code.co_filename) == source:
                        module = sys.modules.get(frame.f_globals.get('__name__'))
                        if module is None or vars(module) is not frame.f_globals:
                            continue
                        if guard.digest(source) != bound['sha256']:
                            self.refuse('source_ordinary_owner_source_drift')
                        code = self.state['isolated_source_code'](source)
                    else:
                        continue
                    expected = (code if frame.f_code.co_name == '<module>' else
                                self.state['isolated_named'](code, frame.f_code.co_name))
                    if frame.f_code == expected:
                        owned = True
                if not owned:
                    self.refuse('source_ordinary_owner_code_globals_drift')
            finally:
                frames.clear()
            # Use the original input vector for routes with an exact console
            # translation; compare the resulting vector as well as the binding.
            actual, vector = guard.admit(launch['args'], cwd, environment)
            if actual != registration or vector != argv:
                self.refuse('source_ordinary_registration_drift')
        self.shared()
        self.emit({'kind': 'source_ordinary_startup_consumption', 'class': name,
                   'source_binding': registration['source_binding'],
                   'launch_token': launch['launch_token'], 'shared_startup_seal': True})

    def before_python(self, argv, cwd, environment, registration=None):
        if registration is not None:
            guard, launch = self.python_launch(argv, cwd, environment, registration)
        reference_classes = frozenset({"reference-integrity:test_skips", "reference-integrity:test_passes",
                                       "reference-integrity:test_fails", "reference-integrity:test_waits"})
        if registration is not None and registration['class'] in reference_classes:
            # Re-resolve the exact original frame/vector/root; a class name alone
            # never substitutes for the finite reference binding.
            actual = self.state['direct_admit'](argv, cwd, environment, self.state, self.emit, self.refuse)
            if actual != registration:
                self.refuse("source_reference_registration_drift")
            self.shared()
            self.emit({"kind": "source_reference_startup_consumption", "class": registration['class'],
                       "source_binding": registration['source_binding'], "shared_startup_seal": True})
            return

        if registration is not None and registration['class'] not in CONSUMERS:
            self.ordinary_python(guard, launch, argv, cwd, environment, registration)
            return

        if self.direct != (
            argv,
            str(Path(cwd or os.getcwd()).resolve()),
            dict(os.environ if environment is None else environment),
        ):
            self.refuse("source_direct_profile_drift")
        self.shared()
        self.direct = None
        self.emit({'kind': 'source_producer_python_startup_consumption',
                   'class': registration['class'] if registration is not None else None,
                   'shared_startup_seal': True})


def create(state, emit, refuse, ready):
    return SourceActivation(state, emit, refuse, ready)
