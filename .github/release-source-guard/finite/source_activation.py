"""Exact original Operations callers; no arbitrary root/interpreter exemption."""

from __future__ import annotations
import inspect
import os
from pathlib import Path
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


class SourceActivation(IsolatedActivation):
    def __init__(self, *args):
        super().__init__(*args)
        self.direct = None
        self.cache_after_build = None

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

    def before_python(self, argv, cwd, environment, registration=None):
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

        if self.direct != (
            argv,
            str(Path(cwd or os.getcwd()).resolve()),
            dict(os.environ if environment is None else environment),
        ):
            self.refuse("source_direct_profile_drift")
        self.shared()
        self.direct = None


def create(state, emit, refuse, ready):
    return SourceActivation(state, emit, refuse, ready)
