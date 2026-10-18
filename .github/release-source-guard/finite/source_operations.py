"""Private operation wiring; no source-package acceptance or complete startup claim."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
from pathlib import Path, PosixPath
from pathlib._abc import _ignore_error  # type: ignore[import-not-found]
import shutil
import stat
import sys
import tarfile
import types
import uuid
import weakref
import zipfile
from typing import Any, Callable, NoReturn

ROOT = Path("/source")
SOURCE_PINS = {
    "tests/contracts/conftest.py": "97e2bc299d7a91353648bb6f55fe1dbaedd925cd1e3fe947e9c74280dc0a5aa8",
    "tests/test_distribution_check.py": "e906c51747e255c0f67c972681d40ac30e9a81c8d9a02939fbd312640ba66ab2",
    "tools/check_distribution.py": "7006e042a83a83e5581414fdebbf2389dcae85eee192e6b5cea3320037ff2745",
    "tests/contracts/test_lean_package.py": "45f8b2e7cd332dc6b9be9b1eaa7ed56f08c6eb07cc7ab75515a563f2135ad68f",
    "tests/contracts/test_lean_provider_security.py": "dcb8f7236331b2cc8e28654e7ad5bbb264b3bfa9e508800d76d2def9ef26f299",
}
SELECTED = {
    "tests/contracts/conftest.py": ("built_distribution", "_run_checked"),
    "tests/test_distribution_check.py": (
        "built_distribution",
        "_rewrite_sdist",
        "_mutated_distribution",
        "_run_checker",
        "test_checker_rejects_each_missing_or_changed_oracle_member",
        "test_extracted_oracle_cannot_borrow_an_omitted_fixture",
        "test_extracted_oracle_cannot_import_from_forced_checkout_path",
    ),
    "tools/check_distribution.py": (
        "_extract_sdist_safely",
        "_run_extracted_restart_oracle",
        "_check_extracted_restart_oracle",
    ),
    "tests/contracts/test_lean_package.py": ("_run_installed_lifecycle",),
    "tests/contracts/test_lean_provider_security.py": (
        "_run_cli_matrix",
        "test_installed_supported_provider_matrix",
        "test_copied_source_and_installed_cli_protect_precommand_credentials",
    ),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hashed(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def identity(path):
    pathname = str(path) if type(path) is PosixPath else str(Path(path))
    before = os.stat(pathname, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("operation input is not a regular file")
    fd = os.open(pathname, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("operation input replaced before read")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(fd)
    finally:
        os.close(fd)

    def key(s):
        return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode)

    before_key, after_key = key(before), key(after)
    if before_key != after_key or after_key != key(os.stat(pathname, follow_symlinks=False)):
        raise RuntimeError("operation input changed during capture")
    return {
        "path": pathname,
        "device": before.st_dev,
        "inode": before.st_ino,
        "size": before.st_size,
        "mode": before.st_mode,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
        "sha256": digest,
    }


def root_identity(root):
    path = Path(root)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.resolve() != path:
        raise RuntimeError("operation root is not a direct directory")
    return {"root": str(path), "device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode}


def _path_type(pathname, predicate, *, follow_symlinks=True):
    # Same pinned CPython error classification as Path.is_file/is_dir/is_symlink.
    try:
        return predicate(os.stat(pathname, follow_symlinks=follow_symlinks).st_mode)
    except OSError as error:
        if not _ignore_error(error):
            raise
        return False
    except ValueError:
        return False


def tree_identity(root):
    result = root_identity(root)
    files = []
    directories = []
    for path in sorted(Path(root).rglob("*"), key=lambda path: path.parts):
        pathname = str(path)
        if _path_type(pathname, stat.S_ISLNK, follow_symlinks=False):
            raise RuntimeError("operation tree contains a symlink")
        if _path_type(pathname, stat.S_ISREG):
            files.append(identity(path))
        elif _path_type(pathname, stat.S_ISDIR):
            directories.append(root_identity(path))
        else:
            raise RuntimeError("operation tree contains a special file")
    if root_identity(root) != result:
        raise RuntimeError("operation root replaced during capture")
    return {**result, "files": files, "directories": directories}


def archive_identity(path):
    result = identity(path)
    members = []
    if str(path).endswith(".whl"):
        with zipfile.ZipFile(path) as archive:
            for m in sorted(archive.infolist(), key=lambda v: v.filename):
                members.append(
                    {
                        "name": m.filename,
                        "size": m.file_size,
                        "mode": m.external_attr,
                        "sha256": sha(archive.read(m)),
                    }
                )
    elif str(path).endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            for tar_member in sorted(archive.getmembers(), key=lambda v: v.name):
                stream = archive.extractfile(tar_member) if tar_member.isfile() else None
                members.append(
                    {
                        "name": tar_member.name,
                        "size": tar_member.size,
                        "mode": tar_member.mode,
                        "type_sha256": sha(tar_member.type),
                        "linkname_sha256": sha(tar_member.linkname.encode()),
                        "sha256": sha(stream.read()) if stream is not None else None,
                    }
                )
    else:
        raise RuntimeError("unregistered archive format")
    if identity(path) != result:
        raise RuntimeError("archive changed during member capture")
    return {**result, "members": members, "functional_pass": False}


def code_objects(code):
    yield code
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            yield from code_objects(value)




def code_identity(code):
    def value(item):
        if isinstance(item, types.CodeType):
            return code_identity(item)
        if isinstance(item, bytes):
            return ["bytes", item.hex()]
        if isinstance(item, tuple):
            return ["tuple", [value(v) for v in item]]
        if isinstance(item, frozenset):
            return [
                "frozenset",
                sorted((value(v) for v in item), key=lambda v: json.dumps(v, sort_keys=True)),
            ]
        if item is None or type(item) in (bool, int, float, str):
            return [type(item).__name__, item]
        if isinstance(item, complex):
            return ["complex", item.real, item.imag]
        raise RuntimeError("unregistered source code constant")

    fields = (
        "co_argcount",
        "co_posonlyargcount",
        "co_kwonlyargcount",
        "co_nlocals",
        "co_stacksize",
        "co_flags",
        "co_code",
        "co_consts",
        "co_names",
        "co_varnames",
        "co_filename",
        "co_name",
        "co_qualname",
        "co_firstlineno",
        "co_linetable",
        "co_exceptiontable",
        "co_freevars",
        "co_cellvars",
    )
    return {key: value(getattr(code, key)) for key in fields}


def registrations():
    rows = []
    for relative, names in SELECTED.items():
        path = ROOT / relative
        data = path.read_bytes()
        if sha(data) != SOURCE_PINS[relative]:
            raise RuntimeError("producer registration source drift")
        compiled = list(code_objects(compile(data, str(path), "exec", dont_inherit=True)))
        for node in ast.parse(data).body:
            if isinstance(node, ast.FunctionDef) and node.name in names:
                line = min([node.lineno, *(n.lineno for n in node.decorator_list)])
                code = next(
                    c for c in compiled if c.co_name == node.name and c.co_firstlineno == line
                )
                rows.append(
                    {
                        "path": str(path),
                        "sha256": sha(data),
                        "function": node.name,
                        "line": line,
                        "ast_sha256": sha(ast.dump(node, include_attributes=False).encode()),
                        "calls": [
                            {
                                "line": n.lineno,
                                "ast_sha256": sha(ast.dump(n, include_attributes=False).encode()),
                            }
                            for n in sorted(
                                (n for n in ast.walk(node) if isinstance(n, ast.Call)),
                                key=lambda n: n.lineno,
                            )
                        ],
                        "_code": code,
                        "_pytest_code": None,
                        "_node": node,
                    }
                )
    return rows


REGISTRATIONS = registrations()
SOURCE_FRAME_PATHS = frozenset(str(ROOT / relative) for relative in SELECTED)


def public(binding):
    return {k: v for k, v in binding.items() if not k.startswith("_")}


def source_frame(frame, function, relative):
    binding = next(
        r for r in REGISTRATIONS if r["path"] == str(ROOT / relative) and r["function"] == function
    )
    if frame is not None and frame.f_code != binding['_code'] and binding['_pytest_code'] is None:
        rewrite = sys.modules.get('_pytest.assertion.rewrite')
        path = ROOT / relative
        if rewrite is not None and path.is_relative_to(ROOT / 'tests'):
            body = path.read_bytes()
            tree = ast.parse(body, filename=str(path))
            rewrite.rewrite_asserts(tree, body, str(path))
            code = compile(tree, str(path), 'exec', dont_inherit=True)
            binding['_pytest_code'] = next(item for item in code_objects(code)
                                            if item.co_qualname == binding['_code'].co_qualname)
    if (
        frame is None
        or (
            frame.f_code != binding["_code"]
            and (binding["_pytest_code"] is None
                 or hashed(code_identity(frame.f_code)) != hashed(code_identity(binding["_pytest_code"])))
        )
        or sha((ROOT / relative).read_bytes()) != binding["sha256"]
    ):
        raise RuntimeError("operation frame/source mismatch")
    return binding


def find_frame(function, relative):
    frame = inspect.currentframe()
    try:
        while frame:
            if frame.f_code.co_name == function and frame.f_code.co_filename == str(
                ROOT / relative
            ):
                source_frame(frame, function, relative)
                return frame
            frame = frame.f_back
        return None
    finally:
        del frame


def literal(function, relative, name):
    row = next(
        r for r in REGISTRATIONS if r["function"] == function and r["path"] == str(ROOT / relative)
    )
    node = next(
        n
        for n in ast.walk(row["_node"])
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)
    )
    return ast.literal_eval(node.value)


def relative_files(tree):
    return {str(Path(r["path"]).relative_to(tree["root"])): r for r in tree["files"]}


def compare_payload_trees(source, target):
    a, b = relative_files(source), relative_files(target)
    if set(a) != set(b) or any(
        (a[k]["sha256"], a[k]["size"]) != (b[k]["sha256"], b[k]["size"]) for k in a
    ):
        raise RuntimeError("copied source payload mismatch")


def extraction_mapping(archive, tree):
    roots = {Path(m["name"]).parts[0] for m in archive["members"]}
    if len(roots) != 1:
        raise RuntimeError("extraction archive is not single-root")
    root = next(iter(roots))
    members = {
        str(Path(m["name"]).relative_to(root)): m
        for m in archive["members"]
        if m["sha256"] is not None
    }
    files = relative_files(tree)
    if set(members) != set(files) or any(members[k]["sha256"] != files[k]["sha256"] for k in files):
        raise RuntimeError("extraction member mapping mismatch")
    return [{"member": k, "file": files[k]} for k in sorted(files)]


def installed_mapping(wheel, site, support, executable, cache_writers=None):
    # This is an inspector, not an admission or synthetic producing receipt.
    # Actual source install settlement still requires its retained owner wait
    # and independently selected interpreter profile at the caller below.
    data = Path(support["path"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != support["sha256"]:
        raise RuntimeError("source_installed_mapping_support_drift")
    namespace = {"__name__": "_installed_outputs", "__file__": support["path"]}
    exec(compile(data, support["path"], "exec", dont_inherit=True), namespace)
    return namespace["inspect_install"](
        Path(wheel["path"]),
        Path(site["root"]),
        executable,
        {"unrest": "unrest_harness.cli:cli", "unrest-server": "unrest_harness.server:main"},
        cache_writers=cache_writers,
    )


def owned_wait(state, handle):
    """Retained object identity plus direct owner's actual OS wait journal."""
    if not any((h() if isinstance(h, weakref.ReferenceType) else h) is handle for h in state["handles"]):
        raise RuntimeError("actual owned handle unavailable")
    rows = [
        json.loads(line)
        for p in sorted(Path(state["events"]).glob("*.jsonl"))
        for line in p.read_text().splitlines()
    ]
    launches = [
        r
        for r in rows
        if r["kind"] == "registered" and r["pid"] == handle.pid and r["owner_pid"] == os.getpid()
    ]
    waits = [
        r
        for r in rows
        if r["kind"] == "actual_waitpid"
        and r["pid"] == handle.pid
        and r["owner_pid"] == os.getpid()
    ]
    if len(launches) != 1 or len(waits) != 1:
        raise RuntimeError("actual registered launch/OS wait unavailable")
    admitted = [
        r
        for r in rows
        if r["kind"] == "admitted"
        and r["token"] == launches[0]["token"]
        and r["owner_pid"] == os.getpid()
    ]
    if len(admitted) != 1:
        raise RuntimeError("actual admission unavailable")
    return {
        "launch_token": launches[0]["token"],
        "argv_sha256": admitted[0]["argv_sha256"],
        "pid": handle.pid,
        "numeric_returncode": waits[0]["numeric_returncode"],
    }


diagnostic_seen = set()


def _diagnostic_mark(owner, phase):
    if phase not in {'operation_inputs_enter', 'operation_input_files_end', 'operation_input_trees_end'}:
        raise ValueError('unknown operation diagnostic phase')
    guard = sys.modules.get('runtime_guard')
    mark = getattr(guard, '_diagnostic_mark', None)
    key = (os.getpid(), phase)
    if getattr(owner, 'diagnostic_inputs', False) and mark is not None and key not in diagnostic_seen:
        diagnostic_seen.add(key)
        mark(phase)


class Operations:
    """Callbacks are called by the checked guard, never by producer callers."""

    def __init__(self, state, emit, refuse: Callable[[str], NoReturn], require_ready):
        self.state, self.emit, self.refuse, self.ready = state, emit, refuse, require_ready
        self.pending: dict[str, Any] = {}
        self.settled: dict[tuple[str, str], Any] = {}
        self.active_files: dict[int, Any] = {}
        self.handles: dict[int, str] = {}
        self.waits: dict[int, int] = {}
        self.cache_writers: dict[str, list[dict[str, Any]]] = {}
        self.spec = state["operation_spec"]

    def inputs(self):
        _diagnostic_mark(self, "operation_inputs_enter")
        observed = []
        for expected in self.spec["files"]:
            current = identity(expected["path"])
            if current != expected:
                self.refuse("source_operation_input_drift")
            observed.append(current)
        _diagnostic_mark(self, "operation_input_files_end")
        for tree in self.spec["trees"]:
            if tree_identity(tree["root"]) != tree:
                self.refuse("source_operation_dependency_site_drift")
        _diagnostic_mark(self, "operation_input_trees_end")
        return {"files_sha256": hashed(observed), "trees_sha256": hashed(self.spec["trees"])}

    def activation(self, record):
        self.ready(self.state["token"])
        # The startup callback is loaded from pinned private support by install.
        # No READY flag or caller-supplied activation receipt can satisfy this seam.
        callback = self.state.get("operation_activation")
        if callback is None:
            self.refuse("source_operation_startup_activation_unavailable")
        callback(record)

    def own(self, root):
        root = Path(root)
        allowed = Path(self.state["owned_root"])
        if (
            not root.is_absolute()
            or ".." in root.parts
            or root == allowed
            or not root.resolve().is_relative_to(allowed)
        ):
            self.refuse("source_operation_root_not_owned")
        return root

    def rows(self):
        return [
            json.loads(line)
            for p in sorted(Path(self.state["events"]).glob("*.jsonl"))
            for line in p.read_text().splitlines()
        ]

    def make(self, kind, frame, binding, output, argv, directory, environment, **extra):
        output = self.own(output)
        if output.exists():
            before = tree_identity(output)
            if before["files"] or before["directories"]:
                self.refuse("source_operation_output_not_fresh")
        else:
            before = {"absent": str(output), "parent": root_identity(output.parent)}
        token = uuid.uuid4().hex
        record = {
            "kind": "operation_admission",
            "operation": kind,
            "token": token,
            "owner_pid": os.getpid(),
            "binding": public(binding),
            "output": str(output),
            "preimage": before,
            "argv_sha256": sha(json.dumps(argv).encode()),
            "cwd": str(directory),
            "environment_sha256": hashed(environment),
            "inputs": self.inputs(),
            "settled": False,
            **extra,
        }
        self.activation(record)
        self.pending[token] = {"record": record, "frame": frame, "handle": None, "returned": False}
        self.emit(record)
        return {
            "class": kind,
            "python": False,
            "source_binding": public(binding),
            "operation_token": token,
        }

    def admit(self, argv, cwd, env):
        callback = self.state.get("operation_activation")
        if callback is not None:
            prototype = callback.admit_prototype(argv, cwd, env)
            if prototype is not None:
                return prototype
        directory = Path(cwd or os.getcwd()).resolve()
        environment = dict(os.environ if env is None else env)
        cf = "tests/contracts/conftest.py"
        df = "tests/test_distribution_check.py"
        checked, fixture = find_frame("_run_checked", cf), find_frame("built_distribution", cf)
        distributed = find_frame("built_distribution", df)
        if checked is not None and fixture is not None:
            local = fixture.f_locals
            if argv == [local["uv"], "build", "--out-dir", str(local["dist"])]:
                if directory != local["repository_root"] or environment != local["child_env"]:
                    self.refuse("source_build_inputs_mismatch")
                self.tool(argv[0], environment)
                return self.make(
                    "source-build",
                    checked,
                    source_frame(fixture, "built_distribution", cf),
                    local["dist"],
                    argv,
                    directory,
                    environment,
                )
            if len(argv) > 1 and argv[1:3] == ["pip", "install"]:
                expected = [
                    local["uv"],
                    "pip",
                    "install",
                    "--target",
                    str(local["environment"]),
                    "--no-deps",
                    "--force-reinstall",
                    str(local["wheel"]),
                ]
                build = self.require(local["dist"], "source-build")
                if (
                    argv != expected
                    or directory != local["root"]
                    or environment != local["child_env"]
                ):
                    self.refuse("source_install_inputs_mismatch")
                self.tool(argv[0], environment)
                return self.make(
                    "source-install",
                    checked,
                    source_frame(fixture, "built_distribution", cf),
                    local["environment"],
                    argv,
                    directory,
                    environment,
                    parent_token=build["token"],
                    wheel=archive_identity(local["wheel"]),
                )
        if distributed is not None:
            local = distributed.f_locals
            if argv == ["uv", "build", "--out-dir", str(local["dist"])]:
                if directory != ROOT or environment != local["environment"]:
                    self.refuse("distribution_build_inputs_mismatch")
                self.tool(argv[0], environment)
                return self.make(
                    "source-build",
                    distributed,
                    source_frame(distributed, "built_distribution", df),
                    local["dist"],
                    argv,
                    directory,
                    environment,
                )
        return self.consumer(argv, directory, environment)

    def tool(self, executable, environment):
        path = shutil.which(executable, path=environment.get("PATH"))
        if path is None or identity(Path(path).resolve()) != self.spec["uv"]:
            self.refuse("source_operation_tool_mismatch")
        if self.spec.get("backend_distribution") is None:
            self.refuse("source_operation_backend_selection_unsealed")

    def retained(self, registration, handle, launch_token):
        token = registration.get("operation_token")
        if token is None:
            return
        pending = self.pending.get(token)
        if (
            pending is None
            or pending["handle"] is not None
            or not any((h() if isinstance(h, weakref.ReferenceType) else h) is handle for h in self.state["handles"])
        ):
            self.refuse("source_operation_handle_custody_mismatch")
        pending["handle"] = handle
        pending["record"]["launch_token"] = launch_token
        self.handles[handle.pid] = token
        self.emit(
            {
                "kind": "operation_retained",
                "token": token,
                "launch_token": launch_token,
                "pid": handle.pid,
            }
        )

    def waited(self, pid, returncode):
        token = self.handles.get(pid)
        if token is not None:
            if pid in self.waits:
                self.refuse("source_operation_duplicate_actual_wait")
            self.waits[pid] = returncode
            self.emit(
                {
                    "kind": "operation_actual_wait",
                    "token": token,
                    "pid": pid,
                    "numeric_returncode": returncode,
                }
            )

    def returned(self, frame, value):
        for token, pending in list(self.pending.items()):
            if frame is not pending["frame"]:
                continue
            handle = pending["handle"]
            completed = frame.f_locals.get("completed", frame.f_locals.get("result"))
            if (
                handle is None
                or not any((h() if isinstance(h, weakref.ReferenceType) else h) is handle for h in self.state["handles"])
                or self.waits.get(handle.pid) != 0
                or completed is None
                or completed.returncode != 0
                or value is None
            ):
                self.emit(
                    {
                        "kind": "operation_failed",
                        "token": token,
                        "reason": "return_or_actual_wait_incomplete",
                    }
                )
                del self.pending[token]
                continue
            self.ready(self.state["token"])
            record = pending["record"]
            observed_wait = owned_wait(self.state, handle)
            if (
                observed_wait["launch_token"] != record["launch_token"]
                or observed_wait["argv_sha256"] != record["argv_sha256"]
                or observed_wait["numeric_returncode"] != 0
            ):
                self.refuse("source_operation_settlement_actual_wait_mismatch")
            if self.inputs() != record["inputs"]:
                self.refuse("source_operation_inputs_changed_before_settlement")
            before = record["preimage"]
            if "absent" in before:
                if root_identity(Path(before["absent"]).parent) != before["parent"]:
                    self.refuse("source_operation_parent_replaced")
            elif root_identity(record["output"]) != {
                k: v for k, v in before.items() if k not in ("files", "directories")
            }:
                self.refuse("source_operation_output_root_replaced")
            tree = tree_identity(record["output"])
            observed = {"tree": tree}
            if record["operation"] == "source-build":
                wheels, sdists = (
                    sorted(Path(record["output"]).glob("*.whl")),
                    sorted(Path(record["output"]).glob("*.tar.gz")),
                )
                marker = Path(record["output"]) / ".gitignore"
                if (
                    marker.read_bytes() != b"*"
                    or {Path(v["path"]).name for v in tree["files"]}
                    != {
                        wheels[0].name if len(wheels) == 1 else "",
                        sdists[0].name if len(sdists) == 1 else "",
                        ".gitignore",
                    }
                    or tree["directories"]
                ):
                    self.refuse("source_build_generated_marker_or_membership")
                if len(wheels) != 1 or len(sdists) != 1 or len(tree["files"]) != 3:
                    self.refuse("source_build_output_cardinality")
                observed["archives"] = [archive_identity(p) for p in wheels + sdists]
            else:
                support = self.spec.get("mapping_support")
                selected = self.spec.get("installed_interpreter")
                if support is None or selected is None:
                    self.refuse("source_install_mapping_or_interpreter_selection_unobserved")
                route = Path(selected["path"])
                if (
                    identity(route.resolve()) != selected["file"]
                    or not route.is_symlink()
                    or route.lstat().st_ino != selected["link_inode"]
                ):
                    self.refuse("source_install_selected_interpreter_drift")
                returns = [
                    r
                    for r in self.rows()
                    if r["kind"] == "query_actual_main_return"
                    and r["info"]["sys_executable"] == selected["path"]
                    and r["parent_pid"] == handle.pid
                ]
                if len(returns) != 1:
                    self.refuse("source_install_query_selection_missing")
                observed["mapping"] = installed_mapping(
                    record["wheel"], tree, support, selected["path"]
                )
                if not observed["mapping"]["complete_generated_file_mapping"]:
                    self.refuse("source_install_generated_mapping_incomplete")
            settled = {
                **record,
                "kind": "operation_settled",
                "settled": True,
                "output_identity": observed,
                "pid": handle.pid,
                "actual_wait_returncode": 0,
                "functional_pass": False,
            }
            self.settled[(record["output"], record["operation"])] = settled
            self.emit(settled)
            if self.state.get("source_activation_support") is not None:
                self.state["operation_activation"].produced(settled)
            del self.pending[token]

    def require(self, output, operation):
        record = self.settled.get((str(output), operation))
        if record is None or not record["settled"]:
            self.refuse("source_producing_operation_not_observed")
        current = tree_identity(output)
        if current != record["output_identity"]["tree"]:
            if operation != "source-install" or self.spec.get("cache_source") is None:
                self.refuse("source_producing_output_drift")
            original = record["output_identity"]["tree"]
            old = relative_files(original)
            new = relative_files(current)
            if any(new.get(n) != v for n, v in old.items()):
                self.refuse("source_cached_install_original_member_drift")
            extras = set(new) - set(old)
            rows = self.rows()
            source = self.spec["cache_source"]
            writers = []
            for name in sorted(extras):
                if not name.endswith(".pyc"):
                    self.refuse("source_cached_install_unknown_member")
                matched = [
                    r
                    for r in rows
                    if r["kind"] == "actual_cache_writer_return"
                    and r["cache"] == str(Path(output) / name)
                    and r["cache_sha256"] == new[name]["sha256"]
                    and r.get("cache_identity")
                    == sys.modules["operation_activation"].identity(Path(output) / name)
                ]
                if len(matched) != 1:
                    self.refuse("source_cache_writer_not_observed")
                writer = matched[0]
                if writer["writer_code_sha256"] != source["writer_code_sha256"]:
                    self.refuse("source_cache_writer_code_drift")
                launches = [
                    r
                    for r in rows
                    if r["kind"] == "registered"
                    and r["pid"] == writer["owner_pid"]
                    and r["class"] == "source-cache-import"
                ]
                if len(launches) != 1:
                    self.refuse("source_cache_writer_registration_missing")
                launch = launches[0]
                admissions = [
                    r for r in rows if r["kind"] == "admitted" and r["token"] == launch["token"]
                ]
                if (
                    len(admissions) != 1
                    or admissions[0]["source_binding"]["path"] != source["path"]
                    or admissions[0]["source_binding"]["sha256"] != source["sha256"]
                    or admissions[0]["source_binding"].get("body") != source["body"]
                ):
                    self.refuse("source_cache_writer_caller_drift")
                waits = [
                    r
                    for r in rows
                    if r["kind"] == "actual_waitpid"
                    and r["pid"] == launch["pid"]
                    and r["owner_pid"] == launch["owner_pid"]
                ]
                imported = [
                    r
                    for r in rows
                    if r["kind"] == "actual_cache_import_return"
                    and r["owner_pid"] == launch["pid"]
                    and r["module"] == writer["source"]
                    and r["source_sha256"] == writer["source_sha256"]
                ]
                ready = [
                    r
                    for r in rows
                    if r["kind"] == "ready"
                    and r["owner_pid"] == launch["pid"]
                    and r["token"] == launch["token"]
                ]
                if (
                    len(waits) != 1
                    or waits[0]["numeric_returncode"] != 0
                    or len(imported) != 1
                    or len(ready) != 1
                ):
                    self.refuse("source_cache_writer_return_ready_or_actual_wait_missing")
                writers.append(writer)
            expected_dirs = {v["root"]: v for v in original["directories"]}
            actual_dirs = {v["root"]: v for v in current["directories"]}
            if any(actual_dirs.get(n) != v for n, v in expected_dirs.items()):
                self.refuse("source_cached_install_original_directory_drift")
            added_dirs = set(actual_dirs) - set(expected_dirs)
            if added_dirs != {str(Path(output) / n.parent) for n in map(Path, extras)}:
                self.refuse("source_cached_install_unknown_directory")
            mapping = installed_mapping(
                record["wheel"],
                current,
                self.spec["mapping_support"],
                self.spec["installed_interpreter"]["path"],
                writers,
            )
            if not mapping["complete_generated_file_mapping"]:
                self.refuse("source_cached_install_mapping_incomplete")
            self.cache_writers[str(output)] = writers
            self.emit(
                {
                    "kind": "source_install_cache_consumption",
                    "source_install_token": record["token"],
                    "mapping_sha256": hashed(mapping),
                    "writer_pids": [w["owner_pid"] for w in writers],
                    "actual_writer_and_owner_wait": True,
                }
            )
        for archive in record["output_identity"].get("archives", []):
            if archive_identity(archive["path"]) != archive:
                self.refuse("source_archive_member_drift")
        return record

    def inherited(self, references):
        rows = self.rows()

        def import_record(reference, seen):
            if reference["token"] in seen:
                self.refuse("source_operation_inheritance_cycle")
            seen = seen | {reference["token"]}
            matches = [
                r
                for r in rows
                if r.get("kind") in ("operation_settled", "file_operation_settled")
                and r.get("token") == reference["token"]
                and hashed(r) == reference["record_sha256"]
            ]
            if len(matches) != 1:
                self.refuse("source_operation_inheritance_journal_mismatch")
            record = matches[0]
            if record["owner_pid"] != reference["owner_pid"]:
                self.refuse("source_operation_inheritance_owner_mismatch")
            if record["kind"] == "operation_settled":
                if not any(
                    r["kind"] == "operation_actual_wait"
                    and r.get("token") == record["token"]
                    and r["owner_pid"] == record["owner_pid"]
                    and r["pid"] == record["pid"]
                    and r["numeric_returncode"] == 0
                    for r in rows
                ):
                    self.refuse("source_operation_inheritance_actual_wait_missing")
            else:
                parents = [
                    r
                    for r in rows
                    if r.get("kind") in ("operation_settled", "file_operation_settled")
                    and r.get("token") == record["parent_token"]
                ]
                if len(parents) != 1:
                    self.refuse("source_operation_inheritance_parent_missing")
                parent = parents[0]
                import_record(
                    {
                        "token": parent["token"],
                        "owner_pid": parent["owner_pid"],
                        "record_sha256": hashed(parent),
                    },
                    seen,
                )
            self.settled[(record["output"], record["operation"])] = record
            self.require(record["output"], record["operation"])

        for reference in references:
            import_record(reference, set())

    def reference(self, record):
        rows = [
            r
            for r in self.rows()
            if r.get("kind") in ("operation_settled", "file_operation_settled")
            and r.get("token") == record["token"]
        ]
        if len(rows) != 1:
            self.refuse("source_operation_journal_settlement_missing")
        return {
            "token": record["token"],
            "owner_pid": record["owner_pid"],
            "record_sha256": hashed(rows[0]),
        }

    def registration(self, name, frame, relative, argv, directory, environment, records):
        binding = source_frame(frame, frame.f_code.co_name, relative)
        self.activation(
            {
                "operation": name,
                "binding": public(binding),
                "inputs": self.inputs(),
                "argv_sha256": sha(json.dumps(argv).encode()),
                "cwd": str(directory),
                "environment_sha256": hashed(environment),
            }
        )
        return {
            "class": name,
            "python": True,
            "source_binding": public(binding),
            "operation_lineage": [self.reference(r) for r in records],
        }

    def consumer(self, argv, directory, environment):
        cf = "tests/contracts/conftest.py"
        df = "tests/test_distribution_check.py"
        checked = find_frame("_run_checked", cf)
        checktest = find_frame("_run_checker", df)
        frame = checktest or checked
        if frame is not None and len(argv) == 3 and argv[1] == "tools/check_distribution.py":
            local = frame.f_locals
            dist = local["dist"] if checktest else Path(local["command"][2])
            if (
                argv != [sys.executable, "tools/check_distribution.py", str(dist)]
                or directory != ROOT
            ):
                self.refuse("source_checker_vector_mismatch")
            expected_env = local["environment"] if checktest else local["env"]
            if environment != dict(os.environ if expected_env is None else expected_env):
                self.refuse("source_checker_environment_mismatch")
            operation = (
                "source-challenge"
                if (str(dist), "source-challenge") in self.settled
                else "source-build"
            )
            record = self.require(dist, operation)
            return self.registration(
                "source-checker",
                frame,
                df if checktest else cf,
                argv,
                directory,
                environment,
                [record],
            )
        oracle = find_frame("_run_extracted_restart_oracle", "tools/check_distribution.py")
        if oracle is not None:
            local = oracle.f_locals
            module = ast.parse((ROOT / "tools/check_distribution.py").read_bytes())
            probe = ast.literal_eval(
                next(
                    n.value
                    for n in module.body
                    if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "_PYTEST_PROBE" for t in n.targets)
                )
            )
            if argv != [
                str(local["candidate_python"]),
                "-c",
                probe,
                str(local["checkout_root"].resolve()),
            ]:
                self.refuse("source_oracle_vector_mismatch")
            if (
                directory != local["extracted_root"].resolve()
                or environment != local["environment"]
            ):
                self.refuse("source_oracle_inputs_mismatch")
            output = local["extracted_root"]
            record = self.settled.get((str(output), "source-extract"))
            if record is None:
                self.refuse("source_extraction_not_observed")
            parent = oracle.f_back
            challenge = None
            if parent is not None and parent.f_code.co_name in (
                "test_extracted_oracle_cannot_borrow_an_omitted_fixture",
                "test_extracted_oracle_cannot_import_from_forced_checkout_path",
            ):
                binding = source_frame(
                    parent, parent.f_code.co_name, "tests/test_distribution_check.py"
                )
                if parent.f_locals["extracted"] != output:
                    self.refuse("source_extraction_challenge_root_mismatch")
                before = record["output_identity"]["tree"]
                after = tree_identity(output)
                expected = json.loads(json.dumps(before))
                if (
                    parent.f_code.co_name
                    == "test_extracted_oracle_cannot_borrow_an_omitted_fixture"
                ):
                    removed = str(output / "tests/fixtures/persistence_schema_v1/corpus.json")
                    expected["files"] = [f for f in expected["files"] if f["path"] != removed]
                    challenge = "omitted-corpus"
                else:
                    original = str(output / "src/unrest_harness")
                    moved = str(output / "removed-unrest-harness")
                    for group in ("files", "directories"):
                        key = "path" if group == "files" else "root"
                        for row in expected[group]:
                            if row[key] == original or row[key].startswith(original + "/"):
                                row[key] = moved + row[key][len(original) :]
                        expected[group].sort(key=lambda row: row[key])
                    challenge = "moved-package"
                if expected != after:
                    self.refuse("source_extraction_challenge_delta_mismatch")
                build = self.archive_parent(record["input_archive"]["path"])
                record = self.file_settlement(
                    "source-extraction-challenge",
                    parent,
                    binding,
                    output,
                    build,
                    {"tree": after},
                    input_tree_sha256=hashed(before),
                    extraction_token=record["token"],
                    challenge={"kind": challenge, "expected_failure": True},
                )
            else:
                self.require(output, "source-extract")
            return self.registration(
                "source-extracted-oracle",
                oracle,
                "tools/check_distribution.py",
                argv,
                directory,
                environment,
                [record],
            )
        fixture = find_frame("built_distribution", cf)
        if checked is not None and fixture is not None and argv[1:3] == ["-S", "-c"]:
            local = fixture.f_locals
            bootstrap = f"import sys; sys.path[:0] = [{str(local['environment'])!r}, {str(local['dependency_site'])!r}]; "
            expected = (
                bootstrap
                + "import json, pathlib, unrest_harness; print(json.dumps({'module': unrest_harness.__file__, 'cwd': str(pathlib.Path.cwd())}, sort_keys=True))"
            )
            if (
                argv != [sys.executable, "-S", "-c", expected]
                or directory != local["root"]
                or environment != local["child_env"]
            ):
                self.refuse("source_provenance_vector_mismatch")
            record = self.require(local["environment"], "source-install")
            self.dependency(local["dependency_site"])
            return self.registration(
                "source-installed-provenance", checked, cf, argv, directory, environment, [record]
            )
        lifecycle = find_frame("_run_installed_lifecycle", "tests/contracts/test_lean_package.py")
        if lifecycle is not None:
            local = lifecycle.f_locals
            built = local["built_distribution"]
            body = literal(
                "_run_installed_lifecycle", "tests/contracts/test_lean_package.py", "script"
            )
            if (
                argv
                != [
                    str(built.installed_python),
                    "-S",
                    "-c",
                    body,
                    str(local["probe_root"]),
                    str(local["repository_root"]),
                    str(built.installed_site),
                    str(built.dependency_site),
                ]
                or directory != built.directory
                or environment != local["child_env"]
            ):
                self.refuse("source_installed_lifecycle_inputs_mismatch")
            record = self.require(built.installed_site, "source-install")
            self.dependency(built.dependency_site)
            return self.registration(
                "source-installed-lifecycle",
                lifecycle,
                "tests/contracts/test_lean_package.py",
                argv,
                directory,
                environment,
                [record],
            )
        matrix = find_frame("test_installed_supported_provider_matrix", "tests/contracts/test_lean_provider_security.py")
        if matrix is not None:
            local = matrix.f_locals
            built = local["built_distribution"]
            provider = local["provider"]
            binding = source_frame(matrix, matrix.f_code.co_name, "tests/contracts/test_lean_provider_security.py")
            fn = matrix.f_globals.get(matrix.f_code.co_name)
            cleaner = matrix.f_globals.get("_clean_cli_environment")
            if (not isinstance(fn, types.FunctionType) or fn.__globals__ is not matrix.f_globals
                    or fn.__code__ is not matrix.f_code or not isinstance(cleaner, types.FunctionType)
                    or cleaner.__globals__ is not matrix.f_globals):
                self.refuse("source_provider_matrix_callable_drift")
            if provider not in ("claude", "codex"):
                self.refuse("source_provider_matrix_parameter_drift")
            workspace = self.own(local["tmp_path"] / provider)
            home = self.own(local["tmp_path"] / f"{provider}-home")
            bootstrap = ("import sys; "
                         f"sys.path[:0]=[{str(built.installed_site)!r}, {str(built.dependency_site)!r}]; "
                         "from unrest_harness.cli import cli; cli.main()")
            # Independently derive the original sanitizer from the pinned source.
            expected_env = {name: value for name, value in os.environ.items()
                            if not any(marker in name.upper() for marker in ("API_KEY", "TOKEN", "PASSWORD", "CREDENTIAL"))}
            expected_env.pop("PYTHONPATH", None)
            expected_env.pop("CODEX_PATH", None)
            expected_env["UNREST_HOME"] = str(home)
            if (argv != [str(built.installed_python), "-S", "-c", bootstrap,
                         "init", "--agent", provider, "--workspace-dir", str(workspace)]
                    or directory != built.directory or environment != expected_env
                    or local["workspace"] != workspace or local["unrest_home"] != home
                    or local["bootstrap"] != bootstrap or not workspace.is_dir()
                    or built.installed_python != Path(sys.executable)):
                self.refuse("source_provider_matrix_vector_or_context_drift")
            record = self.require(built.installed_site, "source-install")
            self.dependency(built.dependency_site)
            self.emit({"kind": "exact_installed_provider_matrix_admission", "provider": provider,
                       "binding": public(binding), "installed_tree_sha256": hashed(tree_identity(built.installed_site)),
                       "bootstrap_sha256": sha(bootstrap.encode()), "original_timeout_seconds": 30,
                       "network_or_provider_acceptance": False})
            return self.registration("source-installed-provider-matrix", matrix,
                                     "tests/contracts/test_lean_provider_security.py", argv,
                                     directory, environment, [record])
        cli = find_frame("_run_cli_matrix", "tests/contracts/test_lean_provider_security.py")
        if cli is not None:
            local = cli.f_locals
            outer = find_frame(
                "test_copied_source_and_installed_cli_protect_precommand_credentials",
                "tests/contracts/test_lean_provider_security.py",
            )
            if outer is None:
                self.refuse("source_cli_outer_lineage_missing")
            selected = outer.f_locals
            built = selected["built_distribution"]
            self.dependency(built.dependency_site)
            if directory == selected["copied_root"]:
                record = self.require(selected["copied_source"], "source-copy")
                bootstrap = f"import sys; sys.path[:0]=[{str(selected['copied_source'])!r}, {str(built.dependency_site)!r}]; "
                python = Path(sys.executable)
            elif directory == built.directory:
                record = self.require(built.installed_site, "source-install")
                bootstrap = f"import sys; sys.path[:0]=[{str(built.installed_site)!r}, {str(built.dependency_site)!r}]; "
                python = built.installed_python
            else:
                self.refuse("source_cli_cwd_mismatch")
            trap = directory / "precommand-callback-trap"
            body = (
                bootstrap
                + "from pathlib import Path; from unrest_harness.cli import cli; "
                + f"trap=Path({str(trap)!r}); "
                + "cli.commands['init'].callback=lambda **kwargs: trap.write_text('called'); cli.main()"
            )
            options = literal(
                "_run_cli_matrix", "tests/contracts/test_lean_provider_security.py", "options"
            )
            sentinel = literal(
                "_run_cli_matrix", "tests/contracts/test_lean_provider_security.py", "sentinel"
            )
            ordinary = literal(
                "_run_cli_matrix", "tests/contracts/test_lean_provider_security.py", "ordinary"
            )
            base = [str(python), "-S", "-c", body, "init"]
            if argv in [base + [option, sentinel] for option in options]:
                expected_environment = {**local["environment"], "OPENAI_API_KEY": sentinel}
            elif argv == base + ["--worker-provider", ordinary]:
                expected_environment = local["environment"]
            else:
                self.refuse("source_cli_vector_mismatch")
            if (
                local["bootstrap"] != bootstrap
                or local["script"] != body
                or environment != expected_environment
                or trap.exists()
            ):
                self.refuse("source_cli_script_environment_or_trap_mismatch")
            return self.registration(
                "source-cli-matrix",
                cli,
                "tests/contracts/test_lean_provider_security.py",
                argv,
                directory,
                environment,
                [record],
            )
        return None

    def dependency(self, site):
        expected = next((t for t in self.spec["trees"] if t["root"] == str(site)), None)
        if expected is None or tree_identity(site) != expected:
            self.refuse("source_dependency_site_mismatch")

    def profile(self, frame, event, value):
        if frame.f_code.co_filename not in SOURCE_FRAME_PATHS and not (
            frame.f_code.co_name == "copytree" and frame.f_code.co_filename == shutil.__file__
        ):
            return
        if frame.f_code.co_filename in SOURCE_FRAME_PATHS:
            selected = next((b for b in REGISTRATIONS
                             if b["path"] == frame.f_code.co_filename
                             and b["function"] == frame.f_code.co_name), None)
            if selected is not None and event in ("call", "return"):
                binding = source_frame(frame, frame.f_code.co_name,
                                       str(Path(frame.f_code.co_filename).relative_to(ROOT)))
                self.emit({"kind": "original_source_frame_" + event,
                           "binding": public(binding),
                           "compiler": "raw" if frame.f_code == selected["_code"] else "pytest",
                           "frame_identity": id(frame),
                           "returns_none": value is None if event == "return" else None})
        if event == "call":
            self.file_call(frame)
        elif event == "return":
            self.returned(frame, value)
            self.file_return(frame, value)

    def archive_parent(self, path):
        for (root, operation), record in list(self.settled.items()):
            if operation == "source-build" and any(
                a["path"] == str(path) for a in record["output_identity"]["archives"]
            ):
                self.require(root, operation)
                return record
        self.refuse("source_archive_producer_not_observed")

    def file_settlement(self, operation, frame, binding, output, parent, observed, **extra):
        self.ready(self.state["token"])
        record = {
            "kind": "file_operation_settled",
            "operation": operation,
            "token": uuid.uuid4().hex,
            "owner_pid": os.getpid(),
            "binding": public(binding),
            "output": str(output),
            "parent_token": parent["token"],
            "output_identity": observed,
            "settled": True,
            "functional_pass": False,
            **extra,
        }
        self.settled[(str(output), operation)] = record
        self.emit(record)
        return record

    def file_call(self, frame):
        relative = (
            str(Path(frame.f_code.co_filename).relative_to(ROOT))
            if Path(frame.f_code.co_filename).is_relative_to(ROOT)
            else None
        )
        name = frame.f_code.co_name
        if relative == "tools/check_distribution.py" and name == "_extract_sdist_safely":
            binding = source_frame(frame, name, relative)
            local = frame.f_locals
            path = local["path"]
            # Pure original safe-extraction negatives retain their own diagnostics.
            parent = next(
                (
                    r
                    for r in self.settled.values()
                    if r["operation"] == "source-build"
                    and any(a["path"] == str(path) for a in r["output_identity"]["archives"])
                ),
                None,
            )
            if parent is None:
                return
            self.require(parent["output"], "source-build")
            destination = self.own(local["destination"])
            before = tree_identity(destination) if destination.exists() else None
            archive = archive_identity(path)
            self.active_files[id(frame)] = {
                "frame": frame,
                "operation": "source-extract",
                "binding": binding,
                "parent": parent,
                "archive": archive,
                "destination": destination,
                "before": before,
            }
        elif relative == "tests/test_distribution_check.py" and name == "_mutated_distribution":
            binding = source_frame(frame, name, relative)
            local = frame.f_locals
            parent = self.require(local["built_distribution"], "source-build")
            member = local["member"]
            allowed = {
                "tests/test_persistence_schema_v1.py",
                "tests/fixtures/persistence_schema_v1/corpus.json",
                "tests/fixtures/persistence_schema_v1/manifest.json",
                "tests/fixtures/persistence_schema_v1/generation-transcript.json",
                "tests/fixtures/persistence_schema_v1/legacy-work-handoff.json",
                "tests/fixtures/persistence_schema_v1/legacy-validation-handoff.json",
                "tools/generate_legacy_handoff_fixtures.py",
            }
            if member not in allowed or type(local["omit"]) is not bool:
                self.refuse("source_archive_challenge_parameter")
            target = self.own(local["tmp_path"] / ("omitted" if local["omit"] else "changed"))
            if target.exists():
                self.refuse("source_archive_challenge_target_not_fresh")
            self.active_files[id(frame)] = {
                "frame": frame,
                "operation": "source-challenge",
                "binding": binding,
                "parent": parent,
                "target": target,
                "member": member,
                "omit": local["omit"],
            }
        elif name == "copytree" and frame.f_code.co_filename == shutil.__file__:
            caller = frame.f_back
            relative = "tests/contracts/test_lean_provider_security.py"
            if (
                caller is None
                or caller.f_code.co_name
                != "test_copied_source_and_installed_cli_protect_precommand_credentials"
            ):
                return
            binding = source_frame(caller, caller.f_code.co_name, relative)
            local = caller.f_locals
            if (
                frame.f_locals["src"] != ROOT / "src"
                or frame.f_locals["dst"] != local["copied_source"]
            ):
                self.refuse("copied_source_inputs_mismatch")
            target = self.own(local["copied_source"])
            if target.exists():
                self.refuse("copied_source_target_not_fresh")
            parent = self.require(local["built_distribution"].installed_site, "source-install")
            self.active_files[id(frame)] = {
                "frame": frame,
                "operation": "source-copy",
                "binding": binding,
                "parent": parent,
                "target": target,
                "source": tree_identity(ROOT / "src"),
            }

    def file_return(self, frame, value):
        pending = self.active_files.pop(id(frame), None)
        if pending is None:
            return
        if frame is not pending["frame"] or value is None:
            self.emit(
                {
                    "kind": "file_operation_failed",
                    "operation": pending["operation"],
                    "reason": "original_source_return_failed",
                }
            )
            return
        operation = pending["operation"]
        parent = pending["parent"]
        self.require(parent["output"], parent["operation"])
        if operation == "source-extract":
            output = self.own(value)
            if (
                output.parent != pending["destination"]
                or archive_identity(pending["archive"]["path"]) != pending["archive"]
            ):
                self.refuse("source_extraction_output_or_input_mismatch")
            if pending["before"] is not None:
                before = pending["before"]
                after = tree_identity(pending["destination"])
                original = relative_files(before)
                observed = relative_files(after)
                if any(k not in observed or observed[k] != v for k, v in original.items()):
                    self.refuse("source_extraction_preexisting_file_changed")
            tree = tree_identity(output)
            mapping = extraction_mapping(pending["archive"], tree)
            self.file_settlement(
                operation,
                frame,
                pending["binding"],
                output,
                parent,
                {"tree": tree, "mapping": mapping},
                input_archive=pending["archive"],
            )
        elif operation == "source-copy":
            output = pending["target"]
            if Path(value) != output or tree_identity(ROOT / "src") != pending["source"]:
                self.refuse("source_copy_return_or_input_mismatch")
            tree = tree_identity(output)
            compare_payload_trees(pending["source"], tree)
            self.file_settlement(
                operation,
                frame,
                pending["binding"],
                output,
                parent,
                {"tree": tree},
                source=pending["source"],
            )
        else:
            target = pending["target"]
            if Path(value) != target:
                self.refuse("source_archive_challenge_return_mismatch")
            originals = parent["output_identity"]["archives"]
            source_tar = next(a for a in originals if a["path"].endswith(".tar.gz"))
            source_wheel = next(a for a in originals if a["path"].endswith(".whl"))
            wheel = archive_identity(target / Path(source_wheel["path"]).name)
            archive = archive_identity(target / Path(source_tar["path"]).name)
            if (
                wheel["members"] != source_wheel["members"]
                or wheel["sha256"] != source_wheel["sha256"]
            ):
                self.refuse("source_challenge_wheel_changed")
            expected = {m["name"]: m for m in source_tar["members"]}
            actual = {m["name"]: m for m in archive["members"]}
            matching = [k for k in expected if "/".join(Path(k).parts[1:]) == pending["member"]]
            if len(matching) != 1:
                self.refuse("source_challenge_member_cardinality")
            selected = matching[0]
            if pending["omit"]:
                del expected[selected]
            else:
                with tarfile.open(source_tar["path"], "r:gz") as stream:
                    reader = stream.extractfile(selected)
                    if reader is None:
                        self.refuse("source_challenge_original_member_missing")
                    body = reader.read() + b"\nmutation"
                expected[selected] = {**expected[selected], "size": len(body), "sha256": sha(body)}
            if expected != actual:
                self.refuse("source_challenge_delta_mismatch")
            self.file_settlement(
                operation,
                frame,
                pending["binding"],
                target,
                parent,
                {"tree": tree_identity(target), "archives": [wheel, archive]},
                challenge={
                    "member": pending["member"],
                    "omit": pending["omit"],
                    "expected_failure": True,
                },
            )
