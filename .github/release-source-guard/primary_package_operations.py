"""Original archive execution with an authenticated cross-capsule data leaf."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from typing import Any
from pathlib import Path

_SOURCE = Path('/guard/primary_operations.py')
_BODY = _SOURCE.read_bytes()
if hashlib.sha256(_BODY).hexdigest() != '6b0c993facb604cbb0978e0bea20c14b02493654e07bb4331604ac536e8d26be':
    raise RuntimeError('primary_package_operations_base_drift')
exec(compile(_BODY, str(_SOURCE), 'exec', dont_inherit=True), globals())

_PackageBase: Any = globals()['Operations']
identity: Any = globals()['identity']
hashed: Any = globals()['hashed']
source_frame: Any = globals()['source_frame']
public: Any = globals()['public']
tree_identity: Any = globals()['tree_identity']
archive_identity: Any = globals()['archive_identity']
code_objects: Any = globals()['code_objects']
sha: Any = globals()['sha']
SOURCE_PINS: Any = globals()['SOURCE_PINS']


class Operations(_PackageBase):
    def package_input(self):
        descriptor = self.spec['primary_package_input']
        body = Path('/inputs/package-input.json').read_bytes()
        if (json.loads(body) != descriptor or descriptor['duty'] != 'Check distribution archives'
                or descriptor['schema'] != 'unrest.v046.primary-package-input.v1'
                or set(descriptor['members']) != {'unrest_harness-0.4.7-py3-none-any.whl',
                                                  'unrest_harness-0.4.7.tar.gz'}):
            self.refuse('primary_package_archive_input_binding')
        root = Path('/source/dist')
        if root.is_symlink() or {p.name for p in root.iterdir()} != set(descriptor['members']):
            self.refuse('primary_package_archive_inventory')
        for name, value in descriptor['members'].items():
            path = root / name
            current = identity(path)
            info = path.lstat()
            if (current['sha256'] != value['sha256'] or current['size'] != value['size']
                    or info.st_uid != 20000 or info.st_nlink != 1):
                self.refuse('primary_package_archive_input_drift')
        return descriptor

    def inputs(self):
        result = super().inputs()
        self.package_input()
        return result

    def import_package(self):
        descriptor = self.package_input()
        root = '/source/dist'
        key = (root, 'primary-package-input')
        if key not in self.settled:
            record = {'kind': 'file_operation_settled', 'operation': key[1],
                      'token': uuid.uuid4().hex, 'owner_pid': os.getpid(),
                      'binding': {'path': '/inputs/package-input.json',
                                  'sha256': hashed(descriptor), 'function': 'authenticated-package-input'},
                      'output': root, 'parent_token': None,
                      'output_identity': {'tree': tree_identity(root)}, 'settled': True,
                      'functional_pass': False, 'package_input_sha256': hashed(descriptor)}
            self.settled[key] = record
            self.emit(record)
        self.require(root, key[1])
        return self.settled[key]

    def file_call(self, frame):
        if (frame.f_code.co_filename == '/source/tools/check_distribution.py'
                and frame.f_code.co_name == '_extract_sdist_safely'):
            binding = source_frame(frame, '_extract_sdist_safely', 'tools/check_distribution.py')
            local = frame.f_locals
            if local['path'] != Path('/source/dist/unrest_harness-0.4.7.tar.gz'):
                self.refuse('primary_package_extraction_archive')
            parent = self.import_package()
            destination = self.own(local['destination'])
            self.active_files[id(frame)] = {
                'frame': frame, 'operation': 'source-extract', 'binding': binding,
                'parent': parent, 'archive': archive_identity(local['path']),
                'destination': destination,
                'before': tree_identity(destination) if destination.exists() else None}
            return
        super().file_call(frame)

    def profile(self, frame, event, value):
        super().profile(frame, event, value)
        if (frame.f_code.co_filename != '/source/tools/check_distribution.py'
                or frame.f_code.co_name != 'check_distribution' or event not in {'call', 'return'}):
            return
        path = Path(frame.f_code.co_filename)
        body = path.read_bytes()
        module = sys.modules.get(frame.f_globals.get('__name__'))
        original = frame.f_globals.get('check_distribution')
        compiled = compile(body, str(path), 'exec', dont_inherit=True)
        expected = next(code for code in code_objects(compiled) if code.co_qualname == 'check_distribution')
        if (sha(body) != SOURCE_PINS['tools/check_distribution.py']
                or frame.f_code != expected or module is None or vars(module) is not frame.f_globals
                or getattr(original, '__code__', None) is not frame.f_code
                or original.__globals__ is not frame.f_globals
                or frame.f_locals['root'] != Path('/source')
                or frame.f_locals['dist'] != Path('/source/dist')):
            self.refuse('primary_package_original_function_binding')
        self.ready(self.state['token'])
        self.package_input()
        if event == 'return':
            if type(value) is not dict:
                self.refuse('primary_package_original_function_failed')
            endpoint = sys.modules['endpoint']
            endpoint.request('primary_package_function_return', function='check_distribution',
                             source_sha256=sha(body), result=value)
            self.ready(self.state['token'])

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
            if record['operation'] == 'primary-package-input':
                descriptor = self.package_input()
                if (record['kind'] != 'file_operation_settled'
                        or record['output'] != '/source/dist' or record['parent_token'] is not None
                        or record['package_input_sha256'] != hashed(descriptor)
                        or record['owner_pid'] != os.getppid()
                        or record['output_identity'] != {'tree': tree_identity('/source/dist')}):
                    self.refuse('primary_package_inherited_input_leaf')
                self.settled[(record['output'], record['operation'])] = record
                self.require(record['output'], record['operation'])
                return
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
