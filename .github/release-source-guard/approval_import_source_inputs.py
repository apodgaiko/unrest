"""One exact lazy type import and equivalent controlled fixture configuration."""
from __future__ import annotations
import ast
import hashlib
import json

PRE = {'tests/test_approval_recovery.py': 'f886178539296b984f19db2814bc53817133b214632146843b6934abb69bb80a', 'src/unrest_harness/approval_recovery.py': '48a4c68fdff042b49f37cc3edf30e240cdb5ae69aa1da8a6e0280d19ec364ff4', 'tests/fixtures/approval_run_executor.py': 'e6074a2e44506fa275bac0a696046e28f8597579775a64e5ddc209c3456a040d', 'docs/architecture/approval-recovery.md': 'ae323b5296003ccd1de850df0c43334c3843b6282cf703cd9fee799b257338a4'}
POST = {'tests/test_approval_recovery.py': 'ac7ac78e3547a29694971aa7cbe858465243a135d0ab1f30ef4f51502f6b586c', 'src/unrest_harness/approval_recovery.py': '8a378de950500f2bb6e4b6bbcf55392343d0127aa68716671208b82c27e5533f', 'tests/fixtures/approval_run_executor.py': 'f6e24716d1b9103035fe99fe2af9f00bf42544d31086caa94486f3e8259a4d33', 'docs/architecture/approval-recovery.md': '622c17d22e82bcbf6e79e27c8c17f59da05eed02ac1d8adc590a22f38ee53496'}
SOURCE_AST = '525d30f9054c9fa087c89382521b8fcc88425450e74c1541489d5abd4e3cb800'
FIXTURE_AST = 'a6c6850031a606eef726455996ebb93fc37b049495f06b9798ceef1063301f8f'
DEFINITION_LINES = '0338a1a6184b61cfd17c992f8a6702697f4188ffa7b957179dfd26a8938ee517'
DOC_PREFIX_SIZE = 14736
CONSTRUCTOR = "Call(func=Name(id='HarnessConfig', ctx=Load()), keywords=[keyword(arg='bundled_dir', value=BinOp(left=Subscript(value=Attribute(value=Call(func=Name(id='Path', ctx=Load()), args=[Name(id='__file__', ctx=Load())]), attr='parents', ctx=Load()), slice=Constant(value=2), ctx=Load()), op=Div(), right=Constant(value='src/unrest_harness/bundled'))), keyword(arg='harness_home', value=BinOp(left=Name(id='root', ctx=Load()), op=Div(), right=Constant(value='home'))), keyword(arg='projects_dir', value=BinOp(left=Name(id='root', ctx=Load()), op=Div(), right=Constant(value='home/projects'))), keyword(arg='orchestrator_provider_name', value=Constant(value='codex')), keyword(arg='worker_provider_name', value=Constant(value='codex')), keyword(arg='worker_acp_command', value=Constant(value=None)), keyword(arg='validator_provider_name', value=Constant(value=None)), keyword(arg='validator_acp_command', value=Constant(value=None)), keyword(arg='terminal_reviewer_provider_name', value=Constant(value=None)), keyword(arg='terminal_reviewer_acp_command', value=Constant(value=None))])"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def verify_source(body):
    if type(body) is str:
        body = body.encode()
    before = b'while self.phase == "reviewing":'
    after = b'while self.phase in {"reviewing", "submitting"}:'
    if body.count(after) > 1:
        raise RuntimeError("approval_submission_wait_scope")
    tree = ast.parse(body.replace(after, before))
    lines = [(type(node).__name__, node.name, node.lineno) for node in ast.walk(tree)
             if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))]
    if digest(json.dumps(lines).encode()) != DEFINITION_LINES:
        raise RuntimeError('approval_import_definition_lines')
    expected = ast.parse('if TYPE_CHECKING:\n    from fastmcp import Context').body[0]
    if ast.dump(tree.body[-1], include_attributes=False) != ast.dump(expected, include_attributes=False):
        raise RuntimeError('approval_import_type_only_scope')
    tree.body.pop()
    imports = [node for node in tree.body if isinstance(node, ast.ImportFrom) and node.module == 'typing']
    if len(imports) != 1 or sum(alias.name == 'TYPE_CHECKING' and alias.asname is None for alias in imports[0].names) != 1:
        raise RuntimeError('approval_import_typing_binding')
    imports[0].names = [alias for alias in imports[0].names if alias.name != 'TYPE_CHECKING']
    tree.body.insert(tree.body.index(imports[0]) + 1, ast.parse('from fastmcp import Context').body[0])
    if digest(ast.dump(tree, include_attributes=False).encode()) != SOURCE_AST:
        raise RuntimeError('approval_import_runtime_body_drift')


def verify_fixture(body):
    tree = ast.parse(body)
    imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)
               and node.module == 'unrest_harness.config' and len(node.names) == 1
               and node.names[0].name == 'HarnessConfig' and node.names[0].asname is None]
    if len(imports) != 1:
        raise RuntimeError('approval_import_fixture_config_import')
    tree.body[tree.body.index(imports[0])] = ast.parse('from tests.test_provider_review import config_at').body[0]
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == 'ProjectStore']
    if (len(calls) != 1 or len(calls[0].args) != 1 or calls[0].keywords
            or ast.dump(calls[0].args[0], include_attributes=False) != CONSTRUCTOR):
        raise RuntimeError('approval_import_fixture_config_fields')
    calls[0].args[0] = ast.parse('config_at(root)', mode='eval').body
    if digest(ast.dump(tree, include_attributes=False).encode()) != FIXTURE_AST:
        raise RuntimeError('approval_import_fixture_behavior_drift')


TEST_ANCHOR = {'expression_ast_sha256': '5027cbfb4f2643c90da6375a4cb84a5ec2044ed2b1eb4100c08fbb59c3f20be2', 'family': 'ordinary-acp-and-role-helper', 'line': 730, 'owner': 'test_unmodified_pinned_adapter_owned_relay', 'path': 'tests/test_approval_recovery.py', 'route': 'asyncio.create_subprocess_exec', 'source_sha256': 'f886178539296b984f19db2814bc53817133b214632146843b6934abb69bb80a'}


def admit_test_anchor(manifest):
    rows = [row for row in manifest['anchor_inventory'] if row['path'] == TEST_ANCHOR['path']]
    if rows != [TEST_ANCHOR]:
        raise RuntimeError('approval_submission_original_anchor_drift')
    # The entire old test file is a verified unchanged prefix. Only its file
    # digest changes when appending the new zero-child regression.
    rows[0]['source_sha256'] = POST[TEST_ANCHOR['path']]


def admit(manifest, root, read):
    pins = manifest['product_pins']
    if any(pins.get(name) != pin for name, pin in PRE.items()):
        raise RuntimeError('approval_import_preimage')
    bodies = {name: read(root, name) for name in POST}
    if any(digest(bodies[name]) != pin for name, pin in POST.items()):
        raise RuntimeError('approval_import_postimage')
    verify_source(bodies['src/unrest_harness/approval_recovery.py'])
    verify_fixture(bodies['tests/fixtures/approval_run_executor.py'])
    if digest(bodies['tests/test_approval_recovery.py'][:46347]) != PRE['tests/test_approval_recovery.py']:
        raise RuntimeError('approval_submission_original_tests_drift')
    if digest(bodies['docs/architecture/approval-recovery.md'][:DOC_PREFIX_SIZE]) != PRE['docs/architecture/approval-recovery.md']:
        raise RuntimeError('approval_import_original_disposition_drift')
    if (len(manifest['anchor_inventory']) != 176
            or any(row['path'] in PRE and row['path'] != 'tests/test_approval_recovery.py'
                   for row in manifest['anchor_inventory'])):
        raise RuntimeError('approval_import_anchor_inventory')
    admit_test_anchor(manifest)
    pins.update(POST)
