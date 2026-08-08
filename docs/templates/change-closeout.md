---
id: TPL-CLOSEOUT-001
status: active
applies_to:
  - docs/templates/change-closeout.md
verified_by:
  - tests/test_documentation_contract.py
related_decisions: []
schema_version: 1
---

# Change closeout template

```yaml
task_id: <stable task id>
status: complete | blocked | incomplete
base_sha: <exact SHA>
result_sha: <exact SHA or null>
summary: <bounded outcome>

scope_completed:
  - <observable completed result>

files_changed:
  - path: <repository-relative path>
    purpose: <why it changed>

public_or_persisted_changes:
  - <schema, CLI, MCP, config, storage, policy, or none>

invariants_and_decisions:
  - id: <INVARIANT/SECURITY/COMPAT/ADR id>
    effect: preserved | added | changed
    note: <concise explanation>

contract_targets:
  - id: <VAL-*>
    result: satisfied | unsatisfied
    evidence: <command/flow/artifact>

verification:
  - command: <exact command or flow>
    exit_code: <integer or null for non-command flow>
    result: <concrete observation>

evaluation_or_evidence:
  - <artifact, fixture, trace, comparison, or none>

risks_or_unknowns:
  - <remaining risk or none>

rollback:
  procedure: <tested command/change or none>
  verification: <observation or none>

follow_ons:
  required:
    - <correctness work or none>
  optional:
    - <non-blocking improvement or none>
```

Do not substitute “tests passed” for exact commands, exit codes, and concrete
observations. Do not include transcripts, hidden reasoning, prompts, secrets,
or unrelated command output.
