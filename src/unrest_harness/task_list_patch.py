"""Pure TaskListPatch application + post-patch invariant re-check.

See `specs/task_list/PRODUCT.md` §Patching and §Edge Cases.

Implementation choice: supersede/cancel REWRITE downstream `depends_on`
references in the task list. No runtime chain resolver needed. Audit of
"why a reference changed" lives in `decisions/NNN.md`, not in tasks.json.

A patch is applied to (task_list, task_state, contract_ids) and returns
either (patched_tl, patched_state, new_contract_ids, []) or
(unchanged_tl, unchanged_state, unchanged_ids, errors).
"""
from __future__ import annotations


from .models import (
    ASSERTION_ID_REGEX,
    Task,
    TaskList,
    TaskListPatch,
    TaskStateFile,
)
from .task_validation import (
    ValidationError,
    check_acyclic,
    check_coverage,
    check_deps_resolve,
    check_task_ids,
    check_task_shape,
)


def _sealed_task_ids(tl: TaskList, task_state: TaskStateFile) -> set[str]:
    """Tasks inside a sealed subgraph — the transitive upstream closure of
    every cleared gate. Sealed tasks may not be superseded or cancelled.
    """
    cleared_gates = [
        t.id
        for t in tl.tasks
        if t.type == "gate" and task_state.status_of(t.id) == "cleared"
    ]
    if not cleared_gates:
        return set()

    by_id = {t.id: t for t in tl.tasks}
    sealed: set[str] = set()
    stack: list[str] = list(cleared_gates)
    while stack:
        cur = stack.pop()
        if cur in sealed or cur not in by_id:
            continue
        sealed.add(cur)
        stack.extend(by_id[cur].depends_on)
    return sealed


def _rewrite_depends_on(
    tasks: list[Task],
    *,
    supersede: dict[str, str],
    cancel: set[str],
) -> list[Task]:
    """Return a new task list with every `depends_on` list rewritten:

    - id in `supersede` keys → replaced with mapped new id (deduped)
    - id in `cancel` → dropped (deduped)

    The cancelled / superseded tasks themselves stay in the task list (so
    audit ids resolve and status transitions are recorded); only the
    references to them in *downstream* `depends_on` are mutated.
    """
    out: list[Task] = []
    for task in tasks:
        new_deps: list[str] = []
        for dep in task.depends_on:
            if dep in cancel:
                continue
            mapped = supersede.get(dep, dep)
            if mapped not in new_deps:
                new_deps.append(mapped)
        if new_deps != task.depends_on:
            out.append(task.model_copy(update={"depends_on": new_deps}))
        else:
            out.append(task)
    return out


def apply_patch(
    tl: TaskList,
    task_state: TaskStateFile,
    contract_ids: set[str],
    patch: TaskListPatch,
    *,
    new_contract_ids_on_disk: set[str] | None = None,
) -> tuple[TaskList, TaskStateFile, set[str], list[ValidationError]]:
    """Apply a TaskListPatch.

    `new_contract_ids_on_disk` is the set of ids the runtime sees in
    `contract/` minus already-known ids. If `None`, we trust `patch.add_items`
    (used by tests that don't touch disk).

    Returns the patched (task_list, task_state, contract_ids) and any errors.
    On error, the input objects are returned unchanged.
    """
    errors: list[ValidationError] = []

    # 1. At least one op must be non-empty.
    if patch.is_empty:
        errors.append(ValidationError("empty_patch", "no ops in TaskListPatch"))
        return tl, task_state, contract_ids, errors

    # 2. add_items: regex; existence on disk; new-ness; orphan-catching.
    for aid in patch.add_items:
        if not ASSERTION_ID_REGEX.fullmatch(aid):
            errors.append(ValidationError("invalid_assertion_id", aid))
        if aid in contract_ids:
            errors.append(ValidationError("duplicate_assertion", aid))
        if new_contract_ids_on_disk is not None and aid not in new_contract_ids_on_disk:
            errors.append(ValidationError("assertion_file_missing", aid))
    if new_contract_ids_on_disk is not None:
        declared = set(patch.add_items)
        for orphan in sorted(new_contract_ids_on_disk - declared):
            errors.append(ValidationError("undeclared_new_assertion", orphan))
    if errors:
        return tl, task_state, contract_ids, errors

    # 3. add: ids unique; no collision with existing tasks.
    existing_ids = {t.id for t in tl.tasks}
    new_ids_seen: set[str] = set()
    for task in patch.add:
        if task.id in existing_ids:
            errors.append(ValidationError("task_id_collision", task.id))
        if task.id in new_ids_seen:
            errors.append(ValidationError("duplicate_add_task", task.id))
        new_ids_seen.add(task.id)
    if errors:
        return tl, task_state, contract_ids, errors

    # 4. supersede + cancel: integrity checks.
    all_ids = existing_ids | new_ids_seen
    sealed = _sealed_task_ids(tl, task_state)

    cancel_set = set(patch.cancel)
    supersede_keys = set(patch.supersede.keys())
    if overlap := (cancel_set & supersede_keys):
        errors.append(
            ValidationError(
                "cancel_supersede_overlap",
                f"task ids cancelled and superseded in the same patch: {sorted(overlap)}",
            )
        )

    for old_id, new_id in patch.supersede.items():
        if old_id == new_id:
            errors.append(ValidationError("supersede_self", old_id))
        if old_id not in existing_ids:
            errors.append(ValidationError("unknown_supersede_target", old_id))
            continue
        _check_retirable(task_state, sealed, old_id, errors, op="supersede")
        if new_id not in all_ids:
            errors.append(
                ValidationError(
                    "supersede_new_id_unknown",
                    f"{old_id} -> {new_id} (new id not in add[] or existing tasks)",
                )
            )
        elif new_id in cancel_set:
            errors.append(
                ValidationError(
                    "supersede_target_cancelled",
                    f"{old_id} -> {new_id} (new id is being cancelled by the same patch)",
                )
            )

    for old_id in patch.cancel:
        if old_id not in existing_ids:
            errors.append(ValidationError("unknown_cancel_target", old_id))
            continue
        _check_retirable(task_state, sealed, old_id, errors, op="cancel")
    if errors:
        return tl, task_state, contract_ids, errors

    # 5. Build patched task list: append `add`, then rewrite depends_on
    # to route through supersede / drop cancelled.
    appended = list(tl.tasks) + list(patch.add)
    rewritten = _rewrite_depends_on(
        appended, supersede=patch.supersede, cancel=cancel_set
    )
    patched_tl = TaskList(tasks=rewritten)

    patched_state = TaskStateFile(tasks=dict(task_state.tasks))
    for old_id in patch.supersede:
        patched_state.set_status(old_id, "superseded")
    for old_id in patch.cancel:
        patched_state.set_status(old_id, "superseded")
    for task in patch.add:
        patched_state.set_status(task.id, "pending")

    patched_contract = set(contract_ids) | set(patch.add_items)

    # 6. Re-check shape + deps + acyclicity + coverage over the patched task list.
    errs = check_task_ids(patched_tl)
    if errs:
        return tl, task_state, contract_ids, errs
    errs = check_task_shape(patched_tl)
    if errs:
        return tl, task_state, contract_ids, errs
    errs = check_deps_resolve(patched_tl)
    if errs:
        return tl, task_state, contract_ids, errs
    errs = check_acyclic(patched_tl)
    if errs:
        return tl, task_state, contract_ids, errs
    errs = check_coverage(patched_contract, patched_tl, task_status=patched_state)
    if errs:
        return tl, task_state, contract_ids, errs

    return patched_tl, patched_state, patched_contract, []


def _check_retirable(
    task_state: TaskStateFile,
    sealed: set[str],
    old_id: str,
    errors: list[ValidationError],
    *,
    op: str,
) -> None:
    """Shared eligibility check for `supersede` and `cancel`.

    Cleared tasks: rejected — sealed evidence.
    Running tasks: rejected — race with the live worker.
    Sealed subgraph: rejected — would invalidate a cleared gate's history.
    """
    cur_status = task_state.status_of(old_id)
    if cur_status == "cleared":
        errors.append(ValidationError(f"{op}_cleared_task", old_id))
        return
    if cur_status == "running":
        errors.append(
            ValidationError(
                f"{op}_status_invalid",
                f"{old_id} (status=running)",
            )
        )
        return
    if cur_status not in ("pending", "failed"):
        errors.append(
            ValidationError(
                f"{op}_status_invalid",
                f"{old_id} (status={cur_status})",
            )
        )
    if old_id in sealed:
        errors.append(ValidationError(f"{op}_inside_sealed_subgraph", old_id))


__all__ = ["apply_patch"]
