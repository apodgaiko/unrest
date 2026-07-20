# VAL-CLI-001: Installed live CLI modes and errors work

Surface: CLI.
Needs: installed command, disposable multi-project bucket, bounded process/PTY.
Behavior: `--once` emits one text snapshot; `--json` emits pure parseable JSON;
watch emits at least two refreshes before interruption; id/path pins resolve;
missing or ambiguous pins and incompatible dashboard/once/json combinations
exit nonzero with diagnostics on stderr.
Evidence: Exact commands, stdout/stderr/exit codes, parsed JSON, refresh count,
pin matrix, and option-conflict matrix.

