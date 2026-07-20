# VAL-TUI-001: Terminal dashboard supports interactive supervision

Surface: TUI.
Needs: installed Textual app, mutable external fixture producer, PTY transcript.
Behavior: Dashboard renders, refreshes after an external state change, navigates
flows/tasks, toggles pin/full/output/attention views, and exits via `q` without a
traceback or project mutation.
Evidence: PTY transcript or screenshots covering `r/j/k/n/b/p/f/o/a/q`, observed
external refresh, stderr and exit status, plus VAL-READONLY-001 inventory with
the producer-attributed delta separated from dashboard observation.
