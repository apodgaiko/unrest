# VAL-WORKSPACE-001: Agent processes use the intended workspace

Surface: background runtime.
Needs: distinct integration, recorded-project, and explicit-cwd sentinels.
Behavior: Workers, validators, and terminal reviewers use the persisted project
workspace by default. An explicit node cwd overrides the worker or validator
process cwd for that dispatch only, without changing the project record; terminal
review continues to use the persisted project workspace.
Evidence: Captured subprocess cwd for worker, validator, and reviewer default
cases plus separate worker and validator override cases, unchanged persisted
project records, and sentinel-relative artifact assertions for both overrides.
