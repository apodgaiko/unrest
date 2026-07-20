# VAL-READONLY-001: Observation never mutates project buckets

Surface: artifact.
Needs: normal, partial, and corrupt disposable project buckets.
Behavior: Text, JSON, watch, and dashboard observation never create, delete,
rewrite, chmod, or retimestamp files or directories in observed buckets.
Evidence: Closed before/after inventory per mode including paths, types, modes,
sizes, mtimes, and content hashes for files and directories.
Immutable sessions require exact inventory equality. In refresh sessions, the
baseline is captured immediately before the declared external producer runs;
the only permitted delta is that producer's predeclared path/content change,
followed by exact equality from post-producer state through dashboard exit.
