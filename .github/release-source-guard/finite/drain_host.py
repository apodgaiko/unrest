"""Cleanup authority restricted to registered direct children of selected worker."""

import ctypes

COMMON = {"id", "kind", "nonce", "pid", "token", "identity"}


def handle(host, request, events, kernel):
    schemas = {
        "drain_inventory": {"children", "source_sha256"},
        "drain_child": {"child", "child_token"},
        "drain_complete": {"children"},
    }
    kind = request["kind"]
    if kind not in schemas or set(request) != COMMON | schemas[kind]:
        raise RuntimeError("drain_schema_refused")
    ready = next(
        e
        for e in events
        if e["kind"] == "ready"
        and e["owner_pid"] == request["pid"]
        and e["token"] == request["token"]
    )
    case = "tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct"
    if ready["class"] != "source-run-worker" or ready["case"] != case:
        raise RuntimeError("drain_foreign_owner")
    registered = {
        e["pid"]: e
        for e in events
        if e["kind"] == "registered" and e["owner_pid"] == request["pid"]
    }
    waited = {
        e["pid"]: e
        for e in events
        if e["kind"] == "actual_waitpid" and e["owner_pid"] == request["pid"]
    }
    if any(
        e["class"] not in {"source-owned-role:worker", "source-composed-adapter"}
        for e in registered.values()
    ):
        raise RuntimeError("drain_unbound_class")
    if kind == "drain_child":
        child = request["child"]
        record = registered.get(child)
        if record is None or record["token"] != request["child_token"]:
            raise RuntimeError("drain_foreign_child")
        if child in waited:
            return {
                "wait_recorded": True,
                "numeric_returncode": waited[child]["numeric_returncode"],
            }
        saved = host.registered.get(child)
        if saved is None:
            raise RuntimeError("drain_missing_custody")
        host.authenticate(
            {
                "nonce": request["nonce"],
                "pid": child,
                "token": record["token"],
                "identity": saved["identity"],
            },
            events,
        )
        if saved["identity"]["ppid"] != request["pid"]:
            raise RuntimeError("drain_not_direct_parent")
        return {"wait_recorded": False, "identity": saved["identity"], "signal": 15}
    if request["children"] != sorted(registered):
        raise RuntimeError("drain_late_or_lost_child")
    if kind == "drain_inventory":
        if (
            request["source_sha256"]
            != host.manifest["product_pins"]["src/unrest_harness/run_worker.py"]
        ):
            raise RuntimeError("drain_source_drift")
        query = kernel.LIB.proc_listchildpids
        query.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        query.restype = ctypes.c_int
        buffer = (ctypes.c_int * 64)()
        count = query(request["pid"], buffer, ctypes.sizeof(buffer))
        if count < 0 or count >= 64 or set(buffer[:count]) != set(registered) - set(waited):
            raise RuntimeError("drain_unknown_kernel_child")
        return {"bound_children": request["children"], "actual_parent": request["pid"]}
    if set(registered) - set(waited):
        return {"pending_actual_wait": True}
    provenance = {}
    for child, registration in registered.items():
        raw = [
            event
            for event in events
            if event["kind"] == "raw_actual_parent_waitpid"
            and event["owner_pid"] == request["pid"]
            and event["pid"] == child
        ]
        if len(raw) != 1:
            raise RuntimeError("drain_raw_actual_wait_missing_or_duplicate")
        event = raw[0]
        if (
            event["nonce"] != request["nonce"]
            or event["owner_token"] != request["token"]
            or event["owner_identity"] != host.registered[request["pid"]]["identity"]
            or event["child_token"] != registration["token"]
            or event["numeric_returncode"] != waited[child]["numeric_returncode"]
        ):
            raise RuntimeError("drain_raw_wait_identity_or_status_drift")
        provenance[str(child)] = event
    return {
        "complete": True,
        "actual_waits": {str(p): e["numeric_returncode"] for p, e in waited.items()},
        "actual_wait_provenance": provenance,
        "new_wait_performed": False,
    }
