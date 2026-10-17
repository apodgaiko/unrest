"""The trusted coordinator refuses scope drift before starting any payload."""
import copy
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "probe_controller", Path(__file__).with_name("probe_controller.py")
)
assert spec is not None and spec.loader is not None
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


def configuration():
    return {
        "HostConfig": {
            "Privileged": False, "ReadonlyRootfs": True, "NetworkMode": "none",
            "IpcMode": "private", "PidMode": "", "CgroupnsMode": "private",
            "PidsLimit": 128, "Memory": 1073741824, "CapDrop": ["ALL"],
            "CapAdd": ["SETUID", "SETGID", "SETPCAP"],
            "SecurityOpt": ["no-new-privileges"],
            "Tmpfs": {"/work": "", "/tmp": "", "/records": ""},
        },
        "Mounts": [{"Type": "bind", "Source": "/public-support", "Destination": "/guard",
                    "RW": False}],
        "Config": {"OpenStdin": False, "Entrypoint": ["/usr/local/bin/python"],
                   "Cmd": ["-B", "/guard/compartment_probe.py"]},
    }


def test_exact_synthetic_configuration():
    controller.validate_container(configuration(), Path("/public-support"))


@pytest.mark.parametrize(("key", "value"), [
    ("Privileged", True), ("ReadonlyRootfs", False), ("NetworkMode", "host"),
    ("IpcMode", "host"), ("PidMode", "host"), ("CgroupnsMode", "host"),
    ("CapAdd", ["SYS_ADMIN"]), ("CapDrop", []), ("SecurityOpt", []),
    ("Tmpfs", {"/": ""}),
])
def test_scope_drift_refuses(key, value):
    current = configuration()
    current["HostConfig"][key] = value
    with pytest.raises(RuntimeError):
        controller.validate_container(current, Path("/public-support"))


def test_mount_and_entrypoint_drift_refuse():
    original = configuration()
    for mutate in (
        lambda value: value["Mounts"][0].update(RW=True),
        lambda value: value["Mounts"].append(dict(value["Mounts"][0])),
        lambda value: value["Config"].update(Cmd=["-c", "arbitrary"]),
        lambda value: value["Config"].update(OpenStdin=True),
    ):
        current = copy.deepcopy(original)
        mutate(current)
        with pytest.raises(RuntimeError):
            controller.validate_container(current, Path("/public-support"))
