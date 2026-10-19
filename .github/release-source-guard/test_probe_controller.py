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
            "CapAdd": ["SETUID", "SETGID", "SETPCAP", "SYS_PTRACE", "DAC_READ_SEARCH"],
            "SecurityOpt": ["no-new-privileges"],
            "Tmpfs": dict(controller.TMPFS),
        },
        "Mounts": [{"Type": "bind", "Source": "/public-support", "Destination": "/guard",
                    "RW": False}],
        "Config": {"OpenStdin": False, "Entrypoint": ["/usr/local/bin/python"],
                   "Cmd": ["-B", "/guard/compartment_probe.py"]},
    }


def test_exact_synthetic_configuration():
    controller.validate_container(configuration(), Path("/public-support"))


def test_docker_canonical_capability_names():
    current = configuration()
    current["HostConfig"]["CapAdd"] = ["CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID",
                                       "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH"]
    controller.validate_container(current, Path("/public-support"))


@pytest.mark.parametrize("capabilities", [
    ["CAP_CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"],
    ["CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP", "SETUID"],
    ["CAP_SETUID", "CAP_SETGID", "CAP_SYS_PTRACE"],
])
def test_capability_inventory_remains_finite(capabilities):
    current = configuration()
    current["HostConfig"]["CapAdd"] = capabilities
    with pytest.raises(RuntimeError):
        controller.validate_container(current, Path("/public-support"))


@pytest.mark.parametrize("root", ["/work", "/tmp", "/records"])
def test_writable_root_options_are_bound(root):
    current = configuration()
    current["HostConfig"]["Tmpfs"][root] = "rw,mode=0777"
    with pytest.raises(RuntimeError):
        controller.validate_container(current, Path("/public-support"))


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


def test_prerequisite_failure_has_closed_fields_without_exception_body():
    import json
    identity = {'run_id': '123', 'head_sha': 'a' * 40, 'support_sha256': 'b' * 64}
    try:
        raise RuntimeError('PRIVATE_EXCEPTION_BODY')
    except RuntimeError as error:
        value = controller.prerequisite_status(identity, 'validate', error)
    assert value['identity'] == identity
    assert value['stage'] == 'validate' and value['status'] == 'failed'
    assert value['exception_class'] == 'RuntimeError'
    assert len(value['location_sha256']) == 64
    assert 'PRIVATE_EXCEPTION_BODY' not in json.dumps(value)
    assert set(value) == {'schema', 'identity', 'stage', 'status', 'exception_class',
                          'location_sha256', 'source_checkpoint_ready', 'selected_carrier'}
    assert controller.prerequisite_status(identity, 'settled')['exception_class'] is None
    with pytest.raises(ValueError):
        controller.prerequisite_status(identity, 'arbitrary-stage')


def test_unknown_exception_class_does_not_escape_closed_enum():
    class PrivateExceptionName(Exception):
        pass
    value = controller.prerequisite_status({}, 'capture', PrivateExceptionName('private'))
    assert value['exception_class'] == 'other'
    assert value['location_sha256'] is None


@pytest.mark.parametrize('change', ['exact', 'missing', 'foreign', 'symlink', 'hardlink', 'unbound'])
def test_control_workflow_data_custody(tmp_path, change):
    import hashlib
    import json
    import environment
    source = tmp_path / 'repository/.github/workflows/v046-source-readiness.yml'
    source.parent.mkdir(parents=True)
    public = Path(__file__).parent.parent / 'workflows/v046-source-readiness.yml'
    if not public.exists():
        public = Path('/metadata/source-readiness-workflow.yml')
    body = public.read_bytes()
    source.write_bytes(body)
    pin = hashlib.sha256(body).hexdigest()
    target = tmp_path / 'output'
    target.mkdir()
    if change == 'missing':
        source.unlink()
    elif change == 'foreign':
        source.write_bytes(body + b'foreign')
    elif change == 'symlink':
        source.rename(source.with_suffix('.original'))
        source.symlink_to(source.with_suffix('.original'))
    elif change == 'hardlink':
        source.with_suffix('.alias').hardlink_to(source)
    elif change == 'unbound':
        pin = None
    if change != 'exact':
        with pytest.raises((OSError, RuntimeError)):
            environment.copy_control_workflow(target, tmp_path / 'repository', pin, 'a' * 64)
        assert not list(target.iterdir())
    else:
        environment.copy_control_workflow(target, tmp_path / 'repository', pin, 'a' * 64)
        assert (target / source.name.replace('v046-source-readiness', 'source-readiness-workflow')).read_bytes() == body
        assert json.loads((target / 'control-input.json').read_bytes()) == {
            'readiness_workflow_sha256': pin, 'support_sha256': 'a' * 64}


@pytest.mark.parametrize('change', ['exact', 'missing', 'foreign-workflow', 'foreign-support', 'extra-field'])
def test_control_image_namespace_binding(tmp_path, change):
    import json
    from compartment_probe import verify_control_input
    from structured_evidence import canonical, digest
    support = tmp_path / 'guard'
    support.mkdir()
    (support / 'definition.py').write_bytes(b'declared support')
    metadata = tmp_path / 'metadata'
    metadata.mkdir()
    workflow = metadata / 'source-readiness-workflow.yml'
    workflow.write_bytes(b'original public workflow')
    value = {'readiness_workflow_sha256': digest(workflow.read_bytes()),
             'support_sha256': digest(canonical({'definition.py': digest(b'declared support')}))}
    if change == 'foreign-workflow':
        workflow.write_bytes(b'foreign')
    elif change == 'foreign-support':
        (support / 'definition.py').write_bytes(b'foreign')
    elif change == 'extra-field':
        value['foreign'] = 'unbound'
    elif change == 'missing':
        workflow.unlink()
    (metadata / 'control-input.json').write_text(json.dumps(value))
    if change == 'exact':
        assert verify_control_input(metadata, support) == value
    else:
        with pytest.raises((OSError, RuntimeError)):
            verify_control_input(metadata, support)
