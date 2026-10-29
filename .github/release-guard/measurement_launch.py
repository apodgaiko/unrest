"""The original provider-free four-arm simulation command, with fixed inputs."""
import hashlib
from pathlib import Path

from content_manifest import Refused
from launch_policy import build_expected
from owned_fixture import acquire

CASE='tests/test_v046_measurement_helpers.py::test_four_arm_simulation_uses_independent_terminal_counts'
TOOL='tools/measure_v046_flow.py'
FIXTURE='tests/fixtures/v046_measurement/flow-cases.json'
PINS={'tests/test_v046_measurement_helpers.py': '019efe94eda1c806082d4880195e12da4d9529e349bb4ab4e55e7c277b03e736', 'tools/measure_v046_flow.py': '650286242250c0a112021f31a2c152b2d682ba32f12488a2fb280d173e3b96a4', 'tests/fixtures/v046_measurement/flow-cases.json': '8c081b8e5f3b6d11a397c7bf64f55f0a377d021bc0395ef0349d5738e7f4b08b'}
OWNER=20000


def expected(host,argv,cwd,environment,native,pin):
    if host.case!=CASE or len(argv)!=8:
        raise Refused('simulation exact original case')
    checkout=Path(host.meta['checkout'])
    for path,digest in PINS.items():
        if hashlib.sha256((checkout/path).read_bytes()).hexdigest()!=digest:
            raise Refused('simulation original input bytes')
    root,info=acquire(str(Path(argv[7]).parent),Path(host.meta['owned']),CASE.split('::')[1][:30],OWNER)
    generation=(str(root),info.st_dev,info.st_ino)
    if host.fixture_roots.setdefault(CASE,generation)!=generation:
        raise Refused('simulation changed fixture generation')
    vector=(native,str(checkout/TOOL),'--case-manifest',str(checkout/FIXTURE),
        '--mode','simulated','--output',str(root/'flow.json'))
    if cwd!=str(checkout):
        raise Refused('simulation original working directory')
    return build_expected('fixed:simulation',CASE,native,pin,vector,tuple(sorted(environment.items())),cwd,'python-script',PINS[TOOL])
