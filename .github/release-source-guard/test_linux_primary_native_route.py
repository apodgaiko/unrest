"""Real immutable UV selection; invoked unconditionally by Linux controls."""
import os
from pathlib import Path
import shutil

from test_primary_native_route import route as route


def test_original_tool_selection_and_route_use_real_immutable_uv_image(route):
    from producer_inputs import SOURCE_UV_ELF_SHA256
    native = Path('/opt/source-bootstrap/bin/uv')
    namespace = route.namespace
    namespace['shutil'] = shutil
    namespace['_UV_NATIVE'] = str(native)
    namespace['os'].statvfs = os.statvfs
    environment = {'PATH': str(route.first) + os.pathsep + str(native.parent)}
    route.record['environment_sha256'] = namespace['hashed'](environment)
    route.record['native_profile']['environment'] = dict(environment)
    route.operation.spec['uv'] = namespace['identity'](native)
    assert route.operation.spec['uv']['sha256'] == SOURCE_UV_ELF_SHA256
    assert shutil.which('uv', path=environment['PATH']) == str(native)
    assert os.statvfs(native).f_flag & os.ST_RDONLY
    before = list(route.argv)
    assert route.operation.native_executable(route.registration, route.argv, '/source', environment) == str(native)
    assert route.argv == before and len(route.emitted) == 1
    assert route.emitted[0]['image'] == route.operation.spec['uv']
