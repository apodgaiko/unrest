"""Existing immutable metadata is discoverable only by the full-source slice."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from primary_policy import command_environment, environment


def test_full_source_can_stat_existing_native_metadata_without_changing_other_duties():
    base = environment()
    source = environment(source=True)
    assert '/native/bin' not in base['PATH'].split(':')
    assert source['PATH'] == base['PATH'] + ':/native/bin'
    assert source['TMPDIR'] == '/work/owned/tmp'
    assert {key: value for key, value in source.items() if key not in {'PATH', 'TMPDIR', 'MYPY_CACHE_DIR'}} == {
        key: value for key, value in base.items() if key not in {'PATH', 'TMPDIR', 'MYPY_CACHE_DIR'}}
    assert command_environment(source, source, source=True)
    assert not command_environment(source, base)


@pytest.mark.parametrize('path', ['/native/bin', '/foreign:/native/bin',
                                 '/opt/source-bootstrap/bin:/usr/local/bin:/usr/bin:/bin:/native/bin:/foreign'])
def test_metadata_presence_never_makes_arbitrary_paths_admissible(path):
    source = environment(source=True)
    assert not command_environment({**source, 'PATH': path}, source, source=True)
