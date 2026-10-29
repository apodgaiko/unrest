"""Child inventory membership supplements observer-issued launch authority."""
from pathlib import Path

import pytest

from content_manifest import Refused
from source_profile import FIELDS,validate
import source_profile


@pytest.mark.parametrize('role,case', [('unknown','case'),('fixed-inline','foreign'),('root','case')])
def test_profile_rejects_unknown_domain_or_unselected_case_before_body(role,case):
    profile=dict.fromkeys(FIELDS)
    profile.update(schema='unrest.bootstrap-source.v1',role=role,case=case,cases=['case'])
    with pytest.raises(Refused,match='closed profile|inventory membership'):
        validate(profile,'cpython.run_module',('outside',))


def test_full_profile_loads_current_byte_bound_inventory_before_case_membership(monkeypatch):
    seen=[]
    def load(reference,directory,source,dependency):
        seen.append((reference,directory,source,dependency))
        return {'cases':['selected']}
    monkeypatch.setattr(source_profile,'load',load)
    reference={'path':'observer-owned-reference'}
    profile=dict.fromkeys(FIELDS)
    profile.update(schema='unrest.bootstrap-source.v1',role='fixed-inline',case='foreign',cases=reference,
                   source_sha256='a'*64,dependency_sha256='b'*64)
    with pytest.raises(Refused,match='inventory membership'):
        validate(profile,'cpython.run_module',('outside',))
    assert seen==[(reference,Path(source_profile.__file__).parent.parent/'profiles','a'*64,'b'*64)]
