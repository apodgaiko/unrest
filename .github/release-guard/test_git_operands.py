"""Git data is bounded and typed without becoming executable syntax."""
import pytest

from content_manifest import Refused
from git_policy import operand_digest as digest, operand_date_text as date_text, operand_text as text


@pytest.mark.parametrize('value',[True,None,'A'*40,'a'*39,'a'*41,'HEAD~1','--option','a'*39+'\n'])
def test_object_ids_never_admit_revision_expressions_or_options(value):
    with pytest.raises(Refused):
        digest(value)


@pytest.mark.parametrize('value',['2026-10-27T18:25:07Z','2026-10-27T18:25:07+00:00','2026-10-27T18:25:07+04:00'])
def test_original_git_date_forms_remain_exact(value):
    assert date_text(value)==value


@pytest.mark.parametrize('value',[True,'2026-10-27','2026-10-27T18:25:07','invalid-date','x'*4097,'x\0y'])
def test_unbounded_or_noncanonical_dates_and_data_refuse(value):
    with pytest.raises(Refused):
        date_text(value)
    if not isinstance(value,str) or '\0' in value or len(value)>4096:
        with pytest.raises(Refused):
            text(value)
