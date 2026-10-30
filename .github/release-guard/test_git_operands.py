"""Git data is bounded and typed without becoming executable syntax."""
import pytest

from content_manifest import Refused
from git_policy import operand_digest as digest, operand_text as text


@pytest.mark.parametrize('value',[True,None,'A'*40,'a'*39,'a'*41,'HEAD~1','--option','a'*39+'\n'])
def test_object_ids_never_admit_revision_expressions_or_options(value):
    with pytest.raises(Refused):
        digest(value)



@pytest.mark.parametrize('value',['2026-10-27T18:25:07Z','relative date','not-a-calendar-date'])
def test_date_metadata_is_bounded_text(value):
    assert text(value)==value


@pytest.mark.parametrize('value',[True,None,'','x'*4097,'x\0y','λ'*2049])
def test_commit_metadata_refuses_nontext_nul_and_oversized_utf8(value):
    with pytest.raises(Refused):
        text(value)
