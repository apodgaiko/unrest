"""Invalid kernel descriptors preserve ordinary errors without socket authority."""
import errno
import os

import pytest

from content_manifest import Refused
from source_observer import number


@pytest.mark.parametrize('descriptor', [-1, -100])
@pytest.mark.parametrize('operation', ['read', 'write'])
def test_negative_fd_keeps_real_ebadf(descriptor, operation):
    function = getattr(os, operation)
    with pytest.raises(OSError) as caught:
        function(descriptor, 1 if operation == 'read' else b'x')
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('descriptor', [True, '-1', object()])
def test_observer_descriptor_operand_never_invokes_conversion(descriptor):
    with pytest.raises(Refused):
        number(descriptor)
