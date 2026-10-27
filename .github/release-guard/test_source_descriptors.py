"""Invalid kernel descriptors preserve ordinary errors without socket authority."""
import errno
import os
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from source_sockets import Hooks


@pytest.mark.parametrize('descriptor', [-1, -100])
@pytest.mark.parametrize('operation', ['read', 'write'])
def test_negative_fd_keeps_real_ebadf(descriptor, operation):
    hooks = object.__new__(Hooks)
    hooks.policy = SimpleNamespace(refuse=lambda reason:pytest.fail(reason))
    function = getattr(os, operation)
    with pytest.raises(OSError) as caught:
        hooks.fd_io(function, descriptor, 1 if operation == 'read' else b'x')
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('descriptor', [True, '-1', object()])
def test_noninteger_descriptor_never_invokes_conversion(descriptor):
    hooks = object.__new__(Hooks)
    def refuse(reason):
        raise Refused(reason)
    hooks.policy = SimpleNamespace(refuse=refuse)
    with pytest.raises(Refused):
        hooks.fd_io(lambda *args:pytest.fail('invalid descriptor delegated'), descriptor, 1)
