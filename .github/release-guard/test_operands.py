"""Primitive extraction stays callback-free after provenance policy retirement."""

from types import ModuleType

import pytest

from content_manifest import Refused
from operands import _namespace, instance_fields


class Trap:
    def __eq__(self, other):
        pytest.fail("equality callback")

    def __hash__(self):
        return 421771


def test_namespace_accepts_only_primitive_string_keys():
    module = ModuleType("fixture")
    module.field = object()
    assert _namespace(module)["field"] is module.field
    assert _namespace({"field": None}) == {"field": None}
    with pytest.raises(Refused):
        _namespace({Trap(): None})
    with pytest.raises(Refused):
        _namespace(Trap())
    with pytest.raises(Refused):
        _namespace({str(i): None for i in range(8193)})


def test_instance_dictionary_bypasses_attribute_and_metaclass_callbacks():
    class Meta(type):
        def __getattribute__(self, key):
            pytest.fail("metaclass attribute callback")

    class Value(metaclass=Meta):
        def __getattribute__(self, key):
            pytest.fail("instance attribute callback")

    value = object.__new__(Value)
    fields = instance_fields(value)
    fields["field"] = 123
    assert instance_fields(value) == {"field": 123}
    fields.clear()
    fields[Trap()] = None
    with pytest.raises(Refused):
        instance_fields(value)
