"""Primitive namespace acquisition; no Python execution provenance policy."""
import types
from typing import Any,cast
from content_manifest import Refused

def _namespace(container: object) -> dict[str, Any]:
    if type(container) in (types.ModuleType, type):
        values = vars(container)
    elif type(container) is dict:
        values = container
    else:
        raise Refused('namespace container refused')
    if len(values) > 8192:
        raise Refused('namespace size bound')
    result = {}
    for key, value in values.items():
        if type(key) is not str:
            raise Refused('non-string namespace key')
        result[key] = value
    return result

def instance_fields(value):
    import types
    cls = type(value)
    # Native type descriptors avoid user-defined metaclass and __dict__ access.
    namespace_descriptor = vars(type)['__dict__']
    lineage_descriptor = vars(type)['__mro__']
    for parent in lineage_descriptor.__get__(cls, type(cls)):
        namespace = namespace_descriptor.__get__(parent, type(parent))
        fields: dict[str, Any] = {}
        for key, item in namespace.items():
            if type(key) is not str or len(fields) >= 8192:
                raise Refused('cleanup inline class namespace')
            fields[key] = item
        descriptor = fields.get('__dict__')
        if type(descriptor) not in (types.GetSetDescriptorType, types.MemberDescriptorType):
            continue
        native = cast(types.GetSetDescriptorType | types.MemberDescriptorType, descriptor)
        if native.__objclass__ is parent and native.__name__ == '__dict__':
            result = native.__get__(value, cls)
            _namespace(result)
            return result
    raise Refused('cleanup inline instance dictionary')
