"""Catalog-backed schemas for the additive v0.3.1 public surface.

FastMCP derives useful schemas from annotations, but those derivations are not
the public contract: they inline references, express nullable values
differently, and cannot represent ``submit_run``'s operation-dependent
arguments.  This module keeps the installed catalog authoritative and gives
every additive tool the exact closed wire schemas frozen before implementation.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import datetime
from functools import lru_cache
from importlib import resources
import inspect
import json
import math
import re
from typing import Any, TypeVar

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool
from pydantic import ValidationError, validate_call

_CATALOG_RESOURCE = "bundled/foundation/public-surface.v1.json"
_F = TypeVar("_F", bound=Callable[..., Any])
_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class PublicSchemaValidationError(ValueError):
    """A value failed the frozen public schema without retaining that value."""

    def __init__(self, path: str, keyword: str) -> None:
        self.path = path
        self.keyword = keyword
        super().__init__(f"public schema rejected {path} ({keyword})")


@lru_cache(maxsize=1)
def public_surface_catalog() -> dict[str, Any]:
    """Load and minimally verify the packaged public-surface authority."""
    raw = resources.files("unrest_harness").joinpath(_CATALOG_RESOURCE).read_bytes()
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise RuntimeError("public-surface catalog must be an object")
    if document.get("catalog_id") != "unrest.public-surface.v1":
        raise RuntimeError("public-surface catalog identity mismatch")
    definitions = document.get("definitions")
    methods = document.get("mcp_methods")
    if not isinstance(definitions, dict) or not isinstance(methods, list):
        raise RuntimeError("public-surface catalog is incomplete")
    names = [method.get("name") for method in methods if isinstance(method, dict)]
    if len(names) != 23 or len(set(names)) != 23 or not all(isinstance(name, str) for name in names):
        raise RuntimeError("public-surface MCP method inventory mismatch")
    for method in methods:
        if not isinstance(method, dict):
            raise RuntimeError("public-surface method must be an object")
        _definition_name(method.get("args_schema"), definitions)
        _definition_name(method.get("result_schema"), definitions)
    _definition_name("#/definitions/error_envelope", definitions)
    return document


def _definition_name(reference: object, definitions: Mapping[str, Any]) -> str:
    prefix = "#/definitions/"
    if not isinstance(reference, str) or not reference.startswith(prefix):
        raise RuntimeError("public-surface schema reference is invalid")
    name = reference.removeprefix(prefix)
    if name not in definitions:
        raise RuntimeError("public-surface schema reference is unresolved")
    return name


def _method(name: str) -> dict[str, Any]:
    catalog = public_surface_catalog()
    for method in catalog["mcp_methods"]:
        if method["name"] == name:
            return method
    raise RuntimeError(f"unknown additive public method: {name}")


def _referenced_names(value: object) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/definitions/"):
            names.add(reference.removeprefix("#/definitions/"))
        for item in value.values():
            names.update(_referenced_names(item))
    elif isinstance(value, list):
        for item in value:
            names.update(_referenced_names(item))
    return names


def _dependency_closure(*schemas: Mapping[str, Any]) -> dict[str, Any]:
    definitions = public_surface_catalog()["definitions"]
    pending: set[str] = set()
    for schema in schemas:
        pending.update(_referenced_names(schema))
    included: dict[str, Any] = {}
    while pending:
        name = min(pending)
        pending.remove(name)
        if name in included:
            continue
        if name not in definitions:
            raise RuntimeError("public-surface schema reference is unresolved")
        definition = deepcopy(definitions[name])
        included[name] = definition
        pending.update(_referenced_names(definition) - included.keys())
    return {name: included[name] for name in sorted(included)}


def public_input_schema(name: str) -> dict[str, Any]:
    """Return one self-contained MCP request schema from the catalog."""
    catalog = public_surface_catalog()
    method = _method(name)
    definition_name = _definition_name(method["args_schema"], catalog["definitions"])
    schema = deepcopy(catalog["definitions"][definition_name])
    dependencies = _dependency_closure(schema)
    if dependencies:
        schema["definitions"] = dependencies
    return schema


def public_output_schema(name: str) -> dict[str, Any]:
    """Return the closed success-or-safe-error MCP result schema."""
    catalog = public_surface_catalog()
    method = _method(name)
    definition_name = _definition_name(method["result_schema"], catalog["definitions"])
    success = deepcopy(catalog["definitions"][definition_name])
    error = deepcopy(catalog["definitions"]["error_envelope"])
    schema: dict[str, Any] = {"oneOf": [success, error], "type": "object"}
    dependencies = _dependency_closure(success, error)
    if dependencies:
        schema["definitions"] = dependencies
    return schema


def _fail(path: str, keyword: str) -> None:
    raise PublicSchemaValidationError(path, keyword)


def _json_equal(left: object, right: object) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, int | float) and isinstance(right, int | float):
        return left == right
    return type(left) is type(right) and left == right


def _matches(value: object, schema: Mapping[str, Any], root: Mapping[str, Any]) -> bool:
    try:
        _validate_schema_value(value, schema, root, "$")
    except PublicSchemaValidationError:
        return False
    return True


def _type_matches(value: object, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (
            isinstance(value, int | float)
            and not isinstance(value, bool)
            and (isinstance(value, int) or math.isfinite(value))
        )
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict) and all(isinstance(key, str) for key in value)
    raise RuntimeError(f"unsupported public schema type: {expected}")


def _validate_schema_value(
    value: object,
    schema: Mapping[str, Any],
    root: Mapping[str, Any],
    path: str,
) -> None:
    reference = schema.get("$ref")
    if reference is not None:
        definitions = root.get("definitions")
        if not isinstance(definitions, dict):
            raise RuntimeError("public schema has no definitions")
        name = _definition_name(reference, definitions)
        target = definitions[name]
        if not isinstance(target, dict):
            raise RuntimeError("public schema definition must be an object")
        _validate_schema_value(value, target, root, path)

    all_of = schema.get("allOf")
    if all_of is not None:
        if not isinstance(all_of, list):
            raise RuntimeError("public schema allOf must be an array")
        for member in all_of:
            if not isinstance(member, dict):
                raise RuntimeError("public schema allOf member must be an object")
            _validate_schema_value(value, member, root, path)

    one_of = schema.get("oneOf")
    if one_of is not None:
        if not isinstance(one_of, list):
            raise RuntimeError("public schema oneOf must be an array")
        matches = sum(
            _matches(value, member, root)
            for member in one_of
            if isinstance(member, dict)
        )
        if matches != 1 or len(one_of) != sum(isinstance(member, dict) for member in one_of):
            _fail(path, "oneOf")

    condition = schema.get("if")
    if condition is not None:
        if not isinstance(condition, dict):
            raise RuntimeError("public schema if must be an object")
        branch = schema.get("then") if _matches(value, condition, root) else schema.get("else")
        if branch is not None:
            if not isinstance(branch, dict):
                raise RuntimeError("public schema conditional branch must be an object")
            _validate_schema_value(value, branch, root, path)

    expected_type = schema.get("type")
    if expected_type is not None:
        expected = [expected_type] if isinstance(expected_type, str) else expected_type
        if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
            raise RuntimeError("public schema type must be a string or string array")
        if not any(_type_matches(value, item) for item in expected):
            _fail(path, "type")

    if "const" in schema and not _json_equal(value, schema["const"]):
        _fail(path, "const")
    enum = schema.get("enum")
    if enum is not None:
        if not isinstance(enum, list):
            raise RuntimeError("public schema enum must be an array")
        if not any(_json_equal(value, member) for member in enum):
            _fail(path, "enum")

    if isinstance(value, dict):
        required = schema.get("required", [])
        if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
            raise RuntimeError("public schema required must be a string array")
        for name in required:
            if name not in value:
                _fail(path, "required")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise RuntimeError("public schema properties must be an object")
        for name, member in properties.items():
            if name in value:
                if not isinstance(member, dict):
                    raise RuntimeError("public property schema must be an object")
                _validate_schema_value(value[name], member, root, f"{path}.{name}")
        additional = schema.get("additionalProperties", True)
        for name in value.keys() - properties.keys():
            if additional is False:
                _fail(f"{path}.{name}", "additionalProperties")
            if isinstance(additional, dict):
                _validate_schema_value(value[name], additional, root, f"{path}.{name}")
            elif additional is not True:
                raise RuntimeError("public additionalProperties must be boolean or schema")

    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        if minimum_items is not None:
            if not isinstance(minimum_items, int) or isinstance(minimum_items, bool):
                raise RuntimeError("public minItems must be an integer")
            if len(value) < minimum_items:
                _fail(path, "minItems")
        if schema.get("uniqueItems") is True:
            for index, item in enumerate(value):
                if any(_json_equal(item, previous) for previous in value[:index]):
                    _fail(f"{path}[{index}]", "uniqueItems")
        items = schema.get("items")
        if items is not None:
            if not isinstance(items, dict):
                raise RuntimeError("public items must be an object")
            for index, item in enumerate(value):
                _validate_schema_value(item, items, root, f"{path}[{index}]")

    if isinstance(value, str):
        minimum_length = schema.get("minLength")
        if minimum_length is not None:
            if not isinstance(minimum_length, int) or isinstance(minimum_length, bool):
                raise RuntimeError("public minLength must be an integer")
            if len(value) < minimum_length:
                _fail(path, "minLength")
        pattern = schema.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                raise RuntimeError("public pattern must be a string")
            if re.search(pattern, value) is None:
                _fail(path, "pattern")
        value_format = schema.get("format")
        if value_format is not None:
            if value_format != "date-time":
                raise RuntimeError(f"unsupported public schema format: {value_format}")
            if _DATE_TIME.fullmatch(value) is None:
                _fail(path, "format")
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                _fail(path, "format")
            if parsed.tzinfo is None:
                _fail(path, "format")

    if isinstance(value, int | float) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and value < minimum:
            _fail(path, "minimum")
        if maximum is not None and value > maximum:
            _fail(path, "maximum")


def _validate(value: object, schema: dict[str, Any]) -> None:
    _validate_schema_value(value, schema, schema, "$")


def validate_public_request(name: str, value: object) -> None:
    """Validate one additive request before any effect is allowed."""
    _validate(value, public_input_schema(name))


def validate_public_result(name: str, value: object) -> None:
    """Validate one additive success or safe error result before disclosure."""
    _validate(value, public_output_schema(name))


def catalog_tool(mcp: FastMCP, name: str) -> Callable[[_F], _F]:
    """Register a function with catalog-owned schemas and runtime validation."""

    def register(function: _F) -> _F:
        checked_function = validate_call(function)

        async def invoke(**arguments: Any) -> dict[str, Any]:
            try:
                validate_public_request(name, arguments)
            except PublicSchemaValidationError:
                return {"error": {"code": "invalid_argument", "message": "invalid argument"}}
            except RuntimeError:
                return {"error": {"code": "internal_error", "message": "internal error"}}
            try:
                result = checked_function(**arguments)
                if inspect.isawaitable(result):
                    result = await result
            except ValidationError:
                return {"error": {"code": "invalid_argument", "message": "invalid argument"}}
            try:
                validate_public_result(name, result)
            except (PublicSchemaValidationError, RuntimeError):
                return {"error": {"code": "internal_error", "message": "internal error"}}
            return result

        tool = FunctionTool(
            fn=invoke,
            name=name,
            parameters=public_input_schema(name),
            output_schema=public_output_schema(name),
            return_type=dict[str, Any],
        )
        mcp.add_tool(tool)
        return function

    return register


__all__ = [
    "PublicSchemaValidationError",
    "catalog_tool",
    "public_input_schema",
    "public_output_schema",
    "public_surface_catalog",
    "validate_public_request",
    "validate_public_result",
]
