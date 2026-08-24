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
from functools import lru_cache
from importlib import resources
import json
from typing import Any, TypeVar

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool

_CATALOG_RESOURCE = "bundled/foundation/public-surface.v1.json"
_F = TypeVar("_F", bound=Callable[..., Any])


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


def catalog_tool(mcp: FastMCP, name: str) -> Callable[[_F], _F]:
    """Register a function with catalog-owned input and output schemas."""

    def register(function: _F) -> _F:
        tool = FunctionTool.from_function(
            function,
            name=name,
            output_schema=public_output_schema(name),
        )
        tool.parameters = public_input_schema(name)
        mcp.add_tool(tool)
        return function

    return register


__all__ = [
    "catalog_tool",
    "public_input_schema",
    "public_output_schema",
    "public_surface_catalog",
]
