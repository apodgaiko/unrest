"""Current startup pins close the source, journal, package and constructor chain."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

ROOT = Path(__file__).parent
EDGES = (
    ('primary_operations.py', 'finite/runtime_guard.py', 'primary_native_route_guard_drift'),
    ('primary_operation_journal.py', 'primary_operations.py', 'primary_journal_operation_base_drift'),
    ('primary_package_operations.py', 'primary_operations.py', 'primary_package_operations_base_drift'),
    ('finite/child_relative.py', 'primary_operations.py', 'child_relative_operation_constructor_source'),
)


def selected_pin(body, reason):
    gates = []
    for node in ast.walk(ast.parse(body)):
        if not isinstance(node, ast.If):
            continue
        for statement in node.body:
            call = statement.exc if isinstance(statement, ast.Raise) else (
                statement.value if isinstance(statement, ast.Expr) else None)
            if (isinstance(call, ast.Call) and len(call.args) == 1
                    and isinstance(call.args[0], ast.Constant) and call.args[0].value == reason):
                gates.append(node.test)
    assert len(gates) == 1
    comparison = gates[0]
    assert isinstance(comparison, ast.Compare) and len(comparison.ops) == 1
    assert isinstance(comparison.ops[0], ast.NotEq)
    assert isinstance(comparison.left, ast.Call) and len(comparison.comparators) == 1
    pin = comparison.comparators[0]
    assert isinstance(pin, ast.Constant) and isinstance(pin.value, str) and len(pin.value) == 64
    return pin.value


@pytest.mark.parametrize(('consumer', 'dependency', 'reason'), EDGES)
def test_exact_current_startup_dependency_pin(consumer, dependency, reason):
    expected = hashlib.sha256((ROOT / dependency).read_bytes()).hexdigest()
    assert selected_pin((ROOT / consumer).read_bytes(), reason) == expected


@pytest.mark.parametrize(('consumer', 'dependency', 'reason'), EDGES)
def test_stale_startup_pin_or_dependency_cannot_match(consumer, dependency, reason):
    body = (ROOT / consumer).read_bytes()
    actual = (ROOT / dependency).read_bytes()
    pin = selected_pin(body, reason)
    assert pin != hashlib.sha256(actual + b'\n# changed dependency\n').hexdigest()
    changed = body.replace(pin.encode(), b'0' * 64)
    assert selected_pin(changed, reason) != hashlib.sha256(actual).hexdigest()
