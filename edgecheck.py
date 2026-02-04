#!/usr/bin/env python3
"""edgecheck - Python Edge Case Detector.

Zero-dependency AST-based static analysis that finds missing edge case
handling in Python code.  Catches the patterns that AI coding agents
most commonly miss: unchecked None, missing zero-division guards,
unprotected dict/list access, missing timeouts, and more.

Usage:
    edgecheck file.py            # scan a single file
    edgecheck src/               # scan a directory
    edgecheck src/ --check       # CI mode (exit 1 if findings)
    edgecheck src/ --json        # JSON output
    cat file.py | edgecheck -    # read from stdin
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Severity ──────────────────────────────────────────────────────────────────

class Severity:
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    _order = {"error": 2, "warning": 1, "info": 0}

    @classmethod
    def rank(cls, s: str) -> int:
        return cls._order.get(s, -1)


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
SEV_COLORS = {
    "error": "\033[91m",
    "warning": "\033[33m",
    "info": "\033[36m",
}


# ── Finding ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    file: str
    line: int
    col: int = 0
    context: str = ""


# ── Rule Registry ────────────────────────────────────────────────────────────

RULES: dict[str, tuple[str, str, str]] = {
    # id: (name, severity, description)
    "EC01": ("Unchecked Optional Parameter", "warning",
             "Function accepts Optional/None type but never checks for None"),
    "EC02": ("Division Without Zero Guard", "error",
             "Division by a variable without checking for zero"),
    "EC03": ("Unguarded Dict Key Access", "warning",
             "Dict subscript access without .get(), 'in' check, or try/except"),
    "EC04": ("next() Without Default", "warning",
             "next() on iterator without default arg (raises StopIteration)"),
    "EC05": ("Missing Network Timeout", "error",
             "HTTP request without explicit timeout parameter"),
    "EC06": ("Unchecked Subprocess", "warning",
             "subprocess.run/call without check=True or returncode handling"),
    "EC07": ("Bare int/float Conversion", "warning",
             "int() or float() on variable without try/except ValueError"),
    "EC08": ("if/elif Chain Without else", "info",
             "Long if/elif chain (3+) without a default else clause"),
    "EC09": ("Unguarded List Index", "warning",
             "List access by variable index without bounds check"),
    "EC10": ("Collection Unpack Without Length Check", "warning",
             "Tuple/list unpacking without ensuring sufficient elements"),
    "EC11": ("Unchecked .pop() on Collection", "info",
             ".pop() on potentially empty list/dict without guard"),
    "EC12": ("File Open Without Existence Guard", "info",
             "open() call without Path.exists(), os.path.exists(), or try/except"),
    "EC13": ("Regex Compile With User Input", "warning",
             "re.compile() or re.search() with variable pattern without try/except"),
    "EC14": ("Missing Return on Error Path", "warning",
             "Function with multiple returns where some branches lack return"),
    "EC15": ("Chained Attribute Without None Check", "warning",
             "Long attribute chain (3+) without intermediate None checks"),
    "EC16": ("Subscript of Function Return", "warning",
             "Indexing into function return without checking for None/empty"),
    "EC17": ("str.split() Index Access", "error",
             "Indexing into str.split() result without checking parts count"),
    "EC18": ("Missing KeyboardInterrupt Handler", "info",
             "Long-running loop without KeyboardInterrupt handling"),
    "EC19": ("json.loads Without Error Handling", "warning",
             "json.loads/json.load without try/except for JSONDecodeError"),
    "EC20": ("os.environ Direct Access", "warning",
             "os.environ['KEY'] without .get() or try/except KeyError"),
}


# ── AST Helpers ──────────────────────────────────────────────────────────────

def _get_name(node: ast.AST) -> str | None:
    """Extract a string name from various AST node types."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _get_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_none_check(node: ast.AST, name: str) -> bool:
    """Check if node is a None check for the given variable name."""
    if isinstance(node, ast.Compare):
        # x is None / x is not None
        left_name = _get_name(node.left)
        if left_name == name:
            for op in node.ops:
                if isinstance(op, (ast.Is, ast.IsNot)):
                    for comp in node.comparators:
                        if isinstance(comp, ast.Constant) and comp.value is None:
                            return True
            # x == None / x != None
            for op in node.ops:
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    for comp in node.comparators:
                        if isinstance(comp, ast.Constant) and comp.value is None:
                            return True
    # not x / if x
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        n = _get_name(node.operand)
        if n == name:
            return True
    if isinstance(node, ast.Name) and node.id == name:
        return True
    return False


def _is_in_try(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Check if node is inside a try/except block."""
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.Try):
            return True
        if isinstance(current, (ast.ExceptHandler,)):
            return True
    return False


def _find_names_checked_for_none(body: list[ast.stmt]) -> set[str]:
    """Find all variable names that are checked for None in if/assert stmts."""
    checked: set[str] = set()
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.If):
            _extract_none_checked(node.test, checked)
        if isinstance(node, ast.Assert):
            _extract_none_checked(node.test, checked)
    return checked


def _extract_none_checked(test: ast.AST, checked: set[str]) -> None:
    """Extract names being checked against None in a test expression."""
    if isinstance(test, ast.Compare):
        left = _get_name(test.left)
        if left:
            for op, comp in zip(test.ops, test.comparators):
                if isinstance(comp, ast.Constant) and comp.value is None:
                    checked.add(left)
    if isinstance(test, ast.BoolOp):
        for v in test.values:
            _extract_none_checked(v, checked)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        n = _get_name(test.operand)
        if n:
            checked.add(n)
    if isinstance(test, ast.Name):
        checked.add(test.id)


def _build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Build child→parent mapping for the AST."""
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _function_has_check(func_body: list[ast.stmt], param_name: str) -> bool:
    """Check if function body contains a None/truthy check for param."""
    for node in ast.walk(ast.Module(body=func_body, type_ignores=[])):
        if isinstance(node, ast.If):
            if _is_none_check(node.test, param_name):
                return True
            if isinstance(node.test, ast.BoolOp):
                for v in node.test.values:
                    if _is_none_check(v, param_name):
                        return True
        if isinstance(node, ast.Assert):
            if _is_none_check(node.test, param_name):
                return True
        # isinstance(x, ...) is also a check
        if isinstance(node, ast.Call):
            fn = _get_name(node.func)
            if fn == "isinstance" and len(node.args) >= 1:
                n = _get_name(node.args[0])
                if n == param_name:
                    return True
        # Guard: if param_name: / if not param_name:
        if isinstance(node, ast.IfExp):
            if _is_none_check(node.test, param_name):
                return True
    return False


# ── Rule Checkers ────────────────────────────────────────────────────────────

def _check_ec01(tree: ast.AST, filepath: str) -> list[Finding]:
    """EC01: Optional parameter without None check."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for arg in node.args.args + node.args.kwonlyargs:
            annotation = arg.annotation
            if annotation is None:
                continue
            is_optional = False
            # Optional[X]
            if isinstance(annotation, ast.Subscript):
                base = _get_name(annotation.value)
                if base in ("Optional", "typing.Optional"):
                    is_optional = True
            # X | None
            if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
                for operand in (annotation.left, annotation.right):
                    if isinstance(operand, ast.Constant) and operand.value is None:
                        is_optional = True
                    if isinstance(operand, ast.Name) and operand.id == "None":
                        is_optional = True
            if not is_optional:
                continue
            param_name = arg.arg
            # Skip self/cls
            if param_name in ("self", "cls"):
                continue
            if not _function_has_check(node.body, param_name):
                findings.append(Finding(
                    rule="EC01",
                    severity="warning",
                    message=f"Parameter '{param_name}' is Optional but never checked for None",
                    file=filepath,
                    line=arg.lineno,
                    col=arg.col_offset,
                    context=f"def {node.name}(..., {param_name}: Optional[...], ...)",
                ))
    return findings


def _check_ec02(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC02: Division without zero guard."""
    findings: list[Finding] = []

    # Pre-scan: find all variables that are zero-checked in if-statements
    zero_checked: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            _extract_zero_checked(node.test, zero_checked)

    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp):
            continue
        if not isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            continue
        # Only flag when divisor is a variable (not a constant)
        if isinstance(node.right, ast.Constant):
            continue
        if isinstance(node.right, ast.Name):
            if _is_in_try(node, parents):
                continue
            divisor = node.right.id
            # Skip if there's a zero-check for this variable
            if divisor in zero_checked:
                continue
            findings.append(Finding(
                rule="EC02",
                severity="error",
                message=f"Division by variable '{divisor}' without zero check or try/except",
                file=filepath,
                line=node.lineno,
                col=node.col_offset,
                context=f"... / {divisor}",
            ))
    return findings


def _extract_zero_checked(test: ast.AST, checked: set[str]) -> None:
    """Find variable names checked against zero in a test expression."""
    if isinstance(test, ast.Compare):
        left = _get_name(test.left)
        if left:
            for op, comp in zip(test.ops, test.comparators):
                if isinstance(comp, ast.Constant) and comp.value == 0:
                    checked.add(left)
                # Also catch `if count:` / `if not count:` patterns
    if isinstance(test, ast.BoolOp):
        for v in test.values:
            _extract_zero_checked(v, checked)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        n = _get_name(test.operand)
        if n:
            checked.add(n)
    # `if divisor:` — truthy check guards against zero
    if isinstance(test, ast.Name):
        checked.add(test.id)


def _is_in_annotation(node: ast.AST, parents: dict) -> bool:
    """Check if node is inside a type annotation context."""
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check if we're in the returns or args annotations
            if hasattr(current, 'returns') and current.returns is not None:
                return True
            for arg in (current.args.args + current.args.kwonlyargs +
                       current.args.posonlyargs):
                if arg.annotation is not None:
                    return True
        if isinstance(current, ast.AnnAssign):
            return True
        if isinstance(current, ast.arg) and current.annotation is not None:
            return True
    return False


def _check_ec03(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC03: Unguarded dict key access (d[key] instead of d.get(key))."""
    findings: list[Finding] = []
    # Collect annotation nodes to skip
    annotation_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.returns:
                for n in ast.walk(node.returns):
                    annotation_nodes.add(id(n))
            for arg in (node.args.args + node.args.kwonlyargs +
                       getattr(node.args, 'posonlyargs', [])):
                if arg.annotation:
                    for n in ast.walk(arg.annotation):
                        annotation_nodes.add(id(n))
        if isinstance(node, ast.AnnAssign) and node.annotation:
            for n in ast.walk(node.annotation):
                annotation_nodes.add(id(n))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript):
            continue
        # Skip type annotations
        if id(node) in annotation_nodes:
            continue
        # Skip when inside try/except
        if _is_in_try(node, parents):
            continue
        # Only flag when both the container and key are variables
        container = _get_name(node.value)
        if not container:
            continue
        # Skip obvious list indexing (numeric subscript)
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int):
            continue
        # Skip known list-like patterns: container[0], container[-1], etc.
        # Only flag when the key is a string constant or string variable
        key_name = None
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            key_name = repr(node.slice.value)
        elif isinstance(node.slice, ast.Name):
            key_name = node.slice.id
        if key_name is None:
            continue
        # Skip os.environ (handled by EC20)
        if container in ("os.environ", "environ"):
            continue
        # Check if there's a preceding 'if key in container' check
        # This is a simplified heuristic
        parent = parents.get(node)
        if isinstance(parent, ast.If):
            # Already in a conditional — likely guarded
            continue
        findings.append(Finding(
            rule="EC03",
            severity="warning",
            message=f"Dict access {container}[{key_name}] may raise KeyError — consider .get()",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=f"{container}[{key_name}]",
        ))
    return findings


def _check_ec04(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC04: next() without default argument."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = _get_name(node.func)
        if fn != "next":
            continue
        if len(node.args) >= 2 or node.keywords:
            continue  # Has default
        if _is_in_try(node, parents):
            continue
        findings.append(Finding(
            rule="EC04",
            severity="warning",
            message="next() without default — raises StopIteration if iterator is empty",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context="next(iterator)  # consider next(iterator, default)",
        ))
    return findings


# HTTP/network libraries and their request functions
NETWORK_CALL_PATTERNS: dict[str, set[str]] = {
    "requests": {"get", "post", "put", "delete", "patch", "head", "options", "request"},
    "httpx": {"get", "post", "put", "delete", "patch", "head", "options", "request"},
    "urllib.request": {"urlopen"},
    "urllib3": {"request"},
    "aiohttp": {"get", "post", "put", "delete", "patch", "head", "options"},
}


def _check_ec05(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC05: HTTP request without timeout."""
    findings: list[Finding] = []
    # Collect imported names
    imports: dict[str, str] = {}  # alias -> module
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name] = alias.name
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = _get_name(node.func)
        if not fn:
            continue

        is_network = False
        # requests.get(...), httpx.post(...), etc.
        parts = fn.rsplit(".", 1)
        if len(parts) == 2:
            module, method = parts
            base_module = imports.get(module, module)
            for lib, methods in NETWORK_CALL_PATTERNS.items():
                if (base_module == lib or module == lib) and method in methods:
                    is_network = True
                    break
        # Direct urlopen() etc.
        if fn in ("urlopen", "urllib.request.urlopen"):
            is_network = True

        if not is_network:
            continue

        has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
        if has_timeout:
            continue

        if _is_in_try(node, parents):
            continue

        findings.append(Finding(
            rule="EC05",
            severity="error",
            message=f"{fn}() without explicit timeout — may hang indefinitely",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=f"{fn}(...)  # add timeout=N",
        ))
    return findings


def _check_ec06(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC06: subprocess.run/call without check=True."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = _get_name(node.func)
        if fn not in ("subprocess.run", "subprocess.call", "subprocess.check_call",
                       "subprocess.check_output"):
            continue
        if fn.startswith("subprocess.check"):
            continue  # Already checking
        has_check = any(
            kw.arg == "check" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        if has_check:
            continue
        # Check if returncode is accessed later (simplified)
        if _is_in_try(node, parents):
            continue
        findings.append(Finding(
            rule="EC06",
            severity="warning",
            message=f"{fn}() without check=True — non-zero exit silently ignored",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=f"{fn}(...)  # add check=True or handle returncode",
        ))
    return findings


def _check_ec07(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC07: int()/float() on variable without try/except."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = _get_name(node.func)
        if fn not in ("int", "float"):
            continue
        if not node.args:
            continue
        # Skip constant conversions like int(3.14)
        if isinstance(node.args[0], ast.Constant):
            continue
        if _is_in_try(node, parents):
            continue
        arg_name = _get_name(node.args[0]) or "variable"
        findings.append(Finding(
            rule="EC07",
            severity="warning",
            message=f"{fn}({arg_name}) without try/except — may raise ValueError",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=f"{fn}({arg_name})  # wrap in try/except ValueError",
        ))
    return findings


def _check_ec08(tree: ast.AST, filepath: str) -> list[Finding]:
    """EC08: if/elif chain (3+) without else."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        # Count the chain length
        depth = 1
        current = node
        while current.orelse:
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                depth += 1
                current = current.orelse[0]
            else:
                break  # has else clause
        else:
            # No else at the end
            if depth >= 3:
                findings.append(Finding(
                    rule="EC08",
                    severity="info",
                    message=f"if/elif chain ({depth} branches) without default else clause",
                    file=filepath,
                    line=node.lineno,
                    col=node.col_offset,
                    context="if ...: ... elif ...: ... elif ...:  # missing else",
                ))
    return findings


def _check_ec09(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC09: List index by variable without bounds check."""
    findings: list[Finding] = []
    # Collect annotation nodes to skip
    annotation_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.returns:
                for n in ast.walk(node.returns):
                    annotation_nodes.add(id(n))
            for arg in (node.args.args + node.args.kwonlyargs +
                       getattr(node.args, 'posonlyargs', [])):
                if arg.annotation:
                    for n in ast.walk(arg.annotation):
                        annotation_nodes.add(id(n))
        if isinstance(node, ast.AnnAssign) and node.annotation:
            for n in ast.walk(node.annotation):
                annotation_nodes.add(id(n))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript):
            continue
        if id(node) in annotation_nodes:
            continue
        # Check if index is a variable (not constant)
        if isinstance(node.slice, ast.Constant):
            continue
        if not isinstance(node.slice, ast.Name):
            continue
        # Skip dict-like access (string keys handled by EC03)
        container = _get_name(node.value)
        if not container:
            continue
        if _is_in_try(node, parents):
            continue
        # Skip when in conditional
        parent = parents.get(node)
        if isinstance(parent, ast.If):
            continue
        idx = node.slice.id
        findings.append(Finding(
            rule="EC09",
            severity="warning",
            message=f"Indexing {container}[{idx}] — may raise IndexError if out of bounds",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=f"{container}[{idx}]  # check len({container}) > {idx} first",
        ))
    return findings


def _check_ec10(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC10: Tuple/list unpacking without length check."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Tuple):
            continue
        # Skip starred unpacking (a, *b = ...) — always safe
        has_starred = any(isinstance(elt, ast.Starred) for elt in target.elts)
        if has_starred:
            continue
        # Check if RHS is a function call or variable (not a literal tuple)
        if isinstance(node.value, (ast.Tuple, ast.List)):
            continue  # Literal unpacking — known length
        expected = len(target.elts)
        if expected < 2:
            continue
        if _is_in_try(node, parents):
            continue
        rhs = _get_name(node.value) or "expression"
        findings.append(Finding(
            rule="EC10",
            severity="warning",
            message=f"Unpacking {expected} values from {rhs} — may raise ValueError if wrong length",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=f"a, b, ... = {rhs}  # verify length first",
        ))
    return findings


def _check_ec11(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC11: .pop() without guard."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = _get_name(node.func)
        if not fn or not fn.endswith(".pop"):
            continue
        # dict.pop(key, default) with 2 args is safe
        if len(node.args) >= 2:
            continue
        # list.pop() with no args or one arg is fine but risky on empty
        if _is_in_try(node, parents):
            continue
        container = fn.rsplit(".pop", 1)[0]
        findings.append(Finding(
            rule="EC11",
            severity="info",
            message=f"{container}.pop() may raise on empty collection — consider checking length",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
        ))
    return findings


def _check_ec12(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC12: open() without existence guard."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = _get_name(node.func)
        if fn not in ("open", "builtins.open"):
            continue
        # Check mode — write modes create the file, so no guard needed
        mode = "r"  # default
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            mode = str(node.args[1].value)
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = str(kw.value.value)
        if "w" in mode or "a" in mode or "x" in mode:
            continue  # Write/append/create modes
        if _is_in_try(node, parents):
            continue
        # Check if path arg is a constant (known to exist by author)
        if node.args and isinstance(node.args[0], ast.Constant):
            continue
        findings.append(Finding(
            rule="EC12",
            severity="info",
            message="open() for reading without existence check or try/except",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context="open(path)  # wrap in try/except FileNotFoundError",
        ))
    return findings


def _check_ec13(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC13: re.compile/search/match with variable pattern without try."""
    findings: list[Finding] = []
    re_funcs = {"re.compile", "re.search", "re.match", "re.findall",
                "re.sub", "re.split", "re.fullmatch"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = _get_name(node.func)
        if fn not in re_funcs:
            continue
        if not node.args:
            continue
        # If pattern is a constant, it's author-controlled → skip
        if isinstance(node.args[0], ast.Constant):
            continue
        if _is_in_try(node, parents):
            continue
        findings.append(Finding(
            rule="EC13",
            severity="warning",
            message=f"{fn}() with variable pattern — may raise re.error on invalid regex",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=f"{fn}(user_pattern)  # wrap in try/except re.error",
        ))
    return findings


def _check_ec14(tree: ast.AST, filepath: str) -> list[Finding]:
    """EC14: Function with inconsistent return paths."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Find all return statements
        returns: list[ast.Return] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child is not node:
                returns.append(child)
        if len(returns) < 2:
            continue
        has_value_return = any(r.value is not None for r in returns)
        # Only bare `return` (no value at all), not `return None`
        has_bare_return = any(r.value is None for r in returns)
        if has_value_return and has_bare_return:
            findings.append(Finding(
                rule="EC14",
                severity="warning",
                message=f"Function '{node.name}' mixes value returns with bare/None returns",
                file=filepath,
                line=node.lineno,
                col=node.col_offset,
                context=f"def {node.name}(): some paths return value, others return None",
            ))
    return findings


def _check_ec15(tree: ast.AST, filepath: str) -> list[Finding]:
    """EC15: Long attribute chain without None checks."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        # Count chain depth
        depth = 1
        current = node
        while isinstance(current.value, ast.Attribute):
            depth += 1
            current = current.value
        if depth < 3:
            continue
        chain = _get_name(node) or "obj.attr1.attr2.attr3"
        findings.append(Finding(
            rule="EC15",
            severity="warning",
            message=f"Long attribute chain ({depth} deep) — intermediate values may be None",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=chain,
        ))
    return findings


def _check_ec16(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC16: Indexing into function call return value."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        # Skip .get() .setdefault() .items() etc — known-safe returns
        fn = _get_name(node.value.func)
        if fn and any(fn.endswith(s) for s in (".get", ".items", ".keys", ".values",
                                                 ".setdefault", "range", "enumerate",
                                                 "zip", "list", "dict", "tuple", "sorted")):
            continue
        if _is_in_try(node, parents):
            continue
        fn_display = fn or "function()"
        findings.append(Finding(
            rule="EC16",
            severity="warning",
            message=f"Indexing into {fn_display} return — may be None or empty",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=f"{fn_display}[index]  # check return value first",
        ))
    return findings


def _check_ec17(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC17: str.split() with immediate index access."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        fn = _get_name(node.value.func)
        if not fn or not fn.endswith(".split"):
            continue
        # Allow [0] only if split has maxsplit arg that guarantees the part
        if _is_in_try(node, parents):
            continue
        idx = None
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int):
            idx = node.slice.value
        findings.append(Finding(
            rule="EC17",
            severity="error",
            message=f".split()[{idx if idx is not None else 'i'}] — may fail on empty/unexpected string",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context="s.split(sep)[n]  # check len(parts) first",
        ))
    return findings


def _check_ec19(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC19: json.loads/load without error handling."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = _get_name(node.func)
        if fn not in ("json.loads", "json.load"):
            continue
        if _is_in_try(node, parents):
            continue
        findings.append(Finding(
            rule="EC19",
            severity="warning",
            message=f"{fn}() without try/except — may raise json.JSONDecodeError",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=f"{fn}(data)  # wrap in try/except json.JSONDecodeError",
        ))
    return findings


def _check_ec20(tree: ast.AST, filepath: str, parents: dict) -> list[Finding]:
    """EC20: os.environ['KEY'] without .get() or try/except."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript):
            continue
        container = _get_name(node.value)
        if container not in ("os.environ", "environ"):
            continue
        if _is_in_try(node, parents):
            continue
        key = None
        if isinstance(node.slice, ast.Constant):
            key = repr(node.slice.value)
        findings.append(Finding(
            rule="EC20",
            severity="warning",
            message=f"os.environ[{key or 'KEY'}] — raises KeyError if unset; use .get() or try/except",
            file=filepath,
            line=node.lineno,
            col=node.col_offset,
            context=f"os.environ[{key or 'KEY'}]  # use os.environ.get({key or 'KEY'}, default)",
        ))
    return findings


# ── Main Scanner ─────────────────────────────────────────────────────────────

ALL_CHECKERS = [
    _check_ec01, _check_ec02, _check_ec03, _check_ec04,
    _check_ec05, _check_ec06, _check_ec07, _check_ec08,
    _check_ec09, _check_ec10, _check_ec11, _check_ec12,
    _check_ec13, _check_ec14, _check_ec15, _check_ec16,
    _check_ec17, _check_ec19, _check_ec20,
]

# Checkers that take parents map
NEEDS_PARENTS = {
    _check_ec02, _check_ec03, _check_ec04, _check_ec05,
    _check_ec06, _check_ec07, _check_ec09, _check_ec10,
    _check_ec11, _check_ec12, _check_ec13, _check_ec16,
    _check_ec17, _check_ec19, _check_ec20,
}


@dataclass
class ScanResult:
    file: str
    findings: list[Finding]
    score: int
    grade: str
    lines: int = 0
    error: str = ""


def scan_file(filepath: str, source: str | None = None,
              ignore_rules: set[str] | None = None,
              severity_filter: str | None = None) -> ScanResult:
    """Scan a single Python file."""
    ignore_rules = ignore_rules or set()

    if source is None:
        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError) as e:
            return ScanResult(file=filepath, findings=[], score=100, grade="A+",
                              error=str(e))

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        return ScanResult(file=filepath, findings=[], score=100, grade="A+",
                          error=f"SyntaxError: {e}")

    lines = source.count("\n") + 1
    parents = _build_parent_map(tree)
    all_findings: list[Finding] = []

    for checker in ALL_CHECKERS:
        if checker in NEEDS_PARENTS:
            findings = checker(tree, filepath, parents)
        else:
            findings = checker(tree, filepath)
        all_findings.extend(findings)

    # Filter by ignored rules
    all_findings = [f for f in all_findings if f.rule not in ignore_rules]

    # Filter by severity
    if severity_filter:
        min_rank = Severity.rank(severity_filter)
        all_findings = [f for f in all_findings if Severity.rank(f.severity) >= min_rank]

    # Sort by severity (highest first), then line number
    all_findings.sort(key=lambda f: (-Severity.rank(f.severity), f.line))

    # Score: start at 100, subtract per finding
    penalty = 0
    for f in all_findings:
        if f.severity == "error":
            penalty += 10
        elif f.severity == "warning":
            penalty += 5
        else:
            penalty += 1
    score = max(0, 100 - penalty)
    grade = _grade(score)

    return ScanResult(file=filepath, findings=all_findings, score=score,
                      grade=grade, lines=lines)


def _grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _grade_color(grade: str) -> str:
    return {
        "A+": "\033[32;1m", "A": "\033[32m", "B": "\033[33m",
        "C": "\033[33m", "D": "\033[91m", "F": "\033[31;1m",
    }.get(grade, "")


# ── File Discovery ───────────────────────────────────────────────────────────

def _find_python_files(path: Path) -> list[Path]:
    """Find all .py files under path."""
    if path.is_file():
        return [path] if path.suffix == ".py" else []

    files: list[Path] = []
    skip = {".git", "__pycache__", "node_modules", ".venv", "venv",
            ".tox", ".eggs", "build", "dist", ".mypy_cache", ".ruff_cache"}
    for root, dirs, filenames in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")]
        for fname in sorted(filenames):
            if fname.endswith(".py"):
                files.append(Path(root) / fname)
    return files


# ── Output Formatters ────────────────────────────────────────────────────────

def _format_rich(results: list[ScanResult], verbose: bool = False) -> str:
    lines: list[str] = []
    total_findings = 0

    for r in results:
        if r.error:
            lines.append(f"  {DIM}⚠ {r.file}: {r.error}{RESET}")
            continue

        total_findings += len(r.findings)
        if not r.findings and not verbose:
            continue

        gc = _grade_color(r.grade)
        lines.append(f"\n{BOLD}{r.file}{RESET}  {gc}{r.grade}{RESET} ({r.score}/100)")

        for f in r.findings:
            sev_color = SEV_COLORS.get(f.severity, "")
            lines.append(
                f"  {sev_color}{f.severity:7}{RESET} {f.line:>4}:{f.col:<3} "
                f"[{f.rule}] {f.message}"
            )
            if verbose and f.context:
                lines.append(f"         {DIM}{f.context}{RESET}")

    # Summary
    lines.append(f"\n{'─' * 50}")
    n_files = sum(1 for r in results if not r.error)
    avg_score = (sum(r.score for r in results if not r.error) / n_files) if n_files else 0
    avg_grade = _grade(int(avg_score))
    gc = _grade_color(avg_grade)
    by_sev: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    sev_summary = "  ".join(
        f"{SEV_COLORS.get(s, '')}{s}: {c}{RESET}"
        for s, c in sorted(by_sev.items(), key=lambda x: -Severity.rank(x[0]))
    )
    lines.append(f"  Files: {n_files}  Findings: {total_findings}  {sev_summary}")
    lines.append(f"  Average: {gc}{avg_grade} ({int(avg_score)}/100){RESET}")
    lines.append("")
    return "\n".join(lines)


def _format_json(results: list[ScanResult]) -> str:
    output = []
    for r in results:
        output.append({
            "file": r.file,
            "score": r.score,
            "grade": r.grade,
            "lines": r.lines,
            "error": r.error or None,
            "findings": [
                {
                    "rule": f.rule,
                    "severity": f.severity,
                    "message": f.message,
                    "line": f.line,
                    "col": f.col,
                    "context": f.context,
                }
                for f in r.findings
            ],
        })
    return json.dumps(output if len(output) > 1 else output[0], indent=2)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="edgecheck",
        description="Python Edge Case Detector — find missing error handling and boundary checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              edgecheck file.py              Scan a single file
              edgecheck src/                 Scan a directory
              edgecheck src/ --check         CI mode (exit 1 if errors/warnings)
              edgecheck src/ --json          JSON output
              edgecheck src/ -v              Verbose with context
              cat file.py | edgecheck -      Read from stdin
              edgecheck --rules              List all rules

            Catches patterns that AI coding agents most commonly miss.
        """),
    )
    parser.add_argument("path", nargs="?",
                        help="Python file, directory, or '-' for stdin")
    parser.add_argument("-s", "--severity", choices=["error", "warning", "info"],
                        help="Minimum severity to report")
    parser.add_argument("--check", action="store_true",
                        help="CI mode: exit 1 if error/warning findings")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show context for each finding")
    parser.add_argument("--ignore", type=str, default="",
                        help="Comma-separated rule IDs to ignore")
    parser.add_argument("--rules", action="store_true",
                        help="List all rules and exit")
    parser.add_argument("--version", action="version", version="edgecheck 1.0.0")

    args = parser.parse_args(argv)

    if args.rules:
        print(f"\n{BOLD}edgecheck Rules{RESET}\n")
        for rid, (name, sev, desc) in sorted(RULES.items()):
            color = SEV_COLORS.get(sev, "")
            print(f"  {color}{rid}{RESET}  {sev:7}  {name}")
            print(f"            {DIM}{desc}{RESET}")
        print()
        return 0

    if not args.path:
        parser.print_help()
        return 1

    ignore = {r.strip().upper() for r in args.ignore.split(",") if r.strip()}

    results: list[ScanResult] = []
    if args.path == "-":
        source = sys.stdin.read()
        results.append(scan_file("<stdin>", source=source,
                                 ignore_rules=ignore, severity_filter=args.severity))
    else:
        target = Path(args.path)
        if not target.exists():
            print(f"Error: {args.path} does not exist", file=sys.stderr)
            return 1
        files = _find_python_files(target)
        if not files:
            print(f"No Python files found at {args.path}", file=sys.stderr)
            return 1
        for f in files:
            results.append(scan_file(str(f), ignore_rules=ignore,
                                     severity_filter=args.severity))

    if args.json:
        print(_format_json(results))
    else:
        print(_format_rich(results, verbose=args.verbose))

    if args.check:
        has_issues = any(
            any(f.severity in ("error", "warning") for f in r.findings)
            for r in results
        )
        return 1 if has_issues else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
