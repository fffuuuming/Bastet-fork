"""
Rule: Low-level call/delegatecall without return value check.

Using .call{} or .delegatecall() in Solidity, or call/delegatecall in inline assembly,
without checking the return value can lead to:
- Ether/tokens locked in the contract when the call fails
- Silent failures and incorrect control flow
- Funds sent to the wrong recipient on subsequent operations (e.g. dust forwarded to next caller)
"""

from __future__ import annotations

import re
import sys
import warnings
from pathlib import Path
from typing import Optional

import tree_sitter
import tree_sitter_solidity
from tree_sitter import Language, Node

from models.audit_report import AuditReportV2

_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))
from rules._utils import (
    line_and_column_from_byte_offset,
    make_finding,
    read_file,
)

RULE_NAME = "Low-level call/delegatecall without return check"
SEVERITY = "medium"
TAG = ["call / delegatecall"]
SUBTAG = ["Missing Return Check"]
DESCRIPTION_BASE = (
    "The return value of a low-level call or delegatecall is not checked. "
    "If the call fails, Ether can be locked in the contract or the caller can lose funds. "
    "Always check the return value and revert or handle failure explicitly."
)

LOW_LEVEL_MEMBERS = frozenset({"call", "delegatecall"})
ASSEMBLY_OPCODES = ("call", "delegatecall")


def _get_solidity_language() -> Language:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return Language(tree_sitter_solidity.language())


def _member_property(member_expression: Node) -> Optional[Node]:
    """Property is the identifier after the dot."""
    if member_expression.child_count >= 3:
        return member_expression.child(2)
    return None


def _get_property_text(node: Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode(
        "utf-8", errors="replace"
    ).strip()


def _is_low_level_call(call_node: Node, source_bytes: bytes) -> bool:
    """
    True if this call_expression is a low-level .call or .delegatecall.
    Handles both member_expression (e.g. .call("")) and struct_expression (e.g. .call{value: x}("")).
    """
    func_node = call_node.child_by_field_name("function") or (
        call_node.child(0) if call_node.child_count > 0 else None
    )
    if not func_node:
        return False
    if func_node.type == "expression" and func_node.child_count > 0:
        func_node = func_node.child(0)
    if func_node.type == "member_expression":
        prop_node = func_node.child_by_field_name("property") or _member_property(
            func_node
        )
        if prop_node:
            prop_text = _get_property_text(prop_node, source_bytes)
            if prop_text in LOW_LEVEL_MEMBERS:
                return True
    if func_node.type == "struct_expression":
        func_text = source_bytes[func_node.start_byte : func_node.end_byte].decode(
            "utf-8", errors="replace"
        )
        for name in LOW_LEVEL_MEMBERS:
            if f".{name}{{" in func_text or f".{name}(" in func_text:
                return True
    return False


def _resolve_to_call_expression(node: Node, source_bytes: bytes) -> Optional[Node]:
    """If node is or wraps a call_expression, return it; else None."""
    if node is None:
        return None
    n = node
    if n.type == "expression" and n.child_count > 0:
        n = n.child(0)
    if n.type == "call_expression":
        return n
    if n.type == "tuple_expression":
        for i in range(n.child_count):
            c = n.child(i)
            if c.type == "expression" and c.child_count > 0:
                inner = c.child(0)
                if inner.type == "call_expression":
                    return inner
            elif c.type == "call_expression":
                return c
    return None


def _get_success_variable_name(
    decl_stmt: Node, source_bytes: bytes
) -> Optional[str]:
    """
    From a variable_declaration_statement that has a value, get the name of the
    first/single variable (the one that would hold the success bool for call/delegatecall).
    """
    # First child can be variable_declaration or variable_declaration_tuple
    for i in range(decl_stmt.child_count):
        c = decl_stmt.child(i)
        if c.type == "variable_declaration":
            name_node = c.child_by_field_name("name")
            if name_node is not None:
                return source_bytes[name_node.start_byte : name_node.end_byte].decode(
                    "utf-8", errors="replace"
                ).strip()
            return None
        if c.type == "variable_declaration_tuple":
            # commaSep(optional(variable_declaration)): walk children for first variable_declaration
            for j in range(c.child_count):
                sub = c.child(j)
                if sub.type == "variable_declaration":
                    name_node = sub.child_by_field_name("name")
                    if name_node is not None:
                        return source_bytes[
                            name_node.start_byte : name_node.end_byte
                        ].decode("utf-8", errors="replace").strip()
            return None
    return None


def _containing_block(node: Node) -> Optional[Node]:
    """
    Return the innermost block_statement or function_body that contains node
    (i.e. the block whose direct statements include node or its wrapper).
    """
    n = node
    while n is not None:
        if n.type in ("block_statement", "function_body"):
            return n
        try:
            n = n.parent
        except AttributeError:
            n = None
    return None


def _find_enclosing_function_body(node: Node, root: Node) -> Optional[Node]:
    """Walk up to find function_definition; return its body (block_statement or function_body)."""
    n = node
    while n is not None:
        if n.type == "function_definition":
            body = n.child_by_field_name("body")
            if body is not None and body.type in (
                "block_statement",
                "function_body",
            ):
                return body
            return None
        try:
            n = n.parent
        except AttributeError:
            n = None
    if n is None:
        # Fallback: find innermost function_definition containing node by byte range
        candidates: list[Node] = []

        def collect(n: Node) -> None:
            if n.type == "function_definition":
                if n.start_byte <= node.start_byte <= n.end_byte:
                    candidates.append(n)
            for c in n.children:
                collect(c)

        collect(root)
        # Pick innermost (smallest span containing our node)
        best = None
        for fn in candidates:
            if fn.start_byte <= node.start_byte <= fn.end_byte:
                if best is None or (fn.end_byte - fn.start_byte) < (
                    best.end_byte - best.start_byte
                ):
                    best = fn
        if best is not None:
            body = best.child_by_field_name("body")
            if body is not None and body.type in (
                "block_statement",
                "function_body",
            ):
                return body
    return None


def _identifier_text(node: Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode(
        "utf-8", errors="replace"
    ).strip()


def _variable_used_in_check_context(
    body: Node, success_var: str, decl_stmt: Node, source_bytes: bytes
) -> bool:
    """
    Return True if success_var appears in a require/if/assert/revert condition
    or as argument to !, in statements that are after decl_stmt within body.
    """
    found_decl = False
    _STMT_TYPES = (
        "expression_statement",
        "variable_declaration_statement",
        "if_statement",
        "block_statement",
        "for_statement",
        "while_statement",
        "do_while_statement",
        "return_statement",
        "emit_statement",
        "revert_statement",
        "try_statement",
        "continue_statement",
        "break_statement",
    )

    statements = []
    for c in body.children:
        if c.type in _STMT_TYPES:
            statements.append(c)
        elif c.type == "statement" and c.child_count > 0:
            statements.append(c.child(0))

    def node_contains_identifier(n: Node, ident: str) -> bool:
        if n.type == "identifier":
            return _identifier_text(n, source_bytes) == ident
        for i in range(n.child_count):
            if node_contains_identifier(n.child(i), ident):
                return True
        return False

    def _first_call_argument_expression(call_expr: Node) -> Optional[Node]:
        # In tree-sitter-solidity, call_expression children are: function, '(', call_argument, ...
        for i in range(call_expr.child_count):
            c = call_expr.child(i)
            if c.type == "call_argument" and c.child_count > 0:
                return c.child(0)  # expression inside call_argument
        return None

    def condition_of_require_if_assert_revert(stmt: Node) -> Optional[Node]:
        if stmt.type == "expression_statement" and stmt.child_count > 0:
            expr = stmt.child(0)
            if expr.type == "expression" and expr.child_count > 0:
                expr = expr.child(0)
            if expr.type == "call_expression":
                func = expr.child_by_field_name("function") or (
                    expr.child(0) if expr.child_count > 0 else None
                )
                if func is not None:
                    if func.type == "expression" and func.child_count > 0:
                        func = func.child(0)
                    if func.type == "identifier":
                        name = _identifier_text(func, source_bytes)
                        if name in ("require", "assert", "revert"):
                            cond = _first_call_argument_expression(expr)
                            if cond is not None:
                                return cond
        if stmt.type == "if_statement":
            cond = stmt.child_by_field_name("condition")
            if cond is not None:
                return cond
        return None

    for stmt in statements:
        if stmt == decl_stmt:
            found_decl = True
            continue
        if not found_decl:
            continue
        cond = condition_of_require_if_assert_revert(stmt)
        if cond is not None and node_contains_identifier(cond, success_var):
            return True
        # Unary !: check expression_statement or any expression with operator "!"
        if stmt.type == "expression_statement" and stmt.child_count > 0:
            expr = stmt.child(0)
            if expr.type == "expression" and expr.child_count > 0:
                expr = expr.child(0)
            if expr.type == "unary_expression":
                op = expr.child_by_field_name("operator") or (
                    expr.child(0) if expr.child_count > 0 else None
                )
                if op is not None and _identifier_text(op, source_bytes) == "!":
                    arg = expr.child_by_field_name("argument") or (
                        expr.child(1) if expr.child_count > 1 else None
                    )
                    if arg is not None and node_contains_identifier(arg, success_var):
                        return True
        # Recurse into block_statement (e.g. if body) to catch require inside
        if stmt.type == "block_statement":
            for k in range(stmt.child_count):
                child = stmt.child(k)
                # Unwrap "statement" so we see expression_statement / if_statement
                inner = child.child(0) if child.type == "statement" and child.child_count > 0 else child
                if inner.type in (
                    "expression_statement",
                    "variable_declaration_statement",
                    "if_statement",
                ):
                    sub_cond = condition_of_require_if_assert_revert(inner)
                    if sub_cond is not None and node_contains_identifier(
                        sub_cond, success_var
                    ):
                        return True
                    if inner.type == "if_statement":
                        if_body = inner.child_by_field_name("body")
                        if if_body is not None and _variable_used_in_check_context(
                            if_body, success_var, decl_stmt, source_bytes
                        ):
                            return True
    return False


def _find_assigned_but_unchecked_solidity_calls(
    root: Node, source_bytes: bytes
) -> list[Node]:
    """
    Flag low-level call when its return value is assigned to a variable (or tuple)
    but the success variable is never used in a check (require/if/assert/revert/!).
    """
    result: list[Node] = []

    def walk(node: Node) -> None:
        if node.type == "variable_declaration_statement":
            value_node = node.child_by_field_name("value")
            if value_node is None:
                for child in node.children:
                    walk(child)
                return
            call_node = _resolve_to_call_expression(value_node, source_bytes)
            if call_node is None or not _is_low_level_call(call_node, source_bytes):
                for child in node.children:
                    walk(child)
                return
            success_var = _get_success_variable_name(node, source_bytes)
            if not success_var:
                for child in node.children:
                    walk(child)
                return
            # Use the block that directly contains this declaration (e.g. if-block body),
            # not the function body, so we see require(success) in the same if-block.
            block = _containing_block(node)
            if block is None:
                for child in node.children:
                    walk(child)
                return
            if _variable_used_in_check_context(block, success_var, node, source_bytes):
                for child in node.children:
                    walk(child)
                return
            result.append(call_node)
            return
        for child in node.children:
            walk(child)

    walk(root)
    return result


def _find_unchecked_solidity_calls(root: Node, source_bytes: bytes) -> list[Node]:
    """
    Flag low-level call when it appears as the top-level expression of an
    expression_statement (i.e. the whole statement is just the call; result discarded).
    """
    result: list[Node] = []

    def walk(node: Node) -> None:
        if node.type == "expression_statement" and node.child_count > 0:
            expr = node.child(0)
            call_expr = expr
            if expr.type == "expression" and expr.child_count > 0:
                call_expr = expr.child(0)
            if call_expr.type == "call_expression" and _is_low_level_call(
                call_expr, source_bytes
            ):
                result.append(call_expr)
            return
        for child in node.children:
            walk(child)

    walk(root)
    return result


def _extract_assembly_blocks(source: str) -> list[tuple[int, int, str]]:
    """
    Return list of (start_offset, end_offset, assembly_content) for each assembly { } block.
    """
    blocks: list[tuple[int, int, str]] = []
    pattern = re.compile(r"\bassembly\s*\{", re.MULTILINE)
    for m in pattern.finditer(source):
        start = m.end()
        depth = 1
        i = start
        while i < len(source) and depth > 0:
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
            i += 1
        if depth == 0:
            end = i - 1
            content = source[start:end]
            blocks.append((m.start(), end + 1, content))
    return blocks


def _line_from_offset(source: str, offset: int) -> int:
    return source[:offset].count("\n") + 1


def _find_unchecked_assembly_calls(
    source: str,
) -> list[tuple[int, ...]]:
    """
    Find call/delegatecall in assembly blocks where return value is not checked.
    Returns list of (line_number,) per finding.
    """
    findings: list[tuple[int, ...]] = []
    blocks = _extract_assembly_blocks(source)

    for block_start, block_end, content in blocks:
        for op in ASSEMBLY_OPCODES:
            bare_pattern = re.compile(rf"\b{re.escape(op)}\s*\(", re.MULTILINE)
            for m in bare_pattern.finditer(content):
                line_start = content.rfind("\n", 0, m.start()) + 1
                line_before = content[line_start : m.start()]
                if re.search(r"let\s+\w+\s*:=\s*$", line_before):
                    continue
                line = _line_from_offset(source, block_start + m.start())
                findings.append((line,))

        assign_pattern = re.compile(
            rf"let\s+(\w+)\s*:=\s*(call|delegatecall)\s*\(",
            re.MULTILINE,
        )
        for m in assign_pattern.finditer(content):
            var_name, op = m.group(1), m.group(2)
            rest = content[m.end() :]
            if re.search(rf"\biszero\s*\(\s*{re.escape(var_name)}\s*\)", rest):
                continue
            if re.search(rf"\beq\s*\(\s*{re.escape(var_name)}\s*,\s*0\s*\)", rest):
                continue
            if re.search(rf"\beq\s*\(\s*0\s*,\s*{re.escape(var_name)}\s*\)", rest):
                continue
            if re.search(rf"\beq\s*\(\s*{re.escape(var_name)}\s*,\s*1\s*\)", rest):
                continue
            if re.search(rf"\beq\s*\(\s*1\s*,\s*{re.escape(var_name)}\s*\)", rest):
                continue
            if re.search(rf"\bif\s+{re.escape(var_name)}\s*{{", rest):
                continue
            if re.search(rf"\b{re.escape(var_name)}\s*\)", rest):
                continue
            line = _line_from_offset(source, block_start + m.start())
            findings.append((line,))

    return findings


def _analyze_file(
    file_path: str,
    source: str,
    language: Language,
) -> list[AuditReportV2]:
    """Run detection on a single file; used internally by run_on_files."""
    findings: list[AuditReportV2] = []
    source_bytes = source.encode("utf-8")
    parser = tree_sitter.Parser(language)
    tree = parser.parse(source_bytes)
    root = tree.root_node

    for call_node in _find_unchecked_solidity_calls(root, source_bytes):
        line, _col = line_and_column_from_byte_offset(source, call_node.start_byte)
        findings.append(
            make_finding(
                tag=TAG,
                subtag=SUBTAG,
                severity=SEVERITY,
                description=DESCRIPTION_BASE,
                code_snippet=f"{file_path}:{line}",
            )
        )

    for call_node in _find_assigned_but_unchecked_solidity_calls(root, source_bytes):
        line, _col = line_and_column_from_byte_offset(source, call_node.start_byte)
        findings.append(
            make_finding(
                tag=TAG,
                subtag=SUBTAG,
                severity=SEVERITY,
                description=DESCRIPTION_BASE,
                code_snippet=f"{file_path}:{line}",
            )
        )

    for (line,) in _find_unchecked_assembly_calls(source):
        findings.append(
            make_finding(
                tag=TAG,
                subtag=SUBTAG,
                severity=SEVERITY,
                description=DESCRIPTION_BASE,
                code_snippet=f"{file_path}:{line}",
            )
        )

    def _sort_key(report: AuditReportV2) -> tuple[str, int]:
        """Sort by file path then line number (code_snippet is 'path:line')."""
        parts = report.code_snippet.rsplit(":", 1)
        if len(parts) == 2:
            try:
                return (parts[0], int(parts[1]))
            except ValueError:
                pass
        return (report.code_snippet, 0)

    findings.sort(key=_sort_key)
    return findings


def run_on_files(files: list[Path]) -> list[AuditReportV2]:
    """
    Run the rule on the given .sol files. Detects low-level call/delegatecall
    (Solidity and inline assembly) where the return value is not checked.
    """
    language = _get_solidity_language()
    all_findings: list[AuditReportV2] = []
    for path in files:
        if not path.exists():
            print(f"Warning: file not found, skipping: {path}", file=sys.stderr)
            continue
        content = read_file(path)
        for report in _analyze_file(str(path), content, language):
            all_findings.append(report)

    def _sort_key(report: AuditReportV2) -> tuple[str, int]:
        """Sort by file path then line number (code_snippet is 'path:line')."""
        parts = report.code_snippet.rsplit(":", 1)
        if len(parts) == 2:
            try:
                return (parts[0], int(parts[1]))
            except ValueError:
                pass
        return (report.code_snippet, 0)

    all_findings.sort(key=_sort_key)
    return all_findings
