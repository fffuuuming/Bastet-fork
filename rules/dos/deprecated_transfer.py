"""
Rule: Deprecated .transfer() on address payable — use .call{value: x}("") instead.

The use of the deprecated transfer() for an address payable may make the transaction fail due to the 2300 gas stipend. Prefer call{value: amount}("").
"""

from __future__ import annotations

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

RULE_NAME = "Deprecated .transfer()"
SEVERITY = "medium"
TAG = ["DoS"]
SUBTAG = ["Out of Gas"]
DESCRIPTION_BASE = (
    "call() should be used instead of transfer() on an address payable. "
    "The use of the deprecated transfer() may make the transaction fail due to the 2300 gas stipend."
)


def _get_solidity_language() -> Language:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return Language(tree_sitter_solidity.language())


def _member_property(member_expression: Node) -> Optional[Node]:
    """Property is the identifier after the dot."""
    if member_expression.child_count >= 3:
        return member_expression.child(2)
    return None


def _count_call_arguments(call_node: Node) -> int:
    """
    Return the number of arguments in a call_expression.
    tree-sitter-solidity: arguments are direct children of type "call_argument".
    """
    n = 0
    for i in range(call_node.child_count):
        if call_node.child(i).type == "call_argument":
            n += 1
    return n


def _find_deprecated_transfer_calls(root: Node, source_bytes: bytes) -> list[Node]:
    """
    Walk the tree and collect every call_expression that is .transfer(<one argument>).
    """
    result: list[Node] = []

    def walk(node: Node) -> None:
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function") or (
                node.child(0) if node.child_count > 0 else None
            )
            if func_node and func_node.type == "expression" and func_node.child_count > 0:
                func_node = func_node.child(0)
            if func_node and func_node.type == "member_expression":
                prop_node = func_node.child_by_field_name("property") or _member_property(func_node)
                if prop_node:
                    prop_text = source_bytes[prop_node.start_byte : prop_node.end_byte].decode(
                        "utf-8", errors="replace"
                    ).strip()
                    if prop_text == "transfer" and _count_call_arguments(node) == 1:
                        result.append(node)
        for child in node.children:
            walk(child)

    walk(root)
    return result


def _get_text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _analyze_file(
    file_path: str,
    source: str,
    language: Language,
) -> list[AuditReportV2]:
    """Run detection on a single file; used internally by run_on_files."""
    parser = tree_sitter.Parser(language)
    source_bytes = source.encode("utf-8")
    tree = parser.parse(source_bytes)
    root = tree.root_node

    findings: list[AuditReportV2] = []
    for call_node in _find_deprecated_transfer_calls(root, source_bytes):
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
    return findings


def run_on_files(files: list[Path]) -> list[AuditReportV2]:
    """
    Run the rule on the given .sol files (by path). Reads each file and
    returns a list of findings as AuditReportV2.
    """
    language = _get_solidity_language()
    findings: list[AuditReportV2] = []
    for path in files:
        if not path.exists():
            print(f"Warning: file not found, skipping: {path}", file=sys.stderr)
            continue
        content = read_file(path)
        for report in _analyze_file(str(path), content, language):
            findings.append(report)
    return findings