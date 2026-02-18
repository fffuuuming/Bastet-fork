"""
Rule: Solmate's SafeTransferLib does not check for token contract's existence

There is a subtle difference between Solmate's SafeTransferLib and OZ's SafeERC20:
OZ's SafeERC20 checks if the token is a contract or not; Solmate's SafeTransferLib does not.
"""

import re
import sys
from pathlib import Path

from models.audit_report import AuditReportV2

_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))
from rules._utils import line_from_byte_offset, make_finding, read_file

RULE_NAME = "Solmate's SafeTransferLib does not check for token contract's existence"
SEVERITY = "medium"
TAG = ["Solmate"]
SUBTAG = ["Missing Return Check"]
DESCRIPTION_BASE = (
    "Solmate's SafeTransferLib does not check that the token has code. "
    "Ensure the token address is a contract (e.g. extcodesize(token) > 0) before calling."
)

REGEX_PRE_CONDITION = re.compile(r"solmate/utils/SafeTransferLib\.sol")
REGEX_MAIN = re.compile(r"\.safeTransfer\(|\.safeTransferFrom\(|\.safeApprove\(")


def _find_findings_in_content(filepath: str, content: str) -> list[tuple[int, str]]:
    """Return list of (line_no, line_content) for each regex match."""
    if not REGEX_PRE_CONDITION.search(content):
        return []
    lines = content.split("\n")
    result: list[tuple[int, str]] = []
    for m in REGEX_MAIN.finditer(content):
        line_no = line_from_byte_offset(content, m.start())
        line_content = lines[line_no - 1] if 1 <= line_no <= len(lines) else ""
        result.append((line_no, line_content))
    return result


def run_on_files(files: list[Path]) -> list[AuditReportV2]:
    """
    Run the rule on the given .sol files (by path). Reads each file and
    returns a list of findings as AuditReportV2.
    """
    findings: list[AuditReportV2] = []
    for path in files:
        if not path.exists():
            print(f"Warning: file not found, skipping: {path}", file=sys.stderr)
            continue
        content = read_file(path)
        for line_no, line_content in _find_findings_in_content(str(path), content):
            findings.append(
                make_finding(
                    tag=TAG,
                    subtag=SUBTAG,
                    severity=SEVERITY,
                    description=DESCRIPTION_BASE,
                    code_snippet=f"{path!s}:{line_no}",
                )
            )
    return findings
