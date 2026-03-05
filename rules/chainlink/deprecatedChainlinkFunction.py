"""
Rule: Use of deprecated Chainlink function `latestAnswer()`

Chainlink price feed contracts historically exposed `latestAnswer()`, but it is deprecated in favor of
`latestRoundData()` (and related getters). Using `latestAnswer()` can be risky because it may return 0
in cases where no valid answer is available, which can lead to incorrect pricing or downstream DoS.
"""

import re
import sys
from pathlib import Path

from models.audit_report import AuditReportV2

_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from rules._utils import line_from_byte_offset, make_finding, read_file

RULE_NAME = "Use of deprecated Chainlink function: `latestAnswer()`"
SEVERITY = "medium"
TAG = ["Chainlink"]
SUBTAG = ["Deprecated Library"]
DESCRIPTION_BASE = (
    "Chainlink's `latestAnswer()` is deprecated. Prefer `latestRoundData()` and perform proper data "
    "validity checks (e.g., updatedAt != 0, answeredInRound, round completeness) to avoid using "
    "stale/invalid answers (including unexpected 0)."
)

# Match `.latestAnswer()` with optional whitespace/newlines between tokens.
REGEX_MAIN = re.compile(r"\.\s*latestAnswer\s*\(\s*\)", re.MULTILINE)


def _find_findings_in_content(filepath: str, content: str) -> list[tuple[int, str]]:
    """Return list of (line_no, line_content) for each regex match."""
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
        for line_no, _line_content in _find_findings_in_content(str(path), content):
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
