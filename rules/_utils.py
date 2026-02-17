"""
Shared helpers for Bastet static rules.

Use these for line/snippet handling and building AuditReportV2 so rule code
only focuses on detection logic and tag/severity.
"""

from pathlib import Path

from models.audit_report import AuditReportV2


def line_and_column_from_byte_offset(source: str, byte_offset: int) -> tuple[int, int]:
    """Return (1-based line, 0-based column) for byte_offset in UTF-8 source."""
    before = source.encode("utf-8")[:byte_offset].decode("utf-8", errors="replace")
    line = before.count("\n") + 1
    last_nl = before.rfind("\n")
    col = (byte_offset - (last_nl + 1)) if last_nl >= 0 else byte_offset
    return line, col


def line_from_byte_offset(source: str, byte_offset: int) -> int:
    """Return 1-based line number for byte_offset in UTF-8 source."""
    line, _ = line_and_column_from_byte_offset(source, byte_offset)
    return line


def truncate_snippet(s: str, max_len: int = 120) -> str:
    """Strip and truncate a code snippet to max_len characters."""
    return s.strip()[:max_len]


def make_finding(
    tag: list[str],
    subtag: list[str],
    severity: str,
    description: str,
    code_snippet: str,
) -> AuditReportV2:
    """Build an AuditReportV2 with the given fields."""
    return AuditReportV2(
        tag=tag,
        subtag=subtag,
        severity=severity.lower(),
        description=description,
        code_snippet=code_snippet,
    )


def read_file(path: Path) -> str:
    """Read file content with consistent encoding."""
    return path.read_text(encoding="utf-8", errors="replace")
