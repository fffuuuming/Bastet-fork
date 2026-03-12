from collections import defaultdict
from pathlib import Path


def _parse_location(code_snippet: str) -> tuple[str | None, int | None]:
    """Parse path:line from code_snippet (location string). Returns (None, None) if not in that form."""
    if not code_snippet or ":" not in code_snippet:
        return None, None
    parts = code_snippet.rsplit(":", 1)
    if len(parts) != 2 or not parts[1].strip().isdigit():
        return None, None
    return parts[0].strip(), int(parts[1].strip())


def _project_from_path(path_str: str, folder_path: str) -> str:
    """Extract repo name (first subdirectory) from file path."""
    folder = Path(folder_path).resolve()
    path = Path(path_str).resolve()
    try:
        relative = path.relative_to(folder)
    except ValueError:
        relative = Path(path_str)
    dir_part = relative.parent
    segments = [p for p in dir_part.parts if p != "."]
    if not segments:
        return "unknown"
    return segments[0]



def scan_static(
    folder_path: str,
    rules_dir: str,
    rules: str,
    mode: str = "normal",
):
    import pandas as pd
    from tqdm import tqdm
    from utils.rule_runner import execute_rules

    root = Path(folder_path)

    if mode == "normal":
        empty_df = pd.DataFrame(
            columns=["repo_path", "tag", "subtag", "severity", "description"]
        )
    else:
        empty_df = pd.DataFrame(
            columns=["repo_path", "tag", "subtag", "severity", "description", "code_snippet"]
        )
    if not root.exists():
        tqdm.write(f"\033[91mFolder not found: {root}\033[0m")
        return empty_df

    sol_files = list(root.rglob("*.sol"))
    if not sol_files:
        tqdm.write(f"\033[91mNo .sol files found in {root}\033[0m")
        return empty_df

    tqdm.write(f"Found {len(sol_files)} .sol files.")

    rules_arg = rules.strip().lower()

    if rules_arg == "all":
        categories = None
    else:
        categories = [r.strip() for r in rules.split(",") if r.strip()]

    findings = execute_rules(sol_files, Path(rules_dir), categories)

    if not findings:
        return empty_df

    groups: dict[tuple[str, tuple, tuple, str], list] = defaultdict(list)
    for report in findings:
        path_str, line = _parse_location(report.code_snippet)
        if path_str is not None and line is not None:
            project = _project_from_path(path_str, folder_path)
        else:
            project = "unknown"
        key = (project, tuple(report.tag), tuple(report.subtag), report.severity)
        groups[key].append(report)

    rows = []
    for (project, tag, subtag, severity), group in groups.items():
        description = group[0].description
        if mode == "normal":
            rows.append(
                {
                    "Repo_path": project,
                    "Tag": ",".join(tag),
                    "Subtag": ",".join(subtag),
                    "Severity": severity,
                    "Description": description,
                }
            )
        else:
            code_snippet_value = "\n".join(r.code_snippet for r in group if r.code_snippet)
            rows.append(
                {
                    "Repo_path": project,
                    "Tag": ",".join(tag),
                    "Subtag": ",".join(subtag),
                    "Severity": severity,
                    "Description": description,
                    "Code_snippet": code_snippet_value,
                }
            )

    return pd.DataFrame(rows)
