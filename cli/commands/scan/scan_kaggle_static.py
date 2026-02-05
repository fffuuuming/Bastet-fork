def scan_static(
    folder_path: str,
    rules_dir: str,
    rules: str,
):
    import pandas as pd
    from pathlib import Path
    from tqdm import tqdm
    from utils.rule_runner import execute_rules

    root = Path(folder_path)

    if not root.exists():
        tqdm.write(f"\033[91mFolder not found: {root}\033[0m")
        return

    sol_files = list(root.rglob("*.sol"))

    if not sol_files:
        tqdm.write(f"\033[91mNo .sol files found in {root}\033[0m")
        return

    tqdm.write(f"Found {len(sol_files)} .sol files.")

    rules_arg = rules.strip().lower()

    if rules_arg == "all":
        categories = None
    else:
        categories = [r.strip() for r in rules.split(",") if r.strip()]

    findings = execute_rules(sol_files, Path(rules_dir), categories)

    df = pd.DataFrame(
        [
            {
                "Tag": ",".join(report.tag),
                "Subtag": ",".join(report.subtag),
                "Severity": report.severity,
                "Description": report.description,
                "Code Snippet": report.code_snippet,
            }
            for report in findings
        ]
    )

    return df
