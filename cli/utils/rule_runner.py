"""
Static rule runner: discovers and executes Python rule scripts from the rules/ directory.

Rules must be placed in subdirectories of the rules/ directory (e.g. rules/solmate/,
rules/Chainlink/). Each rule .py file must implement:

    def run_on_files(files: list[Path]) -> list[AuditReportV2]
"""

import importlib.util
import sys
from pathlib import Path
from typing import Optional

from models.audit_report import AuditReportV2
from tqdm import tqdm

DEFAULT_RULES_DIR = Path.cwd() / "rules"


def discover_rules(
    rules_dir: Path = DEFAULT_RULES_DIR,
    categories: Optional[list[str]] = None,
) -> list[tuple[str, Path]]:
    """
    Walk the rules directory and collect all .py files matching the category filter.

    Args:
        rules_dir: Root directory containing rule subdirectories.
        categories: If provided, only return rules whose parent directory name
                    matches one of these strings (case-insensitive).
                    None means return all rules.

    Returns:
        List of (display_name, file_path) tuples.
    """
    discovered: list[tuple[str, Path]] = []

    for subdir in sorted(rules_dir.iterdir()):
        if not subdir.is_dir():
            continue

        category = subdir.name

        if categories is not None and category.lower() not in categories:
            continue

        for py_file in sorted(subdir.glob("*.py")):
            if py_file.name.startswith("__"):
                continue
            display_name = f"{category}/{py_file.stem}"
            discovered.append((display_name, py_file))

    return discovered


def _load_rule_module(py_file: Path):
    """
    Dynamically load a Python file as a module using importlib.

    Returns the module object, or None on failure.
    """
    module_name = f"rule_{py_file.parent.name}_{py_file.stem}"
    try:
        spec = importlib.util.spec_from_file_location(module_name, str(py_file))
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        tqdm.write(f"\033[91m  Error loading {py_file.name}: {e}\033[0m")
        return None


def execute_rules(
    sol_files: list[Path],
    rules_dir: Path = DEFAULT_RULES_DIR,
    categories: Optional[list[str]] = None,
) -> list[AuditReportV2]:
    """
    Discover and execute static rules against the given .sol files.

    Args:
        sol_files: List of .sol file paths to scan.
        rules_dir: Root directory containing rule subdirectories.
        categories: Optional list of category (subdirectory) names to run.
                    None or ["all"] means run everything.

    Returns:
        Combined list of AuditReportV2 findings from all rules.
    """

    tqdm.write("Discovering static rules...")
    rules = discover_rules(rules_dir, categories)

    if not rules:
        tqdm.write("\033[93m  No matching rules found.\033[0m")
        return []

    tqdm.write(f"Found {len(rules)} rule(s) to execute.")
    tqdm.write("-" * 50)

    all_findings: list[AuditReportV2] = []

    for rule_display_name, rule_path in tqdm(
        rules,
        desc="Running static rules",
        unit="rule",
        ncols=100,
        colour="green",
        bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} rules [Time: {elapsed}]",
        mininterval=0.01,
    ):
        tqdm.write(f"\033[92mRunning rule: {rule_display_name}\033[0m")
        module = _load_rule_module(rule_path)
        if module is None:
            continue

        run_fn = getattr(module, "run_on_files", None)
        if not callable(run_fn):
            tqdm.write(
                f"\033[93m  Skipping {rule_display_name}: "
                f"no callable run_on_files function found\033[0m"
            )
            continue

        try:
            findings = module.run_on_files(sol_files)
            all_findings.extend(findings)
            if findings:
                tqdm.write(f"\033[93m  Found {len(findings)} finding(s)\033[0m")
            else:
                tqdm.write(f"\033[92m  No findings\033[0m")
        except Exception as e:
            tqdm.write(
                f"\033[91m  Error executing rule {rule_display_name}: {e}\033[0m"
            )

    tqdm.write("-" * 50)
    tqdm.write(f"Static scan complete: {len(all_findings)} total finding(s).")
    return all_findings
