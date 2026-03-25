import os
from pathlib import Path


EXCLUDE_DIRS = {
    "test",
    "tests",
    "testing",
    "mock",
    "mocks",
    "script",
    "scripts",
    "deploy",
    "broadcast",
    "cache",
    "out",
    "interface",
    "interfaces",
    "testcontracts",
    "test-forge",
    "forge-std",
    "ds-test",
    "openzeppelin",
    "openzeppelin-contracts",
    "openzeppelin-contracts-upgradeable",
    "openzeppelin-community-contracts",
    "solmate",
    "solady",
    "prb-math",
    "abdk-libraries-solidity",
    "gnosis-safe",
    "safe-contracts",
    "safe-smart-account",
    "uniswap-v2-core",
    "uniswap-v2-periphery",
    "uniswap-v3-core",
    "uniswap-v3-periphery",
    "uniswap-v4-core",
    "uniswap-v4-periphery",
    "permit2",
    "universal-router",
    "multicall",
}


def prune_excluded_dirs(dir_names: list[str]) -> None:
    """In-place removal of excluded directory names, matching case-insensitively."""
    dir_names[:] = [dir_name for dir_name in dir_names if dir_name.lower() not in EXCLUDE_DIRS]


def collect_solidity_files(root: Path) -> list[Path]:
    """Collect in-scope Solidity files while pruning excluded directories."""
    sol_files: list[Path] = []

    for current_root, dirs, files in os.walk(root):
        prune_excluded_dirs(dirs)
        for filename in files:
            file_path = Path(current_root, filename)
            if file_path.is_file() and file_path.suffix.lower() == ".sol":
                sol_files.append(file_path)

    return sol_files
