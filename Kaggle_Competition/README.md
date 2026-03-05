# Bastet Kaggle Competition

## Overview

The benchmark defines a repository-level vulnerability detection task, built on a curated dataset annotated by security experts. It includes standardized train/test splits, structured annotation fields (tag, subtag, severity, description), and a custom evaluation metric combining classification accuracy, semantic similarity, and over-reporting penalties. Baseline detection workflows are provided, enabling reproducible comparison across submissions.

## Quick Start

Please follow the installation instructions in the main [README.md](../README.md).

## Scan Modes

### Static

```bash
poetry run python cli/main.py scan static
poetry run python cli/main.py scan static --rules dos,solmate
```

Runs local Python rule scripts from the `rules/` directory using regex or tree-sitter syntax analysis. No n8n or OpenAI required.

You can filter specific rule categories using the `--rules` option, with multiple categories separated by commas.

### Scan V2

```bash
poetry run python cli/main.py scan scan_v2
```

Uses SourceBundler to resolve Solidity import dependencies and bundles all transitive dependencies into a single source. Sends the bundled source to n8n workflows (LLM) for analysis.

### Hybrid (Official Baseline)

```bash
poetry run python cli/main.py scan hybrid
poetry run python cli/main.py scan hybrid --rules dos,solmate
```

Combines Scan V2 (AI analysis) with Static rules, merging results into a single CSV. This mode provides the highest coverage by leveraging both pattern-based and LLM-based detection.

You can filter specific rule categories using the `--rules` option, with multiple categories separated by commas.

### Output Customization
You can customize the verbosity of your reports using the `--mode` flag .

* **Normal Mode (Default)**: Optimized for clarity. It outputs only essential fields: `tag`, `subtag`, `severity`, and `description`. In this mode, `code_snippet` is optional and omitted.
* **Debug Mode**: Full diagnostic output. This includes all metadata and the `code_snippet` field for deep-dive analysis.

```bash
# Normal Mode (Default)
poetry run python cli/main.py scan --mode normal

# Debug Mode
poetry run python cli/main.py scan --mode debug
```

> You can use flag `--help` for detail information of flag you can use


## Submission Format

Submit a CSV file with the following columns. All columns are required (values may be empty, but columns must exist):

| Column | Description |
|--------|-------------|
| Tag | Vulnerability category |
| Subtag | Vulnerability subcategory |
| Severity | high / medium / low |
| Description | Vulnerability description |

See [submission_example.csv](./submission_example.csv) for reference.

## Evaluation

Submissions are evaluated by the organizers using a custom metric.
