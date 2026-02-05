import typer
import pandas as pd
from . import scan
from .scan_kaggle import scan_v2
from .scan_kaggle_static import scan_static 
from utils.report_generator.generate_csv import generate_csv

app = typer.Typer()


@app.callback(invoke_without_command=True)
def default(
    ctx: typer.Context,
    folder_path: str = typer.Option(
        "./dataset/scan_queue/",
        "--folder-path",
        help="The folder path to scan",
    ),
    n8n_url: str = typer.Option(
        "http://localhost:5678",
        "--n8n-url",
        help="The url of the n8n.",
    ),
    report_name: str = typer.Option(
        "audit_report",
        "--report-name",
        help="The base name of the report files",
    ),
    output_path: str = typer.Option(
        "./scan_report/",
        "--output-path",
        help="The folder path to store the output",
    ),
    output_format: str = typer.Option(
        "csv",
        "--output-format",
        help="Output formats: csv, json, md, pdf, or all. Use comma to separate multiple formats.",
    ),
):
    # Normalize and split formats
    output_formats = set(f.lower() for f in output_format.split(","))

    valid_formats = {"csv", "json", "md", "pdf", "all"}

    # Validate
    if not output_formats.issubset(valid_formats):
        invalid = output_formats - valid_formats
        typer.echo(
            f"❌ Invalid format(s): {', '.join(invalid)}. Choose from : csv, json, md, pdf or all."
        )
        exit(1)

    # Expand 'all' into all formats
    if "all" in output_formats:
        output_formats = {"csv", "json", "md", "pdf"}

    if ctx.invoked_subcommand is None:
        scan.scan_v1(
            folder_path=folder_path,
            n8n_url=n8n_url,
            report_name=report_name,
            output_path=output_path,
            output_formats=output_formats,
        )


@app.command("scan_v2")
def scan_kaggle(
    folder_path: str = typer.Option(
        "./dataset/scan_queue/",
        "--folder-path",
        help="The path to repo to scan",
    ),
    n8n_url: str = typer.Option(
        "http://localhost:5678",
        "--n8n-url",
        help="The url of the n8n.",
    ),
    report_name: str = typer.Option(
        "audit_report",
        "--report-name",
        help="The base name of the report files",
    ),
    output_path: str = typer.Option(
        "./scan_report/",
        "--output-path",
        help="The folder path to store the output",
    ),
):

    ai_findings = scan_v2(
        folder_path=folder_path,
        n8n_url=n8n_url,
    )
    generate_csv(
        df=ai_findings,
        output_path=output_path,
        report_name=report_name,
    )


@app.command("static")
def scan_kaggle_static(
    folder_path: str = typer.Option(
        "./dataset/scan_queue/",
        "--folder-path",
        help="The folder path containing .sol files to scan",
    ),
    rules_dir: str = typer.Option(
        "./rules/",
        "--rules-dir",
        help="The directory containing rule subdirectories",
    ),
    rules: str = typer.Option(
        "all",
        "--rules",
        help="Comma-separated category (subdirectory) names to run, or 'all'",
    ),
    report_name: str = typer.Option(
        "static_report",
        "--report-name",
        help="The base name of the report files",
    ),
    output_path: str = typer.Option(
        "./scan_report/",
        "--output-path",
        help="The folder path to store the output",
    ),
):
    static_findings = scan_static(
        folder_path=folder_path,
        rules_dir=rules_dir,
        rules=rules,
    )
    generate_csv(
        df=static_findings,
        output_path=output_path,
        report_name=report_name,
    )

@app.command("hybrid")
def scan_kaggle_hybrid(
    folder_path: str = typer.Option(
        "./dataset/scan_queue/",
        "--folder-path",
        help="The folder path containing .sol files to scan",
    ),
    n8n_url: str = typer.Option(
        "http://localhost:5678",
        "--n8n-url",
        help="The url of the n8n.",
    ),
    rules_dir: str = typer.Option(
        "./rules/",
        "--rules-dir",
        help="The directory containing rule subdirectories",
    ),
    rules: str = typer.Option(
        "all",
        "--rules",
        help="Comma-separated category (subdirectory) names to run, or 'all'",
    ),
    report_name: str = typer.Option(
        "audit_report",
        "--report-name",
        help="The base name of the report files",
    ),
    output_path: str = typer.Option(
        "./scan_report/",
        "--output-path",
        help="The folder path to store the output",
    ),
):
    static_findings = scan_static(
        folder_path=folder_path,
        rules_dir=rules_dir,
        rules=rules,
    )

    ai_findings = scan_v2(
        folder_path=folder_path,
        n8n_url=n8n_url,
    )

    combined_findings = pd.concat([static_findings, ai_findings], ignore_index=True)
    generate_csv(
        df=combined_findings,
        output_path=output_path,
        report_name=report_name,
    )
