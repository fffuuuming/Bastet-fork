from pathlib import Path

def _project_from_path(file_path: str) -> str:
    """Extract project name from the file path within dataset/scan_queue."""
    folder = Path(file_path).resolve()  # Resolve to absolute path

    # Ensure the file path is within dataset/scan_queue
    if "dataset/scan_queue" not in folder.as_posix():
        return "unknown"

    segments = folder.parts

    # Ensure there's a project name after 'scan_queue'
    try:
        return segments[segments.index("scan_queue") + 1]
    except (ValueError, IndexError):
        return "unknown"