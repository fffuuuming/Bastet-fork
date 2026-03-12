from pathlib import Path

def _project_from_path(folder_path: str) -> str:
    """Extract repo name (first subdirectory) from folder path within dataset/scan_queue."""
    folder = Path(folder_path).resolve()

    # Ensure the folder path is within dataset/scan_queue
    if "dataset/scan_queue" not in folder.as_posix():
        return "unknown"

    segments = folder.parts
    if len(segments) < 2:  # Ensure there's at least one subdirectory
        return "unknown"

    # Return the first subdirectory under dataset/scan_queue
    return segments[segments.index("scan_queue") + 1]