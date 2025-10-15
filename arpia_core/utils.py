import os


def safe_filename(name: str) -> str:
    """Sanitize filenames to avoid directory traversal and bad chars."""
    if not name:
        return ""
    name = os.path.basename(name)
    if "/" in name or "\\" in name or name in {".", ".."}:
        return ""
    allowed = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    cleaned = "".join(ch for ch in name if ch in allowed)
    return cleaned.strip()
