"""
Utility functions for the Secure File Transfer System
"""
import re
import os
from werkzeug.utils import secure_filename
import mimetypes

def sanitize_filename(filename):
    """
    Sanitize filename to prevent issues with special characters
    and ensure consistent naming across platforms
    """
    if not filename:
        return 'unnamed_file'

    # Use werkzeug's secure_filename correctly
    safe_name = secure_filename(filename)

    # Remove extra whitespace
    safe_name = safe_name.strip()

    # Remove trailing underscores/dots
    safe_name = safe_name.rstrip("_.")  

    # If empty after sanitizing, try to keep extension
    if not safe_name:
        _, ext = os.path.splitext(filename)
        safe_name = f"unnamed_file{ext}" if ext else "unnamed_file"

    # Enforce filename length limit (255 chars)
    if len(safe_name) > 255:
        name, ext = os.path.splitext(safe_name)
        safe_name = name[:255 - len(ext)] + ext

    return safe_name


def format_file_size(size_bytes):
    """Convert bytes into human-readable format."""
    if size_bytes == 0:
        return "0 B"

    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    return f"{size:.2f} {units[unit_index]}" if unit_index > 0 else f"{int(size)} B"


def validate_filename(filename):
    """Check if filename is acceptable and safe."""
    if not filename:
        return False, "Filename cannot be empty"

    if len(filename) > 255:
        return False, "Filename too long"

    # Dangerous patterns
    dangerous_patterns = [
        r'\.\.',   # directory traversal
        r'^/',     # absolute paths
        r'\\',     # windows paths
        r'\x00',   # null byte
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, filename):
            return False, "Filename contains invalid characters"

    return True, None


def get_file_extension(filename):
    """Return lowercase file extension including dot."""
    if not filename:
        return ""
    return os.path.splitext(filename)[1].lower()


def get_mime_type(filename):
    """Guess MIME type from filename."""
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def truncate_filename(filename, max_length=50):
    """
    Truncate long filenames for UI display, keeping extension.
    """
    if len(filename) <= max_length:
        return filename

    name, ext = os.path.splitext(filename)
    available = max_length - len(ext) - 3  # 3 for "..."

    if available <= 0:
        return filename[:max_length]

    return name[:available] + "..." + ext
