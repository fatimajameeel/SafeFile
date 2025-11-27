import os
import mimetypes
import magic

# MAGIC NUMBER
MAGIC_SIGNATURES = [
    (b"%PDF-", "pdf", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
    (b"PK\x03\x04", "zip", "application/zip"),  # zip, docx, xlsx, jar
    (b"MZ", "exe", "application/x-dosexec"),     # Windows EXE
    (b"\xFF\xD8\xFF", "jpg", "image/jpeg"),
    (b"GIF87a", "gif", "image/gif"),
    (b"GIF89a", "gif", "image/gif"),
]

# Read the first N bytes for magic number matching


def read_file_header(file_path, n=32):
    with open(file_path, "rb") as f:
        return f.read(n)

    # Match header bytes agaisnt the custom signature list


def detect_from_magic_numbers(header):
    for magic_bytes, short, mime in MAGIC_SIGNATURES:
        if header.startswith(magic_bytes):
            return short, mime
    return None, None

# Detect using python-magic


def detect_using_libmagic(file_path):
    # Use python-magic if installed
    if magic is None:
        return None
    try:
        m = magic.Magic(mime=True)
        return m.from_file(file_path)  # returns "application/pdf"
    except:
        return None

# Return the extension written by the user (.pdf, .exe)


def get_extension(file_path):
    _, ext = os.path.splitext(file_path)
    return ext.lower().lstrip(".") if ext else None

# If mime is empty or None → just return None


def guess_ext_from_mime(mime):
    if not mime:
        return None
    ext = mimetypes.guess_extension(mime)
    return ext.lstrip(".") if ext else None

# Hybrid  file type detector


def detect_file_type(file_path):
    declared_ext = get_extension(file_path)
    header = read_file_header(file_path)

    # Try custom magic numbers
    magic_type, magic_mime = detect_from_magic_numbers(header)

    # Try libmagic
    libmagic_mime = detect_using_libmagic(file_path)

    # Decide final
    if magic_mime:
        final_mime = magic_mime
        final_type = magic_type

    elif libmagic_mime:
        final_mime = libmagic_mime
        final_type = guess_ext_from_mime(libmagic_mime)

    else:
        # No detection — mark as unknown
        final_mime = None
        final_type = None

    # mismatch detection
    mismatch = (
        declared_ext is not None and
        final_type is not None and
        declared_ext.lower() != final_type.lower()
    )

    #  Return detailed output
    return {
        "declared_extension": declared_ext,
        "magic_type": magic_type,
        "magic_mime": magic_mime,
        "libmagic_mime": libmagic_mime,
        "final_mime": final_mime,
        "final_type": final_type,
        "mismatch": mismatch,
    }


def is_corrupted(file_path):
    """
    Simple corruption check:
    Try reading the entire file.
    If Python cannot read it → file is corrupted.
    """
    try:
        with open(file_path, "rb") as f:
            f.read()
        return False  # readable → not corrupted
    except Exception:
        return True   # unreadable → corrupted
