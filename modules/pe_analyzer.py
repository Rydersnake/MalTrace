import os
import hashlib
import pefile


def calculate_hashes(path):
    """Return MD5, SHA1 and SHA256 of a file"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
           md5.update(chunk)
           sha1.update(chunk)
           sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }

def load_pe(path):
    """Try to parse the file as a PE. Returns (pe_object, error_message)."""
    try:
        return pefile.PE(path), None
    except pefile.PEFormatError:
        return None, "Not a valid PE file"
    except PermissionError:
        return None, "Permission denied reading file"

def analyze_pe(path):
    """Entry point: takes a file path, returns a dictionary of results."""
    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}

    result = {
        "file_info": {},
        "headers": {},
        "sections": [],
        "imports": [],
        "flags": [],
    }

    result["file_info"] = {
        "name": os.path.basename(path),
        "size_bytes": os.path.getsize(path),
        "hashes": calculate_hashes(path),
    }

    pe, error = load_pe(path)
    if error:
        result["error"] = error
        return result

    pe.close()
    return result

















