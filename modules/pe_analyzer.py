import os
import hashlib


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
    return result
