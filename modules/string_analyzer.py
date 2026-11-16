"""string_analyzer.py - entropy and string extraction.
Static analysis only: the file is read as bytes and never executed."""
import math
import re
from collections import Counter

MAX_SIZE = 100 * 1024 * 1024  # refuse files bigger than 100 MB
SUSPICIOUS = ["powershell", "cmd.exe", "wscript", "rundll32", "regsvr32", "hkey_", "upx", "themida"]

def calculate_entropy(data):
    """Shannon entropy: 0 = all bytes the same, 8 = completely random."""
    if len(data) == 0:
        return 0.0
    entropy = 0.0
    for count in Counter(data).values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy
    
def extract_ascii(data, min_len=4):
    """Runs of printable ASCII characters (like the 'strings' command)."""
    pattern = rb"[\x20-\x7e]{%d,}" % min_len
    return [m.decode("ascii") for m in re.findall(pattern, data)]


def extract_utf16(data, min_len=4):
    """UTF-16LE text is stored as character + 0x00, so match those pairs."""
    pattern = rb"(?:[\x20-\x7e]\x00){%d,}" % min_len
    return [m.decode("utf-16-le") for m in re.findall(pattern, data)]


def find_packed_regions(data, block_size=4096, threshold=7.2):
    """Split the file into blocks and return the (start, end) of high-entropy parts.
    A packed section can hide inside a file that looks normal overall."""
    regions = []
    start = None
    for offset in range(0, len(data), block_size):
        block_entropy = calculate_entropy(data[offset:offset + block_size])
        if block_entropy >= threshold and start is None:
            start = offset
        elif block_entropy < threshold and start is not None:
            regions.append((start, offset))
            start = None
    if start is not None:
        regions.append((start, len(data)))
    return regions


def analyze(path, min_len=4):
    """Entry point for main.py. Returns a dictionary of results."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_SIZE + 1)
    except OSError as err:
        return {"error": f"Cannot read file: {err}"}
    if len(data) > MAX_SIZE:
        return {"error": "File is larger than 100 MB"}

    entropy = calculate_entropy(data)
    if entropy >= 7.2:
        verdict = "very high - likely packed or encrypted"
    elif entropy >= 6.5:
        verdict = "high - possibly packed or compressed"
    else:
        verdict = "normal"

    ascii_strings = extract_ascii(data, min_len)
    utf16_strings = extract_utf16(data, min_len)
    suspicious = []
    for s in ascii_strings + utf16_strings:
        if any(word in s.lower() for word in SUSPICIOUS):
            suspicious.append(s)

    return {
        "entropy": round(entropy, 3),
        "entropy_verdict": verdict,
        "packed_regions": find_packed_regions(data),
        "ascii_strings": ascii_strings,
        "utf16_strings": utf16_strings,
        "suspicious_strings": sorted(set(suspicious)),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        sys.exit("Usage: py -m modules.string_analyzer <file>")
    result = analyze(sys.argv[1])
    print(result.get("error") or f"entropy {result['entropy']} ({result['entropy_verdict']})")
    if "packed_regions" in result:
        print("packed regions:", result["packed_regions"])
