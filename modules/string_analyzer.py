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
