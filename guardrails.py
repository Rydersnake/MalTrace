"""guardrails.py - ethical guardrails for MalTrace.

Covers the assignment's ethical requirements:
  * Legal disclaimer (Computer Crimes Act 1997) + explicit confirmation
  * Authorization scope (only .exe files inside the samples folder)
  * Output restricted to a folder inside the project
  * Dry-run mode (preview without reading or writing anything)
  * Kill switch (clean abort on Ctrl+C)
"""
import argparse
import sys
from pathlib import Path

ALLOWED_DIR = Path("samples")          # safe default scope
DEFAULT_OUTPUT_DIR = Path("output")    # local, labelled output only
ALLOWED_EXTENSIONS = {".exe"}          # PE executables only

BANNER = """
==============================================================
                  LEGAL DISCLAIMER - MALTRACE
==============================================================
MalTrace is a STATIC analysis tool. It never executes samples.

Unauthorised access to, or modification of, computer material
is an offence under the Computer Crimes Act 1997 (Akta
Kesalahan Komputer 1997) of Malaysia.

Only analyse files that you own or have EXPLICIT WRITTEN
permission to analyse. Handle malware samples inside an
isolated virtual machine.
==============================================================
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="maltrace",
        description="MalTrace - static PE analyzer with MITRE ATT&CK mapping.",
        epilog=(
            "examples:\n"
            "  py main.py --list\n"
            "  py main.py --file samples/explorer.exe\n"
            "  py main.py --file samples/explorer.exe --dry-run\n"
            "  py main.py --file samples/sample.exe --output output\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--file", help="file to analyse (must be an .exe inside samples/)")
    parser.add_argument("--list", action="store_true",
                        help="list files available in samples/")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_DIR),
                        help="output directory inside the project (default: output)")
    parser.add_argument("--dry-run", action="store_true",
                        help="check scope and show what would happen, without analysing")
    parser.add_argument("--confirm-authorized", action="store_true",
                        help="confirm you are authorized (skips the typed prompt)")
    return parser.parse_args()


def show_disclaimer_and_confirm(pre_confirmed=False):
    """Always show the banner. Exit unless the user confirms authorization."""
    print(BANNER)
    if pre_confirmed:
        print("[+] Authorization confirmed via --confirm-authorized.\n")
        return
    answer = input("Do you have authorization to analyse these files? (yes/no): ")
    if answer.strip().lower() != "yes":
        print("[!] Authorization not confirmed. Exiting.")
        sys.exit(1)


def check_scope(file_path, allowed_dir=ALLOWED_DIR):
    """Return the resolved path only if it is an .exe inside the allowed folder."""
    target = Path(file_path).resolve()
    allowed = Path(allowed_dir).resolve()
    if allowed not in target.parents:
        print(f"[!] Out of scope: {target}")
        print(f"    Only files inside '{allowed}' may be analysed.")
        sys.exit(1)
    if not target.is_file():
        print(f"[!] File not found: {target}")
        sys.exit(1)
    if target.suffix.lower() not in ALLOWED_EXTENSIONS:
        print(f"[!] Unsupported file type: {target.suffix}")
        print(f"    Allowed types: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
        sys.exit(1)
    return target


def check_output_dir(output_dir, base_dir):
    """Reports may only be written to a folder inside the project."""
    out = Path(output_dir).resolve()
    base = Path(base_dir).resolve()
    if base not in out.parents:
        print(f"[!] Output directory not allowed: {out}")
        print(f"    Reports must be saved inside '{base}'.")
        sys.exit(1)
    return out


def run_with_kill_switch(func):
    """Run func(); Ctrl+C aborts cleanly instead of dumping a traceback.

    func() may return an int exit code (0 = success).
    """
    try:
        code = func()
    except KeyboardInterrupt:
        print("\n[!] Kill switch triggered (Ctrl+C). Analysis aborted safely.")
        sys.exit(130)
    sys.exit(code or 0)