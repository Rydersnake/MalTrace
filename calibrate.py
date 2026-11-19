"""calibrate.py - run MalTrace on every sample and build ONE comparison table.

Use it to check that known-good programs score low and (inside an isolated
VM, with permission) that known-bad samples score high. If a good program
scores MEDIUM or HIGH, a weight in risk_scorer.py needs tuning.

Static only: it calls the same analysis as main.py and never executes a sample.
"""
import argparse
import contextlib
import csv
import io
from pathlib import Path

import main as maltrace
from guardrails import (
    show_disclaimer_and_confirm,
    check_scope,
    check_output_dir,
    run_with_kill_switch,
)

COLUMNS = ["file", "mitre_only", "combined", "level",
           "suspicious_regions", "review_regions", "unknown_iocs", "error"]


def analyse_quietly(path):
    """Run the normal analysis but hide its terminal output."""
    with contextlib.redirect_stdout(io.StringIO()):
        return maltrace.analyse(path)


def build_row(path):
    row = {"file": path.name, "error": ""}
    try:
        report = analyse_quietly(path)
    except Exception as error:                 # one bad file must not stop the run
        row["error"] = f"{type(error).__name__}: {error}"
        return row
    if report is None:
        row["error"] = "analysis returned an error"
        return row

    regions = report["string_analysis"].get("packed_region_details", [])
    ioc = report["ioc_analysis"]
    risk = report["risk_assessment"]

    row.update(
        mitre_only=report["mitre_analysis"]["risk_score"],
        combined=risk["score"],
        level=risk["level"],
        suspicious_regions=sum(1 for r in regions if r["judgement"] == "suspicious"),
        review_regions=sum(1 for r in regions if r["judgement"] == "review"),
        unknown_iocs=len(ioc["ips"]) + len(ioc["domains"]) + len(ioc["urls"]),
    )
    return row


def to_markdown(rows):
    lines = ["| " + " | ".join(COLUMNS) + " |",
             "|" + "|".join("---" for _ in COLUMNS) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(c, "")) for c in COLUMNS) + " |")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        prog="calibrate",
        description="Run MalTrace on every .exe in samples/ and compare the scores.",
    )
    parser.add_argument("--output", default="output",
                        help="folder for calibration.csv and calibration.md")
    parser.add_argument("--confirm-authorized", action="store_true",
                        help="confirm you are authorized (skips the typed prompt)")
    args = parser.parse_args()

    show_disclaimer_and_confirm(args.confirm_authorized)

    files = maltrace.list_samples()
    if not files:
        print("No EXE files found in samples folder.")
        return 1

    output_dir = Path(args.output)
    if not output_dir.is_absolute():
        output_dir = maltrace.BASE_DIR / output_dir
    output_dir = check_output_dir(output_dir, maltrace.BASE_DIR)

    rows = []
    for number, file in enumerate(files, start=1):
        path = check_scope(file, maltrace.SAMPLES_DIR)
        print(f"[{number}/{len(files)}] {path.name}")
        rows.append(build_row(path))

    # highest combined score first; failed files last
    rows.sort(key=lambda r: -r.get("combined", -1))

    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_dir / "calibration.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    table = to_markdown(rows)
    (output_dir / "calibration.md").write_text(table + "\n", encoding="utf-8")

    print("\n" + table)
    print(f"\nSaved to {output_dir / 'calibration.csv'} and calibration.md")
    return 0


if __name__ == "__main__":
    run_with_kill_switch(main)