import json
from datetime import datetime, timezone
from pathlib import Path

from guardrails import (
    ALLOWED_EXTENSIONS,
    parse_args,
    show_disclaimer_and_confirm,
    check_scope,
    check_output_dir,
    run_with_kill_switch,
)

from modules.pe_analyzer import analyze_pe
from modules.string_analyzer import analyze as analyze_strings
from modules.entropy_context import (
    classify_packed_regions,
    summarize_regions,
    contextual_verdict,
)

from modules.ioc_extractor import (
    extract_ips,
    extract_urls,
    extract_trusted_urls,
    extract_domains,
    extract_trusted_domains,
    extract_hashes
)
from modules.mitre_mapper import analyze as analyze_mitre
from modules.riskscorer import calculate_combined_risk, format_breakdown


VERSION = "1.0.0"

# Project directories
BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"


def list_samples():
    """Return sorted allowed files (.exe) inside the samples folder."""
    if not SAMPLES_DIR.exists():
        return []
    return sorted(
        f for f in SAMPLES_DIR.iterdir()
        if f.is_file() and f.suffix.lower() in ALLOWED_EXTENSIONS
    )


def choose_file_interactively(files):
    """Fallback menu used when --file is not given."""
    print("\nAvailable files:")
    for number, file in enumerate(files, start=1):
        print(f"{number}. {file.name}")

    try:
        choice = int(input("\nSelect a file to analyse: "))
    except ValueError:
        print("Please enter a number.")
        return None

    if choice < 1 or choice > len(files):
        print("Invalid selection.")
        return None

    return files[choice - 1]


def resolve_target(args, files):
    """Work out which file to analyse, then enforce scope."""
    if args.file:
        candidate = Path(args.file)
        # allow "--file explorer.exe" as shortcut for samples/explorer.exe
        if not candidate.exists() and (SAMPLES_DIR / candidate.name).exists():
            candidate = SAMPLES_DIR / candidate.name
    else:
        candidate = choose_file_interactively(files)
        if candidate is None:
            return None

    # Scope enforcement: only .exe files inside samples/ are allowed
    return check_scope(candidate, SAMPLES_DIR)


def resolve_output_dir(args):
    """Relative paths are resolved from the project folder, and must stay inside it."""
    output_dir = Path(args.output)
    if not output_dir.is_absolute():
        output_dir = BASE_DIR / output_dir
    return check_output_dir(output_dir, BASE_DIR)


def analyse(selected_file):
    """Run all analysis steps. Returns the report dict, or None on failure."""
    # Step 1: PE File Analysis
    print("\n[1] PE FILE ANALYSIS")

    pe_result = analyze_pe(str(selected_file))

    if "error" in pe_result:
        print(pe_result["error"])
        return None

    print("File information and hashes collected.")

    # Step 2: Entropy and String Analysis
    print("\n[2] ENTROPY AND STRING ANALYSIS")

    string_result = analyze_strings(str(selected_file))

    if "error" in string_result:
        print(string_result["error"])
        return None

    all_strings = (
        string_result["ascii_strings"]
        + string_result["utf16_strings"]
    )

    # Give each high-entropy region a meaning using the PE sections
    region_details = classify_packed_regions(
        string_result["packed_regions"], pe_result.get("sections", [])
    )
    string_result["packed_region_details"] = region_details
    string_result["context_verdict"] = contextual_verdict(region_details)

    print("Entropy:", string_result["entropy"])
    print("Verdict (global):", string_result["entropy_verdict"])
    print("Packed regions:", len(region_details),
          summarize_regions(region_details))
    print("Verdict (context):", string_result["context_verdict"])
    print("Suspicious strings:", len(string_result["suspicious_strings"]))
    print("Strings extracted:", len(all_strings))

    # Step 3: IOC Extraction
    print("\n[3] IOC EXTRACTION")

    ioc_result = {
        "ips": extract_ips(all_strings),
        "urls": extract_urls(all_strings),
        "trusted_urls": extract_trusted_urls(all_strings),
        "domains": extract_domains(all_strings),
        "trusted_domains": extract_trusted_domains(all_strings),
        "hashes": extract_hashes(all_strings)
    }

    for category, results in ioc_result.items():
        print(f"{category}: {len(results)} found")

    # Step 4: MITRE ATT&CK Analysis
    print("\n[4] MITRE ATT&CK ANALYSIS")

    # Let mitre_mapper extract PE imports itself.
    mitre_result = analyze_mitre(
        str(selected_file),
        strings=all_strings
    )

    if "error" in mitre_result:
        print(mitre_result["error"])
        return None

    print("Suspicious APIs:", len(mitre_result["detected_apis"]))
    print("MITRE Risk Score (behaviour only):", mitre_result["risk_score"], "/100")
    print("MITRE Risk Level (behaviour only):", mitre_result["risk_level"])

    # Step 5: Combined, explainable risk score (uses every module)
    print("\n[5] COMBINED RISK ASSESSMENT")

    risk_assessment = calculate_combined_risk(
        pe_result, string_result, ioc_result, mitre_result, all_strings
    )
    for line in format_breakdown(risk_assessment):
        print(line)

    # Step 6: Combine all results (metadata labels the report clearly)
    return {
        "metadata": {
            "tool": "MalTrace",
            "version": VERSION,
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "mode": "static analysis only (sample was never executed)",
            "scope": str(SAMPLES_DIR),
            "authorization_confirmed": True,
        },
        "filename": selected_file.name,
        "pe_analysis": pe_result,
        "string_analysis": string_result,
        "ioc_analysis": ioc_result,
        "mitre_analysis": mitre_result,
        "risk_assessment": risk_assessment
    }


def save_report(report, output_dir, selected_file):
    """Step 7: save the JSON report locally. Nothing is sent anywhere."""
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / (selected_file.stem + "_report.json")

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report_path


def main():
    args = parse_args()

    print("=" * 40)
    print("             MALTRACE")
    print("    Static Binary Analyzer")
    print("     MITRE ATT&CK Mapper")
    print("=" * 40)

    # Ethical gate: disclaimer + explicit authorization
    show_disclaimer_and_confirm(args.confirm_authorized)

    if not SAMPLES_DIR.exists():
        print("Samples folder not found.")
        return 1

    files = list_samples()

    if not files:
        print("No EXE files found in samples folder.")
        return 1

    if args.list:
        print("\nAvailable files:")
        for f in files:
            print(f" - {f.name}")
        return 0

    selected_file = resolve_target(args, files)
    if selected_file is None:
        return 1

    output_dir = resolve_output_dir(args)

    print(f"\nSelected file: {selected_file.name}")

    # Dry run: show what would happen, touch nothing
    if args.dry_run:
        print("\n[DRY RUN] Scope check passed. No analysis performed.")
        print(f"  Would analyse : {selected_file}")
        print(f"  Would save to : {output_dir / (selected_file.stem + '_report.json')}")
        return 0

    # Analysis. Unexpected errors are reported cleanly instead of a traceback.
    # (Ctrl+C is not caught here, so the kill switch still works.)
    try:
        report = analyse(selected_file)
    except Exception as error:
        print(f"\n[!] Analysis failed: {type(error).__name__}: {error}")
        return 1

    if report is None:
        return 1

    report_path = save_report(report, output_dir, selected_file)

    print("\n" + "=" * 40)
    print("         ANALYSIS COMPLETED")
    print("=" * 40)

    print("Report saved at:")
    print(report_path)
    return 0


if __name__ == "__main__":
    run_with_kill_switch(main)