
import json
from pathlib import Path

# Import modules from your teammates
from modules.pe_analyzer import analyze_pe
from modules.string_analyzer import analyze as analyze_strings

from modules.ioc_extractor import (
    extract_ips,
    extract_urls,
    extract_domains,
    extract_hashes
)

from modules.mitre_mapper import analyze as analyze_mitre


# Project directories
BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"
OUTPUT_DIR = BASE_DIR / "output"


def main():

    print("=" * 40)
    print("             MALTRACE")
    print("    Static Binary Analyzer")
    print("     MITRE ATT&CK Mapper")
    print("=" * 40)

    # Find sample files
    if not SAMPLES_DIR.exists():
        print("Samples folder not found.")
        return

    files = sorted(
        f for f in SAMPLES_DIR.iterdir()
        if f.is_file() and f.suffix.lower() == ".exe"
    )

    if not files:
        print("No EXE files found in samples folder.")
        return

    print("\nAvailable files:")

    for number, file in enumerate(files, start=1):
        print(f"{number}. {file.name}")

    try:
        choice = int(input("\nSelect a file to analyse: "))

        if choice < 1 or choice > len(files):
            print("Invalid selection.")
            return

    except ValueError:
        print("Please enter a number.")
        return

    selected_file = files[choice - 1]

    print(f"\nSelected file: {selected_file.name}")

    # Step 1: PE File Analysis
    print("\n[1] PE FILE ANALYSIS")

    pe_result = analyze_pe(str(selected_file))

    if "error" in pe_result:
        print(pe_result["error"])
        return

    print("File information and hashes collected.")

    # Step 2: Entropy and String Analysis
    print("\n[2] ENTROPY AND STRING ANALYSIS")

    string_result = analyze_strings(str(selected_file))

    if "error" in string_result:
        print(string_result["error"])
        return

    all_strings = (
        string_result["ascii_strings"]
        + string_result["utf16_strings"]
    )

    print("Entropy:", string_result["entropy"])
    print("Verdict:", string_result["entropy_verdict"])
    print("Strings extracted:", len(all_strings))

    # Step 3: IOC Extraction
    print("\n[3] IOC EXTRACTION")

    ioc_result = {
        "ips": extract_ips(all_strings),
        "urls": extract_urls(all_strings),
        "domains": extract_domains(all_strings),
        "hashes": extract_hashes(all_strings)
    }

    for category, results in ioc_result.items():
        print(f"{category}: {len(results)} found")

    # Step 4: MITRE ATT&CK Analysis
    print("\n[4] MITRE ATT&CK ANALYSIS")

    # Let mitre_mapper extract PE imports itself.
    # Do not pass the current empty imports list from pe_analyzer.
    mitre_result = analyze_mitre(
        str(selected_file),
        strings=all_strings
    )

    if "error" in mitre_result:
        print(mitre_result["error"])
        return

    print("Suspicious APIs:",
          len(mitre_result["detected_apis"]))

    print("MITRE Risk Score:",
          mitre_result["risk_score"], "/100")

    print("MITRE Risk Level:",
          mitre_result["risk_level"])

    # Step 5: Combine all results
    report = {
        "filename": selected_file.name,
        "pe_analysis": pe_result,
        "string_analysis": string_result,
        "ioc_analysis": ioc_result,
        "mitre_analysis": mitre_result
    }

    # Step 6: Save JSON report
    OUTPUT_DIR.mkdir(exist_ok=True)

    report_path = OUTPUT_DIR / (
        selected_file.stem + "_report.json"
    )

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n" + "=" * 40)
    print("         ANALYSIS COMPLETED")
    print("=" * 40)

    print("Report saved at:")
    print(report_path)


if __name__ == "__main__":
    main()
