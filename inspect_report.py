
import json

report_path = "output/notepad_report.json"

with open(report_path, "r", encoding="utf-8") as file:
    report = json.load(file)

print("\n=== SUSPICIOUS APIs ===")

for item in report["mitre_analysis"]["detected_apis"]:
    print(
        item["matched_variant"],
        "-",
        item["technique_id"],
        "-",
        item["source"]
    )

print("\n=== DOMAINS (FIRST 30) ===")

for domain in report["ioc_analysis"]["domains"][:30]:
    print(domain)

print("\n=== MITRE RISK ===")
print("Score:", report["mitre_analysis"]["risk_score"])
print("Level:", report["mitre_analysis"]["risk_level"])
