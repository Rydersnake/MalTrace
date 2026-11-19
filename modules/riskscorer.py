"""risk_scorer.py - combine every module's findings into ONE explainable score.

Why this module exists
----------------------
Each module answers a different question:
    mitre_mapper   -> what could the program DO?      (APIs and attack chains)
    pe_analyzer    -> is the file STRUCTURE odd?      (section flags)
    entropy_context-> is there PACKED code?           (high-entropy regions)
    string checks  -> do the TEXT clues point to tools or packers?
    ioc_extractor  -> does it talk to UNKNOWN hosts?

A single weak signal is common in normal software, so it is worth few
points. Signals that agree across modules are worth more. Every category
has a cap, so one noisy module can never push the score to 100 alone.
Every point is listed with its reason, so the score can be audited.

Static only: it works on numbers and text already collected.
"""
import re

# ------------------------------------------------------------ weights
# Maximum points each category may add (they sum to 135 and the total is
# capped at 100, so even a strong sample needs agreement from several modules).
CAPS = {
    "behaviour": 50,
    "packing": 30,
    "strings": 15,
    "network": 15,
    "interaction": 25,
}
LABELS = {
    "behaviour": "Behaviour (MITRE APIs and attack chains)",
    "packing": "Packing and PE structure",
    "strings": "String clues (packers, system tools)",
    "network": "Unknown network indicators",
    "interaction": "Signals that agree across modules",
}

# behaviour
API_POINTS = {"high": 3, "medium": 1, "low": 0}   # one API is weak evidence
API_SUBCAP = 10
CHAIN_KEYS = ("matched_chains", "attack_chains", "chains")
# These two chains are used by almost every Windows program, so they count less
GENERIC_CHAIN_NAMES = {"Dynamic API Obfuscation", "Registry Persistence"}
GENERIC_CHAIN_FACTOR = 0.25

# packing / PE structure
SUSPICIOUS_REGION_POINTS = 10       # high entropy inside executable code
SUSPICIOUS_REGION_CAP = 20
REVIEW_REGION_POINTS = 1            # high entropy in data or overlay
REVIEW_REGION_CAP = 3
FLAG_POINTS = {"high": 8, "medium": 4, "low": 1}
# Entropy is judged by entropy_context (it knows which section a region is
# in), so the plain "section has very high entropy" PE flag is not counted
# again. This avoids double counting and the .rsrc false positive.
ENTROPY_FLAG = re.compile(r"very high entropy", re.I)

# strings (word-boundary matching, so "upx" is not found inside other words)
PACKER_RE = re.compile(
    r"(?<![a-z])(upx\d?|upx!|themida|vmprotect|aspack|mpress)(?![a-z])", re.I)
LOLBIN_RE = re.compile(
    r"(?<![a-z0-9])(rundll32|regsvr32|wscript|cscript|mshta|powershell|"
    r"certutil|bitsadmin|cmd\.exe)(?:\.exe)?(?![a-z0-9])", re.I)
PACKER_POINTS = 8
LOLBIN_POINTS = 2
LOLBIN_CAP = 6

# network (trusted vendor domains are reported elsewhere and score 0)
IP_POINTS = 3
DOMAIN_POINTS = 2

# interactions
PACKED_LOADER_POINTS = 15
INJECTION_NETWORK_POINTS = 10
INJECTION_APIS = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}


# ------------------------------------------------------------ helpers
def _category(name, signals):
    """Sum signals, apply the category cap, keep the reasons."""
    raw = sum(points for _, points in signals)
    return {
        "category": name,
        "label": LABELS[name],
        "points": min(raw, CAPS[name]),
        "cap": CAPS[name],
        "signals": [{"signal": text, "points": points} for text, points in signals],
    }


def _get_chains(mitre):
    """Return (list_of_chains, found_key). Tries the likely key names."""
    for key in CHAIN_KEYS:
        if key in mitre:
            return [c for c in mitre[key] if isinstance(c, dict)], True
    return [], False


def _level(score):
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _is_packed(pe, strings_result):
    """Packing evidence: high entropy inside code, or a high-severity PE flag."""
    regions = strings_result.get("packed_region_details", [])
    in_code = any(r.get("judgement") == "suspicious" for r in regions)
    high_flag = any(
        f.get("severity") == "high" and not ENTROPY_FLAG.search(f.get("reason", ""))
        for f in pe.get("flags", [])
    )
    return in_code or high_flag


# --------------------------------------------------------- categories
def _behaviour(mitre, notes):
    signals = []

    apis = mitre.get("detected_apis", [])
    api_points = sum(API_POINTS.get(a.get("severity"), 0) for a in apis)
    if api_points:
        high = sum(1 for a in apis if a.get("severity") == "high")
        signals.append((f"{len(apis)} suspicious API(s) found, {high} high severity "
                        f"(single APIs are weak evidence)", min(api_points, API_SUBCAP)))

    chains, found = _get_chains(mitre)
    if not found:
        notes.append("No attack-chain data found in the MITRE result, "
                     "so chains were not scored.")
    for chain in chains:
        name = chain.get("name") or chain.get("chain") or chain.get("technique_id") or "unnamed chain"
        base = chain.get("bonus_score", 10)
        if name in GENERIC_CHAIN_NAMES:
            signals.append((f"Chain '{name}' (common in normal software, reduced weight)",
                            int(round(base * GENERIC_CHAIN_FACTOR))))
        else:
            signals.append((f"Chain '{name}'", base))

    return _category("behaviour", signals)


def _packing(pe, strings_result, notes):
    signals = []
    regions = strings_result.get("packed_region_details", [])

    suspicious = [r for r in regions if r.get("judgement") == "suspicious"]
    if suspicious:
        signals.append((f"{len(suspicious)} high-entropy region(s) inside executable sections",
                        min(SUSPICIOUS_REGION_POINTS * len(suspicious), SUSPICIOUS_REGION_CAP)))

    review = [r for r in regions if r.get("judgement") == "review"]
    if review:
        signals.append((f"{len(review)} high-entropy region(s) in data sections or overlay",
                        min(REVIEW_REGION_POINTS * len(review), REVIEW_REGION_CAP)))

    if any(r.get("judgement") == "unknown" for r in regions):
        notes.append("Some high-entropy regions could not be mapped to a PE section.")

    for flag in pe.get("flags", []):
        reason = flag.get("reason", "")
        if ENTROPY_FLAG.search(reason):
            continue                      # judged by region analysis instead
        points = FLAG_POINTS.get(flag.get("severity"), 0)
        if points:
            signals.append((f"PE flag: {reason}", points))

    return _category("packing", signals)


def _strings(strings):
    signals = []
    packers, tools = set(), set()
    for text in strings:
        for match in PACKER_RE.findall(text):
            # UPX0, UPX1 and UPX! are the same packer family
            packers.add(re.sub(r"[\d!]+$", "", match.lower()))
        for match in LOLBIN_RE.findall(text):
            tools.add(match.lower().replace(".exe", ""))

    for name in sorted(packers):
        signals.append((f"Packer or protector name found: {name}", PACKER_POINTS))
    if tools:
        signals.append((f"System tool name(s) found: {', '.join(sorted(tools))} "
                        f"(also used by legitimate software)",
                        min(LOLBIN_POINTS * len(tools), LOLBIN_CAP)))
    return _category("strings", signals)


def _network(ioc):
    signals = []
    ips = ioc.get("ips", [])
    domains = ioc.get("domains", [])        # trusted vendor domains excluded
    if ips:
        signals.append((f"{len(ips)} IP address(es) in strings", IP_POINTS * len(ips)))
    if domains:
        signals.append((f"{len(domains)} unknown domain(s) in strings",
                        DOMAIN_POINTS * len(domains)))
    return _category("network", signals)


def _interactions(pe, strings_result, mitre, ioc):
    """Extra points only when independent modules point the same way."""
    signals = []
    api_names = {a.get("api") for a in mitre.get("detected_apis", [])}
    chains, _ = _get_chains(mitre)

    # 1. Packed file + runtime API resolution = typical packer stub
    resolves_at_runtime = {"LoadLibrary", "GetProcAddress"} <= api_names
    if _is_packed(pe, strings_result) and resolves_at_runtime:
        signals.append(("Packed or odd PE structure AND APIs resolved at runtime "
                        "(typical of a packer stub)", PACKED_LOADER_POINTS))

    # 2. Process injection + unknown network host = remote-controlled injector
    injection = (
        any(str(c.get("technique_id", "")).startswith("T1055") for c in chains)
        or len(INJECTION_APIS & api_names) >= 2
    )
    has_network = bool(ioc.get("ips") or ioc.get("domains"))
    if injection and has_network:
        signals.append(("Process-injection behaviour AND unknown network indicators",
                        INJECTION_NETWORK_POINTS))

    return _category("interaction", signals)


# -- entry point
def calculate_combined_risk(pe_result, string_result, ioc_result, mitre_result,
                            strings=None):
    """Return {"score", "level", "breakdown", "notes"}.

    `strings` is the full list of extracted strings. If it is not given,
    the shorter suspicious_strings list is used.
    """
    notes = []
    if strings is None:
        strings = string_result.get("suspicious_strings", [])

    breakdown = [
        _behaviour(mitre_result, notes),
        _packing(pe_result, string_result, notes),
        _strings(strings),
        _network(ioc_result),
        _interactions(pe_result, string_result, mitre_result, ioc_result),
    ]
    score = min(sum(item["points"] for item in breakdown), 100)
    return {"score": score, "level": _level(score), "breakdown": breakdown, "notes": notes}


def format_breakdown(result, max_signals=3):
    """Readable lines for the terminal (the JSON report keeps every signal)."""
    lines = [f"Combined Risk Score: {result['score']} /100",
             f"Combined Risk Level: {result['level']}"]
    for item in result["breakdown"]:
        lines.append(f"  {item['label']}: {item['points']}/{item['cap']}")
        top = sorted(item["signals"], key=lambda s: -s["points"])[:max_signals]
        for signal in top:
            lines.append(f"      +{signal['points']:<3} {signal['signal']}")
    for note in result["notes"]:
        lines.append(f"  Note: {note}")
    return lines
