"""mitre_mapper.py - Detect suspicious Windows APIs and map to MITRE ATT&CK techniques.
Static analysis only: inspects PE import tables and extracted strings without executing the file."""

import os
from modules.string_analyzer import extract_ascii, extract_utf16, MAX_SIZE

try:
    import pefile
except ImportError:
    pefile = None


# Mapping of suspicious Windows API base names to MITRE ATT&CK metadata
MITRE_API_DB = {
    # Process Injection & Memory Manipulation
    "VirtualAlloc": {
        "technique_id": "T1055",
        "technique": "Process Injection",
        "tactic": "Defense Evasion",
        "severity": "medium",
        "description": "Allocates memory in local or remote process space",
    },
    "VirtualAllocEx": {
        "technique_id": "T1055",
        "technique": "Process Injection",
        "tactic": "Defense Evasion",
        "severity": "high",
        "description": "Allocates memory within a remote process virtual address space",
    },
    "VirtualProtect": {
        "technique_id": "T1055",
        "technique": "Process Injection",
        "tactic": "Defense Evasion",
        "severity": "medium",
        "description": "Changes memory protection permissions (often RW to RX for shellcode)",
    },
    "WriteProcessMemory": {
        "technique_id": "T1055",
        "technique": "Process Injection",
        "tactic": "Defense Evasion",
        "severity": "high",
        "description": "Writes data or shellcode into a remote process memory space",
    },
    "CreateRemoteThread": {
        "technique_id": "T1055",
        "technique": "Process Injection",
        "tactic": "Privilege Escalation",
        "severity": "high",
        "description": "Starts a thread inside another process to execute injected code",
    },
    "QueueUserAPC": {
        "technique_id": "T1055.004",
        "technique": "Asynchronous Procedure Call",
        "tactic": "Defense Evasion",
        "severity": "high",
        "description": "Queues an APC to a thread for APC-based code injection",
    },
    "NtUnmapViewOfSection": {
        "technique_id": "T1055.012",
        "technique": "Process Hollowing",
        "tactic": "Defense Evasion",
        "severity": "high",
        "description": "Unmaps legitimate code from a suspended process before hollowing",
    },
    "OpenProcess": {
        "technique_id": "T1055",
        "technique": "Process Injection",
        "tactic": "Defense Evasion",
        "severity": "low",
        "description": "Opens a handle to another running process",
    },

    # Execution & Dynamic API Resolution
    "CreateProcess": {
        "technique_id": "T1106",
        "technique": "Native API",
        "tactic": "Execution",
        "severity": "medium",
        "description": "Spawns a new process on the host system",
    },
    "ShellExecute": {
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "severity": "medium",
        "description": "Executes a shell command or external file",
    },
    "WinExec": {
        "technique_id": "T1106",
        "technique": "Native API",
        "tactic": "Execution",
        "severity": "medium",
        "description": "Runs an executable program directly",
    },
    "LoadLibrary": {
        "technique_id": "T1027.007",
        "technique": "Dynamic API Resolution",
        "tactic": "Defense Evasion",
        "severity": "low",
        "description": "Loads a DLL into process memory at runtime",
    },
    "GetProcAddress": {
        "technique_id": "T1027.007",
        "technique": "Dynamic API Resolution",
        "tactic": "Defense Evasion",
        "severity": "medium",
        "description": "Resolves function addresses dynamically to hide imports",
    },

    # Persistence
    "RegCreateKey": {
        "technique_id": "T1547.001",
        "technique": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "severity": "low",
        "description": "Creates a Windows Registry key (can be used for persistence)",
    },
    "RegSetValue": {
        "technique_id": "T1547.001",
        "technique": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "severity": "medium",
        "description": "Writes data into a Windows Registry value",
    },
    "CreateService": {
        "technique_id": "T1543.003",
        "technique": "Windows Service",
        "tactic": "Persistence",
        "severity": "high",
        "description": "Installs a new Windows service for persistent execution",
    },

    # Anti-Analysis & Debugger Evasion
    "IsDebuggerPresent": {
        "technique_id": "T1622",
        "technique": "Debugger Evasion",
        "tactic": "Defense Evasion",
        "severity": "low",
        "description": "Checks PEB to detect if the process is being debugged",
    },
    "CheckRemoteDebuggerPresent": {
        "technique_id": "T1622",
        "technique": "Debugger Evasion",
        "tactic": "Defense Evasion",
        "severity": "high",
        "description": "Queries the kernel to see if a debugger is attached",
    },
    "NtQueryInformationProcess": {
        "technique_id": "T1622",
        "technique": "Debugger Evasion",
        "tactic": "Defense Evasion",
        "severity": "high",
        "description": "Retrieves process debug port or flags to evade analysis",
    },

    # Credential Access & Collection (Keylogging)
    "SetWindowsHook": {
        "technique_id": "T1056.001",
        "technique": "Keylogging",
        "tactic": "Collection",
        "severity": "high",
        "description": "Installs a hook procedure to monitor keystrokes or system events",
    },
    "GetAsyncKeyState": {
        "technique_id": "T1056.001",
        "technique": "Keylogging",
        "tactic": "Collection",
        "severity": "high",
        "description": "Polls keyboard state to capture user keystrokes",
    },
    "CryptUnprotectData": {
        "technique_id": "T1555",
        "technique": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "severity": "high",
        "description": "Decrypts DPAPI-protected credentials or browser data",
    },

    # Discovery
    "CreateToolhelp32Snapshot": {
        "technique_id": "T1057",
        "technique": "Process Discovery",
        "tactic": "Discovery",
        "severity": "medium",
        "description": "Takes a snapshot of running processes, threads, and modules",
    },
    "Process32First": {
        "technique_id": "T1057",
        "technique": "Process Discovery",
        "tactic": "Discovery",
        "severity": "low",
        "description": "Enumerates running processes from a system snapshot",
    },
    "GetSystemInfo": {
        "technique_id": "T1082",
        "technique": "System Information Discovery",
        "tactic": "Discovery",
        "severity": "low",
        "description": "Queries hardware and operating system architecture details",
    },

    # Command and Control / Network
    "URLDownloadToFile": {
        "technique_id": "T1105",
        "technique": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "severity": "high",
        "description": "Downloads a remote payload from a URL directly to disk",
    },
    "InternetOpen": {
        "technique_id": "T1071.001",
        "technique": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "severity": "medium",
        "description": "Initializes WinINet functions for HTTP/HTTPS communication",
    },
    "InternetReadFile": {
        "technique_id": "T1105",
        "technique": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "severity": "medium",
        "description": "Reads data from an opened remote URL handle",
    },
    "WSAStartup": {
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "tactic": "Command and Control",
        "severity": "low",
        "description": "Initializes raw Windows Sockets (Winsock) networking",
    },
}

# Behavioral chains: combinations of APIs that strongly indicate a specific attack pattern
ATTACK_CHAINS = [
    {
        "name": "Remote Process Injection",
        "technique_id": "T1055",
        "tactic": "Defense Evasion",
        "required_apis": {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
        "min_match": 3,
        "bonus_score": 25,
        "description": "Opens a target process, allocates memory, writes payload, and executes it remotely",
    },
    {
        "name": "Process Hollowing",
        "technique_id": "T1055.012",
        "tactic": "Defense Evasion",
        "required_apis": {"CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory"},
        "min_match": 3,
        "bonus_score": 25,
        "description": "Creates a suspended process, unmaps its section, and replaces it with malicious code",
    },
    {
        "name": "Dynamic API Obfuscation",
        "technique_id": "T1027.007",
        "tactic": "Defense Evasion",
        "required_apis": {"LoadLibrary", "GetProcAddress"},
        "min_match": 2,
        "bonus_score": 10,
        "description": "Resolves Windows APIs at runtime to hide malicious imports from static analysis",
    },
    {
        "name": "Dropper / Download and Execute",
        "technique_id": "T1105",
        "tactic": "Command and Control",
        "required_apis": {"URLDownloadToFile", "InternetOpen", "WinExec", "ShellExecute", "CreateProcess"},
        "min_match": 2,
        "bonus_score": 20,
        "description": "Combines network download APIs with process execution APIs",
    },
    {
        "name": "Registry Persistence",
        "technique_id": "T1547.001",
        "tactic": "Persistence",
        "required_apis": {"RegCreateKey", "RegSetValue"},
        "min_match": 2,
        "bonus_score": 8,
        "description": "Creates and modifies Registry keys to survive system reboots",
    },
]

SEVERITY_SCORES = {"low": 3, "medium": 8, "high": 18}


def normalize_api_name(raw_name):
    """Strip common Windows ANSI/Unicode/Extended suffixes (A, W, Ex, ExA, ExW)
    so variants like CreateProcessW or RegSetValueExA match their base entry."""
    clean = raw_name.strip()
    if clean in MITRE_API_DB:
        return clean

    for suffix in ("ExA", "ExW", "Ex", "A", "W"):
        if clean.endswith(suffix):
            candidate = clean[:-len(suffix)]
            if candidate in MITRE_API_DB:
                return candidate
    return None


def extract_pe_imports(path):
    """Extract imported API function names from the PE Import Address Table (IAT)."""
    if pefile is None:
        return []

    imported_apis = []
    pe = None
    try:
        pe = pefile.PE(path)
        for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            if hasattr(pe, attr):
                for entry in getattr(pe, attr):
                    for imp in entry.imports:
                        if imp.name:
                            imported_apis.append(imp.name.decode("ascii", errors="ignore"))
    except Exception:
        return []
    finally:
        if pe is not None:
            pe.close()

    return imported_apis


def detect_suspicious_apis(strings, pe_imports=None):
    """Scan PE imports and extracted strings for known suspicious Windows APIs."""
    pe_imports = pe_imports or []
    found = {}

    # 1. Check PE Import Table first
    for raw_api in pe_imports:
        base_api = normalize_api_name(raw_api)
        if base_api:
            info = MITRE_API_DB[base_api]
            found[base_api] = {
                "api": base_api,
                "matched_variant": raw_api,
                "source": "PE Import Table",
                "technique_id": info["technique_id"],
                "technique": info["technique"],
                "tactic": info["tactic"],
                "severity": info["severity"],
                "description": info["description"],
            }

    # 2. Check extracted strings (catches dynamically resolved APIs or non-PE scripts)
    for text in strings:
        for token in text.replace("(", " ").replace(")", " ").split():
            token = token.strip(".,;:!?\"'[]{}<>\\/")
            base_api = normalize_api_name(token)
            if not base_api:
                continue

            if base_api in found:
                if found[base_api]["source"] == "PE Import Table":
                    found[base_api]["source"] = "PE Import Table + Strings"
            else:
                info = MITRE_API_DB[base_api]
                found[base_api] = {
                    "api": base_api,
                    "matched_variant": token,
                    "source": "Strings Only (Possible Dynamic Resolution)",
                    "technique_id": info["technique_id"],
                    "technique": info["technique"],
                    "tactic": info["tactic"],
                    "severity": info["severity"],
                    "description": info["description"],
                }

    return list(found.values())


def evaluate_attack_chains(detected_apis):
    """Identify multi-API behavioral chains (e.g. Process Injection, Dropper)."""
    present_names = {item["api"] for item in detected_apis}
    matched_chains = []

    for chain in ATTACK_CHAINS:
        matched = sorted(chain["required_apis"].intersection(present_names))
        if len(matched) >= chain["min_match"]:
            # For Dropper chain, ensure at least one network API and one execution API matched
            if chain["name"] == "Dropper / Download and Execute":
                net_apis = {"URLDownloadToFile", "InternetOpen"}
                exec_apis = {"WinExec", "ShellExecute", "CreateProcess"}
                if not (net_apis.intersection(matched) and exec_apis.intersection(matched)):
                    continue

            matched_chains.append({
                "name": chain["name"],
                "technique_id": chain["technique_id"],
                "tactic": chain["tactic"],
                "matched_apis": matched,
                "bonus_score": chain["bonus_score"],
                "description": chain["description"],
            })

    return matched_chains


def group_by_tactic(detected_apis):
    """Group unique MITRE ATT&CK techniques under their respective tactics."""
    tactics = {}
    for item in detected_apis:
        tactic = item["tactic"]
        entry = f"{item['technique_id']} - {item['technique']}"
        if tactic not in tactics:
            tactics[tactic] = set()
        tactics[tactic].add(entry)

    return {tactic: sorted(techs) for tactic, techs in sorted(tactics.items())}


def calculate_mitre_risk(detected_apis, matched_chains):
    """Calculate a 0-100 MITRE threat score based on API severity and attack chains."""
    score = 0
    for item in detected_apis:
        score += SEVERITY_SCORES.get(item["severity"], 3)

    # Bonus points for confirmed multi-API behavioral chains
    for chain in matched_chains:
        score += chain.get("bonus_score", 10)
    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "CLEAN"

    return {"score": score, "level": level}


def analyze(path, strings=None, pe_imports=None):
    """Entry point for main.py. Analyzes a file path and maps findings to MITRE ATT&CK."""
    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}

    if strings is None:
        try:
            with open(path, "rb") as f:
                data = f.read(MAX_SIZE + 1)
        except OSError as err:
            return {"error": f"Cannot read file: {err}"}
        if len(data) > MAX_SIZE:
            return {"error": "File is larger than 100 MB"}
        strings = extract_ascii(data) + extract_utf16(data)

    if pe_imports is None:
        pe_imports = extract_pe_imports(path)

    detected_apis = detect_suspicious_apis(strings, pe_imports)
    matched_chains = evaluate_attack_chains(detected_apis)
    tactics_summary = group_by_tactic(detected_apis)
    risk = calculate_mitre_risk(detected_apis, matched_chains)

    return {
        "detected_apis": detected_apis,
        "attack_chains": matched_chains,
        "tactics_summary": tactics_summary,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        sys.exit("Usage: py -m modules.mitre_mapper <file>")

    res = analyze(sys.argv[1])
    if "error" in res:
        sys.exit(res["error"])

    print(f"MITRE Risk: {res['risk_score']}/100 ({res['risk_level']})")
    print(f"Detected Suspicious APIs ({len(res['detected_apis'])}):")
    for api in res["detected_apis"]:
        print(f"  - {api['matched_variant']} -> [{api['technique_id']}] {api['technique']} ({api['tactic']}) [{api['source']}]")

    if res["attack_chains"]:
        print("\nDetected Attack Chains:")
        for chain in res["attack_chains"]:
            print(f"  * {chain['name']} ({chain['technique_id']}): {', '.join(chain['matched_apis'])}")
