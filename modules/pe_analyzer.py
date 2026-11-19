import os
import hashlib
import pefile
from datetime import datetime, timezone
from modules.string_analyzer import calculate_entropy


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

def load_pe(path):
    """Try to parse the file as a PE. Returns (pe_object, error_message)."""
    try:
        return pefile.PE(path), None
    except pefile.PEFormatError:
        return None, "Not a valid PE file"
    except PermissionError:
        return None, "Permission denied reading file"
    except (OSError, ValueError) as err:
        return None, f"Could not read file: {err}"

MACHINE_TYPES = {
    0x14C: "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0x1C0: "ARM",
    0xAA64: "ARM64",
}

SUBSYSTEMS = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
}

def get_headers(pe):
    """Pull the key facts out of the PE headers."""
    machine = pe.FILE_HEADER.Machine
    timestamp = pe.FILE_HEADER.TimeDateStamp
    subsystem = pe.OPTIONAL_HEADER.Subsystem

    return {
        "architecture": MACHINE_TYPES.get(machine, f"Unknown ({hex(machine)})"),
        "compile_timestamp": timestamp,
        "compile_time_utc": datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "subsystem": SUBSYSTEMS.get(subsystem, f"Other ({subsystem})"),
        "is_dll": pe.is_dll(),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
    }

SCN_EXECUTE = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000

def get_sections(pe):
    """List every section with its size, permissions and entropy."""
    sections = []
    for section in pe.sections:
        flags = section.Characteristics
        perms = "R" if flags & SCN_READ else "-"
        perms += "W" if flags & SCN_WRITE else "-"
        perms += "X" if flags & SCN_EXECUTE else "-"

        sections.append({
            "name": section.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": section.Misc_VirtualSize,
            "raw_offset": section.PointerToRawData, 
            "raw_size": section.SizeOfRawData,
            "permissions": perms,
            "entropy": round(calculate_entropy(section.get_data()), 3),
        })
    return sections

def get_imports(pe):
    """List every imported function together with the DLL it comes from."""
    imports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="ignore")
        for imp in entry.imports:
            if imp.name:
                func = imp.name.decode("utf-8", errors="ignore")
            else:
                func = f"ordinal_{imp.ordinal}"
            imports.append({"dll": dll_name, "function": func})
    return imports

STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".pdata", ".xdata", ".idata", ".edata",
    ".rsrc", ".reloc", ".bss", ".tls", ".didat", "_rdata", ".crt",
    ".imrsiv", "fothk", 
}
HIGH_ENTROPY = 7.2
MIN_IMPORTS = 5


def get_flags(headers, sections, imports):
    """Look for signs that a file may be packed, hidden or tampered with."""
    flags = []

    for s in sections:
        name = s["name"]
        if "W" in s["permissions"] and "X" in s["permissions"]:
            flags.append({"severity": "high",
                          "reason": f"Section {name} is writable and executable"})
        if name.upper().startswith("UPX"):
            flags.append({"severity": "high",
                          "reason": f"Section name {name} points to the UPX packer"})
        elif name.lower() not in STANDARD_SECTIONS:
            flags.append({"severity": "low",
                          "reason": f"Non-standard section name: {name}"})
        if s["entropy"] >= HIGH_ENTROPY:
            flags.append({"severity": "medium",
                          "reason": f"Section {name} has very high entropy ({s['entropy']})"})

    if headers["compile_timestamp"] == 0:
        flags.append({"severity": "low", "reason": "Compile timestamp is zero"})
    if len(imports) < MIN_IMPORTS:
        flags.append({"severity": "medium",
                      "reason": f"Only {len(imports)} imports (packed files hide them)"})
    return flags


def entry_point_flag(pe):
    """Check that the program starts running inside a code section."""
    rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if rva == 0:
        return None  # no entry point, e.g. a resource-only DLL
    section = pe.get_section_by_rva(rva)
    if section is None:
        return {"severity": "medium",
                "reason": "Entry point is outside every section"}
    if not section.Characteristics & SCN_EXECUTE:
        name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        return {"severity": "high",
                "reason": f"Entry point is inside a non-executable section ({name})"}
    return None

def analyze_pe(path):
    """Entry point: takes a file path, returns a dictionary of results."""
    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}

    try:
        hashes = calculate_hashes(path)
    except OSError as err:
        return {"error": f"Cannot read file: {err}"}

    result = {
        "file_info": {
            "name": os.path.basename(path),
            "size_bytes": os.path.getsize(path),
            "hashes": hashes,
        },
        "headers": {},
        "sections": [],
        "imports": [],
        "flags": [],
    }

    pe, error = load_pe(path)
    if error:
        result["error"] = error
        return result

    result["headers"] = get_headers(pe)
    result["sections"] = get_sections(pe)
    result["imports"] = get_imports(pe)
    result["flags"] = get_flags(result["headers"], result["sections"], result["imports"])
    entry_flag = entry_point_flag(pe)
    if entry_flag:
        result["flags"].append(entry_flag)
    pe.close()
    return result
