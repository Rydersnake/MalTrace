""entropy_context.py - give high-entropy regions a meaning.

string_analyzer finds high-entropy byte ranges anywhere in the file.
That alone is misleading: a range inside .rsrc (icons, compressed
resources) is normal, while a range inside an executable code section
is a real packing indicator. This module maps every region to the PE
section it falls in and judges it.

Static only: it works on numbers already collected, it reads no files.
"""

# Sections that normally hold compressed or random-looking data
BENIGN_SECTIONS = {".rsrc", ".reloc"}


def _overlap(start, end, sec_start, sec_end):
    """Number of bytes shared by [start, end) and [sec_start, sec_end)."""
    return max(0, min(end, sec_end) - max(start, sec_start))


def _judge_section(section):
    """Return (judgement, reason) for a region that lies in this section."""
    name = section["name"]
    if name.lower() in BENIGN_SECTIONS:
        return "benign", f"inside {name} (resources/relocations are normally high entropy)"
    if "X" in section["permissions"]:
        return "suspicious", f"inside executable section {name} (typical of packed code)"
    return "review", f"inside data section {name} (could be embedded or encrypted data)"


def classify_packed_regions(regions, sections):
    """Attach a PE section and a judgement to each (start, end) region.

    `sections` is the list from pe_analyzer; each item needs raw_offset,
    raw_size, name and permissions. If raw_offset is missing the regions
    are returned as 'unknown' instead of crashing.
    """
    can_map = bool(sections) and all("raw_offset" in s for s in sections)
    details = []

    for start, end in regions:
        item = {"start": start, "end": end, "size": end - start}

        if not can_map:
            item.update(section="unknown", judgement="unknown",
                        reason="section offsets not available")
            details.append(item)
            continue

        # the section that holds most of the region wins
        best, best_overlap = None, 0
        for sec in sections:
            sec_start = sec["raw_offset"]
            overlap = _overlap(start, end, sec_start, sec_start + sec["raw_size"])
            if overlap > best_overlap:
                best, best_overlap = sec, overlap

        if best is None:
            item.update(section="overlay", judgement="review",
                        reason="outside every section (appended data or a digital signature)")
        else:
            judgement, reason = _judge_section(best)
            item.update(section=best["name"], judgement=judgement, reason=reason)

        details.append(item)

    return details


def summarize_regions(details):
    """Count regions per judgement."""
    counts = {"benign": 0, "review": 0, "suspicious": 0, "unknown": 0}
    for item in details:
        counts[item["judgement"]] += 1
    return counts


def contextual_verdict(details):
    """One-line verdict that replaces the plain global-entropy verdict."""
    if not details:
        return "normal - no high-entropy regions"

    counts = summarize_regions(details)
    if counts["suspicious"]:
        return (f"suspicious - high entropy inside executable code "
                f"({counts['suspicious']} region(s))")
    if counts["unknown"]:
        return "inconclusive - section information not available"
    if counts["review"]:
        return (f"review - high-entropy data outside code "
                f"({counts['review']} region(s))")
    return "normal - high entropy only in resources/relocations"
