import re
import ipaddress
from urllib.parse import urlsplit

STRIP_CHARS = ".,;:!?()[]{}<>\"'"

IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"
)

GENERIC_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "mobi", "app", "dev", "io", "co", "ai", "me", "tv", "cc", "xyz",
    "top", "site", "online", "store", "tech", "cloud", "club", "live",
    "link", "click", "shop", "icu", "vip", "work", "tk", "ga", "cf", "gq",
}

COUNTRY_TLDS = {
    "my", "sg", "id", "th", "vn", "ph", "cn", "hk", "tw", "jp", "kr", "in",
    "pk", "bd", "uk", "us", "ca", "au", "nz", "de", "fr", "it", "es", "nl",
    "be", "ch", "at", "se", "no", "dk", "fi", "cz", "ru", "ua", "tr", "il",
    "ae", "sa", "eg", "za", "ng", "ke", "br", "ar", "mx", "cl", "ir",
}

VALID_TLDS = GENERIC_TLDS | COUNTRY_TLDS

TRUSTED_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
    "office.com", "office365.com", "microsoftonline.com", "msn.com",
    "bing.com", "azure.com", "windows.net", "msftncsi.com",
    "skype.com", "xbox.com", "outlook.com",
    "flipgrid.com",
    "w3.org", "xmlsoap.org", "openxmlformats.org",
    "digicert.com", "verisign.com", "globalsign.com", "sectigo.com",
    "comodoca.com", "symantec.com", "letsencrypt.org",
}

HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
HEX_DIGITS = set("0123456789abcdef")


def _looks_like_version(text, start):
    before = text[max(0, start - 15):start].lower()
    return "version" in before or before.endswith("v")


def extract_ips(strings):
    results = set()

    for text in strings:
        for match in IPV4_PATTERN.finditer(text):
            candidate = match.group()

            if _looks_like_version(text, match.start()):
                continue

            try:
                ip = ipaddress.IPv4Address(candidate)
            except ValueError:
                continue

            if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_reserved:
                continue

            if candidate.endswith(".0"):
                continue

            results.add(str(ip))

    return sorted(results)


def is_trusted_domain(domain):
    return any(domain == t or domain.endswith("." + t) for t in TRUSTED_DOMAINS)


def _is_trusted_url(url):
    host = urlsplit(url).hostname
    return host is not None and is_trusted_domain(host)


def _find_urls(strings):
    found = set()

    for text in strings:
        for word in text.split():
            word = word.strip(STRIP_CHARS)

            if not word.lower().startswith(("http://", "https://")):
                continue

            try:
                host = urlsplit(word).hostname
            except ValueError:
                continue

            if host:
                found.add(word)

    return found


def extract_urls(strings):
    return sorted(u for u in _find_urls(strings) if not _is_trusted_url(u))


def extract_trusted_urls(strings):
    return sorted(u for u in _find_urls(strings) if _is_trusted_url(u))


def _find_domains(strings):
    found = set()

    for text in strings:
        for match in DOMAIN_PATTERN.findall(text.lower()):
            labels = match.split(".")

            if labels[-1] not in VALID_TLDS or len(match) > 253:
                continue

            if not any(ch.isalpha() for ch in labels[-2]):
                continue

            found.add(match)

    return found


def extract_domains(strings):
    return sorted(d for d in _find_domains(strings) if not is_trusted_domain(d))


def extract_trusted_domains(strings):
    return sorted(d for d in _find_domains(strings) if is_trusted_domain(d))


def extract_hashes(strings):
    results = set()

    for text in strings:
        for word in text.split():
            word = word.strip(STRIP_CHARS).lower()
            name = HASH_LENGTHS.get(len(word))

            if name and set(word) <= HEX_DIGITS:
                results.add((name, word))

    return sorted(results)
