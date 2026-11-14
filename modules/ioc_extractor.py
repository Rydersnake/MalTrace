import re
import ipaddress
from urllib.parse import urlsplit

def extract_ips(strings):
    results = set()

    for text in strings:
        words = text.split()

        for word in words:
            word = word.strip(".,;:!?()[]{}")

            try:
                ipaddress.ip_address(word)
                results.add(word)

            except ValueError:
                pass

    return sorted(results)

def extract_urls(strings):
    results = set()

    for text in strings:
        words = text.split()

        for word in words:
            word = word.strip(".,;:!?()[]{}")

            if word.startswith("http://") or word.startswith("https://"):
                url = urlsplit(word)

                if url.hostname:
                    results.add(word)

    return sorted(results)   

def extract_domains(strings):
    results = set()

    for text in strings:
        words = text.split()

        for word in words:
            word = word.strip(".,;:!?()[]{}")

            if "." in word and "://" not in word:
                if " " not in word:
                    results.add(word)

    return sorted(results)

def extract_hashes(strings):
    results = set()

    for text in strings:
        words = text.split()

        for word in words:
            word = word.strip(".,;:!?()[]{}")
            word = word.lower()

            if len(word) == 32:
                if all(char in "0123456789abcdef" for char in word):
                    results.add(("MD5", word))

            elif len(word) == 40:
                if all(char in "0123456789abcdef" for char in word):
                    results.add(("SHA-1", word))

            elif len(word) == 64:
                if all(char in "0123456789abcdef" for char in word):
                    results.add(("SHA-256", word))

    return sorted(results)
