"""
IOC (Indicator of Compromise) extractor - identifies IOCs in files.

Extraction favors precision over recall: matches are validated where a cheap,
reliable check exists (e.g. Bitcoin base58check for wallet addresses, hostname
shape for domains, non-degenerate hex for file hashes) so that random bytes in
a binary do not produce false-positive IOCs.
"""

import hashlib
import re
from pathlib import Path


# Bitcoin base58 alphabet (no 0, O, I, l)
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Curated TLD set used for domain matching (lowercase only - real malware
# domains are lower-case; this also rejects mixed-case garbage like "0R.Fr").
_TLDS = (
    "com|net|org|info|biz|xyz|top|club|online|site|pw|ru|cn|work|gov|edu|mil|"
    "int|io|co|me|tv|cc|de|fr|uk|us|ca|au|in|jp|br|nl|se|no|fi|dk|pl|cz|at|"
    "ch|be|es|it|pt|ie|nz|za|mx|ar|cl|pe|ve|pro|mobi|asia|cat|jobs|museum|"
    "coop|aero"
)


def _b58_decode(s: str):
    """Decode a base58 string to raw bytes, or None if invalid."""
    if not s or any(c not in _B58_ALPHABET for c in s):
        return None
    # Count leading '1's -> leading zero bytes
    zeros = 0
    for c in s:
        if c == "1":
            zeros += 1
        else:
            break
    value = 0
    for c in s:
        value = value * 58 + _B58_ALPHABET.index(c)
    out = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return b"\x00" * zeros + out


def _is_valid_btc_address(addr: str) -> bool:
    """True only for a base58check-valid legacy (1.../3...) or 0x... ETH-style address."""
    if addr.startswith("0x"):
        # Pattern already enforces exactly 40 hex chars; accept as-candidate.
        return True
    if addr[0] not in "13":
        return False
    raw = _b58_decode(addr)
    if raw is None or len(raw) != 25:
        return False
    payload, checksum = raw[:21], raw[21:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    return digest[:4] == checksum


def _not_degenerate(h: str) -> bool:
    """Reject hex runs made of a single repeated digit (e.g. 555.../666...)."""
    return len(set(h.lower())) > 1


class IOCExtractor:
    """Extracts Indicators of Compromise from files."""

    # Validators are optional callables; a match is kept only if it returns True.
    IOC_TYPES = {
        "ip_address": {
            "pattern": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            "exclude": {"0.0.0.0", "255.255.255.255", "127.0.0.1"},
        },
        "domain": {
            # Case-sensitive: labels must be lowercase, the first label must start
            # with a letter, and the TLD must be from the curated set. This rejects
            # mixed-case noise (0R.Fr, T0T0T0T0S.nO) and digit-leading labels.
            "pattern": re.compile(
                r"\b(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                r"(?:" + _TLDS + r")\b"
            ),
            "exclude": {"example.com", "localhost", "google.com"},
            "min_length": 4,
        },
        "url": {
            "pattern": re.compile(r"https?://[^\s\"'<>]{5,200}", re.IGNORECASE),
            "exclude": set(),
        },
        "email": {
            "pattern": re.compile(
                r"\b[a-zA-Z0-9._%+-]{3,}@[a-zA-Z0-9.-]{2,}\.[a-zA-Z]{2,}\b"
            ),
            "exclude": set(),
            "min_length": 7,
        },
        "file_hash_md5": {
            "pattern": re.compile(r"(?<![\w])[a-fA-F0-9]{32}(?![\w])"),
            "exclude": set(),
            "validate": _not_degenerate,
        },
        "file_hash_sha1": {
            "pattern": re.compile(r"(?<![\w])[a-fA-F0-9]{40}(?![\w])"),
            "exclude": set(),
            "validate": _not_degenerate,
        },
        "file_hash_sha256": {
            "pattern": re.compile(r"(?<![\w])[a-fA-F0-9]{64}(?![\w])"),
            "exclude": set(),
            "validate": _not_degenerate,
        },
        "registry_key": {
            "pattern": re.compile(
                r"(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)"
                r"\\[^\s\"']+)",
                re.IGNORECASE,
            ),
            "exclude": set(),
        },
        "file_path_windows": {
            "pattern": re.compile(
                r"[C-Z]:\\(?:Windows|Users|Program\s*Files|Program\s*Files\s*\(x86\)|"
                r"Temp|AppData|System32|SysWOW64|tmp|usr|etc|var|home)\\[^\\/:*?\"<>|\r\n]{2,}"
            ),
            "exclude": set(),
            "min_length": 10,
        },
        "crypto_wallet": {
            # Legacy/base58 (1.../3...) or 0x... ETH-style; validated by base58check.
            "pattern": re.compile(
                r"(?<![\w])(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})(?![\w])"
            ),
            "exclude": set(),
            "validate": _is_valid_btc_address,
        },
        "mutex": {
            "pattern": re.compile(r"(?:Global|Local)\\\\[^\s\"'<>]+"),
            "exclude": set(),
        },
        "pipe_name": {
            "pattern": re.compile(r"\\\\\.\\pipe\\[^\s\"'<>]+"),
            "exclude": set(),
        },
    }

    def extract(self, file_path: Path) -> dict:
        """Extract all IOCs from a file."""
        data = file_path.read_bytes()

        # Try to decode as text
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = data.decode("latin-1", errors="ignore")

        result = {}

        for ioc_type, config in self.IOC_TYPES.items():
            matches = set()
            min_len = config.get("min_length", 0)
            validator = config.get("validate")
            for m in config["pattern"].finditer(text):
                value = m.group()
                if value in config["exclude"] or len(value) < min_len:
                    continue
                if validator is not None and not validator(value):
                    continue
                matches.add(value)

            result[ioc_type] = sorted(matches)

        # Summary
        result["summary"] = {
            "total_iocs": sum(len(v) for k, v in result.items() if k != "summary"),
            "by_type": {k: len(v) for k, v in result.items() if k != "summary" and v},
        }

        return result
