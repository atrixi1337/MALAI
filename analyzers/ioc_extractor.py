"""
IOC (Indicator of Compromise) extractor - identifies IOCs in files.
"""

import re
from pathlib import Path


class IOCExtractor:
    """Extracts Indicators of Compromise from files."""

    IOC_TYPES = {
        "ip_address": {
            "pattern": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            "exclude": {"0.0.0.0", "255.255.255.255", "127.0.0.1", "0.0.0.0"},
        },
        "domain": {
            "pattern": re.compile(
                r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
                r"+(?:com|net|org|info|biz|xyz|top|club|online|site|pw|cc|ru|cn|tk|ga|cf|gq|ml|work)\b",
                re.IGNORECASE,
            ),
            "exclude": {"example.com", "localhost", "google.com"},
        },
        "url": {
            "pattern": re.compile(
                r"https?://[^\s\"'<>]{5,200}", re.IGNORECASE
            ),
            "exclude": set(),
        },
        "email": {
            "pattern": re.compile(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
            ),
            "exclude": set(),
        },
        "file_hash_md5": {
            "pattern": re.compile(r"\b[a-fA-F0-9]{32}\b"),
            "exclude": set(),
        },
        "file_hash_sha1": {
            "pattern": re.compile(r"\b[a-fA-F0-9]{40}\b"),
            "exclude": set(),
        },
        "file_hash_sha256": {
            "pattern": re.compile(r"\b[a-fA-F0-9]{64}\b"),
            "exclude": set(),
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
                r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+"
            ),
            "exclude": set(),
        },
        "crypto_wallet": {
            "pattern": re.compile(
                r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}"
            ),
            "exclude": set(),
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
            for m in config["pattern"].finditer(text):
                value = m.group()
                if value not in config["exclude"]:
                    matches.add(value)

            result[ioc_type] = sorted(matches)

        # Summary
        result["summary"] = {
            "total_iocs": sum(len(v) for k, v in result.items() if k != "summary"),
            "by_type": {k: len(v) for k, v in result.items() if k != "summary" and v},
        }

        return result
