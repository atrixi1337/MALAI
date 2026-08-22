"""
String analyzer - extracts and categorizes strings from binary files.
"""

import re
from collections import Counter
from pathlib import Path


class StringAnalyzer:
    """Extracts and categorizes interesting strings from files."""

    # Minimum string length to consider
    MIN_STRING_LENGTH = 4

    # Suspicious API functions (Windows)
    SUSPICIOUS_APIS = {
        # Process manipulation
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "NtUnmapViewOfSection",
        "QueueUserAPC",
        "SetThreadContext",
        # Registry
        "RegCreateKeyEx",
        "RegSetValueEx",
        "RegDeleteKey",
        # Network
        "InternetOpen",
        "InternetConnect",
        "HttpSendRequest",
        "URLDownloadToFile",
        "WinHttpOpen",
        "WSAStartup",
        # Crypto
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptCreateHash",
        # File operations
        "CreateFile",
        "DeleteFile",
        "CopyFile",
        "MoveFile",
        # Process
        "CreateProcess",
        "OpenProcess",
        "TerminateProcess",
        "ShellExecute",
        "WinExec",
        # DLL
        "LoadLibrary",
        "GetProcAddress",
        "DllRegisterServer",
        # Anti-debug
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        # Privilege
        "AdjustTokenPrivileges",
        "OpenProcessToken",
    }

    # Suspicious string patterns
    SUSPICIOUS_PATTERNS = {
        "powershell": re.compile(r"powershell[\s\S]{0,100}(-enc|-e\s|bypass|hidden|download|invoke)", re.IGNORECASE),
        "cmd_injection": re.compile(r"cmd\.exe\s*/[cCkK]\s+", re.IGNORECASE),
        "registry_run": re.compile(r"\\\\(CurrentVersion\\\\Run|Microsoft\\\\Windows\\\\CurrentVersion\\\\Run)", re.IGNORECASE),
        "schtasks": re.compile(r"schtasks\s*/(create|run)", re.IGNORECASE),
        "net_user": re.compile(r"net\s+(user|localgroup|group)\s+", re.IGNORECASE),
        "wmic": re.compile(r"wmic\s+", re.IGNORECASE),
        "certutil": re.compile(r"certutil\s+.*(-urlcache|-split|-f)", re.IGNORECASE),
        "bitsadmin": re.compile(r"bitsadmin\s+/", re.IGNORECASE),
        "base64_long": re.compile(r"[A-Za-z0-9+/]{100,}={0,2}"),
        "ip_address": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "url": re.compile(r"https?://[^\s\"'<>]{5,}"),
        "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "file_path_win": re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"),
        "file_path_unix": re.compile(r"/(?:[^/\0]+/)*[^/\0]+"),
        "crypto_wallet": re.compile(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}"),
        "mutex_name": re.compile(r"Global\\\\[^\s]+|Local\\\\[^\s]+"),
    }

    # Known malware mutex prefixes
    KNOWN_MUTEXES = [
        "SDXGCCoreComponent",
        "jkhdf7hsusdf",
        "hsifhw932hf",
        "OleMainWndClass",
        "AVIRA_",
    ]

    def analyze(self, file_path: Path) -> dict:
        """Extract and categorize strings from a file."""
        data = file_path.read_bytes()

        # Extract ASCII and Unicode strings
        ascii_strings = self._extract_strings(data, encoding="ascii")
        unicode_strings = self._extract_strings(data, encoding="utf-16-le")
        all_strings = ascii_strings + unicode_strings

        # Deduplicate
        unique_strings = list(set(all_strings))

        result = {
            "total_strings": len(unique_strings),
            "ascii_count": len(set(ascii_strings)),
            "unicode_count": len(set(unicode_strings)),
            "suspicious_strings": self._find_suspicious_strings(unique_strings),
            "urls": self._extract_by_pattern(unique_strings, "url"),
            "ips": self._extract_by_pattern(unique_strings, "ip_address"),
            "emails": self._extract_by_pattern(unique_strings, "email"),
            "file_paths": self._extract_file_paths(unique_strings),
            "powershell_commands": self._extract_by_pattern(unique_strings, "powershell"),
            "crypto_wallets": self._extract_by_pattern(unique_strings, "crypto_wallet"),
            "base64_strings": self._extract_by_pattern(unique_strings, "base64_long"),
            "registry_refs": self._extract_by_pattern(unique_strings, "registry_run"),
            "top_strings": self._get_top_strings(unique_strings),
        }

        return result

    def _extract_strings(self, data: bytes, encoding: str = "ascii") -> list:
        """Extract printable strings from binary data."""
        strings = []
        current = []

        if encoding == "utf-16-le":
            # Process pairs of bytes
            for i in range(0, len(data) - 1, 2):
                char_code = data[i] | (data[i + 1] << 8)
                if 32 <= char_code <= 126 or char_code in (9, 10, 13):
                    current.append(chr(char_code))
                else:
                    if len(current) >= self.MIN_STRING_LENGTH:
                        strings.append("".join(current))
                    current = []
        else:
            for byte in data:
                if 32 <= byte <= 126 or byte in (9, 10, 13):
                    current.append(chr(byte))
                else:
                    if len(current) >= self.MIN_STRING_LENGTH:
                        strings.append("".join(current))
                    current = []

        if len(current) >= self.MIN_STRING_LENGTH:
            strings.append("".join(current))

        return strings

    def _find_suspicious_strings(self, strings: list) -> list:
        """Find strings matching suspicious patterns or known APIs."""
        suspicious = []

        for s in strings:
            # Check against known suspicious APIs
            for api in self.SUSPICIOUS_APIS:
                if api.lower() in s.lower():
                    suspicious.append({
                        "string": s[:200],
                        "reason": f"Suspicious API call: {api}",
                        "severity": "HIGH",
                    })
                    break

            # Check against suspicious patterns
            for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
                if pattern.search(s):
                    suspicious.append({
                        "string": s[:200],
                        "reason": f"Suspicious pattern: {pattern_name}",
                        "severity": "MEDIUM",
                    })
                    break

        return suspicious

    def _extract_by_pattern(self, strings: list, pattern_name: str) -> list:
        """Extract strings matching a specific pattern."""
        pattern = self.SUSPICIOUS_PATTERNS.get(pattern_name)
        if not pattern:
            return []

        matches = []
        seen = set()
        for s in strings:
            m = pattern.search(s)
            if m and m.group() not in seen:
                matches.append(m.group())
                seen.add(m.group())

        return matches[:50]  # Limit to prevent huge output

    def _extract_file_paths(self, strings: list) -> list:
        """Extract file paths from strings."""
        paths = []
        seen = set()

        for s in strings:
            # Windows paths
            for m in re.finditer(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*", s):
                path = m.group()
                if path not in seen and len(path) > 5:
                    paths.append(path)
                    seen.add(path)

            # Unix paths
            for m in re.finditer(r"/(?:[^/\0]+/)*[^/\0]+", s):
                path = m.group()
                if path not in seen and len(path) > 5 and not path.startswith("//"):
                    paths.append(path)
                    seen.add(path)

        return paths[:50]

    def _get_top_strings(self, strings: list) -> list:
        """Get the most common strings."""
        counter = Counter(strings)
        return [{"string": s, "count": c} for s, c in counter.most_common(20)]
