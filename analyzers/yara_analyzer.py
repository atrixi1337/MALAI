"""
YARA rule analyzer - matches files against YARA rules.
"""

from pathlib import Path

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

from config import YARA_RULES_DIR


class YaraAnalyzer:
    """Matches files against YARA rules for malware detection."""

    def __init__(self):
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        """Load all YARA rule files from the rules directory."""
        if not HAS_YARA:
            print("[!] yara-python not installed - YARA scanning disabled")
            self.rules = None
            return

        rule_files = list(YARA_RULES_DIR.glob("**/*.yar")) + list(
            YARA_RULES_DIR.glob("**/*.yara")
        )

        if not rule_files:
            print(f"[!] No YARA rules found in {YARA_RULES_DIR}")
            self.rules = None
            return

        try:
            self.rules = yara.compile(
                filepaths={str(f): str(f) for f in rule_files}
            )
            print(f"[+] Loaded {len(rule_files)} YARA rule file(s)")
        except yara.SyntaxError as e:
            print(f"[!] YARA rule syntax error: {e}")
            self.rules = None

    def analyze(self, file_path: Path) -> dict:
        """Match a file against all loaded YARA rules."""
        if not self.rules:
            return {
                "rules_loaded": False,
                "matches": [],
                "match_count": 0,
                "error": "No YARA rules loaded",
            }

        try:
            matches = self.rules.match(str(file_path), timeout=30)

            result = {
                "rules_loaded": True,
                "matches": [],
                "match_count": len(matches),
            }

            for match in matches:
                match_info = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": dict(match.meta) if match.meta else {},
                    "strings": [],
                }

                # Extract matched strings
                for string_id, offset, matched_data in match.strings:
                    match_info["strings"].append({
                        "id": string_id,
                        "offset": hex(offset),
                        "data": matched_data.hex() if isinstance(matched_data, bytes) else str(matched_data),
                    })

                result["matches"].append(match_info)

            return result

        except yara.TimeoutError:
            return {
                "rules_loaded": True,
                "matches": [],
                "match_count": 0,
                "error": "YARA scanning timed out",
            }
        except Exception as e:
            return {
                "rules_loaded": True,
                "matches": [],
                "match_count": 0,
                "error": str(e),
            }

    def get_rules_info(self) -> list:
        """Get information about loaded rules."""
        if not self.rules:
            return []

        rule_files = list(YARA_RULES_DIR.glob("**/*.yar")) + list(
            YARA_RULES_DIR.glob("**/*.yara")
        )
        return [{"file": str(f), "size": f.stat().st_size} for f in rule_files]
