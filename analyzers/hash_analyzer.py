"""
Hash analyzer - computes multiple hash types and fuzzy hashes.
"""

import hashlib
from pathlib import Path

try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False


class HashAnalyzer:
    """Computes various hash types for file identification."""

    def analyze(self, file_path: Path) -> dict:
        """Compute all hash types for a file."""
        data = file_path.read_bytes()

        result = {
            "md5": self._md5(data),
            "sha1": self._sha1(data),
            "sha256": self._sha256(data),
            "sha512": self._sha512(data),
            "ssdeep": self._ssdeep(data),
            "tlsh": self._tlsh(data),
        }

        return result

    def _md5(self, data: bytes) -> str:
        """Compute MD5 hash."""
        return hashlib.md5(data).hexdigest()

    def _sha1(self, data: bytes) -> str:
        """Compute SHA-1 hash."""
        return hashlib.sha1(data).hexdigest()

    def _sha256(self, data: bytes) -> str:
        """Compute SHA-256 hash."""
        return hashlib.sha256(data).hexdigest()

    def _sha512(self, data: bytes) -> str:
        """Compute SHA-512 hash."""
        return hashlib.sha512(data).hexdigest()

    def _ssdeep(self, data: bytes) -> str:
        """Compute ssdeep fuzzy hash."""
        if not HAS_SSDEEP:
            return "N/A (ssdeep not installed)"
        try:
            return ssdeep.hash(data)
        except Exception:
            return "N/A (ssdeep error)"

    def _tlsh(self, data: bytes) -> str:
        """Compute TLSH hash (if available)."""
        try:
            import tlsh as tlsh_mod
            tlsh = tlsh_mod.Tlsh()
            tlsh.update(data)
            return tlsh.hexdigest()
        except ImportError:
            return "N/A (tlsh not installed)"
        except Exception:
            return "N/A (tlsh error)"
