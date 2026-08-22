"""
Static file analyzer - extracts metadata, PE info, entropy, and file anomalies.
"""

import math
import struct
from pathlib import Path
from datetime import datetime


class StaticAnalyzer:
    """Performs static analysis on suspicious files."""

    # Known PE magic numbers
    PE_MAGIC = b"MZ"
    ELF_MAGIC = b"\x7fELF"

    # High entropy threshold (encrypted/packed content)
    HIGH_ENTROPY_THRESHOLD = 7.0
    # Very high entropy (almost certainly encrypted)
    VERY_HIGH_ENTROPY_THRESHOLD = 7.5

    def analyze(self, file_path: Path) -> dict:
        """Run full static analysis on a file."""
        data = file_path.read_bytes()
        result = {
            "file_size": len(data),
            "file_size_human": self._human_size(len(data)),
            "file_type": self._detect_file_type(data, file_path),
            "entropy": self._calculate_entropy(data),
            "entropy_assessment": "",
            "md5": "",
            "sha1": "",
            "sha256": "",
            "ssdeep": "",
            "pe_info": None,
            "anomalies": [],
            "magic_bytes": data[:16].hex() if len(data) >= 16 else data.hex(),
        }

        # Entropy assessment
        e = result["entropy"]
        if e >= self.VERY_HIGH_ENTROPY_THRESHOLD:
            result["entropy_assessment"] = "CRITICAL - Almost certainly encrypted or packed"
        elif e >= self.HIGH_ENTROPY_THRESHOLD:
            result["entropy_assessment"] = "WARNING - High entropy, possibly packed/encrypted"
        elif e >= 6.0:
            result["entropy_assessment"] = "SUSPICIOUS - Above average entropy"
        elif e < 1.0:
            result["entropy_assessment"] = "INFO - Very low entropy, possibly empty/padding"
        else:
            result["entropy_assessment"] = "NORMAL - Typical entropy for executable"

        # PE analysis
        if data[:2] == self.PE_MAGIC:
            result["pe_info"] = self._analyze_pe(data)
            result["file_type"] = "PE Executable"
            result["anomalies"].extend(self._check_pe_anomalies(result["pe_info"]))

        # ELF analysis
        elif data[:4] == self.ELF_MAGIC:
            result["file_type"] = "ELF Binary"
            result["anomalies"].extend(self._check_elf_anomalies(data))

        # Check for common anomalies
        result["anomalies"].extend(self._check_general_anomalies(data, file_path))

        return result

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    def _detect_file_type(self, data: bytes, file_path: Path) -> str:
        """Detect file type from magic bytes."""
        if len(data) < 4:
            return "Unknown (too small)"

        signatures = {
            b"\x89PNG": "PNG Image",
            b"\xff\xd8\xff": "JPEG Image",
            b"GIF8": "GIF Image",
            b"%PDF": "PDF Document",
            b"PK\x03\x04": "ZIP Archive",
            b"Rar!": "RAR Archive",
            b"\x1f\x8b": "GZIP Archive",
            b"BZ": "BZIP2 Archive",
            b"MZ": "PE Executable",
            b"\x7fELF": "ELF Binary",
            b"\xfe\xed\xfa\xce": "Mach-O Binary (32-bit)",
            b"\xfe\xed\xfa\xcf": "Mach-O Binary (64-bit)",
            b"\xca\xfe\xba\xbe": "Mach-O Universal Binary",
            b"7z\xbc\xaf\x27\x1c": "7-Zip Archive",
            b"\xd0\xcf\x11\xe0": "OLE Document (Office)",
            b"SQLite format 3": "SQLite Database",
            b"RIFF": "RIFF Container (AVI/WAV)",
            b"\x00\x00\x01\x00": "ICO Image",
            b"ID3": "MP3 Audio",
            b"\x4f\x67\x67\x53": "OGG Audio",
            b"fLaC": "FLAC Audio",
            b"\x00\x00\x00\x18ftyp": "MP4 Video",
        }

        for sig, name in signatures.items():
            if data[: len(sig)] == sig:
                return name

        # Check for script interpreters
        first_line = data.split(b"\n")[0][:100].decode("utf-8", errors="ignore")
        if first_line.startswith("#!"):
            interpreter = first_line[2:].strip()
            return f"Script ({interpreter})"

        if first_line.startswith("<?xml"):
            return "XML Document"

        return "Unknown"

    def _analyze_pe(self, data: bytes) -> dict:
        """Analyze PE header structure."""
        try:
            offset = struct.unpack_from("<I", data, 0x3C)[0]
            if offset + 4 > len(data):
                return {"error": "Invalid PE header offset"}

            signature = struct.unpack_from("<I", data, offset)[0]
            if signature != 0x00004550:  # "PE\0\0"
                return {"error": "Invalid PE signature"}

            machine = struct.unpack_from("<H", data, offset + 4)[0]
            num_sections = struct.unpack_from("<H", data, offset + 6)[0]
            timestamp = struct.unpack_from("<I", data, offset + 8)[0]
            characteristics = struct.unpack_from("<H", data, offset + 22)[0]

            # Optional header
            opt_offset = offset + 24
            magic = struct.unpack_from("<H", data, opt_offset)[0]
            is_64 = magic == 0x20b

            machine_types = {
                0x0: "Unknown",
                0x14C: "x86 (32-bit)",
                0x8664: "x86-64 (64-bit)",
                0xAA64: "ARM64",
                0x1C0: "ARM",
                0x200: "IA-64",
            }

            # Convert timestamp
            try:
                ts_str = datetime.fromtimestamp(timestamp).isoformat()
            except (ValueError, OSError):
                ts_str = f"Invalid ({timestamp})"

            return {
                "architecture": "64-bit" if is_64 else "32-bit",
                "machine": machine_types.get(machine, f"Unknown (0x{machine:04x})"),
                "num_sections": num_sections,
                "timestamp": ts_str,
                "timestamp_raw": timestamp,
                "characteristics": hex(characteristics),
                "is_dll": bool(characteristics & 0x2000),
                "is_executable": bool(characteristics & 0x0002),
                "has_debug": bool(characteristics & 0x0020),
                "has_relocations": bool(characteristics & 0x0040),
                "stripped": bool(characteristics & 0x0100),
            }

        except (struct.error, IndexError) as e:
            return {"error": f"Failed to parse PE: {str(e)}"}

    def _check_pe_anomalies(self, pe_info: dict) -> list:
        """Check for suspicious PE characteristics."""
        anomalies = []
        if pe_info.get("error"):
            return [f"PE Parse Error: {pe_info['error']}"]

        ts = pe_info.get("timestamp_raw", 0)
        # Timestamps from 1970-1990 or way in the future are suspicious
        if ts > 0 and (ts < 31536000 or ts > 4102444800):
            anomalies.append("Suspicious PE timestamp (forged or corrupted)")

        if pe_info.get("stripped"):
            anomalies.append("PE is stripped (debug symbols removed)")

        if not pe_info.get("has_relocations") and pe_info.get("is_executable"):
            anomalies.append("No relocations in executable (possible packed)")

        if pe_info.get("num_sections", 0) > 20:
            anomalies.append(f"Unusually high number of sections ({pe_info['num_sections']})")

        if pe_info.get("num_sections", 0) == 0:
            anomalies.append("No sections found (unusual)")

        return anomalies

    def _check_elf_anomalies(self, data: bytes) -> list:
        """Check for ELF anomalies."""
        anomalies = []
        if len(data) < 20:
            return anomalies

        ei_class = data[4]  # 1=32-bit, 2=64-bit
        ei_data = data[5]    # 1=LE, 2=BE

        if ei_class not in (1, 2):
            anomalies.append(f"Invalid ELF class: {ei_class}")

        if ei_data not in (1, 2):
            anomalies.append(f"Invalid ELF data encoding: {ei_data}")

        return anomalies

    def _check_general_anomalies(self, data: bytes, file_path: Path) -> list:
        """Check for general file anomalies."""
        anomalies = []
        ext = file_path.suffix.lower()

        # File extension vs content mismatch
        if ext in (".exe", ".dll", ".sys") and not data[:2] == self.PE_MAGIC:
            anomalies.append(f"File has {ext} extension but is not a PE executable")
        elif ext == ".pdf" and not data[:4] == b"%PDF":
            anomalies.append("File has .pdf extension but is not a valid PDF")
        elif ext == ".png" and not data[:4] == b"\x89PNG":
            anomalies.append("File has .png extension but is not a valid PNG")

        # Double extension (common social engineering)
        name = file_path.stem
        if name.count(".") >= 1:
            extensions = name.split(".")
            suspicious_exts = {"exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "scr", "com", "pif"}
            if any(e.lower() in suspicious_exts for e in extensions[1:]):
                anomalies.append(f"Double extension detected: {file_path.name} (social engineering?)")

        # Empty file
        if len(data) == 0:
            anomalies.append("File is empty (0 bytes)")

        # Very small file with executable extension
        if len(data) < 100 and ext in (".exe", ".dll", ".sys", ".scr"):
            anomalies.append(f"Very small file ({len(data)} bytes) with executable extension")

        return anomalies

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """Convert bytes to human-readable size."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
