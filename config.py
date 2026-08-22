import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads"))
YARA_RULES_DIR = Path(os.getenv("YARA_RULES_DIR", "./rules"))
SAMPLES_DIR = BASE_DIR / "samples"

# Ensure directories exist
UPLOAD_DIR.mkdir(exist_ok=True)
YARA_RULES_DIR.mkdir(exist_ok=True)

# AI Configuration (OrcaRouter - OpenAI-compatible)
ORCAROUTER_API_KEY = os.getenv("ORCAROUTER_API_KEY", "")
ORCAROUTER_BASE_URL = os.getenv("ORCAROUTER_BASE_URL", "https://api.orcarouter.ai/v1")
ORCAROUTER_MODEL = os.getenv("ORCAROUTER_MODEL", "qwen/qwen3.8-27b-free")

# VirusTotal configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_BASE_URL = os.getenv("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3")
# If True, upload the sample to VT when no report exists for its hash (requires a
# VT tier that permits file uploads; otherwise the lookup is hash-only).
VIRUSTOTAL_UPLOAD_IF_ABSENT = os.getenv("VIRUSTOTAL_UPLOAD_IF_ABSENT", "true").lower() in (
    "1", "true", "yes", "on",
)

# Analysis limits
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "50"))
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# Risk scoring weights
RISK_WEIGHTS = {
    "entropy": 0.2,
    "yara_matches": 0.3,
    "suspicious_strings": 0.15,
    "file_anomalies": 0.15,
    "ai_confidence": 0.2,
}
