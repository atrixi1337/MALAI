"""
Analysis Engine - orchestrates all analyzers and AI for comprehensive malware analysis.
"""

import time
from pathlib import Path
from datetime import datetime

from analyzers import (
    StaticAnalyzer,
    StringAnalyzer,
    HashAnalyzer,
    YaraAnalyzer,
    IOCExtractor,
    VirusTotalClient,
)
from agents.ai_engine import AIEngine
from config import RISK_WEIGHTS


class AnalysisEngine:
    """Main orchestrator for malware analysis."""

    def __init__(self):
        self.static_analyzer = StaticAnalyzer()
        self.string_analyzer = StringAnalyzer()
        self.hash_analyzer = HashAnalyzer()
        self.yara_analyzer = YaraAnalyzer()
        self.ioc_extractor = IOCExtractor()
        self.vt_client = VirusTotalClient()
        self.ai_engine = AIEngine()

    async def _enrich_vt(self, file_path: Path, result: dict) -> dict:
        """Run VirusTotal enrichment: file report (+ upload) and IOC lookups."""
        vt: dict = await self.vt_client.enrich_file(file_path, result.get("hashes", {}))
        iocs = result.get("iocs", {})
        if iocs:
            vt_iocs = await self.vt_client.enrich_iocs(iocs)
            vt["domain"] = vt_iocs.get("domain", {})
            vt["ip_address"] = vt_iocs.get("ip_address", {})
            vt["url"] = vt_iocs.get("url", {})
            vt["ioc_enabled"] = vt_iocs.get("enabled", False)
        return vt

    async def analyze_file(self, file_path: Path, file_name: str = None) -> dict:
        """Perform full analysis on a file."""
        start_time = time.time()

        if file_name is None:
            file_name = file_path.name

        result = {
            "file_name": file_name,
            "analysis_id": f"{int(time.time())}_{hash(file_name) & 0xFFFF:04x}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status": "analyzing",
        }

        try:
            # Phase 1: Hash computation
            result["hashes"] = self.hash_analyzer.analyze(file_path)

            # Phase 2: Static analysis
            result["static"] = self.static_analyzer.analyze(file_path)

            # Phase 3: String analysis
            result["strings"] = self.string_analyzer.analyze(file_path)

            # Phase 4: YARA matching
            result["yara"] = self.yara_analyzer.analyze(file_path)

            # Phase 5: IOC extraction
            result["iocs"] = self.ioc_extractor.extract(file_path)

            # Phase 5b: VirusTotal enrichment (file by hash + upload-if-absent,
            # plus domain/ip/url IOCs). Degrades gracefully if no key/quota.
            try:
                result["vt"] = await self._enrich_vt(file_path, result)
            except Exception as e:
                result["vt"] = {"enabled": self.vt_client.enabled, "status": "error", "error": str(e)}

            # Phase 5c: AI adjudication of IOCs (true vs false positive),
            # grounded in the VT enrichment above.
            try:
                result["ioc_assessment"] = await self.ai_engine.assess_iocs(
                    result["iocs"], result.get("vt", {})
                )
            except Exception as e:
                result["ioc_assessment"] = {
                    "available": False,
                    "error": str(e),
                    "assessment": {},
                }

            # Phase 6: Risk scoring
            result["risk_score"] = self._calculate_risk_score(result)
            result["risk_level"] = self._score_to_level(result["risk_score"])

            # Phase 7: AI analysis
            try:
                result["ai_analysis"] = await self.ai_engine.analyze(result)
            except Exception as e:
                result["ai_analysis"] = {
                    "ai_available": False,
                    "error": str(e),
                    "analysis": "AI analysis unavailable.",
                }

            result["status"] = "complete"
            result["analysis_time_seconds"] = round(time.time() - start_time, 2)

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            result["analysis_time_seconds"] = round(time.time() - start_time, 2)

        return result

    def _calculate_risk_score(self, results: dict) -> float:
        """Calculate a risk score from 0-100 based on analysis results."""
        score = 0.0

        # Entropy scoring
        entropy = results.get("static", {}).get("entropy", 0)
        if entropy >= 7.5:
            score += 100 * RISK_WEIGHTS["entropy"]
        elif entropy >= 7.0:
            score += 80 * RISK_WEIGHTS["entropy"]
        elif entropy >= 6.0:
            score += 50 * RISK_WEIGHTS["entropy"]
        elif entropy >= 4.0:
            score += 20 * RISK_WEIGHTS["entropy"]
        else:
            score += 5 * RISK_WEIGHTS["entropy"]

        # YARA scoring
        yara_count = results.get("yara", {}).get("match_count", 0)
        if yara_count >= 5:
            score += 100 * RISK_WEIGHTS["yara_matches"]
        elif yara_count >= 3:
            score += 80 * RISK_WEIGHTS["yara_matches"]
        elif yara_count >= 1:
            score += 60 * RISK_WEIGHTS["yara_matches"]
        else:
            score += 10 * RISK_WEIGHTS["yara_matches"]

        # Suspicious strings scoring
        suspicious_count = len(results.get("strings", {}).get("suspicious_strings", []))
        if suspicious_count >= 10:
            score += 100 * RISK_WEIGHTS["suspicious_strings"]
        elif suspicious_count >= 5:
            score += 70 * RISK_WEIGHTS["suspicious_strings"]
        elif suspicious_count >= 1:
            score += 40 * RISK_WEIGHTS["suspicious_strings"]
        else:
            score += 5 * RISK_WEIGHTS["suspicious_strings"]

        # Anomaly scoring
        anomaly_count = len(results.get("static", {}).get("anomalies", []))
        if anomaly_count >= 5:
            score += 100 * RISK_WEIGHTS["file_anomalies"]
        elif anomaly_count >= 3:
            score += 70 * RISK_WEIGHTS["file_anomalies"]
        elif anomaly_count >= 1:
            score += 40 * RISK_WEIGHTS["file_anomalies"]
        else:
            score += 5 * RISK_WEIGHTS["file_anomalies"]

        # AI confidence scoring
        ai_risk = results.get("ai_analysis", {}).get("risk_level", "").upper()
        if ai_risk == "CRITICAL":
            score += 100 * RISK_WEIGHTS["ai_confidence"]
        elif ai_risk == "HIGH":
            score += 80 * RISK_WEIGHTS["ai_confidence"]
        elif ai_risk == "MEDIUM":
            score += 50 * RISK_WEIGHTS["ai_confidence"]
        elif ai_risk == "LOW":
            score += 20 * RISK_WEIGHTS["ai_confidence"]
        else:
            score += 30 * RISK_WEIGHTS["ai_confidence"]

        return round(min(score, 100), 1)

    @staticmethod
    def _score_to_level(score: float) -> str:
        """Convert numeric score to risk level."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "INFO"
