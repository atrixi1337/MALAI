"""
AI Engine - uses OrcaRouter (OpenAI-compatible) for malware analysis and classification.
"""

import json
import re
from openai import AsyncOpenAI

from config import ORCAROUTER_API_KEY, ORCAROUTER_BASE_URL, ORCAROUTER_MODEL


class AIEngine:
    """AI-powered malware analysis via OrcaRouter."""

    def __init__(self):
        self.client = AsyncOpenAI(
            api_key=ORCAROUTER_API_KEY,
            base_url=ORCAROUTER_BASE_URL,
        )
        self.model = ORCAROUTER_MODEL

    SYSTEM_PROMPT = """You are an expert malware analyst and digital forensics specialist.
You analyze file analysis results and provide detailed, accurate assessments.

Your analysis should include:
1. **Malware Classification**: Identify the likely malware family/type based on indicators
2. **Risk Assessment**: Rate the threat level (Critical/High/Medium/Low/Informational)
3. **Key Findings**: Highlight the most important indicators and behaviors
4. **Attack Vector**: How this malware likely spreads or is delivered
5. **Impact Assessment**: What damage this malware could cause
6. **Remediation Steps**: How to remove and prevent this threat
7. **Confidence Level**: How confident you are in your assessment (High/Medium/Low)

Be precise and evidence-based. Reference specific IOCs and indicators in your analysis.
Format your response in clean markdown."""

    async def analyze(self, analysis_results: dict) -> dict:
        """Generate AI analysis from collected results."""
        prompt = self._build_analysis_prompt(analysis_results)

        try:
            response = await self._query(prompt)
            return self._parse_response(response)

        except Exception as e:
            return {
                "ai_available": False,
                "error": str(e),
                "analysis": "AI analysis unavailable. Review the raw analysis data above.",
                "classification": "Unknown",
                "risk_level": "Unknown",
                "confidence": "Low",
            }

    async def assess_iocs(self, iocs: dict, vt: dict) -> dict:
        """Ask the LLM to adjudicate each extracted IOC as true-positive vs noise.

        Returns a dict: {type: {value: {verdict, reason}}} plus 'summary'.
        Verdicts: TRUE_SUSPICIOUS | BENIGN | UNVERIFIED. The LLM is grounded in
        the VirusTotal enrichment when available so it does not hallucinate.
        """
        if not self.client:
            return {"available": False, "error": "no_client", "assessment": {}}

        prompt = self._build_ioc_assessment_prompt(iocs, vt)
        try:
            response = await self._query_json(prompt)
            parsed = self._parse_ioc_assessment(response, iocs)
            return {"available": True, **parsed}
        except Exception as e:  # noqa: BLE001
            return {
                "available": True,
                "error": str(e),
                "assessment": {},
                "raw": str(e),
            }

    async def generate_report(self, analysis_results: dict, ai_analysis: dict) -> str:
        """Generate a comprehensive forensic report."""
        prompt = self._build_report_prompt(analysis_results, ai_analysis)

        try:
            return await self._query(prompt)
        except Exception as e:
            return f"# Forensic Report\n\nAI report generation failed: {e}\n\nPlease review raw analysis data."

    def _build_analysis_prompt(self, results: dict) -> str:
        """Build a prompt for AI analysis."""
        # Summarize results for the AI
        summary = {
            "file_info": {
                "name": results.get("file_name", "unknown"),
                "size": results.get("static", {}).get("file_size_human", "unknown"),
                "type": results.get("static", {}).get("file_type", "unknown"),
            },
            "hashes": results.get("hashes", {}),
            "static_analysis": {
                "entropy": results.get("static", {}).get("entropy", 0),
                "entropy_assessment": results.get("static", {}).get("entropy_assessment", ""),
                "pe_info": results.get("static", {}).get("pe_info"),
                "anomalies": results.get("static", {}).get("anomalies", []),
            },
            "yara_matches": results.get("yara", {}).get("match_count", 0),
            "yara_rules": [
                {"rule": m["rule"], "tags": m.get("tags", [])}
                for m in results.get("yara", {}).get("matches", [])
            ],
            "suspicious_strings": len(results.get("strings", {}).get("suspicious_strings", [])),
            "urls_found": results.get("strings", {}).get("urls", [])[:10],
            "ips_found": results.get("strings", {}).get("ips", [])[:10],
            "powershell_commands": results.get("strings", {}).get("powershell_commands", []),
            "ioc_summary": results.get("iocs", {}).get("summary", {}),
            "risk_score": results.get("risk_score", "N/A"),
        }

        return f"""Analyze the following file analysis results and provide a comprehensive malware assessment:

```json
{json.dumps(summary, indent=2, default=str)}
```

Provide your analysis in the following format:
1. **Classification**: [Malware family/type]
2. **Risk Level**: [Critical/High/Medium/Low/Informational]
3. **Summary**: [Brief description]
4. **Key Indicators**: [Most important IOCs]
5. **Attack Vector**: [How it spreads]
6. **Impact**: [What it can do]
7. **Remediation**: [How to handle it]
8. **Confidence**: [High/Medium/Low]"""

    def _build_report_prompt(self, results: dict, ai_analysis: dict) -> str:
        """Build a prompt for report generation."""
        vt = results.get("vt")
        ioc_assessment = results.get("ioc_assessment", {})

        vt_section = ""
        if isinstance(vt, dict) and vt.get("enabled"):
            vt_section = (
                f"\nVirusTotal:\n{json.dumps(self._vt_brief(vt), indent=2, default=str)}"
            )

        ioc_section = ""
        if isinstance(ioc_assessment, dict) and ioc_assessment.get("assessment"):
            ioc_section = (
                f"\nAI IOC Adjudication:\n"
                f"{json.dumps(ioc_assessment.get('assessment'), indent=2, default=str)}\n"
                f"IOC summary: {ioc_assessment.get('summary', '')}"
            )

        return f"""Generate a professional forensic analysis report in markdown format based on these results:

Analysis:
{json.dumps(ai_analysis, indent=2, default=str)}

Raw Data Summary:
- File: {results.get('file_name', 'unknown')}
- Type: {results.get('static', {}).get('file_type', 'unknown')}
- Size: {results.get('static', {}).get('file_size_human', 'unknown')}
- SHA256: {results.get('hashes', {}).get('sha256', 'N/A')}
- YARA Matches: {results.get('yara', {}).get('match_count', 0)}
- IOCs Found: {results.get('iocs', {}).get('summary', {}).get('total_iocs', 0)}
{vt_section}
{ioc_section}

Format as a professional incident response report with sections for:
Executive Summary, Technical Details, Indicators of Compromise (mark which IOCs were judged TRUE_SUSPICIOUS vs BENIGN/UNVERIFIED), Risk Assessment, and Recommendations."""

    async def _query(self, prompt: str) -> str:
        """Query OrcaRouter via OpenAI-compatible API."""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )
        return response.choices[0].message.content

    async def _query_json(self, prompt: str) -> str:
        """Query the model requesting strict JSON output."""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content

    # ------------------------------------------------------------------ #
    # IOC adjudication
    # ------------------------------------------------------------------ #
    def _build_ioc_assessment_prompt(self, iocs: dict, vt: dict) -> str:
        """Build the prompt that asks the LLM to verify each IOC."""
        # Compact IOC list (cap each type so the prompt stays small).
        ioc_brief = {}
        for k, vals in iocs.items():
            if k == "summary":
                continue
            if vals:
                ioc_brief[k] = vals[:30]

        # Compact VT summary: only what's relevant to judging IOCs.
        vt_brief = self._vt_brief(vt)

        return f"""You are a malware analyst adjudicating automatically-extracted Indicators of Compromise (IOCs) from a file.
Some extracted strings are false positives (random bytes that happen to match a pattern). Your job is to label each IOC.

Rules:
- Verdicts allowed: "TRUE_SUSPICIOUS" (genuinely indicative of malicious infrastructure/artifact), "BENIGN" (clearly legitimate/benign or obviously a false positive), "UNVERIFIED" (cannot determine).
- Ground your reasoning in the VirusTotal enrichment provided. If VirusTotal shows detections/tags for a domain/IP/URL/hash, that strongly supports TRUE_SUSPICIOUS. If VT has never seen it, lean UNVERIFIED unless the string is obviously benign (e.g. a known-good domain).
- Do NOT invent IOCs. Only judge the IOCs listed below.
- A base58/0x wallet string with no VT hit and no supporting context is usually UNVERIFIED or BENIGN.
- A domain like "tvt.jp" or other short generic hostnames with no VT hit and no malicious context is likely BENIGN/UNVERIFIED, not evidence.

Return STRICT JSON only, schema:
{{
  "assessment": {{
    "<ioc_type>": {{
      "<value>": {{ "verdict": "TRUE_SUSPICIOUS|BENIGN|UNVERIFIED", "reason": "<one short sentence>" }}
    }}
  }},
  "summary": "<one sentence overall on IOC credibility>"
}}

Extracted IOCs:
{json.dumps(ioc_brief, indent=2, default=str)}

VirusTotal enrichment:
{json.dumps(vt_brief, indent=2, default=str)}"""

    @staticmethod
    def _vt_brief(vt: dict) -> dict:
        """Extract only the verdict-relevant parts of VT enrichment."""
        brief = {"file": None, "domain": {}, "ip_address": {}, "url": {}}
        if isinstance(vt, dict):
            f = vt.get("file", {})
            if isinstance(f, dict) and f.get("report"):
                rep = f["report"]
                brief["file"] = {
                    "status": f.get("status"),
                    "reputation": rep.get("reputation"),
                    "last_analysis_stats": rep.get("last_analysis_stats"),
                    "tags": rep.get("tags"),
                    "suggested_threat_label": rep.get("popular_threat_classification"),
                }
            for kind in ("domain", "ip_address", "url"):
                src = vt.get(kind, {})
                if isinstance(src, dict):
                    for val, res in src.items():
                        if isinstance(res, dict) and res.get("status") == "ok":
                            attrs = res.get("data", {}).get("attributes", {})
                            brief[kind][val] = {
                                "reputation": attrs.get("reputation"),
                                "last_analysis_stats": attrs.get("last_analysis_stats"),
                                "tags": attrs.get("tags"),
                            }
        return brief

    def _parse_ioc_assessment(self, response: str, iocs: dict) -> dict:
        """Parse the LLM JSON verdicts, validated against the actual IOC set."""
        try:
            data = json.loads(response)
        except Exception:
            # Try to extract the first {...} block.
            m = re.search(r"\{.*\}", response, re.DOTALL)
            if not m:
                return {"assessment": {}, "summary": ""}
            try:
                data = json.loads(m.group(0))
            except Exception:
                return {"assessment": {}, "summary": ""}

        assessment = {}
        valid = {k: set(v) for k, v in iocs.items() if k != "summary"}
        for ioc_type, entries in (data.get("assessment") or {}).items():
            if ioc_type not in valid:
                continue
            kept = {}
            for value, info in (entries or {}).items():
                if value not in valid[ioc_type]:
                    continue
                verdict = str(info.get("verdict", "UNVERIFIED")).upper()
                if verdict not in ("TRUE_SUSPICIOUS", "BENIGN", "UNVERIFIED"):
                    verdict = "UNVERIFIED"
                kept[value] = {
                    "verdict": verdict,
                    "reason": str(info.get("reason", ""))[:200],
                }
            if kept:
                assessment[ioc_type] = kept

        return {"assessment": assessment, "summary": str(data.get("summary", ""))[:500]}

    def _parse_response(self, response: str) -> dict:
        """Parse AI response into structured data."""
        result = {
            "ai_available": True,
            "raw_response": response,
            "analysis": response,
            "classification": "Unknown",
            "risk_level": "Unknown",
            "confidence": "Medium",
        }

        # Try to extract structured fields from the response
        lower = response.lower()

        # Extract risk level
        for level in ["critical", "high", "medium", "low", "informational"]:
            if f"risk level**: {level}" in lower or f"risk**: {level}" in lower:
                result["risk_level"] = level.upper()
                break

        # Extract confidence
        for level in ["high", "medium", "low"]:
            if f"confidence**: {level}" in lower:
                result["confidence"] = level.capitalize()
                break

        # Extract classification
        class_match = re.search(
            r"classification\*\*[:\s]+(.+?)(?:\n|$)", response, re.IGNORECASE
        )
        if class_match:
            result["classification"] = class_match.group(1).strip("* ")

        return result
