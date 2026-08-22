"""
AI Engine - uses OrcaRouter (OpenAI-compatible) for malware analysis and classification.
"""

import json
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

Format as a professional incident response report with sections for:
Executive Summary, Technical Details, Indicators of Compromise, Risk Assessment, and Recommendations."""

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
        import re
        class_match = re.search(
            r"classification\*\*[:\s]+(.+?)(?:\n|$)", response, re.IGNORECASE
        )
        if class_match:
            result["classification"] = class_match.group(1).strip("* ")

        return result
