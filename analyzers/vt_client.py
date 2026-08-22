"""
VirusTotal client - enriches analysis with VirusTotal intelligence.

Capabilities:
- File reports by hash (md5/sha1/sha256). If no report exists and uploads are
  enabled, the sample is uploaded and the resulting analysis is polled.
- Domain / IP-address / URL reports for extracted IOCs.

All calls are best-effort: missing key, rate limiting, or network errors degrade
gracefully to a "skipped"/"error" status so the rest of the analysis still runs.
"""

from pathlib import Path

import httpx

from config import (
    VIRUSTOTAL_API_KEY,
    VIRUSTOTAL_BASE_URL,
    VIRUSTOTAL_UPLOAD_IF_ABSENT,
)

# Relationship types worth summarizing in the report (kept small to limit size).
_NOTABLE_RELATIONSHIPS = (
    "contacted_domains",
    "contacted_ips",
    "communicating_files",
    "urls",
    "downloaded_files",
    "dropped_files",
    "itw_urls",
)

_TIMEOUT = 30.0


class VirusTotalClient:
    """Thin async wrapper around the VirusTotal v3 API."""

    def __init__(self):
        self.api_key = VIRUSTOTAL_API_KEY
        self.base_url = VIRUSTOTAL_BASE_URL.rstrip("/")
        self.upload_if_absent = VIRUSTOTAL_UPLOAD_IF_ABSENT
        self.enabled = bool(self.api_key)

    def _headers(self) -> dict:
        return {"x-apikey": self.api_key}

    # ------------------------------------------------------------------ #
    # Public entry points
    # ------------------------------------------------------------------ #
    async def enrich_file(self, file_path: Path, hashes: dict) -> dict:
        """Get a VT file report for the sample, uploading it if necessary."""
        if not self.enabled:
            return {"enabled": False, "status": "skipped", "reason": "no_api_key"}

        sha256 = hashes.get("sha256") or ""
        result = {
            "enabled": True,
            "status": "unknown",
            "sha256": sha256,
            "report": None,
        }

        # 1) Hash lookup first (works without upload permissions).
        lookup = await self._get_file_report(sha256)
        if lookup.get("found"):
            result["status"] = "found"
            result["report"] = self._summarize_file(lookup["data"])
            return result

        # 2) Upload if allowed.
        if not self.upload_if_absent:
            result["status"] = "not_found"
            return result

        upload = await self._upload_file(file_path)
        analysis_id = upload.get("analysis_id") or ""
        if not upload.get("ok"):
            result["status"] = "not_found"
            result["reason"] = upload.get("reason", "upload_failed")
            return result

        # 3) Poll for the analysis to finish.
        polled = await self._poll_analysis(analysis_id)
        if polled.get("ok"):
            result["status"] = "uploaded"
            result["report"] = self._summarize_file(polled["data"])
        else:
            result["status"] = "uploaded_pending"
            result["reason"] = polled.get("reason", "analysis_pending")
            result["analysis_id"] = analysis_id
        return result

    async def enrich_iocs(self, iocs: dict) -> dict:
        """Look up domains / IPs / URLs extracted from the file."""
        if not self.enabled:
            return {"enabled": False, "status": "skipped", "reason": "no_api_key"}

        out = {"enabled": True, "domain": {}, "ip_address": {}, "url": {}}
        domains = iocs.get("domain", [])[:25]
        ips = iocs.get("ip_address", [])[:25]
        urls = iocs.get("url", [])[:25]

        for d in domains:
            out["domain"][d] = await self._lookup("domain", d)
        for ip in ips:
            out["ip_address"][ip] = await self._lookup("ip_address", ip)
        for u in urls:
            # VT wants URLs base64-encoded (URL-safe, no padding) as the id.
            import base64

            uid = base64.urlsafe_b64encode(u.encode("utf-8")).decode().rstrip("=")
            out["url"][u] = await self._lookup_raw(f"urls/{uid}")
        return out

    # ------------------------------------------------------------------ #
    # Low-level API calls
    # ------------------------------------------------------------------ #
    async def _get_file_report(self, sha256: str) -> dict:
        """Return {'found': bool, 'data': ...} for a file hash."""
        if not sha256:
            return {"found": False}
        r = await self._lookup_raw(f"files/{sha256}")
        if r.get("status") == "ok" and r.get("data"):
            return {"found": True, "data": r["data"]}
        # 404 -> not found; anything else -> error but treat as not-found
        return {"found": False, "error": r.get("error")}

    async def _upload_file(self, file_path: Path) -> dict:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                # VT requires multipart with the raw file.
                with open(file_path, "rb") as fh:
                    files = {"file": (file_path.name, fh, "application/octet-stream")}
                    resp = await client.post(
                        f"{self.base_url}/files", headers=self._headers(), files=files
                    )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                analysis_id = data.get("id")
                return {"ok": True, "analysis_id": analysis_id}
            return {
                "ok": False,
                "reason": f"http_{resp.status_code}",
                "error": self._error_text(resp),
            }
        except Exception as e:  # noqa: BLE001 - degrade gracefully
            return {"ok": False, "reason": "exception", "error": str(e)}

    async def _poll_analysis(self, analysis_id: str, max_polls: int = 10) -> dict:
        import asyncio

        last = None
        for _ in range(max_polls):
            r = await self._lookup_raw(f"analyses/{analysis_id}")
            if r.get("status") != "ok" or not r.get("data"):
                last = r
                break
            attrs = r["data"].get("attributes", {})
            if attrs.get("status") == "completed":
                # Fetch the completed file report by the analysis's hex sha256.
                meta = r["data"].get("meta", {})
                sha = meta.get("file_info", {}).get("sha256") or attrs.get(
                    "sha256", analysis_id
                )
                rep = await self._get_file_report(sha)
                if rep.get("found"):
                    return {"ok": True, "data": rep["data"]}
                return {"ok": True, "data": r["data"]}
            await asyncio.sleep(3)
            last = r
        return {"ok": False, "reason": "timeout", "last": last}

    async def _lookup(self, ioc_type: str, value: str) -> dict:
        return await self._lookup_raw(f"{ioc_type}/{value}")

    async def _lookup_raw(self, path: str) -> dict:
        """GET a VT endpoint; normalize to {'status', 'data'/'error'}."""
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{self.base_url}/{path}", headers=self._headers()
                )
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "error": str(e)}

        if resp.status_code == 200:
            try:
                return {"status": "ok", "data": resp.json().get("data", {})}
            except Exception:  # noqa: BLE001
                return {"status": "error", "error": "bad_json"}
        if resp.status_code == 404:
            return {"status": "not_found"}
        if resp.status_code == 429:
            return {"status": "rate_limited"}
        return {
            "status": "error",
            "error": f"http_{resp.status_code}: {self._error_text(resp)}",
        }

    @staticmethod
    def _error_text(resp: httpx.Response) -> str:
        try:
            body = resp.json()
            return body.get("error", {}).get("message", resp.text[:200])
        except Exception:  # noqa: BLE001
            return resp.text[:200]

    # ------------------------------------------------------------------ #
    # Summarizers (extract the useful, bounded subset of the VT payload)
    # ------------------------------------------------------------------ #
    def _summarize_file(self, data: dict) -> dict:
        attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attrs.get("last_analysis_stats", {})
        detections = self._top_detections(attrs.get("last_analysis_results", {}))
        return {
            "id": data.get("id"),
            "type": data.get("type"),
            "reputation": attrs.get("reputation"),
            "last_analysis_stats": stats,
            "meaningful_name": attrs.get("meaningful_name"),
            "type_tags": attrs.get("type_tags", []),
            "tags": attrs.get("tags", []),
            "size": attrs.get("size"),
            "md5": attrs.get("md5"),
            "sha1": attrs.get("sha1"),
            "sha256": attrs.get("sha256"),
            "tlsh": attrs.get("tlsh"),
            "first_submission_date": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "times_submitted": attrs.get("times_submitted"),
            "popular_threat_classification": attrs.get(
                "popular_threat_classification", {}
            ).get("suggested_threat_label"),
            "detections": detections,
            "relations": self._relations(attrs.get("relations", {})),
        }

    def _top_detections(self, results: dict, limit: int = 8) -> list:
        out = []
        for engine, res in results.items():
            if isinstance(res, dict) and res.get("category") == "malicious":
                out.append(
                    {
                        "engine": engine,
                        "result": res.get("result"),
                    }
                )
        # Sort by result label; cap to limit.
        return out[:limit]

    def _relations(self, relations: dict) -> dict:
        out = {}
        for rel in _NOTABLE_RELATIONSHIPS:
            items = relations.get(rel, {}).get("data", [])
            if items:
                out[rel] = [i.get("id") for i in items if isinstance(i, dict)][:15]
        return out
