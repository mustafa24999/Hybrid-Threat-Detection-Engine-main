# backend/threat_intel/virustotal.py
# Implements ThreatIntelProvider using VirusTotal API v3.
import httpx
import base64
import logging
from typing import Optional, Dict, Any, Tuple
from .base import ThreatIntelProvider

logger = logging.getLogger("virustotal")

class VirusTotalProvider(ThreatIntelProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}

    async def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Lookup a URL on VirusTotal.
        Encodes URL into base64url without padding as per VT API spec.
        """
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"{self.base_url}/urls/{url_id}"
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(endpoint, headers=self.headers)
                if response.status_code == 404:
                    return {"found": False}
                response.raise_for_status()
                data = response.json()
                return self._summarize_stats(data)
        except Exception as e:
            logger.warning(f"VirusTotal URL lookup failed: {e}")
            return None

    async def lookup_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Lookup a file hash on VirusTotal."""
        endpoint = f"{self.base_url}/files/{sha256}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(endpoint, headers=self.headers)
                if response.status_code == 404:
                    return {"found": False}
                response.raise_for_status()
                data = response.json()
                return self._summarize_stats(data)
        except Exception as e:
            logger.warning(f"VirusTotal hash lookup failed: {e}")
            return None

    def _summarize_stats(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts key statistics from VT API response."""
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        harmless = last_analysis_stats.get("harmless", 0)
        undetected = last_analysis_stats.get("undetected", 0)
        
        total_engines = malicious + suspicious + harmless + undetected
        detection_rate = malicious / total_engines if total_engines > 0 else 0
        
        threat_names = []
        results = attributes.get("last_analysis_results", {})
        for engine, res in results.items():
            name = res.get("result")
            if name and name not in threat_names:
                threat_names.append(name)
                if len(threat_names) >= 5: break

        return {
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total_engines,
            "detection_rate": detection_rate,
            "threat_names": threat_names
        }


def vt_score_contribution(vt_summary: Optional[Dict[str, Any]]) -> Tuple[float, Optional[str]]:
    """
    Calculates the contribution to the final risk score from VT results.
    :return: (score_contribution, reason_string)
    """
    if not vt_summary or not vt_summary.get("found"):
        return 0.0, None

    detection_rate = vt_summary.get("detection_rate", 0)
    malicious = vt_summary.get("malicious", 0)
    total = vt_summary.get("total_engines", 0)

    if detection_rate >= 0.10:
        return 0.50, f"VirusTotal: {malicious}/{total} engines flagged this as malicious."
    elif 0.03 <= detection_rate < 0.10:
        return 0.25, f"VirusTotal: {malicious}/{total} engines flagged this as suspicious/malicious."
    elif malicious >= 1:
        return 0.10, "VirusTotal: Low confidence detection (1 engine flagged)."
    
    return 0.0, None
