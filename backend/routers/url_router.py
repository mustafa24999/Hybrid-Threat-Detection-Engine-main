# backend/routers/url_router.py
# FastAPI router for URL scanning.
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl
from ..url_analyzer import compute_url_score
from ..threat_intel.factory import get_provider
from ..threat_intel.virustotal import vt_score_contribution
from ..scoring import build_result
from ..database import save_scan

router = APIRouter(prefix="/scan", tags=["URL Scan"])

class URLScanRequest(BaseModel):
    url: str

@router.post("/url")
async def scan_url(request: URLScanRequest):
    """
    Scans a URL for static threats and checks external intelligence.
    """
    url = request.url
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Only http and https URLs are supported.")

    # 1. Local Static Analysis
    local_analysis = compute_url_score(url)
    
    # 2. External Intelligence (VirusTotal)
    provider = get_provider()
    vt_summary = await provider.lookup_url(url)
    vt_contribution, vt_reason = vt_score_contribution(vt_summary)
    
    # 3. Build Final Result
    result = build_result(
        scan_type="URL",
        target=url,
        local_score=local_analysis["score"],
        local_reasons=local_analysis["reasons"],
        vt_summary=vt_summary,
        vt_contribution=vt_contribution,
        vt_reason=vt_reason
    )
    
    # 4. Persistence
    scan_id = save_scan(result)
    result["id"] = scan_id
    
    return result
