# backend/routers/file_router.py
# FastAPI router for file scanning.
import os
import tempfile
import logging
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException
from ..config import MAX_FILE_SIZE_MB
from ..file_analyzer import analyze_file
from ..threat_intel.factory import get_provider
from ..threat_intel.virustotal import vt_score_contribution
from ..scoring import build_result
from ..database import save_scan

router = APIRouter(prefix="/scan", tags=["File Scan"])
logger = logging.getLogger("file_router")

@router.post("/file")
async def scan_file(file: UploadFile = File(...)):
    """
    Analyzes an uploaded file for threats.
    Enforces size limits and uses temp files for safe processing.
    """
    # 1. Enforce Max File Size
    # Read size from content-length if available, or during read
    file_size_limit = MAX_FILE_SIZE_MB * 1024 * 1024
    
    # Use a temporary file to store the upload for analysis
    fd, tmp_path = tempfile.mkstemp()
    try:
        current_size = 0
        with os.fdopen(fd, 'wb') as tmp:
            while chunk := await file.read(65536):
                current_size += len(chunk)
                if current_size > file_size_limit:
                    raise HTTPException(status_code=413, detail=f"File exceeds limit of {MAX_FILE_SIZE_MB}MB.")
                tmp.write(chunk)
        
        # 2. Local Analysis
        local_analysis = analyze_file(Path(tmp_path))
        
        # 3. External Intelligence (Hash lookup only)
        provider = get_provider()
        vt_summary = await provider.lookup_hash(local_analysis["sha256"])
        vt_contribution, vt_reason = vt_score_contribution(vt_summary)
        
        # 4. Build Result
        result = build_result(
            scan_type="File",
            target=file.filename or "unknown",
            local_score=local_analysis["score"],
            local_reasons=local_analysis["reasons"],
            vt_summary=vt_summary,
            vt_contribution=vt_contribution,
            vt_reason=vt_reason,
            extra_metadata={
                "sha256": local_analysis["sha256"],
                "file_info": local_analysis["metadata"]
            }
        )
        
        # 5. Persistence
        scan_id = save_scan(result)
        result["id"] = scan_id
        
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"File analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during file analysis.")
    finally:
        # 6. Cleanup temp file
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
