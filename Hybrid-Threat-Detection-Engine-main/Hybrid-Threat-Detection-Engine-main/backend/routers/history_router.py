# backend/routers/history_router.py
# FastAPI router for scan history.
from fastapi import APIRouter, HTTPException, Query
from ..database import get_history, get_scan_by_id, delete_scan, clear_all_history

router = APIRouter(prefix="/history", tags=["History"])

@router.get("/")
async def list_history(limit: int = Query(100, le=500)):
    """Retrieves the recent scan history."""
    records = get_history(limit=limit)
    return {"count": len(records), "records": records}

@router.get("/{scan_id}")
async def get_scan(scan_id: int):
    """Retrieves a specific scan result by ID."""
    record = get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return record

@router.delete("/{scan_id}")
async def remove_scan(scan_id: int):
    """Removes a specific scan record."""
    if not delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return {"status": "success"}

@router.delete("/")
async def clear_history():
    """Deletes all records from history."""
    if not clear_all_history():
        raise HTTPException(status_code=500, detail="Failed to clear history.")
    return {"status": "success"}
