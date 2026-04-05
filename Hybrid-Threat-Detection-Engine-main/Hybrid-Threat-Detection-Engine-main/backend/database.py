# backend/database.py
# Handles persistent storage of scan history using SQLite.
import sqlite3
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from .config import HISTORY_DB_PATH, MAX_HISTORY_RECORDS

logger = logging.getLogger("database")
def init_db():
    """Initializes the database schema with WAL mode for high concurrency."""
    try:
        with sqlite3.connect(HISTORY_DB_PATH) as conn:
            # Enable Write-Ahead Logging for better concurrency
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    label TEXT NOT NULL,
                    score REAL NOT NULL,
                    reasons TEXT,
                    explanation TEXT,
                    vt_summary TEXT,
                    timestamp TEXT NOT NULL
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scans (timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_target ON scans (target)")
            conn.commit()
            logger.info("Database initialized successfully with WAL mode.")
    except Exception as e:
        logger.critical(f"Database initialization failed: {e}")
        raise



def save_scan(record: Dict[str, Any]) -> int:
    """
    Saves a scan record to the database.
    Manages record limit to prevent database bloat.
    """
    try:
        with sqlite3.connect(HISTORY_DB_PATH) as conn:
            cursor = conn.cursor()
            
            # Prepare data
            reasons_json = json.dumps(record.get("reasons", []))
            vt_summary_json = json.dumps(record.get("vt_summary", {}))
            timestamp = record.get("timestamp") or datetime.now().isoformat()

            cursor.execute("""
                INSERT INTO scans (
                    scan_type, target, label, score, reasons, explanation, vt_summary, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record["scan_type"], record["target"], record["label"],
                record["score"], reasons_json, record["explanation"],
                vt_summary_json, timestamp
            ))
            
            scan_id = cursor.lastrowid
            
            # Prune old records if limit reached
            cursor.execute("SELECT COUNT(*) FROM scans")
            count = cursor.fetchone()[0]
            if count > MAX_HISTORY_RECORDS:
                cursor.execute("""
                    DELETE FROM scans WHERE id IN (
                        SELECT id FROM scans ORDER BY timestamp ASC LIMIT ?
                    )
                """, (count - MAX_HISTORY_RECORDS,))
            
            conn.commit()
            return scan_id
    except Exception as e:
        logger.error(f"Failed to save scan: {e}")
        return -1

def get_history(limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieves scan history."""
    try:
        with sqlite3.connect(HISTORY_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            
            records = []
            for row in rows:
                record = dict(row)
                record["reasons"] = json.loads(record["reasons"]) if record["reasons"] else []
                record["vt_summary"] = json.loads(record["vt_summary"]) if record["vt_summary"] else {}
                records.append(record)
            
            return records
    except Exception as e:
        logger.error(f"Failed to fetch history: {e}")
        return []

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single scan result by ID."""
    try:
        with sqlite3.connect(HISTORY_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            
            if row:
                record = dict(row)
                record["reasons"] = json.loads(record["reasons"]) if record["reasons"] else []
                record["vt_summary"] = json.loads(record["vt_summary"]) if record["vt_summary"] else {}
                return record
            return None
    except Exception as e:
        logger.error(f"Failed to fetch scan {scan_id}: {e}")
        return None

def delete_scan(scan_id: int) -> bool:
    """Deletes a specific scan record by ID."""
    try:
        with sqlite3.connect(HISTORY_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Failed to delete scan {scan_id}: {e}")
        return False

def clear_all_history() -> bool:
    """Deletes all scan records from the database."""
    try:
        with sqlite3.connect(HISTORY_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans")
            conn.commit()
            return True
    except Exception as e:
        logger.error(f"Failed to clear history: {e}")
        return False
