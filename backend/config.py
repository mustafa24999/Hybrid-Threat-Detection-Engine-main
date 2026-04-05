# backend/config.py
# Single source of truth for all configuration.
import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Provider Configuration
ACTIVE_THREAT_PROVIDER = os.getenv("THREAT_PROVIDER", "virustotal")
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY", "")

# Security Configuration (Zenith-tier)
# Generate a secure key and set it in .env for production
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY", "zenith_default_dev_key")

# SIEM Integration (JSON Logging)
LOG_FORMAT = os.getenv("LOG_FORMAT", "json") # 'json' or 'text'
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Server Configuration
BACKEND_HOST = os.getenv("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8000"))

# Scoring Thresholds
SCORE_MALICIOUS_THRESHOLD = float(os.getenv("SCORE_MALICIOUS_THRESHOLD", "0.65"))
SCORE_SUSPICIOUS_THRESHOLD = float(os.getenv("SCORE_SUSPICIOUS_THRESHOLD", "0.30"))

# File Analysis Constraints
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "50"))

# Database Configuration
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY_DB_PATH = os.path.abspath(os.path.join(BASE_DIR, os.getenv("HISTORY_DB_PATH", "scan_history.db")))
MAX_HISTORY_RECORDS = int(os.getenv("MAX_HISTORY_RECORDS", "500"))
