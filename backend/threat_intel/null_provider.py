# backend/threat_intel/null_provider.py
# Implements ThreatIntelProvider for offline or key-less scenarios.
from .base import ThreatIntelProvider
from typing import Optional, Dict, Any

class NullProvider(ThreatIntelProvider):
    """
    Returns None for all lookups, effectively disabling external lookups.
    """
    async def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        return None

    async def lookup_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        return None
