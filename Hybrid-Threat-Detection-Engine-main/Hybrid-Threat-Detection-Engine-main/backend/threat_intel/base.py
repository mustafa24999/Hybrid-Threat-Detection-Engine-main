# backend/threat_intel/base.py
# Abstract base class for threat intelligence providers.
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class ThreatIntelProvider(ABC):
    """
    Interface for threat intelligence lookups.
    Enables swapping between VirusTotal, other APIs, or a null provider.
    """
    
    @abstractmethod
    async def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Lookup analysis for a given URL.
        :param url: The URL string to scan.
        :return: A summary dictionary or None if error/no match.
        """
        pass

    @abstractmethod
    async def lookup_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        """
        Lookup analysis for a given SHA256 file hash.
        :param sha256: The hex-encoded SHA256 hash.
        :return: A summary dictionary or None if error/no match.
        """
        pass
