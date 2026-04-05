# backend/threat_intel/factory.py
# Factory for instantiating the correct threat intelligence provider.
from ..config import ACTIVE_THREAT_PROVIDER, VIRUSTOTAL_API_KEY
from .base import ThreatIntelProvider
from .virustotal import VirusTotalProvider
from .null_provider import NullProvider

def get_provider() -> ThreatIntelProvider:
    """
    Returns the configured provider if valid, else returns NullProvider.
    """
    if ACTIVE_THREAT_PROVIDER == "virustotal" and VIRUSTOTAL_API_KEY:
        return VirusTotalProvider(api_key=VIRUSTOTAL_API_KEY)
    
    return NullProvider()
