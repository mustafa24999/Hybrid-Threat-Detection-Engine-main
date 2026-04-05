# backend/url_analyzer.py
# Static analysis logic for URLs.
import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List

SUSPICIOUS_WORDS = ["login", "verify", "account", "secure", "update", "bank", "signin", "admin", "wp-admin", "office", "microsoft", "paypal"]
SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr", ".js", ".vbe", ".jar", ".zip", ".rar", ".7z"]
KNOWN_SHORTENERS = ["bit.ly", "goo.gl", "t.co", "rebrand.ly", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "shorte.st"]

def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)

def compute_url_score(url: str) -> Dict[str, Any]:
    """
    Zenith-tier static URL analysis with pattern weighting.
    """
    score = 0.0
    reasons = []
    checks_run = 0
    
    try:
        parsed = urlparse(url)
    except Exception:
        return {"score": 1.0, "reasons": ["Invalid URL format."], "checks_run": 1}

    hostname = (parsed.hostname or "").lower()
    path_lower = parsed.path.lower()

    # 1. Scheme Security (Critical)
    checks_run += 1
    if parsed.scheme == "http":
        score += 0.15
        reasons.append("Insecure protocol: HTTP in use.")

    # 2. Hostname Analysis (IP, TLD, Patterns)
    checks_run += 1
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[a-fA-F0-9:]+$"
    if hostname and re.match(ip_pattern, hostname):
        score += 0.40
        reasons.append("Host is a raw IP address (obfuscated destination).")

    # 3. Enhanced DGA Detection
    if hostname:
        domain_parts = hostname.split(".")
        if len(domain_parts) >= 2:
            # For x7w2q9z4k1m8p0j3.xyz, main_domain is x7w2q9z4k1m8p0j3
            main_domain = domain_parts[-2]
            tld = domain_parts[-1]
            
            # Lowered threshold to 3.8 for better catch rate of random strings
            domain_entropy = calculate_entropy(main_domain)
            if domain_entropy > 3.8:
                score += 0.25
                reasons.append(f"DGA detected (High entropy: {domain_entropy:.2f}).")
            
            # Suspicious TLD check
            if tld in ["zip", "mov", "app", "tk", "ml", "ga", "cf", "gq"]:
                score += 0.20
                reasons.append(f"Suspicious/High-risk TLD detected: .{tld}.")

    # 4. Pattern Obfuscation
    checks_run += 1
    if "@" in url:
        score += 0.30
        reasons.append("User-info '@' pattern used to spoof hostname.")
    
    # Check for homograph attacks or character padding
    if re.search(r"-{2,}", hostname) or re.search(r"_{2,}", hostname):
        score += 0.15
        reasons.append("Suspicious character repetition in hostname.")

    # 5. Path Keyword & Extension Risk
    checks_run += 1
    found_words = [w for w in SUSPICIOUS_WORDS if w in path_lower or w in hostname]
    if found_words:
        score += min(0.40, len(found_words) * 0.20)
        reasons.append(f"Threat keywords detected: {', '.join(found_words)}.")

    for ext in SUSPICIOUS_EXTENSIONS:
        if path_lower.endswith(ext):
            score += 0.35
            reasons.append(f"URL links directly to execution-capable file: {ext}.")
            break

    # 6. Deep Entropy on full URL
    if calculate_entropy(url) > 5.2:
        score += 0.10
        reasons.append("Extreme URL entropy detected (possible shellcode/binary payload).")

    return {
        "score": round(min(1.0, score), 3),
        "reasons": reasons,
        "checks_run": checks_run
    }


