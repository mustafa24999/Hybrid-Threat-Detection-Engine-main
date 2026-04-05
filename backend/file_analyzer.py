# backend/file_analyzer.py
# Static analysis logic for files.
import hashlib
import math
from pathlib import Path
from typing import Dict, Any, List

# Risk Tiers for extensions
HIGH_RISK_EXT = [".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr", ".js", ".vbe", ".jar", ".sys", ".drv", ".cpl", ".msi"]
MEDIUM_RISK_EXT = [".zip", ".rar", ".7z", ".pdf", ".docm", ".xlsm", ".pptm", ".hta"]
LOW_RISK_EXT = [".txt", ".png", ".jpg", ".jpeg", ".csv", ".json", ".log", ".md"]

# Magic Byte Signatures
MAGIC_SIGNATURES = {
    b"\x4d\x5a": "PE Executable (Windows EXE/DLL)",
    b"\x7f\x45\x4c\x46": "ELF Executable (Linux)",
    b"\x25\x50\x44\x46": "PDF Document",
    b"\x50\x4b\x03\x04": "ZIP/Office Document (OpenXML)",
    b"\xca\xfe\xba\xbe": "Java Class File",
    b"\xef\xbb\xbf": "UTF-8 Text",
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image"
}

def get_file_sha256(file_path: Path) -> str:
    """Calculates SHA256 hash in chunks with error handling."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "0" * 64 # Fallback for unreadable files

def calculate_file_entropy(file_path: Path, max_bytes: int = 65536) -> float:
    """Calculates Shannon entropy with safety checks."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
        if not data:
            return 0.0
        prob = [float(data.count(b)) / len(data) for b in set(data)]
        return -sum(p * math.log2(p) for p in prob)
    except Exception:
        return 0.0

def analyze_file(file_path: Path) -> Dict[str, Any]:
    """
    Zenith-tier static file analysis with deep structure inspection.
    """
    file_path = Path(file_path)
    file_size = file_path.stat().st_size
    extension = file_path.suffix.lower()
    
    score = 0.0
    reasons = []
    
    # 1. SHA256 Hash
    sha256 = get_file_sha256(file_path)
    
    # 2. Magic Bytes Check (Multi-signature)
    magic_type = "Unknown"
    header = b""
    try:
        with open(file_path, "rb") as f:
            header = f.read(1024)
            for sig, name in MAGIC_SIGNATURES.items():
                if header.startswith(sig):
                    magic_type = name
                    break
    except Exception:
        return {"score": 1.0, "reasons": ["Unable to read file header."], "sha256": sha256, "metadata": {}}

    # 3. Extension & Header Integrity
    if extension in HIGH_RISK_EXT:
        score += 0.35
        reasons.append(f"High-risk extension: {extension}.")
    
    if magic_type == "PE Executable (Windows EXE/DLL)" and extension not in HIGH_RISK_EXT:
        score += 0.45
        reasons.append(f"Mismatched extension: PE file hiding as {extension}.")
    elif magic_type == "Unknown" and extension in LOW_RISK_EXT and file_size > 0:
        # Zenith-tier scanning: Scan first 4KB instead of just 512 bytes
        try:
            with open(file_path, "rb") as f:
                scan_chunk = f.read(4096)
                if b"\x00" in scan_chunk:
                    score += 0.25
                    reasons.append(f"Binary content detected in text-labeled file ({extension}).")
        except Exception: pass

    # 4. Zenith-tier Heuristic Engine (Deep Inspection)
    # 4a. PE Structure Inspection
    if magic_type == "PE Executable (Windows EXE/DLL)":
        try:
            with open(file_path, "rb") as f:
                f.seek(0x3C)
                raw_off = f.read(4)
                if len(raw_off) == 4:
                    e_lfanew = int.from_bytes(raw_off, byteorder="little")
                    if 0x40 <= e_lfanew < file_size - 4:
                        f.seek(e_lfanew)
                        pe_sig = f.read(4)
                        if pe_sig != b"PE\x00\x00":
                            score += 0.30
                            reasons.append("Malformed PE signature (Static evasion attempt).")
                        
                        f.seek(0)
                        header_full = f.read(1024)
                        suspicious_sections = [b"UPX", b"ASPACK", b"PELOCK", b"THEIDA"]
                        for sec in suspicious_sections:
                            if sec in header_full:
                                score += 0.20
                                reasons.append(f"Known packer/obfuscator signature detected: {sec.decode()}.")
        except Exception:
            score += 0.15
            reasons.append("PE structure analysis interrupted by file error.")

    # 4b. Document & Script Heuristics
    header_peek = b""
    try:
        with open(file_path, "rb") as f:
            header_peek = f.read(4096)
    except Exception: pass

    if extension in [".docm", ".xlsm", ".pptm", ".dotm"]:
        if b"VBA" in header_peek or b"macro" in header_peek.lower():
            score += 0.50
            reasons.append("Embedded VBA Macros detected in Office document.")
    elif extension == ".pdf":
        if b"/JavaScript" in header_peek or b"/JS" in header_peek or b"/OpenAction" in header_peek:
            score += 0.35
            reasons.append("Embedded JavaScript or auto-execution objects detected in PDF.")
    elif extension in [".ps1", ".vbs", ".bat"]:
        suspicious_script_patterns = [b"-ExecutionPolicy", b"bypass", b"WScript.Shell", b"cmd.exe", b"powershell"]
        for p in suspicious_script_patterns:
            if p in header_peek:
                score += 0.20
                reasons.append(f"Suspicious script pattern detected: {p.decode()}.")
                break

    # 5. Shannon Entropy (Global & Targeted)
    entropy = calculate_file_entropy(file_path)
    if entropy > 7.3:
        score += 0.30
        reasons.append(f"Extreme entropy ({entropy:.2f}): Content is packed or encrypted.")
    elif entropy < 1.0 and file_size > 1024:
        score += 0.15
        reasons.append("Abnormally low entropy (Large zero-filled areas/padding).")

    # 6. Metadata Context
    if file_size < 512 and magic_type != "UTF-8 Text":
        score += 0.20
        reasons.append("Suspiciously small binary file (< 512 bytes).")

    return {
        "score": round(min(1.0, score), 3),
        "reasons": reasons,
        "sha256": sha256,
        "metadata": {
            "filename": file_path.name,
            "size_bytes": file_size,
            "extension": extension,
            "magic_type": magic_type,
            "entropy": round(entropy, 2),
            "is_binary": b"\x00" in header
        }
    }


