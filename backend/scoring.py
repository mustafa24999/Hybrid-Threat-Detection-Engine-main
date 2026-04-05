# backend/scoring.py
# Logic for score classification and final result aggregation.
from typing import List, Dict, Any, Optional
from datetime import datetime
from .config import SCORE_MALICIOUS_THRESHOLD, SCORE_SUSPICIOUS_THRESHOLD

def classify(score: float) -> str:
    """Classifies a score into a label."""
    if score >= SCORE_MALICIOUS_THRESHOLD:
        return "Malicious"
    elif score >= SCORE_SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Safe"

def build_explanation(label: str, reasons: List[str], scan_type: str) -> str:
    """Generates a human-friendly explanation of the scan results."""
    if label == "Safe":
        if not reasons:
            return f"No suspicious patterns were detected in this {scan_type}."
        return f"This {scan_type} appears low-risk, although some minor indicators were noted."
    
    if label == "Suspicious":
        return f"Caution: This {scan_type} has characteristics often associated with threats. Review the reasons below."
    
    if label == "Malicious":
        return f"High Risk: This {scan_type} shows strong indicators of being malicious or highly dangerous."
    
    return "Scan complete."

def build_result(
    scan_type: str,
    target: str,
    local_score: float,
    local_reasons: List[str],
    vt_summary: Optional[Dict[str, Any]],
    vt_contribution: float,
    vt_reason: Optional[str],
    extra_metadata: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Aggregates all analysis parts into a single structured result.
    """
    # Final Score Calculation
    final_score = round(min(1.0, local_score + vt_contribution), 3)
    label = classify(final_score)
    
    all_reasons = list(local_reasons)
    if vt_reason:
        all_reasons.append(vt_reason)
        
    explanation = build_explanation(label, all_reasons, scan_type)
    
    result = {
        "scan_type": scan_type,
        "target": target,
        "label": label,
        "score": final_score,
        "reasons": all_reasons,
        "explanation": explanation,
        "vt_summary": vt_summary or {"found": False},
        "timestamp": datetime.now().isoformat()
    }
    
    if extra_metadata:
        result.update(extra_metadata)
        
    return result
