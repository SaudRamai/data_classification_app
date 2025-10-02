"""
Decision Matrix Service
- Computes risk level from CIA
- Suggests minimum label from CIA
- Validates guardrails between chosen label and CIA
"""
from typing import Tuple, List

LABEL_ORDER = ["Public", "Internal", "Restricted", "Confidential"]


def compute_risk(c: int, i: int, a: int) -> str:
    try:
        highest = max(int(c or 0), int(i or 0), int(a or 0))
    except Exception:
        highest = 0
    if highest >= 3:
        return "High"
    if highest == 2:
        return "Medium"
    return "Low"


def suggest_min_label(c: int, i: int, a: int) -> str:
    highest = max(int(c or 0), int(i or 0), int(a or 0))
    if highest >= 3:
        return "Confidential"
    if highest == 2:
        return "Restricted"
    if highest == 1:
        return "Internal"
    return "Public"


def validate(label: str, c: int, i: int, a: int) -> Tuple[bool, List[str]]:
    """Validate if chosen label meets or exceeds the minimum suggested by CIA and that CIA are within 0..3."""
    reasons: List[str] = []
    try:
        ci = int(c); ii = int(i); ai = int(a)
    except Exception:
        return False, ["C/I/A must be integers"]
    for v, name in [(ci, "C"), (ii, "I"), (ai, "A")]:
        if v < 0 or v > 3:
            reasons.append(f"{name} must be in 0..3")
    if reasons:
        return False, reasons
    min_label = suggest_min_label(ci, ii, ai)
    try:
        if LABEL_ORDER.index(label) < LABEL_ORDER.index(min_label):
            reasons.append(f"Label '{label}' below minimum '{min_label}' required by CIA")
    except ValueError:
        reasons.append("Unsupported label")
    return (len(reasons) == 0), reasons
