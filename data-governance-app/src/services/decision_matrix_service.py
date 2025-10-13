"""
Decision Matrix Service
- Computes risk level from CIA
- Suggests minimum label from CIA
- Validates guardrails between chosen label and CIA
"""
from typing import Tuple, List, Optional

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


def validate(
    label: str,
    c: int,
    i: int,
    a: int,
    *,
    categories: Optional[List[str]] = None,
    regulatory_level: Optional[str] = None,
) -> Tuple[bool, List[str]]:
    """
    Validate CIA bounds (0..3), enforce policy floors for special categories, and ensure label meets minimum implied by CIA.

    - categories: optional list like ["PII", "Financial", "Proprietary"]
    - regulatory_level: optional string like "None"|"Some"|"Multiple"|"Strict"

    Backward compatible: If label is not a known classification label (e.g., "Low" risk), skip label-vs-minimum check.
    """
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

    # Enforce special-category minimums (policy Appendix 5.5):
    min_c_floor = 0
    cats = {str(x).strip().lower() for x in (categories or []) if str(x).strip()}
    if any(k in cats for k in {"pii", "financial", "proprietary"}):
        min_c_floor = max(min_c_floor, 2)  # at least C2
    rl = (regulatory_level or "").strip().lower()
    if rl == "multiple":
        min_c_floor = max(min_c_floor, 2)
    if rl == "strict":
        min_c_floor = max(min_c_floor, 3)
    if ci < min_c_floor:
        reasons.append(f"Confidentiality C{ci} below policy minimum C{min_c_floor} for special categories/regulatory context")

    # Minimum label from CIA
    min_label = suggest_min_label(ci, ii, ai)
    try:
        # Only compare if provided label is recognized; otherwise, skip this check for backward compatibility
        if label in LABEL_ORDER and LABEL_ORDER.index(label) < LABEL_ORDER.index(min_label):
            reasons.append(f"Label '{label}' below minimum '{min_label}' required by CIA")
    except Exception:
        # Non-fatal: tolerate non-standard labels (e.g., risk terms)
        pass

    return (len(reasons) == 0), reasons
