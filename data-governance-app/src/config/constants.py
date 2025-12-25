"""
Application constants.
"""

# Classification levels
CLASSIFICATION_LEVELS = [
    "Public",
    "Internal",
    "Restricted",
    "Confidential"
]

# CIA Triad ratings (0-3)
CIA_RATINGS = [
    0,  # Low
    1,  # Medium
    2,  # High
    3   # Critical
]

# Compliance frameworks
COMPLIANCE_FRAMEWORKS = [
    "SOC2",
    "SOX",
    "GDPR",
    "CCPA"
]

# Data quality dimensions
DATA_QUALITY_DIMENSIONS = [
    "Completeness",
    "Accuracy",
    "Consistency",
    "Timeliness",
    "Validity",
    "Uniqueness"
]

# Default pagination settings
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 1000
