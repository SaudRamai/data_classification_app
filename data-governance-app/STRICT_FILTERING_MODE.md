# AI Classification Pipeline - Strict Filtering Mode

## Overview
The AI Classification Pipeline has been updated to implement **strict filtering** for sensitivity classification. Only columns and tables that are **confidently mapped** to one of the three primary sensitivity categories (PII, SOX, or SOC2) are included in the output.

## Filtering Criteria

### Minimum Requirements for Inclusion
Both table-level and column-level classification now require:

1. **Category Validation**: The detected category MUST be one of:
   - `PII` (Personally Identifiable Information)
   - `SOX` (Sarbanes-Oxley Financial Data)
   - `SOC2` (Security & Compliance Data)

2. **Confidence Threshold**: The classification confidence MUST be >= **50%**

### Exclusion Criteria
Assets are **excluded** from results if:
- The detected category is not in {PII, SOX, SOC2}
- The confidence score is below 50%
- The category cannot be mapped to any of the three primary categories
- The asset has low sensitivity (e.g., generic metadata columns)

## Classification Behavior

### High-Confidence Detections (Glossary Map)
The Business Glossary Map provides **deterministic classification** for known sensitive terms:

| Term/Pattern | Category | Confidence |
|--------------|----------|------------|
| ssn, social_security | PII | 99% |
| email, phone | PII | 99% |
| customer, employee | PII | 99% |
| salary, payroll, revenue | SOX | 99% |
| password, key, token | SOC2 | 99% |
| audit, security, access | SOC2 | 99% |

### AI-Driven Detections (Semantic + Keyword + Pattern)
For columns/tables not in the glossary, the system uses:
- **Semantic Similarity** (50% weight): E5-Large embeddings
- **Keyword Matching** (25% weight): Governance-driven keywords
- **Pattern Matching** (15% weight): Regex patterns (SSN, email, etc.)
- **Governance Scores** (10% weight): Additional governance metadata

**Ensemble Score Formula:**
```
score = (0.5 × semantic) + (0.25 × keyword) + (0.15 × pattern) + (0.10 × governance)
```

Only results with `score >= 0.50` are included.

## Output Structure

### Column-Level Results
```json
{
  "column": "SSN",
  "category": "PII",
  "confidence": 0.99,
  "confidence_pct": 99.0,
  "label": "Confidential",
  "multi_label_analysis": {
    "detected_categories": ["PII"],
    "reasoning": {
      "PII": "Semantic match (0.95); Keyword match (0.95)"
    }
  }
}
```

### Table-Level Results
```json
{
  "asset": {"table": "EMPLOYEES", "schema": "HR"},
  "category": "PII",
  "confidence": 0.99,
  "confidence_pct": 99.0,
  "label": "Confidential",
  "reasoning": ["SSN (Confidential)", "EMAIL (Restricted)"],
  "multi_label_analysis": {
    "detected_categories": ["PII"],
    "reasoning": {
      "PII": "Semantic match (0.92); Keyword match (0.88)"
    }
  }
}
```

## Logging

### Included Assets
```
✓ INCLUDED: SSN (PII, 99.0%)
✓ INCLUDED TABLE: HR.EMPLOYEES (PII, 95.2%)
```

### Filtered Assets
```
✗ FILTERED OUT: ID (category 'None' not in [PII, SOX, SOC2])
✗ FILTERED OUT: CREATED_AT (low confidence: 15.0% < 50%)
✗ FILTERED OUT TABLE: METADATA.CONFIG (category 'INTERNAL' not in [PII, SOX, SOC2])
```

## Benefits

1. **Reduced Noise**: Only high-value, sensitive data is flagged
2. **Audit Compliance**: Clear categorization into regulatory frameworks
3. **Actionable Results**: Every result requires attention (no false positives)
4. **Transparent Reasoning**: Multi-label analysis shows WHY each category was detected
5. **Deterministic Core**: Business-critical terms (SSN, Salary, Password) are always caught

## Fallback Behavior

If the AI model fails to load:
- **Glossary Map** still provides 99% confidence for known terms
- **Keyword Matching** provides coverage for governance-defined terms
- **Pattern Matching** catches structured data (SSN format, emails, etc.)

This ensures the system remains **audit-grade** even in degraded modes.
