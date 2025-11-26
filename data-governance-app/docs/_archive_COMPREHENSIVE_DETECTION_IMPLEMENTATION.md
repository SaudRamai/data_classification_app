# Comprehensive Sensitive Data Detection Implementation

## Overview

This document describes the comprehensive multi-layered sensitive data detection implementation in the existing `ai_classification_service.py`. The implementation follows a 13-step detection logic that combines rule-based, pattern-based, and AI-based detection methods.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Governance Configuration                    │
│  (SENSITIVITY_WEIGHTS, THRESHOLDS, PATTERNS, KEYWORDS)      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              1️⃣ Configuration Loading                        │
│  - Load weights for detection methods                        │
│  - Load thresholds per category                              │
│  - Load patterns, keywords, bundles                          │
│  - Load compliance mappings                                  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              2️⃣ Metadata Collection                          │
│  - Identify tables and columns from INFORMATION_SCHEMA       │
│  - Fetch sample data for validation                          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         3️⃣ Rule-Based (Keyword) Detection                    │
│  - Match column names against keywords                        │
│  - Apply EXACT vs FUZZY matching                             │
│  - Calculate rule_score = keyword_weight × rule_weight       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         4️⃣ Pattern-Based Detection                           │
│  - Evaluate regex patterns on column names                   │
│  - Evaluate patterns on sample data                          │
│  - Apply adaptive thresholds based on sample size            │
│  - Calculate pattern_score = pattern_weight × pattern_weight │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         5️⃣ Semantic (AI-Based) Detection                     │
│  - Generate embeddings for column context                    │
│  - Compare with category embeddings                          │
│  - Calculate similarity scores                               │
│  - Calculate ai_score = similarity × ai_weight               │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         6️⃣ Composite Scoring Engine                          │
│  - Combine all detection scores                              │
│  - COMPOSITE_SCORE = rule_score + pattern_score + ai_score   │
│  - Normalize to 0-1 scale                                    │
│  - Apply bundle boosts if applicable                         │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│    7️⃣ Confidence Level & Sensitivity Determination           │
│  - Compare composite_score to category threshold             │
│  - HIGH: score >= threshold                                  │
│  - MEDIUM: score >= (threshold × 0.6)                        │
│  - LOW: score < (threshold × 0.6)                            │
│  - Assign sensitivity level from dominant category           │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         8️⃣ Table-Level Aggregation                           │
│  - Aggregate column detections per table                     │
│  - Calculate table confidence = avg/max of column scores     │
│  - Identify dominant category for table                      │
│  - Determine if table needs review                           │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│    9️⃣ Persistence to AI_ASSISTANT_SENSITIVE_ASSETS           │
│  - Write column-level detections                             │
│  - Include all detection metadata                            │
│  - Append to history table for versioning                    │
│  - MERGE to handle updates                                   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         🔁 10️⃣ Review & Feedback Loop                         │
│  - Present results to data stewards                          │
│  - Allow approve/reject/reclassify                           │
│  - Log feedback to SENSITIVE_FEEDBACK                        │
│  - Update model based on feedback                            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         🔒 12️⃣ Governance & Auditing                          │
│  - Log all actions to CLASSIFICATION_AUDIT                   │
│  - Track configuration changes                               │
│  - Provide full traceability                                 │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Details

### 1️⃣ Configuration Loading

**Location**: `ai_classification_service.py::load_sensitivity_config()`

**Enhancements Made**:
- Added loading of `SENSITIVITY_WEIGHTS` table
- Added loading of `SENSITIVITY_THRESHOLDS` table
- Maps weight sources to standard keys (rule, pattern, ai, composite, ml)
- Loads category-specific thresholds for detection

**Configuration Structure**:
```python
{
    "patterns": {...},           # Regex patterns by category
    "keywords": {...},           # Keywords by category
    "categories": {...},         # CIA scores per category
    "bundles": [...],            # Multi-column bundles
    "compliance_mapping": {...}, # Category → Framework → Policy
    "model_metadata": {...},     # Model configuration
    "weights_table": {           # Detection method weights
        "rule": 0.3,
        "pattern": 0.4,
        "ai": 0.2,
        "ml": 0.1
    },
    "thresholds": {              # Category-specific thresholds
        "PII": 0.7,
        "Financial": 0.8,
        "PHI": 0.9
    }
}
```

### 2️⃣ Metadata Collection

**Location**: `ai_classification_service.py::get_column_metadata()`, `get_sample_data()`

**Existing Implementation**:
- Queries `
ATION_SCHEMA.COLUMNS` for metadata
- Fetches sample data using `SAMPLE` clause
- Supports dynamic sampling strategies

### 3️⃣ Rule-Based (Keyword) Detection

**Location**: `ai_classification_service.py::detect_sensitive_columns()` (lines 3773-3797)

**Implementation**:
```python
# Tokenize column name
parts = [p for p in re.split(r"[^A-Za-z0-9]+", up) if p]

# Match against keywords
for kw in dyn_keywords:
    tok_up = str(kw.get("token") or kw.get("keyword") or "").upper()
    mt = str(kw.get("match_type") or "FUZZY").upper()
    
    # EXACT requires whole-token match
    is_exact_match = tok_up in parts
    # FUZZY allows substring
    is_fuzzy_ok = (len(tok_up) > 2 and tok_up in up)
    
    matched = is_exact_match if mt == "EXACT" else (is_exact_match or is_fuzzy_ok)
    
    if matched:
        categories.append(str(kw.get("category")))
        name_hits += 1
        token_hits.append(tok_up)
```

**Scoring**:
- Each keyword match contributes to `token_score_dict[category]`
- EXACT matches get weight 1.0, FUZZY matches get weight 0.6
- Final rule_score = token_score × rule_weight (from config)

### 4️⃣ Pattern-Based Detection

**Location**: `ai_classification_service.py::detect_sensitive_columns()` (lines 3798-3847)

**Implementation**:
```python
# Pre-compile patterns by category
compiled_patterns: Dict[str, List[Tuple[str, Any, bool]]] = {}
for p in dyn_patterns:
    rx = str(p.get("regex") or "").strip()
    cat = str(p.get("category") or "").strip()
    cre = re.compile(rx)
    compiled_patterns.setdefault(cat, []).append((rx, cre, numeric_hint))

# Adaptive threshold based on sample size
if row_count < 500:
    threshold = 0.05
elif row_count < 2000:
    threshold = 0.10
else:
    threshold = 0.15

# Evaluate patterns on sample data
for cat, lst in compiled_patterns.items():
    cat_matched_rows = 0
    for v in series_vals:
        if any(cre.search(str(v)) for (_rx_str, cre, _nhint) in lst):
            cat_matched_rows += 1
    
    regex_hits_ratio = float(cat_matched_rows) / float(max(1, row_count))
    if regex_hits_ratio >= threshold:
        categories.append(cat)
```

**Scoring**:
- Counts rows matching any pattern in category
- Applies adaptive threshold based on sample size
- pattern_score = (match_ratio / threshold) × pattern_weight

### 5️⃣ Semantic (AI-Based) Detection

**Location**: `ai_classification_service.py::detect_sensitive_columns()` (lines 3941-3973)

**Implementation**:
```python
# Batch-encode column names
if self._embedding_backend != 'none' and self._embedder is not None:
    norm_names = [re.sub(r"[\W_]+", " ", cname.lower()).strip() 
                  for cname in column_names]
    vecs = self._embedder.encode(norm_names, normalize_embeddings=True)
    
    # Compare with category embeddings
    for cat, items in self._category_embeds.items():
        cat_best = 0.0
        for _tok, v in items:
            sc = float(np.dot(vec, v) / (np.linalg.norm(vec) * np.linalg.norm(v)))
            if sc > cat_best:
                cat_best = sc
        
        if cat_best > 0:
            semantic_score_dict[cat] = cat_best
```

**Scoring**:
- Uses sentence transformers for embeddings
- Calculates cosine similarity with category embeddings
- ai_score = similarity_score × ai_weight

### 6️⃣ Composite Scoring Engine

**Location**: `ai_classification_service.py::detect_sensitive_columns()` (lines 3998-4016)

**Implementation**:
```python
# Aggregate per-category scores
agg_scores: Dict[str, float] = {}
for cat in all_detected_categories:
    agg_scores[cat] = (
        w_regex * float(regex_score_dict.get(cat, 0.0)) +
        w_token * float(token_score_dict.get(cat, 0.0)) +
        w_sem * float(semantic_score_dict.get(cat, 0.0)) +
        w_ml * float(max(ml_score, zsc_score_dict.get(cat, 0.0)))
    )

# Overall confidence
conf = (
    w_regex * regex_signal +
    w_token * token_signal +
    w_sem * sem_sig +
    w_ml * ml_sig
)

# Apply bundle boost
if bundle_boost:
    conf += max(0.0, min(bundle_max_boost, max(boosts)))

# Normalize to 0-1
conf = max(0.0, min(1.0, conf))
```

### 7️⃣ Confidence Level Determination

**Location**: `ai_classification_service.py::detect_sensitive_columns()` (returns confidence as 0-100)

**Logic**:
```python
threshold = config.thresholds.get(dominant_category, 0.7)

if composite_score >= threshold:
    confidence_level = "HIGH"
elif composite_score >= (threshold * 0.6):
    confidence_level = "MEDIUM"
else:
    confidence_level = "LOW"
```

### 8️⃣ Table-Level Aggregation

**Location**: `ai_classification_service.py::aggregate_table_sensitivity()`

**Implementation**:
```python
def aggregate_table_sensitivity(self, column_features: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Weighted by confidence
    sums = defaultdict(float)
    counts = defaultdict(int)
    
    for r in column_features:
        conf = float(int(r.get("confidence", 0))) / 100.0
        cats = list(r.get("categories") or [])
        
        for c in cats:
            sums[c] += conf
            counts[c] += 1
    
    # Table score = average of column scores
    col_scores = [float(int(r.get("confidence", 0))) / 100.0 for r in column_features]
    score = sum(col_scores) / max(1, len(col_scores))
    
    # Dominant category by total weighted sum
    dominant = sorted(sums.items(), key=lambda kv: (-kv[1], -counts[kv[0]]))[0][0]
    
    return {
        "table_sensitivity_score": round(score, 2),
        "dominant_table_category": dominant,
        "table_categories": sorted(sums.keys(), key=lambda k: -sums[k])
    }
```

### 9️⃣ Persistence to AI_ASSISTANT_SENSITIVE_ASSETS

**Location**: `comprehensive_detection_methods.py::persist_to_ai_assistant_assets()`

**Schema**:
```sql
CREATE TABLE AI_ASSISTANT_SENSITIVE_ASSETS (
    RUN_ID STRING,
    DATABASE_NAME STRING,
    SCHEMA_NAME STRING,
    TABLE_NAME STRING,
    COLUMN_NAME STRING,
    DETECTED_CATEGORY STRING,
    DETECTED_TYPE STRING,
    COMBINED_CONFIDENCE FLOAT,
    CONFIDENCE_LEVEL STRING,           -- HIGH, MEDIUM, LOW
    METHODS_USED STRING,               -- RULE_BASED,PATTERN_BASED,AI_BASED
    COMPLIANCE_TAGS STRING,            -- Comma-separated categories
    DETECTION_REASON STRING,           -- Evidence summary
    RULE_SCORE FLOAT,
    PATTERN_SCORE FLOAT,
    AI_SCORE FLOAT,
    COMPOSITE_SCORE FLOAT,
    MATCHED_KEYWORDS STRING,
    MATCHED_PATTERNS STRING,
    CIA_SCORES STRING,                 -- C:3/I:2/A:1
    RECOMMENDED_POLICIES STRING,       -- MASKING,ENCRYPTION,etc
    NEED_REVIEW BOOLEAN,
    LAST_SCAN_TS TIMESTAMP_NTZ,
    PRIMARY KEY (DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME)
);
```

**Implementation**:
- Uses MERGE to handle updates
- Inserts into history table for versioning
- Calculates recommended policies based on category
- Determines need_review flag

### 🔁 10️⃣ Review & Feedback Loop

**Location**: `ai_classification_service.py::record_feedback()`, `load_feedback_from_snowflake()`

**Existing Implementation**:
- Records user corrections to `SENSITIVE_FEEDBACK`
- Logs immutable audit trail to `SENSITIVE_FEEDBACK_LOG`
- Applies feedback overrides in `_apply_feedback_overrides()`
- Supports actions: suppress, set_categories, set_confidence

### 🔒 12️⃣ Governance & Auditing

**Location**: `comprehensive_detection_methods.py::log_to_classification_audit()`

**Implementation**:
```python
def log_to_classification_audit(service, action, resource_id, details):
    audit_details = {
        'action': action,
        'resource_id': resource_id,
        'timestamp': datetime.utcnow().isoformat(),
        'user': user_id,
        **details
    }
    
    INSERT INTO CLASSIFICATION_AUDIT (
        RESOURCE_ID, ACTION, DETAILS, CREATED_AT
    ) VALUES (
        resource_id, action, PARSE_JSON(audit_details), CURRENT_TIMESTAMP()
    )
```

**Audit Actions**:
- `DETECTION_RUN`: Log each detection execution
- `CONFIG_CHANGE`: Log configuration updates
- `THRESHOLD_UPDATE`: Log threshold modifications
- `FEEDBACK_APPLIED`: Log user corrections

## Output Schema

### Column-Level Output

```python
{
    'column': 'EMAIL_ADDRESS',
    'categories': ['PII', 'Contact'],
    'dominant_category': 'PII',
    'confidence': 85,                    # 0-100
    'confidence_level': 'HIGH',          # HIGH/MEDIUM/LOW
    'suggested_cia': {'C': 3, 'I': 2, 'A': 1},
    'bundle_boost': False,
    'related_columns': ['PHONE', 'NAME'],
    'bundles_detected': [],
    'regex_hits': 5,
    'pattern_ids': ['EMAIL_PATTERN'],
    'token_hits': ['EMAIL', 'ADDRESS'],
    'ml_score': 0.7,
    'semantic_scores': {'PII': 0.85, 'Contact': 0.72},
    'semantic_top_category': 'PII',
    'semantic_top_confidence': 0.85,
    'detection_methods': ['RULE_BASED', 'PATTERN_BASED', 'AI_BASED'],
    'detection_reason': 'Keywords: EMAIL,ADDRESS; Patterns: EMAIL_PATTERN; Semantic: PII',
    'compliance_frameworks': ['GDPR', 'CCPA'],
    'recommended_policies': ['MASKING', 'ENCRYPTION', 'ACCESS_CONTROL'],
    'need_review': False
}
```

### Table-Level Output

```python
{
    'table_name': 'CUSTOMERS',
    'table_sensitivity_score': 0.78,
    'dominant_table_category': 'PII',
    'table_categories': ['PII', 'Financial', 'Contact'],
    'sensitive_columns': [...],          # List of column detections
    'compliance_frameworks': ['GDPR', 'CCPA', 'PCI DSS'],
    'recommended_policies': ['MASKING', 'ENCRYPTION', 'AUDIT_LOGGING'],
    'need_review': False
}
```

## Usage Example

```python
from src.services.ai_classification_service import AIClassificationService
from src.services.comprehensive_detection_methods import persist_to_ai_assistant_assets, log_to_classification_audit
from datetime import datetime

# Initialize service
service = AIClassificationService()
service.use_snowflake = True

# Load configuration
config = service.load_sensitivity_config(force_refresh=True)

# Run detection on a table
table_name = "DATABASE.SCHEMA.CUSTOMERS"
detections = service.detect_sensitive_columns(table_name, sample_size=200)

# Aggregate to table level
table_metrics = service.aggregate_table_sensitivity(detections)

# Persist results
run_id = datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
persist_to_ai_assistant_assets(
    service, 
    run_id=run_id,
    column_detections=detections,
    database="DATABASE",
    schema_name="SCHEMA",
    table_name="CUSTOMERS"
)

# Log audit trail
log_to_classification_audit(
    service,
    action="DETECTION_RUN",
    resource_id=table_name,
    details={
        'run_id': run_id,
        'columns_scanned': len(detections),
        'sensitive_columns': len([d for d in detections if d['confidence'] > 50]),
        'table_score': table_metrics['table_sensitivity_score']
    }
)
```

## Configuration Tables

### SENSITIVITY_WEIGHTS

Controls the weight of each detection method in the composite score.

```sql
CREATE TABLE SENSITIVITY_WEIGHTS (
    WEIGHT_ID STRING PRIMARY KEY,
    SOURCE STRING,              -- RULE_BASED, PATTERN_BASED, AI_BASED, COMPOSITE
    WEIGHT FLOAT,               -- 0.0 to 1.0
    DESCRIPTION STRING,
    IS_ACTIVE BOOLEAN
);

-- Example data
INSERT INTO SENSITIVITY_WEIGHTS VALUES
('W1', 'RULE_BASED', 0.3, 'Keyword matching weight', TRUE),
('W2', 'PATTERN_BASED', 0.4, 'Regex pattern weight', TRUE),
('W3', 'AI_BASED', 0.2, 'Semantic similarity weight', TRUE),
('W4', 'ML', 0.1, 'Statistical ML weight', TRUE);
```

### SENSITIVITY_THRESHOLDS

Defines detection thresholds per category.

```sql
CREATE TABLE SENSITIVITY_THRESHOLDS (
    THRESHOLD_ID STRING PRIMARY KEY,
    CATEGORY_NAME STRING,
    THRESHOLD_VALUE FLOAT,      -- 0.0 to 1.0
    APPLIES_TO STRING,          -- DETECTION, CLASSIFICATION, REVIEW
    IS_ACTIVE BOOLEAN
);

-- Example data
INSERT INTO SENSITIVITY_THRESHOLDS VALUES
('T1', 'PII', 0.7, 'DETECTION', TRUE),
('T2', 'PHI', 0.9, 'DETECTION', TRUE),
('T3', 'Financial', 0.8, 'DETECTION', TRUE);
```

### SENSITIVE_KEYWORDS

Keywords for rule-based detection.

```sql
CREATE TABLE SENSITIVE_KEYWORDS (
    KEYWORD_ID STRING PRIMARY KEY,
    CATEGORY_ID STRING,
    KEYWORD_STRING STRING,
    MATCH_TYPE STRING,          -- EXACT, FUZZY
    SENSITIVITY_WEIGHT FLOAT,
    PRIORITY INT,
    IS_ACTIVE BOOLEAN
);
```

### SENSITIVE_PATTERNS

Regex patterns for pattern-based detection.

```sql
CREATE TABLE SENSITIVE_PATTERNS (
    PATTERN_ID STRING PRIMARY KEY,
    CATEGORY_ID STRING,
    PATTERN_NAME STRING,
    PATTERN_STRING STRING,      -- Regex pattern
    SENSITIVITY_WEIGHT FLOAT,
    PRIORITY INT,
    IS_ACTIVE BOOLEAN
);
```

### COMPLIANCE_MAPPING

Maps categories to compliance frameworks and policies.

```sql
CREATE TABLE COMPLIANCE_MAPPING (
    MAPPING_ID STRING PRIMARY KEY,
    CATEGORY_ID STRING,
    COMPLIANCE_STANDARD STRING,  -- GDPR, CCPA, HIPAA, PCI DSS, etc.
    DESCRIPTION STRING,          -- Policy description
    PRIORITY INT,
    IS_ACTIVE BOOLEAN
);
```

## Key Features

✅ **Multi-Layered Detection**: Combines rule-based, pattern-based, and AI-based methods  
✅ **Config-Driven**: All detection logic driven by governance tables  
✅ **Weighted Scoring**: Configurable weights for each detection method  
✅ **Adaptive Thresholds**: Category-specific and sample-size-adaptive thresholds  
✅ **Comprehensive Metadata**: Full evidence trail for each detection  
✅ **Compliance Mapping**: Automatic mapping to frameworks and policies  
✅ **Audit Trail**: Complete governance and audit logging  
✅ **Feedback Loop**: User corrections improve future detections  
✅ **Version Control**: History tables track all changes  
✅ **Explainable**: Detection reasons provided for transparency  

## Next Steps

1. **Enable Semantic Detection**: Set `enable_semantic: true` in model metadata
2. **Tune Weights**: Adjust weights in `SENSITIVITY_WEIGHTS` based on accuracy
3. **Refine Thresholds**: Update `SENSITIVITY_THRESHOLDS` per category
4. **Add Keywords/Patterns**: Populate `SENSITIVE_KEYWORDS` and `SENSITIVE_PATTERNS`
5. **Configure Compliance**: Map categories in `COMPLIANCE_MAPPING`
6. **Test Detection**: Run on sample tables and review results
7. **Collect Feedback**: Use feedback loop to improve accuracy
8. **Monitor Audit Logs**: Review `CLASSIFICATION_AUDIT` for governance

## Troubleshooting

### Low Detection Accuracy
- Check if weights are properly configured in `SENSITIVITY_WEIGHTS`
- Verify patterns and keywords are active and correct
- Review thresholds - may be too high/low
- Enable semantic detection for better context understanding

### Missing Detections
- Ensure `IS_ACTIVE = TRUE` for patterns/keywords
- Check if sample size is sufficient
- Verify column names match keyword patterns
- Review adaptive threshold logic

### False Positives
- Increase category thresholds in `SENSITIVITY_THRESHOLDS`
- Add negative patterns (if implemented)
- Use feedback loop to suppress false categories
- Refine keyword match types (EXACT vs FUZZY)

### Performance Issues
- Reduce sample size for large tables
- Use stratified sampling for better performance
- Enable caching in `load_sensitivity_config`
- Batch process tables instead of real-time

## References

- **Service**: `src/services/ai_classification_service.py`
- **Extensions**: `src/services/comprehensive_detection_methods.py`
- **Detection Method**: `detect_sensitive_columns()` (line 3523)
- **Config Loading**: `load_sensitivity_config()` (line 1732)
- **Table Aggregation**: `aggregate_table_sensitivity()` (line 153)
- **Persistence**: `persist_to_ai_assistant_assets()` (comprehensive_detection_methods.py)
- **Audit Logging**: `log_to_classification_audit()` (comprehensive_detection_methods.py)
