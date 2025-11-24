# Metadata-Driven Classification System

## 🎯 Overview

The classification system is now **100% metadata-driven** with **ZERO hardcoded categories, keywords, or patterns**. All classification rules are loaded dynamically from Snowflake governance tables.

---

## 📊 Governance Tables

### 1. **SENSITIVITY_CATEGORIES**

Defines all sensitivity categories and their detection rules.

**Schema:**
```sql
CREATE TABLE SENSITIVITY_CATEGORIES (
    CATEGORY_ID NUMBER PRIMARY KEY,
    CATEGORY_NAME VARCHAR,           -- e.g., "PII", "SOX", "SOC2"
    DESCRIPTION VARCHAR,              -- Category description
    DETECTION_THRESHOLD FLOAT,        -- Minimum score to classify (0.0-1.0)
    SENSITIVITY_WEIGHT FLOAT,         -- Category importance multiplier
    IS_ACTIVE BOOLEAN                 -- Enable/disable category
);
```

**Example Data:**
```sql
INSERT INTO SENSITIVITY_CATEGORIES VALUES
(1, 'PII', 'Personally Identifiable Information', 0.65, 1.2, TRUE),
(2, 'SOX', 'Financial Reporting Data', 0.65, 1.0, TRUE),
(3, 'SOC2', 'Security and Compliance Data', 0.65, 1.1, TRUE);
```

**Key Fields:**
- `DETECTION_THRESHOLD`: Minimum confidence score required (default: 0.65)
- `SENSITIVITY_WEIGHT`: Multiplier for category importance (default: 1.0)
- `IS_ACTIVE`: Set to FALSE to disable a category without deleting it

---

### 2. **SENSITIVE_KEYWORDS**

Maps keywords to categories for keyword-based detection.

**Schema:**
```sql
CREATE TABLE SENSITIVE_KEYWORDS (
    KEYWORD_ID NUMBER PRIMARY KEY,
    CATEGORY_ID NUMBER REFERENCES SENSITIVITY_CATEGORIES,
    KEYWORD_STRING VARCHAR,           -- Keyword to match
    KEYWORD_WEIGHT FLOAT,             -- Keyword importance (optional)
    IS_ACTIVE BOOLEAN                 -- Enable/disable keyword
);
```

**Example Data:**
```sql
INSERT INTO SENSITIVE_KEYWORDS VALUES
(1, 1, 'email', 1.0, TRUE),
(2, 1, 'ssn', 1.2, TRUE),
(3, 1, 'social security number', 1.2, TRUE),
(4, 2, 'revenue', 1.0, TRUE),
(5, 2, 'general ledger', 1.1, TRUE),
(6, 3, 'password', 1.0, TRUE),
(7, 3, 'encryption key', 1.2, TRUE);
```

**Matching Logic:**
- Word boundary matching: `\b{keyword}\b` (preferred)
- Substring matching: fallback if regex fails
- Case-insensitive

---

### 3. **SENSITIVE_PATTERNS**

Defines regex patterns for pattern-based detection.

**Schema:**
```sql
CREATE TABLE SENSITIVE_PATTERNS (
    PATTERN_ID NUMBER PRIMARY KEY,
    CATEGORY_ID NUMBER REFERENCES SENSITIVITY_CATEGORIES,
    PATTERN_STRING VARCHAR,           -- Regex pattern
    PATTERN_DESCRIPTION VARCHAR,      -- Human-readable description
    IS_ACTIVE BOOLEAN                 -- Enable/disable pattern
);
```

**Example Data:**
```sql
INSERT INTO SENSITIVE_PATTERNS VALUES
(1, 1, '\b\d{3}-\d{2}-\d{4}\b', 'SSN Format (XXX-XX-XXXX)', TRUE),
(2, 1, '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email Address', TRUE),
(3, 1, '\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'Phone Number', TRUE),
(4, 2, '\b(revenue|expense|profit|loss)\b', 'Financial Terms', TRUE),
(5, 3, '\b(password|secret|key|token)\b', 'Security Terms', TRUE);
```

**Pattern Matching:**
- Uses Python `re.search()` with case-insensitive flag
- Supports full regex syntax
- Patterns are compiled and cached for performance

---

## 🔄 Classification Flow

### Step 1: Initialization

```python
def _init_local_embeddings():
    # Initialize E5-Large embeddings
    embedder = SentenceTransformer('intfloat/e5-large-v2')
    
    # Load ALL metadata from governance tables
    _load_metadata_driven_categories()
```

### Step 2: Load Categories

```python
def _load_metadata_driven_categories():
    # Query SENSITIVITY_CATEGORIES
    categories = query("""
        SELECT CATEGORY_NAME, DESCRIPTION, DETECTION_THRESHOLD, SENSITIVITY_WEIGHT
        FROM SENSITIVITY_CATEGORIES
        WHERE IS_ACTIVE = TRUE
    """)
    
    # Store thresholds and weights
    for cat in categories:
        _category_thresholds[cat.name] = cat.threshold
        _category_weights[cat.name] = cat.weight
```

### Step 3: Load Keywords

```python
# Query SENSITIVE_KEYWORDS
keywords = query("""
    SELECT c.CATEGORY_NAME, k.KEYWORD_STRING
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
""")

# Group by category
_category_keywords = {
    'PII': ['email', 'ssn', 'phone', ...],
    'SOX': ['revenue', 'ledger', ...],
    'SOC2': ['password', 'encryption', ...]
}
```

### Step 4: Load Patterns

```python
# Query SENSITIVE_PATTERNS
patterns = query("""
    SELECT c.CATEGORY_NAME, p.PATTERN_STRING
    FROM SENSITIVE_PATTERNS p
    JOIN SENSITIVITY_CATEGORIES c ON p.CATEGORY_ID = c.CATEGORY_ID
    WHERE p.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
""")

# Group by category
_category_patterns = {
    'PII': [r'\b\d{3}-\d{2}-\d{4}\b', ...],
    'SOX': [r'\b(revenue|expense)\b', ...],
    'SOC2': [r'\b(password|secret)\b', ...]
}
```

### Step 5: Build Embeddings

```python
for category, description in categories:
    # Combine description + top 50 keywords
    keywords = _category_keywords[category][:50]
    combined_text = f"{description} {' '.join(keywords)}"
    
    # Generate training examples
    examples = _generate_category_examples(category, combined_text)
    examples.extend(keywords[:20])  # Add keywords as examples
    
    # Create embedding centroid
    vectors = embedder.encode(examples, normalize_embeddings=True)
    centroid = np.mean(vectors, axis=0)
    centroid = centroid / np.linalg.norm(centroid)
    
    _category_centroids[category] = centroid
```

---

## 🔍 Column Classification

### Scoring Process

For each column, compute 4 scores:

#### 1. **Semantic Score** (50% weight)
```python
def _semantic_scores(column_context):
    # Embed column context
    vector = embedder.encode(column_context, normalize_embeddings=True)
    
    # Compute similarity to each category centroid
    for category, centroid in _category_centroids.items():
        similarity = np.dot(vector, centroid)
        semantic_scores[category] = (similarity + 1.0) / 2.0  # [-1,1] → [0,1]
```

#### 2. **Keyword Score** (25% weight)
```python
def _keyword_scores_metadata_driven(column_context):
    for category, keywords in _category_keywords.items():
        hits = 0
        for keyword in keywords:
            if re.search(r'\b' + keyword + r'\b', column_context, re.I):
                hits += 1
        
        if hits > 0:
            score = min(1.0, 0.3 + (hits * 0.15))  # Base 0.3 + 15% per hit
            keyword_scores[category] = score
```

#### 3. **Pattern Score** (15% weight)
```python
def _pattern_scores(column_context):
    for category, patterns in _category_patterns.items():
        matches = 0
        for pattern in patterns:
            if re.search(pattern, column_context, re.I):
                matches += 1
        
        if matches > 0:
            pattern_scores[category] = min(1.0, 0.4 + (matches * 0.2))
```

#### 4. **Governance Score** (10% weight)
```python
def _gov_semantic_scores(column_context):
    # Query pre-classified data from governance tables
    # (if available)
    ...
```

### Ensemble Scoring

```python
for category in all_categories:
    ensemble_score = (
        0.50 * semantic_scores[category] +
        0.25 * keyword_scores[category] +
        0.15 * pattern_scores[category] +
        0.10 * governance_scores[category]
    )
    
    # Apply category-specific weight
    weighted_score = ensemble_score * _category_weights[category]
    
    # Check against category threshold
    threshold = _category_thresholds[category]
    if weighted_score >= threshold:
        final_scores[category] = weighted_score
```

---

## ✅ Validation Rules

### Rule 1: Category Threshold

```python
threshold = _category_thresholds.get(category, 0.65)
if score < threshold:
    EXCLUDE  # Score too low
```

### Rule 2: Multi-Signal Validation

```python
strong_signals = sum([
    semantic_score >= 0.40,
    keyword_score >= 0.40,
    pattern_score >= 0.40,
    governance_score >= 0.40
])

if strong_signals < 2:
    EXCLUDE  # Need at least 2 strong signals
```

### Rule 3: Minimum Semantic Evidence

```python
if semantic_score < 0.35:
    EXCLUDE  # Avoid keyword-only false positives
```

### Rule 4: Operational Column Filter

```python
if is_operational_column(col_name, col_type):
    if score < 0.85:
        EXCLUDE  # Operational columns need very high confidence
```

---

## 🎛️ Configuration Examples

### Example 1: Add New Category

```sql
-- Add "HIPAA" category
INSERT INTO SENSITIVITY_CATEGORIES VALUES
(4, 'HIPAA', 'Health Insurance Portability and Accountability Act data', 0.70, 1.3, TRUE);

-- Add keywords
INSERT INTO SENSITIVE_KEYWORDS VALUES
(100, 4, 'patient', 1.0, TRUE),
(101, 4, 'diagnosis', 1.1, TRUE),
(102, 4, 'medical record', 1.2, TRUE),
(103, 4, 'health information', 1.1, TRUE);

-- Add patterns
INSERT INTO SENSITIVE_PATTERNS VALUES
(10, 4, '\b(patient|diagnosis|treatment)\b', 'Medical Terms', TRUE);
```

**Result:** System automatically detects HIPAA data without code changes!

### Example 2: Adjust Detection Sensitivity

```sql
-- Make PII detection stricter
UPDATE SENSITIVITY_CATEGORIES
SET DETECTION_THRESHOLD = 0.75
WHERE CATEGORY_NAME = 'PII';

-- Make SOX detection more lenient
UPDATE SENSITIVITY_CATEGORIES
SET DETECTION_THRESHOLD = 0.60
WHERE CATEGORY_NAME = 'SOX';
```

### Example 3: Disable Category Temporarily

```sql
-- Disable SOC2 classification
UPDATE SENSITIVITY_CATEGORIES
SET IS_ACTIVE = FALSE
WHERE CATEGORY_NAME = 'SOC2';
```

### Example 4: Add Domain-Specific Keywords

```sql
-- Add company-specific PII keywords
INSERT INTO SENSITIVE_KEYWORDS VALUES
(200, 1, 'employee_id', 1.0, TRUE),
(201, 1, 'badge_number', 1.0, TRUE),
(202, 1, 'internal_email', 1.1, TRUE);
```

---

## 📈 Benefits

### 1. **Zero Hardcoding**
- ✅ No hardcoded categories
- ✅ No hardcoded keywords
- ✅ No hardcoded patterns
- ✅ All rules in database

### 2. **Dynamic Configuration**
- ✅ Add categories without code changes
- ✅ Adjust thresholds in real-time
- ✅ Enable/disable rules on-the-fly
- ✅ A/B test different configurations

### 3. **Business Control**
- ✅ Data stewards manage rules
- ✅ No developer dependency
- ✅ Audit trail in database
- ✅ Version control via SQL

### 4. **Scalability**
- ✅ Support unlimited categories
- ✅ Handle thousands of keywords
- ✅ Complex regex patterns
- ✅ Multi-tenant configurations

### 5. **Compliance**
- ✅ Document classification rules
- ✅ Prove rule consistency
- ✅ Track rule changes
- ✅ Regulatory audit support

---

## 🔧 Maintenance

### Adding Keywords

```sql
-- Find category ID
SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII';

-- Add keyword
INSERT INTO SENSITIVE_KEYWORDS (CATEGORY_ID, KEYWORD_STRING, IS_ACTIVE)
VALUES (1, 'new_keyword', TRUE);
```

### Testing Changes

```sql
-- Test with inactive flag first
INSERT INTO SENSITIVE_KEYWORDS (CATEGORY_ID, KEYWORD_STRING, IS_ACTIVE)
VALUES (1, 'test_keyword', FALSE);

-- Run classification, verify results

-- Activate if good
UPDATE SENSITIVE_KEYWORDS SET IS_ACTIVE = TRUE WHERE KEYWORD_STRING = 'test_keyword';
```

### Monitoring

```sql
-- Count active rules per category
SELECT 
    c.CATEGORY_NAME,
    COUNT(DISTINCT k.KEYWORD_ID) as keyword_count,
    COUNT(DISTINCT p.PATTERN_ID) as pattern_count
FROM SENSITIVITY_CATEGORIES c
LEFT JOIN SENSITIVE_KEYWORDS k ON c.CATEGORY_ID = k.CATEGORY_ID AND k.IS_ACTIVE = TRUE
LEFT JOIN SENSITIVE_PATTERNS p ON c.CATEGORY_ID = p.CATEGORY_ID AND p.IS_ACTIVE = TRUE
WHERE c.IS_ACTIVE = TRUE
GROUP BY c.CATEGORY_NAME;
```

---

## 🚀 Migration Guide

### From Hardcoded to Metadata-Driven

**Before:**
```python
# Hardcoded in Python
CATEGORIES = {
    'PII': ['email', 'ssn', 'phone'],
    'SOX': ['revenue', 'ledger'],
    'SOC2': ['password', 'encryption']
}
```

**After:**
```sql
-- Managed in Snowflake
INSERT INTO SENSITIVE_KEYWORDS VALUES
(1, 1, 'email', 1.0, TRUE),
(2, 1, 'ssn', 1.0, TRUE),
(3, 1, 'phone', 1.0, TRUE);
```

**Code Change:**
```python
# Old: Hardcoded
keywords = CATEGORIES['PII']

# New: Metadata-driven
keywords = _category_keywords['PII']  # Loaded from DB
```

---

## 📝 Summary

The metadata-driven classification system provides:

✅ **100% configurable** - All rules in Snowflake tables  
✅ **Zero hardcoding** - No Python constants  
✅ **Business-controlled** - Data stewards manage rules  
✅ **Audit-friendly** - All changes tracked in DB  
✅ **Scalable** - Unlimited categories and rules  
✅ **Flexible** - Real-time configuration changes  
✅ **Compliant** - Documented and traceable  

**Result:** A production-ready, enterprise-grade classification system that adapts to your organization's evolving data governance needs.
