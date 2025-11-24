# AI Classification Pipeline - Complete Logic Explanation

## Overview

The AI Classification Pipeline is a metadata-driven system that automatically detects and classifies sensitive data in Snowflake databases. It identifies columns containing PII (Personally Identifiable Information), SOX (Financial Reporting Data), and SOC2 (Security & Compliance Data) using a combination of semantic analysis, keyword matching, pattern recognition, and governance rules.

---

## Phase 1: System Initialization

### Step 1.1: Load Embedding Model

When the system starts, it initializes the E5-Large-v2 embedding model:

**What happens:**
- The system loads the SentenceTransformer model 'intfloat/e5-large-v2'
- This model converts text into 1024-dimensional numerical vectors
- These vectors capture the semantic meaning of text
- The model is used to understand what columns actually contain, not just their names

**Why it matters:**
- A column named "user_id" might be generic, but if the description says "customer social security number", the semantic model catches this
- It understands context: "email" in "email_count" (metric) vs "customer_email" (PII)

### Step 1.2: Load Governance Metadata

The system queries three Snowflake governance tables to get ALL classification rules:

**SENSITIVITY_CATEGORIES:**
```
Loads: Category names (PII, SOX, SOC2)
       Descriptions (what each category means)
       Detection thresholds (minimum score to classify)
       Sensitivity weights (importance multipliers)
```

**SENSITIVE_KEYWORDS:**
```
Loads: Keywords for each category
       Keyword weights (how important each keyword is)
       Match types (EXACT, PARTIAL, FUZZY)
       Base scores for each keyword
```

**SENSITIVE_PATTERNS:**
```
Loads: Regex patterns (e.g., SSN format: \d{3}-\d{2}-\d{4})
       Pattern weights (importance of each pattern)
       Sensitivity types (STANDARD, HIGH, CRITICAL)
```

**Example of what gets loaded:**
```
Category: PII
  Threshold: 0.65 (need 65% confidence to classify)
  Weight: 1.2 (PII is 20% more important)
  
  Keywords:
    - "email" (weight: 1.2, match_type: EXACT, score: 1.0)
    - "ssn" (weight: 1.5, match_type: EXACT, score: 1.2)
    - "customer" (weight: 1.0, match_type: EXACT, score: 1.0)
  
  Patterns:
    - Email regex (weight: 1.5)
    - SSN regex (weight: 1.8)
    - Phone regex (weight: 1.0)
```

### Step 1.3: Build Category Centroids

For each category, the system creates a "semantic fingerprint":

**Process:**
1. Combine category description + top 50 keywords
2. Generate training examples (e.g., "contains email address", "stores customer email")
3. Convert all examples to vectors using E5-Large
4. Average all vectors to create a centroid
5. Normalize the centroid to unit length

**What is a centroid?**
- It's the "center point" in semantic space for that category
- Think of it as the "ideal representation" of PII, SOX, or SOC2
- When we analyze a column, we measure how close it is to each centroid

**Example:**
```
PII Centroid = Average of vectors for:
  - "personally identifiable information"
  - "customer data"
  - "contains email"
  - "stores ssn"
  - "phone number"
  - ... (all PII keywords and examples)
```

---

## Phase 2: Column Analysis

### Step 2.1: Fetch Column Metadata

For each table in Snowflake, the system retrieves:

**From INFORMATION_SCHEMA.COLUMNS:**
- Column name (e.g., "CUSTOMER_EMAIL")
- Data type (e.g., VARCHAR(255))
- Comment/description (if available)
- Ordinal position

**Sample Values:**
- Query: `SELECT column_name FROM table LIMIT 10`
- Gets actual data examples (e.g., ["john@example.com", "jane@company.com"])

**MIN/MAX Profiling (for numeric/date columns):**
- Gets range of values to understand data distribution
- Helps distinguish IDs from metrics

### Step 2.2: Build Rich Context

The system creates a comprehensive text representation of the column:

**Context Components:**
```
1. Fully Qualified Name: "DATABASE.SCHEMA.TABLE.COLUMN"
2. Data Type: "Type: VARCHAR(255)"
3. Comment: "Comment: Customer contact email address"
4. Sample Values: "Values: john@example.com, jane@company.com, ..."
5. Statistical Info: "Range: ..." (for numeric columns)
```

**Example Context String:**
```
"PROD_DB.CUSTOMER_SCHEMA.USERS.CUSTOMER_EMAIL | Type: VARCHAR(255) | 
Comment: Primary email address for customer communications | 
Values: john.doe@example.com, jane.smith@company.com, bob@test.org"
```

**Why this matters:**
- More context = better classification
- The model sees the full picture, not just the column name
- Sample values provide concrete evidence

---

## Phase 3: Multi-Signal Scoring

The system computes FOUR independent scores for each category:

### Signal 1: Semantic Score (50% weight)

**How it works:**
1. Convert the column context to a vector using E5-Large
2. Compute cosine similarity to each category centroid
3. Normalize similarity to 0-1 range
4. Apply aggressive boosting to push confident matches higher

**Formula:**
```
vector = embed(column_context)
similarity = dot_product(vector, category_centroid)
raw_score = (similarity + 1.0) / 2.0  # Convert [-1,1] to [0,1]

# Aggressive boosting
if raw_score >= 0.60:
    semantic_score = raw_score ^ 0.1  # Push to ~0.95+
elif raw_score >= 0.40:
    semantic_score = raw_score ^ 0.15  # Push to ~0.85+
elif raw_score >= 0.25:
    semantic_score = raw_score ^ 0.25  # Push to ~0.75+
else:
    semantic_score = raw_score ^ 1.5  # Reduce noise
```

**Example:**
```
Column: "CUSTOMER_EMAIL"
Context: "...email address...john@example.com..."

PII Centroid similarity: 0.89 → Semantic Score: 0.95
SOX Centroid similarity: 0.15 → Semantic Score: 0.10
SOC2 Centroid similarity: 0.20 → Semantic Score: 0.15
```

**Why 50% weight?**
- Semantic understanding is the most reliable signal
- It captures meaning, not just keywords
- Resistant to naming variations

### Signal 2: Keyword Score (25% weight)

**How it works:**
1. Load keywords for each category from SENSITIVE_KEYWORDS table
2. For each keyword, check if it matches the column context
3. Apply MATCH_TYPE from metadata:
   - EXACT: Word boundary match (`\bemail\b`)
   - PARTIAL: Substring match
   - FUZZY: Any word from keyword phrase
4. Weight each match by keyword_weight and match_quality
5. Normalize by number of keywords

**Formula:**
```
For each keyword in category:
    if matches(keyword, context, match_type):
        contribution = base_score × keyword_weight × match_quality
        total_score += contribution

normalized_score = (total_score / num_keywords) × category_weight
keyword_score = min(1.0, normalized_score)
```

**Example:**
```
Column: "CUSTOMER_EMAIL"
Context: "customer email address john@example.com"

PII Keywords:
  - "email" (EXACT match) → 1.0 × 1.2 × 1.0 = 1.2
  - "customer" (EXACT match) → 1.0 × 1.0 × 1.0 = 1.0
  Total: 2.2 / 2 keywords = 1.1 × 1.2 (category weight) = 1.32 → capped at 1.0

SOX Keywords:
  - No matches → 0.0
```

**Why 25% weight?**
- Keywords provide explicit evidence
- But can be fooled by similar words
- Lower weight than semantic to avoid false positives

### Signal 3: Pattern Score (15% weight)

**How it works:**
1. Load regex patterns for each category from SENSITIVE_PATTERNS table
2. Test each pattern against column context and sample values
3. Weight each match by pattern_weight
4. Normalize by number of patterns

**Formula:**
```
For each pattern in category:
    if regex_match(pattern, context):
        contribution = pattern_weight
        total_score += contribution

normalized_score = (total_score / num_patterns) × category_weight
pattern_score = min(1.0, normalized_score)
```

**Example:**
```
Column: "CUSTOMER_EMAIL"
Sample Values: ["john@example.com", "jane@company.com"]

PII Patterns:
  - Email regex: \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b
    → MATCH (weight: 1.5)
  Total: 1.5 / 1 pattern × 1.2 = 1.8 → capped at 1.0

SOX Patterns:
  - Financial terms regex → NO MATCH → 0.0
```

**Why 15% weight?**
- Patterns are very specific (high precision)
- But limited coverage (low recall)
- Good for confirming suspicions, not primary signal

### Signal 4: Governance Score (10% weight)

**How it works:**
1. Query governance tables for pre-classified columns
2. Check if column name matches business glossary
3. Use historical classification data if available

**Formula:**
```
if column in business_glossary:
    governance_score = glossary_confidence
elif column in historical_classifications:
    governance_score = historical_confidence
else:
    governance_score = 0.0
```

**Example:**
```
Column: "CUSTOMER_EMAIL"

Business Glossary:
  - "email" → PII (confidence: 0.80)
  
Governance Score: 0.80
```

**Why 10% weight?**
- Governance data is authoritative but may be incomplete
- Used to boost confidence when available
- Not relied upon as primary signal

---

## Phase 4: Ensemble Scoring

### Step 4.1: Combine Signals

The system combines all four scores using weighted averaging:

**Formula:**
```
ensemble_score = (
    0.50 × semantic_score +
    0.25 × keyword_score +
    0.15 × pattern_score +
    0.10 × governance_score
)
```

**Example:**
```
Column: "CUSTOMER_EMAIL" → PII Category

Semantic:    0.95 × 0.50 = 0.475
Keywords:    1.00 × 0.25 = 0.250
Patterns:    1.00 × 0.15 = 0.150
Governance:  0.80 × 0.10 = 0.080
                          -------
Ensemble Score:            0.955
```

### Step 4.2: Apply Category Weight

Each category has a sensitivity weight from the metadata:

**Formula:**
```
weighted_score = ensemble_score × category_weight
final_score = min(1.0, weighted_score)
```

**Example:**
```
PII Category Weight: 1.2
Final Score: 0.955 × 1.2 = 1.146 → capped at 1.0
```

---

## Phase 5: Strict Validation

The system applies SIX validation rules before including a column:

### Rule 1: Category Threshold Check

**Logic:**
```
detection_threshold = category_thresholds[category]  # From metadata

if final_score < detection_threshold:
    EXCLUDE  # Score too low
```

**Example:**
```
PII Threshold: 0.65
Final Score: 1.0

1.0 >= 0.65 → PASS ✓
```

### Rule 2: Multi-Signal Validation

**Logic:**
```
strong_signals = count([
    semantic_score >= 0.40,
    keyword_score >= 0.40,
    pattern_score >= 0.40,
    governance_score >= 0.40
])

if strong_signals < 2:
    EXCLUDE  # Need at least 2 strong signals
```

**Example:**
```
Semantic: 0.95 >= 0.40 ✓
Keywords: 1.00 >= 0.40 ✓
Patterns: 1.00 >= 0.40 ✓
Governance: 0.80 >= 0.40 ✓

Strong Signals: 4 >= 2 → PASS ✓
```

**Why this matters:**
- Prevents false positives from single-signal matches
- Requires corroborating evidence
- A column must be "obviously" sensitive, not just "maybe"

### Rule 3: Minimum Semantic Evidence

**Logic:**
```
if semantic_score < 0.35:
    EXCLUDE  # Avoid keyword-only false positives
```

**Example:**
```
Semantic: 0.95 >= 0.35 → PASS ✓
```

**Why this matters:**
- Prevents classifications based solely on keyword matches
- Ensures semantic meaning aligns with category
- Example: "customer_count" has keyword "customer" but semantically is a metric

### Rule 4: Operational Column Filter

**Logic:**
```
operational_patterns = [
    r'^id$', r'_id$', r'^.*_id$',  # IDs
    r'^created_at$', r'^updated_at$',  # Timestamps
    r'^is_', r'^has_', r'^flag_',  # Flags
    r'^status$', r'^state$',  # Status fields
]

operational_keywords = {
    'quantity', 'qty', 'amount', 'count', 'total',
    'price', 'cost', 'rate', 'discount',
    'order', 'transaction', 'product', 'item'
}

if matches_operational_pattern(col_name):
    if final_score < 0.85:
        EXCLUDE  # Operational columns need very high confidence
```

**Example:**
```
Column: "CUSTOMER_EMAIL"
Not operational → PASS ✓

Column: "ORDER_ID"
Operational pattern: "_id$"
Score: 0.70 < 0.85 → EXCLUDE ✗
```

**Why this matters:**
- Most columns are operational, not sensitive
- Prevents over-classification of business data
- Only includes operational columns if extremely confident

### Rule 5: Simple Numeric Filter

**Logic:**
```
if is_numeric_type(col_type):
    if all(matches(r'^\d{1,4}$', val) for val in sample_values):
        EXCLUDE  # Simple numbers (metrics, not IDs)
```

**Example:**
```
Column: "QUANTITY"
Type: NUMBER
Values: [5, 12, 3, 8, 15]
All simple 1-4 digit numbers → EXCLUDE ✗

Column: "SSN"
Type: NUMBER
Values: [123456789, 987654321]
9-digit numbers → NOT simple → Continue validation
```

### Rule 6: Business Glossary Override

**Logic:**
```
if column in business_glossary:
    INCLUDE  # Bypass all other validation
```

**Example:**
```
Column: "EIN"
Business Glossary: "EIN" → PII
Override: TRUE → INCLUDE ✓ (skip other rules)
```

**Why this matters:**
- Respects explicit business rules
- Data stewards can override AI decisions
- Ensures compliance with organizational policies

---

## Phase 6: Final Output

### Step 6.1: Determine Best Category

For each column, the system:

1. Computes scores for ALL categories (PII, SOX, SOC2)
2. Selects the category with the highest score
3. Checks if that score meets the category's threshold
4. Applies all validation rules
5. If all pass, includes the column in results

**Example:**
```
Column: "CUSTOMER_EMAIL"

Scores:
  PII:  1.00 (threshold: 0.65) ✓
  SOX:  0.10 (threshold: 0.65) ✗
  SOC2: 0.15 (threshold: 0.65) ✗

Best Category: PII (1.00)
Threshold Met: YES
Validation: ALL PASS

Result: INCLUDE as PII
```

### Step 6.2: Calculate CIA Levels

For each classified column, compute Confidentiality, Integrity, Availability:

**Logic:**
```
if category == 'PII':
    C = 3 (High)
    I = 2 (Medium)
    A = 2 (Medium)
elif category == 'SOX':
    C = 2 (Medium)
    I = 3 (High)
    A = 2 (Medium)
elif category == 'SOC2':
    C = 3 (High)
    I = 3 (High)
    A = 3 (High)
```

### Step 6.3: Assign Label

Based on CIA levels, assign a sensitivity label:

**Logic:**
```
max_cia = max(C, I, A)

if max_cia == 3:
    label = "Confidential"
    emoji = "🔴"
elif max_cia == 2:
    label = "Internal"
    emoji = "🟡"
else:
    label = "Public"
    emoji = "🟢"
```

### Step 6.4: Format Result

**Output Structure:**
```json
{
  "column": "CUSTOMER_EMAIL",
  "category": "PII",
  "confidence": 1.0,
  "confidence_pct": 100.0,
  "confidence_tier": "Confident",
  "label": "Confidential",
  "label_emoji": "🔴",
  "c": 3,
  "i": 2,
  "a": 2,
  "signals": {
    "semantic": 0.95,
    "keywords": 1.0,
    "patterns": 1.0,
    "governance": 0.80
  },
  "threshold_met": true,
  "validation_passed": true,
  "glossary_override": false
}
```

---

## Complete Example: Classifying "CUSTOMER_EMAIL"

**Input:**
```
Database: PROD_DB
Schema: CUSTOMER_SCHEMA
Table: USERS
Column: CUSTOMER_EMAIL
Type: VARCHAR(255)
Comment: "Primary email address for customer communications"
Sample Values: ["john.doe@example.com", "jane.smith@company.com"]
```

**Step-by-Step:**

**1. Build Context:**
```
"PROD_DB.CUSTOMER_SCHEMA.USERS.CUSTOMER_EMAIL | Type: VARCHAR(255) | 
Comment: Primary email address for customer communications | 
Values: john.doe@example.com, jane.smith@company.com"
```

**2. Compute Semantic Score:**
```
Vector = embed(context)
PII Similarity = 0.89
Semantic Score = 0.95 (after boosting)
```

**3. Compute Keyword Score:**
```
Matches:
  - "email" (EXACT, weight: 1.2) → 1.2
  - "customer" (EXACT, weight: 1.0) → 1.0
Total: 2.2 / 2 = 1.1 × 1.2 = 1.32 → 1.0
```

**4. Compute Pattern Score:**
```
Email Regex Match (weight: 1.5) → 1.5 × 1.2 = 1.8 → 1.0
```

**5. Compute Governance Score:**
```
Business Glossary: "email" → PII (0.80)
```

**6. Ensemble Score:**
```
(0.50 × 0.95) + (0.25 × 1.0) + (0.15 × 1.0) + (0.10 × 0.80) = 0.955
```

**7. Apply Category Weight:**
```
0.955 × 1.2 = 1.146 → 1.0
```

**8. Validation:**
```
✓ Threshold: 1.0 >= 0.65
✓ Multi-Signal: 4 strong signals
✓ Semantic: 0.95 >= 0.35
✓ Not Operational
✓ Not Simple Numeric
```

**9. Result:**
```
Category: PII
Confidence: 100%
Label: Confidential
CIA: 3/2/2
```

---

## Example: Excluding "ORDER_COUNT"

**Input:**
```
Column: ORDER_COUNT
Type: NUMBER
Sample Values: [5, 12, 3, 8, 15]
```

**Step-by-Step:**

**1. Build Context:**
```
"...ORDER_COUNT | Type: NUMBER | Values: 5, 12, 3, 8, 15"
```

**2. Compute Scores:**
```
Semantic: 0.25 (low similarity to all categories)
Keywords: 0.30 (weak match on "order")
Patterns: 0.10 (no pattern match)
Governance: 0.15 (no governance match)
```

**3. Ensemble Score:**
```
(0.50 × 0.25) + (0.25 × 0.30) + (0.15 × 0.10) + (0.10 × 0.15) = 0.23
```

**4. Validation:**
```
✗ Threshold: 0.23 < 0.65 → FAIL
```

**5. Result:**
```
EXCLUDED (below threshold)
```

---

## Summary

The classification system uses a sophisticated multi-layered approach:

1. **Metadata-Driven:** All rules from Snowflake governance tables
2. **Semantic Understanding:** E5-Large embeddings capture meaning
3. **Multi-Signal:** Combines 4 independent signals
4. **Weighted Scoring:** Keywords, patterns, categories have importance weights
5. **Strict Validation:** 6 validation rules prevent false positives
6. **Threshold-Based:** Only includes columns meeting detection threshold

**Key Principles:**
- **Precision over Recall:** Better to miss some sensitive data than flag too much
- **Evidence-Based:** Requires multiple corroborating signals
- **Context-Aware:** Understands semantic meaning, not just keywords
- **Configurable:** All rules in database, no hardcoded values
- **Transparent:** Logs all decisions and scores

**Result:** Only columns with **strong, clear, data-driven evidence** are classified as PII, SOX, or SOC2.
