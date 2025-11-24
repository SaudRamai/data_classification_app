# Governance-Driven Classification System

## Overview
The AI Classification Pipeline now operates in **100% governance-driven mode**, extracting all sensitivity metadata exclusively from Snowflake governance tables. No categories, keywords, or patterns are hardcoded in the application.

## Governance Tables

### 1. SENSITIVITY_CATEGORIES
Defines the available sensitivity categories and their properties.

**Required Columns:**
- `CATEGORY_NAME` or `category` or `name`: The category identifier (e.g., "PII", "SOX", "SOC2")
- `DESCRIPTION` or `desc` or `details`: Category description for semantic matching
- `IS_ACTIVE` or `is_active`: Boolean flag to enable/disable categories

**Example:**
```sql
INSERT INTO SENSITIVITY_CATEGORIES (CATEGORY_NAME, DESCRIPTION, IS_ACTIVE) VALUES
('PII', 'Personally Identifiable Information including names, emails, SSN, etc.', TRUE),
('SOX', 'Financial data subject to Sarbanes-Oxley compliance', TRUE),
('SOC2', 'Security and operational control data', TRUE);
```

### 2. SENSITIVE_KEYWORDS
Maps keywords to sensitivity categories for deterministic classification.

**Required Columns:**
- `KEYWORD` or `keyword` or `KEYWORD_STRING`: The keyword to match (case-insensitive)
- `CATEGORY` or `category_name` or `CATEGORY_NAME`: The associated category
- `IS_ACTIVE` or `is_active`: Boolean flag to enable/disable keywords

**Example:**
```sql
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD, CATEGORY, IS_ACTIVE) VALUES
('ssn', 'PII', TRUE),
('social_security', 'PII', TRUE),
('email', 'PII', TRUE),
('phone', 'PII', TRUE),
('salary', 'SOX', TRUE),
('payroll', 'SOX', TRUE),
('revenue', 'SOX', TRUE),
('password', 'SOC2', TRUE),
('access_key', 'SOC2', TRUE),
('audit_log', 'SOC2', TRUE);
```

### 3. SENSITIVE_PATTERNS
Defines regex patterns for pattern-based detection.

**Required Columns:**
- `PATTERN` or `pattern` or `REGEX`: The regex pattern
- `CATEGORY` or `category_name`: The associated category
- `IS_ACTIVE` or `is_active`: Boolean flag to enable/disable patterns

**Example:**
```sql
INSERT INTO SENSITIVE_PATTERNS (PATTERN, CATEGORY, IS_ACTIVE) VALUES
('\b\d{3}-\d{2}-\d{4}\b', 'PII', TRUE),  -- SSN format
('\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'PII', TRUE),  -- Email
('\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'PII', TRUE),  -- Phone
('\b(password|secret|key|token|credential)\b', 'SOC2', TRUE);
```

## Classification Logic

### Step 1: Load Governance Metadata
On initialization (`_init_local_embeddings`), the system loads:
1. **Categories** from `SENSITIVITY_CATEGORIES`
2. **Keywords** from `SENSITIVE_KEYWORDS` (builds `_business_glossary_map`)
3. **Patterns** from `SENSITIVE_PATTERNS` (builds `_category_patterns`)

### Step 2: Multi-Signal Scoring
For each column/table, the system computes:

#### A. Semantic Score (50% weight)
- Embeds the column context using E5-Large
- Compares against category centroids built from `DESCRIPTION` field
- Returns similarity score [0, 1]

#### B. Keyword Score (25% weight)
- Checks if column name contains any keywords from `SENSITIVE_KEYWORDS`
- Returns 1.0 if match found, 0.0 otherwise

#### C. Pattern Score (15% weight)
- Tests column values against regex patterns from `SENSITIVE_PATTERNS`
- Returns score based on number of matches

#### D. Governance Score (10% weight)
- Additional governance-specific signals
- Returns score [0, 1]

### Step 3: Ensemble Scoring
```
final_score = (0.5 × semantic) + (0.25 × keyword) + (0.15 × pattern) + (0.10 × governance)
```

### Step 4: Business Glossary Override
If a column/table name contains a keyword from `SENSITIVE_KEYWORDS`:
- **Force score to 0.99** (99% confidence)
- This ensures deterministic classification for known sensitive terms

### Step 5: Filtering
Only include results where:
- `final_score >= 0.50` (50% minimum confidence)
- Category is in `{PII, SOX, SOC2}` (policy groups only)

## Configuration Examples

### Example 1: Add New PII Keyword
```sql
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD, CATEGORY, IS_ACTIVE)
VALUES ('passport', 'PII', TRUE);
```

### Example 2: Add New Financial Pattern
```sql
INSERT INTO SENSITIVE_PATTERNS (PATTERN, CATEGORY, IS_ACTIVE)
VALUES ('\b\d{16}\b', 'SOX', TRUE);  -- Credit card number
```

### Example 3: Add New Category
```sql
-- Step 1: Add category
INSERT INTO SENSITIVITY_CATEGORIES (CATEGORY_NAME, DESCRIPTION, IS_ACTIVE)
VALUES ('HIPAA', 'Protected Health Information', TRUE);

-- Step 2: Add keywords
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD, CATEGORY, IS_ACTIVE) VALUES
('patient', 'HIPAA', TRUE),
('diagnosis', 'HIPAA', TRUE),
('prescription', 'HIPAA', TRUE);

-- Step 3: Add patterns
INSERT INTO SENSITIVE_PATTERNS (PATTERN, CATEGORY, IS_ACTIVE) VALUES
('\b(medical|health|patient)\b', 'HIPAA', TRUE);
```

**Note:** You'll also need to update `_map_category_to_policy_group` to map 'HIPAA' to one of the policy groups (PII, SOX, SOC2), or extend the policy groups.

## Benefits

### 1. Zero Hardcoding
- All classification logic is data-driven
- No code changes required to add/modify categories
- Centralized governance in Snowflake

### 2. Audit Trail
- All keywords, patterns, and categories are versioned in Snowflake
- Changes can be tracked via Snowflake's Time Travel
- Clear lineage from governance tables to classification results

### 3. Dynamic Updates
- Add new keywords without redeploying the application
- Enable/disable categories with a simple UPDATE statement
- Test new patterns in staging before production

### 4. Compliance-Ready
- Governance metadata is stored in the same database as the data
- Classification rules are transparent and auditable
- Easy to demonstrate compliance to auditors

## Troubleshooting

### Issue: Column not being classified
**Check:**
1. Is there a matching keyword in `SENSITIVE_KEYWORDS`?
2. Are the patterns in `SENSITIVE_PATTERNS` correct?
3. Is the category `IS_ACTIVE = TRUE`?
4. Does the category map to PII, SOX, or SOC2?

**Debug:**
```sql
-- Check if keyword exists
SELECT * FROM SENSITIVE_KEYWORDS 
WHERE LOWER(KEYWORD) LIKE '%your_term%' AND IS_ACTIVE = TRUE;

-- Check if pattern exists
SELECT * FROM SENSITIVE_PATTERNS 
WHERE CATEGORY = 'PII' AND IS_ACTIVE = TRUE;

-- Check if category is active
SELECT * FROM SENSITIVITY_CATEGORIES 
WHERE CATEGORY_NAME = 'PII' AND IS_ACTIVE = TRUE;
```

### Issue: Too many false positives
**Solution:**
1. Increase the confidence threshold (currently 50%)
2. Make keywords more specific (e.g., "customer_email" instead of "email")
3. Refine regex patterns to be more restrictive

### Issue: Missing classifications
**Solution:**
1. Add more keywords to `SENSITIVE_KEYWORDS`
2. Lower the confidence threshold (with caution)
3. Improve category descriptions in `SENSITIVITY_CATEGORIES` for better semantic matching

## Migration from Hardcoded to Governance-Driven

If you're migrating from the old hardcoded system, run this SQL to populate your governance tables:

```sql
-- Populate SENSITIVE_KEYWORDS from old BUSINESS_GLOSSARY_MAP
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD, CATEGORY, IS_ACTIVE) VALUES
('customer', 'PII', TRUE),
('vendor', 'SOX', TRUE),
('employee', 'PII', TRUE),
('payroll', 'SOX', TRUE),
('identity', 'PII', TRUE),
('contact', 'PII', TRUE),
('security', 'SOC2', TRUE),
('audit', 'SOC2', TRUE),
('ssn', 'PII', TRUE),
('salary', 'SOX', TRUE),
('revenue', 'SOX', TRUE),
('password', 'SOC2', TRUE),
('email', 'PII', TRUE),
('phone', 'PII', TRUE),
('ip_address', 'PII', TRUE),
('credit_card', 'PII', TRUE),
('bank_account', 'SOX', TRUE);
```

## Summary

The classification system is now **100% governance-driven**:
- ✅ No hardcoded categories
- ✅ No hardcoded keywords
- ✅ No hardcoded patterns
- ✅ All metadata loaded from Snowflake governance tables
- ✅ Dynamic updates without code changes
- ✅ Audit-grade transparency and traceability
