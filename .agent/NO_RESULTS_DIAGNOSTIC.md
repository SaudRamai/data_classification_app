# QUICK DIAGNOSTIC GUIDE: "No assets were successfully classified"

## What This Error Means

The pipeline processed your tables but **EVERY SINGLE ONE was filtered out** before reaching the UI.

## How to Diagnose

### Step 1: Check the Logs (HIGHEST PRIORITY)

When you run the classification pipeline, you should now see detailed logs like:

```
================================================================================
GOVERNANCE-DRIVEN PIPELINE DIAGNOSTICS
================================================================================
Assets to classify: 5
Available governance categories: ['PII_PERSONAL_INFO', 'FINANCIAL_DATA']
Valid centroids: 2/2
Total keywords loaded: 150
Total patterns loaded: 25
Policy mapping: 2 categories → PII/SOX/SOC2
  Policy map: {'PII_PERSONAL_INFO': 'PII', 'FINANCIAL_DATA': 'SOX'}
--------------------------------------------------------------------------------

[1/5] Classifying: PUBLIC.CUSTOMERS
  Result: category=PII, confidence=0.720, status=COMPLETED
  Filter check:
    • Category in {PII,SOX,SOC2}: True (actual: 'PII')
    • Confidence >= 0.25: True (actual: 0.720)
  ✓ PASSED - Added to results

[2/5] Classifying: PUBLIC.ORDERS
  Result: category=NON_SENSITIVE, confidence=0.150, status=COMPLETED
  Filter check:
    • Category in {PII,SOX,SOC2}: False (actual: 'NON_SENSITIVE')
    • Confidence >= 0.25: True (actual: 0.150)
  ✗ FILTERED OUT - Category 'NON_SENSITIVE' is not in {PII,SOX,SOC2}
```

**Look for these specific patterns:**

---

### Pattern 1: Category Mapping Failure

```
[1/5] Classifying: PUBLIC.CUSTOMERS
  Result: category=CUSTOMER_DATA, confidence=0.650, status=COMPLETED
  Filter check:
    • Category in {PII,SOX,SOC2}: False (actual: 'CUSTOMER_DATA')
  ✗ FILTERED OUT - Category 'CUSTOMER_DATA' is not in {PII,SOX,SOC2}
```

**DIAGNOSIS:** Categories are being detected but not mapping to PII/SOX/SOC2

**ROOT CAUSE:**
- Policy mapping is empty or incomplete
- Category names/descriptions don't contain keywords like "personal", "financial", "security"

**FIX:**
1. Run `.agent/diagnose_governance_tables.sql` in Snowflake
2. Check Section 4 "Policy Mapping Check"
3. Update category names or descriptions to include policy keywords
4. OR manually populate `_policy_group_by_category` mapping

---

### Pattern 2: Confidence Too Low

```
[1/5] Classifying: PUBLIC.CUSTOMERS
  Result: category=PII, confidence=0.180, status=COMPLETED
  Filter check:
    • Category in {PII,SOX,SOC2}: True (actual: 'PII')
    • Confidence >= 0.25: False (actual: 0.180)
  ✗ FILTERED OUT - Confidence 0.180 < 0.25
```

**DIAGNOSIS:** Categories map correctly but confidence scores are too low

**ROOT CAUSES:**
1. Detection thresholds in Snowflake are too high (>0.65)
2. Not enough keywords/patterns loaded
3. Semantic scoring is filtering too aggressively
4. Combined scoring weights are wrong

**FIX:**
1. Lower `DETECTION_THRESHOLD` in `SENSITIVITY_CATEGORIES` table to 0.50
2. Apply code fixes from `.agent/CLASSIFICATION_PIPELINE_ANALYSIS.md`
3. Add more keywords/patterns to strengthen detection

---

### Pattern 3: No Governance Metadata

```
================================================================================
GOVERNANCE-DRIVEN PIPELINE DIAGNOSTICS
================================================================================
Assets to classify: 5
Available governance categories: []
Valid centroids: 0/0
Total keywords loaded: 0
Total patterns loaded: 0
Policy mapping: 0 categories → PII/SOX/SOC2
  ⚠️ NO POLICY MAPPING! Categories will not map to PII/SOX/SOC2
```

**DIAGNOSIS:** Governance tables are empty or not loading

**ROOT CAUSES:**
1. `SENSITIVITY_CATEGORIES` table is empty
2. All categories have `IS_ACTIVE = FALSE`
3. All categories have empty `DESCRIPTION` fields
4. Governance database resolution failed

**FIX:**
1. Run `.agent/diagnose_governance_tables.sql` 
2. Check if tables exist and have data
3. Ensure `IS_ACTIVE = TRUE` for categories you want to use
4. Populate `DESCRIPTION` field (minimum 50 characters)

---

### Pattern 4: Classification Errors

```
[1/5] Classifying: PUBLIC.CUSTOMERS
  Result: category=None, confidence=0.000, status=FAILED
  ✗ Classification error: 'NoneType' object has no attribute 'upper'
```

**DIAGNOSIS:** Code errors during classification

**FIX:** Share the full error traceback for debugging

---

## Step 2: Run Python Diagnostic Script

```bash
cd c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app
python .agent\debug_classification.py
```

This will:
1. Check governance metadata loading
2. Test scoring on sample data
3. Show exactly what categories are available
4. Identify which layer is failing

---

## Step 3: Run Snowflake Diagnostic SQL

```sql
-- In Snowflake, run:
.agent/diagnose_governance_tables.sql
```

This will check:
1. Do categories have descriptions?
2. Do categories have keywords?
3. Do categories have patterns?
4. Will categories map to PII/SOX/SOC2?
5. Are thresholds too high?

---

## Most Common Root Causes (in order)

### 🥇 #1: Empty Policy Mapping (90% of cases)

**Symptom:**
```
Policy mapping: 0 categories → PII/SOX/SOC2
  ⚠️ NO POLICY MAPPING!
```

**Why:** Your `SENSITIVITY_CATEGORIES` table has categories like:
- `CUSTOMER_INFO` (doesn't contain "personal", "pii", "financial", etc.)
- `ACCOUNT_DATA` (ambiguous - could map to PII or SOX)
- `SECURE_DATA` (doesn't contain policy keywords)

**Fix:** Update category names or descriptions:
```sql
UPDATE DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
SET DESCRIPTION = 'Personal Identifiable Information for customers and employees'
WHERE CATEGORY_NAME = 'CUSTOMER_INFO';
```

---

### 🥈 #2: Thresholds Too High (75% of cases)

**Symptom:**
```
Avg Detection Threshold: 0.70
Categories with Threshold > 0.65: 15
```

**Why:** Default thresholds of 0.65-0.70 are designed for perfect matches only.

**Fix:**
```sql
UPDATE DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
SET DETECTION_THRESHOLD = 0.50
WHERE DETECTION_THRESHOLD > 0.60;
```

---

### 🥉 #3: Empty Descriptions (50% of cases)

**Symptom:**
```
Categories with EMPTY DESCRIPTION: 8
```

**Why:** Categories with empty descriptions are **completely skipped** (no centroid can be built).

**Fix:**
```sql
-- Find them
SELECT CATEGORY_NAME 
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
WHERE COALESCE(DESCRIPTION, '') = '' AND IS_ACTIVE = TRUE;

-- Fix them (example)
UPDATE DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
SET DESCRIPTION = 'Social Security Numbers and national identification numbers for US persons'
WHERE CATEGORY_NAME = 'SSN';
```

---

## Quick Fixes Checklist

- [ ] Check logs for specific filtering reasons
- [ ] Run `.agent/diagnose_governance_tables.sql` in Snowflake
- [ ] Verify categories have descriptions (>50 chars)
- [ ] Verify categories have keywords (>10 per category)
- [ ] Verify detection thresholds are 0.45-0.55 (not 0.65+)
- [ ] Verify policy mapping shows categories → PII/SOX/SOC2
- [ ] Apply code fixes from `.agent/CLASSIFICATION_PIPELINE_ANALYSIS.md`
- [ ] Run `.agent/debug_classification.py` to test

---

## Next Steps

After making fixes, run the pipeline again and check:

1. **Before:** `Policy mapping: 0 categories → PII/SOX/SOC2`
2. **After:** `Policy mapping: 15 categories → PII/SOX/SOC2`

3. **Before:** `Filtered out: 25` / `Passed: 0`
4. **After:** `Filtered out: 10` / `Passed: 15`

If you still get **0 results**, share:
1. The full diagnostic log output
2. Result of `.agent/diagnose_governance_tables.sql`
3. A sample table that SHOULD be classified as PII but isn't
