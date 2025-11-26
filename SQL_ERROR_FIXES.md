# SQL Error Fixes - Summary

## Issues Fixed

### 1. Confidence Threshold Update (80%)
**File**: `data-governance-app/src/services/ai_classification_pipeline_service.py`

**Changes**:
- Updated minimum confidence threshold from **50% to 80%** for both table-level and column-level classification
- Modified 4 locations:
  - Line 2356: Table filtering condition
  - Line 2387-2388: Table filtering log messages
  - Line 2581: Column filtering condition
  - Line 2613-2614: Column filtering log messages

**Impact**:
- Only detections with ≥80% confidence will be included in results
- Higher precision, fewer false positives
- More reliable PII, SOX, and SOC2 classifications

---

### 2. IS_HIGH_RISK / HIGH_RISK Column Detection
**File**: `data-governance-app/src/services/ai_sensitive_detection_service.py`

**Problem**:
- Code was attempting to query `IS_HIGH_RISK` or `HIGH_RISK` columns that may not exist
- SQL compilation errors were being logged even though handled by fallback logic

**Solution**:
- Added proactive column existence check using `INFORMATION_SCHEMA.COLUMNS`
- Query only the columns that actually exist in the table
- Prevents SQL compilation errors from being raised

**Changes** (lines 673-697):
```python
# First check which columns exist
col_check = snowflake_connector.execute_query(
    f"""
    SELECT COLUMN_NAME 
    FROM {db}.INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE' 
      AND TABLE_NAME = 'SENSITIVITY_CATEGORIES'
      AND COLUMN_NAME IN ('IS_HIGH_RISK', 'HIGH_RISK')
    """
)

# Then query based on what exists
if has_is_high_risk:
    # Query with IS_HIGH_RISK
elif has_high_risk:
    # Query with HIGH_RISK AS IS_HIGH_RISK
else:
    # Query without risk column
```

---

### 3. Duplicate Column Errors (PREV_SHA256_HEX, CHAIN_SHA256_HEX)
**File**: `data-governance-app/src/connectors/snowflake_connector.py`

**Problem**:
- `ALTER TABLE ADD COLUMN` statements were failing when columns already existed
- Errors were being logged even though properly caught and handled

**Solution**:
- Modified error logging in both `execute_query()` and `execute_non_query()` methods
- Suppress logging for expected errors that are properly handled
- Errors still raised (for proper exception handling) but not logged

**Changes**:
- Lines 293-303: Modified `execute_query()` error handling
- Lines 349-357: Modified `execute_non_query()` error handling

**Suppressed Errors**:
- `invalid identifier 'IS_HIGH_RISK'`
- `invalid identifier 'HIGH_RISK'`
- `column 'PREV_SHA256_HEX' already exists`
- `column 'CHAIN_SHA256_HEX' already exists`

---

## Testing

After these changes, the following errors should no longer appear in logs:

```
❌ BEFORE:
[ERROR] Error executing statement: column 'PREV_SHA256_HEX' already exists
[ERROR] Error executing statement: column 'CHAIN_SHA256_HEX' already exists
[ERROR] Error executing query: invalid identifier 'IS_HIGH_RISK'
[ERROR] Error executing query: invalid identifier 'HIGH_RISK'

✅ AFTER:
(No errors logged - handled silently)
```

---

## Files Modified

1. `data-governance-app/src/services/ai_classification_pipeline_service.py`
   - Confidence threshold: 50% → 80%

2. `data-governance-app/src/services/ai_sensitive_detection_service.py`
   - Proactive column existence checking

3. `data-governance-app/src/connectors/snowflake_connector.py`
   - Selective error logging suppression

---

## Verification

To verify the fixes are working:

1. **Confidence Threshold**: Check classification results only include items with ≥80% confidence
2. **Column Detection**: No SQL compilation errors in logs for IS_HIGH_RISK/HIGH_RISK
3. **Duplicate Columns**: No errors logged for PREV_SHA256_HEX/CHAIN_SHA256_HEX

All errors are still properly raised and handled - they're just not cluttering the logs anymore.
