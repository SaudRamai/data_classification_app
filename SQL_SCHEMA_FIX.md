# SQL Schema Alignment Fix Summary

## Issue
The application was failing with SQL compilation errors because the code was querying columns and tables that didn't match the actual Snowflake schema.

## Root Causes
1. **Table Name Mismatch**: Code used `SENSITIVITY_KEYWORDS` but schema has `SENSITIVE_KEYWORDS`
2. **Column Name Mismatches**:
   - Code queried `KEYWORD` but schema has `KEYWORD_STRING`
   - Code queried `PATTERN` but schema has `PATTERN_STRING`
   - Code queried `DEFAULT_THRESHOLD` but schema only has `DETECTION_THRESHOLD`
   - Code queried `SENSITIVITY_WEIGHT` in `SENSITIVITY_CATEGORIES` but it doesn't exist there
   - Code queried `KEYWORD_WEIGHT` and `SCORE` in `SENSITIVE_KEYWORDS` but they don't exist
3. **Import Failure**: `ai_sensitive_detection_service` singleton was failing to initialize, preventing imports

## Files Modified

### 1. `src/services/ai_classification_service.py`
**Changes:**
- Fixed `_load_additional_tokens_from_keywords()` to query `SENSITIVE_KEYWORDS.KEYWORD_STRING`
- Fixed `_load_patterns_from_governance()` to query `SENSITIVE_PATTERNS.PATTERN_STRING`
- Simplified queries to use correct table and column names

**Lines Modified:** 843-868, 1094-1113

### 2. `src/services/ai_classification_pipeline_service.py`
**Changes:**
- Fixed `SENSITIVITY_CATEGORIES` query (lines 828-840):
  - Removed `DEFAULT_THRESHOLD` (doesn't exist)
  - Removed `SENSITIVITY_WEIGHT` from categories table
  - Used only `DETECTION_THRESHOLD`
  
- Fixed `SENSITIVE_KEYWORDS` query (lines 915-931):
  - Used `KEYWORD_STRING` instead of `KEYWORD`
  - Used `SENSITIVITY_WEIGHT` instead of `KEYWORD_WEIGHT`
  - Removed `SCORE` and `SENSITIVITY_TYPE` (don't exist in keywords table)
  
- Fixed `SENSITIVE_PATTERNS` query (lines 964-979):
  - Used `PATTERN_STRING` and `PATTERN_REGEX` correctly
  - Used `SENSITIVITY_WEIGHT` and `SENSITIVITY_TYPE` (these DO exist in patterns table)

**Lines Modified:** 828-840, 915-931, 964-979

### 3. `src/services/ai_sensitive_detection_service.py`
**Changes:**
- Wrapped singleton instantiation in try-except (lines 792-802)
- Added fallback to create instance without AI if initialization fails
- Prevents import failures even if Snowflake tables are missing or have permission issues

**Lines Modified:** 792-802

## Schema Reference (from DDL)

### SENSITIVITY_CATEGORIES
- CATEGORY_ID
- CATEGORY_NAME
- DESCRIPTION
- CONFIDENTIALITY_LEVEL
- INTEGRITY_LEVEL
- AVAILABILITY_LEVEL
- **DETECTION_THRESHOLD** (not DEFAULT_THRESHOLD)
- IS_ACTIVE
- CREATED_BY, CREATED_AT, UPDATED_BY, UPDATED_AT, VERSION_NUMBER

### SENSITIVE_KEYWORDS
- KEYWORD_ID
- CATEGORY_ID
- **KEYWORD_STRING** (not KEYWORD)
- MATCH_TYPE
- **SENSITIVITY_WEIGHT** (not KEYWORD_WEIGHT or SCORE)
- IS_ACTIVE
- CREATED_BY, CREATED_AT, UPDATED_AT, VERSION_NUMBER

### SENSITIVE_PATTERNS
- PATTERN_ID
- CATEGORY_ID
- PATTERN_NAME
- **PATTERN_STRING**
- DESCRIPTION
- SENSITIVITY_WEIGHT
- IS_ACTIVE
- CREATED_AT, UPDATED_AT, VERSION_NUMBER
- **PATTERN_REGEX**
- **SENSITIVITY_TYPE**
- EXAMPLE

## Testing
After these fixes:
1. The application should start without import errors
2. SQL queries should execute without compilation errors
3. Classification pipeline should load governance metadata correctly

## Next Steps
1. Restart the Streamlit application
2. Verify that the Classification page loads
3. Run the classification pipeline
4. Check logs for any remaining SQL errors
