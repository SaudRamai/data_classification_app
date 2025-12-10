-- ============================================================================
-- COMPREHENSIVE FIX: SOCIAL_SECURITY_NUMBER Category
-- ============================================================================
-- Your data shows:
--   KEYWORD_ID: dc825979-d136-4076-bb75-30288c8ef6e5
--   CATEGORY_ID: 3e47f6fd-d870-41a8-b75f-e967bb839475
--   KEYWORD_STRING: SOCIAL_SECURITY_NUMBER
--
-- This script will:
--   1. Check what that CATEGORY_ID represents
--   2. Get the correct PII CATEGORY_ID
--   3. Update the record if needed
--   4. Verify the fix
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- STEP 1: Diagnose the problem
-- ============================================================================

-- What category is the current CATEGORY_ID?
SELECT 
    '🔍 CURRENT CATEGORY' AS STEP,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP,
    CASE 
        WHEN CATEGORY_NAME = 'PII' THEN '✅ CORRECT!'
        WHEN CATEGORY_NAME = 'SOC2' THEN '❌ WRONG! Should be PII'
        WHEN CATEGORY_NAME = 'SOX' THEN '❌ WRONG! Should be PII'
        ELSE '❌ UNEXPECTED CATEGORY!'
    END AS STATUS
FROM SENSITIVITY_CATEGORIES
WHERE CATEGORY_ID = '3e47f6fd-d870-41a8-b75f-e967bb839475';

-- What is the correct PII CATEGORY_ID?
SELECT 
    '✅ CORRECT PII CATEGORY' AS STEP,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP
FROM SENSITIVITY_CATEGORIES
WHERE CATEGORY_NAME = 'PII';

-- ============================================================================
-- STEP 2: Apply the fix
-- ============================================================================

-- Update SOCIAL_SECURITY_NUMBER to use PII category
UPDATE SENSITIVE_KEYWORDS
SET 
    CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII'),
    KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER',  -- Ensure uppercase
    UPDATED_BY = CURRENT_USER(),
    UPDATED_AT = CURRENT_TIMESTAMP(),
    VERSION_NUMBER = COALESCE(VERSION_NUMBER, 1) + 1
WHERE KEYWORD_ID = 'dc825979-d136-4076-bb75-30288c8ef6e5'
  -- Only update if it's NOT already PII
  AND CATEGORY_ID != (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII');

-- Show how many rows were updated
SELECT CASE 
    WHEN SQLROWCOUNT > 0 THEN '✅ Updated ' || SQLROWCOUNT || ' row(s) to PII category'
    ELSE '⚠️ No update needed - already in PII category'
END AS RESULT;

-- ============================================================================
-- STEP 3: Verify the fix
-- ============================================================================

SELECT 
    '✅ VERIFICATION' AS STEP,
    sk.KEYWORD_ID,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.CATEGORY_ID,
    sk.SENSITIVITY_WEIGHT,
    sk.MATCH_TYPE,
    sk.IS_ACTIVE,
    sk.VERSION_NUMBER,
    sk.UPDATED_BY,
    sk.UPDATED_AT
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_ID = 'dc825979-d136-4076-bb75-30288c8ef6e5';

-- Expected result:
--   KEYWORD_STRING: SOCIAL_SECURITY_NUMBER
--   CATEGORY_NAME: PII  ← Must be PII!
--   IS_ACTIVE: TRUE
--   VERSION_NUMBER: 4 (or higher)

-- ============================================================================
-- STEP 4: Check for duplicate entries
-- ============================================================================

SELECT 
    '⚠️ CHECK FOR DUPLICATES' AS STEP,
    sk.KEYWORD_ID,
    sc.CATEGORY_NAME,
    sk.KEYWORD_STRING,
    sk.IS_ACTIVE,
    sk.CREATED_AT
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE UPPER(sk.KEYWORD_STRING) = 'SOCIAL_SECURITY_NUMBER'
  OR LOWER(sk.KEYWORD_STRING) = 'social_security_number'
ORDER BY sk.CREATED_AT;

-- If this returns more than 1 row, you have duplicates!
-- Delete any duplicates that are NOT the one in PII category:

DELETE FROM SENSITIVE_KEYWORDS
WHERE (UPPER(KEYWORD_STRING) = 'SOCIAL_SECURITY_NUMBER' 
   OR LOWER(KEYWORD_STRING) = 'social_security_number')
  AND KEYWORD_ID != 'dc825979-d136-4076-bb75-30288c8ef6e5';

SELECT CASE 
    WHEN SQLROWCOUNT > 0 THEN '🗑️ Deleted ' || SQLROWCOUNT || ' duplicate(s)'
    ELSE '✅ No duplicates found'
END AS RESULT;

-- ============================================================================
-- STEP 5: Final verification - what will the pipeline load?
-- ============================================================================

SELECT 
    '🤖 WHAT PIPELINE WILL LOAD' AS STEP,
    sc.CATEGORY_NAME,
    sk.KEYWORD_STRING,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.IS_ACTIVE
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE (UPPER(sk.KEYWORD_STRING) = 'SOCIAL_SECURITY_NUMBER' 
   OR LOWER(sk.KEYWORD_STRING) = 'social_security_number')
  AND sk.IS_ACTIVE = TRUE;

-- Should return exactly 1 row with CATEGORY_NAME = 'PII'

-- ============================================================================
-- NEXT STEPS
-- ============================================================================
/*
After running this script:

1. ✅ Verify all query results show CATEGORY_NAME = 'PII'
2. 🔄 Restart Streamlit application
3. 🚀 Run AI Classification Pipeline
4. ✅ Verify SOCIAL_SECURITY_NUMBER is now detected as PII

If still showing SOC2:
  - Check if pipeline loads from different database/schema
  - Check logs for which database is being queried
  - Verify no caching issues (restart app with fresh session)
*/

-- ============================================================================
