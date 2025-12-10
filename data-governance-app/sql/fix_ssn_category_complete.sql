-- ============================================================================
-- FIX: Change SOCIAL_SECURITY_NUMBER from SOC2 to PII
-- ============================================================================
-- Based on your data showing CATEGORY_ID = '3e47f6fd-d870-41a8-b75f-e967bb839475'
-- We need to update this to the correct PII CATEGORY_ID
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- STEP 1: Show the problem
-- ============================================================================

SELECT 
    '❌ BEFORE FIX' AS STATUS,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME AS CURRENT_WRONG_CATEGORY,
    sk.CATEGORY_ID AS WRONG_CATEGORY_ID,
    sk.SENSITIVITY_WEIGHT,
    sk.VERSION_NUMBER
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_ID = 'dc825979-d136-4076-bb75-30288c8ef6e5';

-- ============================================================================
-- STEP 2: Get the correct PII category ID
-- ============================================================================

SELECT 
    '✅ CORRECT CATEGORY' AS STATUS,
    CATEGORY_ID AS CORRECT_PII_CATEGORY_ID,
    CATEGORY_NAME
FROM SENSITIVITY_CATEGORIES
WHERE CATEGORY_NAME = 'PII';

-- ============================================================================
-- STEP 3: Fix the category
-- ============================================================================

UPDATE SENSITIVE_KEYWORDS
SET 
    CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII'),
    UPDATED_BY = CURRENT_USER(),
    UPDATED_AT = CURRENT_TIMESTAMP(),
    VERSION_NUMBER = COALESCE(VERSION_NUMBER, 1) + 1
WHERE KEYWORD_ID = 'dc825979-d136-4076-bb75-30288c8ef6e5';

SELECT 'Updated ' || SQLROWCOUNT || ' row(s)' AS RESULT;

-- ============================================================================
-- STEP 4: Verify the fix
-- ============================================================================

SELECT 
    '✅ AFTER FIX' AS STATUS,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME AS CORRECT_NEW_CATEGORY,
    sk.CATEGORY_ID AS CORRECT_CATEGORY_ID,
    sk.SENSITIVITY_WEIGHT,
    sk.VERSION_NUMBER,
    sk.UPDATED_BY,
    sk.UPDATED_AT
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_ID = 'dc825979-d136-4076-bb75-30288c8ef6e5';

-- Expected: CATEGORY_NAME should now be 'PII'

-- ============================================================================
-- STEP 5: Delete any duplicate SOC2 entries
-- ============================================================================

-- Check for duplicates first
SELECT 
    '⚠️ CHECK FOR DUPLICATES' AS STATUS,
    sk.KEYWORD_ID,
    sc.CATEGORY_NAME,
    sk.KEYWORD_STRING,
    sk.IS_ACTIVE
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE LOWER(sk.KEYWORD_STRING) = 'social_security_number'
  AND sk.KEYWORD_ID != 'dc825979-d136-4076-bb75-30288c8ef6e5';

-- If there are duplicates with SOC2 category, delete them:
DELETE FROM SENSITIVE_KEYWORDS
WHERE LOWER(KEYWORD_STRING) = 'social_security_number'
  AND KEYWORD_ID != 'dc825979-d136-4076-bb75-30288c8ef6e5'
  AND CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2');

SELECT 'Deleted ' || SQLROWCOUNT || ' duplicate SOC2 entry(ies)' AS RESULT;

-- ============================================================================
-- STEP 6: Also fix case sensitivity
-- ============================================================================

-- Update to uppercase for consistency
UPDATE SENSITIVE_KEYWORDS
SET 
    KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER',  -- Uppercase
    UPDATED_BY = CURRENT_USER(),
    UPDATED_AT = CURRENT_TIMESTAMP()
WHERE KEYWORD_ID = 'dc825979-d136-4076-bb75-30288c8ef6e5'
  AND KEYWORD_STRING != 'SOCIAL_SECURITY_NUMBER';

-- ============================================================================
-- STEP 7: Final verification
-- ============================================================================

SELECT 
    '✅ FINAL CHECK' AS STATUS,
    sk.KEYWORD_ID,
    sk.KEYWORD_STRING AS SHOULD_BE_UPPERCASE,
    sc.CATEGORY_NAME AS SHOULD_BE_PII,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.IS_ACTIVE AS SHOULD_BE_TRUE,
    sk.VERSION_NUMBER
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_ID = 'dc825979-d136-4076-bb75-30288c8ef6e5';

-- ============================================================================
-- EXPECTED RESULTS AFTER FIX:
-- ============================================================================
/*
✅ KEYWORD_STRING: SOCIAL_SECURITY_NUMBER (uppercase)
✅ CATEGORY_NAME: PII (not SOC2!)
✅ IS_ACTIVE: TRUE
✅ SENSITIVITY_WEIGHT: 0.8
✅ VERSION_NUMBER: 4 (incremented)

After running this, do:
1. Restart Streamlit app
2. Run AI Classification Pipeline again
3. SOCIAL_SECURITY_NUMBER should now be detected as PII
*/

-- ============================================================================
-- BONUS: Fix ALL PII keywords that might be miscategorized
-- ============================================================================

UPDATE SENSITIVE_KEYWORDS
SET 
    CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII'),
    UPDATED_BY = CURRENT_USER(),
    UPDATED_AT = CURRENT_TIMESTAMP(),
    VERSION_NUMBER = COALESCE(VERSION_NUMBER, 1) + 1
WHERE LOWER(KEYWORD_STRING) IN (
    'social_security_number',
    'tax_identification_number',
    'national_id_number',
    'drivers_license_number',
    'passport_number',
    'voter_id_number',
    'military_id_number',
    'alien_registration_number',
    'biometric_hash',
    'voice_print_id',
    'fingerprint_hash',
    'health_condition',
    'device_location_history'
)
AND CATEGORY_ID != (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII');

SELECT 'Fixed ' || SQLROWCOUNT || ' PII keyword(s) that were in wrong category' AS RESULT;

-- ============================================================================
