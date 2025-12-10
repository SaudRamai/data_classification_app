-- ============================================================================
-- DIAGNOSTIC: Find Why SOCIAL_SECURITY_NUMBER is Classified as SOC2
-- ============================================================================
-- This script identifies the root cause of SSN misclassification
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- Step 1: Find the keyword in SENSITIVE_KEYWORDS table
-- ============================================================================
SELECT 
    '1. KEYWORD MAPPING CHECK' AS DIAGNOSTIC_STEP,
    k.KEYWORD_ID,
    k.KEYWORD_STRING,
    k.MATCH_TYPE,
    k.SENSITIVITY_WEIGHT,
    c.CATEGORY_ID,
    c.CATEGORY_NAME,
    c.POLICY_GROUP AS CURRENT_POLICY_GROUP,
    CASE 
        WHEN c.POLICY_GROUP = 'PII' THEN '✓ CORRECT'
        ELSE '✗ WRONG - Should be PII!'
    END AS VALIDATION_STATUS,
    k.IS_ACTIVE,
    c.IS_ACTIVE AS CATEGORY_ACTIVE
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.KEYWORD_STRING ILIKE '%social%security%'
   OR k.KEYWORD_STRING ILIKE '%ssn%'
ORDER BY k.KEYWORD_STRING;

-- ============================================================================
-- Step 2: Check VW_POLICY_GROUP_KEYWORDS validation
-- ============================================================================
SELECT 
    '2. VALIDATION VIEW CHECK' AS DIAGNOSTIC_STEP,
    POLICY_GROUP,
    KEYWORD_STRING,
    CATEGORY_NAME,
    SENSITIVITY_WEIGHT,
    MAPPING_VALIDATION,
    CASE 
        WHEN MAPPING_VALIDATION = 'POTENTIAL_PII_MISMATCH' THEN '⚠️ MISMATCH DETECTED!'
        WHEN MAPPING_VALIDATION = 'VALID_MAPPING' AND POLICY_GROUP = 'PII' THEN '✓ CORRECT'
        ELSE '❓ REVIEW NEEDED'
    END AS STATUS
FROM VW_POLICY_GROUP_KEYWORDS
WHERE KEYWORD_STRING ILIKE '%social%security%'
   OR KEYWORD_STRING ILIKE '%ssn%'
ORDER BY KEYWORD_STRING;

-- ============================================================================
-- Step 3: Check all SOC2 keywords for "security" substring
-- ============================================================================
SELECT 
    '3. SOC2 KEYWORDS WITH "SECURITY"' AS DIAGNOSTIC_STEP,
    k.KEYWORD_STRING,
    c.CATEGORY_NAME,
    c.POLICY_GROUP,
    k.SENSITIVITY_WEIGHT,
    CASE 
        WHEN k.KEYWORD_STRING LIKE '%social%' THEN '⚠️ Should be PII!'
        WHEN k.KEYWORD_STRING LIKE '%security' THEN '✓ Correctly SOC2'
        ELSE '❓ Review'
    END AS ASSESSMENT
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE c.POLICY_GROUP = 'SOC2'
  AND k.KEYWORD_STRING ILIKE '%security%'
  AND k.IS_ACTIVE = TRUE
ORDER BY k.KEYWORD_STRING;

-- ============================================================================
-- Step 4: Find the correct PII category ID for SSN
-- ============================================================================
SELECT 
    '4. CORRECT CATEGORY FOR SSN' AS DIAGNOSTIC_STEP,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP,
    DESCRIPTION,
    DETECTION_THRESHOLD,
    IS_ACTIVE
FROM SENSITIVITY_CATEGORIES
WHERE POLICY_GROUP = 'PII'
  AND (
      CATEGORY_NAME ILIKE '%social%security%'
      OR CATEGORY_NAME ILIKE '%ssn%'
      OR CATEGORY_NAME ILIKE '%government%id%'
      OR CATEGORY_NAME ILIKE '%national%id%'
  )
ORDER BY CATEGORY_NAME;

-- ============================================================================
-- Step 5: Check VW_CATEGORY_MAPPING_VALIDATION
-- ============================================================================
SELECT 
    '5. MAPPING VALIDATION ISSUES' AS DIAGNOSTIC_STEP,
    ISSUE_TYPE,
    KEYWORD_STRING,
    CATEGORY_NAME AS CURRENT_CATEGORY,
    POLICY_GROUP AS CURRENT_POLICY_GROUP,
    DETECTED_PATTERN,
    RECOMMENDED_ACTION
FROM VW_CATEGORY_MAPPING_VALIDATION
WHERE KEYWORD_STRING ILIKE '%social%security%'
   OR KEYWORD_STRING ILIKE '%ssn%'
ORDER BY KEYWORD_STRING;

-- ============================================================================
-- Step 6: Check if there are multiple SSN-related keywords
-- ============================================================================
SELECT 
    '6. ALL SSN-RELATED KEYWORDS' AS DIAGNOSTIC_STEP,
    k.KEYWORD_STRING,
    c.CATEGORY_NAME,
    c.POLICY_GROUP,
    k.SENSITIVITY_WEIGHT,
    k.IS_ACTIVE,
    k.CREATED_AT,
    k.VERSION_NUMBER
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.KEYWORD_STRING ILIKE '%ssn%'
   OR k.KEYWORD_STRING ILIKE '%social%security%'
   OR k.KEYWORD_STRING ILIKE '%soc%sec%'
ORDER BY k.SENSITIVITY_WEIGHT DESC, k.KEYWORD_STRING;

-- ============================================================================
-- RECOMMENDED FIX QUERY
-- ============================================================================
-- Uncomment and run this to fix the issue:

/*
-- Find the correct PII category ID
-- SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES 
-- WHERE POLICY_GROUP = 'PII' 
--   AND CATEGORY_NAME ILIKE '%government%id%'
-- LIMIT 1;

-- Update the keyword to correct category
UPDATE SENSITIVE_KEYWORDS
SET 
    CATEGORY_ID = (
        SELECT CATEGORY_ID 
        FROM SENSITIVITY_CATEGORIES 
        WHERE POLICY_GROUP = 'PII' 
          AND (CATEGORY_NAME ILIKE '%government%id%'
               OR CATEGORY_NAME ILIKE '%national%id%'
               OR CATEGORY_NAME ILIKE '%ssn%')
        ORDER BY CATEGORY_NAME
        LIMIT 1
    ),
    UPDATED_BY = CURRENT_USER(),
    UPDATED_AT = CURRENT_TIMESTAMP(),
    VERSION_NUMBER = VERSION_NUMBER + 1
WHERE KEYWORD_STRING ILIKE 'SOCIAL_SECURITY_NUMBER'
  AND CATEGORY_ID IN (
      SELECT CATEGORY_ID 
      FROM SENSITIVITY_CATEGORIES 
      WHERE POLICY_GROUP != 'PII'
  );

-- Verify the fix
SELECT 
    k.KEYWORD_STRING,
    c.CATEGORY_NAME,
    c.POLICY_GROUP,
    'FIXED!' AS STATUS
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.KEYWORD_STRING ILIKE 'SOCIAL_SECURITY_NUMBER';
*/

-- ============================================================================
-- SUMMARY REPORT
-- ============================================================================
SELECT 
    'SUMMARY: SSN Classification Issue' AS REPORT,
    COUNT(CASE WHEN c.POLICY_GROUP != 'PII' THEN 1 END) AS MISCLASSIFIED_COUNT,
    COUNT(CASE WHEN c.POLICY_GROUP = 'PII' THEN 1 END) AS CORRECT_COUNT,
    COUNT(*) AS TOTAL_SSN_KEYWORDS
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE (k.KEYWORD_STRING ILIKE '%social%security%'
   OR k.KEYWORD_STRING ILIKE '%ssn%')
  AND k.IS_ACTIVE = TRUE;
