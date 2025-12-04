-- 013_fix_keyword_false_positives.sql
-- Fix for keyword matching false positives
-- This script removes overly generic keywords and adds more specific ones
-- to prevent non-sensitive fields like 'product_name', 'brand_name' from being flagged

USE DATABASE IDENTIFIER($DATABASE);
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- =====================================================
-- 1. REMOVE OVERLY GENERIC KEYWORDS
-- =====================================================
-- Remove the generic 'name' keyword that causes false positives
DELETE FROM SENSITIVE_KEYWORDS 
WHERE KEYWORD_STRING IN ('name')
  AND CATEGORY_ID IN (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII');

-- =====================================================
-- 2. ADD SPECIFIC SENSITIVE NAME KEYWORDS
-- =====================================================
-- Add specific name-related keywords that are actually sensitive
INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID,
    CATEGORY_ID,
    KEYWORD_STRING,
    MATCH_TYPE,
    SENSITIVITY_WEIGHT,
    IS_ACTIVE,
    CREATED_BY
)
SELECT
    UUID_STRING(),
    C.CATEGORY_ID,
    K.VALUE::STRING AS KEYWORD_STRING,
    'CONTAINS',
    0.8,
    TRUE,
    CURRENT_USER()
FROM SENSITIVITY_CATEGORIES C,
LATERAL FLATTEN(
    INPUT => ARRAY_CONSTRUCT(
        'first_name', 'last_name', 'full_name', 'user_name', 
        'customer_name', 'employee_name', 'person_name', 
        'individual_name', 'given_name', 'surname'
    )
) K
WHERE C.CATEGORY_NAME = 'PII'
  -- Only insert if not already exists
  AND NOT EXISTS (
      SELECT 1 FROM SENSITIVE_KEYWORDS SK
      WHERE SK.KEYWORD_STRING = K.VALUE::STRING
        AND SK.CATEGORY_ID = C.CATEGORY_ID
  );

-- =====================================================
-- 3. VERIFICATION QUERIES
-- =====================================================
-- Verify the changes
SELECT 'PII Keywords After Fix' AS CHECK_TYPE, KEYWORD_STRING, SENSITIVITY_WEIGHT
FROM SENSITIVE_KEYWORDS SK
JOIN SENSITIVITY_CATEGORIES SC ON SK.CATEGORY_ID = SC.CATEGORY_ID
WHERE SC.CATEGORY_NAME = 'PII'
  AND SK.KEYWORD_STRING LIKE '%name%'
ORDER BY KEYWORD_STRING;

-- Check for any remaining overly generic keywords
SELECT 'Potentially Generic Keywords' AS CHECK_TYPE, 
       SC.CATEGORY_NAME,
       SK.KEYWORD_STRING,
       LENGTH(SK.KEYWORD_STRING) AS KEYWORD_LENGTH
FROM SENSITIVE_KEYWORDS SK
JOIN SENSITIVITY_CATEGORIES SC ON SK.CATEGORY_ID = SC.CATEGORY_ID
WHERE LENGTH(SK.KEYWORD_STRING) <= 5  -- Very short keywords are often too generic
  AND SK.IS_ACTIVE = TRUE
ORDER BY KEYWORD_LENGTH, CATEGORY_NAME;

-- =====================================================
-- 4. TEST CASES
-- =====================================================
-- These queries help verify that the fix works correctly
-- You can run these after applying the fix to ensure:
-- 1. Sensitive fields ARE detected (true positives)
-- 2. Non-sensitive fields are NOT detected (no false positives)

-- Test Case 1: Should MATCH (True Positives)
SELECT 'Should Match - True Positives' AS TEST_CASE,
       K.VALUE::STRING AS COLUMN_NAME,
       'Expected: MATCH' AS EXPECTED_RESULT
FROM TABLE(FLATTEN(INPUT => ARRAY_CONSTRUCT(
    'first_name', 'last_name', 'full_name', 'user_name',
    'customer_name', 'employee_name', 'email', 'phone',
    'ssn', 'social_security', 'address', 'dob'
))) K;

-- Test Case 2: Should NOT MATCH (Avoid False Positives)
SELECT 'Should NOT Match - Avoid False Positives' AS TEST_CASE,
       K.VALUE::STRING AS COLUMN_NAME,
       'Expected: NO MATCH' AS EXPECTED_RESULT
FROM TABLE(FLATTEN(INPUT => ARRAY_CONSTRUCT(
    'product_name', 'brand_name', 'table_name', 'file_name',
    'schema_name', 'database_name', 'column_name', 'display_name',
    'app_name', 'service_name', 'company_name', 'category_name',
    'tracking_number', 'order_number', 'invoice_number',
    'item_number', 'sku', 'product_code'
))) K;

-- =====================================================
-- 5. SUMMARY REPORT
-- =====================================================
SELECT 
    'Keyword Fix Summary' AS REPORT_TYPE,
    COUNT(*) AS TOTAL_PII_KEYWORDS,
    COUNT(CASE WHEN KEYWORD_STRING LIKE '%name%' THEN 1 END) AS NAME_RELATED_KEYWORDS,
    COUNT(CASE WHEN LENGTH(KEYWORD_STRING) <= 5 THEN 1 END) AS SHORT_KEYWORDS
FROM SENSITIVE_KEYWORDS SK
JOIN SENSITIVITY_CATEGORIES SC ON SK.CATEGORY_ID = SC.CATEGORY_ID
WHERE SC.CATEGORY_NAME = 'PII'
  AND SK.IS_ACTIVE = TRUE;
