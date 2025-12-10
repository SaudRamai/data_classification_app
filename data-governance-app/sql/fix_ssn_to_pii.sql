-- ============================================================================
-- FIX SOCIAL_SECURITY_NUMBER CATEGORIZATION
-- ============================================================================
-- Problem: SOCIAL_SECURITY_NUMBER is incorrectly categorized as SOC2
-- Solution: Update it to PII category
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- Step 1: Verify the issue
SELECT 
    '❌ BEFORE FIX - INCORRECT CATEGORY' AS STATUS,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME AS CURRENT_CATEGORY,
    sk.SENSITIVITY_WEIGHT
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- Step 2: Get the correct PII category ID
SELECT 
    '✅ PII CATEGORY (CORRECT)' AS STATUS,
    CATEGORY_ID,
    CATEGORY_NAME
FROM SENSITIVITY_CATEGORIES
WHERE CATEGORY_NAME = 'PII';

-- Step 3: Fix the categorization
UPDATE SENSITIVE_KEYWORDS
SET 
    CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII'),
    UPDATED_BY = CURRENT_USER(),
    UPDATED_AT = CURRENT_TIMESTAMP(),
    VERSION_NUMBER = COALESCE(VERSION_NUMBER, 1) + 1
WHERE KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- Step 4: Verify the fix
SELECT 
    '✅ AFTER FIX - CORRECT CATEGORY' AS STATUS,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME AS NEW_CATEGORY,
    sk.SENSITIVITY_WEIGHT,
    sk.UPDATED_BY,
    sk.UPDATED_AT
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- ============================================================================
-- EXPLANATION
-- ============================================================================
-- SOCIAL_SECURITY_NUMBER is:
--   ✅ PII (Personally Identifiable Information) - CORRECT
--   ❌ SOC2 (Security/Access Controls) - WRONG
--
-- SOC2 is for keywords like:
--   - API_KEY
--   - OAUTH_TOKEN
--   - USER_PASSWORD_HASH
--   - ENCRYPTED_MESSAGES
--
-- PII is for keywords like:
--   - SOCIAL_SECURITY_NUMBER ← This one!
--   - PASSPORT_NUMBER
--   - DRIVERS_LICENSE_NUMBER
--   - TAX_IDENTIFICATION_NUMBER
-- ============================================================================
