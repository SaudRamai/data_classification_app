USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- FIX PII CATEGORY MAPPING
-- ============================================================================
-- The user reported that 'date_of_birth' and 'user_email' are being classified as SOC2.
-- This indicates that the category containing these keywords is incorrectly mapped to SOC2.
-- This script forces the category containing 'date_of_birth' to be mapped to PII.

-- 1. Get the Category ID for 'date_of_birth'
SET PII_CAT_ID = (SELECT CATEGORY_ID FROM SENSITIVE_KEYWORDS WHERE KEYWORD_STRING = 'date_of_birth' LIMIT 1);

-- 2. Update the Category to be PII
UPDATE SENSITIVITY_CATEGORIES
SET 
    POLICY_GROUP = 'PII',
    -- Optional: Standardize name if it's weird
    -- CATEGORY_NAME = 'PII_PERSONAL_INFO', 
    DESCRIPTION = 'Personal Identifiable Information including names, email addresses, phone numbers, physical addresses, SSN, passport numbers, driver licenses, dates of birth, biometric data, and any information that identifies a natural person'
WHERE CATEGORY_ID = $PII_CAT_ID;

-- 3. Ensure 'user_email' category is also PII (should be same, but safety check)
SET EMAIL_CAT_ID = (SELECT CATEGORY_ID FROM SENSITIVE_KEYWORDS WHERE KEYWORD_STRING = 'user_email' LIMIT 1);

UPDATE SENSITIVITY_CATEGORIES
SET POLICY_GROUP = 'PII'
WHERE CATEGORY_ID = $EMAIL_CAT_ID;

-- 4. Verify no PII keywords are in SOC2 categories
-- If 'user_email' exists in a SOC2 category, delete it or move it.
-- (Assuming we want to keep the one we just fixed, so we delete others)
DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN ('user_email', 'date_of_birth', 'ssn', 'social_security_number')
  AND CATEGORY_ID NOT IN ($PII_CAT_ID, $EMAIL_CAT_ID);

SELECT 'Fixed PII Category Mapping' as STATUS;
