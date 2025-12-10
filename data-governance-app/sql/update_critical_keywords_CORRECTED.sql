-- ============================================================================
-- CRITICAL KEYWORDS CLEANUP - CORRECTED VERSION
-- ============================================================================
-- This script removes lower-risk keywords from the CORRECT location
-- where the AI pipeline actually writes data.
--
-- IMPORTANT: This uses the SAME schema as the upsert function!
-- ============================================================================

-- ============================================================================
-- STEP 1: Determine the correct schema location
-- ============================================================================

-- The AI pipeline upsert function uses either:
-- - {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS
-- Where {gov_db} is resolved from resolve_governance_db()

-- First, let's check which database/schema has the keywords
SHOW TABLES LIKE 'SENSITIVE_KEYWORDS' IN ACCOUNT;

-- ============================================================================
-- STEP 2A: OPTION A - If using DATA_CLASSIFICATION_GOVERNANCE database
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- Check current keywords
SELECT 'BEFORE CLEANUP - DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE' AS STATUS,
       COUNT(*) AS TOTAL_KEYWORDS
FROM SENSITIVE_KEYWORDS;

-- Remove PII lower-risk keywords (10 columns)
DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN (
    'CUSTOMER_ID',
    'ETHNICITY',
    'RELIGION',
    'DISABILITY_STATUS',
    'TWO_FACTOR_PHONE',
    'TWO_FACTOR_EMAIL',
    'GPS_COORDINATES',
    'LAST_KNOWN_LOCATION',
    'VOIP_CALL_RECORDS',
    'VIDEO_CALL_SIGNATURE'
) AND CATEGORY_ID IN (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII');

-- Remove SOX lower-risk keywords (4 columns)
DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN (
    'BANK_ROUTING_NUMBER',
    'BANK_SWIFT_CODE',
    'CREDIT_CARD_HOLDER_NAME',
    'BUSINESS_REGISTRATION_NUMBER'
) AND CATEGORY_ID IN (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX');

-- Remove SOC2 lower-risk keywords (5 columns)
DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN (
    'SECURITY_QUESTION_1',
    'SECURITY_QUESTION_2',
    'IP_ADDRESS',
    'LOGIN_DEVICE_ID',
    'CONFIDENTIAL_AGREEMENT_ID'
) AND CATEGORY_ID IN (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2');

-- Check after cleanup
SELECT 'AFTER CLEANUP - DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE' AS STATUS,
       COUNT(*) AS TOTAL_KEYWORDS
FROM SENSITIVE_KEYWORDS;

-- ============================================================================
-- STEP 2B: OPTION B - If using DATA_CLASSIFICATION_DB database
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA GOVERNANCE;

-- Check current keywords
SELECT 'BEFORE CLEANUP - DATA_CLASSIFICATION_DB.GOVERNANCE' AS STATUS,
       COUNT(*) AS TOTAL_KEYWORDS
FROM SENSITIVE_KEYWORDS;

-- Remove PII lower-risk keywords (10 columns)
DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN (
    'CUSTOMER_ID',
    'ETHNICITY',
    'RELIGION',
    'DISABILITY_STATUS',
    'TWO_FACTOR_PHONE',
    'TWO_FACTOR_EMAIL',
    'GPS_COORDINATES',
    'LAST_KNOWN_LOCATION',
    'VOIP_CALL_RECORDS',
    'VIDEO_CALL_SIGNATURE'
) AND CATEGORY_ID IN (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII');

-- Remove SOX lower-risk keywords (4 columns)
DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN (
    'BANK_ROUTING_NUMBER',
    'BANK_SWIFT_CODE',
    'CREDIT_CARD_HOLDER_NAME',
    'BUSINESS_REGISTRATION_NUMBER'
) AND CATEGORY_ID IN (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX');

-- Remove SOC2 lower-risk keywords (5 columns)
DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN (
    'SECURITY_QUESTION_1',
    'SECURITY_QUESTION_2',
    'IP_ADDRESS',
    'LOGIN_DEVICE_ID',
    'CONFIDENTIAL_AGREEMENT_ID'
) AND CATEGORY_ID IN (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2');

-- Check after cleanup
SELECT 'AFTER CLEANUP - DATA_CLASSIFICATION_DB.GOVERNANCE' AS STATUS,
       COUNT(*) AS TOTAL_KEYWORDS
FROM SENSITIVE_KEYWORDS;

-- ============================================================================
-- STEP 3: Verify the 29 critical keywords remain (in the correct location)
-- ============================================================================

-- Run this against the SAME database/schema where the upsert writes!

SELECT 
    sc.CATEGORY_NAME,
    COUNT(*) AS KEYWORD_COUNT
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_STRING IN (
    -- PII: 13 CRITICAL columns
    'SOCIAL_SECURITY_NUMBER', 'TAX_IDENTIFICATION_NUMBER', 'NATIONAL_ID_NUMBER',
    'DRIVERS_LICENSE_NUMBER', 'PASSPORT_NUMBER', 'VOTER_ID_NUMBER', 'MILITARY_ID_NUMBER',
    'ALIEN_REGISTRATION_NUMBER', 'BIOMETRIC_HASH', 'VOICE_PRINT_ID', 'FINGERPRINT_HASH',
    'HEALTH_CONDITION', 'DEVICE_LOCATION_HISTORY',
    
    -- SOX: 9 CRITICAL columns
    'BANK_ACCOUNT_NUMBER', 'BANK_IBAN', 'CREDIT_CARD_NUMBER', 'CREDIT_CARD_EXPIRY_DATE',
    'CREDIT_CARD_CVV', 'ANNUAL_INCOME', 'CREDIT_SCORE', 'TAX_RETURN_ID', 'PAYMENT_HISTORY',
    
    -- SOC2: 7 CRITICAL columns
    'USER_PASSWORD_HASH', 'API_KEY', 'API_SECRET', 'OAUTH_TOKEN', 'OAUTH_REFRESH_TOKEN',
    'TRADE_SECRET_KEY', 'ENCRYPTED_MESSAGES'
)
GROUP BY sc.CATEGORY_NAME
ORDER BY sc.CATEGORY_NAME;

-- Expected: PII=13, SOC2=7, SOX=9 (Total=29)

-- ============================================================================
-- STEP 4: Verify SOCIAL_SECURITY_NUMBER specifically
-- ============================================================================

SELECT 
    'SOCIAL_SECURITY_NUMBER CHECK' AS STATUS,
    sk.*
FROM SENSITIVE_KEYWORDS sk
WHERE sk.KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- If this returns 0 rows, you're querying the WRONG database/schema!
-- ============================================================================
