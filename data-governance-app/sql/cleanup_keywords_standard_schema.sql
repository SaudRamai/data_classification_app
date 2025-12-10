-- ============================================================================
-- CRITICAL KEYWORDS CLEANUP - CORRECTED FOR STANDARD SCHEMA
-- ============================================================================
-- This script removes lower-risk keywords using the STANDARD schema structure:
-- DATA_CLASSIFICATION_DB.GOVERNANCE.SENSITIVE_KEYWORDS
--
-- After the Python code fix, data will be saved here going forward.
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA GOVERNANCE;

-- ============================================================================
-- STEP 1: Verify current location
-- ============================================================================

SELECT 
    'BEFORE CLEANUP' AS STATUS,
    COUNT(*) AS TOTAL_KEYWORDS
FROM SENSITIVE_KEYWORDS;

SELECT 
    'SAMPLE KEYWORDS BEFORE' AS STATUS,
    KEYWORD_STRING,
    sc.CATEGORY_NAME
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
LIMIT 10;

-- ============================================================================
-- STEP 2: Remove Lower Risk PII Keywords (10 columns)
-- ============================================================================

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
) AND CATEGORY_ID IN (
    SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII'
);

-- ============================================================================
-- STEP 3: Remove Lower Risk SOX Keywords (4 columns)
-- ============================================================================

DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN (
    'BANK_ROUTING_NUMBER',
    'BANK_SWIFT_CODE',
    'CREDIT_CARD_HOLDER_NAME',
    'BUSINESS_REGISTRATION_NUMBER'
) AND CATEGORY_ID IN (
    SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX'
);

-- ============================================================================
-- STEP 4: Remove Lower Risk SOC2 Keywords (5 columns)
-- ============================================================================

DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN (
    'SECURITY_QUESTION_1',
    'SECURITY_QUESTION_2',
    'IP_ADDRESS',
    'LOGIN_DEVICE_ID',
    'CONFIDENTIAL_AGREEMENT_ID'
) AND CATEGORY_ID IN (
    SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2'
);

-- ============================================================================
-- STEP 5: Verify the 29 critical keywords remain
-- ============================================================================

SELECT 
    'AFTER CLEANUP - COUNT BY CATEGORY' AS STATUS,
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
-- STEP 6: Total count verification
-- ============================================================================

SELECT 
    'TOTAL KEYWORDS AFTER CLEANUP' AS STATUS,
    COUNT(*) AS TOTAL_COUNT
FROM SENSITIVE_KEYWORDS;

-- ============================================================================
-- STEP 7: Verify SOCIAL_SECURITY_NUMBER specifically
-- ============================================================================

SELECT 
    'SOCIAL_SECURITY_NUMBER CHECK' AS STATUS,
    sk.*
FROM SENSITIVE_KEYWORDS sk
WHERE sk.KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- Should return 1 row with category PII

-- ============================================================================
-- NEXT STEPS
-- ============================================================================
-- 1. Future keywords will be saved to DATA_CLASSIFICATION_DB.GOVERNANCE
-- 2. Query using: SELECT * FROM DATA_CLASSIFICATION_DB.GOVERNANCE.SENSITIVE_KEYWORDS
-- 3. Or just: SELECT * FROM SENSITIVE_KEYWORDS (if context is set)
-- ============================================================================
