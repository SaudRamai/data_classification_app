-- ============================================================================
-- CRITICAL KEYWORDS CLEANUP - FINAL VERSION
-- ============================================================================
-- This script removes lower-risk keywords from the CORRECT location:
-- DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS
--
-- This matches where the Python upsert/insert code saves data.
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- STEP 1: Verify current state
-- ============================================================================

SELECT 
    'BEFORE CLEANUP' AS STATUS,
    COUNT(*) AS TOTAL_KEYWORDS
FROM SENSITIVE_KEYWORDS;

SELECT 
    'SAMPLE KEYWORDS - BEFORE CLEANUP' AS STATUS,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sk.SENSITIVITY_WEIGHT
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
ORDER BY sc.CATEGORY_NAME, sk.KEYWORD_STRING
LIMIT 20;

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

SELECT 'Step 2 Complete: Removed' || ROW_COUNT() || ' PII keywords' AS STATUS;

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

SELECT 'Step 3 Complete: Removed' || ROW_COUNT() || ' SOX keywords' AS STATUS;

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

SELECT 'Step 4 Complete: Removed' || ROW_COUNT() || ' SOC2 keywords' AS STATUS;

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

-- Expected Results:
-- PII: 13 keywords
-- SOC2: 7 keywords
-- SOX: 9 keywords

-- ============================================================================
-- STEP 6: Total count after cleanup
-- ============================================================================

SELECT 
    'TOTAL KEYWORDS AFTER CLEANUP' AS STATUS,
    COUNT(*) AS TOTAL_COUNT
FROM SENSITIVE_KEYWORDS;

-- ============================================================================
-- STEP 7: List all remaining critical keywords
-- ============================================================================

SELECT 
    'ALL CRITICAL KEYWORDS - AFTER CLEANUP' AS STATUS,
    sc.CATEGORY_NAME,
    sk.KEYWORD_STRING,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.IS_ACTIVE
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_STRING IN (
    'SOCIAL_SECURITY_NUMBER', 'TAX_IDENTIFICATION_NUMBER', 'NATIONAL_ID_NUMBER',
    'DRIVERS_LICENSE_NUMBER', 'PASSPORT_NUMBER', 'VOTER_ID_NUMBER', 'MILITARY_ID_NUMBER',
    'ALIEN_REGISTRATION_NUMBER', 'BIOMETRIC_HASH', 'VOICE_PRINT_ID', 'FINGERPRINT_HASH',
    'HEALTH_CONDITION', 'DEVICE_LOCATION_HISTORY',
    'BANK_ACCOUNT_NUMBER', 'BANK_IBAN', 'CREDIT_CARD_NUMBER', 'CREDIT_CARD_EXPIRY_DATE',
    'CREDIT_CARD_CVV', 'ANNUAL_INCOME', 'CREDIT_SCORE', 'TAX_RETURN_ID', 'PAYMENT_HISTORY',
    'USER_PASSWORD_HASH', 'API_KEY', 'API_SECRET', 'OAUTH_TOKEN', 'OAUTH_REFRESH_TOKEN',
    'TRADE_SECRET_KEY', 'ENCRYPTED_MESSAGES'
)
ORDER BY sc.CATEGORY_NAME, sk.KEYWORD_STRING;

-- Should return exactly 29 rows

-- ============================================================================
-- STEP 8: Verify SOCIAL_SECURITY_NUMBER specifically
-- ============================================================================

SELECT 
    'SOCIAL_SECURITY_NUMBER - FINAL CHECK' AS STATUS,
    sk.KEYWORD_ID,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.IS_ACTIVE,
    sk.CREATED_BY,
    sk.CREATED_AT,
    sk.UPDATED_BY,
    sk.UPDATED_AT
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- Should return 1 row with CATEGORY_NAME = 'PII'

-- ============================================================================
-- SUCCESS CRITERIA
-- ============================================================================
-- ✅ Step 5: Shows PII=13, SOX=9, SOC2=7
-- ✅ Step 6: Shows TOTAL_COUNT as a reasonable number (depends on other keywords)
-- ✅ Step 7: Returns exactly 29 rows
-- ✅ Step 8: Returns 1 row for SOCIAL_SECURITY_NUMBER with category PII
--
-- NOTE: All future keyword upserts/inserts will save to this location:
--       DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS
-- ============================================================================
