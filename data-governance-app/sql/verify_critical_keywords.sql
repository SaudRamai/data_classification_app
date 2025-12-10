-- ============================================================================
-- Verify Critical Keywords (29 Total)
-- ============================================================================
-- This script verifies that only the 29 critical keywords remain in the
-- SENSITIVE_KEYWORDS table after cleanup.
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA GOVERNANCE;

-- ============================================================================
-- Check 1: Count by Category (Should be PII=13, SOX=9, SOC2=7)
-- ============================================================================

SELECT 
    '✅ KEYWORD COUNT BY CATEGORY' AS CHECK_NAME,
    CATEGORY,
    COUNT(*) AS KEYWORD_COUNT,
    CASE 
        WHEN CATEGORY = 'PII' AND COUNT(*) = 13 THEN '✅ CORRECT'
        WHEN CATEGORY = 'SOX' AND COUNT(*) = 9 THEN '✅ CORRECT'
        WHEN CATEGORY = 'SOC2' AND COUNT(*) = 7 THEN '✅ CORRECT'
        ELSE '❌ INCORRECT'
    END AS STATUS
FROM SENSITIVE_KEYWORDS
WHERE KEYWORD IN (
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
GROUP BY CATEGORY
ORDER BY CATEGORY;

-- ============================================================================
-- Check 2: Verify Removed Keywords Are Gone
-- ============================================================================

SELECT 
    '❌ VERIFY REMOVED KEYWORDS' AS CHECK_NAME,
    CATEGORY,
    KEYWORD,
    CASE 
        WHEN COUNT(*) = 0 THEN '✅ SUCCESSFULLY REMOVED'
        ELSE '❌ STILL EXISTS'
    END AS STATUS
FROM SENSITIVE_KEYWORDS
WHERE KEYWORD IN (
    -- PII removed
    'CUSTOMER_ID', 'ETHNICITY', 'RELIGION', 'DISABILITY_STATUS',
    'TWO_FACTOR_PHONE', 'TWO_FACTOR_EMAIL', 'GPS_COORDINATES',
    'LAST_KNOWN_LOCATION', 'VOIP_CALL_RECORDS', 'VIDEO_CALL_SIGNATURE',
    
    -- SOX removed
    'BANK_ROUTING_NUMBER', 'BANK_SWIFT_CODE', 'CREDIT_CARD_HOLDER_NAME',
    'BUSINESS_REGISTRATION_NUMBER',
    
    -- SOC2 removed
    'SECURITY_QUESTION_1', 'SECURITY_QUESTION_2', 'IP_ADDRESS',
    'LOGIN_DEVICE_ID', 'CONFIDENTIAL_AGREEMENT_ID'
)
GROUP BY CATEGORY, KEYWORD
ORDER BY CATEGORY, KEYWORD;

-- ============================================================================
-- Check 3: List All Remaining Critical Keywords
-- ============================================================================

SELECT 
    '✅ ALL CRITICAL KEYWORDS' AS CHECK_NAME,
    CATEGORY,
    KEYWORD,
    MATCH_TYPE,
    SENSITIVITY_WEIGHT,
    CREATED_AT,
    UPDATED_AT
FROM SENSITIVE_KEYWORDS
WHERE KEYWORD IN (
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
ORDER BY CATEGORY, KEYWORD;

-- ============================================================================
-- Check 4: Total Count (Should be exactly 29)
-- ============================================================================

SELECT 
    '✅ TOTAL CRITICAL KEYWORDS' AS CHECK_NAME,
    COUNT(*) AS TOTAL_COUNT,
    CASE 
        WHEN COUNT(*) = 29 THEN '✅ CORRECT (29 keywords)'
        ELSE '❌ INCORRECT (Expected 29, got ' || COUNT(*) || ')'
    END AS STATUS
FROM SENSITIVE_KEYWORDS
WHERE KEYWORD IN (
    'SOCIAL_SECURITY_NUMBER', 'TAX_IDENTIFICATION_NUMBER', 'NATIONAL_ID_NUMBER',
    'DRIVERS_LICENSE_NUMBER', 'PASSPORT_NUMBER', 'VOTER_ID_NUMBER', 'MILITARY_ID_NUMBER',
    'ALIEN_REGISTRATION_NUMBER', 'BIOMETRIC_HASH', 'VOICE_PRINT_ID', 'FINGERPRINT_HASH',
    'HEALTH_CONDITION', 'DEVICE_LOCATION_HISTORY',
    'BANK_ACCOUNT_NUMBER', 'BANK_IBAN', 'CREDIT_CARD_NUMBER', 'CREDIT_CARD_EXPIRY_DATE',
    'CREDIT_CARD_CVV', 'ANNUAL_INCOME', 'CREDIT_SCORE', 'TAX_RETURN_ID', 'PAYMENT_HISTORY',
    'USER_PASSWORD_HASH', 'API_KEY', 'API_SECRET', 'OAUTH_TOKEN', 'OAUTH_REFRESH_TOKEN',
    'TRADE_SECRET_KEY', 'ENCRYPTED_MESSAGES'
);

-- ============================================================================
-- Expected Results Summary
-- ============================================================================
-- Check 1: PII=13, SOX=9, SOC2=7 (all marked ✅ CORRECT)
-- Check 2: All removed keywords should show 0 rows (successfully removed)
-- Check 3: Should list exactly 29 keywords
-- Check 4: Total count should be exactly 29 (marked ✅ CORRECT)
-- ============================================================================
