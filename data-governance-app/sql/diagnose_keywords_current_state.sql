-- ============================================================================
-- DIAGNOSTIC: Check Current State of SENSITIVE_KEYWORDS Table
-- ============================================================================
-- This script checks what keywords currently exist in the table
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA GOVERNANCE;

-- ============================================================================
-- Check 1: Total count of all keywords
-- ============================================================================

SELECT 
    '📊 TOTAL KEYWORDS' AS CHECK_NAME,
    COUNT(*) AS TOTAL_COUNT
FROM SENSITIVE_KEYWORDS;

-- ============================================================================
-- Check 2: Count by category
-- ============================================================================

SELECT 
    '📊 COUNT BY CATEGORY' AS CHECK_NAME,
    CATEGORY,
    COUNT(*) AS KEYWORD_COUNT
FROM SENSITIVE_KEYWORDS
GROUP BY CATEGORY
ORDER BY CATEGORY;

-- ============================================================================
-- Check 3: Check if SOCIAL_SECURITY_NUMBER exists
-- ============================================================================

SELECT 
    '🔍 SOCIAL_SECURITY_NUMBER CHECK' AS CHECK_NAME,
    KEYWORD,
    CATEGORY,
    MATCH_TYPE,
    SENSITIVITY_WEIGHT,
    IS_ACTIVE,
    CREATED_BY,
    CREATED_AT,
    UPDATED_BY,
    UPDATED_AT
FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER'
   OR KEYWORD = 'SOCIAL_SECURITY_NUMBER';

-- ============================================================================
-- Check 4: List ALL keywords (to see what's actually there)
-- ============================================================================

SELECT 
    '📋 ALL KEYWORDS' AS CHECK_NAME,
    KEYWORD,
    CATEGORY,
    MATCH_TYPE,
    SENSITIVITY_WEIGHT,
    IS_ACTIVE
FROM SENSITIVE_KEYWORDS
ORDER BY CATEGORY, KEYWORD;

-- ============================================================================
-- Check 5: Check for the 29 critical keywords specifically
-- ============================================================================

SELECT 
    '✅ CRITICAL KEYWORDS CHECK' AS CHECK_NAME,
    CATEGORY,
    KEYWORD,
    CASE 
        WHEN KEYWORD IS NOT NULL THEN '✅ EXISTS'
        ELSE '❌ MISSING'
    END AS STATUS
FROM (
    SELECT 'PII' AS CATEGORY, 'SOCIAL_SECURITY_NUMBER' AS KEYWORD UNION ALL
    SELECT 'PII', 'TAX_IDENTIFICATION_NUMBER' UNION ALL
    SELECT 'PII', 'NATIONAL_ID_NUMBER' UNION ALL
    SELECT 'PII', 'DRIVERS_LICENSE_NUMBER' UNION ALL
    SELECT 'PII', 'PASSPORT_NUMBER' UNION ALL
    SELECT 'PII', 'VOTER_ID_NUMBER' UNION ALL
    SELECT 'PII', 'MILITARY_ID_NUMBER' UNION ALL
    SELECT 'PII', 'ALIEN_REGISTRATION_NUMBER' UNION ALL
    SELECT 'PII', 'BIOMETRIC_HASH' UNION ALL
    SELECT 'PII', 'VOICE_PRINT_ID' UNION ALL
    SELECT 'PII', 'FINGERPRINT_HASH' UNION ALL
    SELECT 'PII', 'HEALTH_CONDITION' UNION ALL
    SELECT 'PII', 'DEVICE_LOCATION_HISTORY' UNION ALL
    
    SELECT 'SOX', 'BANK_ACCOUNT_NUMBER' UNION ALL
    SELECT 'SOX', 'BANK_IBAN' UNION ALL
    SELECT 'SOX', 'CREDIT_CARD_NUMBER' UNION ALL
    SELECT 'SOX', 'CREDIT_CARD_EXPIRY_DATE' UNION ALL
    SELECT 'SOX', 'CREDIT_CARD_CVV' UNION ALL
    SELECT 'SOX', 'ANNUAL_INCOME' UNION ALL
    SELECT 'SOX', 'CREDIT_SCORE' UNION ALL
    SELECT 'SOX', 'TAX_RETURN_ID' UNION ALL
    SELECT 'SOX', 'PAYMENT_HISTORY' UNION ALL
    
    SELECT 'SOC2', 'USER_PASSWORD_HASH' UNION ALL
    SELECT 'SOC2', 'API_KEY' UNION ALL
    SELECT 'SOC2', 'API_SECRET' UNION ALL
    SELECT 'SOC2', 'OAUTH_TOKEN' UNION ALL
    SELECT 'SOC2', 'OAUTH_REFRESH_TOKEN' UNION ALL
    SELECT 'SOC2', 'TRADE_SECRET_KEY' UNION ALL
    SELECT 'SOC2', 'ENCRYPTED_MESSAGES'
) expected
LEFT JOIN SENSITIVE_KEYWORDS sk 
    ON expected.KEYWORD = sk.KEYWORD 
    AND expected.CATEGORY = sk.CATEGORY
ORDER BY CATEGORY, KEYWORD;

-- ============================================================================
-- Check 6: Check table structure
-- ============================================================================

DESCRIBE TABLE SENSITIVE_KEYWORDS;

-- ============================================================================
-- INTERPRETATION GUIDE
-- ============================================================================
-- Check 1: Shows total number of keywords in table
-- Check 2: Shows breakdown by category (PII, SOX, SOC2)
-- Check 3: Specifically looks for SOCIAL_SECURITY_NUMBER
-- Check 4: Lists ALL keywords currently in the table
-- Check 5: Checks if all 29 critical keywords exist (shows ✅ or ❌)
-- Check 6: Shows table structure (column names and types)
-- ============================================================================
