-- ============================================================================
-- CRITICAL KEYWORDS ONLY - Remove Lower Risk Columns
-- ============================================================================
-- This script removes lower-risk keywords from SENSITIVE_KEYWORDS table
-- and keeps only the 29 CRITICAL columns that require strictest controls.
-- 
-- Run this script in your Snowflake worksheet to update the governance database.
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA GOVERNANCE;

-- ============================================================================
-- STEP 1: Remove Lower Risk PII Keywords (10 columns removed)
-- ============================================================================
-- Removing: CUSTOMER_ID, ETHNICITY, RELIGION, DISABILITY_STATUS, 
--           TWO_FACTOR_PHONE, TWO_FACTOR_EMAIL, GPS_COORDINATES, 
--           LAST_KNOWN_LOCATION, VOIP_CALL_RECORDS, VIDEO_CALL_SIGNATURE

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

-- ============================================================================
-- STEP 2: Remove Lower Risk SOX Keywords (4 columns removed)
-- ============================================================================
-- Removing: BANK_ROUTING_NUMBER, BANK_SWIFT_CODE, CREDIT_CARD_HOLDER_NAME,
--           BUSINESS_REGISTRATION_NUMBER

DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN (
    'BANK_ROUTING_NUMBER',
    'BANK_SWIFT_CODE',
    'CREDIT_CARD_HOLDER_NAME',
    'BUSINESS_REGISTRATION_NUMBER'
) AND CATEGORY_ID IN (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX');

-- ============================================================================
-- STEP 3: Remove Lower Risk SOC2 Keywords (5 columns removed)
-- ============================================================================
-- Removing: SECURITY_QUESTION_1, SECURITY_QUESTION_2, IP_ADDRESS,
--           LOGIN_DEVICE_ID, CONFIDENTIAL_AGREEMENT_ID

DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IN (
    'SECURITY_QUESTION_1',
    'SECURITY_QUESTION_2',
    'IP_ADDRESS',
    'LOGIN_DEVICE_ID',
    'CONFIDENTIAL_AGREEMENT_ID'
) AND CATEGORY_ID IN (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2');

-- ============================================================================
-- STEP 4: Verify remaining CRITICAL keywords (29 total)
-- ============================================================================

SELECT 
    CATEGORY,
    COUNT(*) AS KEYWORD_COUNT
FROM SENSITIVE_KEYWORDS
WHERE KEYWORD IN (
    -- PII: 13 CRITICAL columns (Most identifying data)
    'SOCIAL_SECURITY_NUMBER', 'TAX_IDENTIFICATION_NUMBER', 'NATIONAL_ID_NUMBER',
    'DRIVERS_LICENSE_NUMBER', 'PASSPORT_NUMBER', 'VOTER_ID_NUMBER', 'MILITARY_ID_NUMBER',
    'ALIEN_REGISTRATION_NUMBER', 'BIOMETRIC_HASH', 'VOICE_PRINT_ID', 'FINGERPRINT_HASH',
    'HEALTH_CONDITION', 'DEVICE_LOCATION_HISTORY',
    
    -- SOX: 9 CRITICAL columns (Financial accounts and transactions)
    'BANK_ACCOUNT_NUMBER', 'BANK_IBAN', 'CREDIT_CARD_NUMBER', 'CREDIT_CARD_EXPIRY_DATE',
    'CREDIT_CARD_CVV', 'ANNUAL_INCOME', 'CREDIT_SCORE', 'TAX_RETURN_ID', 'PAYMENT_HISTORY',
    
    -- SOC2: 7 CRITICAL columns (Authentication credentials and secrets)
    'USER_PASSWORD_HASH', 'API_KEY', 'API_SECRET', 'OAUTH_TOKEN', 'OAUTH_REFRESH_TOKEN',
    'TRADE_SECRET_KEY', 'ENCRYPTED_MESSAGES'
)
GROUP BY CATEGORY
ORDER BY CATEGORY;

-- Expected Results:
-- PII: 13 keywords
-- SOC2: 7 keywords
-- SOX: 9 keywords
-- Total: 29 keywords

-- ============================================================================
-- STEP 5: View all CRITICAL keywords by category
-- ============================================================================

SELECT 
    CATEGORY,
    KEYWORD,
    MATCH_TYPE,
    SENSITIVITY_WEIGHT,
    CREATED_BY,
    CREATED_AT,
    UPDATED_BY,
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
-- STEP 6: Summary of removed keywords
-- ============================================================================

SELECT 
    '❌ REMOVED - Generic/Lower Risk' AS STATUS,
    CATEGORY,
    KEYWORD,
    'Context-dependent sensitivity' AS REASON
FROM (
    SELECT 'PII' AS CATEGORY, 'CUSTOMER_ID' AS KEYWORD UNION ALL
    SELECT 'PII', 'ETHNICITY' UNION ALL
    SELECT 'PII', 'RELIGION' UNION ALL
    SELECT 'PII', 'DISABILITY_STATUS' UNION ALL
    SELECT 'PII', 'TWO_FACTOR_PHONE' UNION ALL
    SELECT 'PII', 'TWO_FACTOR_EMAIL' UNION ALL
    SELECT 'PII', 'GPS_COORDINATES' UNION ALL
    SELECT 'PII', 'LAST_KNOWN_LOCATION' UNION ALL
    SELECT 'PII', 'VOIP_CALL_RECORDS' UNION ALL
    SELECT 'PII', 'VIDEO_CALL_SIGNATURE' UNION ALL
    
    SELECT 'SOX', 'BANK_ROUTING_NUMBER' UNION ALL
    SELECT 'SOX', 'BANK_SWIFT_CODE' UNION ALL
    SELECT 'SOX', 'CREDIT_CARD_HOLDER_NAME' UNION ALL
    SELECT 'SOX', 'BUSINESS_REGISTRATION_NUMBER' UNION ALL
    
    SELECT 'SOC2', 'SECURITY_QUESTION_1' UNION ALL
    SELECT 'SOC2', 'SECURITY_QUESTION_2' UNION ALL
    SELECT 'SOC2', 'IP_ADDRESS' UNION ALL
    SELECT 'SOC2', 'LOGIN_DEVICE_ID' UNION ALL
    SELECT 'SOC2', 'CONFIDENTIAL_AGREEMENT_ID'
)
ORDER BY CATEGORY, KEYWORD;

-- ============================================================================
-- NEXT STEPS
-- ============================================================================
-- 1. Run this script in Snowflake to remove lower-risk keywords
-- 2. Go to the AI Classification Pipeline in the dashboard
-- 3. Click "🚀 Run New Scan" to re-classify tables with only CRITICAL data
-- 4. Verify that only 29 CRITICAL columns are detected:
--    ✅ 13 PII Columns - Only the most identifying data
--    ✅ 9 SOX Columns - Only financial accounts and transactions
--    ✅ 7 SOC2 Columns - Only authentication credentials and secrets
--
-- All remaining columns have HIGH to CRITICAL sensitivity and require 
-- the strictest controls.
-- ============================================================================
