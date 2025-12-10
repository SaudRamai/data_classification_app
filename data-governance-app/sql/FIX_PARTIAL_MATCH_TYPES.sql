-- ============================================================================
-- FIX PARTIAL MATCH TYPES FOR BETTER CLASSIFICATION ACCURACY
-- ============================================================================
-- This script converts overly broad PARTIAL matches to EXACT matches
-- to prevent false positives in data classification.
-- 
-- Target: 90%+ accuracy
-- Run this in your Snowflake governance database
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- Backup current state (optional but recommended)
CREATE OR REPLACE TABLE SENSITIVE_KEYWORDS_BACKUP_20251205 AS 
SELECT * FROM SENSITIVE_KEYWORDS;

-- ============================================================================
-- PHASE 1: Convert SOC2 PARTIAL Keywords to EXACT
-- ============================================================================
UPDATE SENSITIVE_KEYWORDS
SET MATCH_TYPE = 'EXACT',
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'DATA_QUALITY_FIX'
WHERE MATCH_TYPE = 'PARTIAL'
AND KEYWORD_STRING IN (
    'password',
    'two_factor',
    'oauth_token',
    'trade_secret',
    'pin_code',
    'api_secret',
    'security_answer',
    'security_question',
    'passwd',
    'credential',
    'access_log',
    'authentication',
    'permissions',
    'resource_accessed',
    'role_name',
    'user_agent',
    'activity_description'
)
AND CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2' LIMIT 1);

-- ============================================================================
-- PHASE 2: Convert SOX PARTIAL Keywords to EXACT
-- ============================================================================
UPDATE SENSITIVE_KEYWORDS
SET MATCH_TYPE = 'EXACT',
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'DATA_QUALITY_FIX'
WHERE MATCH_TYPE = 'PARTIAL'
AND KEYWORD_STRING IN (
    'revenue',
    'reconciliation',
    'trial_balance',
    'swift_code',
    'salary',
    'financial_close',
    'ledger',
    'payroll',
    'compensation',
    'card_expiry',
    'journal',
    'wage',
    'bonus',
    'financial_history',
    'financial_transaction',
    'transaction_history',
    'billing_history',
    'payment_history',
    'accrual',
    'invoice',
    'payment',
    'ledger_entry'
)
AND CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX' LIMIT 1);

-- ============================================================================
-- PHASE 3: Convert PII PARTIAL Keywords to EXACT
-- ============================================================================
UPDATE SENSITIVE_KEYWORDS
SET MATCH_TYPE = 'EXACT',
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'DATA_QUALITY_FIX'
WHERE MATCH_TYPE = 'PARTIAL'
AND KEYWORD_STRING IN (
    'residential_address'
)
AND CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII' LIMIT 1);

-- ============================================================================
-- PHASE 4: Deactivate Overly Short/Generic PARTIAL Keywords (< 4 chars)
-- ============================================================================
-- These are too short and cause too many false positives even with EXACT matching
UPDATE SENSITIVE_KEYWORDS
SET IS_ACTIVE = FALSE,
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'DATA_QUALITY_FIX',
    UPDATED_REASON = 'Keyword too short - causes false positives'
WHERE MATCH_TYPE = 'PARTIAL'
AND LENGTH(KEYWORD_STRING) < 4
AND KEYWORD_STRING IN ('mfa', '2fa', 'pin');

-- ============================================================================
-- PHASE 5: Verification Queries
-- ============================================================================

-- Check remaining PARTIAL keywords (should be very few or zero)
SELECT 
    CATEGORY_NAME,
    KEYWORD_STRING,
    MATCH_TYPE,
    LENGTH(KEYWORD_STRING) AS KEYWORD_LENGTH,
    IS_ACTIVE
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE MATCH_TYPE = 'PARTIAL'
AND IS_ACTIVE = TRUE
ORDER BY CATEGORY_NAME, LENGTH(KEYWORD_STRING), KEYWORD_STRING;

-- Summary by category and match type
SELECT 
    c.CATEGORY_NAME,
    k.MATCH_TYPE,
    COUNT(*) AS KEYWORD_COUNT,
    AVG(LENGTH(k.KEYWORD_STRING)) AS AVG_KEYWORD_LENGTH
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.IS_ACTIVE = TRUE
GROUP BY c.CATEGORY_NAME, k.MATCH_TYPE
ORDER BY c.CATEGORY_NAME, k.MATCH_TYPE;

-- Check for any deactivated keywords
SELECT 
    CATEGORY_NAME,
    KEYWORD_STRING,
    MATCH_TYPE,
    UPDATED_REASON
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE IS_ACTIVE = FALSE
AND UPDATED_BY = 'DATA_QUALITY_FIX';
