-- ============================================================================
-- SNOWFLAKE GOVERNANCE TABLE FIXES
-- Fix data quality issues preventing SOX and SOC2 detection
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- ISSUE 1: Incomplete Keyword Records (Missing Required Fields)
-- ============================================================================
-- Several keywords have NULL values for critical fields

-- Fix: Delete incomplete records that can't be used
DELETE FROM SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING IS NULL 
   OR CATEGORY_ID IS NULL
   OR SENSITIVITY_WEIGHT IS NULL
   OR IS_ACTIVE IS NULL;

-- Fix: Set default values for records with missing optional fields
UPDATE SENSITIVE_KEYWORDS
SET CREATED_BY = 'SYSTEM'
WHERE CREATED_BY IS NULL OR CREATED_BY = '';

UPDATE SENSITIVE_KEYWORDS
SET CREATED_AT = CURRENT_TIMESTAMP()
WHERE CREATED_AT IS NULL;

UPDATE SENSITIVE_KEYWORDS
SET UPDATED_AT = CURRENT_TIMESTAMP()
WHERE UPDATED_AT IS NULL;

UPDATE SENSITIVE_KEYWORDS
SET VERSION_NUMBER = 1
WHERE VERSION_NUMBER IS NULL;

-- ============================================================================
-- ISSUE 2: Inactive Keywords That Should Be Active
-- ============================================================================
-- Keywords marked as IS_ACTIVE = FALSE won't be used for detection

-- Activate critical SOX keywords
UPDATE SENSITIVE_KEYWORDS
SET IS_ACTIVE = TRUE
WHERE KEYWORD_STRING IN ('invoice', 'payment', 'vendor', 'expense', 'asset', 'debit')
  AND CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX');

-- Activate critical PII keywords
UPDATE SENSITIVE_KEYWORDS
SET IS_ACTIVE = TRUE
WHERE KEYWORD_STRING IN ('account_number')
  AND CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII');

-- ============================================================================
-- ISSUE 3: Low Sensitivity Weights
-- ============================================================================
-- Some keywords have very low weights (0.2-0.3) which may not trigger detection

-- Increase weights for important date fields (but keep them lower than PII)
UPDATE SENSITIVE_KEYWORDS
SET SENSITIVITY_WEIGHT = 0.5
WHERE KEYWORD_STRING IN ('due_date', 'invoice_date', 'payment_date')
  AND SENSITIVITY_WEIGHT < 0.5;

-- Increase weights for financial keywords
UPDATE SENSITIVE_KEYWORDS
SET SENSITIVITY_WEIGHT = 0.75
WHERE KEYWORD_STRING IN ('invoice', 'payment', 'vendor')
  AND CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX')
  AND SENSITIVITY_WEIGHT < 0.75;

-- ============================================================================
-- ISSUE 4: Missing Critical Keywords
-- ============================================================================
-- Add missing SOX keywords that are in the whitelist but not in the table

INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER)
SELECT 
    UUID_STRING() as KEYWORD_ID,
    (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX') as CATEGORY_ID,
    keyword as KEYWORD_STRING,
    'PARTIAL' as MATCH_TYPE,
    0.85 as SENSITIVITY_WEIGHT,
    TRUE as IS_ACTIVE,
    'SYSTEM' as CREATED_BY,
    CURRENT_TIMESTAMP() as CREATED_AT,
    1 as VERSION_NUMBER
FROM (
    SELECT 'profit' as keyword UNION ALL
    SELECT 'loss' UNION ALL
    SELECT 'salary' UNION ALL
    SELECT 'wage' UNION ALL
    SELECT 'compensation' UNION ALL
    SELECT 'bonus' UNION ALL
    SELECT 'commission' UNION ALL
    SELECT 'income' UNION ALL
    SELECT 'earnings' UNION ALL
    SELECT 'balance'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE KEYWORD_STRING = keywords.keyword 
    AND CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX')
);

-- Add missing SOC2 keywords
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER)
SELECT 
    UUID_STRING() as KEYWORD_ID,
    (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2') as CATEGORY_ID,
    keyword as KEYWORD_STRING,
    'PARTIAL' as MATCH_TYPE,
    0.90 as SENSITIVITY_WEIGHT,
    TRUE as IS_ACTIVE,
    'SYSTEM' as CREATED_BY,
    CURRENT_TIMESTAMP() as CREATED_AT,
    1 as VERSION_NUMBER
FROM (
    SELECT 'refresh_token' as keyword UNION ALL
    SELECT 'auth_token' UNION ALL
    SELECT 'session_key' UNION ALL
    SELECT 'session_token'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE KEYWORD_STRING = keywords.keyword 
    AND CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2')
);

-- ============================================================================
-- ISSUE 5: Detection Thresholds May Be Too High
-- ============================================================================
-- Current thresholds: PII=0.55, SOX=0.60, SOC2=0.65
-- These may be too high when combined with the 0.70 minimum confidence in code

-- OPTION A: Lower thresholds (RECOMMENDED)
UPDATE SENSITIVITY_CATEGORIES
SET DETECTION_THRESHOLD = 0.45
WHERE CATEGORY_NAME = 'PII';

UPDATE SENSITIVITY_CATEGORIES
SET DETECTION_THRESHOLD = 0.50
WHERE CATEGORY_NAME = 'SOX';

UPDATE SENSITIVITY_CATEGORIES
SET DETECTION_THRESHOLD = 0.55
WHERE CATEGORY_NAME = 'SOC2';

-- OPTION B: Keep current thresholds but adjust weights
-- Increase keyword weight to make keyword matching more influential
UPDATE SENSITIVITY_CATEGORIES
SET WEIGHT_KEYWORD = 0.40,
    WEIGHT_EMBEDDING = 0.45,
    WEIGHT_PATTERN = 0.15
WHERE CATEGORY_NAME IN ('SOX', 'SOC2');

-- ============================================================================
-- ISSUE 6: Verify Category Descriptions Are Not Empty
-- ============================================================================
-- Empty descriptions will cause centroid creation to fail

SELECT CATEGORY_NAME, LENGTH(DESCRIPTION) as DESC_LENGTH
FROM SENSITIVITY_CATEGORIES
WHERE DESCRIPTION IS NULL OR TRIM(DESCRIPTION) = '';

-- If any are empty, update them:
UPDATE SENSITIVITY_CATEGORIES
SET DESCRIPTION = 'Financial and accounting data including revenue, transactions, account balances, payments, invoices, general ledger entries, expense reports, payroll, and other financial information subject to SOX compliance'
WHERE CATEGORY_NAME = 'SOX' 
  AND (DESCRIPTION IS NULL OR TRIM(DESCRIPTION) = '');

UPDATE SENSITIVITY_CATEGORIES
SET DESCRIPTION = 'Security and access control data including passwords, authentication tokens, API keys, encryption keys, certificates, credentials, security logs, access records, and other security-critical information'
WHERE CATEGORY_NAME = 'SOC2'
  AND (DESCRIPTION IS NULL OR TRIM(DESCRIPTION) = '');

UPDATE SENSITIVITY_CATEGORIES
SET DESCRIPTION = 'Personal Identifiable Information including names, email addresses, phone numbers, physical addresses, SSN, passport numbers, driver licenses, dates of birth, biometric data, and any information that identifies a natural person'
WHERE CATEGORY_NAME = 'PII'
  AND (DESCRIPTION IS NULL OR TRIM(DESCRIPTION) = '');

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- 1. Count active keywords by category
SELECT 
    sc.CATEGORY_NAME,
    COUNT(*) as TOTAL_KEYWORDS,
    SUM(CASE WHEN sk.IS_ACTIVE = TRUE THEN 1 ELSE 0 END) as ACTIVE_KEYWORDS,
    SUM(CASE WHEN sk.IS_ACTIVE = FALSE THEN 1 ELSE 0 END) as INACTIVE_KEYWORDS
FROM SENSITIVITY_CATEGORIES sc
LEFT JOIN SENSITIVE_KEYWORDS sk ON sc.CATEGORY_ID = sk.CATEGORY_ID
GROUP BY sc.CATEGORY_NAME
ORDER BY sc.CATEGORY_NAME;

-- 2. Check for keywords with low weights
SELECT 
    sc.CATEGORY_NAME,
    sk.KEYWORD_STRING,
    sk.SENSITIVITY_WEIGHT,
    sk.IS_ACTIVE
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.SENSITIVITY_WEIGHT < 0.5
ORDER BY sc.CATEGORY_NAME, sk.SENSITIVITY_WEIGHT;

-- 3. Verify detection thresholds
SELECT 
    CATEGORY_NAME,
    DETECTION_THRESHOLD,
    WEIGHT_EMBEDDING,
    WEIGHT_KEYWORD,
    WEIGHT_PATTERN,
    POLICY_GROUP
FROM SENSITIVITY_CATEGORIES
ORDER BY CATEGORY_NAME;

-- 4. Check for incomplete records
SELECT 
    sc.CATEGORY_NAME,
    COUNT(*) as INCOMPLETE_RECORDS
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_STRING IS NULL 
   OR sk.SENSITIVITY_WEIGHT IS NULL
   OR sk.IS_ACTIVE IS NULL
GROUP BY sc.CATEGORY_NAME;

-- ============================================================================
-- RECOMMENDED: Add Sample Patterns for SOX and SOC2
-- ============================================================================
-- Patterns help detect sensitive data based on format/structure

-- SOX Patterns (if SENSITIVE_PATTERNS table exists)
-- INSERT INTO SENSITIVE_PATTERNS (PATTERN_ID, CATEGORY_ID, PATTERN_REGEX, SENSITIVITY_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE)
-- VALUES 
--     (UUID_STRING(), (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX'), 
--      '\\$[0-9,]+\\.[0-9]{2}', 'CURRENCY', 0.80, TRUE),
--     (UUID_STRING(), (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX'), 
--      'INV-[0-9]{6}', 'INVOICE_NUMBER', 0.75, TRUE);

-- SOC2 Patterns
-- INSERT INTO SENSITIVE_PATTERNS (PATTERN_ID, CATEGORY_ID, PATTERN_REGEX, SENSITIVITY_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE)
-- VALUES 
--     (UUID_STRING(), (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2'), 
--      '[A-Za-z0-9]{32,}', 'API_KEY', 0.85, TRUE),
--     (UUID_STRING(), (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2'), 
--      'Bearer [A-Za-z0-9\\-._~+/]+=*', 'BEARER_TOKEN', 0.90, TRUE);

-- ============================================================================
-- SUMMARY
-- ============================================================================
SELECT 
    'Data Quality Fixes Applied' as STATUS,
    (SELECT COUNT(*) FROM SENSITIVE_KEYWORDS WHERE IS_ACTIVE = TRUE) as TOTAL_ACTIVE_KEYWORDS,
    (SELECT COUNT(*) FROM SENSITIVITY_CATEGORIES WHERE IS_ACTIVE = TRUE) as TOTAL_ACTIVE_CATEGORIES;
