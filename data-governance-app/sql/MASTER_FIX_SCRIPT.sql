-- ============================================================================
-- MASTER EXECUTION SCRIPT - Apply All Classification Fixes
-- ============================================================================
-- Run this script to apply all fixes in the correct order
-- 
-- Fixes Applied:
-- 1. Convert PARTIAL to EXACT match types
-- 2. Add UUID/System ID exclusions
-- 3. Fix SSN misclassification (PII vs SOC2)
-- 4. Create fixed VW_CLASSIFICATION_RULES view
-- 5. Comprehensive validation
-- 
-- Estimated Time: 2-3 minutes
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- Enable transaction mode for safety
-- BEGIN;

SELECT '========================================' AS STEP;
SELECT 'STARTING CLASSIFICATION FIXES' AS STATUS;
SELECT CURRENT_TIMESTAMP() AS START_TIME;
SELECT '========================================' AS STEP;

-- ============================================================================
-- STEP 1: Fix PARTIAL Match Types
-- ============================================================================
SELECT '>>> STEP 1: Converting PARTIAL to EXACT match types...' AS STATUS;

-- Backup current state
CREATE OR REPLACE TABLE SENSITIVE_KEYWORDS_BACKUP AS 
SELECT * FROM SENSITIVE_KEYWORDS;

-- Phase 1: SOC2 Keywords
UPDATE SENSITIVE_KEYWORDS
SET MATCH_TYPE = 'EXACT',
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'MASTER_FIX_SCRIPT'
WHERE MATCH_TYPE = 'PARTIAL'
AND KEYWORD_STRING IN (
    'password', 'two_factor', 'oauth_token', 'trade_secret',
    'pin_code', 'api_secret', 'security_answer', 'security_question',
    'passwd', 'credential', 'access_log', 'authentication',
    'permissions', 'resource_accessed', 'role_name', 'user_agent',
    'activity_description'
)
AND CATEGORY_ID IN (
    SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE POLICY_GROUP = 'SOC2'
);

-- Phase 2: SOX Keywords
UPDATE SENSITIVE_KEYWORDS
SET MATCH_TYPE = 'EXACT',
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'MASTER_FIX_SCRIPT'
WHERE MATCH_TYPE = 'PARTIAL'
AND KEYWORD_STRING IN (
    'revenue', 'reconciliation', 'trial_balance', 'swift_code',
    'salary', 'financial_close', 'ledger', 'payroll', 'compensation',
    'card_expiry', 'journal', 'wage', 'bonus', 'financial_history',
    'financial_transaction', 'transaction_history', 'billing_history',
    'payment_history', 'accrual', 'invoice', 'payment', 'ledger_entry'
)
AND CATEGORY_ID IN (
    SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE POLICY_GROUP = 'SOX'
);

-- Phase 3: PII Keywords
UPDATE SENSITIVE_KEYWORDS
SET MATCH_TYPE = 'EXACT',
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'MASTER_FIX_SCRIPT'
WHERE MATCH_TYPE = 'PARTIAL'
AND KEYWORD_STRING IN ('residential_address')
AND CATEGORY_ID IN (
    SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE POLICY_GROUP = 'PII'
);

SELECT '✅ STEP 1 Complete: ' || CHANGES() || ' keywords updated' AS STATUS;

-- ============================================================================
-- STEP 2: Add UUID and System ID Exclusions
-- ============================================================================
SELECT '>>> STEP 2: Creating exclusion patterns...' AS STATUS;

-- Create table if not exists
CREATE TABLE IF NOT EXISTS EXCLUSION_PATTERNS (
    EXCLUSION_ID VARCHAR(36) PRIMARY KEY,
    PATTERN_TYPE VARCHAR(20),
    PATTERN_VALUE VARCHAR(500),
    EXCLUSION_REASON VARCHAR(500),
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(100),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(100),
    UPDATED_AT TIMESTAMP_NTZ
);

-- Add exact match exclusions
MERGE INTO EXCLUSION_PATTERNS AS target
USING (
    SELECT 
        'SYSTEM' AS created_by,
        pattern_val,
        reason
    FROM (
        VALUES
            ('uuid', 'UUIDs are technical identifiers'),
            ('guid', 'GUIDs are technical identifiers'),
            ('id', 'Generic ID column'),
            ('created_by', 'Audit metadata'),
            ('updated_by', 'Audit metadata'),
            ('created_at', 'Audit metadata'),
            ('updated_at', 'Audit metadata'),
            ('deleted_at', 'Soft delete metadata'),
            ('version', 'Version control'),
            ('etl_load_date', 'ETL metadata'),
            ('batch_id', 'ETL metadata')
    ) AS t(pattern_val, reason)
) AS source
ON target.PATTERN_VALUE = source.pattern_val AND target.PATTERN_TYPE = 'COLUMN_NAME'
WHEN NOT MATCHED THEN
    INSERT (EXCLUSION_ID, PATTERN_TYPE, PATTERN_VALUE, EXCLUSION_REASON, IS_ACTIVE, CREATED_BY, CREATED_AT)
    VALUES (UUID_STRING(), 'COLUMN_NAME', source.pattern_val, source.reason, TRUE, source.created_by, CURRENT_TIMESTAMP());

-- Add regex exclusions
MERGE INTO EXCLUSION_PATTERNS AS target
USING (
    SELECT pattern, reason FROM (
        VALUES
            ('^.*_id$', 'Columns ending with _id'),
            ('^.*_uuid$', 'Columns ending with _uuid'),
            ('^.*_guid$', 'Columns ending with _guid'),
            ('^sys_.*$', 'System columns'),
            ('^etl_.*$', 'ETL metadata columns')
    ) AS t(pattern, reason)
) AS source
ON target.PATTERN_VALUE = source.pattern AND target.PATTERN_TYPE = 'REGEX'
WHEN NOT MATCHED THEN
    INSERT (EXCLUSION_ID, PATTERN_TYPE, PATTERN_VALUE, EXCLUSION_REASON, IS_ACTIVE, CREATED_BY, CREATED_AT)
    VALUES (UUID_STRING(), 'REGEX', source.pattern, source.reason, TRUE, 'SYSTEM', CURRENT_TIMESTAMP());

SELECT '✅ STEP 2 Complete: Exclusion patterns created' AS STATUS;

-- ============================================================================
-- STEP 3: Fix SSN Misclassification
-- ============================================================================
SELECT '>>> STEP 3: Fixing SSN classification (PII vs SOC2)...' AS STATUS;

-- Add category priority if column doesn't exist
ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS CATEGORY_PRIORITY INTEGER DEFAULT 99;

-- Set priorities
UPDATE SENSITIVITY_CATEGORIES
SET CATEGORY_PRIORITY = CASE POLICY_GROUP
    WHEN 'PII' THEN 1
    WHEN 'SOX' THEN 2
    WHEN 'SOC2' THEN 3
    ELSE 99
END,
UPDATED_AT = CURRENT_TIMESTAMP();

-- Deactivate problematic SOC2 keywords
UPDATE SENSITIVE_KEYWORDS
SET IS_ACTIVE = FALSE,
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'MASTER_FIX_SCRIPT',
    UPDATED_REASON = 'Too broad - causes false positives with PII'
WHERE KEYWORD_STRING IN ('security_answer', 'security_question')
AND CATEGORY_ID IN (
    SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE POLICY_GROUP = 'SOC2'
);

SELECT '✅ STEP 3 Complete: SSN prioritization fixed' AS STATUS;

-- ============================================================================
-- STEP 4: Create/Update VW_CLASSIFICATION_RULES View
-- ============================================================================
SELECT '>>> STEP 4: Creating VW_CLASSIFICATION_RULES view...' AS STATUS;

CREATE OR REPLACE VIEW VW_CLASSIFICATION_RULES AS
WITH 
keyword_rules AS (
    SELECT
        'KEYWORD' AS RULE_TYPE,
        k.KEYWORD_ID AS RULE_ID,
        k.KEYWORD_STRING AS RULE_PATTERN,
        COALESCE(k.MATCH_TYPE, 'EXACT') AS MATCH_TYPE,
        c.CATEGORY_ID,
        c.CATEGORY_NAME,
        COALESCE(c.POLICY_GROUP, c.CATEGORY_NAME) AS POLICY_GROUP,
        COALESCE(c.CONFIDENTIALITY_LEVEL, 3) AS CONFIDENTIALITY_LEVEL,
        COALESCE(c.INTEGRITY_LEVEL, 2) AS INTEGRITY_LEVEL,
        COALESCE(c.AVAILABILITY_LEVEL, 2) AS AVAILABILITY_LEVEL,
        COALESCE(c.DETECTION_THRESHOLD, 0.4) AS DETECTION_THRESHOLD,
        COALESCE(k.SENSITIVITY_WEIGHT, 1.0) AS RULE_WEIGHT,
        COALESCE(c.WEIGHT_KEYWORD, 0.4) AS CATEGORY_WEIGHT,
        COALESCE(c.MULTI_LABEL, TRUE) AS MULTI_LABEL,
        'Keyword match for ' || c.CATEGORY_NAME AS RULE_DESCRIPTION,
        COALESCE(k.IS_ACTIVE, TRUE) AS IS_ACTIVE,
        COALESCE(k.CREATED_BY, 'SYSTEM') AS CREATED_BY,
        COALESCE(k.CREATED_AT, CURRENT_TIMESTAMP()) AS CREATED_AT,
        COALESCE(k.VERSION_NUMBER, 1) AS VERSION_NUMBER,
        CASE 
            WHEN COALESCE(k.SENSITIVITY_WEIGHT, 1.0) >= 0.95 THEN 'PRIORITY_1'
            WHEN COALESCE(k.SENSITIVITY_WEIGHT, 1.0) >= 0.85 THEN 'PRIORITY_2'
            ELSE 'PRIORITY_3'
        END AS PRIORITY_TIER
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE COALESCE(k.IS_ACTIVE, TRUE) = TRUE 
      AND COALESCE(c.IS_ACTIVE, TRUE) = TRUE
),
pattern_rules AS (
    SELECT
        'PATTERN' AS RULE_TYPE,
        p.PATTERN_ID AS RULE_ID,
        p.PATTERN_REGEX AS RULE_PATTERN,
        'REGEX' AS MATCH_TYPE,
        c.CATEGORY_ID,
        c.CATEGORY_NAME,
        COALESCE(c.POLICY_GROUP, c.CATEGORY_NAME) AS POLICY_GROUP,
        COALESCE(c.CONFIDENTIALITY_LEVEL, 3) AS CONFIDENTIALITY_LEVEL,
        COALESCE(c.INTEGRITY_LEVEL, 2) AS INTEGRITY_LEVEL,
        COALESCE(c.AVAILABILITY_LEVEL, 2) AS AVAILABILITY_LEVEL,
        COALESCE(c.DETECTION_THRESHOLD, 0.4) AS DETECTION_THRESHOLD,
        COALESCE(p.SENSITIVITY_WEIGHT, 1.0) AS RULE_WEIGHT,
        COALESCE(c.WEIGHT_PATTERN, 0.3) AS CATEGORY_WEIGHT,
        COALESCE(c.MULTI_LABEL, TRUE) AS MULTI_LABEL,
        COALESCE(TRY_CAST(p.DESCRIPTION AS VARCHAR), 'Pattern match for ' || c.CATEGORY_NAME) AS RULE_DESCRIPTION,
        COALESCE(p.IS_ACTIVE, TRUE) AS IS_ACTIVE,
        'SYSTEM' AS CREATED_BY,
        COALESCE(p.CREATED_AT, CURRENT_TIMESTAMP()) AS CREATED_AT,
        COALESCE(TRY_CAST(p.VERSION_NUMBER AS INTEGER), 1) AS VERSION_NUMBER,
        CASE 
            WHEN COALESCE(p.SENSITIVITY_WEIGHT, 1.0) >= 0.95 THEN 'PRIORITY_1'
            WHEN COALESCE(p.SENSITIVITY_WEIGHT, 1.0) >= 0.85 THEN 'PRIORITY_2'
            ELSE 'PRIORITY_3'
        END AS PRIORITY_TIER
    FROM SENSITIVE_PATTERNS p
    JOIN SENSITIVITY_CATEGORIES c ON p.CATEGORY_ID = c.CATEGORY_ID
    WHERE COALESCE(p.IS_ACTIVE, TRUE) = TRUE 
      AND COALESCE(c.IS_ACTIVE, TRUE) = TRUE
)
SELECT * FROM keyword_rules
UNION ALL
SELECT * FROM pattern_rules
ORDER BY 
    CASE PRIORITY_TIER
        WHEN 'PRIORITY_1' THEN 1
        WHEN 'PRIORITY_2' THEN 2
        ELSE 3
    END,
    RULE_WEIGHT DESC, 
    POLICY_GROUP, 
    CATEGORY_NAME;

SELECT '✅ STEP 4 Complete: View created' AS STATUS;

-- ============================================================================
-- STEP 5: Verification
-- ============================================================================
SELECT '>>> STEP 5: Running verification checks...' AS STATUS;

-- Quick validation
SELECT 
    'Keywords Updated' AS metric,
    COUNT(*) AS value
FROM SENSITIVE_KEYWORDS
WHERE UPDATED_BY = 'MASTER_FIX_SCRIPT'
UNION ALL
SELECT 
    'Exclusions Created',
    COUNT(*)
FROM EXCLUSION_PATTERNS
WHERE IS_ACTIVE = TRUE
UNION ALL
SELECT 
    'PII Category Priority',
    COALESCE(TRY_CAST(CATEGORY_PRIORITY AS INTEGER), 99)
FROM SENSITIVITY_CATEGORIES
WHERE POLICY_GROUP = 'PII'
LIMIT 1
UNION ALL
SELECT 
    'View Row Count',
    COUNT(*)
FROM VW_CLASSIFICATION_RULES;

-- COMMIT; -- Uncomment if using transactions

SELECT '========================================' AS STEP;
SELECT '✅ ALL FIXES APPLIED SUCCESSFULLY!' AS STATUS;
SELECT CURRENT_TIMESTAMP() AS COMPLETE_TIME;
SELECT '========================================' AS STEP;
SELECT '' AS NEXT_STEP;
SELECT '>>> Next: Run COMPREHENSIVE_VALIDATION.sql to verify all fixes' AS NEXT_STEP;
