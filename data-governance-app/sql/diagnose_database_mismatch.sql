-- ============================================================================
-- DATABASE MISMATCH DIAGNOSTIC
-- ============================================================================
--This script helps identify WHERE the SOCIAL_SECURITY_NUMBER keyword actually exists
-- ============================================================================

-- Check 1: Current context
SELECT CURRENT_DATABASE() AS CURRENT_DB, 
       CURRENT_SCHEMA() AS CURRENT_SCHEMA;

-- ============================================================================
-- Check 2: Search in DATA_CLASSIFICATION_DB.GOVERNANCE
-- ============================================================================

SELECT 
    '❓ DATA_CLASSIFICATION_DB.GOVERNANCE' AS LOCATION,
    COUNT(*) AS TOTAL_KEYWORDS,
    SUM(CASE WHEN KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER' THEN 1 ELSE 0 END) AS SSN_COUNT
FROM DATA_CLASSIFICATION_DB.GOVERNANCE.SENSITIVE_KEYWORDS;

SELECT 
   'DATA_CLASSIFICATION_DB.GOVERNANCE - SSN Details' AS CHECK,
    *
FROM DATA_CLASSIFICATION_DB.GOVERNANCE.SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- ============================================================================
-- Check 3: Search in DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE (nested schema)
-- ============================================================================

SELECT 
    '❓ DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE' AS LOCATION,
    COUNT(*) AS TOTAL_KEYWORDS,
    SUM(CASE WHEN KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER' THEN 1 ELSE 0 END) AS SSN_COUNT
FROM DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS;

SELECT 
    'DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE - SSN Details' AS CHECK,
    *
FROM DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- ============================================================================
-- Check 4: List ALL databases that have SENSITIVE_KEYWORDS tables
-- ============================================================================

SHOW TABLES LIKE 'SENSITIVE_KEYWORDS' IN ACCOUNT;

-- ============================================================================
-- Check 5: Show all schemas in DATA_CLASSIFICATION_GOVERNANCE database
-- ============================================================================

SHOW SCHEMAS IN DATABASE DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- Check 6: Show all schemas in DATA_CLASSIFICATION_DB database
-- ============================================================================

SHOW SCHEMAS IN DATABASE DATA_CLASSIFICATION_DB;

-- ============================================================================
-- INTERPRETATION
-- ============================================================================
-- The upsert logs show: "Using schema: DATA_CLASSIFICATION_GOVERNANCE"
-- This MIGHT mean:
--   - Database: DATA_CLASSIFICATION_GOVERNANCE
--   - Schema: DATA_CLASSIFICATION_GOVERNANCE
--   - Table: SENSITIVE_KEYWORDS
--
-- But the cleanup script targets:
--   - Database: DATA_CLASSIFICATION_DB
--   - Schema: GOVERNANCE
--   - Table: SENSITIVE_KEYWORDS
--
-- These are DIFFERENT locations!
-- ============================================================================
