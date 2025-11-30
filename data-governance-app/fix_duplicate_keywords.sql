-- ============================================================================
-- FIX GOVERNANCE DATA: DUPLICATES AND DATES
-- ============================================================================
-- This script performs two critical maintenance tasks:
-- 1. Deduplicates the SENSITIVE_KEYWORDS table (keeping the best record).
-- 2. Fixes invalid or future timestamps in CREATED_AT/UPDATED_AT.
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- PART 1: DEDUPLICATION
-- ============================================================================

-- 1. Create a temporary table with the unique records we want to keep
CREATE OR REPLACE TEMPORARY TABLE KEYWORDS_TO_KEEP AS
SELECT 
    KEYWORD_STRING,
    CATEGORY_ID,
    MAX(SENSITIVITY_WEIGHT) as MAX_WEIGHT,
    MAX(UPDATED_AT) as LATEST_UPDATE
FROM SENSITIVE_KEYWORDS
WHERE IS_ACTIVE = TRUE
GROUP BY KEYWORD_STRING, CATEGORY_ID;

-- 2. Identify the IDs of the records to keep
CREATE OR REPLACE TEMPORARY TABLE IDS_TO_KEEP AS
SELECT a.KEYWORD_ID
FROM SENSITIVE_KEYWORDS a
JOIN KEYWORDS_TO_KEEP b
  ON a.KEYWORD_STRING = b.KEYWORD_STRING
  AND a.CATEGORY_ID = b.CATEGORY_ID
  AND a.SENSITIVITY_WEIGHT = b.MAX_WEIGHT
  AND a.UPDATED_AT = b.LATEST_UPDATE
WHERE a.IS_ACTIVE = TRUE;

-- 3. Deactivate (soft delete) duplicates
UPDATE SENSITIVE_KEYWORDS
SET IS_ACTIVE = FALSE,
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'SYSTEM_CLEANUP'
WHERE KEYWORD_ID NOT IN (SELECT KEYWORD_ID FROM IDS_TO_KEEP)
  AND IS_ACTIVE = TRUE;

-- ============================================================================
-- PART 2: DATE FIXES
-- ============================================================================

-- 1. Fix future dates (set to current time)
UPDATE SENSITIVE_KEYWORDS
SET UPDATED_AT = CURRENT_TIMESTAMP()
WHERE UPDATED_AT > CURRENT_TIMESTAMP();

UPDATE SENSITIVE_KEYWORDS
SET CREATED_AT = CURRENT_TIMESTAMP()
WHERE CREATED_AT > CURRENT_TIMESTAMP();

-- 2. Fix NULL dates
UPDATE SENSITIVE_KEYWORDS
SET CREATED_AT = CURRENT_TIMESTAMP()
WHERE CREATED_AT IS NULL;

UPDATE SENSITIVE_KEYWORDS
SET UPDATED_AT = CURRENT_TIMESTAMP()
WHERE UPDATED_AT IS NULL;

-- ============================================================================
-- VERIFICATION
-- ============================================================================

SELECT 
    'Governance Data Cleaned' as STATUS,
    (SELECT COUNT(*) FROM SENSITIVE_KEYWORDS WHERE IS_ACTIVE = TRUE) as ACTIVE_KEYWORDS,
    (SELECT COUNT(DISTINCT KEYWORD_STRING) FROM SENSITIVE_KEYWORDS WHERE IS_ACTIVE = TRUE) as UNIQUE_KEYWORDS;
