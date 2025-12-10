-- ============================================================================
-- VERIFY INLINE EDIT FLOW: Storage → Retrieval → Usage
-- ============================================================================
-- This script verifies that inline edits are:
--   1. Stored in SENSITIVE_KEYWORDS
--   2. Properly joined with SENSITIVITY_CATEGORIES
--   3. Ready to be used in next classification run
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- TEST 1: Check if Inline Edits are Saved
-- ============================================================================

SELECT 
    '✅ TEST 1: Recent Inline Edits' AS TEST_NAME,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.UPDATED_BY,
    sk.UPDATED_AT,
    sk.VERSION_NUMBER,
    sk.IS_ACTIVE
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.UPDATED_AT >= DATEADD(hour, -24, CURRENT_TIMESTAMP())
ORDER BY sk.UPDATED_AT DESC
LIMIT 20;

-- Expected: Should show any keywords edited in last 24 hours

-- ============================================================================
-- TEST 2: Verify Category Joins Work Correctly
-- ============================================================================

SELECT 
    '✅ TEST 2: All Keywords with Categories' AS TEST_NAME,
    sc.CATEGORY_NAME,
    COUNT(*) AS KEYWORD_COUNT,
    AVG(sk.SENSITIVITY_WEIGHT) AS AVG_WEIGHT
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
GROUP BY sc.CATEGORY_NAME
ORDER BY sc.CATEGORY_NAME;

-- Expected: 
-- PII: 13 keywords
-- SOX: 9 keywords
-- SOC2: 7 keywords

-- ============================================================================
-- TEST 3: Check Specific Keyword (SOCIAL_SECURITY_NUMBER)
-- ============================================================================

SELECT 
    '✅ TEST 3: SOCIAL_SECURITY_NUMBER Detail' AS TEST_NAME,
    sk.KEYWORD_ID,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.CATEGORY_ID,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.IS_ACTIVE,
    sk.CREATED_BY,
    sk.CREATED_AT,
    sk.UPDATED_BY,
    sk.UPDATED_AT,
    sk.VERSION_NUMBER
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- Expected:
-- CATEGORY_NAME = 'PII' (not SOC2!)
-- IS_ACTIVE = TRUE
-- SENSITIVITY_WEIGHT = some value (e.g., 0.8)

-- ============================================================================
-- TEST 4: List ALL Active Keywords (What Pipeline Will Use)
-- ============================================================================

SELECT 
    '✅ TEST 4: All Active Keywords for Pipeline' AS TEST_NAME,
    sc.CATEGORY_NAME,
    sk.KEYWORD_STRING,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.VERSION_NUMBER
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
ORDER BY sc.CATEGORY_NAME, sk.KEYWORD_STRING;

-- Expected: 29 total keywords (13 PII + 9 SOX + 7 SOC2)

-- ============================================================================
-- TEST 5: Check for Orphaned Keywords (Bad Category IDs)
-- ============================================================================

SELECT 
    '❌ TEST 5: Orphaned Keywords' AS TEST_NAME,
    sk.KEYWORD_STRING,
    sk.CATEGORY_ID AS BAD_CATEGORY_ID,
    sk.IS_ACTIVE
FROM SENSITIVE_KEYWORDS sk
WHERE NOT EXISTS (
    SELECT 1 
    FROM SENSITIVITY_CATEGORIES sc 
    WHERE sc.CATEGORY_ID = sk.CATEGORY_ID
);

-- Expected: 0 rows (no orphaned keywords)

-- ============================================================================
-- TEST 6: Verify Category Table Structure
-- ============================================================================

SELECT 
    '✅ TEST 6: Available Categories' AS TEST_NAME,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP,
    MIN_CONFIDENCE_THRESHOLD,
    DEFAULT_SENSITIVITY,
    IS_ACTIVE
FROM SENSITIVITY_CATEGORIES
WHERE IS_ACTIVE = TRUE
ORDER BY CATEGORY_NAME;

-- Expected: At least PII, SOX, SOC2 categories

-- ============================================================================
-- TEST 7: Simulate What Pipeline Loads
-- ============================================================================

-- This mimics what _init_local_embeddings does
SELECT 
    '✅ TEST 7: Pipeline Data Load Simulation' AS TEST_NAME,
    sc.CATEGORY_NAME,
    sk.KEYWORD_STRING,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    -- Simulate how keywords are grouped
    LISTAGG(sk.KEYWORD_STRING, ', ') WITHIN GROUP (ORDER BY sk.KEYWORD_STRING) 
        OVER (PARTITION BY sc.CATEGORY_NAME) AS ALL_KEYWORDS_IN_CATEGORY
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
ORDER BY sc.CATEGORY_NAME, sk.KEYWORD_STRING
LIMIT 50;

-- Expected: Shows how keywords are grouped by category for classification

-- ============================================================================
-- TEST 8: Version History (Audit Trail)
-- ============================================================================

SELECT 
    '✅ TEST 8: Keywords with Multiple Versions' AS TEST_NAME,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sk.VERSION_NUMBER,
    sk.CREATED_AT,
    sk.UPDATED_AT,
    DATEDIFF(minute, sk.CREATED_AT, sk.UPDATED_AT) AS MINUTES_SINCE_CREATION
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.VERSION_NUMBER > 1
ORDER BY sk.VERSION_NUMBER DESC, sk.UPDATED_AT DESC;

-- Expected: Keywords that have been edited (version > 1)

-- ============================================================================
-- SUCCESS CRITERIA
-- ============================================================================
/*
✅ TEST 1: Shows recent edits with updated timestamps
✅ TEST 2: Shows correct category distribution (PII=13, SOX=9, SOC2=7)
✅ TEST 3: SOCIAL_SECURITY_NUMBER has category 'PII' (not SOC2)
✅ TEST 4: Shows all 29 active keywords
✅ TEST 5: Returns 0 rows (no orphans)
✅ TEST 6: Shows at least PII, SOX, SOC2 categories
✅ TEST 7: Shows keywords grouped by category
✅ TEST 8: Shows audit trail of edited keywords

If all tests pass:
  → Inline edits ARE being stored correctly ✅
  → Categories ARE properly joined ✅
  → Next pipeline run WILL use updated values ✅
*/

-- ============================================================================
-- QUICK CHECK: Did my last edit save?
-- ============================================================================
-- Replace 'YOUR_KEYWORD' with the keyword you just edited

SELECT 
    '🔍 QUICK CHECK' AS STATUS,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME AS CURRENT_CATEGORY,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.UPDATED_AT,
    sk.UPDATED_BY
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER'  -- Change this
ORDER BY sk.UPDATED_AT DESC
LIMIT 1;

-- ============================================================================
