-- ============================================================================
-- DIAGNOSE: Why SOCIAL_SECURITY_NUMBER Detected as SOC2 Instead of PII
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- STEP 1: What category is this CATEGORY_ID?
-- ============================================================================

SELECT 
    '🔍 STEP 1: What is CATEGORY_ID 3e47f6fd-d870-41a8-b75f-e967bb839475?' AS DIAGNOSTIC,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP
FROM SENSITIVITY_CATEGORIES
WHERE CATEGORY_ID = '3e47f6fd-d870-41a8-b75f-e967bb839475';

-- This will tell us if this ID is actually PII or SOC2!

-- ============================================================================
-- STEP 2: Check for case sensitivity issues
-- ============================================================================

SELECT 
    '🔍 STEP 2: All variations of SOCIAL_SECURITY_NUMBER' AS DIAGNOSTIC,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.IS_ACTIVE,
    sk.KEYWORD_ID,
    sk.CATEGORY_ID
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE LOWER(sk.KEYWORD_STRING) = 'social_security_number'
ORDER BY sk.CREATED_AT;

-- Check if there are multiple entries with different cases

-- ============================================================================
-- STEP 3: Get correct PII category ID
-- ============================================================================

SELECT 
    '✅ STEP 3: What is the PII CATEGORY_ID?' AS DIAGNOSTIC,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP
FROM SENSITIVITY_CATEGORIES
WHERE CATEGORY_NAME = 'PII';

-- This is the CATEGORY_ID we SHOULD be using

-- ============================================================================
-- STEP 4: Get SOC2 category ID
-- ============================================================================

SELECT 
    '❌ STEP 4: What is the SOC2 CATEGORY_ID?' AS DIAGNOSTIC,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP
FROM SENSITIVITY_CATEGORIES
WHERE CATEGORY_NAME = 'SOC2';

-- Is the current CATEGORY_ID matching this (wrong) one?

-- ============================================================================
-- STEP 5: Check if there are duplicates
-- ============================================================================

SELECT 
    '⚠️ STEP 5: Duplicate SOCIAL_SECURITY_NUMBER entries?' AS DIAGNOSTIC,
    COUNT(*) AS TOTAL_COUNT,
    COUNT(DISTINCT CATEGORY_ID) AS DISTINCT_CATEGORIES
FROM SENSITIVE_KEYWORDS
WHERE LOWER(KEYWORD_STRING) = 'social_security_number';

-- Expected: COUNT = 1, DISTINCT_CATEGORIES = 1
-- If COUNT > 1, we have duplicates!

-- ============================================================================
-- STEP 6: Show ALL related entries
-- ============================================================================

SELECT 
    '📋 STEP 6: All SOCIAL_SECURITY_NUMBER entries' AS DIAGNOSTIC,
    sk.KEYWORD_ID,
    sc.CATEGORY_NAME AS CURRENT_CATEGORY,
    sk.KEYWORD_STRING AS STORED_AS,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.IS_ACTIVE,
    sk.CREATED_BY,
    sk.CREATED_AT,
    sk.UPDATED_AT,
    sk.VERSION_NUMBER
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE LOWER(sk.KEYWORD_STRING) = 'social_security_number'
ORDER BY sk.CREATED_AT;

-- ============================================================================
-- STEP 7: Check what the AI pipeline is actually loading
-- ============================================================================

SELECT 
    '🤖 STEP 7: What will the AI pipeline load?' AS DIAGNOSTIC,
    sc.CATEGORY_NAME,
    sk.KEYWORD_STRING,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND LOWER(sk.KEYWORD_STRING) LIKE '%social%security%'
ORDER BY sc.CATEGORY_NAME;

-- ============================================================================
-- DIAGNOSIS RESULTS
-- ============================================================================
/*
POSSIBLE ISSUES:

1. WRONG CATEGORY_ID:
   If STEP 1 shows CATEGORY_NAME = 'SOC2'
   → The keyword is stored with SOC2 category ID, not PII!
   → Need to UPDATE to use PII category ID from STEP 3

2. CASE SENSITIVITY:
   If keyword is stored as 'social_security_number' (lowercase)
   But column name is 'SOCIAL_SECURITY_NUMBER' (uppercase)
   → Depends on MATCH_TYPE:
      - CONTAINS: Should work (case-insensitive substring match)
      - EXACT: Won't work (case-sensitive exact match)

3. DUPLICATES:
   If STEP 5 shows COUNT > 1
   → Multiple entries exist, pipeline might pick wrong one
   → Need to delete duplicates, keep only PII version

4. INACTIVE:
   If IS_ACTIVE = FALSE
   → Pipeline won't use it
   → Need to SET IS_ACTIVE = TRUE

Next steps depend on the diagnosis results!
*/
