-- GOVERNANCE METADATA DIAGNOSTIC QUERIES
-- Run these to verify your governance tables are properly configured

-- ============================================================
-- 1. CHECK CATEGORY DESCRIPTIONS (Critical for E5 Embeddings)
-- ============================================================
SELECT 
    CATEGORY_NAME,
    LENGTH(COALESCE(DESCRIPTION, '')) AS DESC_LENGTH,
    CASE 
        WHEN LENGTH(COALESCE(DESCRIPTION, '')) < 10 THEN '❌ TOO SHORT'
        WHEN LENGTH(COALESCE(DESCRIPTION, '')) < 50 THEN '⚠️ WEAK'
        ELSE '✅ GOOD'
    END AS QUALITY,
    LEFT(COALESCE(DESCRIPTION, '(EMPTY)'), 100) AS DESCRIPTION_PREVIEW
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
WHERE IS_ACTIVE = TRUE
ORDER BY DESC_LENGTH;

-- Expected: All categories should have descriptions of at least 50 characters
-- Action: Update empty/short descriptions using the fix script


-- ============================================================
-- 2. CHECK KEYWORD COVERAGE
-- ============================================================
SELECT 
    CATEGORY_NAME,
    COUNT(*) AS KEYWORD_COUNT,
    CASE 
        WHEN COUNT(*) < 5 THEN '❌ TOO FEW'
        WHEN COUNT(*) < 10 THEN '⚠️ WEAK'
        ELSE '✅ GOOD'
    END AS COVERAGE
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS
WHERE IS_ACTIVE = TRUE
GROUP BY CATEGORY_NAME
ORDER BY KEYWORD_COUNT;

-- Expected: Each category should have at least 10 keywords
-- Action: Add more keywords for categories with low counts


-- ============================================================
-- 3. CHECK PATTERN COVERAGE
-- ============================================================
SELECT 
    CATEGORY_NAME,
    COUNT(*) AS PATTERN_COUNT,
    SUM(CASE WHEN PATTERN_REGEX IS NULL THEN 1 ELSE 0 END) AS NULL_PATTERNS,
    CASE 
        WHEN COUNT(*) < 3 THEN '❌ TOO FEW'
        WHEN COUNT(*) < 5 THEN '⚠️ WEAK'
        ELSE '✅ GOOD'
    END AS COVERAGE
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS
WHERE IS_ACTIVE = TRUE
GROUP BY CATEGORY_NAME
ORDER BY PATTERN_COUNT;

-- Expected: Each category should have at least 5 patterns
-- Action: Add more patterns for categories with low counts


-- ============================================================
-- 4. CHECK CATEGORY → POLICY GROUP MAPPING
-- ============================================================
SELECT 
    CATEGORY_NAME,
    CASE 
        WHEN UPPER(CATEGORY_NAME) LIKE '%PII%' OR UPPER(CATEGORY_NAME) LIKE '%PERSONAL%' 
             OR UPPER(CATEGORY_NAME) LIKE '%CUSTOMER%' OR UPPER(CATEGORY_NAME) LIKE '%EMPLOYEE%' THEN 'PII'
        WHEN UPPER(CATEGORY_NAME) LIKE '%SOX%' OR UPPER(CATEGORY_NAME) LIKE '%FINANCIAL%' 
             OR UPPER(CATEGORY_NAME) LIKE '%ACCOUNT%' OR UPPER(CATEGORY_NAME) LIKE '%TRANSACTION%' THEN 'SOX'
        WHEN UPPER(CATEGORY_NAME) LIKE '%SOC%' OR UPPER(CATEGORY_NAME) LIKE '%SECURITY%' 
             OR UPPER(CATEGORY_NAME) LIKE '%ACCESS%' OR UPPER(CATEGORY_NAME) LIKE '%CREDENTIAL%' THEN 'SOC2'
        ELSE '❌ UNMAPPED'
    END AS INFERRED_POLICY_GROUP,
    DETECTION_THRESHOLD
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
WHERE IS_ACTIVE = TRUE
ORDER BY INFERRED_POLICY_GROUP, CATEGORY_NAME;

-- Expected: All categories should map to PII, SOX, or SOC2
-- Action: Rename categories or update the policy mapping logic


-- ============================================================
-- 5. CHECK DETECTION THRESHOLDS
-- ============================================================
SELECT 
    CATEGORY_NAME,
    DETECTION_THRESHOLD,
    CASE 
        WHEN DETECTION_THRESHOLD > 0.50 THEN '❌ TOO HIGH (will miss detections)'
        WHEN DETECTION_THRESHOLD > 0.35 THEN '⚠️ MODERATE'
        ELSE '✅ GOOD'
    END AS THRESHOLD_STATUS
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
WHERE IS_ACTIVE = TRUE
ORDER BY DETECTION_THRESHOLD DESC;

-- Expected: Thresholds should be between 0.25 and 0.35 for good recall
-- Action: Lower thresholds using: UPDATE ... SET DETECTION_THRESHOLD = 0.30 WHERE ...


-- ============================================================
-- 6. OVERALL GOVERNANCE HEALTH CHECK
-- ============================================================
SELECT 
    'CATEGORIES' AS TABLE_NAME,
    COUNT(*) AS TOTAL_RECORDS,
    SUM(CASE WHEN LENGTH(COALESCE(DESCRIPTION, '')) < 10 THEN 1 ELSE 0 END) AS ISSUES,
    ROUND(100.0 * SUM(CASE WHEN LENGTH(COALESCE(DESCRIPTION, '')) >= 10 THEN 1 ELSE 0 END) / COUNT(*), 1) AS HEALTH_PCT
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES 
WHERE IS_ACTIVE = TRUE

UNION ALL

SELECT 
    'KEYWORDS',
    COUNT(*),
    SUM(CASE WHEN LENGTH(COALESCE(KEYWORD_STRING, '')) < 3 THEN 1 ELSE 0 END),
    ROUND(100.0 * SUM(CASE WHEN LENGTH(COALESCE(KEYWORD_STRING, '')) >= 3 THEN 1 ELSE 0 END) / COUNT(*), 1)
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS 
WHERE IS_ACTIVE = TRUE

UNION ALL

SELECT 
    'PATTERNS',
    COUNT(*),
    SUM(CASE WHEN PATTERN_REGEX IS NULL THEN 1 ELSE 0 END),
    ROUND(100.0 * SUM(CASE WHEN PATTERN_REGEX IS NOT NULL THEN 1 ELSE 0 END) / COUNT(*), 1)
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS 
WHERE IS_ACTIVE = TRUE;

-- Expected: HEALTH_PCT should be > 95% for all tables
-- Action: Fix issues identified in queries 1-3 above


-- ============================================================
-- 7. SAMPLE CATEGORY DEFINITIONS (for E5 Embedding Quality)
-- ============================================================
SELECT 
    CATEGORY_NAME,
    DESCRIPTION,
    (SELECT COUNT(*) FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS k 
     WHERE k.CATEGORY_NAME = c.CATEGORY_NAME AND k.IS_ACTIVE = TRUE) AS KEYWORD_COUNT,
    (SELECT COUNT(*) FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS p 
     WHERE p.CATEGORY_NAME = c.CATEGORY_NAME AND p.IS_ACTIVE = TRUE) AS PATTERN_COUNT
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES c
WHERE IS_ACTIVE = TRUE
  AND CATEGORY_NAME IN ('PII_PERSONAL_INFO', 'SOX_FINANCIAL_DATA', 'SOC2_SECURITY_DATA')
ORDER BY CATEGORY_NAME;

-- Expected: Rich descriptions + multiple keywords/patterns for each core category
