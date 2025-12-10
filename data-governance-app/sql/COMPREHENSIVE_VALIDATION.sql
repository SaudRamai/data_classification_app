-- ============================================================================
-- COMPREHENSIVE VALIDATION SCRIPT - All Classification Fixes
-- ============================================================================
-- This script validates:
-- 1. PARTIAL match type fixes
-- 2. UUID/System ID exclusions
-- 3. SSN misclassification fix (PII vs SOC2)
-- 4. VW_CLASSIFICATION_RULES view
-- 5. Overall data quality
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- Set output formatting
-- !set output_format=vertical

-- ============================================================================
-- TEST 1: Verify PARTIAL Match Types Are Fixed
-- ============================================================================
SELECT '=== TEST 1: PARTIAL Match Type Validation ===' AS TEST_SECTION;

SELECT 
    c.POLICY_GROUP,
    k.MATCH_TYPE,
    COUNT(*) AS KEYWORD_COUNT,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (PARTITION BY c.POLICY_GROUP), 1) AS PERCENTAGE
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.IS_ACTIVE = TRUE
GROUP BY c.POLICY_GROUP, k.MATCH_TYPE
ORDER BY c.POLICY_GROUP, k.MATCH_TYPE;

-- Expected: Very few PARTIAL matches, mostly EXACT
-- Success Criteria: PARTIAL < 5% for each policy group

-- Show remaining PARTIAL keywords (should be minimal)
SELECT 
    '=== Remaining PARTIAL Keywords ===' AS DETAIL,
    c.POLICY_GROUP,
    k.KEYWORD_STRING,
    k.MATCH_TYPE,
    k.SENSITIVITY_WEIGHT
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.IS_ACTIVE = TRUE
AND k.MATCH_TYPE = 'PARTIAL'
ORDER BY c.POLICY_GROUP, k.KEYWORD_STRING
LIMIT 20;

-- ============================================================================
-- TEST 2: Validate Exclusion Patterns Exist
-- ============================================================================
SELECT '=== TEST 2: Exclusion Patterns Validation ===' AS TEST_SECTION;

-- Check if table exists and has data
SELECT 
    PATTERN_TYPE,
    COUNT(*) AS PATTERN_COUNT
FROM EXCLUSION_PATTERNS
WHERE IS_ACTIVE = TRUE
GROUP BY PATTERN_TYPE
ORDER BY PATTERN_TYPE;

-- Expected: Multiple COLUMN_NAME and REGEX patterns
-- Success Criteria: At least 20 exact matches, 10 regex patterns

-- Test exclusion logic on sample columns
WITH test_columns AS (
    SELECT 'uuid' AS col_name, 'Should be excluded' AS expected UNION ALL
    SELECT 'user_id', 'Should be excluded' UNION ALL
    SELECT 'created_at', 'Should be excluded' UNION ALL
    SELECT 'email', 'Should NOT be excluded' UNION ALL
    SELECT 'ssn', 'Should NOT be excluded' UNION ALL
    SELECT 'social_security_number', 'Should NOT be excluded' UNION ALL
    SELECT 'customer_uuid', 'Should be excluded' UNION ALL
    SELECT 'transaction_id', 'Should be excluded' UNION ALL
    SELECT 'password_hash', 'Should NOT be excluded'
)
SELECT 
    tc.col_name,
    tc.expected,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM EXCLUSION_PATTERNS ep
            WHERE ep.IS_ACTIVE = TRUE
            AND (
                (ep.PATTERN_TYPE = 'COLUMN_NAME' AND LOWER(tc.col_name) = LOWER(ep.PATTERN_VALUE))
                OR
                (ep.PATTERN_TYPE = 'REGEX' AND RLIKE(LOWER(tc.col_name), ep.PATTERN_VALUE, 'i'))
            )
        ) THEN '🚫 EXCLUDED'
        ELSE '✅ INCLUDED'
    END AS actual_status,
    CASE 
        WHEN (tc.expected LIKE '%NOT%' AND NOT EXISTS (
            SELECT 1 FROM EXCLUSION_PATTERNS ep
            WHERE ep.IS_ACTIVE = TRUE
            AND (
                (ep.PATTERN_TYPE = 'COLUMN_NAME' AND LOWER(tc.col_name) = LOWER(ep.PATTERN_VALUE))
                OR
                (ep.PATTERN_TYPE = 'REGEX' AND RLIKE(LOWER(tc.col_name), ep.PATTERN_VALUE, 'i'))
            )
        )) THEN '✅ PASS'
        WHEN (tc.expected NOT LIKE '%NOT%' AND EXISTS (
            SELECT 1 FROM EXCLUSION_PATTERNS ep
            WHERE ep.IS_ACTIVE = TRUE
            AND (
                (ep.PATTERN_TYPE = 'COLUMN_NAME' AND LOWER(tc.col_name) = LOWER(ep.PATTERN_VALUE))
                OR
                (ep.PATTERN_TYPE = 'REGEX' AND RLIKE(LOWER(tc.col_name), ep.PATTERN_VALUE, 'i'))
            )
        )) THEN '✅ PASS'
        ELSE '❌ FAIL'
    END AS test_result
FROM test_columns tc
ORDER BY 
    CASE WHEN test_result = '❌ FAIL' THEN 1 ELSE 2 END,
    col_name;

-- ============================================================================
-- TEST 3: Validate SSN Classification (PII Only, Not SOC2)
-- ============================================================================
SELECT '=== TEST 3: SSN Misclassification Fix ===' AS TEST_SECTION;

-- Check category priorities
SELECT 
    CATEGORY_NAME,
    POLICY_GROUP,
    COALESCE(TRY_CAST(CATEGORY_PRIORITY AS INTEGER), 99) AS CATEGORY_PRIORITY
FROM SENSITIVITY_CATEGORIES
WHERE IS_ACTIVE = TRUE
ORDER BY CATEGORY_PRIORITY;

-- Expected: PII=1, SOX=2, SOC2=3

-- Check SSN keywords are in PII only
SELECT 
    '=== SSN Keywords ===' AS DETAIL,
    c.CATEGORY_NAME,
    c.POLICY_GROUP,
    k.KEYWORD_STRING,
    k.MATCH_TYPE,
    k.IS_ACTIVE
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE LOWER(k.KEYWORD_STRING) LIKE '%social%security%'
   OR LOWER(k.KEYWORD_STRING) IN ('ssn', 'social_security_no')
ORDER BY c.POLICY_GROUP, k.KEYWORD_STRING;

-- Expected: All in PII, none in SOC2

-- Check for deactivated SOC2 "security" keywords
SELECT 
    '=== SOC2 Security Keywords Status ===' AS DETAIL,
    k.KEYWORD_STRING,
    k.IS_ACTIVE,
    k.UPDATED_REASON
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE c.POLICY_GROUP = 'SOC2'
AND k.KEYWORD_STRING IN ('security_answer', 'security_question')
ORDER BY k.KEYWORD_STRING;

-- Expected: Both deactivated with reason

-- Test classification logic simulation
WITH test_columns AS (
    SELECT 'SOCIAL_SECURITY_NUMBER' AS col_name UNION ALL
    SELECT 'SSN' UNION ALL
    SELECT 'user_social_security_number'
),
-- Simulate keyword matching
keyword_matches AS (
    SELECT 
        tc.col_name,
        c.CATEGORY_NAME,
        c.POLICY_GROUP,
        COALESCE(TRY_CAST(c.CATEGORY_PRIORITY AS INTEGER), 99) AS CATEGORY_PRIORITY,
        k.KEYWORD_STRING,
        k.MATCH_TYPE,
        k.SENSITIVITY_WEIGHT,
        CASE 
            WHEN k.MATCH_TYPE = 'EXACT' AND LOWER(tc.col_name) = LOWER(k.KEYWORD_STRING) THEN 1.0
            WHEN k.MATCH_TYPE = 'EXACT' AND LOWER(tc.col_name) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%' 
                 AND REGEXP_LIKE(LOWER(tc.col_name), '\\b' || LOWER(k.KEYWORD_STRING) || '\\b') THEN 0.9
            WHEN k.MATCH_TYPE = 'PARTIAL' AND LOWER(tc.col_name) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%' THEN 0.7
            ELSE 0.0
        END AS match_score
    FROM test_columns tc
    CROSS JOIN SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE
    AND c.IS_ACTIVE = TRUE
    AND (
        (k.MATCH_TYPE = 'EXACT' AND LOWER(tc.col_name) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%')
        OR (k.MATCH_TYPE = 'PARTIAL' AND LOWER(k.KEYWORD_STRING) LIKE '%' || LOWER(tc.col_name) || '%')
    )
),
-- Get best match per column
best_matches AS (
    SELECT 
        col_name,
        CATEGORY_NAME,
        POLICY_GROUP,
        CATEGORY_PRIORITY,
        KEYWORD_STRING,
        match_score,
        ROW_NUMBER() OVER (
            PARTITION BY col_name 
            ORDER BY CATEGORY_PRIORITY, match_score DESC, SENSITIVITY_WEIGHT DESC
        ) AS rn
    FROM keyword_matches
    WHERE match_score > 0
)
SELECT 
    col_name,
    CATEGORY_NAME AS predicted_category,
    POLICY_GROUP AS predicted_policy_group,
    KEYWORD_STRING AS matched_keyword,
    ROUND(match_score, 2) AS score,
    CASE 
        WHEN POLICY_GROUP = 'PII' THEN '✅ CORRECT'
        ELSE '❌ WRONG - Should be PII'
    END AS validation
FROM best_matches
WHERE rn = 1
ORDER BY col_name;

-- Expected: All SSN variants should show PII, not SOC2

-- ============================================================================
-- TEST 4: Validate VW_CLASSIFICATION_RULES View
-- ============================================================================
SELECT '=== TEST 4: VW_CLASSIFICATION_RULES View Validation ===' AS TEST_SECTION;

-- Test view exists and returns data
SELECT 
    RULE_TYPE,
    POLICY_GROUP,
    PRIORITY_TIER,
    COUNT(*) AS RULE_COUNT
FROM VW_CLASSIFICATION_RULES
GROUP BY RULE_TYPE, POLICY_GROUP, PRIORITY_TIER
ORDER BY POLICY_GROUP, PRIORITY_TIER, RULE_TYPE;

-- Expected: Mixed KEYWORD and PATTERN rules across all policy groups

-- Sample top priority rules
SELECT 
    '=== Top Priority Rules Sample ===' AS DETAIL,
    RULE_TYPE,
    POLICY_GROUP,
    RULE_PATTERN,
    MATCH_TYPE,
    RULE_WEIGHT,
    PRIORITY_TIER
FROM VW_CLASSIFICATION_RULES
WHERE PRIORITY_TIER = 'PRIORITY_1'
LIMIT 20;

-- ============================================================================
-- TEST 5: Overall Data Quality Metrics
-- ============================================================================
SELECT '=== TEST 5: Overall Data Quality ===' AS TEST_SECTION;

-- Count active rules by policy group
SELECT 
    c.POLICY_GROUP,
    COUNT(DISTINCT k.KEYWORD_ID) AS keyword_count,
    COUNT(DISTINCT p.PATTERN_ID) AS pattern_count,
    COUNT(DISTINCT k.KEYWORD_ID) + COUNT(DISTINCT p.PATTERN_ID) AS total_rules
FROM SENSITIVITY_CATEGORIES c
LEFT JOIN SENSITIVE_KEYWORDS k ON c.CATEGORY_ID = k.CATEGORY_ID AND k.IS_ACTIVE = TRUE
LEFT JOIN SENSITIVE_PATTERNS p ON c.CATEGORY_ID = p.CATEGORY_ID AND p.IS_ACTIVE = TRUE
WHERE c.IS_ACTIVE = TRUE
GROUP BY c.POLICY_GROUP
ORDER BY c.POLICY_GROUP;

-- Check for duplicate keywords
SELECT 
    '=== Duplicate Keywords ===' AS DETAIL,
    k.KEYWORD_STRING,
    COUNT(*) AS duplicate_count,
    LISTAGG(DISTINCT c.POLICY_GROUP, ', ') AS policy_groups
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.IS_ACTIVE = TRUE
GROUP BY k.KEYWORD_STRING
HAVING COUNT(*) > 1
ORDER BY duplicate_count DESC
LIMIT 10;

-- Check for keywords with no category
SELECT 
    COUNT(*) AS orphaned_keywords
FROM SENSITIVE_KEYWORDS k
WHERE k.IS_ACTIVE = TRUE
AND NOT EXISTS (
    SELECT 1 FROM SENSITIVITY_CATEGORIES c 
    WHERE c.CATEGORY_ID = k.CATEGORY_ID AND c.IS_ACTIVE = TRUE
);

-- ============================================================================
-- TEST 6: End-to-End Classification Simulation
-- ============================================================================
SELECT '=== TEST 6: End-to-End Classification Test ===' AS TEST_SECTION;

WITH test_data AS (
    SELECT 'email' AS col_name, 'PII' AS expected_policy UNION ALL
    SELECT 'user_email', 'PII' UNION ALL
    SELECT 'social_security_number', 'PII' UNION ALL
    SELECT 'ssn', 'PII' UNION ALL
    SELECT 'credit_card_number', 'SOX' UNION ALL
    SELECT 'account_number', 'SOX' UNION ALL
    SELECT 'api_key', 'SOC2' UNION ALL
    SELECT 'password_hash', 'SOC2' UNION ALL
    SELECT 'access_token', 'SOC2' UNION ALL
    -- System columns (should be excluded)
    SELECT 'uuid', 'EXCLUDED' UNION ALL
    SELECT 'created_at', 'EXCLUDED' UNION ALL
    SELECT 'user_id', 'EXCLUDED'
),
classifications AS (
    SELECT 
        td.col_name,
        td.expected_policy,
        -- Check exclusions first
        CASE 
            WHEN EXISTS (
                SELECT 1 FROM EXCLUSION_PATTERNS ep
                WHERE ep.IS_ACTIVE = TRUE
                AND (
                    (ep.PATTERN_TYPE = 'COLUMN_NAME' AND LOWER(td.col_name) = LOWER(ep.PATTERN_VALUE))
                    OR (ep.PATTERN_TYPE = 'REGEX' AND RLIKE(LOWER(td.col_name), ep.PATTERN_VALUE, 'i'))
                )
            ) THEN 'EXCLUDED'
            ELSE (
                SELECT POLICY_GROUP
                FROM VW_CLASSIFICATION_RULES r
                WHERE r.IS_ACTIVE = TRUE
                AND (
                    (r.MATCH_TYPE = 'EXACT' AND LOWER(td.col_name) = LOWER(r.RULE_PATTERN))
                    OR (r.MATCH_TYPE = 'EXACT' AND LOWER(td.col_name) LIKE '%' || LOWER(r.RULE_PATTERN) || '%')
                )
                ORDER BY 
                    CASE r.PRIORITY_TIER
                        WHEN 'PRIORITY_1' THEN 1
                        WHEN 'PRIORITY_2' THEN 2
                        ELSE 3
                    END,
                    r.RULE_WEIGHT DESC
                LIMIT 1
            )
        END AS predicted_policy
    FROM test_data td
)
SELECT 
    col_name,
    expected_policy,
    COALESCE(predicted_policy, 'NONE') AS predicted_policy,
    CASE 
        WHEN expected_policy = COALESCE(predicted_policy, 'NONE') THEN '✅ PASS'
        ELSE '❌ FAIL'
    END AS test_result
FROM classifications
ORDER BY 
    CASE WHEN test_result = '❌ FAIL' THEN 1 ELSE 2 END,
    col_name;

-- ============================================================================
-- FINAL SUMMARY
-- ============================================================================
SELECT '=== FINAL VALIDATION SUMMARY ===' AS TEST_SECTION;

SELECT 
    'Total Active Keywords' AS metric,
    COUNT(*)::VARCHAR AS value
FROM SENSITIVE_KEYWORDS
WHERE IS_ACTIVE = TRUE
UNION ALL
SELECT 
    'Total Active Patterns',
    COUNT(*)::VARCHAR
FROM SENSITIVE_PATTERNS
WHERE IS_ACTIVE = TRUE
UNION ALL
SELECT 
    'Total Exclusion Rules',
    COUNT(*)::VARCHAR
FROM EXCLUSION_PATTERNS
WHERE IS_ACTIVE = TRUE
UNION ALL
SELECT 
    'PII Priority',
    COALESCE(TRY_CAST(CATEGORY_PRIORITY AS VARCHAR), 'NOT SET')
FROM SENSITIVITY_CATEGORIES
WHERE POLICY_GROUP = 'PII' AND IS_ACTIVE = TRUE
LIMIT 1
UNION ALL
SELECT 
    'SOC2 "security" Keywords Active',
    COUNT(*)::VARCHAR
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE c.POLICY_GROUP = 'SOC2'
AND k.KEYWORD_STRING IN ('security_answer', 'security_question')
AND k.IS_ACTIVE = TRUE;

-- ============================================================================
-- Success Criteria Summary:
-- 1. ✅ PARTIAL keywords < 5% of total
-- 2. ✅ Exclusion patterns exist and work correctly
-- 3. ✅ SSN keywords in PII only, not SOC2
-- 4. ✅ Category priorities set (PII=1)
-- 5. ✅ SOC2 "security" keywords deactivated
-- 6. ✅ VW_CLASSIFICATION_RULES returns data
-- 7. ✅ End-to-end test passes for all scenarios
-- ============================================================================
