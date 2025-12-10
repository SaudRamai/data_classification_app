-- ============================================================================
-- VALIDATION: Check Classification Accuracy After Fixes
-- ============================================================================
-- Run this after applying the PARTIAL match type fixes
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- TEST 1: Verify PARTIAL Keywords Are Minimal
-- ============================================================================
SELECT 
    '=== REMAINING PARTIAL KEYWORDS ===' AS TEST_NAME,
    c.CATEGORY_NAME,
    c.POLICY_GROUP,
    k.KEYWORD_STRING,
    k.MATCH_TYPE,
    LENGTH(k.KEYWORD_STRING) AS LEN,
    k.IS_ACTIVE
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.MATCH_TYPE = 'PARTIAL'
AND k.IS_ACTIVE = TRUE
ORDER BY c.POLICY_GROUP, LENGTH(k.KEYWORD_STRING), k.KEYWORD_STRING;

-- Expected Result: 0-5 rows (nearly all should be EXACT now)

-- ============================================================================
-- TEST 2: Verify Distribution of Match Types
-- ============================================================================
SELECT 
    '=== MATCH TYPE DISTRIBUTION ===' AS TEST_NAME,
    c.POLICY_GROUP,
    k.MATCH_TYPE,
    COUNT(*) AS COUNT,
    ROUND(AVG(LENGTH(k.KEYWORD_STRING)), 1) AS AVG_LENGTH
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.IS_ACTIVE = TRUE
GROUP BY c.POLICY_GROUP, k.MATCH_TYPE
ORDER BY c.POLICY_GROUP, k.MATCH_TYPE;

-- Expected Result:
-- PII  : EXACT (majority), REGEX (patterns)
-- SOC2 : EXACT (majority), REGEX (patterns)
-- SOX  : EXACT (majority), REGEX (patterns)
-- Very few or ZERO PARTIAL matches

-- ============================================================================
-- TEST 3: Check for Short Problematic Keywords
-- ============================================================================
SELECT 
    '=== SHORT KEYWORDS (< 5 chars) ===' AS TEST_NAME,
    c.POLICY_GROUP,
    k.KEYWORD_STRING,
    LENGTH(k.KEYWORD_STRING) AS LEN,
    k.MATCH_TYPE,
    k.IS_ACTIVE,
    CASE 
        WHEN LENGTH(k.KEYWORD_STRING) < 4 AND k.MATCH_TYPE = 'PARTIAL' THEN '🔴 HIGH RISK'
        WHEN LENGTH(k.KEYWORD_STRING) < 4 AND k.MATCH_TYPE = 'EXACT' THEN '🟡 MEDIUM RISK'
        ELSE '🟢 OK'
    END AS RISK_LEVEL
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE LENGTH(k.KEYWORD_STRING) < 5
AND k.IS_ACTIVE = TRUE
ORDER BY LENGTH(k.KEYWORD_STRING), c.POLICY_GROUP;

-- Expected Result: Only EXACT matches for short keywords, or inactive

-- ============================================================================
-- TEST 4: Sample Test Cases - Simulate Column Matching
-- ============================================================================
-- Test how keywords would match against sample column names

WITH test_columns AS (
    SELECT 'user_password' AS col_name UNION ALL
    SELECT 'password_hash' UNION ALL
    SELECT 'user_email' UNION ALL
    SELECT 'email_address' UNION ALL
    SELECT 'social_security_number' UNION ALL
    SELECT 'ssn' UNION ALL
    SELECT 'credit_card_number' UNION ALL
    SELECT 'card_number' UNION ALL
    SELECT 'api_key' UNION ALL
    SELECT 'encryption_key' UNION ALL
    SELECT 'account_number' UNION ALL
    SELECT 'bank_account' UNION ALL
    SELECT 'revenue_amount' UNION ALL
    SELECT 'total_revenue' UNION ALL
    SELECT 'access_token' UNION ALL
    SELECT 'oauth_token'
),
keyword_matches AS (
    SELECT 
        tc.col_name,
        k.KEYWORD_STRING,
        k.MATCH_TYPE,
        c.POLICY_GROUP,
        CASE 
            WHEN k.MATCH_TYPE = 'EXACT' AND LOWER(tc.col_name) = LOWER(k.KEYWORD_STRING) THEN 'MATCH'
            WHEN k.MATCH_TYPE = 'EXACT' AND LOWER(tc.col_name) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%' THEN 'PARTIAL_MATCH'
            WHEN k.MATCH_TYPE = 'PARTIAL' AND LOWER(tc.col_name) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%' THEN 'MATCH'
  ELSE 'NO_MATCH'
        END AS MATCH_RESULT
    FROM test_columns tc
    CROSS JOIN SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE
    AND (
        (k.MATCH_TYPE = 'EXACT' AND (
            LOWER(tc.col_name) = LOWER(k.KEYWORD_STRING) OR
            LOWER(tc.col_name) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%'
        ))
        OR
        (k.MATCH_TYPE = 'PARTIAL' AND LOWER(tc.col_name) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%')
    )
)
SELECT 
    '=== SAMPLE MATCHES ===' AS TEST_NAME,
    col_name,
    LISTAGG(DISTINCT POLICY_GROUP || ':' || KEYWORD_STRING || '(' || MATCH_TYPE || ')', ', ') 
        WITHIN GROUP (ORDER BY POLICY_GROUP, KEYWORD_STRING) AS MATCHED_KEYWORDS
FROM keyword_matches
WHERE MATCH_RESULT IN ('MATCH', 'PARTIAL_MATCH')
GROUP BY col_name
ORDER BY col_name;

-- Expected Results:
-- user_password    -> SOC2:password(EXACT)
-- password_hash    -> SOC2:password_hash(EXACT)
-- user_email       -> PII:user_email(EXACT), PII:email(EXACT)
-- ssn              -> PII:ssn(EXACT)
-- credit_card_number -> PII,SOX:credit_card(EXACT)
-- etc.

-- ============================================================================
-- TEST 5: High-Confidence Keywords by Priority
-- ============================================================================
SELECT 
    '=== PRIORITY 1 KEYWORDS Summary ===' AS TEST_NAME,
    c.POLICY_GROUP,
    COUNT(*) AS TOTAL_KEYWORDS,
    COUNT(CASE WHEN k.MATCH_TYPE = 'EXACT' THEN 1 END) AS EXACT_COUNT,
    COUNT(CASE WHEN k.MATCH_TYPE = 'PARTIAL' THEN 1 END) AS PARTIAL_COUNT,
    COUNT(CASE WHEN k.MATCH_TYPE = 'REGEX' THEN 1 END) AS REGEX_COUNT,
    ROUND(100.0 * COUNT(CASE WHEN k.MATCH_TYPE = 'EXACT' THEN 1 END) / COUNT(*), 1) AS EXACT_PERCENTAGE
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.PRIORITY_TIER = 'PRIORITY_1'
AND k.IS_ACTIVE = TRUE
AND k.RULE_TYPE = 'KEYWORD'
GROUP BY c.POLICY_GROUP
ORDER BY c.POLICY_GROUP;

-- Expected Result: EXACT_PERCENTAGE >= 90% for all policy groups

-- ============================================================================
-- TEST 6: Final Summary
-- ============================================================================
SELECT 
    '=== OVERALL SUMMARY ===' AS TEST_NAME,
    COUNT(*) AS TOTAL_ACTIVE_KEYWORDS,
    COUNT(CASE WHEN MATCH_TYPE = 'EXACT' THEN 1 END) AS EXACT,
    COUNT(CASE WHEN MATCH_TYPE = 'PARTIAL' THEN 1 END) AS PARTIAL,
    COUNT(CASE WHEN MATCH_TYPE = 'REGEX' THEN 1 END) AS REGEX,
    COUNT(CASE WHEN MATCH_TYPE = 'CONTAINS' THEN 1 END) AS CONTAINS,
    ROUND(100.0 * COUNT(CASE WHEN MATCH_TYPE = 'EXACT' THEN 1 END) / COUNT(*), 1) AS EXACT_PCT
FROM SENSITIVE_KEYWORDS
WHERE IS_ACTIVE = TRUE;

-- ============================================================================
-- Success Criteria:
-- 1. PARTIAL keywords <= 5 total
-- 2. EXACT_PCT >= 80% for keywords
-- 3. No short keywords (< 4 chars) with PARTIAL match type
-- 4. All compound keywords use EXACT matching
-- ============================================================================
