-- ============================================================================
-- FIX: SOCIAL_SECURITY_NUMBER Incorrectly Classified as SOC2
-- ============================================================================
-- Root Cause: Substring "security" in "social_security_number" matches
--             SOC2 keywords like "security_question", "security_answer"
-- 
-- Solution: Add category priority and improve keyword specificity
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- STEP 1: Add CATEGORY_PRIORITY to SENSITIVITY_CATEGORIES
-- ============================================================================
-- Priority: Lower number = Higher priority
-- PII should have highest priority (1) to override SOC2/SOX

ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS CATEGORY_PRIORITY INTEGER DEFAULT 99;

UPDATE SENSITIVITY_CATEGORIES
SET CATEGORY_PRIORITY = CASE POLICY_GROUP
    WHEN 'PII' THEN 1   -- Highest priority
    WHEN 'SOX' THEN 2
    WHEN 'SOC2' THEN 3
    ELSE 99
END,
UPDATED_AT = CURRENT_TIMESTAMP(),
UPDATED_BY = 'PRIORITY_FIX';

-- ============================================================================
-- STEP 2: Deactivate Overly Broad SOC2 "security" Keywords
-- ============================================================================
-- These keywords cause false positives when matching PII columns

-- Option A: Deactivate (Recommended)
UPDATE SENSITIVE_KEYWORDS
SET IS_ACTIVE = FALSE,
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'SECURITY_KEYWORD_FIX',
    UPDATED_REASON = 'Too broad - causes false positive matches with PII columns containing "security"'
WHERE KEYWORD_STRING IN ('security_answer', 'security_question')
AND CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2' LIMIT 1);

-- Option B: Make them more specific (Alternative)
-- If you still want to detect these, make them require word boundaries
-- This is handled in the code via EXACT match type

-- ============================================================================
-- STEP 3: Add Explicit SSN Keywords for PII (if not exist)
-- ============================================================================
-- Ensure SSN variations are all explicitly in PII

MERGE INTO SENSITIVE_KEYWORDS AS target
USING (
    SELECT 
        'PII' AS cat_name,
        kw_string,
        'EXACT' AS match_type
    FROM (
        SELECT 'ssn' AS kw_string UNION ALL
        SELECT 'social_security_number' UNION ALL
        SELECT 'social_security_no' UNION ALL
        SELECT 'soc_sec_num'
    ) keywords
) AS source
ON target.KEYWORD_STRING = source.kw_string
   AND target.CATEGORY_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = source.cat_name LIMIT 1)
WHEN NOT MATCHED THEN
    INSERT (
        KEYWORD_ID,
        CATEGORY_ID,
        KEYWORD_STRING,
        MATCH_TYPE,
        SENSITIVITY_WEIGHT,
        IS_ACTIVE,
        CREATED_BY,
        CREATED_AT,
        PRIORITY_TIER
    )
    VALUES (
        UUID_STRING(),
        (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = source.cat_name LIMIT 1),
        source.kw_string,
        source.match_type,
        1.0,
        TRUE,
        'SSN_FIX',
        CURRENT_TIMESTAMP(),
        'PRIORITY_1'
    );

-- ============================================================================
-- STEP 4: Add Anti-Pattern Rules to Prevent Misclassification
-- ============================================================================
-- Create a negative rules table to explicitly block certain classifications

CREATE TABLE IF NOT EXISTS CLASSIFICATION_NEGATIVE_RULES (
    RULE_ID VARCHAR(36) PRIMARY KEY,
    COLUMN_PATTERN VARCHAR(500),  -- Regex pattern for column names
    BLOCKED_CATEGORY VARCHAR(100), -- Category that should NOT be applied
    REASON VARCHAR(500),
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(100),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- Add rule: Columns with "social_security" should NEVER be SOC2
MERGE INTO CLASSIFICATION_NEGATIVE_RULES AS target
USING (
    SELECT 
        UUID_STRING() AS RULE_ID,
        '.*social.*security.*' AS COLUMN_PATTERN,
        'SOC2' AS BLOCKED_CATEGORY,
        'Social Security columns are PII, not SOC2 security data' AS REASON,
        TRUE AS IS_ACTIVE,
        'SYSTEM' AS CREATED_BY,
        CURRENT_TIMESTAMP() AS CREATED_AT
) AS source
ON target.COLUMN_PATTERN = source.COLUMN_PATTERN
   AND target.BLOCKED_CATEGORY = source.BLOCKED_CATEGORY
WHEN NOT MATCHED THEN
    INSERT (RULE_ID, COLUMN_PATTERN, BLOCKED_CATEGORY, REASON, IS_ACTIVE, CREATED_BY, CREATED_AT)
    VALUES (source.RULE_ID, source.COLUMN_PATTERN, source.BLOCKED_CATEGORY, source.REASON, source.IS_ACTIVE, source.CREATED_BY, source.CREATED_AT);

-- More negative rules
INSERT INTO CLASSIFICATION_NEGATIVE_RULES (
    RULE_ID, COLUMN_PATTERN, BLOCKED_CATEGORY, REASON, IS_ACTIVE, CREATED_BY, CREATED_AT
)
SELECT 
    UUID_STRING(),
    pattern,
    blocked_cat,
    reason,
    TRUE,
    'SYSTEM',
    CURRENT_TIMESTAMP()
FROM (
    SELECT '.*ssn.*' AS pattern, 'SOC2' AS blocked_cat, 'SSN is PII, not SOC2' AS reason UNION ALL
    SELECT '.*ssn.*', 'SOX', 'SSN is PII, not SOX' UNION ALL
    SELECT '.*tax.*id.*', 'SOC2', 'Tax ID is PII, not SOC2' UNION ALL
    SELECT '.*passport.*', 'SOC2', 'Passport is PII, not SOC2' UNION ALL
    SELECT '.*passport.*', 'SOX', 'Passport is PII, not SOX' UNION ALL
    SELECT '.*driver.*license.*', 'SOC2', 'Driver license is PII, not SOC2' UNION ALL
    SELECT '.*driver.*license.*', 'SOX', 'Driver license is PII, not SOX'
) rules
WHERE NOT EXISTS (
    SELECT 1 FROM CLASSIFICATION_NEGATIVE_RULES nr
    WHERE nr.COLUMN_PATTERN = rules.pattern
    AND nr.BLOCKED_CATEGORY = rules.blocked_cat
);

-- ============================================================================
-- STEP 5: Verification Queries
-- ============================================================================

-- Check category priorities
SELECT 
    CATEGORY_NAME,
    POLICY_GROUP,
    CATEGORY_PRIORITY,
    IS_ACTIVE
FROM SENSITIVITY_CATEGORIES
ORDER BY CATEGORY_PRIORITY, POLICY_GROUP;

-- Expected:
-- PII    | PII   | 1  | TRUE
-- SOX    | SOX   | 2  | TRUE
-- SOC2   | SOC2  | 3  | TRUE

-- Check deactivated SOC2 keywords
SELECT 
    KEYWORD_STRING,
    MATCH_TYPE,
    IS_ACTIVE,
    UPDATED_REASON
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE c.CATEGORY_NAME = 'SOC2'
AND k.KEYWORD_STRING LIKE '%security%'
ORDER BY k.IS_ACTIVE DESC, k.KEYWORD_STRING;

-- Check negative rules
SELECT * FROM CLASSIFICATION_NEGATIVE_RULES
WHERE IS_ACTIVE = TRUE
ORDER BY BLOCKED_CATEGORY, COLUMN_PATTERN;

-- ============================================================================
-- STEP 6: Test Classification Logic
-- ============================================================================

WITH test_columns AS (
    SELECT 'SOCIAL_SECURITY_NUMBER' AS col_name UNION ALL
    SELECT 'SSN' UNION ALL
    SELECT 'social_security_no' UNION ALL
    SELECT 'security_question' UNION ALL
    SELECT 'security_answer' UNION ALL
    SELECT 'password_hash' UNION ALL
    SELECT 'api_key'
),
matches AS (
    SELECT 
        tc.col_name,
        c.CATEGORY_NAME,
        c.POLICY_GROUP,
        c.CATEGORY_PRIORITY,
        k.KEYWORD_STRING AS matched_keyword,
        k.MATCH_TYPE,
        CASE 
            WHEN k.MATCH_TYPE = 'EXACT' AND LOWER(tc.col_name) = LOWER(k.KEYWORD_STRING) THEN 1.0
            WHEN k.MATCH_TYPE = 'EXACT' AND LOWER(tc.col_name) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%' THEN 0.8
            ELSE 0.5
        END AS match_score,
        -- Check if blocked by negative rule
        CASE 
            WHEN EXISTS (
                SELECT 1 FROM CLASSIFICATION_NEGATIVE_RULES nr
                WHERE nr.IS_ACTIVE = TRUE
                AND nr.BLOCKED_CATEGORY = c.POLICY_GROUP
                AND RLIKE(LOWER(tc.col_name), nr.COLUMN_PATTERN, 'i')
            ) THEN 'BLOCKED'
            ELSE 'ALLOWED'
        END AS rule_status
    FROM test_columns tc
    CROSS JOIN SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE
    AND (
        (k.MATCH_TYPE = 'EXACT' AND LOWER(tc.col_name) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%')
        OR
        (LOWER(k.KEYWORD_STRING) LIKE '%' || LOWER(tc.col_name) || '%')
    )
)
SELECT 
    col_name,
    LISTAGG(DISTINCT 
        CASE WHEN rule_status = 'BLOCKED' THEN '🚫 ' ELSE '✅ ' END ||
        POLICY_GROUP || ':' || matched_keyword || 
        ' (pri=' || CATEGORY_PRIORITY::STRING || ', score=' || ROUND(match_score, 2)::STRING || ')',
        ' | '
    ) WITHIN GROUP (ORDER BY CATEGORY_PRIORITY, match_score DESC) AS classifications
FROM matches
GROUP BY col_name
ORDER BY col_name;

-- Expected Results:
-- SOCIAL_SECURITY_NUMBER | ✅ PII:social_security_number (pri=1, score=1.0) | 🚫 SOC2:security_question (pri=3, score=0.8) [BLOCKED]
-- SSN                    | ✅ PII:ssn (pri=1, score=1.0)
-- security_question      | ✅ SOC2:security_question (pri=3, score=1.0)

-- ============================================================================
-- SUCCESS CRITERIA:
-- 1. PII has priority=1, SOX=2, SOC2=3
-- 2. SOC2 "security_*" keywords are deactivated
-- 3. Negative rules block SOC2/SOX from PII columns
-- 4. SOCIAL_SECURITY_NUMBER matches PII only
-- ============================================================================
