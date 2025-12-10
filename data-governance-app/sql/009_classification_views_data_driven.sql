-- ============================================================================
-- DATA-DRIVEN CLASSIFICATION VIEWS
-- Dynamic views that derive classification rules from existing governance tables
-- ============================================================================
-- Purpose: Eliminate hardcoded logic by creating views that combine
--          SENSITIVITY_CATEGORIES, SENSITIVE_KEYWORDS, and SENSITIVE_PATTERNS
-- Author: AI Classification System
-- Date: 2025-12-04
-- ============================================================================

-- Set database context
SET DB = COALESCE($DATABASE, CURRENT_DATABASE(), 'DATA_CLASSIFICATION_DB');
USE DATABASE IDENTIFIER($DB);

-- Determine governance schema
CREATE SCHEMA IF NOT EXISTS DATA_CLASSIFICATION_GOVERNANCE;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- VIEW 1: VW_CLASSIFICATION_RULES
-- Combines keywords and patterns with category metadata for rule-based classification
-- ============================================================================

CREATE OR REPLACE VIEW VW_CLASSIFICATION_RULES AS
WITH 
-- Get all active keywords with their category metadata
keyword_rules AS (
    SELECT
        'KEYWORD' AS RULE_TYPE,
        k.KEYWORD_ID AS RULE_ID,
        k.KEYWORD_STRING AS RULE_PATTERN,
        k.MATCH_TYPE,
        c.CATEGORY_ID,
        c.CATEGORY_NAME,
        c.POLICY_GROUP,
        c.CONFIDENTIALITY_LEVEL,
        c.INTEGRITY_LEVEL,
        c.AVAILABILITY_LEVEL,
        c.DETECTION_THRESHOLD,
        k.SENSITIVITY_WEIGHT AS RULE_WEIGHT,
        c.WEIGHT_KEYWORD AS CATEGORY_WEIGHT,
        c.MULTI_LABEL,
        'Keyword match for ' || c.CATEGORY_NAME AS RULE_DESCRIPTION,
        k.IS_ACTIVE,
        k.CREATED_BY,
        k.CREATED_AT,
        k.VERSION_NUMBER
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
),
-- Get all active patterns with their category metadata
pattern_rules AS (
    SELECT
        'PATTERN' AS RULE_TYPE,
        p.PATTERN_ID AS RULE_ID,
        p.PATTERN_REGEX AS RULE_PATTERN,
        'REGEX' AS MATCH_TYPE,
        c.CATEGORY_ID,
        c.CATEGORY_NAME,
        c.POLICY_GROUP,
        c.CONFIDENTIALITY_LEVEL,
        c.INTEGRITY_LEVEL,
        c.AVAILABILITY_LEVEL,
        c.DETECTION_THRESHOLD,
        p.SENSITIVITY_WEIGHT AS RULE_WEIGHT,
        c.WEIGHT_PATTERN AS CATEGORY_WEIGHT,
        c.MULTI_LABEL,
        COALESCE(p.DESCRIPTION, 'Pattern match for ' || c.CATEGORY_NAME) AS RULE_DESCRIPTION,
        p.IS_ACTIVE,
        'SYSTEM' AS CREATED_BY,
        p.CREATED_AT,
        p.VERSION_NUMBER
    FROM SENSITIVE_PATTERNS p
    JOIN SENSITIVITY_CATEGORIES c ON p.CATEGORY_ID = c.CATEGORY_ID
    WHERE p.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
)
-- Union all rules
SELECT * FROM keyword_rules
UNION ALL
SELECT * FROM pattern_rules
ORDER BY POLICY_GROUP, CATEGORY_NAME, RULE_TYPE;

COMMENT ON VIEW VW_CLASSIFICATION_RULES IS 
'Dynamic classification rules derived from SENSITIVE_KEYWORDS and SENSITIVE_PATTERNS with category metadata. 
Used by classification pipeline to apply data-driven detection logic.';

-- ============================================================================
-- VIEW 2: VW_POLICY_GROUP_KEYWORDS
-- Groups keywords by policy group for tiebreaking and context detection
-- ============================================================================

CREATE OR REPLACE VIEW VW_POLICY_GROUP_KEYWORDS AS
SELECT
    c.POLICY_GROUP,
    k.KEYWORD_STRING,
    k.MATCH_TYPE,
    k.SENSITIVITY_WEIGHT,
    c.CATEGORY_NAME,
    c.DETECTION_THRESHOLD,
    k.IS_ACTIVE
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
ORDER BY c.POLICY_GROUP, k.SENSITIVITY_WEIGHT DESC, k.KEYWORD_STRING;

COMMENT ON VIEW VW_POLICY_GROUP_KEYWORDS IS 
'Keywords grouped by policy group (PII, SOX, SOC2) for intelligent tiebreaking and context-aware adjustments.';

-- ============================================================================
-- VIEW 3: VW_CATEGORY_SCORING_WEIGHTS
-- Provides scoring weights for each category (embedding, keyword, pattern)
-- ============================================================================

CREATE OR REPLACE VIEW VW_CATEGORY_SCORING_WEIGHTS AS
SELECT
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP,
    WEIGHT_EMBEDDING,
    WEIGHT_KEYWORD,
    WEIGHT_PATTERN,
    DETECTION_THRESHOLD,
    MULTI_LABEL,
    CONFIDENTIALITY_LEVEL,
    INTEGRITY_LEVEL,
    AVAILABILITY_LEVEL,
    IS_ACTIVE
FROM SENSITIVITY_CATEGORIES
WHERE IS_ACTIVE = TRUE
ORDER BY POLICY_GROUP, CATEGORY_NAME;

COMMENT ON VIEW VW_CATEGORY_SCORING_WEIGHTS IS 
'Scoring weights and thresholds for each sensitivity category. Used to calculate final confidence scores.';

-- ============================================================================
-- VIEW 4: VW_CONTEXT_AWARE_RULES
-- Derives context-aware adjustment rules from keyword patterns
-- ============================================================================

CREATE OR REPLACE VIEW VW_CONTEXT_AWARE_RULES AS
WITH kw AS (
    SELECT 
        c.POLICY_GROUP,
        c.CATEGORY_NAME,
        k.KEYWORD_ID,
        k.KEYWORD_STRING,
        k.SENSITIVITY_WEIGHT,
        c.WEIGHT_KEYWORD
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
), norm AS (
    SELECT 
        POLICY_GROUP,
        CATEGORY_NAME,
        KEYWORD_ID,
        KEYWORD_STRING,
        SENSITIVITY_WEIGHT,
        WEIGHT_KEYWORD,
        CASE WHEN MAX(SENSITIVITY_WEIGHT) OVER (PARTITION BY POLICY_GROUP) > 0
             THEN SENSITIVITY_WEIGHT / MAX(SENSITIVITY_WEIGHT) OVER (PARTITION BY POLICY_GROUP)
             ELSE 0 END AS NORM_WEIGHT
    FROM kw
)
SELECT 
    POLICY_GROUP,
    KEYWORD_STRING,
    'KEYWORD_CONTEXT' AS RULE_TYPE,
    'BOOST' AS ACTION_TYPE,
    GREATEST(0.0001, NORM_WEIGHT) AS ACTION_FACTOR,
    'Derived from active keywords and category keyword weight' AS DESCRIPTION
FROM norm
ORDER BY POLICY_GROUP, ACTION_FACTOR DESC, KEYWORD_STRING;

COMMENT ON VIEW VW_CONTEXT_AWARE_RULES IS 
'Context-aware adjustment rules derived from keyword patterns. Used to boost/reduce scores based on table and column context.';

-- ============================================================================
-- VIEW 5: VW_EXCLUSION_PATTERNS
-- Identifies non-sensitive patterns that should reduce sensitivity scores
-- ============================================================================

CREATE OR REPLACE VIEW VW_EXCLUSION_PATTERNS AS
WITH kw AS (
    SELECT 
        c.POLICY_GROUP,
        c.CATEGORY_NAME,
        k.KEYWORD_ID,
        k.KEYWORD_STRING,
        k.SENSITIVITY_WEIGHT
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
), norm AS (
    SELECT 
        POLICY_GROUP,
        CATEGORY_NAME,
        KEYWORD_ID,
        KEYWORD_STRING,
        SENSITIVITY_WEIGHT,
        CASE WHEN MAX(SENSITIVITY_WEIGHT) OVER (PARTITION BY POLICY_GROUP) > 0
             THEN SENSITIVITY_WEIGHT / MAX(SENSITIVITY_WEIGHT) OVER (PARTITION BY POLICY_GROUP)
             ELSE 0 END AS NORM_WEIGHT
    FROM kw
)
SELECT
    'KEYWORD_DOWNWEIGHT' AS EXCLUSION_TYPE,
    ARRAY_CONSTRUCT(KEYWORD_STRING) AS EXCLUSION_KEYWORDS,
    (1 - NORM_WEIGHT) AS REDUCE_PII_FACTOR,
    (1 - NORM_WEIGHT) AS REDUCE_SOX_FACTOR,
    (1 - NORM_WEIGHT) AS REDUCE_SOC2_FACTOR,
    'Derived from relative keyword weight within policy group' AS DESCRIPTION
FROM norm
ORDER BY POLICY_GROUP, REDUCE_PII_FACTOR DESC;

COMMENT ON VIEW VW_EXCLUSION_PATTERNS IS 
'Patterns for identifying non-sensitive generic fields. Used to reduce false positives.';

-- ============================================================================
-- VIEW 6: VW_ADDRESS_CONTEXT_INDICATORS
-- Distinguishes between physical addresses (PII) and network addresses (SOC2)
-- ============================================================================

CREATE OR REPLACE VIEW VW_ADDRESS_CONTEXT_INDICATORS AS
WITH kw AS (
    SELECT 
        c.POLICY_GROUP,
        c.CATEGORY_NAME,
        k.KEYWORD_ID,
        k.KEYWORD_STRING,
        k.SENSITIVITY_WEIGHT
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
), norm AS (
    SELECT 
        POLICY_GROUP,
        CATEGORY_NAME,
        KEYWORD_ID,
        KEYWORD_STRING,
        CASE WHEN MAX(SENSITIVITY_WEIGHT) OVER (PARTITION BY POLICY_GROUP) > 0
             THEN SENSITIVITY_WEIGHT / MAX(SENSITIVITY_WEIGHT) OVER (PARTITION BY POLICY_GROUP)
             ELSE 0 END AS NORM_WEIGHT
    FROM kw
)
SELECT
    'GENERIC' AS CONTEXT_TYPE,
    'KEYWORD' AS INDICATOR_TYPE,
    KEYWORD_STRING AS INDICATOR_KEYWORD,
    POLICY_GROUP AS BOOST_POLICY_GROUP,
    GREATEST(0.0001, NORM_WEIGHT) AS BOOST_FACTOR,
    NULL::STRING AS SUPPRESS_POLICY_GROUP,
    NULL::FLOAT AS SUPPRESS_FACTOR,
    'Derived from active keywords and policy group' AS DESCRIPTION
FROM norm
ORDER BY POLICY_GROUP, BOOST_FACTOR DESC, INDICATOR_KEYWORD;

COMMENT ON VIEW VW_ADDRESS_CONTEXT_INDICATORS IS 
'Context indicators to distinguish between physical addresses (PII) and network addresses (SOC2).';

-- ============================================================================
-- VIEW 7: VW_TIEBREAKER_KEYWORDS
-- Keywords used for intelligent tiebreaking when multiple categories have identical scores
-- ============================================================================

CREATE OR REPLACE VIEW VW_TIEBREAKER_KEYWORDS AS
SELECT
    c.POLICY_GROUP,
    k.KEYWORD_STRING AS KEYWORD,
    k.SENSITIVITY_WEIGHT AS WEIGHT,
    c.CATEGORY_NAME,
    k.IS_ACTIVE
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
QUALIFY ROW_NUMBER() OVER (PARTITION BY c.POLICY_GROUP ORDER BY k.SENSITIVITY_WEIGHT DESC, k.KEYWORD_STRING) >= 1
ORDER BY c.POLICY_GROUP, k.SENSITIVITY_WEIGHT DESC, k.KEYWORD_STRING;

COMMENT ON VIEW VW_TIEBREAKER_KEYWORDS IS 
'High-confidence keywords for intelligent tiebreaking when multiple categories have identical scores.';

-- ============================================================================
-- VIEW 8: VW_CATEGORY_METADATA
-- Complete category metadata for classification pipeline
-- ============================================================================

CREATE OR REPLACE VIEW VW_CATEGORY_METADATA AS
SELECT
    c.CATEGORY_ID,
    c.CATEGORY_NAME,
    c.DESCRIPTION,
    c.POLICY_GROUP,
    c.CONFIDENTIALITY_LEVEL,
    c.INTEGRITY_LEVEL,
    c.AVAILABILITY_LEVEL,
    c.DETECTION_THRESHOLD,
    c.WEIGHT_EMBEDDING,
    c.WEIGHT_KEYWORD,
    c.WEIGHT_PATTERN,
    c.MULTI_LABEL,
    c.IS_ACTIVE,
    COUNT(DISTINCT k.KEYWORD_ID) AS KEYWORD_COUNT,
    COUNT(DISTINCT p.PATTERN_ID) AS PATTERN_COUNT
FROM SENSITIVITY_CATEGORIES c
LEFT JOIN SENSITIVE_KEYWORDS k ON c.CATEGORY_ID = k.CATEGORY_ID AND k.IS_ACTIVE = TRUE
LEFT JOIN SENSITIVE_PATTERNS p ON c.CATEGORY_ID = p.CATEGORY_ID AND p.IS_ACTIVE = TRUE
WHERE c.IS_ACTIVE = TRUE
GROUP BY 
    c.CATEGORY_ID, c.CATEGORY_NAME, c.DESCRIPTION, c.POLICY_GROUP,
    c.CONFIDENTIALITY_LEVEL, c.INTEGRITY_LEVEL, c.AVAILABILITY_LEVEL,
    c.DETECTION_THRESHOLD, c.WEIGHT_EMBEDDING, c.WEIGHT_KEYWORD, c.WEIGHT_PATTERN,
    c.MULTI_LABEL, c.IS_ACTIVE
ORDER BY c.POLICY_GROUP, c.CATEGORY_NAME;

COMMENT ON VIEW VW_CATEGORY_METADATA IS 
'Complete category metadata with keyword and pattern counts. Used for initialization and validation.';

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Verify all views created successfully
SELECT 'VW_CLASSIFICATION_RULES' AS VIEW_NAME, COUNT(*) AS ROW_COUNT FROM VW_CLASSIFICATION_RULES
UNION ALL
SELECT 'VW_POLICY_GROUP_KEYWORDS', COUNT(*) FROM VW_POLICY_GROUP_KEYWORDS
UNION ALL
SELECT 'VW_CATEGORY_SCORING_WEIGHTS', COUNT(*) FROM VW_CATEGORY_SCORING_WEIGHTS
UNION ALL
SELECT 'VW_CONTEXT_AWARE_RULES', COUNT(*) FROM VW_CONTEXT_AWARE_RULES
UNION ALL
SELECT 'VW_EXCLUSION_PATTERNS', COUNT(*) FROM VW_EXCLUSION_PATTERNS
UNION ALL
SELECT 'VW_ADDRESS_CONTEXT_INDICATORS', COUNT(*) FROM VW_ADDRESS_CONTEXT_INDICATORS
UNION ALL
SELECT 'VW_TIEBREAKER_KEYWORDS', COUNT(*) FROM VW_TIEBREAKER_KEYWORDS
UNION ALL
SELECT 'VW_CATEGORY_METADATA', COUNT(*) FROM VW_CATEGORY_METADATA;

-- Sample data from key views
SELECT '=== VW_CLASSIFICATION_RULES Sample ===' AS INFO;
SELECT RULE_TYPE, CATEGORY_NAME, POLICY_GROUP, RULE_PATTERN, MATCH_TYPE
FROM VW_CLASSIFICATION_RULES
LIMIT 10;

SELECT '=== VW_CONTEXT_AWARE_RULES Sample ===' AS INFO;
SELECT POLICY_GROUP, RULE_TYPE, KEYWORD_STRING, ACTION_TYPE, ACTION_FACTOR
FROM VW_CONTEXT_AWARE_RULES
LIMIT 10;

SELECT '=== VW_CATEGORY_METADATA Summary ===' AS INFO;
SELECT POLICY_GROUP, CATEGORY_NAME, KEYWORD_COUNT, PATTERN_COUNT, DETECTION_THRESHOLD
FROM VW_CATEGORY_METADATA
ORDER BY POLICY_GROUP, CATEGORY_NAME;
