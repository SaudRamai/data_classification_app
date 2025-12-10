-- ============================================================================
-- VW_CLASSIFICATION_RULES - Unified View of All Classification Rules
-- ============================================================================
-- Combines keywords and patterns into a single view for the classification engine
-- Handles column mismatches and provides consistent schema
-- ============================================================================

CREATE OR REPLACE VIEW VW_CLASSIFICATION_RULES AS
WITH 
-- Get all active keywords with their category metadata
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
        -- Dynamic priority based on sensitivity weight
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
-- Get all active patterns with their category metadata
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
        COALESCE(
            TRY_CAST(p.DESCRIPTION AS VARCHAR),
            'Pattern match for ' || c.CATEGORY_NAME
        ) AS RULE_DESCRIPTION,
        COALESCE(p.IS_ACTIVE, TRUE) AS IS_ACTIVE,
        'SYSTEM' AS CREATED_BY,
        COALESCE(p.CREATED_AT, CURRENT_TIMESTAMP()) AS CREATED_AT,
        COALESCE(
            TRY_CAST(p.VERSION_NUMBER AS INTEGER),
            1
        ) AS VERSION_NUMBER,
        -- Dynamic priority based on sensitivity weight
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
-- Union all rules
SELECT * FROM keyword_rules
UNION ALL
SELECT * FROM pattern_rules
ORDER BY 
    CASE PRIORITY_TIER
        WHEN 'PRIORITY_1' THEN 1
        WHEN 'PRIORITY_2' THEN 2
        WHEN 'PRIORITY_3' THEN 3
        ELSE 4
    END,
    RULE_WEIGHT DESC, 
    POLICY_GROUP, 
    CATEGORY_NAME, 
    RULE_TYPE;

-- ============================================================================
-- View Description:
-- This view unifies keywords and patterns into a single classification ruleset
-- 
-- Columns:
-- - RULE_TYPE: 'KEYWORD' or 'PATTERN'
-- - RULE_ID: Unique identifier (KEYWORD_ID or PATTERN_ID)
-- - RULE_PATTERN: The keyword string or regex pattern
-- - MATCH_TYPE: How to match ('EXACT', 'PARTIAL', 'CONTAINS', 'REGEX')
-- - CATEGORY_ID: FK to SENSITIVITY_CATEGORIES
-- - CATEGORY_NAME: Name of the sensitivity category
-- - POLICY_GROUP: Compliance framework (PII, SOX, SOC2)
-- - CONFIDENTIALITY_LEVEL: 0-3 (Public to Confidential)
-- - INTEGRITY_LEVEL: 0-3 (None to High)
-- - AVAILABILITY_LEVEL: 0-3 (None to High)
-- - DETECTION_THRESHOLD: Minimum confidence score for classification
-- - RULE_WEIGHT: Weight of this specific rule (0-1)
-- - CATEGORY_WEIGHT: Weight of keyword/pattern scoring for this category
-- - MULTI_LABEL: Whether multiple categories can be applied
-- - RULE_DESCRIPTION: Human-readable description
-- - IS_ACTIVE: Whether the rule is active
-- - CREATED_BY: User who created the rule
-- - CREATED_AT: Timestamp of creation
-- - VERSION_NUMBER: Version for tracking changes
-- - PRIORITY_TIER: Priority tier (PRIORITY_1, PRIORITY_2, PRIORITY_3)
-- 
-- Usage:
-- SELECT * FROM VW_CLASSIFICATION_RULES 
-- WHERE POLICY_GROUP = 'PII' AND PRIORITY_TIER = 'PRIORITY_1';
-- ============================================================================

-- Grant select to appropriate roles
-- GRANT SELECT ON VW_CLASSIFICATION_RULES TO ROLE DATA_GOVERNANCE_READER;
