-- ============================================================================
-- COMPREHENSIVE GOVERNANCE VIEWS FOR DATA CLASSIFICATION
-- ============================================================================
-- This script creates all the views needed for the AI classification pipeline
-- to fetch data from Snowflake governance tables dynamically.
-- 
-- Author: Data Classification System
-- Date: 2025-12-05
-- Version: 1.0
-- ============================================================================

-- Use the governance database and schema
USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- VIEW 1: VW_CLASSIFICATION_RULES
-- Purpose: Unified view of all classification rules (keywords + patterns)
--          with category metadata and priority tiers
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
        k.VERSION_NUMBER,
        -- Dynamic priority based on sensitivity weight
        CASE 
            WHEN k.SENSITIVITY_WEIGHT >= 0.9 THEN 'PRIORITY_1'
            WHEN k.SENSITIVITY_WEIGHT >= 0.7 THEN 'PRIORITY_2'
            ELSE 'PRIORITY_3'
        END AS PRIORITY_TIER
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
        p.VERSION_NUMBER,
        -- Dynamic priority based on sensitivity weight
        CASE 
            WHEN p.SENSITIVITY_WEIGHT >= 0.9 THEN 'PRIORITY_1'
            WHEN p.SENSITIVITY_WEIGHT >= 0.7 THEN 'PRIORITY_2'
            ELSE 'PRIORITY_3'
        END AS PRIORITY_TIER
    FROM SENSITIVE_PATTERNS p
    JOIN SENSITIVITY_CATEGORIES c ON p.CATEGORY_ID = c.CATEGORY_ID
    WHERE p.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
)
-- Union all rules
SELECT * FROM keyword_rules
UNION ALL
SELECT * FROM pattern_rules
ORDER BY PRIORITY_TIER, RULE_WEIGHT DESC, POLICY_GROUP, CATEGORY_NAME, RULE_TYPE;

-- ============================================================================
-- VIEW 2: VW_POLICY_GROUP_KEYWORDS
-- Purpose: Keywords grouped by policy group with mapping validation
-- ============================================================================
CREATE OR REPLACE VIEW VW_POLICY_GROUP_KEYWORDS AS
SELECT
    c.POLICY_GROUP,
    k.KEYWORD_STRING,
    k.MATCH_TYPE,
    k.SENSITIVITY_WEIGHT,
    c.CATEGORY_NAME,
    c.DETECTION_THRESHOLD,
    k.IS_ACTIVE,
    -- Identify potential mapping issues based on keyword patterns
    CASE 
        -- Check for PII keywords in non-PII categories
        WHEN c.POLICY_GROUP != 'PII' AND (
            k.KEYWORD_STRING LIKE '%ssn%' OR 
            k.KEYWORD_STRING LIKE '%social_security%' OR
            k.KEYWORD_STRING LIKE '%passport%' OR
            k.KEYWORD_STRING LIKE '%drivers_license%' OR
            k.KEYWORD_STRING LIKE '%fingerprint%' OR
            k.KEYWORD_STRING LIKE '%biometric%' OR
            k.KEYWORD_STRING LIKE '%ethnicity%' OR
            k.KEYWORD_STRING LIKE '%religion%' OR
            k.KEYWORD_STRING LIKE '%birth%'
        ) THEN 'POTENTIAL_PII_MISMATCH'
        
        -- Check for SOC2 keywords in non-SOC2 categories
        WHEN c.POLICY_GROUP != 'SOC2' AND (
            k.KEYWORD_STRING LIKE '%ip_address%' OR
            k.KEYWORD_STRING LIKE '%mac_address%' OR
            k.KEYWORD_STRING LIKE '%api_key%' OR
            k.KEYWORD_STRING LIKE '%oauth_token%' OR
            k.KEYWORD_STRING LIKE '%password_hash%'
        ) THEN 'POTENTIAL_SOC2_MISMATCH'
        
        -- Check for SOX keywords in non-SOX categories
        WHEN c.POLICY_GROUP != 'SOX' AND (
            k.KEYWORD_STRING LIKE '%bank_account%' OR
            k.KEYWORD_STRING LIKE '%credit_card%' OR
            k.KEYWORD_STRING LIKE '%routing_number%' OR
            k.KEYWORD_STRING LIKE '%iban%' OR
            k.KEYWORD_STRING LIKE '%swift_code%' OR
            k.KEYWORD_STRING LIKE '%revenue%' OR
            k.KEYWORD_STRING LIKE '%transaction%' OR
            k.KEYWORD_STRING LIKE '%invoice%' OR
            k.KEYWORD_STRING LIKE '%salary%'
        ) THEN 'POTENTIAL_SOX_MISMATCH'
        
        ELSE 'VALID_MAPPING'
    END AS MAPPING_VALIDATION
FROM SENSITIVE_KEYWORDS k
JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
WHERE k.IS_ACTIVE = TRUE 
  AND c.IS_ACTIVE = TRUE
ORDER BY 
    c.POLICY_GROUP, 
    k.SENSITIVITY_WEIGHT DESC, 
    k.KEYWORD_STRING;

-- ============================================================================
-- VIEW 3: VW_CONTEXT_AWARE_RULES
-- Purpose: Context-aware adjustment rules for boosting/reducing scores
--          based on table name, column name, and column suffix patterns
-- ============================================================================
CREATE OR REPLACE VIEW VW_CONTEXT_AWARE_RULES AS
WITH 
-- Get high-weight keywords for context rules
high_weight_keywords AS (
    SELECT 
        k.KEYWORD_STRING,
        c.POLICY_GROUP,
        k.SENSITIVITY_WEIGHT,
        c.CATEGORY_NAME
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE 
      AND c.IS_ACTIVE = TRUE
      AND k.SENSITIVITY_WEIGHT >= 0.7  -- Only high-confidence keywords
),
-- Table context rules from keywords that indicate table purpose
table_context_keywords AS (
    SELECT DISTINCT
        h.POLICY_GROUP,
        h.KEYWORD_STRING,
        'TABLE_NAME' AS RULE_TYPE,
        'BOOST' AS ACTION_TYPE,
        -- Higher weight = higher boost factor
        CASE 
            WHEN h.SENSITIVITY_WEIGHT >= 0.9 THEN 1.8
            WHEN h.SENSITIVITY_WEIGHT >= 0.7 THEN 1.5
            ELSE 1.3
        END AS ACTION_FACTOR,
        'Boost ' || h.POLICY_GROUP || ' for tables containing: ' || h.KEYWORD_STRING AS DESCRIPTION,
        -- Override flag for critical keywords
        CASE 
            WHEN h.SENSITIVITY_WEIGHT >= 0.9 THEN 'HIGH_CONFIDENCE'
            ELSE 'NORMAL'
        END AS OVERRIDE_FLAG
    FROM high_weight_keywords h
    WHERE h.KEYWORD_STRING IN (
        SELECT DISTINCT KEYWORD_STRING 
        FROM high_weight_keywords 
        WHERE KEYWORD_STRING LIKE '%customer%' OR
              KEYWORD_STRING LIKE '%user%' OR
              KEYWORD_STRING LIKE '%employee%' OR
              KEYWORD_STRING LIKE '%patient%' OR
              KEYWORD_STRING LIKE '%person%' OR
              KEYWORD_STRING LIKE '%order%' OR
              KEYWORD_STRING LIKE '%transaction%' OR
              KEYWORD_STRING LIKE '%payment%' OR
              KEYWORD_STRING LIKE '%invoice%' OR
              KEYWORD_STRING LIKE '%auth%' OR
              KEYWORD_STRING LIKE '%security%' OR
              KEYWORD_STRING LIKE '%credential%'
    )
),
-- ID classification rules (keywords that often appear in ID columns)
id_classification_keywords AS (
    SELECT DISTINCT
        h.POLICY_GROUP,
        h.KEYWORD_STRING,
        'COLUMN_SUFFIX' AS RULE_TYPE,
        'BOOST' AS ACTION_TYPE,
        -- Stronger boost for ID-related keywords
        CASE 
            WHEN h.SENSITIVITY_WEIGHT >= 0.9 THEN 2.0
            WHEN h.SENSITIVITY_WEIGHT >= 0.7 THEN 1.6
            ELSE 1.3
        END AS ACTION_FACTOR,
        'Boost ' || h.POLICY_GROUP || ' for ID columns containing: ' || h.KEYWORD_STRING AS DESCRIPTION,
        'ID_OVERRIDE' AS OVERRIDE_FLAG
    FROM high_weight_keywords h
    WHERE h.KEYWORD_STRING IN (
        SELECT DISTINCT KEYWORD_STRING 
        FROM high_weight_keywords 
        WHERE KEYWORD_STRING LIKE '%customer%' OR
              KEYWORD_STRING LIKE '%user%' OR
              KEYWORD_STRING LIKE '%employee%' OR
              KEYWORD_STRING LIKE '%patient%' OR
              KEYWORD_STRING LIKE '%order%' OR
              KEYWORD_STRING LIKE '%transaction%' OR
              KEYWORD_STRING LIKE '%session%' OR
              KEYWORD_STRING LIKE '%auth%' OR
              KEYWORD_STRING LIKE '%credential%'
    )
),
-- Critical field rules (highest weight keywords)
critical_field_keywords AS (
    SELECT DISTINCT
        h.POLICY_GROUP,
        h.KEYWORD_STRING,
        'COLUMN_NAME' AS RULE_TYPE,
        'BOOST' AS ACTION_TYPE,
        -- Very strong boost for critical identifiers
        CASE 
            WHEN h.SENSITIVITY_WEIGHT >= 0.95 THEN 2.5
            WHEN h.SENSITIVITY_WEIGHT >= 0.9 THEN 2.0
            WHEN h.SENSITIVITY_WEIGHT >= 0.8 THEN 1.8
            ELSE 1.5
        END AS ACTION_FACTOR,
        'Critical boost for ' || h.POLICY_GROUP || ' field: ' || h.KEYWORD_STRING AS DESCRIPTION,
        'CRITICAL_OVERRIDE' AS OVERRIDE_FLAG
    FROM high_weight_keywords h
    WHERE h.SENSITIVITY_WEIGHT >= 0.9
      AND h.KEYWORD_STRING NOT LIKE '%generic%'  -- Exclude generic terms
)
-- Union all context rules
SELECT * FROM table_context_keywords
UNION ALL
SELECT * FROM id_classification_keywords
UNION ALL
SELECT * FROM critical_field_keywords
ORDER BY 
    CASE OVERRIDE_FLAG 
        WHEN 'CRITICAL_OVERRIDE' THEN 1
        WHEN 'ID_OVERRIDE' THEN 2
        WHEN 'HIGH_CONFIDENCE' THEN 3
        ELSE 4
    END,
    ACTION_FACTOR DESC,
    POLICY_GROUP,
    RULE_TYPE;

-- ============================================================================
-- VIEW 4: VW_TIEBREAKER_KEYWORDS
-- Purpose: High-weight keywords used for intelligent tiebreaking
--          when multiple policy groups have identical scores
-- ============================================================================
CREATE OR REPLACE VIEW VW_TIEBREAKER_KEYWORDS AS
WITH high_weight_keywords AS (
    SELECT 
        k.KEYWORD_STRING,
        c.POLICY_GROUP,
        k.SENSITIVITY_WEIGHT,
        c.CATEGORY_NAME,
        k.IS_ACTIVE
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE 
      AND c.IS_ACTIVE = TRUE
      AND k.SENSITIVITY_WEIGHT >= 0.7  -- Only high-weight keywords
)
SELECT
    h.POLICY_GROUP,
    h.KEYWORD_STRING AS KEYWORD,
    h.SENSITIVITY_WEIGHT AS WEIGHT,
    h.CATEGORY_NAME,
    h.IS_ACTIVE,
    -- Tier priority based on weight
    CASE 
        WHEN h.SENSITIVITY_WEIGHT >= 0.95 THEN 'TIER_1_CRITICAL'
        WHEN h.SENSITIVITY_WEIGHT >= 0.9 THEN 'TIER_2_HIGH'
        WHEN h.SENSITIVITY_WEIGHT >= 0.8 THEN 'TIER_3_MEDIUM'
        ELSE 'TIER_4_LOW'
    END AS TIER_PRIORITY,
    -- Check for keyword patterns that suggest policy group conflicts
    CASE 
        -- Keywords with "social" or "ssn" should be PII
        WHEN (h.KEYWORD_STRING LIKE '%social%' OR h.KEYWORD_STRING LIKE '%ssn%')
             AND h.POLICY_GROUP != 'PII' THEN 'CHECK_PII_MAPPING'
             
        -- Keywords with "fingerprint" or "biometric" should be PII
        WHEN (h.KEYWORD_STRING LIKE '%fingerprint%' OR h.KEYWORD_STRING LIKE '%biometric%')
             AND h.POLICY_GROUP != 'PII' THEN 'CHECK_PII_MAPPING'
             
        -- Keywords with "ip" or "mac" should be SOC2
        WHEN (h.KEYWORD_STRING LIKE '%ip%' OR h.KEYWORD_STRING LIKE '%mac%')
             AND h.KEYWORD_STRING NOT LIKE '%zip%'  -- Exclude zip codes
             AND h.POLICY_GROUP != 'SOC2' THEN 'CHECK_SOC2_MAPPING'
             
        -- Keywords with "bank" or "credit" should be SOX
        WHEN (h.KEYWORD_STRING LIKE '%bank%' OR h.KEYWORD_STRING LIKE '%credit%')
             AND h.POLICY_GROUP != 'SOX' THEN 'CHECK_SOX_MAPPING'
             
        ELSE 'VALID_MAPPING'
    END AS MAPPING_VALIDATION
FROM high_weight_keywords h
-- Order by tier priority, then weight, then keyword
ORDER BY 
    CASE TIER_PRIORITY
        WHEN 'TIER_1_CRITICAL' THEN 1
        WHEN 'TIER_2_HIGH' THEN 2
        WHEN 'TIER_3_MEDIUM' THEN 3
        ELSE 4
    END,
    h.SENSITIVITY_WEIGHT DESC,
    h.KEYWORD_STRING;

-- ============================================================================
-- VIEW 5: VW_EXCLUSION_PATTERNS (Enhanced Structure)
-- Purpose: Patterns for identifying non-sensitive fields to reduce false positives
--          Returns one row per keyword instead of arrays
-- ============================================================================
CREATE OR REPLACE VIEW VW_EXCLUSION_PATTERNS AS
WITH base_exclusions AS (

    ---------------------------------------------------------------------
    -- 1️⃣ Status, Flags, Modes (Never Sensitive)
    ---------------------------------------------------------------------
    SELECT 
        'STATUS_FLAG' AS EXCLUSION_TYPE,
        keyword AS KEYWORD_PARSED,
        0.1 AS REDUCE_PII_FACTOR,
        0.2 AS REDUCE_SOX_FACTOR,
        0.1 AS REDUCE_SOC2_FACTOR,
        'Reduce sensitivity for generic status/flag fields' AS DESCRIPTION
    FROM (
        SELECT LOWER(column1) AS keyword
        FROM VALUES 
            ('status'), ('state'), ('flag'), ('type'), ('mode'),
            ('method'), ('config'), ('setting'), ('enabled'),
            ('disabled'), ('active'), ('inactive'),
            ('stage'), ('phase'), ('flag_code'), ('indicator')
    )

    UNION ALL

    ---------------------------------------------------------------------
    -- 2️⃣ Generic Business Terms (Non-regulated)
    ---------------------------------------------------------------------
    SELECT 
        'GENERIC_BUSINESS' AS EXCLUSION_TYPE,
        keyword AS KEYWORD_PARSED,
        0.25 AS REDUCE_PII_FACTOR,
        0.25 AS REDUCE_SOX_FACTOR,
        0.25 AS REDUCE_SOC2_FACTOR,
        'Generic non-sensitive business fields' AS DESCRIPTION
    FROM (
        SELECT LOWER(column1) AS keyword
        FROM VALUES
            ('name'), ('description'), ('details'), ('info'),
            ('remarks'), ('comment'), ('notes'), ('summary'),
            ('category'), ('group'), ('class'), ('segment'),
            ('priority'), ('level'), ('type'), ('code'),
            ('tags'), ('label'), ('title'),
            ('reference'), ('status_text')
    )

    UNION ALL

    ---------------------------------------------------------------------
    -- 3️⃣ Non-sensitive Financial Terms (not SOX-relevant)
    ---------------------------------------------------------------------
    SELECT 
        'NON_SENSITIVE_FINANCIAL' AS EXCLUSION_TYPE,
        keyword AS KEYWORD_PARSED,
        0.1 AS REDUCE_PII_FACTOR,
        0.4 AS REDUCE_SOX_FACTOR,
        0.3 AS REDUCE_SOC2_FACTOR,
        'General financial but non-sensitive fields' AS DESCRIPTION
    FROM (
        SELECT LOWER(column1) AS keyword
        FROM VALUES
            ('amount'), ('value'), ('fees'), ('charge'), ('balance'),
            ('price'), ('cost'), ('rate'), ('discount'), ('taxrate'),
            ('margin'), ('profit'), ('loss'), ('quantity'), ('unit_price')
    )

    UNION ALL

    ---------------------------------------------------------------------
    -- 4️⃣ Inventory / Product / Logistics (Not PII nor regulated)
    ---------------------------------------------------------------------
    SELECT 
        'GENERIC_INVENTORY' AS EXCLUSION_TYPE,
        keyword AS KEYWORD_PARSED,
        0.2 AS REDUCE_PII_FACTOR,
        0.3 AS REDUCE_SOX_FACTOR,
        0.2 AS REDUCE_SOC2_FACTOR,
        'Generic product/inventory fields' AS DESCRIPTION
    FROM (
        SELECT LOWER(column1) AS keyword
        FROM VALUES
            ('product'), ('item'), ('sku'), ('stock'),
            ('warehouse'), ('location'), ('bin'), ('rack'),
            ('catalog'), ('inventory'), ('unit'), ('bundle'),
            ('variant'), ('material'), ('package'), ('shelf')
    )

    UNION ALL

    ---------------------------------------------------------------------
    -- 5️⃣ Metadata / Audit Fields
    ---------------------------------------------------------------------
    SELECT 
        'METADATA' AS EXCLUSION_TYPE,
        keyword AS KEYWORD_PARSED,
        0.3 AS REDUCE_PII_FACTOR,
        0.2 AS REDUCE_SOX_FACTOR,
        0.4 AS REDUCE_SOC2_FACTOR,
        'Audit and metadata fields' AS DESCRIPTION
    FROM (
        SELECT LOWER(column1) AS keyword
        FROM VALUES 
            ('created'), ('created_by'), ('updated'), ('updated_by'),
            ('modified'), ('modified_by'), ('deleted'), ('deleted_by'),
            ('timestamp'), ('time'), ('date'), ('datetime'),
            ('version'), ('revision'), ('sync'), ('batch'),
            ('source_system'), ('job_id'), ('process_id'),
            ('load_id'), ('run_id'), ('status_date')
    )

    UNION ALL

    ---------------------------------------------------------------------
    -- 6️⃣ Technical / System / Internal fields
    ---------------------------------------------------------------------
    SELECT 
        'SYSTEM_FIELDS' AS EXCLUSION_TYPE,
        keyword AS KEYWORD_PARSED,
        0.2 AS REDUCE_PII_FACTOR,
        0.1 AS REDUCE_SOX_FACTOR,
        0.4 AS REDUCE_SOC2_FACTOR,
        'System generated or technical fields' AS DESCRIPTION
    FROM (
        SELECT LOWER(column1) AS keyword
        FROM VALUES
            ('ip'), ('host'), ('server'), ('session'), ('token'), 
            ('hash'), ('checksum'), ('status_code'), ('error'),
            ('message'), ('retries'), ('attempt'), ('event'),
            ('log'), ('trace'), ('stack'), ('metadata'),
            ('schema'), ('tablename'), ('columnname'),
            ('uuid'), ('guid')
    )

),

---------------------------------------------------------------------
-- 7️⃣ Dynamic: Low Weight Keywords from SENSITIVE_KEYWORDS Table
---------------------------------------------------------------------
low_weight_keywords AS (
    SELECT
        'LOW_WEIGHT_KEYWORD' AS EXCLUSION_TYPE,
        LOWER(k.KEYWORD_STRING) AS KEYWORD_PARSED,
        0.2 AS REDUCE_PII_FACTOR,
        0.2 AS REDUCE_SOX_FACTOR,
        0.2 AS REDUCE_SOC2_FACTOR,
        'Exclude low-sensitivity database keywords' AS DESCRIPTION
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c 
        ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE
      AND c.IS_ACTIVE = TRUE
      AND k.SENSITIVITY_WEIGHT < 0.5
)

---------------------------------------------------------------------
-- 8️⃣ FINAL MERGE (Non-JSON, one row per keyword)
---------------------------------------------------------------------
SELECT * FROM base_exclusions
UNION ALL
SELECT * FROM low_weight_keywords
ORDER BY EXCLUSION_TYPE, KEYWORD_PARSED;

-- ============================================================================
-- VIEW 6: VW_CATEGORY_METADATA
-- Purpose: Comprehensive category metadata with validation flags
-- ============================================================================
CREATE OR REPLACE VIEW VW_CATEGORY_METADATA AS
WITH category_stats AS (
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
        COUNT(DISTINCT p.PATTERN_ID) AS PATTERN_COUNT,
        -- Calculate average keyword weight
        AVG(k.SENSITIVITY_WEIGHT) AS AVG_KEYWORD_WEIGHT,
        AVG(p.SENSITIVITY_WEIGHT) AS AVG_PATTERN_WEIGHT
    FROM SENSITIVITY_CATEGORIES c
    LEFT JOIN SENSITIVE_KEYWORDS k ON c.CATEGORY_ID = k.CATEGORY_ID AND k.IS_ACTIVE = TRUE
    LEFT JOIN SENSITIVE_PATTERNS p ON c.CATEGORY_ID = p.CATEGORY_ID AND p.IS_ACTIVE = TRUE
    WHERE c.IS_ACTIVE = TRUE
    GROUP BY 
        c.CATEGORY_ID, c.CATEGORY_NAME, c.DESCRIPTION, c.POLICY_GROUP,
        c.CONFIDENTIALITY_LEVEL, c.INTEGRITY_LEVEL, c.AVAILABILITY_LEVEL,
        c.DETECTION_THRESHOLD, c.WEIGHT_EMBEDDING, c.WEIGHT_KEYWORD, c.WEIGHT_PATTERN,
        c.MULTI_LABEL, c.IS_ACTIVE
),
validation_flags AS (
    SELECT
        cs.*,
        -- Check for categories with very few keywords/patterns
        CASE 
            WHEN cs.KEYWORD_COUNT < 3 THEN 'LOW_KEYWORD_COUNT'
            WHEN cs.PATTERN_COUNT = 0 THEN 'NO_PATTERNS'
            WHEN cs.AVG_KEYWORD_WEIGHT < 0.5 THEN 'LOW_KEYWORD_WEIGHT'
            WHEN LENGTH(cs.DESCRIPTION) < 50 THEN 'SHORT_DESCRIPTION'
            ELSE 'OK'
        END AS VALIDATION_STATUS,
        
        -- Check for potential policy group mismatches based on category name
        CASE 
            WHEN cs.POLICY_GROUP != 'PII' AND (
                cs.CATEGORY_NAME LIKE '%SSN%' OR
                cs.CATEGORY_NAME LIKE '%SOCIAL%' OR
                cs.CATEGORY_NAME LIKE '%PASSPORT%' OR
                cs.CATEGORY_NAME LIKE '%BIRTH%' OR
                cs.CATEGORY_NAME LIKE '%FINGERPRINT%' OR
                cs.CATEGORY_NAME LIKE '%BIOMETRIC%'
            ) THEN 'POTENTIAL_PII_MISMATCH'
            
            WHEN cs.POLICY_GROUP != 'SOC2' AND (
                cs.CATEGORY_NAME LIKE '%IP%' OR
                cs.CATEGORY_NAME LIKE '%MAC%' OR
                cs.CATEGORY_NAME LIKE '%API%' OR
                cs.CATEGORY_NAME LIKE '%PASSWORD%' OR
                cs.CATEGORY_NAME LIKE '%TOKEN%'
            ) THEN 'POTENTIAL_SOC2_MISMATCH'
            
            WHEN cs.POLICY_GROUP != 'SOX' AND (
                cs.CATEGORY_NAME LIKE '%BANK%' OR
                cs.CATEGORY_NAME LIKE '%CREDIT%' OR
                cs.CATEGORY_NAME LIKE '%REVENUE%' OR
                cs.CATEGORY_NAME LIKE '%TRANSACTION%' OR
                cs.CATEGORY_NAME LIKE '%SALARY%'
            ) THEN 'POTENTIAL_SOX_MISMATCH'
            
            ELSE 'POLICY_GROUP_OK'
        END AS POLICY_GROUP_VALIDATION
    FROM category_stats cs
)
SELECT * FROM validation_flags
ORDER BY POLICY_GROUP, CATEGORY_NAME;

-- ============================================================================
-- VIEW 7: VW_ADDRESS_CONTEXT_INDICATORS
-- Purpose: Distinguish physical addresses (PII) from network addresses (SOC2)
-- ============================================================================
CREATE OR REPLACE VIEW VW_ADDRESS_CONTEXT_INDICATORS AS
WITH address_keywords AS (
    SELECT DISTINCT
        k.KEYWORD_STRING,
        c.POLICY_GROUP
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE 
      AND c.IS_ACTIVE = TRUE
      AND (k.KEYWORD_STRING LIKE '%address%' OR 
           k.KEYWORD_STRING LIKE '%street%' OR
           k.KEYWORD_STRING LIKE '%city%' OR
           k.KEYWORD_STRING LIKE '%zip%' OR
           k.KEYWORD_STRING LIKE '%postal%' OR
           k.KEYWORD_STRING LIKE '%country%' OR
           k.KEYWORD_STRING LIKE '%ip%' OR
           k.KEYWORD_STRING LIKE '%mac%' OR
           k.KEYWORD_STRING LIKE '%host%' OR
           k.KEYWORD_STRING LIKE '%url%')
)
SELECT
    CASE 
        WHEN KEYWORD_STRING LIKE '%ip%' OR 
             KEYWORD_STRING LIKE '%mac%' OR
             KEYWORD_STRING LIKE '%host%' OR
             KEYWORD_STRING LIKE '%url%' THEN 'NETWORK_ADDRESS'
        ELSE 'PHYSICAL_ADDRESS'
    END AS CONTEXT_TYPE,
    'POSITIVE' AS INDICATOR_TYPE,
    KEYWORD_STRING AS INDICATOR_KEYWORD,
    POLICY_GROUP AS EXPECTED_POLICY_GROUP,
    CASE 
        WHEN POLICY_GROUP = 'PII' THEN 2.5
        WHEN POLICY_GROUP = 'SOC2' THEN 2.0
        ELSE 1.5
    END AS BOOST_FACTOR,
    CASE 
        WHEN POLICY_GROUP = 'PII' THEN 'SOC2,SOX'
        WHEN POLICY_GROUP = 'SOC2' THEN 'PII,SOX'
        WHEN POLICY_GROUP = 'SOX' THEN 'PII,SOC2'
        ELSE ''
    END AS SUPPRESS_POLICY_GROUPS,
    CASE 
        WHEN POLICY_GROUP = 'PII' THEN 0.05
        WHEN POLICY_GROUP = 'SOC2' THEN 0.1
        WHEN POLICY_GROUP = 'SOX' THEN 0.2
        ELSE 0.5
    END AS SUPPRESS_FACTOR,
    'Context indicator for ' || CONTEXT_TYPE || ': ' || KEYWORD_STRING AS DESCRIPTION
FROM address_keywords;

-- ============================================================================
-- VIEW 8: VW_CATEGORY_MAPPING_VALIDATION
-- Purpose: Identify and flag incorrect keyword-to-category mappings
-- ============================================================================
CREATE OR REPLACE VIEW VW_CATEGORY_MAPPING_VALIDATION AS
WITH keyword_patterns AS (
    SELECT 
        k.KEYWORD_STRING,
        c.CATEGORY_NAME,
        c.POLICY_GROUP,
        k.SENSITIVITY_WEIGHT,
        -- Pattern detection
        CASE 
            WHEN k.KEYWORD_STRING LIKE '%ssn%' OR 
                 k.KEYWORD_STRING LIKE '%social_security%' THEN 'PII_PATTERN'
            WHEN k.KEYWORD_STRING LIKE '%passport%' OR 
                 k.KEYWORD_STRING LIKE '%drivers_license%' THEN 'PII_PATTERN'
            WHEN k.KEYWORD_STRING LIKE '%fingerprint%' OR 
                 k.KEYWORD_STRING LIKE '%biometric%' THEN 'PII_PATTERN'
            WHEN k.KEYWORD_STRING LIKE '%ip_address%' OR 
                 k.KEYWORD_STRING LIKE '%mac_address%' THEN 'SOC2_PATTERN'
            WHEN k.KEYWORD_STRING LIKE '%api_key%' OR 
                 k.KEYWORD_STRING LIKE '%oauth_token%' THEN 'SOC2_PATTERN'
            WHEN k.KEYWORD_STRING LIKE '%bank_account%' OR 
                 k.KEYWORD_STRING LIKE '%credit_card%' THEN 'SOX_PATTERN'
            WHEN k.KEYWORD_STRING LIKE '%revenue%' OR 
                 k.KEYWORD_STRING LIKE '%transaction%' THEN 'SOX_PATTERN'
            ELSE 'OTHER_PATTERN'
        END AS DETECTED_PATTERN
    FROM SENSITIVE_KEYWORDS k
    JOIN SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
    WHERE k.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
)
SELECT 
    CASE 
        WHEN DETECTED_PATTERN = 'PII_PATTERN' AND POLICY_GROUP != 'PII' THEN 'INVALID_PII_MAPPING'
        WHEN DETECTED_PATTERN = 'SOC2_PATTERN' AND POLICY_GROUP != 'SOC2' THEN 'INVALID_SOC2_MAPPING'
        WHEN DETECTED_PATTERN = 'SOX_PATTERN' AND POLICY_GROUP != 'SOX' THEN 'INVALID_SOX_MAPPING'
        ELSE 'VALID_MAPPING'
    END AS ISSUE_TYPE,
    KEYWORD_STRING,
    CATEGORY_NAME,
    POLICY_GROUP,
    DETECTED_PATTERN,
    SENSITIVITY_WEIGHT,
    CASE 
        WHEN DETECTED_PATTERN = 'PII_PATTERN' AND POLICY_GROUP != 'PII' THEN 'Move to PII category'
        WHEN DETECTED_PATTERN = 'SOC2_PATTERN' AND POLICY_GROUP != 'SOC2' THEN 'Move to SOC2 category'
        WHEN DETECTED_PATTERN = 'SOX_PATTERN' AND POLICY_GROUP != 'SOX' THEN 'Move to SOX category'
        ELSE 'Mapping is correct'
    END AS RECOMMENDED_ACTION
FROM keyword_patterns
WHERE (DETECTED_PATTERN = 'PII_PATTERN' AND POLICY_GROUP != 'PII') OR
      (DETECTED_PATTERN = 'SOC2_PATTERN' AND POLICY_GROUP != 'SOC2') OR
      (DETECTED_PATTERN = 'SOX_PATTERN' AND POLICY_GROUP != 'SOX')
ORDER BY ISSUE_TYPE, KEYWORD_STRING;

-- ============================================================================
-- VIEW 9: VW_CATEGORY_SCORING_WEIGHTS
-- Purpose: Category-level scoring weights for embedding, keyword, pattern
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

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Verify all views are created successfully
SELECT 'VW_CLASSIFICATION_RULES' AS VIEW_NAME, COUNT(*) AS ROW_COUNT 
FROM VW_CLASSIFICATION_RULES
UNION ALL
SELECT 'VW_POLICY_GROUP_KEYWORDS', COUNT(*) FROM VW_POLICY_GROUP_KEYWORDS
UNION ALL
SELECT 'VW_CONTEXT_AWARE_RULES', COUNT(*) FROM VW_CONTEXT_AWARE_RULES
UNION ALL
SELECT 'VW_TIEBREAKER_KEYWORDS', COUNT(*) FROM VW_TIEBREAKER_KEYWORDS
UNION ALL
SELECT 'VW_EXCLUSION_PATTERNS', COUNT(*) FROM VW_EXCLUSION_PATTERNS
UNION ALL
SELECT 'VW_CATEGORY_METADATA', COUNT(*) FROM VW_CATEGORY_METADATA
UNION ALL
SELECT 'VW_ADDRESS_CONTEXT_INDICATORS', COUNT(*) FROM VW_ADDRESS_CONTEXT_INDICATORS
UNION ALL
SELECT 'VW_CATEGORY_MAPPING_VALIDATION', COUNT(*) FROM VW_CATEGORY_MAPPING_VALIDATION
UNION ALL
SELECT 'VW_CATEGORY_SCORING_WEIGHTS', COUNT(*) FROM VW_CATEGORY_SCORING_WEIGHTS
ORDER BY VIEW_NAME;

-- Show any mapping validation issues
SELECT * FROM VW_CATEGORY_MAPPING_VALIDATION LIMIT 10;

-- ============================================================================
-- END OF SCRIPT
-- ============================================================================
