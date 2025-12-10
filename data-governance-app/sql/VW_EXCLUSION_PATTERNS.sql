-- ============================================================================
-- VW_EXCLUSION_PATTERNS - Enhanced Version
-- ============================================================================
-- This view returns one row per keyword instead of JSON arrays
-- Makes it easier to work with and extend
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

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
-- Verification Query
-- ============================================================================
-- Run this to verify the view returns data:
-- SELECT EXCLUSION_TYPE, COUNT(*) AS KEYWORD_COUNT
-- FROM VW_EXCLUSION_PATTERNS
-- GROUP BY EXCLUSION_TYPE
-- ORDER BY EXCLUSION_TYPE;
