-- ============================================================================
-- SNOWFLAKE SQL: ASSET AI CLASSIFICATION UPDATE
-- ============================================================================
-- Description: Aggregates column-level AI results to table-level and updates 
--              the ASSETS inventory table using FQN-based join logic.
-- ============================================================================

MERGE INTO DATA_CLASSIFICATION_GOVERNANCE.ASSETS AS t
USING (
    WITH aggregated_ai AS (
        SELECT
            -- Use new ASSET_FULL_NAME schema
            ASSET_FULL_NAME,
            -- Aggregate to Table Level: TRUE if ANY column is TRUE
            MAX(COALESCE(PII_RELEVANT, FALSE)) as PII_RELEVANT,
            MAX(COALESCE(SOX_RELEVANT, FALSE)) as SOX_RELEVANT,
            MAX(COALESCE(SOC2_RELEVANT, FALSE)) as SOC2_RELEVANT
        FROM DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS
        WHERE ASSET_FULL_NAME IS NOT NULL
        GROUP BY ASSET_FULL_NAME
    )
    SELECT 
        ASSET_FULL_NAME as FQN,
        PII_RELEVANT,
        SOX_RELEVANT,
        SOC2_RELEVANT
    FROM aggregated_ai
) AS s
ON UPPER(t.FULLY_QUALIFIED_NAME) = UPPER(s.FQN)
WHEN MATCHED 
    -- Constraint: Only update TABLE assets
    AND t.ASSET_TYPE IN ('TABLE', 'BASE TABLE', 'VIEW')
    -- Constraint: Only update when values actually change (Change Detection)
    AND (
        (t.PII_RELEVANT IS DISTINCT FROM s.PII_RELEVANT) OR
        (t.SOX_RELEVANT IS DISTINCT FROM s.SOX_RELEVANT) OR
        (t.SOC2_RELEVANT IS DISTINCT FROM s.SOC2_RELEVANT)
    )
THEN
    UPDATE SET
        t.PII_RELEVANT = s.PII_RELEVANT,
        t.SOX_RELEVANT = s.SOX_RELEVANT,
        t.SOC2_RELEVANT = s.SOC2_RELEVANT,
        t.LAST_MODIFIED_TIMESTAMP = CURRENT_TIMESTAMP(),
        t.LAST_MODIFIED_BY = CURRENT_USER(),
        t.RECORD_VERSION = t.RECORD_VERSION + 1;

-- ============================================================================
-- DEBUG QUERY: Check unmatched AI results (Updated for new schema)
-- ============================================================================
-- SELECT 
--     ASSET_FULL_NAME as UNMATCHED_FQN
-- FROM DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS
-- WHERE UPPER(ASSET_FULL_NAME) NOT IN (SELECT UPPER(FULLY_QUALIFIED_NAME) FROM DATA_CLASSIFICATION_GOVERNANCE.ASSETS)
-- GROUP BY 1;
