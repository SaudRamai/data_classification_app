-- ============================================================================
-- ADD EXCLUSION RULES FOR UUIDs AND SYSTEM-GENERATED IDs
-- ============================================================================
-- This script creates exclusion patterns to prevent classification of:
-- 1. UUIDs (e.g., 9e5a4c7e-9daa-48b3-941e-a6cfb5faa6a5)
-- 2. System-generated IDs (e.g., id, created_by, updated_at)
-- 3. Technical metadata columns
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- STEP 1: Create Exclusion Patterns Table (if not exists)
-- ============================================================================
CREATE TABLE IF NOT EXISTS EXCLUSION_PATTERNS (
    EXCLUSION_ID VARCHAR(36) PRIMARY KEY,
    PATTERN_TYPE VARCHAR(20), -- 'COLUMN_NAME', 'DATA_TYPE', 'REGEX'
    PATTERN_VALUE VARCHAR(500),
    EXCLUSION_REASON VARCHAR(500),
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(100),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(100),
    UPDATED_AT TIMESTAMP_NTZ
);

-- ============================================================================
-- STEP 2: Add UUID Exclusion Patterns
-- ============================================================================

-- Exclude columns named exactly "UUID" or "GUID"
MERGE INTO EXCLUSION_PATTERNS AS target
USING (
    SELECT 
        UUID_STRING() AS EXCLUSION_ID,
        'COLUMN_NAME' AS PATTERN_TYPE,
        'uuid' AS PATTERN_VALUE,
        'UUIDs are technical identifiers, not sensitive data' AS EXCLUSION_REASON,
        TRUE AS IS_ACTIVE,
        'SYSTEM' AS CREATED_BY,
        CURRENT_TIMESTAMP() AS CREATED_AT
) AS source
ON target.PATTERN_VALUE = source.PATTERN_VALUE 
   AND target.PATTERN_TYPE = source.PATTERN_TYPE
WHEN NOT MATCHED THEN
    INSERT (EXCLUSION_ID, PATTERN_TYPE, PATTERN_VALUE, EXCLUSION_REASON, IS_ACTIVE, CREATED_BY, CREATED_AT)
    VALUES (source.EXCLUSION_ID, source.PATTERN_TYPE, source.PATTERN_VALUE, source.EXCLUSION_REASON, source.IS_ACTIVE, source.CREATED_BY, source.CREATED_AT);

MERGE INTO EXCLUSION_PATTERNS AS target
USING (
    SELECT 
        UUID_STRING() AS EXCLUSION_ID,
        'COLUMN_NAME' AS PATTERN_TYPE,
        'guid' AS PATTERN_VALUE,
        'GUIDs are technical identifiers, not sensitive data' AS EXCLUSION_REASON,
        TRUE AS IS_ACTIVE,
        'SYSTEM' AS CREATED_BY,
        CURRENT_TIMESTAMP() AS CREATED_AT
) AS source
ON target.PATTERN_VALUE = source.PATTERN_VALUE 
   AND target.PATTERN_TYPE = source.PATTERN_TYPE
WHEN NOT MATCHED THEN
    INSERT (EXCLUSION_ID, PATTERN_TYPE, PATTERN_VALUE, EXCLUSION_REASON, IS_ACTIVE, CREATED_BY, CREATED_AT)
    VALUES (source.EXCLUSION_ID, source.PATTERN_TYPE, source.PATTERN_VALUE, source.EXCLUSION_REASON, source.IS_ACTIVE, source.CREATED_BY, source.CREATED_AT);

-- ============================================================================
-- STEP 3: Add System ID Column Patterns
-- ============================================================================

INSERT INTO EXCLUSION_PATTERNS (EXCLUSION_ID, PATTERN_TYPE, PATTERN_VALUE, EXCLUSION_REASON, IS_ACTIVE, CREATED_BY, CREATED_AT)
SELECT 
    UUID_STRING(),
    'COLUMN_NAME',
    col_pattern,
    'System-generated metadata, not business-sensitive data',
    TRUE,
    'SYSTEM',
    CURRENT_TIMESTAMP()
FROM (
    SELECT 'id' AS col_pattern UNION ALL
    SELECT 'row_id' UNION ALL
    SELECT 'record_id' UNION ALL
    SELECT 'created_by' UNION ALL
    SELECT 'updated_by' UNION ALL
    SELECT 'created_at' UNION ALL
    SELECT 'updated_at' UNION ALL
    SELECT 'modified_at' UNION ALL
    SELECT 'modified_by' UNION ALL
    SELECT 'deleted_at' UNION ALL
    SELECT 'deleted_by' UNION ALL
    SELECT 'created_date' UNION ALL
    SELECT 'updated_date' UNION ALL
    SELECT 'created_time' UNION ALL
    SELECT 'updated_time' UNION ALL
    SELECT 'insert_timestamp' UNION ALL
    SELECT 'update_timestamp' UNION ALL
    SELECT 'version' UNION ALL
    SELECT 'version_number' UNION ALL
    SELECT 'row_version' UNION ALL
    SELECT 'etl_load_date' UNION ALL
    SELECT 'etl_update_date' UNION ALL
    SELECT 'batch_id' UNION ALL
    SELECT 'load_id' UNION ALL
    SELECT 'source_system' UNION ALL
    SELECT 'active_flag' UNION ALL
    SELECT 'is_active' UNION ALL
    SELECT 'is_deleted' UNION ALL
    SELECT 'hash_key' UNION ALL
    SELECT 'hash_diff'
) patterns
WHERE NOT EXISTS (
    SELECT 1 FROM EXCLUSION_PATTERNS ep
    WHERE ep.PATTERN_VALUE = patterns.col_pattern
    AND ep.PATTERN_TYPE = 'COLUMN_NAME'
);

-- ============================================================================
-- STEP 4: Add Regex Patterns for UUIDs and System IDs
-- ============================================================================

-- Pattern: Columns ending with _id, _uuid, _guid
INSERT INTO EXCLUSION_PATTERNS (EXCLUSION_ID, PATTERN_TYPE, PATTERN_VALUE, EXCLUSION_REASON, IS_ACTIVE, CREATED_BY, CREATED_AT)
SELECT 
    UUID_STRING(),
    'REGEX',
    pattern,
    reason,
    TRUE,
    'SYSTEM',
    CURRENT_TIMESTAMP()
FROM (
    SELECT '^.*_id$' AS pattern, 'Column name ends with _id (likely system ID)' AS reason UNION ALL
    SELECT '^.*_uuid$', 'Column name ends with _uuid (UUID identifier)' UNION ALL
    SELECT '^.*_guid$', 'Column name ends with _guid (GUID identifier)' UNION ALL
    SELECT '^id_.*$', 'Column name starts with id_ (likely system ID)' UNION ALL
    SELECT '^uuid_.*$', 'Column name starts with uuid_ (UUID identifier)' UNION ALL
    SELECT '^guid_.*$', 'Column name starts with guid_ (GUID identifier)' UNION ALL
    SELECT '^sys_.*$', 'Column name starts with sys_ (system column)' UNION ALL
    SELECT '^_.*$', 'Column name starts with underscore (internal system column)' UNION ALL
    SELECT '^created_(by|at|date|time|timestamp)$', 'Audit trail metadata' UNION ALL
    SELECT '^updated_(by|at|date|time|timestamp)$', 'Audit trail metadata' UNION ALL
    SELECT '^modified_(by|at|date|time|timestamp)$', 'Audit trail metadata' UNION ALL
    SELECT '^deleted_(by|at|date|time|timestamp)$', 'Audit trail metadata' UNION ALL
    SELECT '^insert_(date|time|timestamp|user)$', 'ETL metadata' UNION ALL
    SELECT '^update_(date|time|timestamp|user)$', 'ETL metadata' UNION ALL
    SELECT '^etl_.*$', 'ETL system metadata'
) exclusions
WHERE NOT EXISTS (
    SELECT 1 FROM EXCLUSION_PATTERNS ep
    WHERE ep.PATTERN_VALUE = exclusions.pattern
    AND ep.PATTERN_TYPE = 'REGEX'
);

-- ============================================================================
-- STEP 5: Verification - Show All Exclusion Patterns
-- ============================================================================
SELECT 
    PATTERN_TYPE,
    PATTERN_VALUE,
    EXCLUSION_REASON,
    IS_ACTIVE,
    CREATED_BY,
    CREATED_AT
FROM EXCLUSION_PATTERNS
WHERE IS_ACTIVE = TRUE
ORDER BY PATTERN_TYPE, PATTERN_VALUE;

-- ============================================================================
-- STEP 6: Test Exclusion Patterns
-- ============================================================================
-- Test which common column names would be excluded

WITH test_columns AS (
    SELECT 'uuid' AS col_name UNION ALL
    SELECT 'guid' UNION ALL
    SELECT 'id' UNION ALL
    SELECT 'user_id' UNION ALL
    SELECT 'order_id' UNION ALL
    SELECT 'created_by' UNION ALL
    SELECT 'updated_at' UNION ALL
    SELECT 'created_timestamp' UNION ALL
    SELECT 'etl_load_date' UNION ALL
    SELECT 'customer_uuid' UNION ALL
    SELECT 'transaction_guid' UNION ALL
    SELECT 'sys_created_date' UNION ALL
    SELECT '_internal_id' UNION ALL
    SELECT 'version_number' UNION ALL
    -- These should NOT be excluded
    SELECT 'email' UNION ALL
    SELECT 'ssn' UNION ALL
    SELECT 'credit_card' UNION ALL
    SELECT 'phone_number'
)
SELECT 
    tc.col_name,
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
    END AS STATUS,
    (
        SELECT LISTAGG(ep.EXCLUSION_REASON, '; ') WITHIN GROUP (ORDER BY ep.PATTERN_VALUE)
        FROM EXCLUSION_PATTERNS ep
        WHERE ep.IS_ACTIVE = TRUE
        AND (
            (ep.PATTERN_TYPE = 'COLUMN_NAME' AND LOWER(tc.col_name) = LOWER(ep.PATTERN_VALUE))
            OR
            (ep.PATTERN_TYPE = 'REGEX' AND RLIKE(LOWER(tc.col_name), ep.PATTERN_VALUE, 'i'))
        )
    ) AS EXCLUSION_REASON
FROM test_columns tc
ORDER BY STATUS DESC, col_name;

-- Expected Results:
-- 🚫 EXCLUDED: uuid, guid, id, user_id, order_id, created_by, updated_at, etc.
-- ✅ INCLUDED: email, ssn, credit_card, phone_number

-- ============================================================================
-- SUCCESS CRITERIA:
-- 1. All UUID/GUID columns excluded
-- 2. All *_id columns excluded
-- 3. All system metadata columns excluded
-- 4. Business-sensitive columns still included
-- ============================================================================
