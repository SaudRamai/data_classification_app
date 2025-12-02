-- ============================================================================
-- SIMPLIFIED GOVERNANCE SCHEMA FIX
-- Adds only missing columns (NO COMPLIANCE_CATEGORIES table)
-- Uses POLICY_GROUP from SENSITIVITY_CATEGORIES for compliance mapping
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- PART 1: FIX SENSITIVITY_CATEGORIES - Add COLOR_CODE and DEFAULT_THRESHOLD
-- ============================================================================

-- Add COLOR_CODE column (for UI display)
ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS COLOR_CODE VARCHAR(16) DEFAULT '#808080' 
COMMENT 'Hex color code for UI display (e.g., #FF5733)';

-- Add DEFAULT_THRESHOLD column (for backward compatibility)
ALTER TABLE SENSITIVITY_CATEGORIES
ADD COLUMN IF NOT EXISTS DEFAULT_THRESHOLD FLOAT DEFAULT 0.45
COMMENT 'Default detection threshold (same as DETECTION_THRESHOLD)';

-- Update COLOR_CODE with policy-based colors
UPDATE SENSITIVITY_CATEGORIES
SET COLOR_CODE = CASE 
    WHEN UPPER(POLICY_GROUP) = 'PII' THEN '#FF5733'      -- Red for PII
    WHEN UPPER(POLICY_GROUP) = 'SOX' THEN '#FFA500'      -- Orange for SOX
    WHEN UPPER(POLICY_GROUP) = 'SOC2' THEN '#4169E1'     -- Blue for SOC2
    WHEN CONFIDENTIALITY_LEVEL >= 3 THEN '#DC143C'       -- Crimson for high
    WHEN CONFIDENTIALITY_LEVEL = 2 THEN '#FF8C00'        -- Dark orange for medium
    WHEN CONFIDENTIALITY_LEVEL = 1 THEN '#FFD700'        -- Gold for low
    ELSE '#808080'                                        -- Gray default
END
WHERE COLOR_CODE IS NULL OR COLOR_CODE = '#808080';

-- Sync DEFAULT_THRESHOLD with DETECTION_THRESHOLD
UPDATE SENSITIVITY_CATEGORIES
SET DEFAULT_THRESHOLD = COALESCE(DETECTION_THRESHOLD, 0.45)
WHERE DEFAULT_THRESHOLD IS NULL OR DEFAULT_THRESHOLD = 0.45;

-- ============================================================================
-- PART 2: FIX CLASSIFICATION_AI_RESULTS - Add missing columns
-- ============================================================================

-- Add SCHEMA_NAME column
ALTER TABLE CLASSIFICATION_AI_RESULTS
ADD COLUMN IF NOT EXISTS SCHEMA_NAME VARCHAR(16777216) 
COMMENT 'Schema name for the classified table';

-- Add DATABASE_NAME column
ALTER TABLE CLASSIFICATION_AI_RESULTS
ADD COLUMN IF NOT EXISTS DATABASE_NAME VARCHAR(16777216) 
COMMENT 'Database name for the classified table';

-- Add SENSITIVITY_CATEGORY_ID column (foreign key reference)
ALTER TABLE CLASSIFICATION_AI_RESULTS
ADD COLUMN IF NOT EXISTS SENSITIVITY_CATEGORY_ID VARCHAR(16777216)
COMMENT 'Foreign key to SENSITIVITY_CATEGORIES.CATEGORY_ID';

-- ============================================================================
-- PART 3: FIX BROKEN REGEX PATTERNS IN SENSITIVE_PATTERNS
-- ============================================================================

-- Fix the specific malformed account pattern
UPDATE SENSITIVE_PATTERNS
SET PATTERN_REGEX = '(?:account|acct).*?\\d{4,12}',
    UPDATED_AT = CURRENT_TIMESTAMP()
WHERE PATTERN_REGEX LIKE '%y(?:account|acct)%'
   OR PATTERN_REGEX LIKE '%d{4,12}y%';

-- Fix unescaped \d patterns
UPDATE SENSITIVE_PATTERNS
SET PATTERN_REGEX = REPLACE(PATTERN_REGEX, 'd{', '\\d{'),
    UPDATED_AT = CURRENT_TIMESTAMP()
WHERE PATTERN_REGEX LIKE '%d{%' 
  AND PATTERN_REGEX NOT LIKE '%\\d{%'
  AND IS_ACTIVE = TRUE;

-- Fix unescaped \w patterns
UPDATE SENSITIVE_PATTERNS
SET PATTERN_REGEX = REPLACE(PATTERN_REGEX, 'w+', '\\w+'),
    UPDATED_AT = CURRENT_TIMESTAMP()
WHERE PATTERN_REGEX LIKE '%w+%' 
  AND PATTERN_REGEX NOT LIKE '%\\w+%'
  AND IS_ACTIVE = TRUE;

-- Fix unescaped \s patterns
UPDATE SENSITIVE_PATTERNS
SET PATTERN_REGEX = REPLACE(PATTERN_REGEX, 's+', '\\s+'),
    UPDATED_AT = CURRENT_TIMESTAMP()
WHERE PATTERN_REGEX LIKE '%s+%' 
  AND PATTERN_REGEX NOT LIKE '%\\s+%'
  AND IS_ACTIVE = TRUE;

-- ============================================================================
-- PART 4: GRANT PERMISSIONS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA DATA_CLASSIFICATION_GOVERNANCE TO ROLE SYSADMIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA DATA_CLASSIFICATION_GOVERNANCE TO ROLE ACCOUNTADMIN;

-- ============================================================================
-- PART 5: VERIFICATION QUERIES
-- ============================================================================

-- Verify SENSITIVITY_CATEGORIES has all required columns
SELECT '✓ SENSITIVITY_CATEGORIES Columns:' AS CHECK_TYPE;
SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE'
  AND TABLE_NAME = 'SENSITIVITY_CATEGORIES'
  AND COLUMN_NAME IN ('COLOR_CODE', 'DEFAULT_THRESHOLD', 'POLICY_GROUP', 
                      'WEIGHT_EMBEDDING', 'WEIGHT_KEYWORD', 'WEIGHT_PATTERN')
ORDER BY COLUMN_NAME;

-- Verify CLASSIFICATION_AI_RESULTS has all required columns
SELECT '✓ CLASSIFICATION_AI_RESULTS Columns:' AS CHECK_TYPE;
SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE'
  AND TABLE_NAME = 'CLASSIFICATION_AI_RESULTS'
  AND COLUMN_NAME IN ('SCHEMA_NAME', 'DATABASE_NAME', 'SENSITIVITY_CATEGORY_ID')
ORDER BY COLUMN_NAME;

-- Check for any remaining broken regex patterns
SELECT '✓ Regex Pattern Validation:' AS CHECK_TYPE;
SELECT 
    PATTERN_ID,
    PATTERN_NAME,
    PATTERN_REGEX,
    CASE 
        WHEN PATTERN_REGEX LIKE '%y(?:%' THEN '❌ NEEDS FIX: Invalid y(?: prefix'
        WHEN PATTERN_REGEX LIKE '%d{%' AND PATTERN_REGEX NOT LIKE '%\\d{%' THEN '❌ NEEDS FIX: Unescaped d{'
        WHEN PATTERN_REGEX LIKE '%w+%' AND PATTERN_REGEX NOT LIKE '%\\w+%' THEN '❌ NEEDS FIX: Unescaped w+'
        WHEN PATTERN_REGEX LIKE '%s+%' AND PATTERN_REGEX NOT LIKE '%\\s+%' THEN '❌ NEEDS FIX: Unescaped s+'
        ELSE '✅ OK'
    END AS VALIDATION_STATUS
FROM SENSITIVE_PATTERNS
WHERE IS_ACTIVE = TRUE
ORDER BY VALIDATION_STATUS DESC, PATTERN_NAME
LIMIT 20;

-- Verify COLOR_CODE values are set
SELECT '✓ COLOR_CODE Distribution:' AS CHECK_TYPE;
SELECT 
    POLICY_GROUP,
    COLOR_CODE,
    COUNT(*) AS CATEGORY_COUNT
FROM SENSITIVITY_CATEGORIES
WHERE IS_ACTIVE = TRUE
GROUP BY POLICY_GROUP, COLOR_CODE
ORDER BY POLICY_GROUP;

-- Verify POLICY_GROUP is populated (used for compliance mapping)
SELECT '✓ POLICY_GROUP Distribution:' AS CHECK_TYPE;
SELECT 
    POLICY_GROUP,
    COUNT(*) AS CATEGORY_COUNT,
    LISTAGG(CATEGORY_NAME, ', ') WITHIN GROUP (ORDER BY CATEGORY_NAME) AS CATEGORIES
FROM SENSITIVITY_CATEGORIES
WHERE IS_ACTIVE = TRUE
GROUP BY POLICY_GROUP
ORDER BY POLICY_GROUP;

-- Final summary
SELECT '✅ SCHEMA FIX COMPLETED SUCCESSFULLY!' AS STATUS,
       CURRENT_TIMESTAMP() AS COMPLETED_AT;

-- ============================================================================
-- INSTRUCTIONS FOR USE:
-- ============================================================================
-- 1. Execute this entire script in Snowflake Web UI or SnowSQL
-- 2. Review the verification output at the end
-- 3. Ensure POLICY_GROUP is populated for all categories
-- 4. If any validation shows ❌, re-run the relevant section
-- 5. Restart your Streamlit application
-- ============================================================================
