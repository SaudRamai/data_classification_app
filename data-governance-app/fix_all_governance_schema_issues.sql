-- ============================================================================
-- COMPREHENSIVE GOVERNANCE SCHEMA FIX - COMPLETE SOLUTION
-- Addresses ALL missing columns, tables, and broken patterns
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- PART 1: FIX SENSITIVITY_CATEGORIES
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
-- PART 2: FIX CLASSIFICATION_AI_RESULTS
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

-- Add COMPLIANCE_CATEGORY_ID column (foreign key reference)
ALTER TABLE CLASSIFICATION_AI_RESULTS
ADD COLUMN IF NOT EXISTS COMPLIANCE_CATEGORY_ID VARCHAR(16777216)
COMMENT 'Foreign key to COMPLIANCE_CATEGORIES.COMPLIANCE_ID';

-- Add CLASSIFICATION_TAG column (for Snowflake tag application)
ALTER TABLE CLASSIFICATION_AI_RESULTS
ADD COLUMN IF NOT EXISTS CLASSIFICATION_TAG VARCHAR(16777216)
COMMENT 'Snowflake tag to be applied to the classified object';

-- ============================================================================
-- PART 3: CREATE COMPLIANCE_CATEGORIES TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS COMPLIANCE_CATEGORIES (
    COMPLIANCE_ID VARCHAR(16777216) NOT NULL PRIMARY KEY,
    CATEGORY_NAME VARCHAR(16777216) NOT NULL,
    DESCRIPTION VARCHAR(16777216),
    REGULATORY_FRAMEWORK VARCHAR(16777216) COMMENT 'e.g., GDPR, HIPAA, PCI-DSS, SOX',
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ(9),
    CREATED_BY VARCHAR(16777216) DEFAULT 'SYSTEM',
    UPDATED_BY VARCHAR(16777216)
);

-- Seed COMPLIANCE_CATEGORIES with standard frameworks
MERGE INTO COMPLIANCE_CATEGORIES AS target
USING (
    SELECT 'COMP_PII' AS COMPLIANCE_ID, 
           'PII' AS CATEGORY_NAME, 
           'Personal Identifiable Information - Data that can identify an individual' AS DESCRIPTION, 
           'GDPR, CCPA, Privacy Shield' AS REGULATORY_FRAMEWORK,
           TRUE AS IS_ACTIVE,
           'SYSTEM' AS CREATED_BY
    UNION ALL
    SELECT 'COMP_SOX', 'SOX', 
           'Financial Data - Sarbanes-Oxley Act compliance for financial reporting', 
           'SOX, SEC', TRUE, 'SYSTEM'
    UNION ALL
    SELECT 'COMP_SOC2', 'SOC2', 
           'Security and Access Control - SOC 2 Type II compliance', 
           'SOC2, AICPA', TRUE, 'SYSTEM'
    UNION ALL
    SELECT 'COMP_HIPAA', 'HIPAA', 
           'Healthcare Information - Protected Health Information', 
           'HIPAA, HITECH', TRUE, 'SYSTEM'
    UNION ALL
    SELECT 'COMP_PCI', 'PCI-DSS', 
           'Payment Card Industry - Credit card and payment data', 
           'PCI-DSS', TRUE, 'SYSTEM'
    UNION ALL
    SELECT 'COMP_FERPA', 'FERPA', 
           'Educational Records - Family Educational Rights and Privacy Act', 
           'FERPA', TRUE, 'SYSTEM'
) AS source
ON target.COMPLIANCE_ID = source.COMPLIANCE_ID
WHEN NOT MATCHED THEN
    INSERT (COMPLIANCE_ID, CATEGORY_NAME, DESCRIPTION, REGULATORY_FRAMEWORK, IS_ACTIVE, CREATED_BY)
    VALUES (source.COMPLIANCE_ID, source.CATEGORY_NAME, source.DESCRIPTION, 
            source.REGULATORY_FRAMEWORK, source.IS_ACTIVE, source.CREATED_BY);

-- ============================================================================
-- PART 4: FIX BROKEN REGEX PATTERNS IN SENSITIVE_PATTERNS
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
-- PART 5: GRANT PERMISSIONS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA DATA_CLASSIFICATION_GOVERNANCE TO ROLE SYSADMIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA DATA_CLASSIFICATION_GOVERNANCE TO ROLE ACCOUNTADMIN;

-- ============================================================================
-- PART 6: VERIFICATION QUERIES
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
  AND COLUMN_NAME IN ('SCHEMA_NAME', 'DATABASE_NAME', 'SENSITIVITY_CATEGORY_ID', 
                      'COMPLIANCE_CATEGORY_ID', 'CLASSIFICATION_TAG')
ORDER BY COLUMN_NAME;

-- Verify COMPLIANCE_CATEGORIES table exists and has data
SELECT '✓ COMPLIANCE_CATEGORIES Data:' AS CHECK_TYPE;
SELECT COMPLIANCE_ID, CATEGORY_NAME, REGULATORY_FRAMEWORK, IS_ACTIVE
FROM COMPLIANCE_CATEGORIES
ORDER BY CATEGORY_NAME;

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

-- Final summary
SELECT '✅ SCHEMA FIX COMPLETED SUCCESSFULLY!' AS STATUS,
       CURRENT_TIMESTAMP() AS COMPLETED_AT;

-- ============================================================================
-- INSTRUCTIONS FOR USE:
-- ============================================================================
-- 1. Execute this entire script in Snowflake Web UI or SnowSQL
-- 2. Review the verification output at the end
-- 3. If any validation shows ❌, re-run the relevant section
-- 4. Restart your Streamlit application
-- ============================================================================


-- ============================================================================
-- 1. FIX SENSITIVITY_CATEGORIES - Add missing COLOR_CODE column
-- ============================================================================
ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS COLOR_CODE VARCHAR(16) DEFAULT '#808080' 
COMMENT 'Hex color code for UI display (e.g., #FF5733)';

-- Update existing rows with default colors based on policy group
UPDATE SENSITIVITY_CATEGORIES
SET COLOR_CODE = CASE 
    WHEN UPPER(POLICY_GROUP) = 'PII' THEN '#FF5733'  -- Red for PII
    WHEN UPPER(POLICY_GROUP) = 'SOX' THEN '#FFA500'  -- Orange for SOX
    WHEN UPPER(POLICY_GROUP) = 'SOC2' THEN '#4169E1' -- Blue for SOC2
    WHEN CONFIDENTIALITY_LEVEL >= 3 THEN '#DC143C'   -- Crimson for high confidentiality
    WHEN CONFIDENTIALITY_LEVEL = 2 THEN '#FF8C00'    -- Dark orange for medium
    WHEN CONFIDENTIALITY_LEVEL = 1 THEN '#FFD700'    -- Gold for low
    ELSE '#808080'  -- Gray for unknown
END
WHERE COLOR_CODE IS NULL OR COLOR_CODE = '#808080';

-- ============================================================================
-- 2. FIX CLASSIFICATION_AI_RESULTS - Add missing columns
-- ============================================================================
ALTER TABLE CLASSIFICATION_AI_RESULTS
ADD COLUMN IF NOT EXISTS SCHEMA_NAME VARCHAR(16777216) 
COMMENT 'Schema name for the classified table';

ALTER TABLE CLASSIFICATION_AI_RESULTS
ADD COLUMN IF NOT EXISTS DATABASE_NAME VARCHAR(16777216) 
COMMENT 'Database name for the classified table';

ALTER TABLE CLASSIFICATION_AI_RESULTS
ADD COLUMN IF NOT EXISTS SENSITIVITY_CATEGORY_ID VARCHAR(16777216)
COMMENT 'Foreign key to SENSITIVITY_CATEGORIES';

ALTER TABLE CLASSIFICATION_AI_RESULTS
ADD COLUMN IF NOT EXISTS COMPLIANCE_CATEGORY_ID VARCHAR(16777216)
COMMENT 'Foreign key to COMPLIANCE_CATEGORIES';

ALTER TABLE CLASSIFICATION_AI_RESULTS
ADD COLUMN IF NOT EXISTS CLASSIFICATION_TAG VARCHAR(16777216)
COMMENT 'Snowflake tag to be applied';

-- ============================================================================
-- 3. CREATE COMPLIANCE_CATEGORIES table if it doesn't exist
-- ============================================================================
CREATE TABLE IF NOT EXISTS COMPLIANCE_CATEGORIES (
    COMPLIANCE_ID VARCHAR(16777216) NOT NULL PRIMARY KEY,
    CATEGORY_NAME VARCHAR(16777216) NOT NULL,
    DESCRIPTION VARCHAR(16777216),
    REGULATORY_FRAMEWORK VARCHAR(16777216) COMMENT 'e.g., GDPR, HIPAA, PCI-DSS',
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ(9)
);

-- Seed compliance categories
MERGE INTO COMPLIANCE_CATEGORIES AS target
USING (
    SELECT 'COMP_PII' AS COMPLIANCE_ID, 'PII' AS CATEGORY_NAME, 
           'Personal Identifiable Information' AS DESCRIPTION, 
           'GDPR, CCPA' AS REGULATORY_FRAMEWORK
    UNION ALL
    SELECT 'COMP_SOX', 'SOX', 'Financial Data (Sarbanes-Oxley)', 'SOX'
    UNION ALL
    SELECT 'COMP_SOC2', 'SOC2', 'Security and Access Control', 'SOC2'
    UNION ALL
    SELECT 'COMP_HIPAA', 'HIPAA', 'Healthcare Information', 'HIPAA'
    UNION ALL
    SELECT 'COMP_PCI', 'PCI-DSS', 'Payment Card Industry', 'PCI-DSS'
) AS source
ON target.COMPLIANCE_ID = source.COMPLIANCE_ID
WHEN NOT MATCHED THEN
    INSERT (COMPLIANCE_ID, CATEGORY_NAME, DESCRIPTION, REGULATORY_FRAMEWORK)
    VALUES (source.COMPLIANCE_ID, source.CATEGORY_NAME, source.DESCRIPTION, source.REGULATORY_FRAMEWORK);

-- ============================================================================
-- 4. FIX SENSITIVE_PATTERNS - Fix broken regex patterns
-- ============================================================================

-- Fix the malformed account number pattern
UPDATE SENSITIVE_PATTERNS
SET PATTERN_REGEX = '(?:account|acct).*?\\d{4,12}'
WHERE PATTERN_REGEX LIKE '%y(?:account|acct)%'
   OR PATTERN_REGEX LIKE '%d{4,12}y%';

-- Validate and fix other common regex issues
UPDATE SENSITIVE_PATTERNS
SET PATTERN_REGEX = REPLACE(PATTERN_REGEX, 'd{', '\\d{')
WHERE PATTERN_REGEX LIKE '%d{%' 
  AND PATTERN_REGEX NOT LIKE '%\\d{%';

UPDATE SENSITIVE_PATTERNS
SET PATTERN_REGEX = REPLACE(PATTERN_REGEX, 'w+', '\\w+')
WHERE PATTERN_REGEX LIKE '%w+%' 
  AND PATTERN_REGEX NOT LIKE '%\\w+%';

-- ============================================================================
-- 5. ADD DEFAULT THRESHOLD COLUMN to SENSITIVITY_CATEGORIES
-- ============================================================================
ALTER TABLE SENSITIVITY_CATEGORIES
ADD COLUMN IF NOT EXISTS DEFAULT_THRESHOLD FLOAT DEFAULT 0.45
COMMENT 'Default detection threshold (same as DETECTION_THRESHOLD for backward compatibility)';

-- Sync DEFAULT_THRESHOLD with DETECTION_THRESHOLD
UPDATE SENSITIVITY_CATEGORIES
SET DEFAULT_THRESHOLD = COALESCE(DETECTION_THRESHOLD, 0.45)
WHERE DEFAULT_THRESHOLD IS NULL;

-- ============================================================================
-- 6. Verify all required columns exist
-- ============================================================================
SELECT 
    'SENSITIVITY_CATEGORIES' AS TABLE_NAME,
    COUNT(*) AS COLUMN_COUNT,
    LISTAGG(COLUMN_NAME, ', ') WITHIN GROUP (ORDER BY ORDINAL_POSITION) AS COLUMNS
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE'
  AND TABLE_NAME = 'SENSITIVITY_CATEGORIES'
GROUP BY TABLE_NAME

UNION ALL

SELECT 
    'CLASSIFICATION_AI_RESULTS' AS TABLE_NAME,
    COUNT(*) AS COLUMN_COUNT,
    LISTAGG(COLUMN_NAME, ', ') WITHIN GROUP (ORDER BY ORDINAL_POSITION) AS COLUMNS
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE'
  AND TABLE_NAME = 'CLASSIFICATION_AI_RESULTS'
GROUP BY TABLE_NAME

UNION ALL

SELECT 
    'COMPLIANCE_CATEGORIES' AS TABLE_NAME,
    COUNT(*) AS COLUMN_COUNT,
    LISTAGG(COLUMN_NAME, ', ') WITHIN GROUP (ORDER BY ORDINAL_POSITION) AS COLUMNS
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE'
  AND TABLE_NAME = 'COMPLIANCE_CATEGORIES'
GROUP BY TABLE_NAME;

-- ============================================================================
-- 7. Grant necessary permissions
-- ============================================================================
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA DATA_CLASSIFICATION_GOVERNANCE TO ROLE SYSADMIN;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA DATA_CLASSIFICATION_GOVERNANCE TO ROLE ACCOUNTADMIN;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Check COLOR_CODE column exists and has values
SELECT 
    CATEGORY_NAME, 
    POLICY_GROUP, 
    COLOR_CODE,
    DETECTION_THRESHOLD,
    DEFAULT_THRESHOLD
FROM SENSITIVITY_CATEGORIES
ORDER BY CATEGORY_NAME;

-- Check CLASSIFICATION_AI_RESULTS has all required columns
SELECT COLUMN_NAME, DATA_TYPE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE'
  AND TABLE_NAME = 'CLASSIFICATION_AI_RESULTS'
ORDER BY ORDINAL_POSITION;

-- Check for broken regex patterns
SELECT 
    PATTERN_ID,
    CATEGORY_ID,
    PATTERN_NAME,
    PATTERN_REGEX,
    CASE 
        WHEN PATTERN_REGEX LIKE '%y(?:%' THEN 'NEEDS FIX: Invalid escape'
        WHEN PATTERN_REGEX LIKE '%d{%' AND PATTERN_REGEX NOT LIKE '%\\d{%' THEN 'NEEDS FIX: Missing backslash'
        ELSE 'OK'
    END AS STATUS
FROM SENSITIVE_PATTERNS
WHERE IS_ACTIVE = TRUE
ORDER BY STATUS DESC, PATTERN_NAME;

SELECT '✅ Schema fixes completed successfully!' AS STATUS;
