-- ============================================================================
-- METADATA-DRIVEN CLASSIFICATION SCHEMA UPDATE
-- ============================================================================
-- This script extends the SENSITIVITY_CATEGORIES table to support:
-- 1. Explicit Policy Group mapping (removing hardcoded PII/SOX/SOC2 logic)
-- 2. Configurable scoring weights per category
-- 3. Multi-label flags
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE;
USE SCHEMA PUBLIC; -- Adjust if your governance table is in a different schema

-- 1. Add Policy Group Column
-- Used to group categories (e.g., "CREDIT_CARD" -> "SOX") without hardcoding
ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS POLICY_GROUP VARCHAR(50) COMMENT 'High-level policy group (PII, SOX, SOC2, etc.)';

-- 2. Add Scoring Configuration Columns
-- Allows tuning the importance of signals per category
ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS WEIGHT_EMBEDDING FLOAT DEFAULT 0.6 COMMENT 'Weight for semantic embedding score (0.0-1.0)';

ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS WEIGHT_KEYWORD FLOAT DEFAULT 0.25 COMMENT 'Weight for keyword match score (0.0-1.0)';

ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS WEIGHT_PATTERN FLOAT DEFAULT 0.15 COMMENT 'Weight for regex pattern match score (0.0-1.0)';

-- 3. Add Multi-Label Configuration
ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS MULTI_LABEL BOOLEAN DEFAULT TRUE COMMENT 'Whether this category can be detected alongside others';

-- 4. Ensure Detection Threshold Exists
ALTER TABLE SENSITIVITY_CATEGORIES 
ADD COLUMN IF NOT EXISTS DETECTION_THRESHOLD FLOAT DEFAULT 0.45 COMMENT 'Minimum confidence score required for detection';

-- ============================================================================
-- DATA MIGRATION (One-time setup)
-- ============================================================================

-- Populate POLICY_GROUP based on existing naming conventions (Migration only)
-- Future updates should be done directly in this table, not via code heuristics.

UPDATE SENSITIVITY_CATEGORIES 
SET POLICY_GROUP = 'PII' 
WHERE POLICY_GROUP IS NULL 
  AND (UPPER(CATEGORY_NAME) LIKE '%PII%' OR UPPER(CATEGORY_NAME) LIKE '%PERSONAL%' OR UPPER(CATEGORY_NAME) LIKE '%CUSTOMER%');

UPDATE SENSITIVITY_CATEGORIES 
SET POLICY_GROUP = 'SOX' 
WHERE POLICY_GROUP IS NULL 
  AND (UPPER(CATEGORY_NAME) LIKE '%SOX%' OR UPPER(CATEGORY_NAME) LIKE '%FINANCIAL%');

UPDATE SENSITIVITY_CATEGORIES 
SET POLICY_GROUP = 'SOC2' 
WHERE POLICY_GROUP IS NULL 
  AND (UPPER(CATEGORY_NAME) LIKE '%SOC%' OR UPPER(CATEGORY_NAME) LIKE '%SECURITY%');

-- Set default weights if null
UPDATE SENSITIVITY_CATEGORIES SET WEIGHT_EMBEDDING = 0.6 WHERE WEIGHT_EMBEDDING IS NULL;
UPDATE SENSITIVITY_CATEGORIES SET WEIGHT_KEYWORD = 0.25 WHERE WEIGHT_KEYWORD IS NULL;
UPDATE SENSITIVITY_CATEGORIES SET WEIGHT_PATTERN = 0.15 WHERE WEIGHT_PATTERN IS NULL;
UPDATE SENSITIVITY_CATEGORIES SET MULTI_LABEL = TRUE WHERE MULTI_LABEL IS NULL;

-- Verification
SELECT 
    CATEGORY_NAME, 
    POLICY_GROUP, 
    WEIGHT_EMBEDDING, 
    WEIGHT_KEYWORD, 
    WEIGHT_PATTERN,
    DETECTION_THRESHOLD
FROM SENSITIVITY_CATEGORIES;
