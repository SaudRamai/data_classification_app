-- ============================================================================
-- COMPREHENSIVE FIX: Ensure SOCIAL_SECURITY_NUMBER is PII, not SOC2
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- STEP 1: Identify the Problem
-- ============================================================================

SELECT '🔍 STEP 1: Current Status of SOCIAL_SECURITY_NUMBER' AS STATUS;

SELECT 
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME AS CURRENT_CATEGORY,
    sc.POLICY_GROUP AS CURRENT_POLICY_GROUP,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.IS_ACTIVE,
    sk.KEYWORD_ID,
    sk.CATEGORY_ID
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE LOWER(sk.KEYWORD_STRING) = 'social_security_number'
ORDER BY sk.CREATED_AT;

-- ============================================================================
-- STEP 2: Get Correct Category IDs
-- ============================================================================

SELECT '✅ STEP 2: Get PII and SOC2 Category IDs' AS STATUS;

-- PII Category ID (what we SHOULD use)
SELECT 
    'PII' AS CATEGORY_TYPE,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP
FROM SENSITIVITY_CATEGORIES
WHERE CATEGORY_NAME = 'PII';

-- SOC2 Category ID (what we're currently using - WRONG)
SELECT 
    'SOC2' AS CATEGORY_TYPE,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP
FROM SENSITIVITY_CATEGORIES
WHERE CATEGORY_NAME = 'SOC2';

-- ============================================================================
-- STEP 3: Delete ALL existing SOCIAL_SECURITY_NUMBER entries (clean slate)
-- ============================================================================

SELECT '🗑️ STEP 3: Deleting ALL existing SOCIAL_SECURITY_NUMBER entries' AS STATUS;

DELETE FROM SENSITIVE_KEYWORDS
WHERE LOWER(KEYWORD_STRING) = 'social_security_number';

-- Verify deletion
SELECT 
    '✅ Verification: SOCIAL_SECURITY_NUMBER entries after deletion',
    COUNT(*) AS REMAINING_COUNT
FROM SENSITIVE_KEYWORDS
WHERE LOWER(KEYWORD_STRING) = 'social_security_number';

-- ============================================================================
-- STEP 4: Insert SOCIAL_SECURITY_NUMBER with CORRECT PII Category ID
-- ============================================================================

SELECT '➕ STEP 4: Inserting SOCIAL_SECURITY_NUMBER with PII category' AS STATUS;

INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID,
    CATEGORY_ID,
    KEYWORD_STRING,
    MATCH_TYPE,
    SENSITIVITY_WEIGHT,
    IS_ACTIVE,
    CREATED_BY,
    CREATED_AT,
    VERSION_NUMBER
)
SELECT
    UUID_STRING() AS KEYWORD_ID,
    sc.CATEGORY_ID,
    'social_security_number' AS KEYWORD_STRING,
    'CONTAINS' AS MATCH_TYPE,
    0.95 AS SENSITIVITY_WEIGHT,  -- Very high weight for critical PII
    TRUE AS IS_ACTIVE,
    CURRENT_USER() AS CREATED_BY,
    CURRENT_TIMESTAMP() AS CREATED_AT,
    1 AS VERSION_NUMBER
FROM SENSITIVITY_CATEGORIES sc
WHERE sc.CATEGORY_NAME = 'PII';

-- ============================================================================
-- STEP 5: Insert Related SSN Keywords (all variations)
-- ============================================================================

SELECT '➕ STEP 5: Inserting SSN variations' AS STATUS;

-- SSN
INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, 
    SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER
)
SELECT
    UUID_STRING(), sc.CATEGORY_ID, 'ssn', 'CONTAINS',
    0.95, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
FROM SENSITIVITY_CATEGORIES sc
WHERE sc.CATEGORY_NAME = 'PII'
  AND NOT EXISTS (
      SELECT 1 FROM SENSITIVE_KEYWORDS sk2 
      WHERE LOWER(sk2.KEYWORD_STRING) = 'ssn' 
        AND sk2.CATEGORY_ID = sc.CATEGORY_ID
  );

-- SOCIAL_SECURITY
INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, 
    SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER
)
SELECT
    UUID_STRING(), sc.CATEGORY_ID, 'social_security', 'CONTAINS',
    0.95, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
FROM SENSITIVITY_CATEGORIES sc
WHERE sc.CATEGORY_NAME = 'PII'
  AND NOT EXISTS (
      SELECT 1 FROM SENSITIVE_KEYWORDS sk2 
      WHERE LOWER(sk2.KEYWORD_STRING) = 'social_security' 
        AND sk2.CATEGORY_ID = sc.CATEGORY_ID
  );

-- SOCIALSECURITY (no underscore)
INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, 
    SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER
)
SELECT
    UUID_STRING(), sc.CATEGORY_ID, 'socialsecurity', 'CONTAINS',
    0.95, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
FROM SENSITIVITY_CATEGORIES sc
WHERE sc.CATEGORY_NAME = 'PII'
  AND NOT EXISTS (
      SELECT 1 FROM SENSITIVE_KEYWORDS sk2 
      WHERE LOWER(sk2.KEYWORD_STRING) = 'socialsecurity' 
        AND sk2.CATEGORY_ID = sc.CATEGORY_ID
  );

-- SOCIALSECURITYNUMBER (no underscores)
INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, 
    SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER
)
SELECT
    UUID_STRING(), sc.CATEGORY_ID, 'socialsecuritynumber', 'CONTAINS',
    0.95, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
FROM SENSITIVITY_CATEGORIES sc
WHERE sc.CATEGORY_NAME = 'PII'
  AND NOT EXISTS (
      SELECT 1 FROM SENSITIVE_KEYWORDS sk2 
      WHERE LOWER(sk2.KEYWORD_STRING) = 'socialsecuritynumber' 
        AND sk2.CATEGORY_ID = sc.CATEGORY_ID
  );

-- ============================================================================
-- STEP 6: Verify the Fix
-- ============================================================================

SELECT '🎉 STEP 6: Final Verification' AS STATUS;

SELECT 
    '✅ All SSN-related keywords now mapped to PII' AS VERIFICATION,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.KEYWORD_STRING,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT,
    sk.IS_ACTIVE
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE LOWER(sk.KEYWORD_STRING) IN (
    'ssn', 
    'social_security', 
    'social_security_number',
    'socialsecurity',
    'socialsecuritynumber'
)
ORDER BY sc.CATEGORY_NAME, sk.KEYWORD_STRING;

-- ============================================================================
-- STEP 7: Audit Log
-- ============================================================================

INSERT INTO CLASSIFICATION_AUDIT (
    ID, 
    RESOURCE_ID, 
    ACTION, 
    DETAILS, 
    CREATED_AT
)
VALUES (
    UUID_STRING(),
    'SOCIAL_SECURITY_NUMBER',
    'FIX_CATEGORY_MAPPING',
    'Fixed SOCIAL_SECURITY_NUMBER keyword mapping from SOC2 to PII. Deleted all existing entries and re-created with correct PII category_id.',
    CURRENT_TIMESTAMP()
);

SELECT '✅ COMPLETE: SOCIAL_SECURITY_NUMBER is now correctly mapped to PII!' AS FINAL_STATUS;

-- ============================================================================
-- IMPORTANT: After running this script, you MUST:
-- 1. Restart the Streamlit app to reload the governance rules
-- 2. OR call the pipeline's _load_metadata_driven_categories() method
-- 3. OR run the classification again to pick up the new mappings
-- ============================================================================
