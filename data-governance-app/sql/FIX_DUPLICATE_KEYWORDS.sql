-- ============================================================================
-- FIX DUPLICATE KEYWORD MAPPINGS
-- ============================================================================
-- This script identifies and removes incorrect duplicate keyword mappings
-- that are causing misclassification (e.g., SSN classified as SOC2 instead of PII)
--
-- Author: Data Governance Team
-- Date: 2025-12-05
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- STEP 1: IDENTIFY ALL DUPLICATE KEYWORDS
-- ============================================================================

SELECT 
    '=== DUPLICATE KEYWORD ANALYSIS ===' AS analysis_step;

-- Find keywords that map to multiple categories
SELECT 
    LOWER(sk.KEYWORD_STRING) AS keyword_lower,
    COUNT(DISTINCT sc.CATEGORY_NAME) AS category_count,
    COUNT(*) AS total_mappings,
    LISTAGG(DISTINCT sc.CATEGORY_NAME, ', ') 
        WITHIN GROUP (ORDER BY sc.CATEGORY_NAME) AS all_categories,
    LISTAGG(DISTINCT sc.POLICY_GROUP, ', ') 
        WITHIN GROUP (ORDER BY sc.POLICY_GROUP) AS all_policy_groups,
    LISTAGG(sk.RULE_ID || ':' || sc.CATEGORY_NAME, ' | ') 
        WITHIN GROUP (ORDER BY sc.CATEGORY_NAME) AS rule_details
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc
  ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
GROUP BY LOWER(sk.KEYWORD_STRING)
HAVING COUNT(DISTINCT sc.CATEGORY_NAME) > 1
ORDER BY category_count DESC, keyword_lower;

-- ============================================================================
-- STEP 2: IDENTIFY CRITICAL PII KEYWORDS WITH INCORRECT MAPPINGS
-- ============================================================================

SELECT 
    '=== CRITICAL PII KEYWORDS WITH INCORRECT SOC2/SOX MAPPINGS ===' AS analysis_step;

-- Find critical PII keywords that are incorrectly mapped to SOC2 or SOX
WITH critical_pii_keywords AS (
    SELECT keyword FROM (
        VALUES 
            -- Social Security & Tax IDs
            ('ssn'),
            ('social_security'),
            ('social_security_number'),
            ('social_security_num'),
            ('tax_id'),
            ('tax_identification'),
            ('tax_identification_number'),
            ('ein'),
            ('itin'),
            -- National IDs & Government IDs
            ('national_id'),
            ('national_id_number'),
            ('national_number'),
            ('national_identification'),
            ('passport'),
            ('passport_number'),
            ('drivers_license'),
            ('driver_license'),
            ('drivers_license_number'),
            ('driver_license_number'),
            ('license_number'),
            ('voter_id'),
            ('voter_registration'),
            ('military_id'),
            ('alien_registration'),
            ('alien_registration_number'),
            ('alien_number'),
            -- Biometric Data
            ('biometric'),
            ('biometric_hash'),
            ('fingerprint'),
            ('fingerprint_hash'),
            ('voice_print'),
            ('voiceprint'),
            ('retina'),
            ('iris'),
            ('facial'),
            ('facial_recognition'),
            -- Sensitive Personal Data
            ('ethnicity'),
            ('race'),
            ('religion'),
            ('religious'),
            ('medical_record'),
            ('patient_id'),
            ('health_record'),
            ('health_condition'),
            ('disability'),
            ('disability_status')
    ) AS t(keyword)
)
SELECT 
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.RULE_ID,
    sk.MATCH_TYPE,
    sk.RULE_WEIGHT,
    CASE 
        WHEN sc.POLICY_GROUP != 'PII' THEN '❌ INCORRECT - Should be PII'
        ELSE '✅ CORRECT'
    END AS validation_status
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc
  ON sk.CATEGORY_ID = sc.CATEGORY_ID
JOIN critical_pii_keywords cpk
  ON LOWER(sk.KEYWORD_STRING) = LOWER(cpk.keyword)
WHERE sk.IS_ACTIVE = TRUE
ORDER BY 
    validation_status DESC,
    sk.KEYWORD_STRING,
    sc.POLICY_GROUP;

-- ============================================================================
-- STEP 3: DELETE INCORRECT MAPPINGS
-- ============================================================================

-- IMPORTANT: Review the above queries before running these DELETE statements!
-- Uncomment to execute

/*
SELECT 
    '=== DELETING INCORRECT MAPPINGS ===' AS action_step;

-- Delete specific known incorrect mappings
DELETE FROM SENSITIVE_KEYWORDS
WHERE RULE_ID IN (
    -- SOCIAL_SECURITY_NUMBER incorrectly mapped to SOC2
    'e2576be4-a464-44a3-a9d1-85e78490f783',
    
    -- SOCIAL_SECURITY_NUMBER incorrectly mapped to SOX
    'f6743997-ee18-449b-adf0-61ae5747a102'
);

SELECT '✅ Deleted ' || SQL%ROWCOUNT || ' incorrect social_security_number mappings' AS status;

-- Delete ALL keywords from critical_pii list that are mapped to SOC2
DELETE FROM SENSITIVE_KEYWORDS
WHERE RULE_ID IN (
    SELECT sk.RULE_ID
    FROM SENSITIVE_KEYWORDS sk
    JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
    WHERE sk.IS_ACTIVE = TRUE
      AND sc.POLICY_GROUP = 'SOC2'
      AND LOWER(sk.KEYWORD_STRING) IN (
            'ssn', 'social_security', 'social_security_number', 'social_security_num',
            'tax_id', 'tax_identification', 'tax_identification_number',
            'national_id', 'national_id_number', 'drivers_license', 'driver_license',
            'drivers_license_number', 'driver_license_number', 'license_number',
            'passport', 'passport_number', 'alien_registration', 'alien_registration_number',
            'biometric', 'biometric_hash', 'fingerprint', 'fingerprint_hash',
            'ethnicity', 'race', 'religion', 'religious',
            'medical_record', 'patient_id', 'health_record', 'disability'
        )
);

SELECT '✅ Deleted ' || SQL%ROWCOUNT || ' critical PII keywords incorrectly mapped to SOC2' AS status;

-- Delete ALL keywords from critical_pii list that are mapped to SOX
DELETE FROM SENSITIVE_KEYWORDS
WHERE RULE_ID IN (
    SELECT sk.RULE_ID
    FROM SENSITIVE_KEYWORDS sk
    JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
    WHERE sk.IS_ACTIVE = TRUE
      AND sc.POLICY_GROUP = 'SOX'
      AND LOWER(sk.KEYWORD_STRING) IN (
            'ssn', 'social_security', 'social_security_number', 'social_security_num',
            'national_id', 'national_id_number', 'drivers_license', 'driver_license',
            'drivers_license_number', 'driver_license_number', 'license_number',
            'passport', 'passport_number', 'alien_registration', 'alien_registration_number',
            'biometric', 'biometric_hash', 'fingerprint', 'fingerprint_hash',
            'ethnicity', 'race', 'religion', 'religious',
            'medical_record', 'patient_id', 'health_record', 'disability'
        )
);

SELECT '✅ Deleted ' || SQL%ROWCOUNT || ' critical PII keywords incorrectly mapped to SOX' AS status;
*/

-- ============================================================================
-- STEP 4: VERIFY CLEANUP
-- ============================================================================

SELECT 
    '=== VERIFICATION: REMAINING DUPLICATE KEYWORDS ===' AS analysis_step;

-- Check if any duplicates remain
SELECT 
    LOWER(sk.KEYWORD_STRING) AS keyword_lower,
    COUNT(DISTINCT sc.CATEGORY_NAME) AS category_count,
    LISTAGG(DISTINCT sc.CATEGORY_NAME, ', ') 
        WITHIN GROUP (ORDER BY sc.CATEGORY_NAME) AS remaining_categories
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc
  ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
GROUP BY LOWER(sk.KEYWORD_STRING)
HAVING COUNT(DISTINCT sc.CATEGORY_NAME) > 1
ORDER BY category_count DESC, keyword_lower;

-- ============================================================================
-- STEP 5: VERIFY CRITICAL PII KEYWORDS ARE CORRECTLY MAPPED TO PII ONLY
-- ============================================================================

SELECT 
    '=== VERIFICATION: CRITICAL PII KEYWORDS MAPPING ===' AS analysis_step;

WITH critical_pii_keywords AS (
    SELECT keyword FROM (
        VALUES 
            ('ssn'), ('social_security'), ('social_security_number'),
            ('tax_id'), ('tax_identification_number'),
            ('national_id'), ('national_id_number'),
            ('drivers_license'), ('driver_license'), ('drivers_license_number'),
            ('passport'), ('passport_number'),
            ('alien_registration'), ('alien_registration_number'),
            ('biometric'), ('biometric_hash'),
            ('fingerprint'), ('fingerprint_hash'),
            ('ethnicity'), ('race'), ('religion')
    ) AS t(keyword)
)
SELECT 
    cpk.keyword,
    COALESCE(sc.CATEGORY_NAME, 'NOT MAPPED') AS category,
    COALESCE(sc.POLICY_GROUP, 'N/A') AS policy_group,
    CASE 
        WHEN sc.POLICY_GROUP IS NULL THEN '⚠️ MISSING MAPPING'
        WHEN sc.POLICY_GROUP = 'PII' THEN '✅ CORRECT'
        ELSE '❌ INCORRECT - Should be PII, not ' || sc.POLICY_GROUP
    END AS validation_status
FROM critical_pii_keywords cpk
LEFT JOIN SENSITIVE_KEYWORDS sk
  ON LOWER(sk.KEYWORD_STRING) = LOWER(cpk.keyword)
  AND sk.IS_ACTIVE = TRUE
LEFT JOIN SENSITIVITY_CATEGORIES sc
  ON sk.CATEGORY_ID = sc.CATEGORY_ID
ORDER BY validation_status DESC, cpk.keyword;

-- ============================================================================
-- STEP 6: SUMMARY REPORT
-- ============================================================================

SELECT 
    '=== SUMMARY REPORT ===' AS report_section;

-- Count keywords by policy group
SELECT 
    sc.POLICY_GROUP,
    COUNT(DISTINCT sk.KEYWORD_STRING) AS unique_keywords,
    COUNT(*) AS total_mappings
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc
  ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
GROUP BY sc.POLICY_GROUP
ORDER BY sc.POLICY_GROUP;

-- ============================================================================
-- OPTIONAL: ADD MISSING CRITICAL PII KEYWORDS
-- ============================================================================

/*
-- If any critical PII keywords are missing, add them
-- First, get the PII category ID
SET pii_category_id = (
    SELECT CATEGORY_ID 
    FROM SENSITIVITY_CATEGORIES 
    WHERE UPPER(POLICY_GROUP) = 'PII' 
    LIMIT 1
);

-- Then insert missing keywords (example)
INSERT INTO SENSITIVE_KEYWORDS (
    RULE_ID,
    CATEGORY_ID,
    KEYWORD_STRING,
    MATCH_TYPE,
    RULE_WEIGHT,
    IS_ACTIVE,
    CREATED_BY,
    CREATED_AT,
    PRIORITY_TIER
)
VALUES
    (UUID_STRING(), $pii_category_id, 'tax_identification_number', 'EXACT', 0.95, TRUE, 'SYSTEM', CURRENT_TIMESTAMP(), 'PRIORITY_1'),
    (UUID_STRING(), $pii_category_id, 'drivers_license_number', 'EXACT', 0.95, TRUE, 'SYSTEM', CURRENT_TIMESTAMP(), 'PRIORITY_1'),
    (UUID_STRING(), $pii_category_id, 'alien_registration_number', 'EXACT', 0.95, TRUE, 'SYSTEM', CURRENT_TIMESTAMP(), 'PRIORITY_1');
*/

SELECT 'Script execution complete. Review results above.' AS status;
