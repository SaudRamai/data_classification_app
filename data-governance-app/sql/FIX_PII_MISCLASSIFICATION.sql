-- ============================================================================
-- FIX PII MISCLASSIFICATION ISSUE
-- ============================================================================
-- Problem: PII columns (SSN, TAX_ID, DRIVERS_LICENSE, etc.) are being
--          misclassified as SOC2 instead of PII
--
-- Root Cause: Duplicate keywords exist - the same keyword (e.g. 'social_security')
--             is mapped to BOTH PII and SOC2 categories. When the classifier
--             evaluates these duplicates, SOC2 is winning due to:
--             1. Higher rule weights
--             2. Match type precedence (PARTIAL vs EXACT)
--             3. Alphabetical ordering in conflict resolution
--
-- Solution: DELETE all incorrect PII→SOC2 and PII→SOX keyword mappings,
--          ensuring PII-specific keywords ONLY map to PII categories
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- STEP 1: Backup existing keywords (safety measure)
-- ============================================================================

CREATE TABLE IF NOT EXISTS SENSITIVE_KEYWORDS_BACKUP_20251205 AS
SELECT * FROM SENSITIVE_KEYWORDS;

SELECT '✅ Backed up ' || COUNT(*) || ' keywords' AS backup_status 
FROM SENSITIVE_KEYWORDS_BACKUP_20251205;

-- ============================================================================
-- STEP 2: Delete INCORRECT PII→SOC2 keyword mappings
-- ============================================================================

SELECT '=== Deleting INCORRECT PII→SOC2 mappings ===' AS step;

DELETE FROM SENSITIVE_KEYWORDS
WHERE RULE_ID IN (
    SELECT sk.RULE_ID
    FROM SENSITIVE_KEYWORDS sk
    JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
    WHERE sk.IS_ACTIVE = TRUE
      AND sc.POLICY_GROUP = 'SOC2'  -- These should be PII, not SOC2!
      AND LOWER(sk.KEYWORD_STRING) IN (
          -- National/Government IDs
          'ssn', 'social_security', 'social_security_number',
          'tax', 'tax_id', 'tax_identification', 'tax_identification_number',
          'national', 'national_id', 'national_id_number',
          'drivers', 'drivers_license', 'driver_license', 'drivers_license_number',
          'passport', 'passport_number',
          'voter', 'voter_id', 'voter_id_number',
          'military', 'military_id', 'military_id_number',
          'alien', 'alien_registration', 'alien_registration_number',
          
          -- Biometric PII
          'biometric', 'biometric_hash', 'biometric_data',
          'fingerprint', 'fingerprint_hash',
          'voice', 'voice_print', 'voiceprint',
          'facial', 'face', 'facial_recognition',
          'iris', 'iris_scan',
          'retina', 'retina_scan',
          
          -- Health PII
          'health', 'health_condition', 'medical', 'medical_record',
          'diagnosis', 'prescription', 'patient',
          
          -- Sensitive Personal Attributes
          'ethnicity', 'race', 'racial',
          'religion', 'religious',
          'sexual_orientation', 'gender_identity',
          
          -- Security/Authentication PII
          'two_factor', '2fa', 'mfa', 'multi_factor',
          'two_factor_phone', 'two_factor_email',
          
          -- Location PII
          'gps', 'gps_coordinates', 'geolocation', 'location',
          'last_known_location', 'home_address', 'current_location',
          
          -- Communication PII
          'voip', 'voip_call', 'voip_call_history',
          'call_log', 'call_history',
          
          -- Financial PII (personal level)
          'salary', 'income', 'annual_income', 'compensation'
      )
);

SELECT '✅ Deleted ' || SQL%ROWCOUNT || ' incorrect PII→SOC2 mappings' AS status;

-- ============================================================================
-- STEP 3: Delete INCORRECT PII→SOX keyword mappings
-- ============================================================================

SELECT '=== Deleting INCORRECT PII→SOX mappings ===' AS step;

DELETE FROM SENSITIVE_KEYWORDS
WHERE RULE_ID IN (
    SELECT sk.RULE_ID
    FROM SENSITIVE_KEYWORDS sk
    JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
    WHERE sk.IS_ACTIVE = TRUE
      AND sc.POLICY_GROUP = 'SOX'  -- These should be PII, not SOX!
      AND LOWER(sk.KEYWORD_STRING) IN (
          -- National/Government IDs
          'ssn', 'social_security', 'social_security_number',
          'tax_id', 'tax_identification_number',
          'national_id', 'national_id_number',
          'drivers_license', 'drivers_license_number',
          'passport', 'passport_number',
          'voter_id', 'military_id', 'alien_registration',
          
          -- Biometric
          'biometric', 'fingerprint', 'voice_print',
          
          -- Health
          'health_condition', 'medical_record',
          
          -- Sensitive Attributes
          'ethnicity', 'religion'
      )
);

SELECT '✅ Deleted ' || SQL%ROWCOUNT || ' incorrect PII→SOX mappings' AS status;

-- ============================================================================
-- STEP 4: Verify NO duplicate keywords remain
-- ============================================================================

SELECT '=== Checking for remaining duplicate keywords ===' AS step;

SELECT 
    LOWER(sk.KEYWORD_STRING) AS keyword_lower,
    COUNT(DISTINCT sc.POLICY_GROUP) AS policy_group_count,
    LISTAGG(DISTINCT sc.POLICY_GROUP, ', ') 
        WITHIN GROUP (ORDER BY sc.POLICY_GROUP) AS all_policy_groups,
    LISTAGG(sk.RULE_ID || ':' || sc.POLICY_GROUP || ':' || COALESCE(sk.RULE_WEIGHT, 1.0), ' | ')
        WITHIN GROUP (ORDER BY COALESCE(sk.RULE_WEIGHT, 1.0) DESC) AS conflicting_rules
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND LOWER(sk.KEYWORD_STRING) IN (
      'ssn', 'social_security', 'social_security_number',
      'tax_id', 'tax_identification_number',
      'drivers_license', 'drivers_license_number',
      'fingerprint', 'fingerprint_hash',
      'biometric', 'ethnicity', 'religion'
  )
GROUP BY LOWER(sk.KEYWORD_STRING)
HAVING COUNT(DISTINCT sc.POLICY_GROUP) > 1;

-- Should return NO ROWS if fix was successful

-- ============================================================================
-- STEP 5: Verify PII keywords now ONLY map to PII categories
-- ============================================================================

SELECT '=== Verifying PII keywords now map ONLY to PII ===' AS step;

SELECT 
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    COALESCE(sk.MATCH_TYPE, 'EXACT') AS MATCH_TYPE,
    COALESCE(sk.RULE_WEIGHT, 1.0) AS RULE_WEIGHT,
    sk.PRIORITY_TIER
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND LOWER(sk.KEYWORD_STRING) IN (
      'ssn', 'social_security', 'social_security_number',
      'tax_id', 'tax_identification_number',
      'drivers_license', 'drivers_license_number',
      'fingerprint', 'fingerprint_hash',
      'biometric', 'biometric_hash',
      'ethnicity', 'religion',
      'two_factor', 'gps',
      'voip', 'annual_income'
  )
ORDER BY 
    sk.KEYWORD_STRING,
    sc.POLICY_GROUP,
    COALESCE(sk.RULE_WEIGHT, 1.0) DESC;

-- All rows should show POLICY_GROUP = 'PII'

-- ============================================================================
-- STEP 6: Test classification for specific columns
-- ============================================================================

SELECT '=== Testing classification for TEST_CUSTOMER_MASTER columns ===' AS step;

WITH test_columns AS (
    SELECT column_name FROM (
        VALUES 
            ('SOCIAL_SECURITY_NUMBER'),
            ('TAX_IDENTIFICATION_NUMBER'),
            ('NATIONAL_ID_NUMBER'),
            ('DRIVERS_LICENSE_NUMBER'),
            ('FINGERPRINT_HASH'),
            ('BIOMETRIC_HASH'),
            ('ETHNICITY'),
            ('RELIGION'),
            ('TWO_FACTOR_PHONE'),
            ('GPS_COORDINATES'),
            ('ANNUAL_INCOME')
    ) AS t(column_name)
),
matched_keywords AS (
    SELECT 
        tc.column_name,
        sk.KEYWORD_STRING,
        sc.CATEGORY_NAME,
        sc.POLICY_GROUP,
        COALESCE(sk.MATCH_TYPE, 'EXACT') AS MATCH_TYPE,
        COALESCE(sk.RULE_WEIGHT, 1.0) AS RULE_WEIGHT,
        sk.PRIORITY_TIER,
        ROW_NUMBER() OVER (
            PARTITION BY tc.column_name 
            ORDER BY 
                COALESCE(sk.RULE_WEIGHT, 1.0) DESC,
                CASE WHEN sk.MATCH_TYPE = 'EXACT' THEN 1
                     WHEN sk.MATCH_TYPE = 'PARTIAL' THEN 2
                     WHEN sk.MATCH_TYPE = 'CONTAINS' THEN 3
                     ELSE 4 END,
                LENGTH(sk.KEYWORD_STRING) DESC
        ) AS rank
    FROM test_columns tc
    CROSS JOIN SENSITIVE_KEYWORDS sk
    JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
    WHERE sk.IS_ACTIVE = TRUE
      AND sc.IS_ACTIVE = TRUE
      AND LOWER(tc.column_name) LIKE '%' || LOWER(sk.KEYWORD_STRING) || '%'
)
SELECT 
    column_name,
    KEYWORD_STRING AS matched_keyword,
    CATEGORY_NAME,
    POLICY_GROUP,
    MATCH_TYPE,
    RULE_WEIGHT,
    PRIORITY_TIER,
    CASE 
        WHEN POLICY_GROUP = 'PII' THEN '✅ CORRECT'
        ELSE '❌ STILL WRONG!'
    END AS classification_status
FROM matched_keywords
WHERE rank = 1
ORDER BY column_name;

-- All should show POLICY_GROUP = 'PII' and classification_status = '✅ CORRECT'

-- ============================================================================
-- STEP 7: Ensure PII categories have proper weights
-- ============================================================================

SELECT '=== Verifying PII category configuration ===' AS step;

SELECT 
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP,
    DETECTION_THRESHOLD,
    WEIGHT_KEYWORD,
    WEIGHT_PATTERN,
    WEIGHT_SEMANTIC,
    CONFIDENTIALITY_LEVEL,
    INTEGRITY_LEVEL,
    AVAILABILITY_LEVEL,
    MULTI_LABEL,
    IS_ACTIVE
FROM SENSITIVITY_CATEGORIES
WHERE POLICY_GROUP = 'PII'
  AND IS_ACTIVE = TRUE
ORDER BY CATEGORY_NAME;

-- ============================================================================
SELECT '✅ FIX COMPLETE - PII keywords should now classify correctly!' AS final_status;
-- ============================================================================

-- Next steps:
-- 1. Re-run the classification pipeline on TEST_CUSTOMER_MASTER
-- 2. Verify all PII columns now show POLICY_GROUP = 'PII'
-- 3. Check that SOC2 and SOX classifications are still working for their respective columns
