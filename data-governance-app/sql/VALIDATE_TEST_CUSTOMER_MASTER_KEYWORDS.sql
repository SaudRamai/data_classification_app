-- ============================================================================
-- VALIDATE TEST_CUSTOMER_MASTER COLUMN CLASSIFICATIONS
-- ============================================================================
-- This script checks the governance data to understand why certain columns
-- are being misclassified
--
-- Expected correct classifications:
--   SOCIAL_SECURITY_NUMBER → PII (not SOC2!)
--   TAX_IDENTIFICATION_NUMBER → PII (not SOC2!)
--   DRIVERS_LICENSE_NUMBER → PII (not SOC2!)
--   FINGERPRINT_HASH → PII (not SOC2!)
--   TWO_FACTOR_PHONE → PII (not SOC2!)
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- CHECK 1: What keywords match each problematic column?
-- ============================================================================

SELECT '=== KEYWORD MATCHES FOR PROBLEMATIC COLUMNS ===' AS check_section;

WITH test_columns AS (
    SELECT column_name FROM (
        VALUES 
            ('SOCIAL_SECURITY_NUMBER'),
            ('TAX_IDENTIFICATION_NUMBER'),
            ('NATIONAL_ID_NUMBER'),
            ('DRIVERS_LICENSE_NUMBER'),
            ('ALIEN_REGISTRATION_NUMBER'),
            ('BIOMETRIC_HASH'),
            ('FINGERPRINT_HASH'),
            ('ETHNICITY'),
            ('RELIGION'),
            ('TWO_FACTOR_PHONE')
    ) AS t(column_name)
)
SELECT 
    tc.column_name,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.MATCH_TYPE,
    sk.RULE_WEIGHT,
    sk.PRIORITY_TIER,
    CASE 
        WHEN LOWER(tc.column_name) LIKE '%' || LOWER(sk.KEYWORD_STRING) || '%' THEN '✅ Match'
        WHEN sk.MATCH_TYPE = 'REGEX' THEN '? Regex (check pattern)'
        ELSE '❌ No match'
    END AS match_status,
    sk.RULE_ID
FROM test_columns tc
CROSS JOIN SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc
  ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND (
      LOWER(tc.column_name) LIKE '%' || LOWER(sk.KEYWORD_STRING) || '%'
      OR sk.MATCH_TYPE = 'REGEX'
  )
ORDER BY 
    tc.column_name,
    sk.RULE_WEIGHT DESC,
    sc.POLICY_GROUP;

-- ============================================================================
-- CHECK 2: For each column, show ALL matching keywords with their categories
-- ============================================================================

SELECT '=== DETAILED ANALYSIS: SOCIAL_SECURITY_NUMBER ===' AS check_section;

SELECT 
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.MATCH_TYPE,
    sk.RULE_WEIGHT,
    sk.PRIORITY_TIER,
    sk.RULE_ID
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND LOWER(sk.KEYWORD_STRING) IN (
      'ssn', 
      'social', 
      'social_security', 
      'social_security_number',
      'security',
      'number'
  )
ORDER BY 
    sk.KEYWORD_STRING,
    sk.RULE_WEIGHT DESC,
    sc.POLICY_GROUP;

-- ============================================================================
SELECT '=== DETAILED ANALYSIS: TAX_IDENTIFICATION_NUMBER ===' AS check_section;

SELECT 
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.MATCH_TYPE,
    sk.RULE_WEIGHT,
    sk.PRIORITY_TIER,
    sk.RULE_ID
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND LOWER(sk.KEYWORD_STRING) IN (
      'tax',
      'tax_id',
      'tax_identification',
      'tax_identification_number',
      'identification',
      'number'
  )
ORDER BY 
    sk.KEYWORD_STRING,
    sk.RULE_WEIGHT DESC,
    sc.POLICY_GROUP;

-- ============================================================================
SELECT '=== DETAILED ANALYSIS: DRIVERS_LICENSE_NUMBER ===' AS check_section;

SELECT 
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.MATCH_TYPE,
    sk.RULE_WEIGHT,
    sk.PRIORITY_TIER,
    sk.RULE_ID
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND LOWER(sk.KEYWORD_STRING) IN (
      'driver',
      'drivers',
      'drivers_license',
      'driver_license',
      'drivers_license_number',
      'driver_license_number',
      'license',
      'license_number'
  )
ORDER BY 
    sk.KEYWORD_STRING,
    sk.RULE_WEIGHT DESC,
    sc.POLICY_GROUP;

-- ============================================================================
SELECT '=== DETAILED ANALYSIS: FINGERPRINT_HASH ===' AS check_section;

SELECT 
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.MATCH_TYPE,
    sk.RULE_WEIGHT,
    sk.PRIORITY_TIER,
    sk.RULE_ID
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND LOWER(sk.KEYWORD_STRING) IN (
      'fingerprint',
      'fingerprint_hash',
      'biometric',
      'biometric_hash',
      'hash'
  )
ORDER BY 
    sk.KEYWORD_STRING,
    sk.RULE_WEIGHT DESC,
    sc.POLICY_GROUP;

-- ============================================================================
SELECT '=== DETAILED ANALYSIS: TWO_FACTOR_PHONE ===' AS check_section;

SELECT 
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.MATCH_TYPE,
    sk.RULE_WEIGHT,
    sk.PRIORITY_TIER,
    sk.RULE_ID
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND LOWER(sk.KEYWORD_STRING) IN (
      'phone',
      'phone_number',
      'two_factor',
      'two_factor_phone',
      '2fa',
      'mfa',
      'factor'
  )
ORDER BY 
    sk.KEYWORD_STRING,
    sk.RULE_WEIGHT DESC,
    sc.POLICY_GROUP;

-- ============================================================================
-- CHECK 3: Identify the ROOT CAUSE - duplicate keywords with conflicting categories
-- ============================================================================

SELECT '=== ROOT CAUSE: DUPLICATE KEYWORDS ===' AS check_section;

SELECT 
    LOWER(sk.KEYWORD_STRING) AS keyword_lower,
    COUNT(DISTINCT sc.POLICY_GROUP) AS policy_group_count,
    LISTAGG(DISTINCT sc.POLICY_GROUP, ', ') 
        WITHIN GROUP (ORDER BY sc.POLICY_GROUP) AS all_policy_groups,
    LISTAGG(DISTINCT sc.CATEGORY_NAME, ', ') 
        WITHIN GROUP (ORDER BY sc.CATEGORY_NAME) AS all_categories,
    LISTAGG(sk.RULE_ID || ':' || sc.POLICY_GROUP || ':' || sk.RULE_WEIGHT, ' | ')
        WITHIN GROUP (ORDER BY sk.RULE_WEIGHT DESC) AS conflicting_rules
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND LOWER(sk.KEYWORD_STRING) IN (
      -- Critical PII keywords that should NEVER be SOC2
      'ssn', 'social_security', 'social_security_number',
      'tax_id', 'tax_identification_number',
      'drivers_license', 'driver_license', 'drivers_license_number',
      'fingerprint', 'fingerprint_hash',
      'biometric', 'biometric_hash',
      'phone', 'phone_number'
  )
GROUP BY LOWER(sk.KEYWORD_STRING)
HAVING COUNT(DISTINCT sc.POLICY_GROUP) > 1
ORDER BY policy_group_count DESC, keyword_lower;

-- ============================================================================
-- CHECK 4: Show the SPECIFIC INCORRECT RULE_IDs to delete
-- ============================================================================

SELECT '=== RULE_IDs TO DELETE (Incorrect PII→SOC2 mappings) ===' AS check_section;

SELECT 
    sk.RULE_ID,
    sk.KEYWORD_STRING,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.RULE_WEIGHT,
    sk.CREATED_BY,
    sk.CREATED_AT,
    'DELETE FROM SENSITIVE_KEYWORDS WHERE RULE_ID = ''' || sk.RULE_ID || ''';' AS delete_statement
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND sc.POLICY_GROUP IN ('SOC2', 'SOX')  -- These should be PII, not SOC2/SOX
  AND LOWER(sk.KEYWORD_STRING) IN (
      'ssn', 'social_security', 'social_security_number',
      'tax_id', 'tax_identification', 'tax_identification_number',
      'national_id', 'national_id_number',
      'drivers_license', 'driver_license', 'drivers_license_number',
      'passport', 'passport_number',
      'alien_registration', 'alien_registration_number',
      'biometric', 'biometric_hash',
      'fingerprint', 'fingerprint_hash',
      'ethnicity', 'race', 'religion'
  )
ORDER BY sc.POLICY_GROUP, sk.KEYWORD_STRING;

-- ============================================================================
-- CHECK 5: Verify what's LEFT after cleanup
-- ============================================================================

SELECT '=== EXPECTED STATE AFTER CLEANUP ===' AS check_section;

SELECT 
    LOWER(sk.KEYWORD_STRING) AS keyword_lower,
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    sk.RULE_WEIGHT,
    sk.PRIORITY_TIER,
    COUNT(*) OVER (PARTITION BY LOWER(sk.KEYWORD_STRING)) AS remaining_mappings
FROM SENSITIVE_KEYWORDS sk
JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
WHERE sk.IS_ACTIVE = TRUE
  AND LOWER(sk.KEYWORD_STRING) IN (
      'ssn', 'social_security', 'social_security_number',
      'tax_id', 'tax_identification_number',
      'drivers_license', 'drivers_license_number',
      'fingerprint', 'fingerprint_hash'
  )
  AND sc.POLICY_GROUP = 'PII'  -- Only show PII mappings (correct state)
ORDER BY keyword_lower;

SELECT '✅ Validation complete. Review results above.' AS status;
