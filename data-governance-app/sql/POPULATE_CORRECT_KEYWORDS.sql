-- ============================================================================
-- POPULATE CORRECT KEYWORDS FOR ACCURATE PII/SOX/SOC2 DETECTION
-- ============================================================================
-- This script ensures all keywords from your correct detection list are present
-- in the governance tables with proper categorization
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- Get Category IDs
SET PII_CAT_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE UPPER(CATEGORY_NAME) = 'PII' LIMIT 1);
SET SOX_CAT_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE UPPER(CATEGORY_NAME) = 'SOX' LIMIT 1);
SET SOC2_CAT_ID = (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE UPPER(CATEGORY_NAME) = 'SOC2' LIMIT 1);

-- ============================================================================
-- PII KEYWORDS (High Sensitivity - Exact Matches)
-- ============================================================================

-- Government IDs and Personal Identifiers
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $PII_CAT_ID, keyword, 'CONTAINS', 0.95, TRUE, CURRENT_USER()
FROM (
    SELECT 'social_security_number' AS keyword UNION ALL
    SELECT 'ssn' UNION ALL
    SELECT 'tax_identification_number' UNION ALL
    SELECT 'tax_id' UNION ALL
    SELECT 'national_id_number' UNION ALL
    SELECT 'national_id' UNION ALL
    SELECT 'drivers_license_number' UNION ALL
    SELECT 'driver_license' UNION ALL
    SELECT 'voter_id_number' UNION ALL
    SELECT 'voter_id' UNION ALL
    SELECT 'military_id_number' UNION ALL
    SELECT 'military_id' UNION ALL
    SELECT 'alien_registration_number' UNION ALL
    SELECT 'passport_number' UNION ALL
    SELECT 'passport'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $PII_CAT_ID
);

-- Biometric Data
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $PII_CAT_ID, keyword, 'CONTAINS', 0.95, TRUE, CURRENT_USER()
FROM (
    SELECT 'biometric_hash' AS keyword UNION ALL
    SELECT 'biometric' UNION ALL
    SELECT 'voice_print_id' UNION ALL
    SELECT 'voice_print' UNION ALL
    SELECT 'voiceprint' UNION ALL
    SELECT 'fingerprint_hash' UNION ALL
    SELECT 'fingerprint' UNION ALL
    SELECT 'facial_recognition' UNION ALL
    SELECT 'retina_scan'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $PII_CAT_ID
);

-- Sensitive Personal Attributes
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $PII_CAT_ID, keyword, 'CONTAINS', 0.95, TRUE, CURRENT_USER()
FROM (
    SELECT 'health_condition' AS keyword UNION ALL
    SELECT 'medical_condition' UNION ALL
    SELECT 'disability_status' UNION ALL
    SELECT 'ethnicity' UNION ALL
    SELECT 'race' UNION ALL
    SELECT 'religion' UNION ALL
    SELECT 'religious_affiliation'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $PII_CAT_ID
);

-- Communication and Contact Info
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $PII_CAT_ID, keyword, 'CONTAINS', 0.90, TRUE, CURRENT_USER()
FROM (
    SELECT 'two_factor_phone' AS keyword UNION ALL
    SELECT 'two_factor_email' UNION ALL
    SELECT 'phone_number' UNION ALL
    SELECT 'mobile_number' UNION ALL
    SELECT 'email_address' UNION ALL
    SELECT 'email'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $PII_CAT_ID
);

-- Location and Tracking Data
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $PII_CAT_ID, keyword, 'CONTAINS', 0.95, TRUE, CURRENT_USER()
FROM (
    SELECT 'gps_coordinates' AS keyword UNION ALL
    SELECT 'latitude' UNION ALL
    SELECT 'longitude' UNION ALL
    SELECT 'last_known_location' UNION ALL
    SELECT 'location_history' UNION ALL
    SELECT 'geolocation'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $PII_CAT_ID
);

-- Communication Records
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $PII_CAT_ID, keyword, 'CONTAINS', 0.90, TRUE, CURRENT_USER()
FROM (
    SELECT 'voip_call_records' AS keyword UNION ALL
    SELECT 'call_history' UNION ALL
    SELECT 'video_call_signature' UNION ALL
    SELECT 'chat_history'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $PII_CAT_ID
);

-- Personal Names and Identity
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $PII_CAT_ID, keyword, 'CONTAINS', 0.85, TRUE, CURRENT_USER()
FROM (
    SELECT 'credit_card_holder_name' AS keyword UNION ALL
    SELECT 'cardholder_name' UNION ALL
    SELECT 'account_holder_name' UNION ALL
    SELECT 'full_name' UNION ALL
    SELECT 'first_name' UNION ALL
    SELECT 'last_name' UNION ALL
    SELECT 'date_of_birth' UNION ALL
    SELECT 'birth_date'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $PII_CAT_ID
);

-- Financial PII (also in SOX but PII takes precedence for personal data)
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $PII_CAT_ID, keyword, 'CONTAINS', 0.85, TRUE, CURRENT_USER()
FROM (
    SELECT 'annual_income' AS keyword UNION ALL
    SELECT 'salary' UNION ALL
    SELECT 'income' UNION ALL
    SELECT 'business_registration_number' UNION ALL
    SELECT 'company_registration'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $PII_CAT_ID
);

-- ============================================================================
-- SOX KEYWORDS (Financial Data - Critical Sensitivity)
-- ============================================================================

-- Banking Information
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $SOX_CAT_ID, keyword, 'CONTAINS', 0.98, TRUE, CURRENT_USER()
FROM (
    SELECT 'bank_account_number' AS keyword UNION ALL
    SELECT 'account_number' UNION ALL
    SELECT 'bank_routing_number' UNION ALL
    SELECT 'routing_number' UNION ALL
    SELECT 'routing' UNION ALL
    SELECT 'bank_iban' UNION ALL
    SELECT 'iban' UNION ALL
    SELECT 'bank_swift_code' UNION ALL
    SELECT 'swift_code' UNION ALL
    SELECT 'swift' UNION ALL
    SELECT 'bic_code'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $SOX_CAT_ID
);

-- Credit Card Information
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $SOX_CAT_ID, keyword, 'CONTAINS', 0.98, TRUE, CURRENT_USER()
FROM (
    SELECT 'credit_card_number' AS keyword UNION ALL
    SELECT 'credit_card' UNION ALL
    SELECT 'card_number' UNION ALL
    SELECT 'credit_card_expiry_date' UNION ALL
    SELECT 'card_expiry' UNION ALL
    SELECT 'expiry_date' UNION ALL
    SELECT 'cvv' UNION ALL
    SELECT 'cvv2' UNION ALL
    SELECT 'card_verification'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $SOX_CAT_ID
);

-- Financial History and Transactions
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $SOX_CAT_ID, keyword, 'CONTAINS', 0.90, TRUE, CURRENT_USER()
FROM (
    SELECT 'payment_history' AS keyword UNION ALL
    SELECT 'transaction_history' UNION ALL
    SELECT 'payment_record' UNION ALL
    SELECT 'financial_record' UNION ALL
    SELECT 'tax_return' UNION ALL
    SELECT 'invoice_amount' UNION ALL
    SELECT 'revenue'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $SOX_CAT_ID
);

-- ============================================================================
-- SOC2 KEYWORDS (Security and Access Control - High Sensitivity)
-- ============================================================================

-- Authentication Credentials
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $SOC2_CAT_ID, keyword, 'CONTAINS', 0.98, TRUE, CURRENT_USER()
FROM (
    SELECT 'user_password_hash' AS keyword UNION ALL
    SELECT 'password_hash' UNION ALL
    SELECT 'password' UNION ALL
    SELECT 'passwd' UNION ALL
    SELECT 'pwd' UNION ALL
    SELECT 'user_password'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $SOC2_CAT_ID
);

-- API and Integration Secrets
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $SOC2_CAT_ID, keyword, 'CONTAINS', 0.98, TRUE, CURRENT_USER()
FROM (
    SELECT 'api_key' AS keyword UNION ALL
    SELECT 'api_secret' UNION ALL
    SELECT 'api_token' UNION ALL
    SELECT 'client_secret' UNION ALL
    SELECT 'client_id' UNION ALL
    SELECT 'service_account_key'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $SOC2_CAT_ID
);

-- OAuth and Session Tokens
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $SOC2_CAT_ID, keyword, 'CONTAINS', 0.95, TRUE, CURRENT_USER()
FROM (
    SELECT 'oauth_token' AS keyword UNION ALL
    SELECT 'oauth_refresh_token' UNION ALL
    SELECT 'refresh_token' UNION ALL
    SELECT 'access_token' UNION ALL
    SELECT 'bearer_token' UNION ALL
    SELECT 'session_token' UNION ALL
    SELECT 'jwt_token'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $SOC2_CAT_ID
);

-- Device and Login Tracking
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $SOC2_CAT_ID, keyword, 'CONTAINS', 0.90, TRUE, CURRENT_USER()
FROM (
    SELECT 'login_device_id' AS keyword UNION ALL
    SELECT 'device_id' UNION ALL
    SELECT 'device_fingerprint' UNION ALL
    SELECT 'login_ip' UNION ALL
    SELECT 'ip_address'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $SOC2_CAT_ID
);

-- Trade Secrets and Confidential Data
INSERT INTO SENSITIVE_KEYWORDS (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
SELECT UUID_STRING(), $SOC2_CAT_ID, keyword, 'CONTAINS', 0.95, TRUE, CURRENT_USER()
FROM (
    SELECT 'trade_secret_key' AS keyword UNION ALL
    SELECT 'trade_secret' UNION ALL
    SELECT 'confidential_agreement_id' UNION ALL
    SELECT 'confidential' UNION ALL
    SELECT 'proprietary' UNION ALL
    SELECT 'encryption_key' UNION ALL
    SELECT 'private_key'
) keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE LOWER(KEYWORD_STRING) = keywords.keyword 
    AND CATEGORY_ID = $SOC2_CAT_ID
);

-- ============================================================================
-- UPDATE CATEGORY METADATA FOR CORRECT CIA LEVELS
-- ============================================================================

-- Update PII: C2-Restricted, I2-Moderate, A2-Moderate
UPDATE SENSITIVITY_CATEGORIES
SET 
    CONFIDENTIALITY_LEVEL = 2,
    INTEGRITY_LEVEL = 2,
    AVAILABILITY_LEVEL = 2,
    DETECTION_THRESHOLD = 0.45,
    WEIGHT_EMBEDDING = 0.60,
    WEIGHT_KEYWORD = 0.30,
    WEIGHT_PATTERN = 0.10,
    MULTI_LABEL = TRUE
WHERE UPPER(CATEGORY_NAME) = 'PII';

-- Update SOX: C3-Confidential, I3-High, A3-High
UPDATE SENSITIVITY_CATEGORIES
SET 
    CONFIDENTIALITY_LEVEL = 3,
    INTEGRITY_LEVEL = 3,
    AVAILABILITY_LEVEL = 3,
    DETECTION_THRESHOLD = 0.45,
    WEIGHT_EMBEDDING = 0.60,
    WEIGHT_KEYWORD = 0.30,
    WEIGHT_PATTERN = 0.10,
    MULTI_LABEL = TRUE
WHERE UPPER(CATEGORY_NAME) = 'SOX';

-- Update SOC2: C2-Restricted, I2-Moderate, A2-Moderate
UPDATE SENSITIVITY_CATEGORIES
SET 
    CONFIDENTIALITY_LEVEL = 2,
    INTEGRITY_LEVEL = 2,
    AVAILABILITY_LEVEL = 2,
    DETECTION_THRESHOLD = 0.45,
    WEIGHT_EMBEDDING = 0.60,
    WEIGHT_KEYWORD = 0.30,
    WEIGHT_PATTERN = 0.10,
    MULTI_LABEL = TRUE
WHERE UPPER(CATEGORY_NAME) = 'SOC2';

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Check keyword counts per category
SELECT 
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    COUNT(sk.KEYWORD_ID) as KEYWORD_COUNT,
    sc.DETECTION_THRESHOLD,
    CONCAT('C', sc.CONFIDENTIALITY_LEVEL, '-I', sc.INTEGRITY_LEVEL, '-A', sc.AVAILABILITY_LEVEL) as CIA_LEVELS
FROM SENSITIVITY_CATEGORIES sc
LEFT JOIN SENSITIVE_KEYWORDS sk ON sc.CATEGORY_ID = sk.CATEGORY_ID AND sk.IS_ACTIVE = TRUE
WHERE sc.CATEGORY_NAME IN ('PII', 'SOX', 'SOC2')
GROUP BY sc.CATEGORY_NAME, sc.POLICY_GROUP, sc.DETECTION_THRESHOLD, 
         sc.CONFIDENTIALITY_LEVEL, sc.INTEGRITY_LEVEL, sc.AVAILABILITY_LEVEL
ORDER BY sc.CATEGORY_NAME;

-- Show sample keywords per category
SELECT 
    sc.CATEGORY_NAME,
    sk.KEYWORD_STRING,
    sk.MATCH_TYPE,
    sk.SENSITIVITY_WEIGHT
FROM SENSITIVITY_CATEGORIES sc
JOIN SENSITIVE_KEYWORDS sk ON sc.CATEGORY_ID = sk.CATEGORY_ID
WHERE sc.CATEGORY_NAME IN ('PII', 'SOX', 'SOC2')
  AND sk.IS_ACTIVE = TRUE
ORDER BY sc.CATEGORY_NAME, sk.SENSITIVITY_WEIGHT DESC
LIMIT 100;

-- ============================================================================
-- DONE! 
-- Run this script to populate all necessary keywords for accurate detection
-- ============================================================================
