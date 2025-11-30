-- ============================================================================
-- CHECK AND POPULATE SENSITIVE_PATTERNS TABLE
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- STEP 1: Check if SENSITIVE_PATTERNS table exists
-- ============================================================================
SHOW TABLES LIKE 'SENSITIVE_PATTERNS';

-- ============================================================================
-- STEP 2: Clear existing patterns to avoid duplicates and remove bad patterns
-- ============================================================================
DELETE FROM SENSITIVE_PATTERNS;

-- ============================================================================
-- STEP 3: Populate with essential patterns
-- ============================================================================

-- PII Patterns
INSERT INTO SENSITIVE_PATTERNS (
    PATTERN_ID, 
    CATEGORY_ID, 
    PATTERN_NAME,
    PATTERN_REGEX, 
    SENSITIVITY_TYPE, 
    SENSITIVITY_WEIGHT, 
    IS_ACTIVE,
    CREATED_BY,
    CREATED_AT,
    VERSION_NUMBER
)
SELECT 
    UUID_STRING() as PATTERN_ID,
    (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'PII') as CATEGORY_ID,
    sensitivity_type as PATTERN_NAME,
    pattern_regex,
    sensitivity_type,
    sensitivity_weight,
    TRUE as IS_ACTIVE,
    'SYSTEM' as CREATED_BY,
    CURRENT_TIMESTAMP() as CREATED_AT,
    1 as VERSION_NUMBER
FROM (
    -- Email Pattern
    SELECT 
        '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}' as pattern_regex,
        'EMAIL' as sensitivity_type,
        0.95 as sensitivity_weight
    UNION ALL
    -- Phone Pattern (US)
    SELECT 
        '\\(?\\d{3}\\)?[-.]?\\d{3}[-.]?\\d{4}',
        'PHONE',
        0.90
    UNION ALL
    -- SSN Pattern
    SELECT 
        '\\d{3}-\\d{2}-\\d{4}',
        'SSN',
        1.0
    UNION ALL
    -- Credit Card Pattern
    SELECT 
        '\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}',
        'CREDIT_CARD',
        1.0
    UNION ALL
    -- ZIP Code Pattern
    SELECT 
        '\\d{5}(-\\d{4})?',
        'ZIP_CODE',
        0.70
    UNION ALL
    -- Date of Birth Pattern
    SELECT 
        '(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])/(19|20)\\d{2}',
        'DATE_OF_BIRTH',
        0.85
) patterns;

-- SOX Patterns
INSERT INTO SENSITIVE_PATTERNS (
    PATTERN_ID, 
    CATEGORY_ID, 
    PATTERN_NAME,
    PATTERN_REGEX, 
    SENSITIVITY_TYPE, 
    SENSITIVITY_WEIGHT, 
    IS_ACTIVE,
    CREATED_BY,
    CREATED_AT,
    VERSION_NUMBER
)
SELECT 
    UUID_STRING() as PATTERN_ID,
    (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOX') as CATEGORY_ID,
    sensitivity_type as PATTERN_NAME,
    pattern_regex,
    sensitivity_type,
    sensitivity_weight,
    TRUE as IS_ACTIVE,
    'SYSTEM' as CREATED_BY,
    CURRENT_TIMESTAMP() as CREATED_AT,
    1 as VERSION_NUMBER
FROM (
    -- Currency Pattern
    SELECT 
        '\\$[0-9,]+\\.[0-9]{2}' as pattern_regex,
        'CURRENCY' as sensitivity_type,
        0.80 as sensitivity_weight
    UNION ALL
    -- Invoice Number Pattern
    SELECT 
        'INV-[0-9]{6,}',
        'INVOICE_NUMBER',
        0.75
    UNION ALL
    -- Account Number Pattern
    SELECT 
        'ACCT-[0-9]{8,}',
        'ACCOUNT_NUMBER',
        0.85
    UNION ALL
    -- Transaction ID Pattern
    SELECT 
        'TXN-[A-Z0-9]{10,}',
        'TRANSACTION_ID',
        0.75
) patterns;

-- SOC2 Patterns
INSERT INTO SENSITIVE_PATTERNS (
    PATTERN_ID, 
    CATEGORY_ID, 
    PATTERN_NAME,
    PATTERN_REGEX, 
    SENSITIVITY_TYPE, 
    SENSITIVITY_WEIGHT, 
    IS_ACTIVE,
    CREATED_BY,
    CREATED_AT,
    VERSION_NUMBER
)
SELECT 
    UUID_STRING() as PATTERN_ID,
    (SELECT CATEGORY_ID FROM SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = 'SOC2') as CATEGORY_ID,
    sensitivity_type as PATTERN_NAME,
    pattern_regex,
    sensitivity_type,
    sensitivity_weight,
    TRUE as IS_ACTIVE,
    'SYSTEM' as CREATED_BY,
    CURRENT_TIMESTAMP() as CREATED_AT,
    1 as VERSION_NUMBER
FROM (
    -- API Key Pattern (32+ alphanumeric)
    SELECT 
        '[A-Za-z0-9]{32,}' as pattern_regex,
        'API_KEY' as sensitivity_type,
        0.85 as sensitivity_weight
    UNION ALL
    -- Bearer Token Pattern
    SELECT 
        'Bearer [A-Za-z0-9\\-._~+/]+=*',
        'BEARER_TOKEN',
        0.90
    UNION ALL
    -- JWT Token Pattern
    SELECT 
        'eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*',
        'JWT_TOKEN',
        0.95
    UNION ALL
    -- AWS Access Key Pattern
    SELECT 
        'AKIA[0-9A-Z]{16}',
        'AWS_ACCESS_KEY',
        1.0
    UNION ALL
    -- Private Key Pattern
    SELECT 
        '-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        'PRIVATE_KEY',
        1.0
) patterns;

-- ============================================================================
-- STEP 4: Verify patterns were added
-- ============================================================================
SELECT 
    sc.CATEGORY_NAME,
    COUNT(sp.PATTERN_ID) as PATTERN_COUNT,
    SUM(CASE WHEN sp.IS_ACTIVE = TRUE THEN 1 ELSE 0 END) as ACTIVE_PATTERNS
FROM SENSITIVITY_CATEGORIES sc
LEFT JOIN SENSITIVE_PATTERNS sp ON sc.CATEGORY_ID = sp.CATEGORY_ID
GROUP BY sc.CATEGORY_NAME
ORDER BY sc.CATEGORY_NAME;

-- ============================================================================
-- STEP 5: View sample patterns
-- ============================================================================
SELECT 
    sc.CATEGORY_NAME,
    sp.SENSITIVITY_TYPE,
    sp.PATTERN_REGEX,
    sp.SENSITIVITY_WEIGHT,
    sp.IS_ACTIVE
FROM SENSITIVE_PATTERNS sp
JOIN SENSITIVITY_CATEGORIES sc ON sp.CATEGORY_ID = sc.CATEGORY_ID
ORDER BY sc.CATEGORY_NAME, sp.SENSITIVITY_WEIGHT DESC;
