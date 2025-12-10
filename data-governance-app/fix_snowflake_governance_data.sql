-- ============================================================================
-- FIX SNOWFLAKE GOVERNANCE DATA - CRITICAL ISSUES
-- ============================================================================
-- This script fixes all data quality issues preventing accurate PII/SOX/SOC2 detection
-- Run this in your Snowflake environment
-- ============================================================================

USE DATABASE DATA_GOVERNANCE_DB;
USE SCHEMA GOVERNANCE;

-- ============================================================================
-- ISSUE 1: Fix NULL values in SENSITIVE_KEYWORDS table
-- ============================================================================

-- Set default values for rows with NULL SENSITIVITY_WEIGHT
UPDATE SENSITIVE_KEYWORDS
SET SENSITIVITY_WEIGHT = 0.8
WHERE SENSITIVITY_WEIGHT IS NULL
  AND KEYWORD_STRING IS NOT NULL;

-- Set default IS_ACTIVE = TRUE for rows with NULL
UPDATE SENSITIVE_KEYWORDS
SET IS_ACTIVE = TRUE
WHERE IS_ACTIVE IS NULL
  AND KEYWORD_STRING IS NOT NULL;

-- Set default CREATED_AT for rows with NULL
UPDATE SENSITIVE_KEYWORDS
SET CREATED_AT = CURRENT_TIMESTAMP(),
    CREATED_BY = 'SYSTEM_FIX'
WHERE CREATED_AT IS NULL
  AND KEYWORD_STRING IS NOT NULL;

-- Set default VERSION_NUMBER for rows with NULL
UPDATE SENSITIVE_KEYWORDS
SET VERSION_NUMBER = 1
WHERE VERSION_NUMBER IS NULL
  AND KEYWORD_STRING IS NOT NULL;

-- ============================================================================
-- ISSUE 2: Fix NEGATIVE weights (invalid data)
-- ============================================================================

-- Delete or deactivate keywords with negative weights
UPDATE SENSITIVE_KEYWORDS
SET IS_ACTIVE = FALSE,
    UPDATED_AT = CURRENT_TIMESTAMP()
WHERE SENSITIVITY_WEIGHT < 0;

-- Alternative: Set them to a default value
-- UPDATE SENSITIVE_KEYWORDS
-- SET SENSITIVITY_WEIGHT = 0.7,
--     UPDATED_AT = CURRENT_TIMESTAMP()
-- WHERE SENSITIVITY_WEIGHT < 0;

-- ============================================================================
-- ISSUE 3: Move financial date keywords from PII to SOX
-- ============================================================================

-- Get SOX category ID
SET SOX_CATEGORY_ID = (
    SELECT CATEGORY_ID 
    FROM SENSITIVITY_CATEGORIES 
    WHERE CATEGORY_NAME = 'SOX' 
    LIMIT 1
);

-- Move financial date keywords to SOX category
UPDATE SENSITIVE_KEYWORDS
SET CATEGORY_ID = $SOX_CATEGORY_ID,
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'SYSTEM_FIX'
WHERE KEYWORD_STRING IN ('due_date', 'invoice_date', 'payment_date', 
                         'transaction_date', 'fiscal_date', 'billing_date')
  AND IS_ACTIVE = TRUE;

-- ============================================================================
-- ISSUE 4: Reactivate critical SOX keywords
-- ============================================================================

UPDATE SENSITIVE_KEYWORDS
SET IS_ACTIVE = TRUE,
    SENSITIVITY_WEIGHT = CASE 
        WHEN KEYWORD_STRING = 'account_number' THEN 0.85
        WHEN KEYWORD_STRING = 'invoice' THEN 0.80
        WHEN KEYWORD_STRING = 'payment' THEN 0.80
        WHEN KEYWORD_STRING = 'vendor' THEN 0.75
        ELSE SENSITIVITY_WEIGHT
    END,
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'SYSTEM_FIX'
WHERE KEYWORD_STRING IN ('account_number', 'invoice', 'payment', 'vendor')
  AND CATEGORY_ID = $SOX_CATEGORY_ID;

-- ============================================================================
-- ISSUE 5: Add missing critical SOX keywords
-- ============================================================================

-- Insert missing SOX keywords if they don't exist
INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, 
    SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER
)
SELECT 
    UUID_STRING() AS KEYWORD_ID,
    $SOX_CATEGORY_ID AS CATEGORY_ID,
    keyword AS KEYWORD_STRING,
    'PARTIAL' AS MATCH_TYPE,
    weight AS SENSITIVITY_WEIGHT,
    TRUE AS IS_ACTIVE,
    'SYSTEM_FIX' AS CREATED_BY,
    CURRENT_TIMESTAMP() AS CREATED_AT,
    1 AS VERSION_NUMBER
FROM (
    SELECT 'order_id' AS keyword, 0.85 AS weight UNION ALL
    SELECT 'invoice_id', 0.85 UNION ALL
    SELECT 'transaction_id', 0.85 UNION ALL
    SELECT 'invoice_number', 0.85 UNION ALL
    SELECT 'order_number', 0.85 UNION ALL
    SELECT 'invoice_amount', 0.90 UNION ALL
    SELECT 'total_amount', 0.85 UNION ALL
    SELECT 'payment_amount', 0.85 UNION ALL
    SELECT 'total_due', 0.85 UNION ALL
    SELECT 'amount_paid', 0.85 UNION ALL
    SELECT 'currency_code', 0.80 UNION ALL
    SELECT 'tax_amount', 0.85 UNION ALL
    SELECT 'discount_amount', 0.80
) AS new_keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE KEYWORD_STRING = new_keywords.keyword
      AND CATEGORY_ID = $SOX_CATEGORY_ID
);

-- ============================================================================
-- ISSUE 6: Add missing critical PII keywords
-- ============================================================================

-- Get PII category ID
SET PII_CATEGORY_ID = (
    SELECT CATEGORY_ID 
    FROM SENSITIVITY_CATEGORIES 
    WHERE CATEGORY_NAME = 'PII' 
    LIMIT 1
);

-- Insert missing PII keywords
INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, 
    SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER
)
SELECT 
    UUID_STRING() AS KEYWORD_ID,
    $PII_CATEGORY_ID AS CATEGORY_ID,
    keyword AS KEYWORD_STRING,
    'PARTIAL' AS MATCH_TYPE,
    weight AS SENSITIVITY_WEIGHT,
    TRUE AS IS_ACTIVE,
    'SYSTEM_FIX' AS CREATED_BY,
    CURRENT_TIMESTAMP() AS CREATED_AT,
    1 AS VERSION_NUMBER
FROM (
    SELECT 'customer_id' AS keyword, 0.90 AS weight UNION ALL
    SELECT 'user_id', 0.90 UNION ALL
    SELECT 'employee_id', 0.90 UNION ALL
    SELECT 'billing_city', 0.85 UNION ALL
    SELECT 'billing_state', 0.85 UNION ALL
    SELECT 'billing_state_province', 0.85 UNION ALL
    SELECT 'shipping_city', 0.85 UNION ALL
    SELECT 'shipping_state', 0.85 UNION ALL
    SELECT 'first_name', 0.95 UNION ALL
    SELECT 'last_name', 0.95 UNION ALL
    SELECT 'middle_name', 0.90 UNION ALL
    SELECT 'dob', 0.95 UNION ALL
    SELECT 'date_of_birth', 0.95
) AS new_keywords
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE KEYWORD_STRING = new_keywords.keyword
      AND CATEGORY_ID = $PII_CATEGORY_ID
);

-- ============================================================================
-- ISSUE 7: Fix SENSITIVITY_CATEGORIES descriptions (ensure they're complete)
-- ============================================================================

-- Verify PII category has proper description
UPDATE SENSITIVITY_CATEGORIES
SET DESCRIPTION = 'Personally Identifiable Information (PII). This category covers any information that can directly or indirectly identify a natural person, customer, client, employee, contractor, or user. PII includes data elements that reveal identity, demographics, contact information, authentication details, government identifiers, personal attributes, medical or biometric data, or any sensitive information tied to a specific individual. Examples include: Full names, email addresses, phone numbers, home/mailing address, date of birth, SSN, credit card numbers, biometrics, medical records, etc. EXCLUDE: Business process dates (due_date, invoice_date, order_date, payment_date, created_at, updated_at).',
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'SYSTEM_FIX'
WHERE CATEGORY_NAME = 'PII'
  AND (DESCRIPTION IS NULL OR LENGTH(DESCRIPTION) < 100);

-- Verify SOX category has proper description
UPDATE SENSITIVITY_CATEGORIES
SET DESCRIPTION = 'SOX (Sarbanes-Oxley Act) Financial Reporting and Internal Controls Data. This category includes all information used for external financial reporting, internal controls, accounting processes, audits, regulatory compliance, revenue recognition, expenditure tracking, and any financial data that affects the accuracy and integrity of financial statements. Examples include: General Ledger, Journal Entries, Trial Balance, Financial statements, Revenue, Expenses, Accounts Payable/Receivable, Invoices, Payments, Payroll, Purchase Orders, Sales Orders, Budgeting, SOX controls, Audit trails, etc.',
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'SYSTEM_FIX'
WHERE CATEGORY_NAME = 'SOX'
  AND (DESCRIPTION IS NULL OR LENGTH(DESCRIPTION) < 100);

-- Verify SOC2 category has proper description
UPDATE SENSITIVITY_CATEGORIES
SET DESCRIPTION = 'SOC 2 (Service Organization Control Type 2) Security, Availability, Integrity, Confidentiality, and Privacy Data. This category includes information related to cybersecurity controls, operational processes, system configurations, logging, access management, incident response, monitoring, and compliance activities aligned with the SOC 2 Trust Services Criteria. Examples include: Access control data, Authentication/authorization, Security logs, Encryption details, Network security, Vulnerability scans, Incident response, Disaster Recovery, Change management, Segregation of Duties, System hardening, Data protection controls, etc.',
    UPDATED_AT = CURRENT_TIMESTAMP(),
    UPDATED_BY = 'SYSTEM_FIX'
WHERE CATEGORY_NAME = 'SOC2'
  AND (DESCRIPTION IS NULL OR LENGTH(DESCRIPTION) < 100);

-- ============================================================================
-- ISSUE 8: Ensure POLICY_GROUP is set correctly
-- ============================================================================

UPDATE SENSITIVITY_CATEGORIES
SET POLICY_GROUP = 'PII'
WHERE CATEGORY_NAME = 'PII' AND (POLICY_GROUP IS NULL OR POLICY_GROUP != 'PII');

UPDATE SENSITIVITY_CATEGORIES
SET POLICY_GROUP = 'SOX'
WHERE CATEGORY_NAME = 'SOX' AND (POLICY_GROUP IS NULL OR POLICY_GROUP != 'SOX');

UPDATE SENSITIVITY_CATEGORIES
SET POLICY_GROUP = 'SOC2'
WHERE CATEGORY_NAME = 'SOC2' AND (POLICY_GROUP IS NULL OR POLICY_GROUP != 'SOC2');

-- ============================================================================
-- ISSUE 9: Set proper thresholds
-- ============================================================================

UPDATE SENSITIVITY_CATEGORIES
SET DETECTION_THRESHOLD = 0.30,
    UPDATED_AT = CURRENT_TIMESTAMP()
WHERE CATEGORY_NAME IN ('PII', 'SOX', 'SOC2')
  AND (DETECTION_THRESHOLD IS NULL OR DETECTION_THRESHOLD > 0.50);

-- ============================================================================
-- ISSUE 10: Ensure weights are set properly
-- ============================================================================

UPDATE SENSITIVITY_CATEGORIES
SET WEIGHT_EMBEDDING = 0.50,
    WEIGHT_KEYWORD = 0.35,
    WEIGHT_PATTERN = 0.15,
    UPDATED_AT = CURRENT_TIMESTAMP()
  AND (WEIGHT_EMBEDDING IS NULL OR WEIGHT_KEYWORD IS NULL OR WEIGHT_PATTERN IS NULL);

-- ============================================================================
-- ISSUE 11: Add Multi-Label Test Data (Example: ANNUAL_INCOME)
-- ============================================================================

-- Add 'annual_income' to PII
INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, 
    SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER
)
SELECT 
    UUID_STRING(), $PII_CATEGORY_ID, 'annual_income', 'CONTAINS', 
    0.95, TRUE, 'SYSTEM_FIX', CURRENT_TIMESTAMP(), 1
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE KEYWORD_STRING = 'annual_income' AND CATEGORY_ID = $PII_CATEGORY_ID
);

-- Add 'annual_income' to SOX
INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, 
    SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER
)
SELECT 
    UUID_STRING(), $SOX_CATEGORY_ID, 'annual_income', 'CONTAINS', 
    0.90, TRUE, 'SYSTEM_FIX', CURRENT_TIMESTAMP(), 1
WHERE NOT EXISTS (
    SELECT 1 FROM SENSITIVE_KEYWORDS 
    WHERE KEYWORD_STRING = 'annual_income' AND CATEGORY_ID = $SOX_CATEGORY_ID
);

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Check for remaining NULL values
SELECT 'NULL_KEYWORDS' AS issue, COUNT(*) AS count
FROM SENSITIVE_KEYWORDS
WHERE SENSITIVITY_WEIGHT IS NULL OR IS_ACTIVE IS NULL

UNION ALL

-- Check for negative weights
SELECT 'NEGATIVE_WEIGHTS' AS issue, COUNT(*) AS count
FROM SENSITIVE_KEYWORDS
WHERE SENSITIVITY_WEIGHT < 0

UNION ALL

-- Check for inactive critical keywords
SELECT 'INACTIVE_CRITICAL' AS issue, COUNT(*) AS count
FROM SENSITIVE_KEYWORDS
WHERE IS_ACTIVE = FALSE
  AND KEYWORD_STRING IN ('customer_id', 'invoice_id', 'order_id', 'email', 'phone', 'ssn')

UNION ALL

-- Check category configuration
SELECT 'MISSING_POLICY_GROUP' AS issue, COUNT(*) AS count
FROM SENSITIVITY_CATEGORIES
WHERE POLICY_GROUP IS NULL OR POLICY_GROUP NOT IN ('PII', 'SOX', 'SOC2', 'NON_SENSITIVE');

-- Display summary of keywords by category
SELECT 
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    COUNT(sk.KEYWORD_ID) AS keyword_count,
    COUNT(CASE WHEN sk.IS_ACTIVE = TRUE THEN 1 END) AS active_count,
    AVG(sk.SENSITIVITY_WEIGHT) AS avg_weight
FROM SENSITIVITY_CATEGORIES sc
LEFT JOIN SENSITIVE_KEYWORDS sk ON sc.CATEGORY_ID = sk.CATEGORY_ID
WHERE sc.CATEGORY_NAME IN ('PII', 'SOX', 'SOC2')
GROUP BY sc.CATEGORY_NAME, sc.POLICY_GROUP
ORDER BY sc.CATEGORY_NAME;

-- Display summary of patterns by category
SELECT 
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    COUNT(sp.PATTERN_ID) AS pattern_count,
    COUNT(CASE WHEN sp.IS_ACTIVE = TRUE THEN 1 END) AS active_count,
    AVG(sp.SENSITIVITY_WEIGHT) AS avg_weight
FROM SENSITIVITY_CATEGORIES sc
LEFT JOIN SENSITIVE_PATTERNS sp ON sc.CATEGORY_ID = sp.CATEGORY_ID
WHERE sc.CATEGORY_NAME IN ('PII', 'SOX', 'SOC2')
GROUP BY sc.CATEGORY_NAME, sc.POLICY_GROUP
ORDER BY sc.CATEGORY_NAME;

-- ============================================================================
-- COMMIT CHANGES
-- ============================================================================

COMMIT;

SELECT 'Governance data fixes completed successfully!' AS status;
