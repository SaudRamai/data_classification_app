-- ============================================================================
-- FIX MISCLASSIFICATION AND POLICY GROUP MAPPINGS
-- ============================================================================
-- This script corrects the root causes of PII columns being misclassified as SOC2
-- and moves vendor-related data to the appropriate SOX category.

USE DATABASE DATA_CLASSIFICATION_GOVERNANCE_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- 1. FIX POLICY GROUP MAPPINGS IN SENSITIVITY_CATEGORIES
-- ============================================================================
-- The PII category was incorrectly mapped to 'SOC2' policy group, causing 
-- all PII columns (SSN, Tax ID, etc.) to appear as SOC2 in the UI.

-- Fix PII Category Mapping
UPDATE SENSITIVITY_CATEGORIES
SET POLICY_GROUP = 'PII',
    DESCRIPTION = 'Personal Identifiable Information including names, email addresses, phone numbers, physical addresses, SSN, passport numbers, driver licenses, dates of birth, biometric data, and any information that identifies a natural person'
WHERE CATEGORY_ID = 'c3b32acc-552c-477d-bbf6-bc5e9150f34f'; -- Category containing SSN, Birth Date

-- Ensure SOX Category Mapping is Correct
UPDATE SENSITIVITY_CATEGORIES
SET POLICY_GROUP = 'SOX',
    DESCRIPTION = 'Financial and accounting data including revenue, transactions, account balances, payments, invoices, general ledger entries, expense reports, payroll, and other financial information subject to SOX compliance'
WHERE CATEGORY_ID = '88779456-5355-484e-84af-b86e288c2a40'; -- Category containing Revenue, Invoice

-- Ensure SOC2 Category Mapping is Correct
UPDATE SENSITIVITY_CATEGORIES
SET POLICY_GROUP = 'SOC2',
    DESCRIPTION = 'Security and access control data including passwords, authentication tokens, API keys, encryption keys, certificates, credentials, security logs, access records, and other security-critical information'
WHERE CATEGORY_ID = '3fb45bc8-a053-487b-8234-358adf3afab1'; -- Category containing Password, API Key

-- ============================================================================
-- 2. MOVE MISCLASSIFIED KEYWORDS TO CORRECT CATEGORIES
-- ============================================================================
-- Vendor data and Payment Terms were incorrectly placed in the PII category.
-- They are business/financial data and belong in the SOX category.

UPDATE SENSITIVE_KEYWORDS
SET CATEGORY_ID = '88779456-5355-484e-84af-b86e288c2a40', -- Move to SOX
    UPDATED_AT = CURRENT_TIMESTAMP(),
    VERSION_NUMBER = VERSION_NUMBER + 1
WHERE KEYWORD_STRING IN ('vendor_name', 'vendor_address', 'payment_terms')
  AND CATEGORY_ID = 'c3b32acc-552c-477d-bbf6-bc5e9150f34f'; -- Currently in PII

-- ============================================================================
-- 3. VERIFICATION
-- ============================================================================
SELECT 
    sc.CATEGORY_NAME,
    sc.POLICY_GROUP,
    COUNT(sk.KEYWORD_ID) as KEYWORD_COUNT
FROM SENSITIVITY_CATEGORIES sc
LEFT JOIN SENSITIVE_KEYWORDS sk ON sc.CATEGORY_ID = sk.CATEGORY_ID
WHERE sc.CATEGORY_ID IN (
    'c3b32acc-552c-477d-bbf6-bc5e9150f34f', 
    '88779456-5355-484e-84af-b86e288c2a40', 
    '3fb45bc8-a053-487b-8234-358adf3afab1'
)
GROUP BY sc.CATEGORY_NAME, sc.POLICY_GROUP;
