-- ============================================================================
-- SIMPLE FIX: Query the CORRECT location where upsert writes
-- ============================================================================
-- Based on the upsert code, data is written to:
-- {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS
--
-- Where {gov_db} is resolved by resolve_governance_db()
-- This usually returns DATA_CLASSIFICATION_GOVERNANCE or DATA_CLASSIFICATION_DB
-- ============================================================================

-- Option 1: Try DATA_CLASSIFICATION_GOVERNANCE database
SELECT 
    'OPTION 1: DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE' AS LOCATION,
    *
FROM DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- Option 2: Try DATA_CLASSIFICATION_DB database
SELECT 
    'OPTION 2: DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE' AS LOCATION,
    *
FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS
WHERE KEYWORD_STRING = 'SOCIAL_SECURITY_NUMBER';

-- Option 3: Check ALL keywords in OPTION 1
SELECT 
    'ALL KEYWORDS IN DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE' AS LOCATION,
    COUNT(*) AS TOTAL_COUNT
FROM DATA_CLASSIFICATION_GOVERNANCE.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS;

-- Option 4: Check ALL keywords in OPTION 2
SELECT 
    'ALL KEYWORDS IN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE' AS LOCATION,
    COUNT(*) AS TOTAL_COUNT
FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS;

-- ============================================================================
-- IMPORTANT: The schema name is DATA_CLASSIFICATION_GOVERNANCE, NOT GOVERNANCE!
-- This is why your queries aren't finding anything!
-- ============================================================================
