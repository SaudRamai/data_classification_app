-- ============================================================================
-- CHECK: What category is CATEGORY_ID 3e47f6fd-d870-41a8-b75f-e967bb839475?
-- ============================================================================

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- Check what this CATEGORY_ID actually is
SELECT 
    '🔍 WHAT IS THIS CATEGORY?' AS QUESTION,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP
FROM SENSITIVITY_CATEGORIES
WHERE CATEGORY_ID = '3e47f6fd-d870-41a8-b75f-e967bb839475';

-- If it returns 'SOC2', that's the problem!
-- If it returns 'PII', then the problem is elsewhere!

-- Also check all categories
SELECT 
    '📋 ALL CATEGORIES' AS INFO,
    CATEGORY_ID,
    CATEGORY_NAME,
    POLICY_GROUP
FROM SENSITIVITY_CATEGORIES
ORDER BY CATEGORY_NAME;
