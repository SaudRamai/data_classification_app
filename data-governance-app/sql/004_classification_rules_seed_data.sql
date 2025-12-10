-- ============================================================================
-- DATA-DRIVEN CLASSIFICATION ARCHITECTURE
-- Seed Data for Classification Rules
-- ============================================================================
-- Purpose: Populate governance tables with current hardcoded logic
-- Author: AI Classification System
-- Date: 2025-12-04
-- ============================================================================

USE DATABASE GOVERNANCE_DB;
USE SCHEMA GOVERNANCE_SCHEMA;

-- ============================================================================
-- CLASSIFICATION_RULES - Table Context Rules
-- ============================================================================

-- Rule 1: Financial/Transactional Tables → Boost SOX
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Financial Table Context - Boost SOX',
    'TABLE_CONTEXT',
    10,
    'TABLE',
    '["order", "transaction", "payment", "invoice", "billing", "purchase", "sale", "revenue"]',
    'ANY',
    'SOX',
    'BOOST',
    1.3,
    'Boost SOX for columns in financial/transactional tables',
    TRUE,
    'SYSTEM'
);

-- Rule 2: Customer/User Tables → Boost PII
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Customer Table Context - Boost PII',
    'TABLE_CONTEXT',
    10,
    'TABLE',
    '["customer", "user", "employee", "person", "contact"]',
    'ANY',
    'PII',
    'BOOST',
    1.3,
    'Boost PII for columns in customer/user tables',
    TRUE,
    'SYSTEM'
);

-- Rule 3: Security/Auth Tables → Boost SOC2
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Security Table Context - Boost SOC2',
    'TABLE_CONTEXT',
    10,
    'TABLE',
    '["auth", "security", "access", "credential", "session", "login"]',
    'ANY',
    'SOC2',
    'BOOST',
    1.3,
    'Boost SOC2 for columns in security/auth tables',
    TRUE,
    'SYSTEM'
);

-- ============================================================================
-- CLASSIFICATION_RULES - ID Classification Rules
-- ============================================================================

-- Rule 4: PII IDs
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    SECONDARY_POLICY_GROUP, SECONDARY_ACTION_TYPE, SECONDARY_ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'PII ID Classification',
    'ID_CLASSIFICATION',
    20,
    'COLUMN',
    '["customer", "user", "employee", "person", "patient", "member", "subscriber", "citizen", "contact"]',
    'ANY',
    'PII',
    'BOOST',
    1.5,
    'SOC2',
    'REDUCE',
    0.3,
    'Boost PII and reduce SOC2/SOX for person-identifying IDs',
    TRUE,
    'SYSTEM'
);

-- Rule 5: SOX IDs
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    SECONDARY_POLICY_GROUP, SECONDARY_ACTION_TYPE, SECONDARY_ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'SOX ID Classification',
    'ID_CLASSIFICATION',
    20,
    'COLUMN',
    '["order", "transaction", "payment", "invoice", "account", "billing", "purchase", "sale"]',
    'ANY',
    'SOX',
    'BOOST',
    1.4,
    'SOC2',
    'REDUCE',
    0.3,
    'Boost SOX and reduce SOC2/PII for financial/transactional IDs',
    TRUE,
    'SYSTEM'
);

-- Rule 6: SOC2 IDs
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    SECONDARY_POLICY_GROUP, SECONDARY_ACTION_TYPE, SECONDARY_ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'SOC2 ID Classification',
    'ID_CLASSIFICATION',
    20,
    'COLUMN',
    '["session", "token", "auth", "credential", "access", "login", "permission"]',
    'ANY',
    'SOC2',
    'BOOST',
    1.5,
    'PII',
    'REDUCE',
    0.3,
    'Boost SOC2 and reduce PII/SOX for security/access IDs',
    TRUE,
    'SYSTEM'
);

-- Rule 7: Generic IDs (NON_SENSITIVE)
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Generic ID Exclusion',
    'ID_CLASSIFICATION',
    20,
    'COLUMN',
    '["product", "item", "category", "catalog", "inventory", "sku", "department", "store", "warehouse", "location", "region", "branch", "division"]',
    'ANY',
    'NON_SENSITIVE',
    'REMOVE',
    0.0,
    'Remove all sensitivity for generic catalog/organizational IDs',
    TRUE,
    'SYSTEM'
);

-- ============================================================================
-- CLASSIFICATION_RULES - Field Type Rules
-- ============================================================================

-- Rule 8: Price/Amount Fields → SOX
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    SECONDARY_POLICY_GROUP, SECONDARY_ACTION_TYPE, SECONDARY_ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Price/Amount Fields - Boost SOX',
    'FIELD_TYPE',
    30,
    'COLUMN',
    '["price", "amount", "total", "cost", "fee", "charge", "balance", "revenue", "salary", "wage"]',
    'ANY',
    'SOX',
    'BOOST',
    1.4,
    'PII',
    'REDUCE',
    0.4,
    'Boost SOX and reduce PII/SOC2 for price/amount fields',
    TRUE,
    'SYSTEM'
);

-- Rule 9: Quantity/Count Fields
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Quantity/Count Fields - Reduce Sensitivity',
    'FIELD_TYPE',
    30,
    'COLUMN',
    '["quantity", "count", "qty", "number_of"]',
    'ANY',
    'PII',
    'REDUCE',
    0.5,
    'Reduce PII/SOC2 for quantity/count fields',
    TRUE,
    'SYSTEM'
);

-- Rule 10: Personal Name Fields → PII
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    EXCLUDE_KEYWORDS,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Personal Name Fields - Boost PII',
    'FIELD_TYPE',
    30,
    'COLUMN',
    '["name", "first_name", "last_name", "full_name", "firstname", "lastname"]',
    'ANY',
    '["product", "company", "business", "organization", "vendor", "supplier", "merchant", "store", "shop", "brand", "category", "item", "service", "package", "plan"]',
    'PII',
    'BOOST',
    1.7,
    'Boost PII for personal name fields (excluding business names)',
    TRUE,
    'SYSTEM'
);

-- Rule 11: Description/Notes Fields
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    EXCLUDE_KEYWORDS,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Description/Notes Fields - Reduce Sensitivity',
    'FIELD_TYPE',
    30,
    'COLUMN',
    '["description", "desc", "notes", "comment", "remarks", "memo"]',
    'ANY',
    '["patient", "medical", "health", "diagnosis", "treatment"]',
    'PII',
    'REDUCE',
    0.4,
    'Reduce sensitivity for generic description fields (excluding medical)',
    TRUE,
    'SYSTEM'
);

-- Rule 12: Vendor/Supplier Fields
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    EXCLUDE_KEYWORDS,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Vendor/Supplier Fields - Reduce PII',
    'FIELD_TYPE',
    30,
    'COLUMN',
    '["vendor", "supplier", "merchant", "partner"]',
    'ANY',
    '["contact", "email", "phone", "address", "name"]',
    'PII',
    'REDUCE',
    0.3,
    'Reduce PII for vendor/supplier fields (excluding contact info)',
    TRUE,
    'SYSTEM'
);

-- Rule 13: Financial Codes → SOX
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Financial Codes - Boost SOX',
    'FIELD_TYPE',
    30,
    'COLUMN',
    '["currency", "tax", "fiscal", "invoice", "payment"]',
    'ANY',
    'SOX',
    'BOOST',
    1.3,
    'Boost SOX for financial codes and identifiers',
    TRUE,
    'SYSTEM'
);

-- Rule 14: Currency/ISO Code Fields → SOX
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Currency/ISO Code Fields - Boost SOX',
    'FIELD_TYPE',
    30,
    'COLUMN',
    '["currency", "iso_code"]',
    'ANY',
    'SOX',
    'BOOST',
    1.4,
    'Boost SOX for currency and ISO code fields',
    TRUE,
    'SYSTEM'
);

-- Rule 15: Strict PII Enforcement
INSERT INTO CLASSIFICATION_RULES (
    RULE_NAME, RULE_TYPE, PRIORITY, MATCH_SCOPE, MATCH_KEYWORDS, MATCH_LOGIC,
    EXCLUDE_KEYWORDS,
    TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR,
    DESCRIPTION, IS_ACTIVE, CREATED_BY
) VALUES (
    'Strict PII Enforcement',
    'FIELD_TYPE',
    5,  -- High priority
    'COLUMN',
    '["email", "birth", "dob", "ssn", "social_security", "passport", "license", "gender", "ethnicity", "marital", "address", "city", "state", "zip", "postal", "country"]',
    'ANY',
    '["vendor", "supplier", "company", "business", "office", "store", "branch", "merchant"]',
    'PII',
    'BOOST',
    2.0,
    'Strong PII boost for high-confidence PII fields (excluding business context)',
    TRUE,
    'SYSTEM'
);

-- ============================================================================
-- GENERIC_EXCLUSIONS - Non-Sensitive Field Patterns
-- ============================================================================

-- Exclusion 1: Status/Flag/Type Fields
INSERT INTO GENERIC_EXCLUSIONS (
    EXCLUSION_NAME, EXCLUSION_TYPE, KEYWORDS,
    REDUCE_PII_FACTOR, REDUCE_SOX_FACTOR, REDUCE_SOC2_FACTOR,
    IS_ACTIVE, CREATED_BY
) VALUES (
    'Status/Flag/Type Fields',
    'STATUS_FLAG',
    '["status", "state", "flag", "type", "mode", "method", "config", "setting"]',
    0.1, 0.2, 0.1,
    TRUE, 'SYSTEM'
);

-- Exclusion 2: Date/Time Fields (excluding DOB)
INSERT INTO GENERIC_EXCLUSIONS (
    EXCLUSION_NAME, EXCLUSION_TYPE, KEYWORDS, EXCEPTION_KEYWORDS,
    REDUCE_PII_FACTOR, REDUCE_SOX_FACTOR, REDUCE_SOC2_FACTOR,
    IS_ACTIVE, CREATED_BY
) VALUES (
    'Date/Time Fields',
    'DATE_TIME',
    '["date", "time", "at", "on", "window", "period"]',
    '["birth", "dob"]',
    0.1, 0.4, 0.2,
    TRUE, 'SYSTEM'
);

-- Exclusion 3: Generic IDs (excluding sensitive IDs)
INSERT INTO GENERIC_EXCLUSIONS (
    EXCLUSION_NAME, EXCLUSION_TYPE, KEYWORDS, EXCEPTION_KEYWORDS,
    REDUCE_PII_FACTOR, REDUCE_SOX_FACTOR, REDUCE_SOC2_FACTOR,
    IS_ACTIVE, CREATED_BY
) VALUES (
    'Generic ID Fields',
    'GENERIC_ID',
    '["_id", "id"]',
    '["tax", "ssn", "account", "card", "user", "customer", "employee", "member", "patient"]',
    0.2, 0.3, 0.2,
    TRUE, 'SYSTEM'
);

-- ============================================================================
-- TIEBREAKER_KEYWORDS - PII Keywords
-- ============================================================================

INSERT INTO TIEBREAKER_KEYWORDS (POLICY_GROUP, KEYWORD, WEIGHT, IS_ACTIVE, CREATED_BY) VALUES
('PII', 'name', 1.0, TRUE, 'SYSTEM'),
('PII', 'email', 1.0, TRUE, 'SYSTEM'),
('PII', 'phone', 1.0, TRUE, 'SYSTEM'),
('PII', 'address', 1.0, TRUE, 'SYSTEM'),
('PII', 'ssn', 1.0, TRUE, 'SYSTEM'),
('PII', 'passport', 1.0, TRUE, 'SYSTEM'),
('PII', 'license', 1.0, TRUE, 'SYSTEM'),
('PII', 'birth', 1.0, TRUE, 'SYSTEM'),
('PII', 'customer', 1.0, TRUE, 'SYSTEM'),
('PII', 'user', 1.0, TRUE, 'SYSTEM'),
('PII', 'person', 1.0, TRUE, 'SYSTEM'),
('PII', 'contact', 1.0, TRUE, 'SYSTEM'),
('PII', 'identity', 1.0, TRUE, 'SYSTEM'),
('PII', 'biometric', 1.0, TRUE, 'SYSTEM'),
('PII', 'fingerprint', 1.0, TRUE, 'SYSTEM'),
('PII', 'ethnicity', 1.0, TRUE, 'SYSTEM'),
('PII', 'voter', 1.0, TRUE, 'SYSTEM'),
('PII', 'military', 1.0, TRUE, 'SYSTEM'),
('PII', 'driver', 1.0, TRUE, 'SYSTEM'),
('PII', 'credit_card', 1.0, TRUE, 'SYSTEM'),
('PII', 'two_factor', 1.0, TRUE, 'SYSTEM'),
('PII', 'city', 1.0, TRUE, 'SYSTEM'),
('PII', 'state', 1.0, TRUE, 'SYSTEM'),
('PII', 'zip', 1.0, TRUE, 'SYSTEM'),
('PII', 'country', 1.0, TRUE, 'SYSTEM');

-- ============================================================================
-- TIEBREAKER_KEYWORDS - SOX Keywords
-- ============================================================================

INSERT INTO TIEBREAKER_KEYWORDS (POLICY_GROUP, KEYWORD, WEIGHT, IS_ACTIVE, CREATED_BY) VALUES
('SOX', 'revenue', 1.0, TRUE, 'SYSTEM'),
('SOX', 'transaction', 1.0, TRUE, 'SYSTEM'),
('SOX', 'invoice', 1.0, TRUE, 'SYSTEM'),
('SOX', 'payment', 1.0, TRUE, 'SYSTEM'),
('SOX', 'ledger', 1.0, TRUE, 'SYSTEM'),
('SOX', 'financial', 1.0, TRUE, 'SYSTEM'),
('SOX', 'account', 1.0, TRUE, 'SYSTEM'),
('SOX', 'bank', 1.0, TRUE, 'SYSTEM'),
('SOX', 'billing', 1.0, TRUE, 'SYSTEM'),
('SOX', 'payroll', 1.0, TRUE, 'SYSTEM'),
('SOX', 'order', 1.0, TRUE, 'SYSTEM'),
('SOX', 'purchase', 1.0, TRUE, 'SYSTEM'),
('SOX', 'sale', 1.0, TRUE, 'SYSTEM'),
('SOX', 'expense', 1.0, TRUE, 'SYSTEM'),
('SOX', 'asset', 1.0, TRUE, 'SYSTEM'),
('SOX', 'liability', 1.0, TRUE, 'SYSTEM'),
('SOX', 'income', 1.0, TRUE, 'SYSTEM'),
('SOX', 'cash', 1.0, TRUE, 'SYSTEM'),
('SOX', 'audit', 1.0, TRUE, 'SYSTEM'),
('SOX', 'tax', 1.0, TRUE, 'SYSTEM'),
('SOX', 'annual_income', 1.0, TRUE, 'SYSTEM'),
('SOX', 'credit_amount', 1.0, TRUE, 'SYSTEM'),
('SOX', 'debit_amount', 1.0, TRUE, 'SYSTEM');

-- ============================================================================
-- TIEBREAKER_KEYWORDS - SOC2 Keywords
-- ============================================================================

INSERT INTO TIEBREAKER_KEYWORDS (POLICY_GROUP, KEYWORD, WEIGHT, IS_ACTIVE, CREATED_BY) VALUES
('SOC2', 'password', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'secret', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'key', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'token', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'auth', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'credential', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'session', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'login', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'permission', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'role', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'privilege', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'encryption', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'certificate', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'api_key', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'api_secret', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'oauth', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'security', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'access', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'logout', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'mfa', 1.0, TRUE, 'SYSTEM'),
('SOC2', '2fa', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'hash', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'private_key', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'public_key', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'refresh_token', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'access_token', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'jwt', 1.0, TRUE, 'SYSTEM'),
('SOC2', 'bearer', 1.0, TRUE, 'SYSTEM');

-- ============================================================================
-- ADDRESS_CONTEXT_REGISTRY - Physical Address Indicators
-- ============================================================================

INSERT INTO ADDRESS_CONTEXT_REGISTRY (
    CONTEXT_TYPE, INDICATOR_TYPE, INDICATOR_KEYWORD,
    BOOST_POLICY_GROUP, BOOST_FACTOR, SUPPRESS_POLICY_GROUP, SUPPRESS_FACTOR,
    IS_ACTIVE, CREATED_BY
) VALUES
('PHYSICAL_ADDRESS', 'POSITIVE', 'street', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'POSITIVE', 'city', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'POSITIVE', 'zip', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'POSITIVE', 'postal', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'POSITIVE', 'province', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'POSITIVE', 'country', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'POSITIVE', 'state', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'POSITIVE', 'billing_address', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'POSITIVE', 'shipping_address', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'NEGATIVE', 'ip', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'NEGATIVE', 'mac', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM'),
('PHYSICAL_ADDRESS', 'NEGATIVE', 'host', 'PII', 1.6, 'SOC2', 0.1, TRUE, 'SYSTEM');

-- ============================================================================
-- ADDRESS_CONTEXT_REGISTRY - Network Address Indicators
-- ============================================================================

INSERT INTO ADDRESS_CONTEXT_REGISTRY (
    CONTEXT_TYPE, INDICATOR_TYPE, INDICATOR_KEYWORD,
    BOOST_POLICY_GROUP, BOOST_FACTOR, SUPPRESS_POLICY_GROUP, SUPPRESS_FACTOR,
    IS_ACTIVE, CREATED_BY
) VALUES
('NETWORK_ADDRESS', 'POSITIVE', 'ip_address', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'POSITIVE', 'mac_address', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'POSITIVE', 'host', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'POSITIVE', 'port', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'POSITIVE', 'subnet', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'POSITIVE', 'gateway', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'POSITIVE', 'dns', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'POSITIVE', 'url', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'POSITIVE', 'endpoint', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'NEGATIVE', 'street', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'NEGATIVE', 'city', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM'),
('NETWORK_ADDRESS', 'NEGATIVE', 'billing', 'SOC2', 1.5, 'PII', 0.2, TRUE, 'SYSTEM');

-- ============================================================================
-- VERIFICATION
-- ============================================================================

SELECT 'CLASSIFICATION_RULES' AS TABLE_NAME, COUNT(*) AS ROW_COUNT FROM CLASSIFICATION_RULES
UNION ALL
SELECT 'TIEBREAKER_KEYWORDS', COUNT(*) FROM TIEBREAKER_KEYWORDS
UNION ALL
SELECT 'ADDRESS_CONTEXT_REGISTRY', COUNT(*) FROM ADDRESS_CONTEXT_REGISTRY
UNION ALL
SELECT 'GENERIC_EXCLUSIONS', COUNT(*) FROM GENERIC_EXCLUSIONS;

-- Show sample data
SELECT 'Sample Classification Rules:' AS INFO;
SELECT RULE_NAME, RULE_TYPE, TARGET_POLICY_GROUP, ACTION_TYPE, ACTION_FACTOR
FROM CLASSIFICATION_RULES
ORDER BY PRIORITY, RULE_ID
LIMIT 10;

SELECT 'Sample Tiebreaker Keywords by Policy Group:' AS INFO;
SELECT POLICY_GROUP, COUNT(*) AS KEYWORD_COUNT
FROM TIEBREAKER_KEYWORDS
GROUP BY POLICY_GROUP
ORDER BY POLICY_GROUP;
