-- =====================================================
-- ✅ Fixed & Validated Sensitivity Configuration Seed Script
-- Works fully with UUID_STRING()
-- =====================================================

-- 1️⃣ Create Database and Schema
CREATE DATABASE IF NOT EXISTS DATA_CLASSIFICATION_DB;
USE DATABASE DATA_CLASSIFICATION_DB;

-- Create Governance Schema
CREATE SCHEMA IF NOT EXISTS DATA_CLASSIFICATION_GOVERNANCE;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- =====================================================
-- ✅ Core Tables
-- =====================================================

CREATE OR REPLACE TABLE SENSITIVITY_CATEGORIES (
    CATEGORY_ID STRING PRIMARY KEY,
    CATEGORY_NAME STRING NOT NULL,
    DESCRIPTION STRING,
    CONFIDENTIALITY_LEVEL NUMBER(1,0) DEFAULT 1,
    INTEGRITY_LEVEL NUMBER(1,0) DEFAULT 1,
    AVAILABILITY_LEVEL NUMBER(1,0) DEFAULT 1,
    DETECTION_THRESHOLD FLOAT DEFAULT 0.5,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY STRING NOT NULL,
    CREATED_AT TIMESTAMP_NTZ NOT NULL DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY STRING,
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

CREATE OR REPLACE TABLE SENSITIVITY_WEIGHTS (
    WEIGHT_ID STRING PRIMARY KEY,
    SENSITIVITY_TYPE STRING NOT NULL,
    WEIGHT FLOAT NOT NULL,
    DESCRIPTION STRING,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

CREATE OR REPLACE TABLE SENSITIVITY_THRESHOLDS (
    THRESHOLD_ID STRING PRIMARY KEY,
    THRESHOLD_NAME STRING NOT NULL,
    CONFIDENCE_LEVEL FLOAT NOT NULL,
    SENSITIVITY_LEVEL STRING NOT NULL,
    DESCRIPTION STRING,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

CREATE OR REPLACE TABLE SENSITIVITY_MODEL_CONFIG (
    MODEL_ID STRING PRIMARY KEY,
    MODEL_NAME STRING NOT NULL,
    MODEL_VERSION STRING NOT NULL,
    MODEL_TYPE STRING NOT NULL,
    CONFIGURATION VARIANT,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

CREATE OR REPLACE TABLE SENSITIVE_PATTERNS (
    PATTERN_ID STRING PRIMARY KEY,
    CATEGORY_ID STRING NOT NULL REFERENCES SENSITIVITY_CATEGORIES(CATEGORY_ID),
    PATTERN_NAME STRING NOT NULL,
    PATTERN_STRING STRING NOT NULL,
    DESCRIPTION STRING,
    SENSITIVITY_WEIGHT FLOAT DEFAULT 0.5,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

CREATE OR REPLACE TABLE SENSITIVE_KEYWORDS (
    KEYWORD_ID STRING PRIMARY KEY,
    CATEGORY_ID STRING NOT NULL REFERENCES SENSITIVITY_CATEGORIES(CATEGORY_ID),
    KEYWORD_STRING STRING NOT NULL,
    MATCH_TYPE STRING DEFAULT 'EXACT',
    SENSITIVITY_WEIGHT FLOAT DEFAULT 0.5,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY STRING,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

CREATE OR REPLACE TABLE SENSITIVE_BUNDLES (
    BUNDLE_ID STRING PRIMARY KEY,
    BUNDLE_NAME STRING NOT NULL,
    DESCRIPTION STRING,
    COLUMNS VARIANT,
    MIN_MATCH_COUNT INTEGER DEFAULT 1,
    CONFIDENCE_BOOST FLOAT DEFAULT 0.1,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

CREATE OR REPLACE TABLE COMPLIANCE_MAPPING (
    MAPPING_ID STRING PRIMARY KEY,
    CATEGORY_ID STRING NOT NULL REFERENCES SENSITIVITY_CATEGORIES(CATEGORY_ID),
    COMPLIANCE_STANDARD STRING NOT NULL,
    REQUIREMENT_IDS VARIANT,
    DESCRIPTION STRING,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

-- =====================================================
-- ✅ SEED DATA (Fixed for UUID_STRING)
-- =====================================================

-- Categories (static IDs)
INSERT INTO SENSITIVITY_CATEGORIES (CATEGORY_ID, CATEGORY_NAME, DESCRIPTION, CREATED_BY)
SELECT COLUMN1, COLUMN2, COLUMN3, COLUMN4 FROM VALUES
    ('PII', 'Personally Identifiable Information', 'Data that can identify individuals', CURRENT_USER()),
    ('FINANCIAL', 'Financial Data', 'Monetary and financial information', CURRENT_USER()),
    ('SOX', 'SOX Compliance', 'Sarbanes–Oxley related data', CURRENT_USER()),
    ('SOC2', 'SOC2 Compliance', 'Security and availability controls', CURRENT_USER()),
    ('AUTH', 'Authentication Data', 'Credentials and secrets', CURRENT_USER()),
    ('INTERNAL', 'Internal Data', 'Non-sensitive internal data', CURRENT_USER()),
    ('AI_MODEL', 'AI Model Data', 'Machine learning model information', CURRENT_USER());

-- Weights
INSERT INTO SENSITIVITY_WEIGHTS (WEIGHT_ID, SENSITIVITY_TYPE, WEIGHT, DESCRIPTION)
SELECT UUID_STRING(), 'PII', 10.0, 'High sensitivity for personal identifiers' UNION ALL
SELECT UUID_STRING(), 'FINANCIAL', 9.0, 'High sensitivity for financial data' UNION ALL
SELECT UUID_STRING(), 'AUTH', 10.0, 'Credentials, passwords, or tokens' UNION ALL
SELECT UUID_STRING(), 'SOC2', 8.0, 'Security, logging, and operational data' UNION ALL
SELECT UUID_STRING(), 'SOX', 7.5, 'Financial control and audit-related data' UNION ALL
SELECT UUID_STRING(), 'INTERNAL', 2.0, 'Non-sensitive internal data' UNION ALL
SELECT UUID_STRING(), 'AI_MODEL', 7.0, 'Machine learning artifacts and metadata' UNION ALL
SELECT UUID_STRING(), 'HR', 8.5, 'Employee-related personal and payroll data' UNION ALL
SELECT UUID_STRING(), 'LEGAL', 9.0, 'Legal and compliance-related data' UNION ALL
SELECT UUID_STRING(), 'HEALTH', 10.0, 'Medical and health information (HIPAA)';


-- Thresholds
INSERT INTO SENSITIVITY_THRESHOLDS (THRESHOLD_ID, THRESHOLD_NAME, CONFIDENCE_LEVEL, SENSITIVITY_LEVEL, DESCRIPTION)
SELECT UUID_STRING(), 'Very High', 0.95, 'CRITICAL', 'Critical sensitivity threshold' UNION ALL
SELECT UUID_STRING(), 'High', 0.9, 'HIGH', 'High sensitivity classification threshold' UNION ALL
SELECT UUID_STRING(), 'Medium', 0.7, 'MEDIUM', 'Moderate sensitivity detection threshold' UNION ALL
SELECT UUID_STRING(), 'Low', 0.5, 'LOW', 'Potential sensitivity, low confidence' UNION ALL
SELECT UUID_STRING(), 'Very Low', 0.3, 'INFORM', 'Informational sensitivity only';

-- Model Config
INSERT INTO SENSITIVITY_MODEL_CONFIG (MODEL_ID, MODEL_NAME, MODEL_VERSION, MODEL_TYPE, CONFIGURATION)
SELECT UUID_STRING(), 'TextPatternDetector', 'v1.0', 'REGEX', PARSE_JSON('{"engine": "Snowflake RegEx Engine"}') UNION ALL
SELECT UUID_STRING(), 'KeywordClassifier', 'v1.2', 'KEYWORD', PARSE_JSON('{"case_sensitive": false, "fuzzy_match": true}') UNION ALL
SELECT UUID_STRING(), 'AIModelClassifier', 'v2.0', 'ML', PARSE_JSON('{"framework": "OpenAI GPT", "threshold": 0.8}');

-- Patterns
INSERT INTO SENSITIVE_PATTERNS (PATTERN_ID, CATEGORY_ID, PATTERN_NAME, PATTERN_STRING, DESCRIPTION, SENSITIVITY_WEIGHT)
SELECT UUID_STRING(), 'PII', 'Email Pattern', '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', 'Detects email addresses', 8.0 UNION ALL
SELECT UUID_STRING(), 'PII', 'Phone Number Pattern', '\\b\\+?\\d{1,3}?[-.\\s]?\\(?\\d{1,3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b', 'Detects phone numbers', 7.5 UNION ALL
SELECT UUID_STRING(), 'PII', 'Passport Pattern', '(?i)(passport|ppn|passport_no)\\s*[:=]?\\s*\\w{6,10}', 'Passport identifiers', 9.0 UNION ALL
SELECT UUID_STRING(), 'PII', 'National ID Pattern', '(?i)(nid|national[_ ]id|aadhar|ssn)[-:\\s]*[0-9]{6,12}', 'Gov-issued national ID', 9.5 UNION ALL
SELECT UUID_STRING(), 'FINANCIAL', 'Credit Card Pattern', '\\b(?:\\d[ -]*?){13,16}\\b', 'Credit card numbers', 10.0 UNION ALL
SELECT UUID_STRING(), 'FINANCIAL', 'Account Number Pattern', '(account|acct)[-:\\s]*[0-9]{8,20}', 'Bank account numbers', 9.0 UNION ALL
SELECT UUID_STRING(), 'FINANCIAL', 'IBAN Pattern', '\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\\b', 'International bank account number', 9.0 UNION ALL
SELECT UUID_STRING(), 'AUTH', 'API Key Pattern', '(?i)api[_-]?key\\s*[:=]\\s*[A-Za-z0-9-_]{20,}', 'API keys or tokens', 9.0 UNION ALL
SELECT UUID_STRING(), 'AUTH', 'Password Field Pattern', '(?i)password\\s*[:=]\\s*[A-Za-z0-9!@#%&*]{6,}', 'Plain password fields', 10.0 UNION ALL
SELECT UUID_STRING(), 'SOC2', 'Access Log ID Pattern', '\\b(session|log|access|trace|request)_id\\b', 'Access or session logs', 7.0 UNION ALL
SELECT UUID_STRING(), 'AI_MODEL', 'Model File Pattern', '\\b(model|checkpoint|weights)\\.(pt|bin|h5|onnx)\\b', 'AI model artifacts', 7.5 UNION ALL
SELECT UUID_STRING(), 'HEALTH', 'Medical Record Pattern', '(?i)(mrn|medical[_ ]record|patient_id)\\s*[:=]?\\s*\\w{6,15}', 'Health records', 10.0 UNION ALL
SELECT UUID_STRING(), 'HR', 'Employee ID Pattern', '(?i)(emp[_ ]id|employee[_ ]number)\\s*[:=]?\\s*\\w{4,10}', 'Employee identifiers', 8.0;
SELECT UUID_STRING(), 'INTERNAL', 'System Timestamp Pattern', '(?i)(created_at|updated_at|timestamp|last_modified)\\b', 'System timestamps or audit fields', 2.0 UNION ALL
SELECT UUID_STRING(), 'INTERNAL', 'Internal Identifier Pattern', '(?i)(internal[_ ]id|ref[_ ]id|system[_ ]id|batch[_ ]id)\\b', 'Internal reference identifiers', 2.5 UNION ALL
SELECT UUID_STRING(), 'INTERNAL', 'Status Code Pattern', '(?i)(status|state|flag|code)\\b', 'System status or code fields', 1.5 UNION ALL
SELECT UUID_STRING(), 'INTERNAL', 'Audit User Pattern', '(?i)(created_by|updated_by|modified_by|owner|approver)\\b', 'Internal audit user tracking fields', 2.0 UNION ALL
SELECT UUID_STRING(), 'INTERNAL', 'Metadata Pattern', '(?i)(meta|config|param|setting|attribute)\\b', 'System configuration or metadata fields', 1.0 UNION ALL
SELECT UUID_STRING(), 'INTERNAL', 'Internal Notes Pattern', '(?i)(notes|remarks|comments|description)\\b', 'Internal remarks or descriptive text', 1.0 UNION ALL
SELECT UUID_STRING(), 'INTERNAL', 'Transaction Reference Pattern', '(?i)(txn[_ ]id|reference[_ ]no|order[_ ]id|invoice[_ ]id)\\b', 'Internal transaction or invoice references', 2.5 UNION ALL
SELECT UUID_STRING(), 'INTERNAL', 'Version Control Pattern', '(?i)(version|rev|revision|release)\\b', 'Application version or release info', 1.0;


-- Bundles
INSERT INTO SENSITIVE_BUNDLES (BUNDLE_ID, BUNDLE_NAME, DESCRIPTION, COLUMNS, MIN_MATCH_COUNT, CONFIDENCE_BOOST)
SELECT UUID_STRING(), 'User Identity Bundle', 'PII: name, email, phone', PARSE_JSON('["first_name","last_name","email","phone"]'), 2, 0.3 UNION ALL
SELECT UUID_STRING(), 'Financial Transaction Bundle', 'Financial data fields', PARSE_JSON('["account_number","transaction_amount","balance"]'), 2, 0.25 UNION ALL
SELECT UUID_STRING(), 'Auth Bundle', 'Auth tokens', PARSE_JSON('["password","api_key","secret_key"]'), 2, 0.4;

-- Compliance Mapping
INSERT INTO COMPLIANCE_MAPPING (MAPPING_ID, CATEGORY_ID, COMPLIANCE_STANDARD, REQUIREMENT_IDS, DESCRIPTION)
SELECT UUID_STRING(), 'PII', 'GDPR', PARSE_JSON('["Art.4","Art.5","Art.6","Art.9"]'), 'EU Data Privacy Regulations' UNION ALL
SELECT UUID_STRING(), 'PII', 'CCPA', PARSE_JSON('["Sec.1798.100","Sec.1798.105"]'), 'California Consumer Privacy Act' UNION ALL
SELECT UUID_STRING(), 'FINANCIAL', 'PCI-DSS', PARSE_JSON('["Req.3","Req.7","Req.8","Req.10"]'), 'Payment data protection' UNION ALL
SELECT UUID_STRING(), 'SOX', 'SOX', PARSE_JSON('["Sec.302","Sec.404","Sec.409"]'), 'Corporate financial reporting compliance' UNION ALL
SELECT UUID_STRING(), 'SOC2', 'SOC2', PARSE_JSON('["CC1.0","CC6.0","CC8.0","CC9.0"]'), 'Trust and security controls' UNION ALL
SELECT UUID_STRING(), 'AUTH', 'ISO27001', PARSE_JSON('["A.9.2","A.10.1","A.12.4"]'), 'Access control & encryption compliance' UNION ALL
SELECT UUID_STRING(), 'HR', 'GDPR', PARSE_JSON('["Art.88","Art.9"]'), 'Employee data privacy compliance' UNION ALL
SELECT UUID_STRING(), 'HEALTH', 'HIPAA', PARSE_JSON('["§164.312","§164.308"]'), 'Protected Health Information (PHI)' UNION ALL
SELECT UUID_STRING(), 'LEGAL', 'FERPA', PARSE_JSON('["§99.30","§99.31"]'), 'Education records compliance (US)';


MERGE INTO SENSITIVE_KEYWORDS AS target
USING (
    SELECT UUID_STRING() AS KEYWORD_ID, 'AI_MODEL' AS CATEGORY_ID, 'tensorflow' AS KEYWORD_STRING, 'EXACT' AS MATCH_TYPE, 0.8 AS SENSITIVITY_WEIGHT, TRUE AS IS_ACTIVE, CURRENT_USER() AS CREATED_BY, CURRENT_TIMESTAMP() AS CREATED_AT, 1 AS VERSION_NUMBER
    UNION ALL SELECT UUID_STRING(), 'AI_MODEL', 'pytorch', 'EXACT', 0.8, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'AI_MODEL', 'llm', 'EXACT', 0.9, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'PII', 'ssn', 'EXACT', 10.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'PII', 'social_security', 'EXACT', 10.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'PII', 'passport', 'EXACT', 9.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'PII', 'drivers_license', 'EXACT', 9.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'PII', 'medical_record', 'EXACT', 9.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'PII', 'address', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'PII', 'phone', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'PII', 'email', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'PII', 'date_of_birth', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'FINANCIAL', 'credit_card', 'EXACT', 10.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'FINANCIAL', 'account_number', 'EXACT', 9.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'FINANCIAL', 'routing_number', 'EXACT', 9.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'FINANCIAL', 'iban', 'EXACT', 9.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'FINANCIAL', 'swift_code', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'FINANCIAL', 'balance', 'EXACT', 7.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'FINANCIAL', 'transaction_amount', 'EXACT', 7.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOX', 'general_ledger', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOX', 'journal_entry', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOX', 'financial_statement', 'EXACT', 9.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOX', 'audit_trail', 'EXACT', 9.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOX', 'internal_control', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOX', 'revenue_recognition', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOX', 'segregation_duties', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOC2', 'encryption_key', 'EXACT', 10.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOC2', 'access_log', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOC2', 'authentication_token', 'EXACT', 9.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOC2', 'security_incident', 'EXACT', 8.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOC2', 'session_id', 'EXACT', 7.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOC2', 'firewall_rule', 'EXACT', 6.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'SOC2', 'data_retention', 'EXACT', 7.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'AUTH', 'password', 'EXACT', 10.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'AUTH', 'secret_key', 'EXACT', 10.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'AUTH', 'api_key', 'EXACT', 9.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'AUTH', 'private_key', 'EXACT', 10.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'INTERNAL', 'invoice_date', 'EXACT', 1.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'INTERNAL', 'due_date', 'EXACT', 1.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'INTERNAL', 'created_date', 'EXACT', 1.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'INTERNAL', 'updated_date', 'EXACT', 1.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'INTERNAL', 'status', 'EXACT', 1.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'INTERNAL', 'type', 'EXACT', 1.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'INTERNAL', 'category', 'EXACT', 1.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'INTERNAL', 'currency_code', 'EXACT', 1.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
    UNION ALL SELECT UUID_STRING(), 'INTERNAL', 'country_code', 'EXACT', 1.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
) AS source
ON target.KEYWORD_ID = source.KEYWORD_ID
WHEN MATCHED THEN
    UPDATE SET
        target.CATEGORY_ID = source.CATEGORY_ID,
        target.KEYWORD_STRING = source.KEYWORD_STRING,
        target.MATCH_TYPE = source.MATCH_TYPE,
        target.SENSITIVITY_WEIGHT = source.SENSITIVITY_WEIGHT,
        target.IS_ACTIVE = source.IS_ACTIVE,
        target.CREATED_BY = source.CREATED_BY,
        target.UPDATED_AT = CURRENT_TIMESTAMP(),
        target.VERSION_NUMBER = source.VERSION_NUMBER
WHEN NOT MATCHED THEN
    INSERT (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, 
            IS_ACTIVE, CREATED_BY, CREATED_AT, VERSION_NUMBER)
    VALUES (source.KEYWORD_ID, source.CATEGORY_ID, source.KEYWORD_STRING, source.MATCH_TYPE, 
            source.SENSITIVITY_WEIGHT, source.IS_ACTIVE, source.CREATED_BY, 
            source.CREATED_AT, source.VERSION_NUMBER);
