<<<<<<< HEAD
=======
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

>>>>>>> origin/main
CREATE OR REPLACE TABLE SENSITIVITY_CATEGORIES (
    CATEGORY_ID STRING PRIMARY KEY,
    CATEGORY_NAME STRING NOT NULL,
    DESCRIPTION STRING,
    CONFIDENTIALITY_LEVEL NUMBER(1,0) DEFAULT 1,
    INTEGRITY_LEVEL NUMBER(1,0) DEFAULT 1,
    AVAILABILITY_LEVEL NUMBER(1,0) DEFAULT 1,
    DETECTION_THRESHOLD DOUBLE DEFAULT 0.5,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY STRING NOT NULL,
<<<<<<< HEAD
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
=======
    CREATED_AT TIMESTAMP_NTZ NOT NULL DEFAULT CURRENT_TIMESTAMP(),
>>>>>>> origin/main
    UPDATED_BY STRING,
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

<<<<<<< HEAD
-- =====================================================
-- TABLE: SENSITIVITY_WEIGHTS
-- =====================================================
CREATE OR REPLACE TABLE SENSITIVITY_WEIGHTS (
    WEIGHT_ID STRING PRIMARY KEY,
    SENSITIVITY_TYPE STRING NOT NULL,
    WEIGHT DOUBLE NOT NULL,
=======
CREATE OR REPLACE TABLE SENSITIVITY_WEIGHTS (
    WEIGHT_ID STRING PRIMARY KEY,
    SENSITIVITY_TYPE STRING NOT NULL,
    WEIGHT FLOAT NOT NULL,
>>>>>>> origin/main
    DESCRIPTION STRING,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

<<<<<<< HEAD
-- =====================================================
-- TABLE: SENSITIVITY_THRESHOLDS
-- =====================================================
CREATE OR REPLACE TABLE SENSITIVITY_THRESHOLDS (
    THRESHOLD_ID STRING PRIMARY KEY,
    THRESHOLD_NAME STRING NOT NULL,
    CONFIDENCE_LEVEL DOUBLE NOT NULL,
=======
CREATE OR REPLACE TABLE SENSITIVITY_THRESHOLDS (
    THRESHOLD_ID STRING PRIMARY KEY,
    THRESHOLD_NAME STRING NOT NULL,
    CONFIDENCE_LEVEL FLOAT NOT NULL,
>>>>>>> origin/main
    SENSITIVITY_LEVEL STRING NOT NULL,
    DESCRIPTION STRING,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

<<<<<<< HEAD
-- =====================================================
-- TABLE: SENSITIVITY_MODEL_CONFIG
-- =====================================================
=======
>>>>>>> origin/main
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

<<<<<<< HEAD
-- =====================================================
-- TABLE: SENSITIVE_PATTERNS
-- =====================================================
=======
>>>>>>> origin/main
CREATE OR REPLACE TABLE SENSITIVE_PATTERNS (
    PATTERN_ID STRING PRIMARY KEY,
    CATEGORY_ID STRING NOT NULL REFERENCES SENSITIVITY_CATEGORIES(CATEGORY_ID),
    PATTERN_NAME STRING NOT NULL,
    PATTERN_STRING STRING NOT NULL,
    DESCRIPTION STRING,
<<<<<<< HEAD
    SENSITIVITY_WEIGHT DOUBLE DEFAULT 0.5,
=======
    SENSITIVITY_WEIGHT FLOAT DEFAULT 0.5,
>>>>>>> origin/main
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

<<<<<<< HEAD
-- =====================================================
-- TABLE: SENSITIVE_KEYWORDS
-- =====================================================
=======
>>>>>>> origin/main
CREATE OR REPLACE TABLE SENSITIVE_KEYWORDS (
    KEYWORD_ID STRING PRIMARY KEY,
    CATEGORY_ID STRING NOT NULL REFERENCES SENSITIVITY_CATEGORIES(CATEGORY_ID),
    KEYWORD_STRING STRING NOT NULL,
    MATCH_TYPE STRING DEFAULT 'EXACT',
<<<<<<< HEAD
    SENSITIVITY_WEIGHT DOUBLE DEFAULT 0.5,
=======
    SENSITIVITY_WEIGHT FLOAT DEFAULT 0.5,
>>>>>>> origin/main
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY STRING,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

<<<<<<< HEAD
-- =====================================================
-- TABLE: SENSITIVE_BUNDLES
-- =====================================================
=======
>>>>>>> origin/main
CREATE OR REPLACE TABLE SENSITIVE_BUNDLES (
    BUNDLE_ID STRING PRIMARY KEY,
    BUNDLE_NAME STRING NOT NULL,
    DESCRIPTION STRING,
    COLUMNS VARIANT,
    MIN_MATCH_COUNT INTEGER DEFAULT 1,
<<<<<<< HEAD
    CONFIDENCE_BOOST DOUBLE DEFAULT 0.1,
=======
    CONFIDENCE_BOOST FLOAT DEFAULT 0.1,
>>>>>>> origin/main
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1
);

<<<<<<< HEAD
-- =====================================================
-- TABLE: COMPLIANCE_MAPPING
-- =====================================================
=======
>>>>>>> origin/main
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
<<<<<<< HEAD
-- ✅ SEED DATA
-- =====================================================

-- CATEGORIES
INSERT INTO SENSITIVITY_CATEGORIES (
    CATEGORY_ID, CATEGORY_NAME, DESCRIPTION,
    CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL,
    DETECTION_THRESHOLD, IS_ACTIVE, CREATED_BY
)
SELECT UUID_STRING(), 'PII', 'Personally Identifiable Information – data that can identify individuals', 5, 5, 3, 0.9, TRUE, CURRENT_USER() UNION ALL
SELECT UUID_STRING(), 'FINANCIAL', 'Financial or payment-related data such as bank accounts or card numbers', 5, 5, 4, 0.95, TRUE, CURRENT_USER() UNION ALL
SELECT UUID_STRING(), 'HEALTH', 'Health and medical data governed by HIPAA or similar regulations', 5, 4, 3, 0.9, TRUE, CURRENT_USER() UNION ALL
SELECT UUID_STRING(), 'HR', 'Human resources and employee data including personal and salary details', 4, 4, 3, 0.8, TRUE, CURRENT_USER() UNION ALL
SELECT UUID_STRING(), 'AUTH', 'Authentication or credential data such as passwords and API keys', 5, 5, 5, 1.0, TRUE, CURRENT_USER() UNION ALL
SELECT UUID_STRING(), 'SOC2', 'Data related to SOC2 security, confidentiality, and integrity controls', 4, 5, 4, 0.85, TRUE, CURRENT_USER() UNION ALL
SELECT UUID_STRING(), 'SOX', 'SOX compliance and audit control–related data', 4, 5, 4, 0.8, TRUE, CURRENT_USER() UNION ALL
SELECT UUID_STRING(), 'LEGAL', 'Legal documents, contracts, and compliance data', 3, 5, 3, 0.75, TRUE, CURRENT_USER() UNION ALL
SELECT UUID_STRING(), 'AI_MODEL', 'AI and ML model artifacts, training data, and model weights', 3, 4, 3, 0.7, TRUE, CURRENT_USER() UNION ALL
SELECT UUID_STRING(), 'INTERNAL', 'Internal operational or system data – low sensitivity', 2, 3, 3, 0.5, TRUE, CURRENT_USER();

-- =====================================================
-- ✅ SEED: SENSITIVE_KEYWORDS
-- =====================================================
INSERT INTO SENSITIVE_KEYWORDS (
    KEYWORD_ID,
    CATEGORY_ID,
    KEYWORD_STRING,
    MATCH_TYPE,
    SENSITIVITY_WEIGHT,
    IS_ACTIVE,
    CREATED_BY
)
SELECT
    UUID_STRING(),
    C.CATEGORY_ID,
    K.VALUE::STRING AS KEYWORD_STRING,
    'CONTAINS',
    0.8,
    TRUE,
    CURRENT_USER()
FROM SENSITIVITY_CATEGORIES C,
LATERAL FLATTEN(
    INPUT =>
        CASE
            WHEN C.CATEGORY_NAME = 'PII' THEN ARRAY_CONSTRUCT(
                'email','e-mail','mail_id','ssn','social_security','passport',
                'aadhaar','aadhar','driving_license','phone','mobile','contact',
                'address','residence','city','pincode','zipcode','fullname',
                'name','dob','birthdate','gender','national_id'
            )
            WHEN C.CATEGORY_NAME = 'FINANCIAL' THEN ARRAY_CONSTRUCT(
                'credit_card','card_number','cvv','iban','swift','bank_account',
                'account_number','routing_number','ifsc','upi','pan','gst','transaction_id',
                'balance','invoice','loan_number','billing'
            )
            WHEN C.CATEGORY_NAME = 'HEALTH' THEN ARRAY_CONSTRUCT(
                'diagnosis','medical_record','mrn','patient_id','disease','treatment',
                'doctor','prescription','medication','lab_result','hospital','insurance_id',
                'blood_group','vaccine','allergy'
            )
            WHEN C.CATEGORY_NAME = 'HR' THEN ARRAY_CONSTRUCT(
                'employee','emp_id','emp_code','salary','payroll','bonus','manager',
                'department','joining_date','termination_date','designation',
                'ssn','performance_review','attendance','timesheet'
            )
            WHEN C.CATEGORY_NAME = 'AUTH' THEN ARRAY_CONSTRUCT(
                'password','pwd','api_key','api-token','access_token','secret','private_key',
                'client_secret','bearer','encryption_key','auth_token','refresh_token','credential'
            )
            WHEN C.CATEGORY_NAME = 'SOC2' THEN ARRAY_CONSTRUCT(
                'audit_log','access_log','incident_id','security_event','session_id',
                'trace_id','data_integrity','policy','encryption'
            )
            WHEN C.CATEGORY_NAME = 'AI_MODEL' THEN ARRAY_CONSTRUCT(
                'model','weights','checkpoint','onnx','training_data','embedding',
                'ai_output','ml_dataset','inference','prompt','tensor'
            )
            WHEN C.CATEGORY_NAME = 'LEGAL' THEN ARRAY_CONSTRUCT(
                'contract','agreement','nda','legal_clause','jurisdiction','case_id',
                'court_order','disclaimer','liability','compliance'
            )
            WHEN C.CATEGORY_NAME = 'INTERNAL' THEN ARRAY_CONSTRUCT(
                'internal_doc','confidential','restricted','project_code','internal_use_only',
                'roadmap','strategy','internal_id'
            )
            ELSE ARRAY_CONSTRUCT()
        END
) K;


-- =====================================================
-- ✅ SEED: SENSITIVE_PATTERNS
-- =====================================================
INSERT INTO SENSITIVE_PATTERNS (
    PATTERN_ID,
    CATEGORY_ID,
    PATTERN_NAME,
    PATTERN_STRING,
    DESCRIPTION,
    SENSITIVITY_WEIGHT
)
-- 🔹 PII Patterns
SELECT UUID_STRING(), C.CATEGORY_ID, 'EMAIL_PATTERN',
       '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}',
       'Email Address Pattern', 0.9
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='PII'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'PHONE_PATTERN',
       '\\b\\+?\\d{1,3}?[-.\\s]?\\(?\\d{2,4}\\)?[-.\\s]?\\d{3,4}[-.\\s]?\\d{3,4}\\b',
       'Generic International Phone Number', 0.85
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='PII'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'AADHAAR_PATTERN',
       '\\b\\d{4}\\s\\d{4}\\s\\d{4}\\b',
       'Indian Aadhaar Number Pattern', 0.95
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='PII'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'PASSPORT_PATTERN',
       '\\b[A-PR-WYa-pr-wy][1-9]\\d{6}\\b',
       'Generic Passport Number Pattern', 0.9
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='PII'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'PAN_PATTERN',
       '\\b[A-Z]{5}[0-9]{4}[A-Z]{1}\\b',
       'Indian PAN Card Pattern', 0.9
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='PII'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'SSN_PATTERN',
       '\\b\\d{3}-\\d{2}-\\d{4}\\b',
       'US Social Security Number Pattern', 0.9
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='PII'

-- 🔹 FINANCIAL Patterns
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'CREDIT_CARD_PATTERN',
       '\\b(?:\\d[ -]*?){13,16}\\b',
       'Credit Card Number (Visa, MasterCard, etc.)', 0.95
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='FINANCIAL'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'IBAN_PATTERN',
       '\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b',
       'IBAN (International Bank Account Number)', 0.9
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='FINANCIAL'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'IFSC_PATTERN',
       '\\b[A-Z]{4}0[A-Z0-9]{6}\\b',
       'Indian IFSC Bank Code', 0.9
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='FINANCIAL'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'UPI_PATTERN',
       '\\b[a-zA-Z0-9._%+-]+@[a-zA-Z]{3,}\\b',
       'UPI ID Pattern', 0.85
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='FINANCIAL'

-- 🔹 HEALTH Patterns
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'HEALTH_INSURANCE_PATTERN',
       '\\b[A-Z]{2,3}\\d{8,10}\\b',
       'Generic Health Insurance ID Pattern', 0.8
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='HEALTH'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'MRN_PATTERN',
       '\\b[0-9]{6,10}\\b',
       'Medical Record Number Pattern', 0.75
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='HEALTH'

-- 🔹 HR Patterns
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'EMPLOYEE_ID_PATTERN',
       '\\bEMP[0-9]{4,6}\\b',
       'Employee ID Format (EMP####)', 0.8
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='HR'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'PAYSLIP_PATTERN',
       '(?i)payslip|salary\\s*statement|income\\s*summary',
       'Payslip or Salary Statement Keywords', 0.7
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='HR'

-- 🔹 AUTH Patterns
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'API_KEY_PATTERN',
       '(?i)(api[_-]?key|key|apikey)[=:]\\s*[A-Za-z0-9_\\-]{20,50}',
       'API Key Pattern', 0.95
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='AUTH'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'TOKEN_PATTERN',
       '(?i)(bearer|token|access[_-]?token)\\s+[A-Za-z0-9\\-_.]+',
       'Bearer or Access Token Pattern', 0.95
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='AUTH'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'SECRET_PATTERN',
       '(?i)(secret|password|pass|pwd)[=:]\\s*[A-Za-z0-9@#$%^&*!]{6,}',
       'Password or Secret Pattern', 1.0
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='AUTH'

-- 🔹 LEGAL Patterns
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'CONTRACT_ID_PATTERN',
       '\\bCONTRACT[-_]?[0-9]{4,8}\\b',
       'Contract ID Reference Pattern', 0.75
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='LEGAL'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'CASE_NUMBER_PATTERN',
       '\\bCASE[-_]?[0-9]{3,8}\\b',
       'Legal Case Number Pattern', 0.75
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME='LEGAL';


-- =====================================================
-- ✅ SEED: SENSITIVITY_WEIGHTS
-- =====================================================
INSERT INTO SENSITIVITY_WEIGHTS (WEIGHT_ID, SENSITIVITY_TYPE, WEIGHT, DESCRIPTION)
SELECT UUID_STRING(), 'HIGH_CONFIDENCE', 0.95, 'Matches with strong confidence' UNION ALL
SELECT UUID_STRING(), 'MEDIUM_CONFIDENCE', 0.75, 'Moderate confidence matches' UNION ALL
SELECT UUID_STRING(), 'LOW_CONFIDENCE', 0.5, 'Low confidence or partial matches' UNION ALL
SELECT UUID_STRING(), 'HEURISTIC_MATCH', 0.65, 'Detected through AI-based inference' UNION ALL
SELECT UUID_STRING(), 'PATTERN_MATCH', 0.9, 'Regex or deterministic rule-based match' UNION ALL
SELECT UUID_STRING(), 'KEYWORD_MATCH', 0.7, 'Detected through keyword-based search';

-- =====================================================
-- ✅ SEED: SENSITIVITY_THRESHOLDS
-- =====================================================
INSERT INTO SENSITIVITY_THRESHOLDS (THRESHOLD_ID, THRESHOLD_NAME, CONFIDENCE_LEVEL, SENSITIVITY_LEVEL, DESCRIPTION)
SELECT UUID_STRING(), 'Critical', 0.9, 'High', 'Highly sensitive data threshold — immediate alert or quarantine' UNION ALL
SELECT UUID_STRING(), 'Moderate', 0.7, 'Medium', 'Moderate sensitivity threshold — monitor or flag for review' UNION ALL
SELECT UUID_STRING(), 'Low', 0.5, 'Low', 'Low sensitivity threshold — safe for general use' UNION ALL
SELECT UUID_STRING(), 'Heuristic', 0.65, 'Medium', 'AI or probabilistic detection threshold' UNION ALL
SELECT UUID_STRING(), 'Strict', 0.95, 'Very High', 'Only the most confident matches are considered sensitive';

-- =====================================================
-- ✅ SEED: COMPLIANCE_MAPPING
-- =====================================================
INSERT INTO COMPLIANCE_MAPPING (MAPPING_ID, CATEGORY_ID, COMPLIANCE_STANDARD, REQUIREMENT_IDS, DESCRIPTION)
-- 🔹 PII → GDPR, CCPA, ISO 27001
SELECT UUID_STRING(), C.CATEGORY_ID, 'GDPR', PARSE_JSON('["Article 4", "Article 5", "Article 32"]'),
       'GDPR compliance for personal data handling and protection'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'PII'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'CCPA', PARSE_JSON('["1798.100", "1798.105"]'),
       'California Consumer Privacy Act compliance'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'PII'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'ISO 27001', PARSE_JSON('["A.9.2", "A.18.1.4"]'),
       'ISO 27001 controls related to personal data'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'PII'

-- 🔹 FINANCIAL → SOX, PCI DSS
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'SOX', PARSE_JSON('["404", "409"]'),
       'Sarbanes-Oxley Act compliance for financial reporting'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'FINANCIAL'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'PCI DSS', PARSE_JSON('["3.2", "3.4", "4.1"]'),
       'Payment Card Industry Data Security Standard compliance'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'FINANCIAL'

-- 🔹 HEALTH → HIPAA, ISO 27799
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'HIPAA', PARSE_JSON('["164.306", "164.308", "164.312"]'),
       'HIPAA compliance for Protected Health Information (PHI)'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'HEALTH'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'ISO 27799', PARSE_JSON('["8.2", "8.3"]'),
       'ISO standard for health information security management'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'HEALTH'

-- 🔹 HR → GDPR, SOC2
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'GDPR', PARSE_JSON('["Article 9", "Article 88"]'),
       'GDPR protections for employee and HR data'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'HR'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'SOC2', PARSE_JSON('["CC6.1", "CC7.2"]'),
       'SOC2 control requirements for access and confidentiality of HR data'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'HR'

-- 🔹 AUTH → SOC2, ISO 27001
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'SOC2', PARSE_JSON('["CC6.1", "CC7.1"]'),
       'SOC2 Trust Service Criteria for authentication and access management'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'AUTH'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'ISO 27001', PARSE_JSON('["A.9.4", "A.10.1"]'),
       'ISO 27001 control for credential protection'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'AUTH'

-- 🔹 SOC2 → SOC2, ISO 27018
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'SOC2', PARSE_JSON('["CC1.1", "CC2.1", "CC3.2"]'),
       'SOC2 controls for data security and confidentiality'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'SOC2'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'ISO 27018', PARSE_JSON('["10.1", "11.2"]'),
       'ISO 27018 cloud privacy controls'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'SOC2'

-- 🔹 SOX → SOX, ISO 22301
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'SOX', PARSE_JSON('["302", "404", "409"]'),
       'SOX compliance for audit and internal control systems'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'SOX'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'ISO 22301', PARSE_JSON('["8.4", "9.1"]'),
       'Business continuity and operational resilience'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'SOX'

-- 🔹 LEGAL → GDPR, ISO 27001
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'GDPR', PARSE_JSON('["Article 28", "Article 30"]'),
       'GDPR obligations for contracts and processing records'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'LEGAL'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'ISO 27001', PARSE_JSON('["A.18.1.1", "A.18.1.3"]'),
       'ISO controls for legal and regulatory compliance'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'LEGAL'

-- 🔹 AI_MODEL → EU AI Act, NIST AI RMF
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'EU AI ACT', PARSE_JSON('["Article 10", "Article 13"]'),
       'EU AI Act compliance for model transparency and data usage'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'AI_MODEL'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'NIST AI RMF', PARSE_JSON('["1.1", "2.2"]'),
       'AI Risk Management Framework compliance'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'AI_MODEL'

-- 🔹 INTERNAL → ISO 27001, NIST SP 800-53
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'ISO 27001', PARSE_JSON('["A.8.1.1", "A.8.1.2"]'),
       'Internal data management and access control'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'INTERNAL'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'NIST SP 800-53', PARSE_JSON('["AC-1", "MP-2"]'),
       'NIST control mapping for internal data security'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'INTERNAL';


-- ==============================================
-- Additional governance DDL (canonical alignment)
-- ==============================================

-- Align existing tables to canonical schema expected by pipeline
ALTER TABLE IF EXISTS SENSITIVE_PATTERNS ADD COLUMN IF NOT EXISTS PATTERN_REGEX STRING;
ALTER TABLE IF EXISTS SENSITIVE_PATTERNS ADD COLUMN IF NOT EXISTS SENSITIVITY_TYPE STRING;
ALTER TABLE IF EXISTS SENSITIVE_PATTERNS ADD COLUMN IF NOT EXISTS EXAMPLE STRING;

ALTER TABLE IF EXISTS SENSITIVE_KEYWORDS ADD COLUMN IF NOT EXISTS KEYWORD STRING;
ALTER TABLE IF EXISTS SENSITIVE_KEYWORDS ADD COLUMN IF NOT EXISTS SCORE FLOAT;
ALTER TABLE IF EXISTS SENSITIVE_KEYWORDS ADD COLUMN IF NOT EXISTS SENSITIVITY_TYPE STRING;
ALTER TABLE IF EXISTS SENSITIVE_KEYWORDS ADD COLUMN IF NOT EXISTS SCOPE STRING;

ALTER TABLE IF EXISTS SENSITIVITY_CATEGORIES ADD COLUMN IF NOT EXISTS PARENT_CATEGORY STRING;
ALTER TABLE IF EXISTS SENSITIVITY_CATEGORIES ADD COLUMN IF NOT EXISTS DEFAULT_THRESHOLD FLOAT;

ALTER TABLE IF EXISTS SENSITIVITY_THRESHOLDS ADD COLUMN IF NOT EXISTS NAME STRING;
ALTER TABLE IF EXISTS SENSITIVITY_THRESHOLDS ADD COLUMN IF NOT EXISTS VALUE FLOAT;
ALTER TABLE IF EXISTS SENSITIVITY_THRESHOLDS ADD COLUMN IF NOT EXISTS APPLIES_TO STRING;

ALTER TABLE IF EXISTS SENSITIVITY_WEIGHTS ADD COLUMN IF NOT EXISTS SOURCE STRING;

ALTER TABLE IF EXISTS SENSITIVE_BUNDLES ADD COLUMN IF NOT EXISTS PATTERN_IDS_ARRAY ARRAY;
ALTER TABLE IF EXISTS SENSITIVE_BUNDLES ADD COLUMN IF NOT EXISTS KEYWORD_IDS_ARRAY ARRAY;

ALTER TABLE IF EXISTS COMPLIANCE_MAPPING ADD COLUMN IF NOT EXISTS SENSITIVITY_TYPE STRING;
ALTER TABLE IF EXISTS COMPLIANCE_MAPPING ADD COLUMN IF NOT EXISTS COMPLIANCE_FRAMEWORK STRING;
ALTER TABLE IF EXISTS COMPLIANCE_MAPPING ADD COLUMN IF NOT EXISTS REQUIRED_ACTIONS STRING;

ALTER TABLE IF EXISTS SENSITIVITY_MODEL_CONFIG ADD COLUMN IF NOT EXISTS MODEL_PROVIDER STRING;
ALTER TABLE IF EXISTS SENSITIVITY_MODEL_CONFIG ADD COLUMN IF NOT EXISTS PROMPT_TEMPLATE STRING;
ALTER TABLE IF EXISTS SENSITIVITY_MODEL_CONFIG ADD COLUMN IF NOT EXISTS TEMPERATURE FLOAT;
ALTER TABLE IF EXISTS SENSITIVITY_MODEL_CONFIG ADD COLUMN IF NOT EXISTS MAX_TOKENS NUMBER;
ALTER TABLE IF EXISTS SENSITIVITY_MODEL_CONFIG ADD COLUMN IF NOT EXISTS RESPONSE_SCHEMA VARIANT;

-- Control tables
CREATE TABLE IF NOT EXISTS DETECTION_ALLOWLIST (
  FQN STRING PRIMARY KEY,
  CREATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
  CREATED_BY STRING DEFAULT CURRENT_USER()
);

CREATE TABLE IF NOT EXISTS DETECTION_BLOCKLIST (
  FQN STRING PRIMARY KEY,
  CREATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
  CREATED_BY STRING DEFAULT CURRENT_USER()
);

CREATE TABLE IF NOT EXISTS FALSE_POSITIVE_EXCEPTIONS (
  FQN STRING PRIMARY KEY,
  EXPLANATION STRING,
  CREATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
  CREATED_BY STRING DEFAULT CURRENT_USER()
);

-- Canonical results tables
CREATE TABLE IF NOT EXISTS AI_ASSISTANT_SENSITIVE_ASSETS (
  RUN_ID STRING,
  DATABASE_NAME STRING,
  SCHEMA_NAME STRING,
  TABLE_NAME STRING,
  COLUMN_NAME STRING,
  DETECTED_CATEGORY STRING,
  DETECTED_TYPE STRING,
  COMBINED_CONFIDENCE FLOAT,
  METHODS_USED ARRAY,
  COMPLIANCE_TAGS ARRAY,
  SAMPLE_METADATA VARIANT,
  DETECTION_REASON STRING,
  LAST_SCAN_TS TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
  PRIMARY KEY (DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME)
);

CREATE TABLE IF NOT EXISTS AI_ASSISTANT_SENSITIVE_ASSETS_HISTORY LIKE AI_ASSISTANT_SENSITIVE_ASSETS;

-- Canonical views
CREATE OR REPLACE VIEW VW_SENSITIVE_PATTERNS_CANONICAL AS
SELECT 
  PATTERN_ID,
  COALESCE(PATTERN_REGEX, PATTERN_STRING) AS PATTERN_REGEX,
  PATTERN_NAME,
  COALESCE(SENSITIVITY_TYPE, CATEGORY_ID) AS SENSITIVITY_TYPE,
  EXAMPLE,
  SENSITIVITY_WEIGHT,
  IS_ACTIVE,
  CREATED_AT,
  UPDATED_AT
FROM SENSITIVE_PATTERNS;

CREATE OR REPLACE VIEW VW_SENSITIVE_KEYWORDS_CANONICAL AS
SELECT 
  KEYWORD_ID,
  COALESCE(KEYWORD, KEYWORD_STRING) AS KEYWORD,
  COALESCE(SCORE, SENSITIVITY_WEIGHT) AS SCORE,
  COALESCE(SENSITIVITY_TYPE, CATEGORY_ID) AS SENSITIVITY_TYPE,
  COALESCE(SCOPE, 'column_name') AS SCOPE,
  IS_ACTIVE,
  CREATED_AT,
  UPDATED_AT
FROM SENSITIVE_KEYWORDS;

CREATE OR REPLACE VIEW VW_SENSITIVITY_THRESHOLDS_CANONICAL AS
SELECT 
  THRESHOLD_ID,
  COALESCE(NAME, THRESHOLD_NAME) AS NAME,
  COALESCE(VALUE, CONFIDENCE_LEVEL) AS VALUE,
  COALESCE(APPLIES_TO, SENSITIVITY_LEVEL) AS APPLIES_TO,
  DESCRIPTION,
  IS_ACTIVE
FROM SENSITIVITY_THRESHOLDS;

CREATE OR REPLACE VIEW VW_SENSITIVITY_WEIGHTS_CANONICAL AS
SELECT 
  WEIGHT_ID,
  COALESCE(SOURCE, SENSITIVITY_TYPE) AS SOURCE,
  WEIGHT,
  DESCRIPTION,
  IS_ACTIVE
FROM SENSITIVITY_WEIGHTS;

CREATE OR REPLACE VIEW VW_SENSITIVITY_MODEL_CONFIG_CANONICAL AS
SELECT 
  MODEL_ID,
  COALESCE(MODEL_PROVIDER, 'OpenAI') AS MODEL_PROVIDER,
  MODEL_NAME,
  MODEL_VERSION,
  MODEL_TYPE,
  COALESCE(PROMPT_TEMPLATE, TRY_TO_VARCHAR(CONFIGURATION)) AS PROMPT_TEMPLATE,
  COALESCE(TEMPERATURE, 0.0) AS TEMPERATURE,
  COALESCE(MAX_TOKENS, 800) AS MAX_TOKENS,
  RESPONSE_SCHEMA,
  IS_ACTIVE
FROM SENSITIVITY_MODEL_CONFIG;
=======
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
    UNION ALL SELECT UUID_STRING(), 'INTERNAL', 'currency_key', 'EXACT', 1.0, TRUE, CURRENT_USER(), CURRENT_TIMESTAMP(), 1
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
>>>>>>> origin/main
