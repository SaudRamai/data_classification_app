-- ============================================================================
-- DATA CLASSIFICATION GOVERNANCE - DATABASE SCHEMA
-- ============================================================================
-- Description: Complete DDL script for Data Classification Governance tables
-- Database: DATA_CLASSIFICATION_DB
-- Schema: DATA_CLASSIFICATION_GOVERNANCE
-- Version: 1.0
-- Created: 2026-02-04
-- ============================================================================

-- Prerequisites:
-- 1. Ensure the database and schema exist
-- 2. Ensure the required tags exist in DATA_CLASSIFICATION_DB.DATA_GOVERNANCE schema
-- 3. Execute with appropriate privileges (CREATE TABLE, CREATE TAG, etc.)

-- ============================================================================
-- STEP 1: Create Database and Schema (if not exists)
-- ============================================================================

CREATE DATABASE IF NOT EXISTS DATA_CLASSIFICATION_DB;
CREATE SCHEMA IF NOT EXISTS DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE;
CREATE SCHEMA IF NOT EXISTS DATA_CLASSIFICATION_DB.DATA_GOVERNANCE;

-- ============================================================================
-- STEP 2: Create Tags (if not exists)
-- ============================================================================

-- DATA CLASSIFICATION APP SCHEMA DEFINITIONS
-- ============================================================================
-- Description: Core schema definitions for Data Classification Governance
-- This file contains DDL for all governance tables with dynamic database context
-- ============================================================================

-- Note: In Snowflake Native App context, database names should be dynamic
-- Use {db_name} and {schema_name} placeholders for dynamic substitution
-- Default values: db_name = 'DATA_CLASSIFICATION_DB', schema_name = 'DATA_CLASSIFICATION_GOVERNANCE'

-- ============================================================================
-- TAG DEFINITIONS
-- ============================================================================

CREATE TAG IF NOT EXISTS {db_name}.{schema_name}.COMPLIANCE_FRAMEWORKS
    ALLOWED_VALUES 'SOC', 'SOX', 'GDPR', 'HIPAA', 'PCI-DSS';

CREATE TAG IF NOT EXISTS {db_name}.{schema_name}.DATA_CLASSIFICATION
    ALLOWED_VALUES 'Public', 'Internal', 'Confidential', 'Restricted';

CREATE TAG IF NOT EXISTS {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL
    ALLOWED_VALUES 'C1', 'C2', 'C3';

CREATE TAG IF NOT EXISTS {db_name}.{schema_name}.INTEGRITY_LEVEL
    ALLOWED_VALUES 'I1', 'I2', 'I3';

CREATE TAG IF NOT EXISTS {db_name}.{schema_name}.AVAILABILITY_LEVEL
    ALLOWED_VALUES 'A1', 'A2', 'A3';

-- ============================================================================
-- STEP 3: Create Tables
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table: SENSITIVITY_CATEGORIES
-- Description: Master table for sensitivity category definitions
-- Dependencies: None (Referenced by SENSITIVE_PATTERNS)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.SENSITIVITY_CATEGORIES (
    CATEGORY_ID VARCHAR(16777216) NOT NULL,
    CATEGORY_NAME VARCHAR(16777216) NOT NULL,
    DESCRIPTION VARCHAR(16777216),
    CONFIDENTIALITY_LEVEL NUMBER(1,0) DEFAULT 1,
    INTEGRITY_LEVEL NUMBER(1,0) DEFAULT 1,
    AVAILABILITY_LEVEL NUMBER(1,0) DEFAULT 1,
    DETECTION_THRESHOLD FLOAT DEFAULT 0.5,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(16777216) NOT NULL,
    CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(16777216),
    UPDATED_AT TIMESTAMP_NTZ(9),
    VERSION_NUMBER NUMBER(38,0) DEFAULT 1,
    POLICY_GROUP VARCHAR(50),
    WEIGHT_EMBEDDING FLOAT DEFAULT 0.6,
    WEIGHT_KEYWORD FLOAT DEFAULT 0.25,
    WEIGHT_PATTERN FLOAT DEFAULT 0.15,
    MULTI_LABEL BOOLEAN DEFAULT TRUE,
    PRIMARY KEY (CATEGORY_ID)
);

COMMENT ON TABLE {db_name}.{schema_name}.SENSITIVITY_CATEGORIES IS 
    'Master table containing sensitivity category definitions with CIA levels and detection thresholds';

-- ----------------------------------------------------------------------------
-- ============================================================================
-- DATA CLASSIFICATION APP SCHEMA DEFINITIONS
-- ============================================================================
-- Description: Core schema definitions for Data Classification Governance
-- This file contains DDL for all governance tables with dynamic database context
-- ============================================================================

-- Note: In Snowflake Native App context, database names should be dynamic
-- Use {db_name} and {schema_name} placeholders for dynamic substitution

-- Table: ASSETS
-- Description: Core asset registry for data classification
-- Dependencies: None (Referenced by CLASSIFICATION_HISTORY)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.ASSETS (
    ASSET_ID VARCHAR(100) NOT NULL,
    ASSET_NAME VARCHAR(500) NOT NULL,
    ASSET_TYPE VARCHAR(50) NOT NULL,
    DATABASE_NAME VARCHAR(255),
    SCHEMA_NAME VARCHAR(255),
    OBJECT_NAME VARCHAR(255),
    FULLY_QUALIFIED_NAME VARCHAR(1000),
    BUSINESS_UNIT VARCHAR(100),
    DATA_OWNER VARCHAR(100) NOT NULL,
    DATA_OWNER_EMAIL VARCHAR(255),
    DATA_CUSTODIAN VARCHAR(100),
    DATA_CUSTODIAN_EMAIL VARCHAR(255),
    BUSINESS_PURPOSE VARCHAR(2000),
    DATA_DESCRIPTION VARCHAR(4000),
    BUSINESS_DOMAIN VARCHAR(100),
    LIFECYCLE VARCHAR(50) DEFAULT 'Active',
    CLASSIFICATION_LABEL VARCHAR(20) WITH TAG ({db_name}.{schema_name}.DATA_CLASSIFICATION='Confidential'),
    CLASSIFICATION_LABEL_COLOR VARCHAR(20),
    CONFIDENTIALITY_LEVEL VARCHAR(2) WITH TAG ({db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C3'),
    INTEGRITY_LEVEL VARCHAR(2) WITH TAG ({db_name}.{schema_name}.INTEGRITY_LEVEL='I3'),
    AVAILABILITY_LEVEL VARCHAR(2) WITH TAG ({db_name}.{schema_name}.AVAILABILITY_LEVEL='A3'),
    OVERALL_RISK_CLASSIFICATION VARCHAR(20),
    PII_RELEVANT BOOLEAN DEFAULT FALSE,
    SOX_RELEVANT BOOLEAN DEFAULT FALSE,
    SOC2_RELEVANT BOOLEAN DEFAULT FALSE,
    CLASSIFICATION_RATIONALE VARCHAR(4000),
    CONFIDENTIALITY_IMPACT_ASSESSMENT VARCHAR(2000),
    INTEGRITY_IMPACT_ASSESSMENT VARCHAR(2000),
    AVAILABILITY_IMPACT_ASSESSMENT VARCHAR(2000),
    CLASSIFICATION_DATE TIMESTAMP_NTZ(9),
    CLASSIFIED_BY VARCHAR(100),
    CLASSIFICATION_METHOD VARCHAR(50),
    LAST_RECLASSIFICATION_DATE TIMESTAMP_NTZ(9),
    RECLASSIFICATION_TRIGGER VARCHAR(500),
    RECLASSIFICATION_COUNT NUMBER(10,0) DEFAULT 0,
    PREVIOUS_CLASSIFICATION_LABEL VARCHAR(20),
    LAST_REVIEW_DATE TIMESTAMP_NTZ(9),
    NEXT_REVIEW_DATE TIMESTAMP_NTZ(9),
    REVIEW_FREQUENCY_DAYS NUMBER(10,0) DEFAULT 365,
    REVIEW_STATUS VARCHAR(50),
    PEER_REVIEW_COMPLETED BOOLEAN DEFAULT FALSE,
    PEER_REVIEWER VARCHAR(100),
    MANAGEMENT_REVIEW_COMPLETED BOOLEAN DEFAULT FALSE,
    MANAGEMENT_REVIEWER VARCHAR(100),
    CONSISTENCY_CHECK_DATE TIMESTAMP_NTZ(9),
    CONSISTENCY_CHECK_STATUS VARCHAR(20),
    DATA_CREATION_DATE TIMESTAMP_NTZ(9),
    DATA_SOURCE_SYSTEM VARCHAR(255),
    DATA_RETENTION_PERIOD_DAYS NUMBER(10,0),
    SENSITIVE_DATA_USAGE_COUNT NUMBER(10,0) DEFAULT 0,
    LAST_ACCESSED_DATE TIMESTAMP_NTZ(9),
    ACCESS_FREQUENCY VARCHAR(20),
    NUMBER_OF_CONSUMERS NUMBER(10,0),
    HAS_EXCEPTION BOOLEAN DEFAULT FALSE,
    EXCEPTION_TYPE VARCHAR(100),
    EXCEPTION_JUSTIFICATION VARCHAR(2000),
    EXCEPTION_APPROVED_BY VARCHAR(100),
    EXCEPTION_APPROVAL_DATE TIMESTAMP_NTZ(9),
    EXCEPTION_EXPIRY_DATE TIMESTAMP_NTZ(9),
    EXCEPTION_MITIGATION_MEASURES VARCHAR(2000),
    COMPLIANCE_STATUS VARCHAR(20),
    NON_COMPLIANCE_REASON VARCHAR(1000),
    CORRECTIVE_ACTION_REQUIRED BOOLEAN DEFAULT FALSE,
    CORRECTIVE_ACTION_DESCRIPTION VARCHAR(2000),
    CORRECTIVE_ACTION_DUE_DATE TIMESTAMP_NTZ(9),
    CREATED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    CREATED_BY VARCHAR(100),
    LAST_MODIFIED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    LAST_MODIFIED_BY VARCHAR(100),
    RECORD_VERSION NUMBER(10,0) DEFAULT 1,
    ADDITIONAL_NOTES VARCHAR(4000),
    PRIMARY KEY (ASSET_ID)
) WITH TAG (
    {db_name}.{schema_name}.AVAILABILITY_LEVEL='A1',
    {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C1',
    {db_name}.{schema_name}.DATA_CLASSIFICATION='Internal',
    {db_name}.{schema_name}.INTEGRITY_LEVEL='I1'
);

COMMENT ON TABLE {db_name}.{schema_name}.ASSETS IS 
    'Core asset registry containing all data assets with their classification levels, ownership, and compliance information';

-- ----------------------------------------------------------------------------
-- Table: ALERT_LOGS
-- Description: Stores alerts and notifications for governance events
-- Dependencies: References ASSETS (ASSET_ID)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.ALERT_LOGS (
    ALERT_ID VARCHAR(16777216) NOT NULL,
    ALERT_TYPE VARCHAR(16777216),
    ALERT_PRIORITY VARCHAR(16777216),
    ALERT_STATUS VARCHAR(16777216),
    ASSET_ID VARCHAR(16777216),
    ALERT_TITLE VARCHAR(16777216),
    ALERT_MESSAGE VARCHAR(16777216),
    ALERT_DETAILS VARIANT,
    ASSIGNED_TO VARCHAR(16777216),
    DUE_DATE DATE,
    CREATED_BY VARCHAR(16777216),
    CREATED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    ACKNOWLEDGED_TIMESTAMP TIMESTAMP_NTZ(9),
    RESOLVED_TIMESTAMP TIMESTAMP_NTZ(9),
    RESOLUTION_NOTES VARCHAR(16777216),
    PRIMARY KEY (ALERT_ID)
) WITH TAG (
    {db_name}.{schema_name}.AVAILABILITY_LEVEL='A1',
    {db_name}.{schema_name}.COMPLIANCE_FRAMEWORKS='SOC',
    {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C1',
    {db_name}.{schema_name}.DATA_CLASSIFICATION='Internal',
    {db_name}.{schema_name}.INTEGRITY_LEVEL='I1'
);

COMMENT ON TABLE {db_name}.{schema_name}.ALERT_LOGS IS 
    'Stores governance alerts and notifications with priority, status, and resolution tracking';

-- ----------------------------------------------------------------------------
-- Table: AUDIT_LOG
-- Description: General audit log for tracking user actions
-- Dependencies: None
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.AUDIT_LOG (
    TIMESTAMP TIMESTAMP_NTZ(9),
    USER_ID VARCHAR(16777216),
    ACTION VARCHAR(16777216),
    RESOURCE_TYPE VARCHAR(16777216),
    RESOURCE_ID VARCHAR(16777216),
    DETAILS VARIANT
);

COMMENT ON TABLE {db_name}.{schema_name}.AUDIT_LOG IS 
    'General audit log for tracking all user actions and system events';

-- ----------------------------------------------------------------------------
-- Table: CLASSIFICATION_AI_RESULTS
-- Description: Stores AI/ML classification results with confidence scores
-- Dependencies: None
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.CLASSIFICATION_AI_RESULTS (
    RESULT_ID NUMBER(38,0) NOT NULL AUTOINCREMENT START 1 INCREMENT 1 NOORDER,
    SCHEMA_NAME VARCHAR(16777216),
    TABLE_NAME VARCHAR(16777216),
    COLUMN_NAME VARCHAR(16777216),
    AI_CATEGORY VARCHAR(16777216),
    SENSITIVITY_CATEGORY_ID VARCHAR(16777216),
    SEMANTIC_CATEGORY VARCHAR(16777216),
    REGEX_CONFIDENCE FLOAT,
    KEYWORD_CONFIDENCE FLOAT,
    ML_CONFIDENCE FLOAT,
    SEMANTIC_CONFIDENCE FLOAT,
    FINAL_CONFIDENCE FLOAT,
    MODEL_VERSION VARCHAR(16777216),
    DETAILS VARIANT,
    CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (RESULT_ID)
);

COMMENT ON TABLE {db_name}.{schema_name}.CLASSIFICATION_AI_RESULTS IS 
    'Stores AI/ML-based classification results with multi-source confidence scores';

-- ----------------------------------------------------------------------------
-- Table: CLASSIFICATION_AUDIT
-- Description: Audit trail specifically for classification actions
-- Dependencies: None
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.CLASSIFICATION_AUDIT (
    ID VARCHAR(16777216) DEFAULT UUID_STRING(),
    RESOURCE_ID VARCHAR(16777216),
    ACTION VARCHAR(16777216),
    ACTION_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    USER_ID VARCHAR(16777216),
    PREVIOUS_STATE VARIANT,
    NEW_STATE VARIANT,
    REASON VARCHAR(1000),
    DECISION_MAKER VARCHAR(16777216),
    APPROVAL_REQUIRED BOOLEAN,
    APPROVED_BY VARCHAR(16777216),
    APPROVAL_TIMESTAMP TIMESTAMP_NTZ(9),
    COMPLIANCE_FLAGS VARCHAR(16777216)
) WITH TAG (
    {db_name}.{schema_name}.AVAILABILITY_LEVEL='A3',
    {db_name}.{schema_name}.COMPLIANCE_FRAMEWORKS='SOC',
    {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C3',
    {db_name}.{schema_name}.DATA_CLASSIFICATION='Confidential',
    {db_name}.{schema_name}.INTEGRITY_LEVEL='I3'
);

COMMENT ON TABLE {db_name}.{schema_name}.CLASSIFICATION_AUDIT IS 
    'Audit trail for classification-specific actions and decisions';

-- ----------------------------------------------------------------------------
-- Table: CLASSIFICATION_DECISIONS
-- Description: Records all classification decisions made by users
-- Dependencies: References ASSETS (ASSET_ID)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.CLASSIFICATION_DECISIONS (
    ID VARCHAR(16777216),
    ASSET_FULL_NAME VARCHAR(16777216),
    ASSET_ID VARCHAR(100),
    USER_ID VARCHAR(16777216),
    ACTION VARCHAR(16777216),
    CLASSIFICATION_LEVEL VARCHAR(16777216),
    CIA_CONF NUMBER(38,0),
    CIA_INT NUMBER(38,0),
    CIA_AVAIL NUMBER(38,0),
    RATIONALE VARCHAR(1000),
    CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ(9),
    LABEL VARCHAR(16777216),
    C NUMBER(38,0),
    I NUMBER(38,0),
    A NUMBER(38,0),
    SOURCE VARCHAR(16777216),
    STATUS VARCHAR(16777216),
    DECISION_BY VARCHAR(16777216),
    APPROVED_BY VARCHAR(16777216),
    APPROVAL_TIMESTAMP TIMESTAMP_NTZ(9),
    COMPLIANCE_FLAGS VARCHAR(16777216)
) WITH TAG (
    {db_name}.{schema_name}.AVAILABILITY_LEVEL='A3',
    {db_name}.{schema_name}.COMPLIANCE_FRAMEWORKS='SOC',
    {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C3',
    {db_name}.{schema_name}.DATA_CLASSIFICATION='Confidential',
    {db_name}.{schema_name}.INTEGRITY_LEVEL='I3'
);

COMMENT ON TABLE {db_name}.{schema_name}.CLASSIFICATION_DECISIONS IS 
    'Records all classification decisions including CIA levels, rationale, and approval workflow';

-- ----------------------------------------------------------------------------
-- Table: CLASSIFICATION_HISTORY
-- Description: Tracks historical changes to asset classifications
-- Dependencies: References ASSETS (ASSET_ID) via foreign key
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.CLASSIFICATION_HISTORY (
    HISTORY_ID VARCHAR(100) NOT NULL,
    ASSET_ID VARCHAR(100),
    ASSET_FULL_NAME VARCHAR(1000),
    PREVIOUS_CLASSIFICATION VARCHAR(20),
    NEW_CLASSIFICATION VARCHAR(20),
    PREVIOUS_CONFIDENTIALITY NUMBER(38,0),
    NEW_CONFIDENTIALITY NUMBER(38,0),
    PREVIOUS_INTEGRITY NUMBER(38,0),
    NEW_INTEGRITY NUMBER(38,0),
    PREVIOUS_AVAILABILITY NUMBER(38,0),
    NEW_AVAILABILITY NUMBER(38,0),
    CHANGED_BY VARCHAR(150),
    CHANGE_REASON VARCHAR(1000),
    CHANGE_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    WAREHOUSE_NAME VARCHAR(255),
    APPROVAL_REQUIRED BOOLEAN,
    APPROVED_BY VARCHAR(150),
    APPROVAL_TIMESTAMP TIMESTAMP_NTZ(9),
    BUSINESS_JUSTIFICATION VARCHAR(1000),
    PRIMARY KEY (HISTORY_ID),
    FOREIGN KEY (ASSET_ID) REFERENCES {db_name}.{schema_name}.ASSETS(ASSET_ID)
);

COMMENT ON TABLE {db_name}.{schema_name}.CLASSIFICATION_HISTORY IS 
    'Historical record of all classification changes with before/after values and approval tracking';

-- ----------------------------------------------------------------------------
-- Table: CLASSIFICATION_REVIEW
-- Description: Manages classification review workflow
-- Dependencies: None
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.CLASSIFICATION_REVIEW (
    REVIEW_ID VARCHAR(16777216) NOT NULL DEFAULT UUID_STRING(),
    ASSET_FULL_NAME VARCHAR(16777216),
    PROPOSED_CLASSIFICATION VARCHAR(16777216),
    PROPOSED_C NUMBER(38,0),
    PROPOSED_I NUMBER(38,0),
    PROPOSED_A NUMBER(38,0),
    REVIEWER VARCHAR(16777216),
    STATUS VARCHAR(16777216),
    CREATED_BY VARCHAR(16777216),
    CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ(9),
    REVIEW_DUE_DATE TIMESTAMP_NTZ(9),
    LAST_COMMENT VARCHAR(16777216),
    RISK_SCORE NUMBER(38,2),
    PRIMARY KEY (REVIEW_ID)
);

COMMENT ON TABLE {db_name}.{schema_name}.CLASSIFICATION_REVIEW IS 
    'Manages the classification review workflow with proposed changes and reviewer assignments';

-- ----------------------------------------------------------------------------
-- Table: CLASSIFICATION_TASKS
-- Description: Task management for classification assignments
-- Dependencies: None
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.CLASSIFICATION_TASKS (
    TASK_ID VARCHAR(16777216),
    DATASET_NAME VARCHAR(16777216),
    ASSET_FULL_NAME VARCHAR(16777216),
    ASSIGNED_TO VARCHAR(16777216),
    STATUS VARCHAR(16777216),
    CONFIDENTIALITY_LEVEL VARCHAR(16777216),
    INTEGRITY_LEVEL VARCHAR(16777216),
    AVAILABILITY_LEVEL VARCHAR(16777216),
    DUE_DATE DATE,
    CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ(9),
    DETAILS VARIANT
) WITH TAG (
    {db_name}.{schema_name}.AVAILABILITY_LEVEL='A3',
    {db_name}.{schema_name}.COMPLIANCE_FRAMEWORKS='SOC',
    {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C3',
    {db_name}.{schema_name}.DATA_CLASSIFICATION='Confidential',
    {db_name}.{schema_name}.INTEGRITY_LEVEL='I3'
);

COMMENT ON TABLE {db_name}.{schema_name}.CLASSIFICATION_TASKS IS 
    'Task management table for classification assignments with status tracking';

-- ----------------------------------------------------------------------------
-- Table: LABEL_REGISTRY
-- Description: Master registry of classification labels
-- Dependencies: None
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.LABEL_REGISTRY (
    LABEL_NAME VARCHAR(16777216) NOT NULL,
    DESCRIPTION VARCHAR(16777216),
    COLOR VARCHAR(16777216),
    DEFAULT_C NUMBER(38,0),
    DEFAULT_I NUMBER(38,0),
    DEFAULT_A NUMBER(38,0),
    ENFORCEMENT_POLICY VARCHAR(16777216),
    PRIMARY KEY (LABEL_NAME)
) WITH TAG (
    {db_name}.{schema_name}.AVAILABILITY_LEVEL='A3',
    {db_name}.{schema_name}.COMPLIANCE_FRAMEWORKS='SOC',
    {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C3',
    {db_name}.{schema_name}.DATA_CLASSIFICATION='Confidential',
    {db_name}.{schema_name}.INTEGRITY_LEVEL='I3'
);

COMMENT ON TABLE {db_name}.{schema_name}.LABEL_REGISTRY IS 
    'Master registry of classification labels with default CIA levels and enforcement policies';

-- ----------------------------------------------------------------------------
-- Table: POLICIES
-- Description: Stores governance policies and documents
-- Dependencies: None
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.POLICIES (
    POLICY_ID VARCHAR(16777216) NOT NULL DEFAULT UUID_STRING(),
    POLICY_NAME VARCHAR(16777216) NOT NULL,
    POLICY_VERSION VARCHAR(16777216),
    POLICY_TYPE VARCHAR(16777216),
    DOCUMENT_CLASSIFICATION VARCHAR(16777216),
    EFFECTIVE_DATE DATE,
    NEXT_REVIEW_DATE DATE,
    DOCUMENT_OWNER VARCHAR(16777216),
    APPROVAL_AUTHORITY VARCHAR(16777216),
    BUSINESS_UNIT VARCHAR(16777216),
    POLICY_CONTENT VARCHAR(16777216),
    FILE_CONTENT VARIANT,
    FILE_NAME VARCHAR(16777216),
    FILE_SIZE NUMBER(38,0),
    MIME_TYPE VARCHAR(16777216),
    CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    CREATED_BY VARCHAR(16777216) DEFAULT CURRENT_USER(),
    UPDATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(16777216) DEFAULT CURRENT_USER(),
    STATUS VARCHAR(16777216) DEFAULT 'ACTIVE',
    PRIMARY KEY (POLICY_ID)
) WITH TAG (
    {db_name}.{schema_name}.AVAILABILITY_LEVEL='A3',
    {db_name}.{schema_name}.COMPLIANCE_FRAMEWORKS='SOC',
    {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C3',
    {db_name}.{schema_name}.DATA_CLASSIFICATION='Confidential',
    {db_name}.{schema_name}.INTEGRITY_LEVEL='I3'
);

COMMENT ON TABLE {db_name}.{schema_name}.POLICIES IS 
    'Stores governance policies including document content, versioning, and review schedules';

-- ----------------------------------------------------------------------------
-- Table: RECLASSIFICATION_REQUESTS
-- Description: Manages reclassification request workflow
-- Dependencies: References ASSETS (ASSET_ID)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.RECLASSIFICATION_REQUESTS (
    ID VARCHAR(16777216),
    ASSET_FULL_NAME VARCHAR(16777216),
    ASSET_ID VARCHAR(100),
    TRIGGER_TYPE VARCHAR(16777216),
    CURRENT_CLASSIFICATION VARCHAR(16777216),
    CURRENT_C NUMBER(38,0),
    CURRENT_I NUMBER(38,0),
    CURRENT_A NUMBER(38,0),
    PROPOSED_CLASSIFICATION VARCHAR(16777216),
    PROPOSED_C NUMBER(38,0),
    PROPOSED_I NUMBER(38,0),
    PROPOSED_A NUMBER(38,0),
    STATUS VARCHAR(16777216),
    VERSION NUMBER(38,0),
    JUSTIFICATION VARCHAR(16777216),
    CREATED_BY VARCHAR(16777216),
    APPROVED_BY VARCHAR(16777216),
    CREATED_AT TIMESTAMP_NTZ(9),
    UPDATED_AT TIMESTAMP_NTZ(9),
    REQUESTER VARCHAR(16777216)
) WITH TAG (
    {db_name}.{schema_name}.AVAILABILITY_LEVEL='A3',
    {db_name}.{schema_name}.COMPLIANCE_FRAMEWORKS='SOC',
    {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C3',
    {db_name}.{schema_name}.DATA_CLASSIFICATION='Confidential',
    {db_name}.{schema_name}.INTEGRITY_LEVEL='I3'
);

COMMENT ON TABLE {db_name}.{schema_name}.RECLASSIFICATION_REQUESTS IS 
    'Manages reclassification requests with current/proposed values and approval workflow';

-- ----------------------------------------------------------------------------
-- Table: RECLASSIFICATION_WORKFLOW_LOG
-- Description: Audit log for reclassification workflow actions
-- Dependencies: None
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.RECLASSIFICATION_WORKFLOW_LOG (
    ID VARCHAR(16777216),
    REQUEST_ID VARCHAR(16777216),
    ACTION VARCHAR(16777216),
    OLD_STATUS VARCHAR(16777216),
    NEW_STATUS VARCHAR(16777216),
    ACTOR VARCHAR(16777216),
    COMMENT VARCHAR(16777216),
    CREATED_AT TIMESTAMP_NTZ(9)
);

COMMENT ON TABLE DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.RECLASSIFICATION_WORKFLOW_LOG IS 
    'Audit log tracking all actions and status transitions in the reclassification workflow';

-- ----------------------------------------------------------------------------
-- Table: SENSITIVE_KEYWORDS
-- Description: Keywords used for sensitive data detection
-- Dependencies: References SENSITIVITY_CATEGORIES (CATEGORY_ID)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE TABLE {db_name}.{schema_name}.SENSITIVE_KEYWORDS (
    KEYWORD_ID VARCHAR(16777216),
    CATEGORY_ID VARCHAR(16777216),
    KEYWORD_STRING VARCHAR(16777216),
    MATCH_TYPE VARCHAR(16777216),
    SENSITIVITY_WEIGHT FLOAT,
    IS_ACTIVE BOOLEAN,
    CREATED_BY VARCHAR(16777216),
    CREATED_AT TIMESTAMP_NTZ(9),
    UPDATED_AT TIMESTAMP_NTZ(9),
    VERSION_NUMBER NUMBER(38,0)
) WITH TAG (
    {db_name}.{schema_name}.AVAILABILITY_LEVEL='A3',
    {db_name}.{schema_name}.COMPLIANCE_FRAMEWORKS='SOC',
    {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C3',
    {db_name}.{schema_name}.DATA_CLASSIFICATION='Confidential',
    {db_name}.{schema_name}.INTEGRITY_LEVEL='I3'
);

COMMENT ON TABLE {db_name}.{schema_name}.SENSITIVE_KEYWORDS IS 
    'Keywords used for detecting sensitive data with category associations and weights';

-- ----------------------------------------------------------------------------
-- Table: SENSITIVE_PATTERNS
-- Description: Regex patterns for sensitive data detection
-- Dependencies: References SENSITIVITY_CATEGORIES (CATEGORY_ID) via foreign key
-- Note: Requires masking policy MASK_REDACT_STRING to exist
-- ----------------------------------------------------------------------------
-- First, create the masking policy if it doesn't exist
CREATE MASKING POLICY IF NOT EXISTS DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.MASK_REDACT_STRING AS (val STRING) 
RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'SYSADMIN', 'DATA_GOVERNANCE_ADMIN') THEN val
        ELSE '***REDACTED***'
    END;

CREATE OR REPLACE TABLE {db_name}.{schema_name}.SENSITIVE_PATTERNS (
    PATTERN_ID VARCHAR(16777216) NOT NULL,
    CATEGORY_ID VARCHAR(16777216) NOT NULL,
    PATTERN_NAME VARCHAR(16777216) NOT NULL WITH MASKING POLICY {db_name}.{schema_name}.MASK_REDACT_STRING,
    DESCRIPTION VARCHAR(16777216),
    SENSITIVITY_WEIGHT FLOAT DEFAULT 0.5,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ(9),
    VERSION_NUMBER NUMBER(38,0) DEFAULT 1,
    PATTERN_REGEX VARCHAR(16777216),
    SENSITIVITY_TYPE VARCHAR(16777216),
    EXAMPLE VARCHAR(16777216),
    PRIMARY KEY (PATTERN_ID),
    FOREIGN KEY (CATEGORY_ID) REFERENCES {db_name}.{schema_name}.SENSITIVITY_CATEGORIES(CATEGORY_ID)
) WITH TAG (
    {db_name}.{schema_name}.AVAILABILITY_LEVEL='A1',
    {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C1',
    {db_name}.{schema_name}.DATA_CLASSIFICATION='Internal',
    {db_name}.{schema_name}.INTEGRITY_LEVEL='I1'
);

COMMENT ON TABLE {db_name}.{schema_name}.SENSITIVE_PATTERNS IS 
    'Regex patterns for detecting sensitive data with category associations and examples';

-- ============================================================================
-- STEP 4: Create Indexes for Performance (Optional)
-- ============================================================================

-- ============================================================================
-- STEP 4: Create Indexes for Performance
-- ============================================================================
-- Snowflake automatically manages micro-partitions and clustering.
-- You can add explicit CLUSTER BY keys here if specific query patterns require it.

-- ============================================================================
-- STEP 5: Insert Default Data
-- ============================================================================

-- Insert default classification labels
INSERT INTO {db_name}.{schema_name}.LABEL_REGISTRY 
    (LABEL_NAME, DESCRIPTION, COLOR, DEFAULT_C, DEFAULT_I, DEFAULT_A, ENFORCEMENT_POLICY)
SELECT * FROM VALUES
    ('Public', 'Information intended for public disclosure', '#28a745', 1, 1, 1, 'NONE'),
    ('Internal', 'Internal use only - not for external distribution', '#17a2b8', 2, 2, 2, 'ROLE_BASED'),
    ('Confidential', 'Sensitive business information requiring protection', '#ffc107', 3, 3, 2, 'STRICT'),
    ('Restricted', 'Highly sensitive - maximum protection required', '#dc3545', 3, 3, 3, 'MAXIMUM')
WHERE NOT EXISTS (SELECT 1 FROM {db_name}.{schema_name}.LABEL_REGISTRY);

-- Insert default sensitivity categories
INSERT INTO {db_name}.{schema_name}.SENSITIVITY_CATEGORIES 
    (CATEGORY_ID, CATEGORY_NAME, DESCRIPTION, CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, 
     AVAILABILITY_LEVEL, DETECTION_THRESHOLD, IS_ACTIVE, CREATED_BY)
SELECT * FROM VALUES
    ('CAT_PII', 'Personal Identifiable Information', 'Data that can identify an individual', 3, 3, 2, 0.7, TRUE, 'SYSTEM'),
    ('CAT_PHI', 'Protected Health Information', 'Health-related personal information', 3, 3, 3, 0.8, TRUE, 'SYSTEM'),
    ('CAT_PCI', 'Payment Card Information', 'Credit card and payment data', 3, 3, 3, 0.9, TRUE, 'SYSTEM'),
    ('CAT_FIN', 'Financial Data', 'Financial records and transactions', 3, 3, 2, 0.7, TRUE, 'SYSTEM'),
    ('CAT_AUTH', 'Authentication Data', 'Passwords, tokens, and credentials', 3, 3, 3, 0.9, TRUE, 'SYSTEM')
WHERE NOT EXISTS (SELECT 1 FROM {db_name}.{schema_name}.SENSITIVITY_CATEGORIES);

-- ============================================================================
-- STEP 6: Grant Permissions
-- ============================================================================
-- Ensure appropriate roles (e.g., DATA_STEWARD) have USAGE on DB/Schema and SELECT/MODIFY on tables.

-- ============================================================================
-- END OF SCHEMA SCRIPT
-- ============================================================================
