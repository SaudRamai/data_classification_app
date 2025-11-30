-- 001_governance_schema.sql
-- Create core governance schema, inventory, audit, and compliance tables

set DB = coalesce($DATABASE, current_database(), 'DATA_CLASSIFICATION_DB');
use database identifier($DB);

CREATE SCHEMA IF NOT EXISTS DATA_GOVERNANCE;
CREATE SCHEMA IF NOT EXISTS DATA_CLASSIFICATION_GOVERNANCE;

-- ============================================================================
-- SENSITIVITY CATEGORIES
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES (
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
	POLICY_GROUP VARCHAR(50) COMMENT 'High-level policy group (PII, SOX, SOC2, etc.)',
	WEIGHT_EMBEDDING FLOAT DEFAULT 0.6 COMMENT 'Weight for semantic embedding score (0.0-1.0)',
	WEIGHT_KEYWORD FLOAT DEFAULT 0.25 COMMENT 'Weight for keyword match score (0.0-1.0)',
	WEIGHT_PATTERN FLOAT DEFAULT 0.15 COMMENT 'Weight for regex pattern match score (0.0-1.0)',
	MULTI_LABEL BOOLEAN DEFAULT TRUE COMMENT 'Whether this category can be detected alongside others',
	primary key (CATEGORY_ID)
);

-- ============================================================================
-- SENSITIVE PATTERNS
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS (
	PATTERN_ID VARCHAR(16777216) NOT NULL,
	CATEGORY_ID VARCHAR(16777216) NOT NULL,
	PATTERN_NAME VARCHAR(16777216) NOT NULL,
	DESCRIPTION VARCHAR(16777216),
	SENSITIVITY_WEIGHT FLOAT DEFAULT 0.5,
	IS_ACTIVE BOOLEAN DEFAULT TRUE,
	CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
	UPDATED_AT TIMESTAMP_NTZ(9),
	VERSION_NUMBER NUMBER(38,0) DEFAULT 1,
	PATTERN_REGEX VARCHAR(16777216),
	SENSITIVITY_TYPE VARCHAR(16777216),
	EXAMPLE VARCHAR(16777216),
	primary key (PATTERN_ID),
	foreign key (CATEGORY_ID) references DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES(CATEGORY_ID)
);

-- ============================================================================
-- SENSITIVE KEYWORDS
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS (
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
);

-- ============================================================================
-- SENSITIVE AUDIT
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_AUDIT (
	AUDIT_ID NUMBER(38,0) NOT NULL autoincrement start 1 increment 1 noorder,
	TABLE_NAME VARCHAR(16777216),
	COLUMN_NAME VARCHAR(16777216),
	CATEGORY VARCHAR(16777216),
	CONFIDENCE NUMBER(38,0),
	CIA VARCHAR(16777216),
	BUNDLE_DETECTED BOOLEAN,
	SCANNED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
	primary key (AUDIT_ID)
);

-- ============================================================================
-- RECLASSIFICATION REQUESTS
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.RECLASSIFICATION_REQUESTS (
	ID VARCHAR(16777216),
	ASSET_FULL_NAME VARCHAR(16777216),
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
	UPDATED_AT TIMESTAMP_NTZ(9)
);

-- ============================================================================
-- COMPLIANCE MAPPING
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.COMPLIANCE_MAPPING (
	MAPPING_ID VARCHAR(16777216) NOT NULL,
	CATEGORY_ID VARCHAR(16777216) NOT NULL,
	COMPLIANCE_STANDARD VARCHAR(16777216) NOT NULL,
	REQUIREMENT_IDS VARIANT,
	DESCRIPTION VARCHAR(16777216),
	IS_ACTIVE BOOLEAN DEFAULT TRUE,
	CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
	UPDATED_AT TIMESTAMP_NTZ(9),
	VERSION_NUMBER NUMBER(38,0) DEFAULT 1,
	SENSITIVITY_TYPE VARCHAR(16777216),
	COMPLIANCE_FRAMEWORK VARCHAR(16777216),
	REQUIRED_ACTIONS VARCHAR(16777216),
	primary key (MAPPING_ID),
	foreign key (CATEGORY_ID) references DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES(CATEGORY_ID)
);

-- ============================================================================
-- CLASSIFICATION TASKS
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_TASKS (
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
);

-- ============================================================================
-- CLASSIFICATION REVIEW
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_REVIEW (
	REVIEW_ID VARCHAR(16777216) NOT NULL DEFAULT UUID_STRING(),
	ASSET_FULL_NAME VARCHAR(16777216),
	PROPOSED_CLASSIFICATION VARCHAR(16777216),
	PROPOSED_C NUMBER(38,0),
	PROPOSED_I NUMBER(38,0),
	PROPOSED_A NUMBER(38,0),
	REVIEWER VARCHAR(16777216),
	STATUS VARCHAR(16777216),
	CREATED_BY VARCHAR(16777216),
	CREATED_AT TIMESTAMP_TZ(9) DEFAULT CURRENT_TIMESTAMP(),
	UPDATED_AT TIMESTAMP_TZ(9),
	REVIEW_DUE_DATE TIMESTAMP_TZ(9),
	LAST_COMMENT VARCHAR(16777216),
	RISK_SCORE NUMBER(38,2),
	primary key (REVIEW_ID)
);

-- ============================================================================
-- ASSETS
-- ============================================================================
CREATE OR REPLACE TABLE DATA_CLASSIFICATION_GOVERNANCE.ASSETS (
    -- Primary Identification
    asset_id VARCHAR(100) PRIMARY KEY,
    asset_name VARCHAR(500) NOT NULL,
    asset_type VARCHAR(50) NOT NULL, -- TABLE, VIEW, SCHEMA, DATABASE, etc.
    database_name VARCHAR(255),
    schema_name VARCHAR(255),
    object_name VARCHAR(255),
    fully_qualified_name VARCHAR(1000),
    
    -- Business Context
    business_unit VARCHAR(100),
    data_owner VARCHAR(100) NOT NULL,
    data_owner_email VARCHAR(255),
    data_custodian VARCHAR(100),
    data_custodian_email VARCHAR(255),
    business_purpose VARCHAR(2000),
    data_description VARCHAR(4000),
    
    -- Classification Framework
    classification_label VARCHAR(20) NOT NULL, -- PUBLIC, INTERNAL, RESTRICTED, CONFIDENTIAL
    classification_label_color VARCHAR(20), -- Green, Yellow, Orange, Red
    confidentiality_level VARCHAR(2) NOT NULL, -- C0, C1, C2, C3
    integrity_level VARCHAR(2) NOT NULL, -- I0, I1, I2, I3
    availability_level VARCHAR(2) NOT NULL, -- A0, A1, A2, A3
    overall_risk_classification VARCHAR(20) NOT NULL, -- LOW_RISK, MEDIUM_RISK, HIGH_RISK
    
    -- Special Classification Categories
    contains_pii BOOLEAN DEFAULT FALSE,
    contains_financial_data BOOLEAN DEFAULT FALSE,
    sox_relevant BOOLEAN DEFAULT FALSE,
    soc_relevant BOOLEAN DEFAULT FALSE,
    regulatory_data BOOLEAN DEFAULT FALSE,
    
    -- Classification Decision Documentation
    classification_rationale VARCHAR(4000) NOT NULL,
    confidentiality_impact_assessment VARCHAR(2000),
    integrity_impact_assessment VARCHAR(2000),
    availability_impact_assessment VARCHAR(2000),
    
    -- Classification Process Metadata
    classification_date TIMESTAMP_NTZ NOT NULL,
    classified_by VARCHAR(100) NOT NULL,
    classification_method VARCHAR(50), -- MANUAL, AUTOMATED, ASSISTED
    classification_reviewed_by VARCHAR(100),
    classification_review_date TIMESTAMP_NTZ,
    classification_approved_by VARCHAR(100),
    classification_approval_date TIMESTAMP_NTZ,
    
    -- Reclassification History
    last_reclassification_date TIMESTAMP_NTZ,
    reclassification_trigger VARCHAR(500),
    reclassification_count NUMBER(10,0) DEFAULT 0,
    previous_classification_label VARCHAR(20),
    
    -- Review and Maintenance
    last_review_date TIMESTAMP_NTZ,
    next_review_date TIMESTAMP_NTZ NOT NULL,
    review_frequency_days NUMBER(10,0) DEFAULT 365,
    review_status VARCHAR(20), -- CURRENT, DUE, OVERDUE
    
    -- Compliance and Quality Assurance
    peer_review_completed BOOLEAN DEFAULT FALSE,
    peer_reviewer VARCHAR(100),
    management_review_completed BOOLEAN DEFAULT FALSE,
    management_reviewer VARCHAR(100),
    technical_review_completed BOOLEAN DEFAULT FALSE,
    technical_reviewer VARCHAR(100),
    consistency_check_date TIMESTAMP_NTZ,
    consistency_check_status VARCHAR(20), -- PASSED, FAILED, PENDING
    
    -- Data Lifecycle
    data_creation_date TIMESTAMP_NTZ,
    data_source_system VARCHAR(255),
    data_retention_period_days NUMBER(10,0),
    data_disposal_date TIMESTAMP_NTZ,
    
    -- Usage and Access Metrics
    sensitive_data_usage_count NUMBER(10,0) DEFAULT 0,
    last_accessed_date TIMESTAMP_NTZ,
    access_frequency VARCHAR(20), -- HIGH, MEDIUM, LOW
    number_of_consumers NUMBER(10,0),
    
    -- Exception Management
    has_exception BOOLEAN DEFAULT FALSE,
    exception_type VARCHAR(100),
    exception_justification VARCHAR(2000),
    exception_approved_by VARCHAR(100),
    exception_approval_date TIMESTAMP_NTZ,
    exception_expiry_date TIMESTAMP_NTZ,
    exception_mitigation_measures VARCHAR(2000),
    
    -- Compliance Status
    compliance_status VARCHAR(20) NOT NULL, -- COMPLIANT, NON_COMPLIANT, UNDER_REVIEW
    non_compliance_reason VARCHAR(1000),
    corrective_action_required BOOLEAN DEFAULT FALSE,
    corrective_action_description VARCHAR(2000),
    corrective_action_due_date TIMESTAMP_NTZ,
    
    -- Audit Trail
    created_timestamp TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    created_by VARCHAR(100) NOT NULL,
    last_modified_timestamp TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    last_modified_by VARCHAR(100) NOT NULL,
    record_version NUMBER(10,0) DEFAULT 1,
    
    -- Comments and Notes
    additional_notes VARCHAR(4000),
    stakeholder_comments VARCHAR(4000)
);

-- ============================================================================
-- CLASSIFICATION HISTORY
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_HISTORY (
	HISTORY_ID VARCHAR(100) NOT NULL,
	ASSET_ID VARCHAR(100),
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
	APPROVAL_REQUIRED BOOLEAN,
	APPROVED_BY VARCHAR(150),
	APPROVAL_TIMESTAMP TIMESTAMP_NTZ(9),
	BUSINESS_JUSTIFICATION VARCHAR(1000),
	primary key (HISTORY_ID),
	foreign key (ASSET_ID) references DATA_CLASSIFICATION_GOVERNANCE.ASSETS(ASSET_ID)
);

-- ============================================================================
-- CLASSIFICATION DECISIONS
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_DECISIONS (
	ID VARCHAR(16777216),
	ASSET_FULL_NAME VARCHAR(16777216),
	USER_ID VARCHAR(16777216),
	ACTION VARCHAR(16777216),
	CLASSIFICATION_LEVEL VARCHAR(16777216),
	CIA_CONF NUMBER(38,0),
	CIA_INT NUMBER(38,0),
	CIA_AVAIL NUMBER(38,0),
	RATIONALE VARCHAR(16777216),
	CREATED_AT TIMESTAMP_NTZ(9),
	DETAILS VARIANT
);

-- ============================================================================
-- CLASSIFICATION AUDIT
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AUDIT (
	ID VARCHAR(16777216) DEFAULT UUID_STRING(),
	RESOURCE_ID VARCHAR(16777216),
	ACTION VARCHAR(16777216),
	DETAILS VARCHAR(16777216),
	CREATED_AT TIMESTAMP_TZ(9) DEFAULT CURRENT_TIMESTAMP()
);

-- ============================================================================
-- AI ASSISTANT SENSITIVE ASSETS
-- ============================================================================
create or replace TABLE DATA_CLASSIFICATION_GOVERNANCE.AI_ASSISTANT_SENSITIVE_ASSETS (
	RUN_ID VARCHAR(16777216),
	DATABASE_NAME VARCHAR(16777216) NOT NULL,
	SCHEMA_NAME VARCHAR(16777216) NOT NULL,
	TABLE_NAME VARCHAR(16777216) NOT NULL,
	COLUMN_NAME VARCHAR(16777216) NOT NULL,
	DETECTED_CATEGORY VARCHAR(16777216),
	DETECTED_TYPE VARCHAR(16777216),
	COMBINED_CONFIDENCE FLOAT,
	METHODS_USED ARRAY,
	COMPLIANCE_TAGS ARRAY,
	SAMPLE_METADATA VARIANT,
	DETECTION_REASON VARCHAR(16777216),
	LAST_SCAN_TS TIMESTAMP_LTZ(9) DEFAULT CURRENT_TIMESTAMP(),
	PREV_SHA256_HEX VARCHAR(16777216),
	CHAIN_SHA256_HEX VARCHAR(16777216),
	primary key (DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME)
);

-- ============================================================================
-- LEGACY TABLES (Keep if needed, or remove if fully replaced)
-- ============================================================================

-- Audit log (immutable-style) - keeping as legacy or for other uses
CREATE TABLE IF NOT EXISTS DATA_GOVERNANCE.AUDIT_LOG (
  TIMESTAMP TIMESTAMP_NTZ,
  USER_ID STRING,
  ACTION STRING,
  RESOURCE_TYPE STRING,
  RESOURCE_ID STRING,
  DETAILS VARIANT
);

-- Compliance artifacts
CREATE TABLE IF NOT EXISTS DATA_GOVERNANCE.REVIEW_SCHEDULES (
  ID STRING,
  ASSET_FULL_NAME STRING,
  FREQUENCY STRING,
  NEXT_RUN TIMESTAMP_NTZ,
  LAST_RUN TIMESTAMP_NTZ,
  OWNER STRING,
  ACTIVE BOOLEAN
);

CREATE TABLE IF NOT EXISTS DATA_GOVERNANCE.COMPLIANCE_REPORTS (
  ID STRING,
  FRAMEWORK STRING,
  GENERATED_AT TIMESTAMP_NTZ,
  GENERATED_BY STRING,
  METRICS VARIANT,
  LOCATION STRING
);

CREATE TABLE IF NOT EXISTS DATA_GOVERNANCE.VIOLATIONS (
  ID STRING,
  RULE_CODE STRING,
  SEVERITY STRING,
  DESCRIPTION STRING,
  ASSET_FULL_NAME STRING,
  DETECTED_AT TIMESTAMP_NTZ,
  STATUS STRING,
  DETAILS VARIANT
);

CREATE TABLE IF NOT EXISTS DATA_GOVERNANCE.REMEDIATION_TASKS (
  ID STRING,
  VIOLATION_ID STRING,
  ASSIGNEE STRING,
  DUE_DATE DATE,
  STATUS STRING,
  CREATED_AT TIMESTAMP_NTZ,
  UPDATED_AT TIMESTAMP_NTZ
);

-- View used by the app as queue for classification
CREATE OR REPLACE VIEW DATA_GOVERNANCE.CLASSIFICATION_QUEUE AS
SELECT *
FROM DATA_CLASSIFICATION_GOVERNANCE.ASSETS
WHERE COALESCE(CLASSIFICATION_LABEL, '') = ''
ORDER BY CREATED_TIMESTAMP DESC;
