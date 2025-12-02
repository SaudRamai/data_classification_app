-- 002_governance_seed_data.sql
-- Seed data for SENSITIVITY_CATEGORIES and SENSITIVE_KEYWORDS
-- Incorporates fixes for PII/SOX/SOC2 policy groups and keyword mappings

USE DATABASE IDENTIFIER($DATABASE);
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

-- =====================================================
-- 1. SEED SENSITIVITY_CATEGORIES
-- =====================================================
-- Clear existing data to avoid duplicates if re-run
DELETE FROM SENSITIVITY_CATEGORIES;

INSERT INTO SENSITIVITY_CATEGORIES (
    CATEGORY_ID, CATEGORY_NAME, DESCRIPTION,
    CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL,
    DETECTION_THRESHOLD, IS_ACTIVE, CREATED_BY,
    POLICY_GROUP, WEIGHT_EMBEDDING, WEIGHT_KEYWORD, WEIGHT_PATTERN, MULTI_LABEL
)
SELECT UUID_STRING(), 'PII', 'Personally Identifiable Information – data that can identify individuals', 2, 2, 2, 0.6, TRUE, CURRENT_USER(), 'PII', 0.6, 0.25, 0.15, TRUE UNION ALL
SELECT UUID_STRING(), 'FINANCIAL', 'Financial or payment-related data such as bank accounts or card numbers', 2, 2, 2, 0.6, TRUE, CURRENT_USER(), 'SOX', 0.6, 0.25, 0.15, TRUE UNION ALL
SELECT UUID_STRING(), 'HEALTH', 'Health and medical data governed by HIPAA or similar regulations', 3, 2, 2, 0.7, TRUE, CURRENT_USER(), 'HIPAA', 0.6, 0.25, 0.15, TRUE UNION ALL
SELECT UUID_STRING(), 'HR', 'Human resources and employee data including personal and salary details', 2, 2, 2, 0.6, TRUE, CURRENT_USER(), 'GDPR', 0.6, 0.25, 0.15, TRUE UNION ALL
SELECT UUID_STRING(), 'AUTH', 'Authentication or credential data such as passwords and API keys', 3, 3, 3, 0.8, TRUE, CURRENT_USER(), 'SOC2', 0.7, 0.2, 0.1, TRUE UNION ALL
SELECT UUID_STRING(), 'SOC2', 'Data related to SOC2 security, confidentiality, and integrity controls', 2, 2, 2, 0.6, TRUE, CURRENT_USER(), 'SOC2', 0.6, 0.25, 0.15, TRUE UNION ALL
SELECT UUID_STRING(), 'SOX', 'SOX compliance and audit control–related data', 2, 2, 2, 0.6, TRUE, CURRENT_USER(), 'SOX', 0.6, 0.25, 0.15, TRUE UNION ALL
SELECT UUID_STRING(), 'LEGAL', 'Legal documents, contracts, and compliance data', 2, 2, 2, 0.6, TRUE, CURRENT_USER(), 'LEGAL', 0.6, 0.25, 0.15, TRUE UNION ALL
SELECT UUID_STRING(), 'AI_MODEL', 'AI and ML model artifacts, training data, and model weights', 2, 2, 2, 0.6, TRUE, CURRENT_USER(), 'AI', 0.6, 0.25, 0.15, TRUE UNION ALL
SELECT UUID_STRING(), 'INTERNAL', 'Internal operational or system data – low sensitivity', 1, 1, 1, 0.4, TRUE, CURRENT_USER(), 'INTERNAL', 0.5, 0.3, 0.2, TRUE;

-- =====================================================
-- 2. SEED SENSITIVE_KEYWORDS
-- =====================================================
DELETE FROM SENSITIVE_KEYWORDS;

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
            WHEN C.CATEGORY_NAME = 'SOX' THEN ARRAY_CONSTRUCT(
                -- Moved from PII/Other based on fix_misclassification.sql
                'vendor_name', 'vendor_address', 'payment_terms',
                'general_ledger', 'journal_entry', 'financial_statement', 'audit_trail',
                'internal_control', 'revenue_recognition', 'segregation_duties'
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
                'roadmap','strategy','internal_id','currency_key'
            )
            ELSE ARRAY_CONSTRUCT()
        END
) K;

-- =====================================================
-- 3. SEED COMPLIANCE_MAPPING
-- =====================================================
DELETE FROM COMPLIANCE_MAPPING;

INSERT INTO COMPLIANCE_MAPPING (MAPPING_ID, CATEGORY_ID, COMPLIANCE_STANDARD, REQUIREMENT_IDS, DESCRIPTION)
SELECT UUID_STRING(), C.CATEGORY_ID, 'GDPR', PARSE_JSON('["Art.4","Art.5","Art.6","Art.9"]'), 'EU Data Privacy Regulations'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'PII'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'CCPA', PARSE_JSON('["Sec.1798.100","Sec.1798.105"]'), 'California Consumer Privacy Act'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'PII'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'PCI-DSS', PARSE_JSON('["Req.3","Req.7","Req.8","Req.10"]'), 'Payment data protection'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'FINANCIAL'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'SOX', PARSE_JSON('["Sec.302","Sec.404","Sec.409"]'), 'Corporate financial reporting compliance'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'SOX'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'SOC2', PARSE_JSON('["CC1.0","CC6.0","CC8.0","CC9.0"]'), 'Trust and security controls'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'SOC2'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'ISO27001', PARSE_JSON('["A.9.2","A.10.1","A.12.4"]'), 'Access control & encryption compliance'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'AUTH'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'GDPR', PARSE_JSON('["Art.88","Art.9"]'), 'Employee data privacy compliance'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'HR'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'HIPAA', PARSE_JSON('["§164.312","§164.308"]'), 'Protected Health Information (PHI)'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'HEALTH'
UNION ALL
SELECT UUID_STRING(), C.CATEGORY_ID, 'FERPA', PARSE_JSON('["§99.30","§99.31"]'), 'Education records compliance (US)'
FROM SENSITIVITY_CATEGORIES C WHERE CATEGORY_NAME = 'LEGAL';
