-- ============================================================================
-- DATA-DRIVEN CLASSIFICATION ARCHITECTURE
-- New Governance Tables for Rule-Based Classification
-- ============================================================================
-- Purpose: Eliminate hardcoded logic from Python code
-- Author: AI Classification System
-- Date: 2025-12-04
-- ============================================================================

USE DATABASE GOVERNANCE_DB;
USE SCHEMA GOVERNANCE_SCHEMA;

-- ============================================================================
-- TABLE 1: CLASSIFICATION_RULES
-- Stores all context-aware adjustment rules
-- ============================================================================

CREATE OR REPLACE TABLE CLASSIFICATION_RULES (
    -- Primary Key
    RULE_ID VARCHAR(36) PRIMARY KEY DEFAULT UUID_STRING(),
    
    -- Rule Identification
    RULE_NAME VARCHAR(255) NOT NULL,
    RULE_TYPE VARCHAR(50) NOT NULL,  -- 'TABLE_CONTEXT', 'COLUMN_PATTERN', 'ID_CLASSIFICATION', 'FIELD_TYPE', 'EXCLUSION'
    PRIORITY INTEGER DEFAULT 100,     -- Lower number = higher priority (10, 20, 30...)
    
    -- Matching Criteria
    MATCH_SCOPE VARCHAR(20),          -- 'TABLE', 'COLUMN', 'BOTH'
    MATCH_KEYWORDS TEXT,              -- JSON array: ["order", "transaction", "payment"]
    MATCH_PATTERN VARCHAR(500),       -- Regex pattern (optional)
    MATCH_LOGIC VARCHAR(20),          -- 'ANY', 'ALL', 'EXACT', 'REGEX'
    
    -- Exclusion Criteria (optional - for exceptions)
    EXCLUDE_KEYWORDS TEXT,            -- JSON array: ["vendor", "supplier"]
    EXCLUDE_PATTERN VARCHAR(500),     -- Regex for exclusions
    
    -- Actions to Apply
    TARGET_POLICY_GROUP VARCHAR(50),  -- 'PII', 'SOX', 'SOC2', 'NON_SENSITIVE'
    ACTION_TYPE VARCHAR(20),          -- 'BOOST', 'REDUCE', 'REMOVE'
    ACTION_FACTOR FLOAT,              -- 1.5 for boost, 0.3 for reduce, 0.0 for remove
    
    -- Secondary Actions (optional - for multi-action rules)
    SECONDARY_POLICY_GROUP VARCHAR(50),
    SECONDARY_ACTION_TYPE VARCHAR(20),
    SECONDARY_ACTION_FACTOR FLOAT,
    
    -- Metadata
    DESCRIPTION TEXT,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(100),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(100),
    UPDATED_AT TIMESTAMP_NTZ,
    VERSION_NUMBER INTEGER DEFAULT 1,
    
    -- Constraints
    CONSTRAINT chk_rule_type CHECK (RULE_TYPE IN ('TABLE_CONTEXT', 'COLUMN_PATTERN', 'ID_CLASSIFICATION', 'FIELD_TYPE', 'EXCLUSION')),
    CONSTRAINT chk_match_scope CHECK (MATCH_SCOPE IN ('TABLE', 'COLUMN', 'BOTH')),
    CONSTRAINT chk_match_logic CHECK (MATCH_LOGIC IN ('ANY', 'ALL', 'EXACT', 'REGEX')),
    CONSTRAINT chk_action_type CHECK (ACTION_TYPE IN ('BOOST', 'REDUCE', 'REMOVE'))
);

-- Indexes for performance
CREATE INDEX idx_classification_rules_type ON CLASSIFICATION_RULES(RULE_TYPE);
CREATE INDEX idx_classification_rules_active ON CLASSIFICATION_RULES(IS_ACTIVE);
CREATE INDEX idx_classification_rules_priority ON CLASSIFICATION_RULES(PRIORITY);

-- ============================================================================
-- TABLE 2: TIEBREAKER_KEYWORDS
-- Stores keywords for intelligent tiebreaking
-- ============================================================================

CREATE OR REPLACE TABLE TIEBREAKER_KEYWORDS (
    KEYWORD_ID VARCHAR(36) PRIMARY KEY DEFAULT UUID_STRING(),
    POLICY_GROUP VARCHAR(50) NOT NULL,  -- 'PII', 'SOX', 'SOC2'
    KEYWORD VARCHAR(255) NOT NULL,
    WEIGHT FLOAT DEFAULT 1.0,           -- Higher weight = stronger signal for tiebreaking
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(100),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(100),
    UPDATED_AT TIMESTAMP_NTZ,
    
    -- Constraints
    CONSTRAINT chk_tiebreaker_policy_group CHECK (POLICY_GROUP IN ('PII', 'SOX', 'SOC2')),
    CONSTRAINT uk_tiebreaker_keyword UNIQUE (POLICY_GROUP, KEYWORD)
);

-- Indexes
CREATE INDEX idx_tiebreaker_policy_group ON TIEBREAKER_KEYWORDS(POLICY_GROUP);
CREATE INDEX idx_tiebreaker_active ON TIEBREAKER_KEYWORDS(IS_ACTIVE);

-- ============================================================================
-- TABLE 3: ADDRESS_CONTEXT_REGISTRY
-- Stores address context detection logic (Physical vs Network)
-- ============================================================================

CREATE OR REPLACE TABLE ADDRESS_CONTEXT_REGISTRY (
    CONTEXT_ID VARCHAR(36) PRIMARY KEY DEFAULT UUID_STRING(),
    CONTEXT_TYPE VARCHAR(50) NOT NULL,  -- 'PHYSICAL_ADDRESS', 'NETWORK_ADDRESS'
    INDICATOR_TYPE VARCHAR(20),         -- 'POSITIVE', 'NEGATIVE'
    INDICATOR_KEYWORD VARCHAR(255),
    
    -- Actions for this context
    BOOST_POLICY_GROUP VARCHAR(50),     -- Policy group to boost when matched
    BOOST_FACTOR FLOAT,
    SUPPRESS_POLICY_GROUP VARCHAR(50),  -- Policy group to suppress when matched
    SUPPRESS_FACTOR FLOAT,
    
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(100),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(100),
    UPDATED_AT TIMESTAMP_NTZ,
    
    -- Constraints
    CONSTRAINT chk_context_type CHECK (CONTEXT_TYPE IN ('PHYSICAL_ADDRESS', 'NETWORK_ADDRESS')),
    CONSTRAINT chk_indicator_type CHECK (INDICATOR_TYPE IN ('POSITIVE', 'NEGATIVE'))
);

-- Indexes
CREATE INDEX idx_address_context_type ON ADDRESS_CONTEXT_REGISTRY(CONTEXT_TYPE);
CREATE INDEX idx_address_indicator_type ON ADDRESS_CONTEXT_REGISTRY(INDICATOR_TYPE);

-- ============================================================================
-- TABLE 4: GENERIC_EXCLUSIONS
-- Stores patterns for non-sensitive generic fields
-- ============================================================================

CREATE OR REPLACE TABLE GENERIC_EXCLUSIONS (
    EXCLUSION_ID VARCHAR(36) PRIMARY KEY DEFAULT UUID_STRING(),
    EXCLUSION_NAME VARCHAR(255),
    EXCLUSION_TYPE VARCHAR(50),         -- 'STATUS_FLAG', 'DATE_TIME', 'GENERIC_ID', 'DESCRIPTION', 'QUANTITY'
    KEYWORDS TEXT,                      -- JSON array of keywords to match
    
    -- Reduction factors for each policy group
    REDUCE_PII_FACTOR FLOAT DEFAULT 0.1,
    REDUCE_SOX_FACTOR FLOAT DEFAULT 0.2,
    REDUCE_SOC2_FACTOR FLOAT DEFAULT 0.1,
    
    -- Exception handling
    EXCEPTION_KEYWORDS TEXT,            -- JSON array of exceptions (e.g., ["birth", "dob"] for dates)
    
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(100),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(100),
    UPDATED_AT TIMESTAMP_NTZ,
    
    -- Constraints
    CONSTRAINT chk_exclusion_type CHECK (EXCLUSION_TYPE IN ('STATUS_FLAG', 'DATE_TIME', 'GENERIC_ID', 'DESCRIPTION', 'QUANTITY', 'VENDOR'))
);

-- Indexes
CREATE INDEX idx_generic_exclusions_type ON GENERIC_EXCLUSIONS(EXCLUSION_TYPE);
CREATE INDEX idx_generic_exclusions_active ON GENERIC_EXCLUSIONS(IS_ACTIVE);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE CLASSIFICATION_RULES IS 'Stores all context-aware classification rules for data-driven sensitivity detection';
COMMENT ON TABLE TIEBREAKER_KEYWORDS IS 'Keywords used for intelligent tiebreaking when multiple categories have identical scores';
COMMENT ON TABLE ADDRESS_CONTEXT_REGISTRY IS 'Registry for distinguishing between physical addresses (PII) and network addresses (SOC2)';
COMMENT ON TABLE GENERIC_EXCLUSIONS IS 'Patterns for identifying and reducing sensitivity scores for generic non-sensitive fields';

-- ============================================================================
-- GRANT PERMISSIONS
-- ============================================================================

GRANT SELECT ON TABLE CLASSIFICATION_RULES TO ROLE DATA_GOVERNANCE_READER;
GRANT SELECT ON TABLE TIEBREAKER_KEYWORDS TO ROLE DATA_GOVERNANCE_READER;
GRANT SELECT ON TABLE ADDRESS_CONTEXT_REGISTRY TO ROLE DATA_GOVERNANCE_READER;
GRANT SELECT ON TABLE GENERIC_EXCLUSIONS TO ROLE DATA_GOVERNANCE_READER;

GRANT ALL ON TABLE CLASSIFICATION_RULES TO ROLE DATA_GOVERNANCE_ADMIN;
GRANT ALL ON TABLE TIEBREAKER_KEYWORDS TO ROLE DATA_GOVERNANCE_ADMIN;
GRANT ALL ON TABLE ADDRESS_CONTEXT_REGISTRY TO ROLE DATA_GOVERNANCE_ADMIN;
GRANT ALL ON TABLE GENERIC_EXCLUSIONS TO ROLE DATA_GOVERNANCE_ADMIN;

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
