-- Create GOVERNANCE_AUDIT_LOG table for tracking all data classification changes
-- This table provides complete audit trail for governance and compliance

USE DATABASE DATA_CLASSIFICATION_DB;
USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE;

CREATE TABLE IF NOT EXISTS GOVERNANCE_AUDIT_LOG (
    -- Primary audit fields
    AUDIT_ID STRING DEFAULT UUID_STRING() PRIMARY KEY,
    USERNAME STRING NOT NULL,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    ACTION_TYPE STRING NOT NULL, -- 'edit', 'add', 'review', 'approve', 'delete'
    
    -- Change tracking
    FIELD STRING, -- Field that was changed
    OLD_VALUE VARIANT, -- Previous value (can be string, number, boolean, etc.)
    NEW_VALUE VARIANT, -- New value (can be string, number, boolean, etc.)
    
    -- Object identification
    OBJECT_PATH VARIANT NOT NULL, -- JSON object with table/column path info
    OBJECT_TYPE STRING DEFAULT 'column', -- 'table', 'column', 'schema', 'database'
    
    -- Additional context
    COMMENT STRING, -- User-provided reason/justification
    SESSION_ID STRING, -- For tracking related changes in same session
    IP_ADDRESS STRING, -- For security auditing
    USER_AGENT STRING, -- Browser/client information
    
    -- Metadata
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS IDX_GOVERNANCE_AUDIT_USERNAME ON GOVERNANCE_AUDIT_LOG(USERNAME);
CREATE INDEX IF NOT EXISTS IDX_GOVERNANCE_AUDIT_TIMESTAMP ON GOVERNANCE_AUDIT_LOG(TIMESTAMP);
CREATE INDEX IF NOT EXISTS IDX_GOVERNANCE_AUDIT_ACTION ON GOVERNANCE_AUDIT_LOG(ACTION_TYPE);
CREATE INDEX IF NOT EXISTS IDX_GOVERNANCE_AUDIT_OBJECT ON GOVERNANCE_AUDIT_LOG(OBJECT_PATH);

-- Create a view for easier querying
CREATE OR REPLACE VIEW GOVERNANCE_AUDIT_VIEW AS
SELECT 
    AUDIT_ID,
    USERNAME,
    TIMESTAMP,
    ACTION_TYPE,
    FIELD,
    OLD_VALUE,
    NEW_VALUE,
    OBJECT_PATH:table::STRING AS TABLE_NAME,
    OBJECT_PATH:column::STRING AS COLUMN_NAME,
    OBJECT_PATH:database::STRING AS DATABASE_NAME,
    OBJECT_PATH:schema::STRING AS SCHEMA_NAME,
    COMMENT,
    SESSION_ID,
    CREATED_AT
FROM GOVERNANCE_AUDIT_LOG
ORDER BY TIMESTAMP DESC;

-- Grant permissions
GRANT SELECT, INSERT ON GOVERNANCE_AUDIT_LOG TO ROLE DATA_CLASSIFICATION_ROLE;
GRANT SELECT ON GOVERNANCE_AUDIT_VIEW TO ROLE DATA_CLASSIFICATION_ROLE;

-- Add comments for documentation
COMMENT ON TABLE GOVERNANCE_AUDIT_LOG IS 'Complete audit trail for all data classification governance activities';
COMMENT ON COLUMN GOVERNANCE_AUDIT_LOG.USERNAME IS 'User who made the change';
COMMENT ON COLUMN GOVERNANCE_AUDIT_LOG.ACTION_TYPE IS 'Type of action: edit, add, review, approve, delete';
COMMENT ON COLUMN GOVERNANCE_AUDIT_LOG.OBJECT_PATH IS 'JSON path to the object being modified (database.schema.table.column)';
COMMENT ON COLUMN GOVERNANCE_AUDIT_LOG.OLD_VALUE IS 'Previous value before change';
COMMENT ON COLUMN GOVERNANCE_AUDIT_LOG.NEW_VALUE IS 'New value after change';
COMMENT ON COLUMN GOVERNANCE_AUDIT_LOG.COMMENT IS 'User-provided justification for the change';

-- Sample insert for testing
-- INSERT INTO GOVERNANCE_AUDIT_LOG (
--     USERNAME, ACTION_TYPE, FIELD, OLD_VALUE, NEW_VALUE, 
--     OBJECT_PATH, COMMENT
-- ) VALUES (
--     'test_user', 'edit', 'sensitivity_type', 'GENERAL', 'PII',
--     {'database': 'TEST_DB', 'schema': 'TEST_SCHEMA', 'table': 'TEST_TABLE', 'column': 'EMAIL'},
--     'Updated classification based on data review'
-- );
