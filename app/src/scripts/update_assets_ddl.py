
import logging
from src.connectors.snowflake_connector import snowflake_connector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_assets_table():
    """
    Updates the ASSETS table schema using the provided DDL.
    Uses dynamic database context for Snowflake Native App compatibility.
    """
    # Get dynamic database context
    try:
        # Try to get database from session state or governance config
        import streamlit as st
        if hasattr(st, 'session_state'):
            db = st.session_state.get('sf_database')
            if not db:
                from src.services.governance_config_service import governance_config_service
                db = governance_config_service.resolve_context().get('database')
        else:
            db = None
    except Exception:
        db = None
    
    # Fallback to current database if no context found
    if not db:
        try:
            result = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() as DB")
            db = result[0].get('DB') if result else None
        except Exception:
            db = None
    
    # Use dynamic database name or fallback
    db_name = db if db else "DATA_CLASSIFICATION_DB"
    schema_name = "DATA_CLASSIFICATION_GOVERNANCE"
    
    ddl = f"""
    create or replace TABLE {db_name}.{schema_name}.ASSETS (
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
        primary key (ASSET_ID)
    ) WITH TAG ({db_name}.{schema_name}.AVAILABILITY_LEVEL='A1', {db_name}.{schema_name}.CONFIDENTIALITY_LEVEL='C1', {db_name}.{schema_name}.DATA_CLASSIFICATION='Internal', {db_name}.{schema_name}.INTEGRITY_LEVEL='I1')
    """

    try:
        logger.info("Executing DDL to update ASSETS table...")
        snowflake_connector.execute_non_query(ddl)
        logger.info("Successfully updated ASSETS table.")
    except Exception as e:
        logger.error(f"Failed to update ASSETS table: {e}")
        # Check if error is due to missing tags and try without tags?
        # For now, just report the error.
        
if __name__ == "__main__":
    update_assets_table()
