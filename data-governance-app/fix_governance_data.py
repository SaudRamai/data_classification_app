
import logging
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.connectors.snowflake_connector import snowflake_connector
from src.services.governance_db_resolver import resolve_governance_db

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_governance_data():
    logger.info("Starting Governance Data Fixes...")

    # Resolve governance database
    gov_db = resolve_governance_db()
    if not gov_db:
        logger.error("Could not resolve governance database. Aborting.")
        return

    schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
    logger.info(f"Using governance schema: {schema_fqn}")

    # SQL Statements
    sql_statements = [
        # FIX 1: Populate Category Descriptions
        f"""
        UPDATE {schema_fqn}.SENSITIVITY_CATEGORIES
        SET DESCRIPTION = 'Personal Identifiable Information including names, email addresses, phone numbers, physical addresses, Social Security Numbers, passport numbers, and other individual identifiers'
        WHERE CATEGORY_NAME = 'PII_PERSONAL_INFO' AND (DESCRIPTION IS NULL OR DESCRIPTION = '')
        """,
        f"""
        UPDATE {schema_fqn}.SENSITIVITY_CATEGORIES
        SET DESCRIPTION = 'Financial and accounting data including revenue records, transaction details, account balances, payment information, invoices, general ledger entries, expense reports, and financial statements'
        WHERE CATEGORY_NAME = 'SOX_FINANCIAL_DATA' AND (DESCRIPTION IS NULL OR DESCRIPTION = '')
        """,
        f"""
        UPDATE {schema_fqn}.SENSITIVITY_CATEGORIES
        SET DESCRIPTION = 'Security and access control data including passwords, authentication tokens, API keys, encryption keys, certificates, security logs, access records, and authorization decisions'
        WHERE CATEGORY_NAME = 'SOC2_SECURITY_DATA' AND (DESCRIPTION IS NULL OR DESCRIPTION = '')
        """,

        # FIX 2: Add Policy Group Mapping
        f"""
        UPDATE {schema_fqn}.SENSITIVITY_CATEGORIES
        SET POLICY_GROUP = 'PII'
        WHERE (CATEGORY_NAME LIKE '%PII%' OR CATEGORY_NAME LIKE '%PERSONAL%') AND (POLICY_GROUP IS NULL OR POLICY_GROUP = '')
        """,
        f"""
        UPDATE {schema_fqn}.SENSITIVITY_CATEGORIES
        SET POLICY_GROUP = 'SOX'
        WHERE (CATEGORY_NAME LIKE '%SOX%' OR CATEGORY_NAME LIKE '%FINANCIAL%') AND (POLICY_GROUP IS NULL OR POLICY_GROUP = '')
        """,
        f"""
        UPDATE {schema_fqn}.SENSITIVITY_CATEGORIES
        SET POLICY_GROUP = 'SOC2'
        WHERE (CATEGORY_NAME LIKE '%SOC%' OR CATEGORY_NAME LIKE '%SECURITY%') AND (POLICY_GROUP IS NULL OR POLICY_GROUP = '')
        """,

        # FIX 3: Deduplicate Keywords (Keep best match)
        f"""
        CREATE OR REPLACE TEMPORARY TABLE {schema_fqn}.KEYWORDS_TO_KEEP AS
        SELECT KEYWORD_STRING, CATEGORY_ID, MAX(SENSITIVITY_WEIGHT) as MAX_WEIGHT, MAX(UPDATED_AT) as LATEST_UPDATE
        FROM {schema_fqn}.SENSITIVE_KEYWORDS WHERE IS_ACTIVE = TRUE
        GROUP BY KEYWORD_STRING, CATEGORY_ID
        """,
        f"""
        UPDATE {schema_fqn}.SENSITIVE_KEYWORDS
        SET IS_ACTIVE = FALSE, UPDATED_AT = CURRENT_TIMESTAMP(), UPDATED_BY = 'SYSTEM_CLEANUP'
        WHERE KEYWORD_ID NOT IN (
            SELECT a.KEYWORD_ID
            FROM {schema_fqn}.SENSITIVE_KEYWORDS a
            JOIN {schema_fqn}.KEYWORDS_TO_KEEP b
            ON a.KEYWORD_STRING = b.KEYWORD_STRING AND a.CATEGORY_ID = b.CATEGORY_ID
            AND a.SENSITIVITY_WEIGHT = b.MAX_WEIGHT AND a.UPDATED_AT = b.LATEST_UPDATE
        ) AND IS_ACTIVE = TRUE
        """,

        # FIX 4: Date Fixes (Future/Null dates)
        f"UPDATE {schema_fqn}.SENSITIVE_KEYWORDS SET UPDATED_AT = CURRENT_TIMESTAMP() WHERE UPDATED_AT > CURRENT_TIMESTAMP()",
        f"UPDATE {schema_fqn}.SENSITIVE_KEYWORDS SET CREATED_AT = CURRENT_TIMESTAMP() WHERE CREATED_AT > CURRENT_TIMESTAMP()",
        f"UPDATE {schema_fqn}.SENSITIVE_KEYWORDS SET CREATED_AT = CURRENT_TIMESTAMP() WHERE CREATED_AT IS NULL",
        f"UPDATE {schema_fqn}.SENSITIVE_KEYWORDS SET UPDATED_AT = CURRENT_TIMESTAMP() WHERE UPDATED_AT IS NULL"
    ]

    for sql in sql_statements:
        try:
            logger.info(f"Executing SQL: {sql.strip()}")
            snowflake_connector.execute_non_query(sql)
            logger.info("✓ Success")
        except Exception as e:
            logger.error(f"✗ Failed: {e}")

    logger.info("Governance Data Fixes Completed.")

if __name__ == "__main__":
    fix_governance_data()
