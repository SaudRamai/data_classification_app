
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

    # Updated to execute the comprehensive SQL script
    sql_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fix_snowflake_governance_data.sql')
    logger.info(f"Reading SQL file: {sql_file_path}")
    
    try:
        with open(sql_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Split statements by semicolon, but handle cases where semicolon is inside comments or strings roughly
        # For this specific SQL file, we can split by ';\n' or just ';' and filter empty
        statements = [s.strip() for s in content.split(';') if s.strip()]
        
        for i, sql in enumerate(statements):
            if not sql:
                continue
            
            # Skip pure comments
            lines = [l for l in sql.split('\n') if not l.strip().startswith('--') and l.strip()]
            if not lines:
                continue
                
            logger.info(f"Executing Statement {i+1}...")
            # We don't print the whole query to avoid log noise, just preview
            logger.info(f"Query: {lines[0][:100]}...")
            
            try:
                snowflake_connector.execute_non_query(sql)
                logger.info("✓ Success")
            except Exception as e:
                logger.warning(f"✗ Failed (might be expected for duplicates): {str(e)[:500]}")
                
        logger.info("Governance Data Fixes from SQL file Completed.")
        
    except Exception as e:
        logger.error(f"Failed to execute SQL file: {e}")

if __name__ == "__main__":
    fix_governance_data()
