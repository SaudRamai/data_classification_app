
import sys
import os
import pathlib
import logging

# Add the project root to the Python path
project_root = r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\app"
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.connectors.snowflake_connector import snowflake_connector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_stored_procedure():
    setup_file = r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\setup.sql"
    
    with open(setup_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find the SP definition block
    # It starts with CREATE OR REPLACE PROCEDURE DATA_CLASSIFICATION_GOVERNANCE.SP_MERGE_ASSETS()
    # and ends with $$;
    
    start_marker = "CREATE OR REPLACE PROCEDURE DATA_CLASSIFICATION_GOVERNANCE.SP_MERGE_ASSETS()"
    end_marker = "$$;"
    
    start_index = content.find(start_marker)
    if start_index == -1:
        logger.error("Could not find SP start marker in setup.sql")
        return

    # Find the end marker after the start index
    end_index = content.find(end_marker, start_index)
    if end_index == -1:
        logger.error("Could not find SP end marker in setup.sql")
        return
    
    # Extract the full SQL including the end marker
    sp_sql = content[start_index : end_index + len(end_marker)]
    
    logger.info("Extracted Stored Procedure SQL from setup.sql")
    
    try:
        # Use execute_non_query to run the DDL
        snowflake_connector.execute_non_query(sp_sql)
        logger.info("Successfully updated SP_MERGE_ASSETS in Snowflake.")
        print("SUCCESS: Stored procedure updated successfully.")
    except Exception as e:
        logger.error(f"Failed to update stored procedure: {e}")
        print(f"ERROR: {e}")

if __name__ == "__main__":
    update_stored_procedure()
