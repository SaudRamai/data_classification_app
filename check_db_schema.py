
import sys
import os
import pathlib

# Add the project root to the Python path
_here = pathlib.Path(str(__file__)).resolve()
_project_root = _here.parent.parent # Assuming this is in /tmp/ or something

# For this script, we need to find the actual project root to import src
# Let's use the absolute path provided in the environment
project_path = r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\app"
if project_path not in sys.path:
    sys.path.insert(0, project_path)

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

def check_schema():
    db = settings.SNOWFLAKE_DATABASE or "DATA_CLASSIFICATION_DB"
    schema = "DATA_CLASSIFICATION_GOVERNANCE"
    table = "ROLE_ASSIGNMENTS"
    
    print(f"Checking schema for {db}.{schema}.{table}")
    
    try:
        # Try to use the database first
        snowflake_connector.execute_non_query(f"USE DATABASE {db}")
        snowflake_connector.execute_non_query(f"USE SCHEMA {schema}")
        
        query = f"DESC TABLE {table}"
        results = snowflake_connector.execute_query(query)
        
        print("\nTable Columns:")
        for row in results:
            print(f"- {row['name']} ({row['type']})")
            
        # Also check DATA_GOVERNANCE schema for IDP_GROUP_MAP
        print(f"\nChecking for IDP_GROUP_MAP in {db}.DATA_GOVERNANCE")
        try:
            results = snowflake_connector.execute_query("SHOW TABLES LIKE 'IDP_GROUP_MAP' IN SCHEMA DATA_GOVERNANCE")
            if results:
                print("IDP_GROUP_MAP exists in DATA_GOVERNANCE.")
                desc = snowflake_connector.execute_query("DESC TABLE DATA_GOVERNANCE.IDP_GROUP_MAP")
                for row in desc:
                   print(f"  - {row['name']} ({row['type']})")
            else:
                print("IDP_GROUP_MAP DOES NOT exist in DATA_GOVERNANCE.")
        except Exception as e:
            print(f"Error checking DATA_GOVERNANCE: {e}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_schema()
