from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
import os

def check_columns():
    db = os.getenv("SNOWFLAKE_DATABASE", "DATA_CLASSIFICATION_DB")
    schema = "DATA_CLASSIFICATION_GOVERNANCE"
    table = "ASSETS"
    fqn = f"{db}.{schema}.{table}"
    try:
        cols = snowflake_connector.execute_query(f"DESC TABLE {fqn}")
        for col in cols:
            print(f"{col['name']}: {col['type']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_columns()
