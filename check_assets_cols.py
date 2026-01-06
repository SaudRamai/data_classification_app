from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

def check_columns():
    db = settings.SNOWFLAKE_DATABASE or "DATA_CLASSIFICATION_DB"
    schema = "DATA_CLASSIFICATION_GOVERNANCE"
    table = "ASSETS"
    try:
        rows = snowflake_connector.execute_query(f"SHOW COLUMNS IN TABLE {db}.{schema}.{table}")
        for r in rows:
            print(f"{r.get('column_name') or r.get('COLUMN_NAME')}: {r.get('data_type') or r.get('DATA_TYPE')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_columns()
