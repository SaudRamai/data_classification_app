from src.connectors.snowflake_connector import snowflake_connector
import os

def check_columns():
    db = os.getenv("SNOWFLAKE_DATABASE", "DATA_CLASSIFICATION_DB")
    schema = "DATA_CLASSIFICATION_GOVERNANCE"
    table = "ASSETS"
    fqn = f"{db}.{schema}.{table}"
    try:
        cols = snowflake_connector.execute_query(f"DESC TABLE {fqn}")
        with open("columns.txt", "w") as f:
            for col in cols:
                f.write(f"{col['name']}\n")
    except Exception as e:
        with open("columns.txt", "w") as f:
            f.write(f"Error: {e}")

if __name__ == "__main__":
    check_columns()
