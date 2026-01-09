from src.connectors.snowflake_connector import snowflake_connector
import pandas as pd

def check_stale_stats():
    try:
        # Check a few tables to see their LAST_ALTERED dates
        query = """
        SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, LAST_ALTERED, ROW_COUNT
        FROM DATA_CLASSIFICATION_DB.INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA', 'ACCOUNT_USAGE')
        ORDER BY LAST_ALTERED ASC
        LIMIT 20
        """
        rows = snowflake_connector.execute_query(query)
        if rows:
            df = pd.DataFrame(rows)
            print("SAMPLE TABLES METADATA:")
            print(df.to_string())
            
            # Count how many would be stale at different thresholds
            from datetime import datetime, timedelta
            now = datetime.now()
            for days in [1, 7, 30, 90]:
                limit = now - timedelta(days=days)
                stale = df[df['LAST_ALTERED'].fillna(limit - timedelta(days=1)) < limit]
                print(f"Stale at {days} days: {len(stale)}")
        else:
            print("No tables found in DATA_CLASSIFICATION_DB.")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    check_stale_stats()
