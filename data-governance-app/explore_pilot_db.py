"""
Explore script to see what schemas and tables are available in the pilot database.
"""
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.connectors.snowflake_connector import snowflake_connector

def explore_database():
    """Explore the pilot database structure."""
    try:
        print("Exploring Snowflake pilot database structure...")
        
        # Get available databases
        print("\n=== Available Databases ===")
        db_results = snowflake_connector.execute_query("SHOW DATABASES")
        for db in db_results[:10]:  # Show first 10
            print(f"- {db['name']}")
        if len(db_results) > 10:
            print(f"... and {len(db_results) - 10} more")
        
        # Get available schemas (in the first database)
        if db_results:
            first_db = db_results[0]['name']
            print(f"\n=== Available Schemas in {first_db} ===")
            schema_results = snowflake_connector.execute_query(f"SHOW SCHEMAS IN DATABASE {first_db}")
            for schema in schema_results[:10]:  # Show first 10
                print(f"- {schema['name']}")
            if len(schema_results) > 10:
                print(f"... and {len(schema_results) - 10} more")
            
            # Get available tables (in the first schema)
            if schema_results:
                first_schema = schema_results[0]['name']
                print(f"\n=== Available Tables in {first_db}.{first_schema} ===")
                table_results = snowflake_connector.execute_query(f"SHOW TABLES IN SCHEMA {first_db}.{first_schema}")
                for table in table_results[:10]:  # Show first 10
                    print(f"- {table['name']}")
                if len(table_results) > 10:
                    print(f"... and {len(table_results) - 10} more")
        
        print("\n✅ Database exploration completed!")
        
    except Exception as e:
        print(f"❌ Database exploration failed with error: {e}")

if __name__ == "__main__":
    explore_database()