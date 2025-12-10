import os
import sys
import re

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.connectors.snowflake_connector import snowflake_connector

def execute_sql_file(file_path):
    print(f"Reading SQL file: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Rudimentary split by semicolon. 
    # This works for the provided SQL file as strictly formatted.
    # For robust splitting, we'd need a SQL parser, but simple split is sufficient here.
    statements = [s.strip() for s in content.split(';') if s.strip()]
    
    print("Connecting to Snowflake...")
    try:
        # Use a single connection context for all statements
        with snowflake_connector.get_connection() as connection:
            cursor = connection.cursor()
            print("Connected.")
            
            for i, sql in enumerate(statements):
                if not sql:
                    continue
                
                # Check if it's just comments
                lines = [l for l in sql.split('\n') if not l.strip().startswith('--') and l.strip()]
                if not lines:
                    continue
                
                print(f"\n--- Executing Statement {i+1} ---")
                
                # Print preview (first non-comment line)
                preview = lines[0] if lines else "..."
                print(f"Query: {preview[:80]}...")
                
                try:
                    cursor.execute(sql)
                    print("  ✓ Success")
                except Exception as e:
                    print(f"  ✗ Error: {e}")
                    # Don't abort, try to continue
            
            print("\nAll statements executed.")
            
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    execute_sql_file("fix_snowflake_governance_data.sql")
