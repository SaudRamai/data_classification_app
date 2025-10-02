"""
Test script to verify Snowflake connection with pilot database credentials.
"""
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.connectors.snowflake_connector import snowflake_connector

def test_connection():
    """Test connection to Snowflake pilot database."""
    try:
        print("Testing connection to Snowflake pilot database...")
        
        # Test a simple query
        result = snowflake_connector.execute_query("SELECT 1 as test")
        
        if result and len(result) > 0:
            print("✅ Connection successful!")
            print(f"Test query result: {result[0]['TEST']}")
            return True
        else:
            print("❌ Connection failed: No results returned")
            return False
            
    except Exception as e:
        print(f"❌ Connection failed with error: {e}")
        return False

if __name__ == "__main__":
    success = test_connection()
    if success:
        print("\n🎉 Snowflake connection test passed!")
    else:
        print("\n💥 Snowflake connection test failed!")