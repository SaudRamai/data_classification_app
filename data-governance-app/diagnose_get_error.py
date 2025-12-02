#!/usr/bin/env python3
"""
Diagnostic script to identify 'str' object has no attribute 'get' errors
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.connectors.snowflake_connector import snowflake_connector
from src.services.governance_db_resolver import resolve_governance_db

def check_query_results():
    """Check if Snowflake query results are dictionaries or strings"""
    
    print("=" * 80)
    print("SNOWFLAKE QUERY RESULT TYPE CHECKER")
    print("=" * 80)
    print()
    
    gov_db = resolve_governance_db()
    if not gov_db:
        print("❌ ERROR: Could not resolve governance database")
        return False
    
    print(f"✓ Governance DB: {gov_db}")
    print()
    
    # Test 1: Check SENSITIVITY_CATEGORIES
    print("Test 1: SENSITIVITY_CATEGORIES")
    print("-" * 40)
    try:
        query = f"""
            SELECT 
                CATEGORY_ID,
                CATEGORY_NAME,
                DESCRIPTION,
                POLICY_GROUP
            FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
            LIMIT 1
        """
        results = snowflake_connector.execute_query(query)
        
        if results:
            first_row = results[0]
            print(f"  Result type: {type(first_row)}")
            print(f"  Result: {first_row}")
            
            if isinstance(first_row, dict):
                print("  ✅ Results are dictionaries (CORRECT)")
                print(f"  Keys: {list(first_row.keys())}")
            else:
                print(f"  ❌ Results are {type(first_row).__name__} (WRONG - should be dict)")
                print("  This will cause '.get()' errors!")
        else:
            print("  ⚠️  No results returned")
    except Exception as e:
        print(f"  ❌ ERROR: {e}")
    print()
    
    # Test 2: Check SENSITIVE_KEYWORDS
    print("Test 2: SENSITIVE_KEYWORDS")
    print("-" * 40)
    try:
        query = f"""
            SELECT 
                KEYWORD_ID,
                CATEGORY_ID,
                KEYWORD_STRING,
                MATCH_TYPE
            FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS
            LIMIT 1
        """
        results = snowflake_connector.execute_query(query)
        
        if results:
            first_row = results[0]
            print(f"  Result type: {type(first_row)}")
            
            if isinstance(first_row, dict):
                print("  ✅ Results are dictionaries (CORRECT)")
                print(f"  Sample: KEYWORD_STRING = {first_row.get('KEYWORD_STRING')}")
            else:
                print(f"  ❌ Results are {type(first_row).__name__} (WRONG)")
        else:
            print("  ⚠️  No results returned")
    except Exception as e:
        print(f"  ❌ ERROR: {e}")
    print()
    
    # Test 3: Check SENSITIVE_PATTERNS
    print("Test 3: SENSITIVE_PATTERNS")
    print("-" * 40)
    try:
        query = f"""
            SELECT 
                PATTERN_ID,
                CATEGORY_ID,
                PATTERN_REGEX,
                SENSITIVITY_WEIGHT
            FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS
            LIMIT 1
        """
        results = snowflake_connector.execute_query(query)
        
        if results:
            first_row = results[0]
            print(f"  Result type: {type(first_row)}")
            
            if isinstance(first_row, dict):
                print("  ✅ Results are dictionaries (CORRECT)")
                print(f"  Sample: PATTERN_REGEX = {first_row.get('PATTERN_REGEX')}")
            else:
                print(f"  ❌ Results are {type(first_row).__name__} (WRONG)")
        else:
            print("  ⚠️  No results returned")
    except Exception as e:
        print(f"  ❌ ERROR: {e}")
    print()
    
    print("=" * 80)
    print("DIAGNOSIS COMPLETE")
    print("=" * 80)
    print()
    print("If you see '❌ Results are X (WRONG)', the Snowflake connector is not")
    print("returning dictionaries. This causes '.get()' attribute errors.")
    print()
    print("Solution: Check snowflake_connector.py and ensure it returns")
    print("cursor.fetchall() results as dictionaries, not tuples or strings.")
    
    return True

if __name__ == "__main__":
    try:
        check_query_results()
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
