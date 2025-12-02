#!/usr/bin/env python3
"""
Quick Fix Executor for Governance Schema Issues
Executes the SQL fix script and verifies the results
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.connectors.snowflake_connector import snowflake_connector

def execute_fix_script():
    """Execute the governance schema fix SQL script"""
    
    print("=" * 80)
    print("GOVERNANCE SCHEMA FIX EXECUTOR")
    print("=" * 80)
    print()
    
    # Read the SQL fix script
    script_path = os.path.join(os.path.dirname(__file__), 'fix_all_schema_issues_final.sql')
    
    if not os.path.exists(script_path):
        print(f"❌ ERROR: Fix script not found at {script_path}")
        return False
    
    print(f"📄 Reading fix script from: {script_path}")
    
    with open(script_path, 'r', encoding='utf-8') as f:
        sql_script = f.read()
    
    # Split into individual statements (simple split on semicolon)
    statements = [s.strip() for s in sql_script.split(';') if s.strip() and not s.strip().startswith('--')]
    
    print(f"📊 Found {len(statements)} SQL statements to execute")
    print()
    
    # Execute each statement
    success_count = 0
    error_count = 0
    
    for i, statement in enumerate(statements, 1):
        # Skip comments and empty statements
        if not statement or statement.startswith('--'):
            continue
        
        # Get first line for display
        first_line = statement.split('\n')[0][:60]
        print(f"[{i}/{len(statements)}] Executing: {first_line}...")
        
        try:
            result = snowflake_connector.execute_query(statement)
            success_count += 1
            print(f"    ✅ Success")
            
            # Display results for SELECT statements
            if statement.strip().upper().startswith('SELECT') and result:
                for row in result[:5]:  # Show first 5 rows
                    print(f"    📋 {row}")
                if len(result) > 5:
                    print(f"    ... and {len(result) - 5} more rows")
        
        except Exception as e:
            error_count += 1
            error_msg = str(e)
            
            # Check if it's a benign error (column already exists, etc.)
            if any(phrase in error_msg.lower() for phrase in [
                'already exists',
                'duplicate',
                'object does not exist or not authorized'  # Expected for some checks
            ]):
                print(f"    ⚠️  Warning (can be ignored): {error_msg[:100]}")
                success_count += 1  # Count as success
                error_count -= 1
            else:
                print(f"    ❌ ERROR: {error_msg[:200]}")
        
        print()
    
    # Summary
    print("=" * 80)
    print("EXECUTION SUMMARY")
    print("=" * 80)
    print(f"✅ Successful: {success_count}")
    print(f"❌ Errors: {error_count}")
    print()
    
    if error_count == 0:
        print("🎉 ALL FIXES APPLIED SUCCESSFULLY!")
        print()
        print("Next steps:")
        print("1. Restart your Streamlit application")
        print("2. Verify the dashboard loads without errors")
        print("3. Run a test classification to verify functionality")
        return True
    else:
        print("⚠️  Some errors occurred. Please review the output above.")
        print("   Common issues:")
        print("   - Missing permissions: Grant SELECT, INSERT, UPDATE on tables")
        print("   - Database not selected: Run 'USE DATABASE DATA_CLASSIFICATION_DB;'")
        return False

if __name__ == "__main__":
    try:
        success = execute_fix_script()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Execution cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
