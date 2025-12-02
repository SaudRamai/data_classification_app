"""
Diagnostic Script: Category Centroids Check
=============================================

This script checks whether category centroids are properly loaded from the 
SENSITIVITY_CATEGORIES table.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.services.snowflake_connector import snowflake_connector
from src.services.governance_utils import resolve_governance_db

def main():
    print("=" * 80)
    print("CATEGORY CENTROIDS DIAGNOSTIC")
    print("=" * 80)
    
    # Step 1: Resolve governance database
    try:
        gov_db = resolve_governance_db()
        print(f"\n✓ Governance Database: {gov_db}")
    except Exception as e:
        print(f"\n✗ Failed to resolve governance database: {e}")
        return
    
    schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE" if gov_db else "DATA_CLASSIFICATION_GOVERNANCE"
    print(f"✓ Schema FQN: {schema_fqn}")
    
    # Step 2: Query SENSITIVITY_CATEGORIES
    print("\n" + "-" * 80)
    print("STEP 1: Querying SENSITIVITY_CATEGORIES")
    print("-" * 80)
    
    try:
        categories_data = snowflake_connector.execute_query(
            f"""
            SELECT 
                CATEGORY_ID,
                CATEGORY_NAME,
                COALESCE(DESCRIPTION, '') AS DESCRIPTION,
                POLICY_GROUP,
                COALESCE(IS_ACTIVE, TRUE) AS IS_ACTIVE
            FROM {schema_fqn}.SENSITIVITY_CATEGORIES
            WHERE COALESCE(IS_ACTIVE, true)
            ORDER BY CATEGORY_NAME
            """
        ) or []
        
        print(f"\n✓ Found {len(categories_data)} active categories")
        
        # Analyze each category
        valid_categories = 0
        skipped_categories = 0
        
        for idx, cat in enumerate(categories_data, 1):
            if not isinstance(cat, dict):
                print(f"\n  [{idx}] ✗ Row is not a dict: {type(cat)}")
                skipped_categories += 1
                continue
            
            cat_name = str(cat.get("CATEGORY_NAME") or "").strip()
            cat_id = cat.get("CATEGORY_ID")
            desc = str(cat.get("DESCRIPTION") or "").strip()
            pg = str(cat.get("POLICY_GROUP") or "None")
            
            print(f"\n  [{idx}] Category: {cat_name}")
            print(f"       ID: {cat_id}")
            print(f"       Policy Group: {pg}")
            print(f"       Description Length: {len(desc)} chars")
            
            # Validation checks
            if not cat_name:
                print(f"       ❌ SKIP REASON: Empty CATEGORY_NAME")
                skipped_categories += 1
                continue
            
            if not desc:
                print(f"       ❌ SKIP REASON: Empty DESCRIPTION (centroid cannot be built)")
                skipped_categories += 1
                continue
            
            if len(desc) < 10:
                print(f"       ⚠️  WARNING: Very short DESCRIPTION")
            
            print(f"       ✅ VALID - Will create centroid")
            valid_categories += 1
        
        # Summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total Categories Found: {len(categories_data)}")
        print(f"Valid Categories: {valid_categories}")
        print(f"Skipped Categories: {skipped_categories}")
        
        if valid_categories == 0:
            print("\n❌ CRITICAL: No valid categories found!")
            print("   Category centroids CANNOT be created.")
            print("\n   Possible issues:")
            print("   1. CATEGORY_NAME column is missing or NULL in all rows")
            print("   2. DESCRIPTION column is missing or empty in all rows")
            print("   3. IS_ACTIVE is FALSE for all rows")
        else:
            print(f"\n✅ SUCCESS: {valid_categories} category centroid(s) will be created")
        
    except Exception as e:
        print(f"\n✗ Failed to query SENSITIVITY_CATEGORIES: {e}")
        import traceback
        print(traceback.format_exc())
        return
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    main()
