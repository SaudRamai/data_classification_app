"""
Debug script to diagnose centroid initialization issues
"""

import sys
sys.path.insert(0, 'src')

from services.ai_classification_pipeline_service import AIClassificationPipelineService
from services.snowflake_connector import snowflake_connector
from services.governance_db_resolver import resolve_governance_db

def debug_centroid_initialization():
    print("=" * 80)
    print("DEBUGGING CENTROID INITIALIZATION")
    print("=" * 80)
    
    # Step 1: Check governance database
    print("\n1. Checking Governance Database...")
    try:
        gov_db = resolve_governance_db()
        print(f"   ✓ Governance DB: {gov_db}")
    except Exception as e:
        print(f"   ✗ Failed to resolve governance DB: {e}")
        return
    
    # Step 2: Check SENSITIVITY_CATEGORIES table
    print("\n2. Checking SENSITIVITY_CATEGORIES...")
    try:
        schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
        categories = snowflake_connector.execute_query(f"""
            SELECT 
                COALESCE(category_name, category, name) AS CATEGORY_NAME,
                COALESCE(description, desc, details, '') AS DESCRIPTION,
                COALESCE(is_active, true) AS IS_ACTIVE
            FROM {schema_fqn}.SENSITIVITY_CATEGORIES
            WHERE COALESCE(is_active, true)
        """)
        
        if categories:
            print(f"   ✓ Found {len(categories)} active categories:")
            for cat in categories:
                print(f"      - {cat.get('CATEGORY_NAME')}: {cat.get('DESCRIPTION')[:50]}...")
        else:
            print("   ✗ No active categories found!")
            print("   → This is why centroids are not being created")
            print("   → Please populate SENSITIVITY_CATEGORIES table")
            return
    except Exception as e:
        print(f"   ✗ Failed to query SENSITIVITY_CATEGORIES: {e}")
        return
    
    # Step 3: Check SENSITIVE_KEYWORDS table
    print("\n3. Checking SENSITIVE_KEYWORDS...")
    try:
        keywords = snowflake_connector.execute_query(f"""
            SELECT 
                c.CATEGORY_NAME,
                COUNT(*) as keyword_count
            FROM {schema_fqn}.SENSITIVE_KEYWORDS k
            JOIN {schema_fqn}.SENSITIVITY_CATEGORIES c
              ON k.CATEGORY_ID = c.CATEGORY_ID
            WHERE COALESCE(k.IS_ACTIVE, true)
              AND COALESCE(c.IS_ACTIVE, true)
            GROUP BY c.CATEGORY_NAME
        """)
        
        if keywords:
            print(f"   ✓ Found keywords for {len(keywords)} categories:")
            for kw in keywords:
                print(f"      - {kw.get('CATEGORY_NAME')}: {kw.get('KEYWORD_COUNT')} keywords")
        else:
            print("   ⚠ No keywords found")
            print("   → Centroids will be created from descriptions only")
    except Exception as e:
        print(f"   ✗ Failed to query SENSITIVE_KEYWORDS: {e}")
    
    # Step 4: Check SENSITIVE_PATTERNS table
    print("\n4. Checking SENSITIVE_PATTERNS...")
    try:
        patterns = snowflake_connector.execute_query(f"""
            SELECT 
                c.CATEGORY_NAME,
                COUNT(*) as pattern_count
            FROM {schema_fqn}.SENSITIVE_PATTERNS p
            JOIN {schema_fqn}.SENSITIVITY_CATEGORIES c
              ON p.CATEGORY_ID = c.CATEGORY_ID
            WHERE COALESCE(p.IS_ACTIVE, true)
              AND COALESCE(c.IS_ACTIVE, true)
            GROUP BY c.CATEGORY_NAME
        """)
        
        if patterns:
            print(f"   ✓ Found patterns for {len(patterns)} categories:")
            for pat in patterns:
                print(f"      - {pat.get('CATEGORY_NAME')}: {pat.get('PATTERN_COUNT')} patterns")
        else:
            print("   ⚠ No patterns found")
    except Exception as e:
        print(f"   ✗ Failed to query SENSITIVE_PATTERNS: {e}")
    
    # Step 5: Initialize pipeline and check centroids
    print("\n5. Initializing AI Classification Pipeline...")
    try:
        pipeline = AIClassificationPipelineService()
        
        # Check if centroids were created
        if hasattr(pipeline, '_category_centroids'):
            centroids = pipeline._category_centroids
            if centroids:
                print(f"   ✓ Created {len(centroids)} category centroids:")
                for cat, centroid in centroids.items():
                    if centroid is not None:
                        print(f"      - {cat}: ✓ (dimension: {len(centroid)})")
                    else:
                        print(f"      - {cat}: ✗ (failed to create)")
            else:
                print("   ✗ No centroids created!")
                print("   → Check if categories were loaded from governance tables")
        else:
            print("   ✗ _category_centroids attribute not found!")
        
        # Check if keywords were loaded
        if hasattr(pipeline, '_category_keywords'):
            keywords = pipeline._category_keywords
            if keywords:
                print(f"\n   ✓ Loaded keywords for {len(keywords)} categories:")
                for cat, kws in keywords.items():
                    print(f"      - {cat}: {len(kws)} keywords")
            else:
                print("\n   ✗ No keywords loaded!")
        
        # Check if patterns were loaded
        if hasattr(pipeline, '_category_patterns'):
            patterns = pipeline._category_patterns
            if patterns:
                print(f"\n   ✓ Loaded patterns for {len(patterns)} categories:")
                for cat, pats in patterns.items():
                    print(f"      - {cat}: {len(pats)} patterns")
            else:
                print("\n   ✗ No patterns loaded!")
        
    except Exception as e:
        print(f"   ✗ Failed to initialize pipeline: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 80)
    print("DIAGNOSIS COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    debug_centroid_initialization()
