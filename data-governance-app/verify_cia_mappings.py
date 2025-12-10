"""
Verification Script: Ensure CIA Level Mappings Match Expected Detection
========================================================================

This script verifies that the AI classification pipeline correctly maps
categories to their CIA levels according to your specifications:

PII:  C2-Restricted, I2-Moderate, A2-Moderate (🟠 HIGH)
SOX:  C3-Confidential, I3-High, A3-High (🔴 CRITICAL)  
SOC2: C2-Restricted, I2-Moderate, A2-Moderate (🟠 HIGH)
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.snowflake_connector import snowflake_connector
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def verify_cia_mappings():
    """Verify that CIA mappings in governance tables match expected values."""
    
    logger.info("=" * 80)
    logger.info("VERIFYING CIA LEVEL MAPPINGS")
    logger.info("=" * 80)
    
    try:
        # Check current CIA levels in governance tables
        results = snowflake_connector.execute_query("""
            SELECT 
                CATEGORY_NAME,
                POLICY_GROUP,
                CONFIDENTIALITY_LEVEL,
                INTEGRITY_LEVEL,
                AVAILABILITY_LEVEL,
                DETECTION_THRESHOLD,
                MULTI_LABEL
            FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
            WHERE CATEGORY_NAME IN ('PII', 'SOX', 'SOC2')
            ORDER BY CATEGORY_NAME
        """)
        
        # Expected mappings
        expected = {
            'PII': {
                'CONFIDENTIALITY_LEVEL': 2,
                'INTEGRITY_LEVEL': 2,
                'AVAILABILITY_LEVEL': 2,
                'POLICY_GROUP': 'PII',
                'LABEL': 'Restricted',
                'SEVERITY': 'HIGH'
            },
            'SOX': {
                'CONFIDENTIALITY_LEVEL': 3,
                'INTEGRITY_LEVEL': 3,
                'AVAILABILITY_LEVEL': 3,
                'POLICY_GROUP': 'SOX',
                'LABEL': 'Confidential',
                'SEVERITY': 'CRITICAL'
            },
            'SOC2': {
                'CONFIDENTIALITY_LEVEL': 2,
                'INTEGRITY_LEVEL': 2,
                'AVAILABILITY_LEVEL': 2,
                'POLICY_GROUP': 'SOC2',
                'LABEL': 'Restricted',
                'SEVERITY': 'HIGH'
            }
        }
        
        print("\n" + "=" * 80)
        print("GOVERNANCE TABLE CIA LEVELS")
        print("=" * 80)
        
        all_correct = True
        
        for row in results:
            cat = row['CATEGORY_NAME']
            c = row['CONFIDENTIALITY_LEVEL']
            i = row['INTEGRITY_LEVEL']
            a = row['AVAILABILITY_LEVEL']
            pg = row['POLICY_GROUP']
            threshold = row['DETECTION_THRESHOLD']
            multi_label = row['MULTI_LABEL']
            
            exp = expected.get(cat, {})
            exp_c = exp.get('CONFIDENTIALITY_LEVEL')
            exp_i = exp.get('INTEGRITY_LEVEL')
            exp_a = exp.get('AVAILABILITY_LEVEL')
            exp_label = exp.get('LABEL')
            exp_severity = exp.get('SEVERITY')
            
            # Check if correct
            is_correct = (c == exp_c and i == exp_i and a == exp_a)
            
            status = "✓" if is_correct else "✗"
            
            print(f"\n{cat}:")
            print(f"  {status} CIA: C{c}-{exp_label}, I{i}-{'Moderate' if i==2 else 'High'}, A{a}-{'Moderate' if a==2 else 'High'}")
            print(f"  Expected: C{exp_c}, I{exp_i}, A{exp_a}")
            print(f"  Policy Group: {pg}")
            print(f"  Detection Threshold: {threshold}")
            print(f"  Multi-Label: {multi_label}")
            print(f"  Severity: 🟠 {exp_severity}" if exp_severity == 'HIGH' else f"  Severity: 🔴 {exp_severity}")
            
            if not is_correct:
                all_correct = False
                print(f"  ❌ MISMATCH! Expected C{exp_c}/I{exp_i}/A{exp_a}, got C{c}/I{i}/A{a}")
        
        print("\n" + "=" * 80)
        
        if all_correct:
            print("✅ ALL CIA MAPPINGS ARE CORRECT!")
        else:
            print("❌ SOME CIA MAPPINGS ARE INCORRECT - Run POPULATE_CORRECT_KEYWORDS.sql")
        
        print("=" * 80)
        
        # Check keyword counts
        print("\n" + "=" * 80)
        print("KEYWORD COVERAGE")
        print("=" * 80)
        
        keyword_counts = snowflake_connector.execute_query("""
            SELECT 
                sc.CATEGORY_NAME,
                COUNT(sk.KEYWORD_ID) as KEYWORD_COUNT,
                COUNT(CASE WHEN sk.MATCH_TYPE = 'EXACT' THEN 1 END) as EXACT_MATCHES,
                COUNT(CASE WHEN sk.MATCH_TYPE = 'CONTAINS' THEN 1 END) as CONTAINS_MATCHES,
                COUNT(CASE WHEN sk.SENSITIVITY_WEIGHT >= 0.90 THEN 1 END) as HIGH_WEIGHT
            FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES sc
            LEFT JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS sk 
                ON sc.CATEGORY_ID = sk.CATEGORY_ID AND sk.IS_ACTIVE = TRUE
            WHERE sc.CATEGORY_NAME IN ('PII', 'SOX', 'SOC2')
            GROUP BY sc.CATEGORY_NAME
            ORDER BY sc.CATEGORY_NAME
        """)
        
        for row in keyword_counts:
            cat = row['CATEGORY_NAME']
            total = row['KEYWORD_COUNT']
            exact = row['EXACT_MATCHES']
            contains = row['CONTAINS_MATCHES']
            high_weight = row['HIGH_WEIGHT']
            
            status = "✓" if total > 20 else "⚠️" if total > 10 else "❌"
            
            print(f"\n{cat}: {status}")
            print(f"  Total Keywords: {total}")
            print(f"  Exact Matches: {exact}")
            print(f"  Contains Matches: {contains}")
            print(f"  High Weight (≥0.90): {high_weight}")
            
            if total < 10:
                print(f"  ⚠️ WARNING: Only {total} keywords. Consider adding more.")
        
        print("\n" + "=" * 80)
        
        # Show sample high-value keywords
        print("\n" + "=" * 80)
        print("SAMPLE HIGH-VALUE KEYWORDS (Top 10 per category)")
        print("=" * 80)
        
        sample_keywords = snowflake_connector.execute_query("""
            WITH ranked AS (
                SELECT 
                    sc.CATEGORY_NAME,
                    sk.KEYWORD_STRING,
                    sk.MATCH_TYPE,
                    sk.SENSITIVITY_WEIGHT,
                    ROW_NUMBER() OVER (PARTITION BY sc.CATEGORY_NAME ORDER BY sk.SENSITIVITY_WEIGHT DESC, sk.KEYWORD_STRING) as rn
                FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES sc
                JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS sk 
                    ON sc.CATEGORY_ID = sk.CATEGORY_ID AND sk.IS_ACTIVE = TRUE
                WHERE sc.CATEGORY_NAME IN ('PII', 'SOX', 'SOC2')
            )
            SELECT CATEGORY_NAME, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT
            FROM ranked
            WHERE rn <= 10
            ORDER BY CATEGORY_NAME, SENSITIVITY_WEIGHT DESC
        """)
        
        current_cat = None
        for row in sample_keywords:
            cat = row['CATEGORY_NAME']
            kw = row['KEYWORD_STRING']
            match_type = row['MATCH_TYPE']
            weight = row['SENSITIVITY_WEIGHT']
            
            if cat != current_cat:
                print(f"\n{cat}:")
                current_cat = cat
            
            print(f"  • {kw:<40} (weight: {weight:.2f}, {match_type})")
        
        print("\n" + "=" * 80)
        print("VERIFICATION COMPLETE")
        print("=" * 80)
        
        return all_correct
        
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_sample_columns():
    """Test detection on sample columns from your list."""
    
    logger.info("\n" + "=" * 80)
    logger.info("TESTING SAMPLE COLUMN DETECTION")
    logger.info("=" * 80)
    
    test_columns = [
        'SOCIAL_SECURITY_NUMBER',
        'TAX_IDENTIFICATION_NUMBER',
        'BANK_ACCOUNT_NUMBER',
        'CREDIT_CARD_NUMBER',
        'USER_PASSWORD_HASH',
        'API_KEY',
        'OAUTH_TOKEN'
    ]
    
    print("\nAttempting keyword-based detection simulation:")
    print("(Full detection requires running the pipeline)")
    
    for col in test_columns:
        col_lower = col.lower()
        print(f"\n{col}:")
        
        # Check which categories would match
        results = snowflake_connector.execute_query(f"""
            SELECT 
                sc.CATEGORY_NAME,
                sc.POLICY_GROUP,
                sk.KEYWORD_STRING,
                sk.SENSITIVITY_WEIGHT,
                sk.MATCH_TYPE
            FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES sc
            JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS sk 
                ON sc.CATEGORY_ID = sk.CATEGORY_ID AND sk.IS_ACTIVE = TRUE
            WHERE LOWER('{col_lower}') LIKE '%' || LOWER(sk.KEYWORD_STRING) || '%'
            ORDER BY sk.SENSITIVITY_WEIGHT DESC
            LIMIT 5
        """)
        
        if results:
            for row in results:
                cat = row['CATEGORY_NAME']
                pg = row['POLICY_GROUP']
                kw = row['KEYWORD_STRING']
                weight = row['SENSITIVITY_WEIGHT']
                match_type = row['MATCH_TYPE']
                print(f"  ✓ Matches {cat} (keyword: '{kw}', weight: {weight:.2f}, {match_type})")
        else:
            print(f"  ❌ No keyword matches found!")
            print(f"     Check if keywords exist in governance tables")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("CIA LEVEL VERIFICATION SCRIPT")
    print("=" * 80)
    
    # Run verification
    mappings_correct = verify_cia_mappings()
    
    # Test sample columns
    test_sample_columns()
    
    # Final summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    if mappings_correct:
        print("✅ CIA mappings are correct in governance tables")
        print("✅ System should detect columns accurately")
        print("\nNext steps:")
        print("1. Re-run the classification pipeline")
        print("2. Check debug logs to see detection tier being used")
        print("3. Verify multi-label classification is working")
    else:
        print("❌ CIA mappings need correction")
        print("\nAction required:")
        print("1. Run: sql/POPULATE_CORRECT_KEYWORDS.sql")
        print("2. Restart the application")
        print("3. Re-run classification")
    
    print("=" * 80)
