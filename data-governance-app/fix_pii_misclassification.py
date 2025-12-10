import os
import sys
# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.utils.snowflake_connector import SnowflakeConnector

def run_pii_misclassification_fix():
    """
    Fix PII misclassification by removing duplicate keyword mappings.
    
    Problem: PII keywords (ssn, tax_id, fingerprint, etc.) are mapped to BOTH
             PII and SOC2 categories. This causes misclassification.
    
    Solution: Delete all PII keywords that are incorrectly mapped to SOC2/SOX.
    """
    print("=" * 80)
    print("FIX PII MISCLASSIFICATION ISSUE")
    print("=" * 80)
    
    print("\nInitializing Snowflake connection...")
    connector = SnowflakeConnector()
    
    # Switch to governance schema
    connector.execute_query("USE DATABASE DATA_CLASSIFICATION_DB")
    connector.execute_query("USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE")
    
    print("\n✅ Connected to DATA_CLASSIFICATION_GOVERNANCE schema")
    
    # ========================================================================
    # STEP 1: Backup existing keywords
    # ========================================================================
    print("\n" + "=" * 80)
    print("STEP 1: Backup existing keywords")
    print("=" * 80)
    
    try:
        connector.execute_query("""
            CREATE TABLE IF NOT EXISTS SENSITIVE_KEYWORDS_BACKUP_20251205 AS
            SELECT * FROM SENSITIVE_KEYWORDS
        """)
        
        result = connector.execute_query("""
            SELECT COUNT(*) as cnt FROM SENSITIVE_KEYWORDS_BACKUP_20251205
        """)
        print(f"✅ Backed up {result[0]['CNT']} keywords")
    except Exception as e:
        print(f"⚠️  Backup table may already exist: {e}")
    
    # ========================================================================
    # STEP 2: Identify problematic duplicate keywords
    # ========================================================================
    print("\n" + "=" * 80)
    print("STEP 2: Identify problematic duplicate PII keywords")
    print("=" * 80)
    
    duplicates_query = """
    SELECT 
        LOWER(sk.KEYWORD_STRING) AS keyword_lower,
        COUNT(DISTINCT sc.POLICY_GROUP) AS policy_group_count,
        LISTAGG(DISTINCT sc.POLICY_GROUP, ', ') 
            WITHIN GROUP (ORDER BY sc.POLICY_GROUP) AS all_policy_groups
    FROM SENSITIVE_KEYWORDS sk
    JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
    WHERE sk.IS_ACTIVE = TRUE
      AND LOWER(sk.KEYWORD_STRING) IN (
          'ssn', 'social_security', 'social_security_number',
          'tax', 'tax_id', 'tax_identification_number',
          'drivers_license', 'drivers', 'fingerprint', 'biometric'
      )
    GROUP BY LOWER(sk.KEYWORD_STRING)
    HAVING COUNT(DISTINCT sc.POLICY_GROUP) > 1
    """
    
    duplicates = connector.execute_query(duplicates_query)
    
    if duplicates:
        print(f"\n⚠️  Found {len(duplicates)} keywords with duplicate policy groups:")
        for dup in duplicates:
            print(f"   - {dup['KEYWORD_LOWER']}: {dup['ALL_POLICY_GROUPS']}")
    else:
        print("\n✅ No duplicate keywords found!")
    
    # ========================================================================
    # STEP 3: Delete incorrect PII→SOC2 mappings
    # ========================================================================
    print("\n" + "=" * 80)
    print("STEP 3: Delete incorrect PII→SOC2 mappings")
    print("=" * 80)
    
    delete_soc2_sql = """
    DELETE FROM SENSITIVE_KEYWORDS
    WHERE RULE_ID IN (
        SELECT sk.RULE_ID
        FROM SENSITIVE_KEYWORDS sk
        JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
        WHERE sk.IS_ACTIVE = TRUE
          AND sc.POLICY_GROUP = 'SOC2'
          AND LOWER(sk.KEYWORD_STRING) IN (
              -- National/Government IDs
              'ssn', 'social_security', 'social_security_number',
              'tax', 'tax_id', 'tax_identification', 'tax_identification_number',
              'national', 'national_id', 'national_id_number',
              'drivers', 'drivers_license', 'driver_license', 'drivers_license_number',
              'passport', 'passport_number',
              'voter', 'voter_id', 'voter_id_number',
              'military', 'military_id', 'military_id_number',
              'alien', 'alien_registration', 'alien_registration_number',
              
              -- Biometric PII
              'biometric', 'biometric_hash', 'biometric_data',
              'fingerprint', 'fingerprint_hash',
              'voice', 'voice_print', 'voiceprint',
              
              -- Health PII
              'health', 'health_condition', 'medical', 'medical_record',
              
              -- Sensitive Personal Attributes
              'ethnicity', 'race', 'religion',
              
              -- Security/Authentication PII
              'two_factor', '2fa', 'mfa',
              
              -- Location PII
              'gps', 'gps_coordinates', 'geolocation', 'location',
              
              -- Communication PII
              'voip', 'voip_call',
              
              -- Financial PII (personal level)
              'salary', 'income', 'annual_income'
          )
    )
    """
    
    try:
        connector.execute_query(delete_soc2_sql)
        print("✅ Deleted incorrect PII→SOC2 mappings")
    except Exception as e:
        print(f"❌ Error deleting SOC2 mappings: {e}")
    
    # ========================================================================
    # STEP 4: Delete incorrect PII→SOX mappings
    # ========================================================================
    print("\n" + "=" * 80)
    print("STEP 4: Delete incorrect PII→SOX mappings")
    print("=" * 80)
    
    delete_sox_sql = """
    DELETE FROM SENSITIVE_KEYWORDS
    WHERE RULE_ID IN (
        SELECT sk.RULE_ID
        FROM SENSITIVE_KEYWORDS sk
        JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
        WHERE sk.IS_ACTIVE = TRUE
          AND sc.POLICY_GROUP = 'SOX'
          AND LOWER(sk.KEYWORD_STRING) IN (
              'ssn', 'social_security', 'tax_id',
              'drivers_license', 'passport',
              'biometric', 'fingerprint',
              'ethnicity', 'religion'
          )
    )
    """
    
    try:
        connector.execute_query(delete_sox_sql)
        print("✅ Deleted incorrect PII→SOX mappings")
    except Exception as e:
        print(f"❌ Error deleting SOX mappings: {e}")
    
    # ========================================================================
    # STEP 5: Verify fix - check for remaining duplicates
    # ========================================================================
    print("\n" + "=" * 80)
    print("STEP 5: Verify fix - check for remaining duplicates")
    print("=" * 80)
    
    verify_duplicates = connector.execute_query(duplicates_query)
    
    if verify_duplicates:
        print(f"\n❌ Still found {len(verify_duplicates)} duplicate keywords:")
        for dup in verify_duplicates:
            print(f"   - {dup['KEYWORD_LOWER']}: {dup['ALL_POLICY_GROUPS']}")
    else:
        print("\n✅ SUCCESS: No duplicate keywords remain!")
    
    # ========================================================================
    # STEP 6: Show final PII keyword mappings
    # ========================================================================
    print("\n" + "=" * 80)
    print("STEP 6: Final PII keyword mappings")
    print("=" * 80)
    
    final_mappings = connector.execute_query("""
    SELECT 
        sk.KEYWORD_STRING,
        sc.CATEGORY_NAME,
        sc.POLICY_GROUP
    FROM SENSITIVE_KEYWORDS sk
    JOIN SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
    WHERE sk.IS_ACTIVE = TRUE
      AND LOWER(sk.KEYWORD_STRING) IN (
          'ssn', 'social_security_number',
          'tax_id', 'tax_identification_number',
          'drivers_license', 'drivers_license_number',
          'fingerprint', 'biometric',
          'ethnicity', 'religion'
      )
    ORDER BY sk.KEYWORD_STRING, sc.POLICY_GROUP
    """)
    
    print(f"\nFound {len(final_mappings)} PII keyword mappings:")
    for mapping in final_mappings:
        policy_group = mapping['POLICY_GROUP']
        status = "✅" if policy_group == "PII" else "❌"
        print(f"  {status} {mapping['KEYWORD_STRING']} → {policy_group}")
    
    # ========================================================================
    # FINAL STATUS
    # ========================================================================
    print("\n" + "=" * 80)
    print("FIX COMPLETE!")
    print("=" * 80)
    
    all_correct = all(m['POLICY_GROUP'] == 'PII' for m in final_mappings)
    
    if all_correct and not verify_duplicates:
        print("\n✅ SUCCESS: All PII keywords are now correctly mapped to PII category")
        print("\nNext steps:")
        print("  1. Re-run the classification pipeline on TEST_CUSTOMER_MASTER")
        print("  2. Verify that PII columns now show POLICY_GROUP = 'PII'")
        print("  3. Verify that SOC2 and SOX classifications still work correctly")
    else:
        print("\n⚠️  WARNING: Some issues remain - please review the output above")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    try:
        run_pii_misclassification_fix()
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
