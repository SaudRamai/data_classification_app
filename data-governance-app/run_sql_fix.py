import os
import sys
# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.utils.snowflake_connector import SnowflakeConnector

def run_fix():
    print("Initializing Snowflake connection...")
    connector = SnowflakeConnector()
    
    print("1. Finding Category ID for 'date_of_birth'...")
    res = connector.execute_query("SELECT CATEGORY_ID FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS WHERE KEYWORD_STRING = 'date_of_birth' LIMIT 1")
    if not res:
        print("Error: Could not find 'date_of_birth' keyword!")
        return
    pii_cat_id = res[0]['CATEGORY_ID']
    print(f"  Found Category ID: {pii_cat_id}")
    
    print("2. Updating Category to PII...")
    update_sql = f"""
    UPDATE DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
    SET 
        POLICY_GROUP = 'PII',
        DESCRIPTION = 'Personal Identifiable Information including names, email addresses, phone numbers, physical addresses, SSN, passport numbers, driver licenses, dates of birth, biometric data, and any information that identifies a natural person'
    WHERE CATEGORY_ID = '{pii_cat_id}'
    """
    connector.execute_query(update_sql)
    print("  Success.")
    
    print("3. Finding Category ID for 'user_email'...")
    res_email = connector.execute_query("SELECT CATEGORY_ID FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS WHERE KEYWORD_STRING = 'user_email' LIMIT 1")
    if res_email:
        email_cat_id = res_email[0]['CATEGORY_ID']
        print(f"  Found Category ID: {email_cat_id}")
        if email_cat_id != pii_cat_id:
            print("  Updating 'user_email' category to PII...")
            connector.execute_query(f"UPDATE DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES SET POLICY_GROUP = 'PII' WHERE CATEGORY_ID = '{email_cat_id}'")
            print("  Success.")
        else:
            print("  Category ID matches 'date_of_birth' category. Already updated.")
    
    print("Done.")

if __name__ == "__main__":
    run_fix()
