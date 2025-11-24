import sys
import os
import logging

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
sys.path.append(os.path.dirname(__file__))

from src.utils.snowflake_connector import snowflake_connector
from src.services.governance_db_resolver import resolve_governance_db

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def seed_data():
    logger.info("Starting governance data seed...")
    
    try:
        gov_db = resolve_governance_db()
        schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
        logger.info(f"Target Schema: {schema_fqn}")
        
        snowflake_connector.execute_non_query(f"USE DATABASE {gov_db}")
        snowflake_connector.execute_non_query(f"USE SCHEMA DATA_CLASSIFICATION_GOVERNANCE")
        
    except Exception as e:
        logger.error(f"Failed to resolve governance DB: {e}")
        return

    # 1. Define Categories and Descriptions
    categories = [
        {
            "name": "PII",
            "description": """Personally Identifiable Information (PII). 
This category covers any information that can directly or indirectly identify a natural person, customer, client, employee, contractor, or user. 
PII includes data elements that reveal identity, demographics, contact information, authentication details, government identifiers, personal attributes, 
medical or biometric data, or any sensitive information tied to a specific individual.

Examples include:
- Full names, first/last names, maiden names, middle names  
- Email addresses, phone numbers, mobile numbers, fax numbers  
- Home/mailing address, city, state, ZIP/postal code, country  
- Date of birth, age, gender, nationality, citizenship, ethnicity, religion  
- Government-issued identifiers: SSN, Tax ID, TIN, EIN, passport number, driver’s license  
- Financial identifiers: credit/debit card numbers, CVV/CVC, IBAN, SWIFT, routing number, bank account number  
- Biometrics: fingerprints, iris scans, retina scans, facial recognition data, voice prints  
- Medical/health identifiers: patient IDs, diagnoses, prescriptions, treatment data  
- Authentication and login data: username, login ID, user ID, passwords, security questions, tokens  
- Network identifiers: IP address, MAC address, device IDs

Exclude system-generated or non-personal identifiers unless they can be traced back to an actual person."""
        },
        {
            "name": "SOC2",
            "description": """SOC 2 (Service Organization Control Type 2) Security, Availability, Integrity, Confidentiality, and Privacy Data. 
This category includes information related to cybersecurity controls, operational processes, system configurations, logging, 
access management, incident response, monitoring, and compliance activities aligned with the SOC 2 Trust Services Criteria (TSC).

Examples include:
- Access control data: user permissions, roles, privileges, access rights, access logs  
- Authentication/authorization: MFA, 2FA, tokens, identity verification  
- Security logs, audit logs, event logs, SIEM alerts  
- Encryption/decryption details, certificates, TLS/SSL, key management  
- Network security data: firewalls, IDS/IPS, intrusion detection logs  
- Vulnerability scans, penetration tests, security assessments  
- Incident response records, breach reports, security incident evidence  
- Disaster Recovery (DR), Business Continuity Planning (BCP), backup/restore logs  
- Change management: requests, approvals, configuration updates, releases  
- Segregation of Duties (SoD), access reviews, provisioning/deprovisioning  
- System hardening baselines, patch management, configuration standards  
- Data protection and privacy controls: GDPR, HIPAA, PCI-DSS-related mappings

Exclude non-security operational data not tied to access, configuration, or compliance controls."""
        },
        {
            "name": "SOX",
            "description": """SOX (Sarbanes-Oxley Act) Financial Reporting and Internal Controls Data. 
This category includes all information used for external financial reporting, internal controls, accounting processes, audits, 
regulatory compliance, revenue recognition, expenditure tracking, and any financial data that affects the accuracy and integrity 
of financial statements.

Examples include:
- General Ledger (GL), Journal Entries (JE), Trial Balance (TB), chart of accounts  
- Financial statements: Balance Sheet, Income Statement, Profit & Loss, Cash Flow Statement  
- Revenue, sales, expenses, cost of goods sold, assets, liabilities, equity  
- Accounts Payable (AP), Accounts Receivable (AR), invoices, billing, payments  
- Bank statements, reconciliations, accruals, deferrals, financial adjustments  
- Payroll, wages, bonuses, commissions, compensation  
- Purchase Orders (PO), Sales Orders (SO), receipts, procurement records  
- Budgeting, forecasting, variance analysis, financial planning  
- SOX controls, ICFR, audit trails, documentation, testing evidence, materiality thresholds  
- Fiscal year, quarter, period close metadata

Exclude general operational data unless it impacts financial reporting or SOX compliance."""
        }
    ]

    # 2. Update Categories
    logger.info("Updating SENSITIVITY_CATEGORIES...")
    for cat in categories:
        try:
            # Check if exists
            exists = snowflake_connector.execute_query(
                f"SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = '{cat['name']}'"
            )
            
            desc_safe = cat['description'].replace("'", "''")
            
            if exists:
                logger.info(f"  Updating {cat['name']}...")
                snowflake_connector.execute_non_query(
                    f"""
                    UPDATE {schema_fqn}.SENSITIVITY_CATEGORIES 
                    SET DESCRIPTION = '{desc_safe}', IS_ACTIVE = TRUE 
                    WHERE CATEGORY_NAME = '{cat['name']}'
                    """
                )
            else:
                logger.info(f"  Inserting {cat['name']}...")
                snowflake_connector.execute_non_query(
                    f"""
                    INSERT INTO {schema_fqn}.SENSITIVITY_CATEGORIES (CATEGORY_NAME, DESCRIPTION, IS_ACTIVE)
                    VALUES ('{cat['name']}', '{desc_safe}', TRUE)
                    """
                )
        except Exception as e:
            logger.error(f"Error updating category {cat['name']}: {e}")

    # 3. Insert Keywords (Sample from input)
    # Map Category Name -> List of Keywords
    keywords_map = {
        "PII": [
            "account_number", "bank_account", "bank_account_number", "biometric", "birth_date", 
            "card_number", "credit_card", "credit_card_number", "cvv", "date_of_birth", "dob", 
            "driver_license", "drivers_license", "drivers_license_number", "email_address", 
            "ethnicity", "fingerprint", "first_name", "full_name", "government_id_number", 
            "home_address", "home_phone", "iban", "last_name", "mailing_address", "marital_status", 
            "medical_record", "mobile_number", "national_id", "national_identifier", "passport", 
            "passport_number", "patient_id", "patient_medical_record", "personal_email", 
            "phone_number", "postal_code", "routing_number", "social_security", 
            "social_security_number", "ssn", "street_address", "swift_code", "tax_id", 
            "tax_identification_number", "work_email", "zip_code"
        ],
        "SOC2": [
            "access_control", "access_control_list", "access_log", "access_review_log", 
            "access_token", "api_key", "api_secret", "authentication", "authentication_token", 
            "authorization", "bearer_token", "breach_notification", "change_log", 
            "change_management_log", "disaster_recovery", "encryption", "encryption_algorithm", 
            "encryption_key", "firewall_rule", "incident_response_plan", "jwt_token", 
            "login_password", "oauth_token", "password", "private_key", "role_based_access", 
            "secret_key", "security_audit_log", "security_event", "security_incident", 
            "security_incident_report", "security_log", "security_policy", "session_cookie", 
            "session_id", "ssl_certificate", "system_audit_trail", "system_config", 
            "tls_certificate", "user_credentials", "user_permissions", "vulnerability"
        ],
        "SOX": [
            "accounting_entry"
            # ... truncated in input, but we add what we have
        ]
    }

    logger.info("Updating SENSITIVE_KEYWORDS...")
    for cat_name, kws in keywords_map.items():
        try:
            # Get Category ID
            res = snowflake_connector.execute_query(
                f"SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE CATEGORY_NAME = '{cat_name}'"
            )
            if not res:
                logger.warning(f"Skipping keywords for {cat_name} (Category not found)")
                continue
            
            cat_id = res[0]['CATEGORY_ID']
            
            # Delete existing keywords for this category to avoid duplicates/stale data
            snowflake_connector.execute_non_query(
                f"DELETE FROM {schema_fqn}.SENSITIVE_KEYWORDS WHERE CATEGORY_ID = {cat_id}"
            )
            
            # Insert new keywords
            values = []
            for kw in kws:
                values.append(f"({cat_id}, '{cat_name}', '{kw}', 'PARTIAL', 1.0, TRUE)")
            
            if values:
                stmt = f"""
                INSERT INTO {schema_fqn}.SENSITIVE_KEYWORDS 
                (CATEGORY_ID, CATEGORY_NAME, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE)
                VALUES {','.join(values)}
                """
                snowflake_connector.execute_non_query(stmt)
                logger.info(f"  Inserted {len(values)} keywords for {cat_name}")
                
        except Exception as e:
            logger.error(f"Error updating keywords for {cat_name}: {e}")

    logger.info("✅ Governance data seed complete.")

if __name__ == "__main__":
    seed_data()
