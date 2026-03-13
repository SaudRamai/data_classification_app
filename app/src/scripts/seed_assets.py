
import logging
import random
import uuid
from datetime import datetime, timedelta
from src.connectors.snowflake_connector import snowflake_connector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def seed_data():
    """
    Populates the ASSETS table with sample data matching the new schema.
    """
    db_name = "DATA_CLASSIFICATION_DB"
    schema_name = "DATA_CLASSIFICATION_GOVERNANCE"
    table_name = "ASSETS"
    fqn = f"{db_name}.{schema_name}.{table_name}"

    try:
        # Check if table exists
        check_query = f"SELECT count(*) FROM {fqn}"
        try:
            snowflake_connector.execute_query(check_query)
        except Exception:
            logger.warning(f"Table {fqn} does not exist or is not accessible. Skipping seed.")
            return

        # Sample data generation
        asset_types = ["TABLE", "VIEW"]
        business_units = ["Finance", "HR", "Marketing", "Sales", "Engineering", "Legal"]
        classifications = ["Public", "Internal", "Restricted", "Confidential"]
        classification_colors = {"Public": "green", "Internal": "blue", "Restricted": "orange", "Confidential": "red"}
        owners = ["data.steward@example.com", "compliance.officer@example.com", "hr.admin@example.com", "eng.lead@example.com"]
        
        insert_query = f"""
        INSERT INTO {fqn} (
            ASSET_ID, ASSET_NAME, ASSET_TYPE, DATABASE_NAME, SCHEMA_NAME, OBJECT_NAME, FULLY_QUALIFIED_NAME,
            BUSINESS_UNIT, DATA_OWNER, DATA_OWNER_EMAIL, CLASSIFICATION_LABEL, CLASSIFICATION_LABEL_COLOR,
            CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL, OVERALL_RISK_CLASSIFICATION,
            PII_RELEVANT, SOX_RELEVANT, SOC2_RELEVANT, REVIEW_STATUS, BUSINESS_DOMAIN, LIFECYCLE,
            CREATED_TIMESTAMP, LAST_MODIFIED_TIMESTAMP, COMPLIANCE_STATUS, DATA_CREATION_DATE
        ) VALUES (
            %(id)s, %(name)s, %(type)s, %(db)s, %(schema)s, %(obj)s, %(fqn)s,
            %(bu)s, %(owner)s, %(owner_email)s, %(label)s, %(color)s,
            %(c)s, %(i)s, %(a)s, %(risk)s,
            %(pii)s, %(sox)s, %(soc2)s, %(status)s, %(domain)s, %(lifecycle)s,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %(compliance)s, CURRENT_TIMESTAMP
        )
        """

        logger.info(f"Seeding {fqn} with sample data...")
        
        for i in range(50):
            at = random.choice(asset_types)
            bu = random.choice(business_units)
            cl = random.choice(classifications)
            owner_email = random.choice(owners)
            owner_name = owner_email.split('@')[0].replace('.', ' ').title()
            
            c_level = "C1"
            i_level = "I1"
            a_level = "A1"
            if cl == "Confidential": c_level = "C3"
            elif cl == "Restricted": c_level = "C2"
            
            risk = "Low"
            if cl == "Confidential": risk = "High"
            elif cl == "Restricted": risk = "Medium"
            
            is_pii = cl in ["Confidential", "Restricted"] and random.random() > 0.3
            is_sox = bu == "Finance" and random.random() > 0.5
            is_soc2 = True
            
            status = random.choice(["Approved", "Pending", "Draft"])
            compliance = "COMPLIANT" if status == "Approved" else "NON_COMPLIANT"

            name = f"Reference_Data_{i}"
            schema = "RAW" if i % 2 == 0 else "ANALYTICS"
            obj_name = f"{bu}_{name}_{i}".upper()
            full_name = f"{db_name}.{schema}.{obj_name}"

            params = {
                "id": str(uuid.uuid4()),
                "name": obj_name,
                "type": at,
                "db": db_name,
                "schema": schema,
                "obj": obj_name,
                "fqn": full_name,
                "bu": bu,
                "owner": owner_name,
                "owner_email": owner_email,
                "label": cl,
                "color": classification_colors[cl],
                "c": c_level,
                "i": i_level,
                "a": a_level,
                "risk": risk,
                "pii": is_pii,
                "sox": is_sox,
                "soc2": is_soc2,
                "status": status,
                "domain": random.choice(["Customer Data", "Finance Data", "HR Data", "Logistics", "Operations"]),
                "lifecycle": random.choice(["Active", "Archive", "Deprecated", "Development", "Staging"]),
                "compliance": compliance
            }
            
            snowflake_connector.execute_non_query(insert_query, params)

        logger.info("Seeding completed successfully.")

    except Exception as e:
        logger.error(f"Failed to seed data: {e}")

if __name__ == "__main__":
    seed_data()
