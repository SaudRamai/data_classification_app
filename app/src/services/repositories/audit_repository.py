"""
Audit Repository
Handles database interactions for the AUDIT_LOG and DAILY_AUDIT_DIGESTS tables.
"""
from typing import Optional, Dict, Any, List
import logging
import json
from datetime import datetime, date, timedelta
from src.connectors.snowflake_connector import snowflake_connector

logger = logging.getLogger(__name__)

SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
LOG_TABLE = "AUDIT_LOG"
DIGEST_TABLE = "DAILY_AUDIT_DIGESTS"

def ensure_audit_tables(db: str) -> None:
    """Ensure audit tables exist in the specified database."""
    try:
        snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db}.{SCHEMA}")
        
        # Main audit log table
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {db}.{SCHEMA}.{LOG_TABLE} (
              TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
              USER_ID STRING,
              ACTION STRING,
              RESOURCE_TYPE STRING,
              RESOURCE_ID STRING,
              DETAILS VARIANT
            )
            """
        )
        
        # Daily digests for tamper-evidence
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {db}.{SCHEMA}.{DIGEST_TABLE} (
              DATE_KEY DATE,
              RECORD_COUNT NUMBER,
              SHA256_HEX STRING,
              PREV_SHA256_HEX STRING,
              CHAIN_SHA256_HEX STRING,
              CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        
        # Add missing columns if they don't exist
        for col, typ in [("PREV_SHA256_HEX","STRING"),("CHAIN_SHA256_HEX","STRING")]:
            try:
                snowflake_connector.execute_non_query(
                    f"ALTER TABLE {db}.{SCHEMA}.{DIGEST_TABLE} ADD COLUMN {col} {typ}"
                )
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Failed to ensure audit tables: {e}")

def insert_audit_log(
    db: str,
    user_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """Insert a new record into the audit log."""
    details_json = json.dumps(details) if details is not None else None
    try:
        snowflake_connector.execute_non_query(
            f"""
            INSERT INTO {db}.{SCHEMA}.{LOG_TABLE} (TIMESTAMP, USER_ID, ACTION, RESOURCE_TYPE, RESOURCE_ID, DETAILS)
            SELECT CURRENT_TIMESTAMP, %(user)s, %(action)s, %(rtype)s, %(rid)s, 
                   TRY_PARSE_JSON(%(details)s)
            """,
            {
                "user": user_id,
                "action": action,
                "rtype": resource_type,
                "rid": resource_id,
                "details": details_json,
            }
        )
    except Exception as e:
        logger.error(f"Failed to insert audit log: {e}")
        raise


def get_daily_digest(db: str, day: str) -> Optional[Dict[str, Any]]:
    """Fetch daily digest record for a specific date."""
    try:
        res = snowflake_connector.execute_query(
            f"SELECT * FROM {db}.{SCHEMA}.{DIGEST_TABLE} WHERE DATE_KEY = TO_DATE(%(d)s) LIMIT 1",
            {"d": day}
        ) or []
        return res[0] if res else None
    except Exception as e:
        logger.error(f"Failed to get daily digest: {e}")
        return None


def fetch_audit_rows(
    database: Optional[str] = None,
    schema: str = "DATA_CLASSIFICATION_GOVERNANCE", 
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    dataset_name: Optional[str] = None,
    classification_levels: Optional[List[str]] = None,
    owner: Optional[str] = None,
    limit: int = 1000
) -> List[Dict[str, Any]]:
    """Fetch classification audit rows from CLASSIFICATION_DECISIONS."""
    try:
        query = f"""
        SELECT 
            ASSET_FULL_NAME as dataset,
            '0/0/0' as prev_cia,
            COALESCE(C, 0) || '/' || COALESCE(I, 0) || '/' || COALESCE(A, 0) as curr_cia,
            CASE 
                WHEN GREATEST(COALESCE(C, 0), COALESCE(I, 0), COALESCE(A, 0)) >= 3 THEN 'High'
                WHEN GREATEST(COALESCE(C, 0), COALESCE(I, 0), COALESCE(A, 0)) >= 2 THEN 'Medium'
                ELSE 'Low'
            END as overall_risk,
            COALESCE(RATIONALE, '') as approver_comments,
            DECISION_AT as submitted_at,
            DECISION_AT as approved_at,
            COALESCE(DECISION_BY, 'Unknown') as owner,
            COALESCE(LABEL, 'Unclassified') as classification_level
        FROM {database}.{schema}.CLASSIFICATION_DECISIONS
        WHERE 1=1
        """
        params = {}
        if start_date:
            query += " AND DATE(DECISION_AT) >= %(start_date)s"
            params["start_date"] = start_date
        if end_date:
            query += " AND DATE(DECISION_AT) <= %(end_date)s"
            params["end_date"] = end_date
        if dataset_name:
            query += " AND UPPER(ASSET_FULL_NAME) LIKE UPPER(%(dataset_name)s)"
            params["dataset_name"] = f"%{dataset_name}%"
        if classification_levels:
            placeholders = [f"%(cl_{i})s" for i in range(len(classification_levels))]
            for i, level in enumerate(classification_levels): params[f"cl_{i}"] = level
            query += f" AND UPPER(LABEL) IN ({','.join(placeholders)})"
        if owner:
            query += " AND UPPER(DECISION_BY) LIKE UPPER(%(owner)s)"
            params["owner"] = f"%{owner}%"
        
        query += f" ORDER BY DECISION_AT DESC LIMIT {limit}"
        rows = snowflake_connector.execute_query(query, params) or []
        return [{
            "dataset": r.get("DATASET", ""),
            "prev_cia": r.get("PREV_CIA", "0/0/0"),
            "curr_cia": r.get("CURR_CIA", "0/0/0"),
            "overall_risk": r.get("OVERALL_RISK", "Low"),
            "approver_comments": r.get("APPROVER_COMMENTS", ""),
            "submitted_at": r.get("SUBMITTED_AT"),
            "approved_at": r.get("APPROVED_AT"),
            "owner": r.get("OWNER", "Unknown"),
            "classification_level": r.get("CLASSIFICATION_LEVEL", "Unclassified")
        } for r in rows]
    except Exception as e:
        logger.error(f"Failed to fetch audit rows: {e}")
        return []

