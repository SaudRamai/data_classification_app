"""
Classification Audit Service

- Centralized service for all audit-related concerns including classification history and general workflow events.
- Designates a single authoritative layer for audit writes and reads.
- Delegates to repository layers for Snowflake interactions.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import logging
import json
import hashlib

from src.services.repositories import audit_repository as _audit_repo
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

try:
    import streamlit as st
except Exception:
    st = None

logger = logging.getLogger(__name__)

class ClassificationAuditService:
    def __init__(self) -> None:
        self._ensure_initialized = False

    def _get_db(self) -> str:
        """Resolve database from session or settings."""
        db = None
        try:
            if st is not None:
                db = st.session_state.get("sf_database")
        except Exception:
            pass
        
        if not db:
            db = getattr(settings, "SNOWFLAKE_DATABASE", None)
            
        if not db or str(db).strip().upper() == 'NONE':
            # Last resort default if everything else fails
            return "DATA_CLASSIFICATION_DB"
        return str(db).strip()

    def _ensure_tables(self) -> None:
        """Lazy initialization of tables."""
        if self._ensure_initialized:
            return
        try:
            db = self._get_db()
            _audit_repo.ensure_audit_tables(db)
            self._ensure_initialized = True
        except Exception as e:
            logger.error(f"Failed to ensure audit tables: {e}")

    def log(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a generic workflow event.
        Alias for log_workflow_event provided for backward compatibility with audit_service.
        """
        self.log_workflow_event(user_id, action, resource_type, resource_id, details)

    def log_workflow_event(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a workflow event into the AUDIT_LOG table."""
        try:
            self._ensure_tables()
            db = self._get_db()
            _audit_repo.insert_audit_log(db, user_id, action, resource_type, resource_id, details)
        except Exception as e:
            logger.error(f"Failed to log workflow event: {e}")

    def query(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Query recent generic audit logs."""
        try:
            self._ensure_tables()
            db = self._get_db()
            return _audit_repo.query_audit_logs(db, limit)
        except Exception as e:
            logger.error(f"Failed to query audit logs: {e}")
            return []

    def fetch_audit(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        dataset_name: Optional[str] = None,
        classification_levels: Optional[List[str]] = None,
        owner: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Fetch classification history (from CLASSIFICATION_DECISIONS).
        Matches the expected UI schema for classification history.
        """
        try:
            db = self._get_db()
            # Note: classification_audit_repository defaults schema to DATA_GOVERNANCE
            return _audit_repo.fetch_audit_rows(
                database=db,
                start_date=start_date,
                end_date=end_date,
                dataset_name=dataset_name,
                classification_levels=classification_levels,
                owner=owner,
                limit=limit
            )
        except Exception as e:
            logger.error(f"Failed to fetch classification history: {e}")
            return []

    def compute_daily_digest(self, day: Optional[str] = None) -> Dict[str, Any]:
        """Compute and persist a daily audit digest for tamper evidence."""
        db = self._get_db()
        if not day:
            day = datetime.utcnow().strftime("%Y-%m-%d")
        
        try:
            self._ensure_tables()
            # Fetch logs for the day
            logs = snowflake_connector.execute_query(
                f"""
                SELECT TO_CHAR(TIMESTAMP, 'YYYY-MM-DD HH24:MI:SS.FF3') AS TS,
                       COALESCE(USER_ID,'' ) AS U,
                       COALESCE(ACTION,'' ) AS A,
                       COALESCE(RESOURCE_TYPE,'' ) AS RT,
                       COALESCE(RESOURCE_ID,'' ) AS RID,
                       COALESCE(TO_JSON(DETAILS),'') AS D
                FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.AUDIT_LOG
                WHERE TO_DATE(TIMESTAMP) = TO_DATE(%(d)s)
                ORDER BY TS, U, A, RT, RID
                """,
                {"d": day},
            ) or []
            
            h = hashlib.sha256()
            for r in logs:
                line = "|".join([str(r.get(k, "")) for k in ["TS","U","A","RT","RID","D"]])
                h.update(line.encode("utf-8"))
            digest = h.hexdigest()
            
            # Chain with previous day
            prev_dt = datetime.strptime(day, "%Y-%m-%d") - timedelta(days=1)
            prev_day = prev_dt.strftime("%Y-%m-%d")
            prev = _audit_repo.get_daily_digest(db, prev_day) or {}
            prev_sha = prev.get("SHA256_HEX") or prev.get("SHA256")
            
            chain_h = hashlib.sha256()
            chain_h.update((prev_sha or "").encode("utf-8"))
            chain_h.update(digest.encode("utf-8"))
            chain_digest = chain_h.hexdigest()
            
            _audit_repo.upsert_daily_digest(db, day, len(logs), digest, prev_sha, chain_digest)
            
            return {
                "date_key": day,
                "count": len(logs),
                "sha256": digest,
                "prev_sha256": prev_sha,
                "chain_sha256": chain_digest
            }
        except Exception as e:
            logger.error(f"Failed to compute daily digest: {e}")
            raise

    def get_daily_digest(self, day: str) -> Optional[Dict[str, Any]]:
        """Fetch a daily digest for a specific day."""
        try:
            db = self._get_db()
            return _audit_repo.get_daily_digest(db, day)
        except Exception as e:
            logger.error(f"Failed to get daily digest: {e}")
            return None

    def render_snowflake_task_sql(self, task_name: str = "DAILY_AUDIT_DIGEST_TASK", schedule: str = "USING CRON 0 0 * * * UTC") -> str:
        """Return SQL for a daily audit digest task."""
        db = self._get_db()
        return f"""
CREATE OR REPLACE TASK {task_name}
{schedule}
AS
BEGIN
  CREATE TEMP TABLE IF NOT EXISTS TMP_AUDIT_CHECK AS
  SELECT HASH_AGG(OBJECT_CONSTRUCT('ts',TO_CHAR(TIMESTAMP,'YYYY-MM-DD HH24:MI:SS.FF3'),'u',USER_ID,'a',ACTION,'rt',RESOURCE_TYPE,'rid',RESOURCE_ID,'d',DETAILS)) AS H, COUNT(*) AS C
  FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.AUDIT_LOG
  WHERE TO_DATE(TIMESTAMP) = CURRENT_DATE;
  
  MERGE INTO {db}.DATA_CLASSIFICATION_GOVERNANCE.DAILY_AUDIT_DIGESTS t
  USING (SELECT CURRENT_DATE AS DATE_KEY, C AS RECORD_COUNT, TO_VARCHAR(H) AS SHA256_HEX FROM TMP_AUDIT_CHECK) s
  ON t.DATE_KEY = s.DATE_KEY
  WHEN MATCHED THEN UPDATE SET t.RECORD_COUNT = s.RECORD_COUNT, t.SHA256_HEX = s.SHA256_HEX, t.CREATED_AT = CURRENT_TIMESTAMP
  WHEN NOT MATCHED THEN INSERT (DATE_KEY, RECORD_COUNT, SHA256_HEX) VALUES (s.DATE_KEY, s.RECORD_COUNT, s.SHA256_HEX);
END;
"""

# Create singleton instance
classification_audit_service = ClassificationAuditService()

# Export helper functions for backward compatibility with existing functional calls
def fetch_audit(*args, **kwargs):
    return classification_audit_service.fetch_audit(*args, **kwargs)

def log_workflow_event(*args, **kwargs):
    return classification_audit_service.log_workflow_event(*args, **kwargs)
