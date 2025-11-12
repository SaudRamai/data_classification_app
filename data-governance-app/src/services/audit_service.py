"""
Audit Service
- Provides immutable audit logging for key actions.
- Persists logs in Snowflake table <DB>.DATA_CLASSIFICATION_GOVERNANCE.AUDIT_LOG (DB from settings)
"""
from typing import Optional, Dict, Any, List
from datetime import datetime
import logging
import uuid

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
TABLE = "AUDIT_LOG"
DIGEST_TABLE = "DAILY_AUDIT_DIGESTS"


class AuditService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        self._ensure_table()

    def _get_db(self) -> Optional[str]:
        """Get database from settings or session state, with validation."""
        db = settings.SNOWFLAKE_DATABASE
        # Also try to get from streamlit session if available
        try:
            import streamlit as st
            if hasattr(st, 'session_state'):
                db = st.session_state.get('sf_database') or db
        except Exception:
            pass
        # Validate database is not None or 'NONE'
        if db and str(db).upper() not in ('NONE', 'NULL', ''):
            return str(db)
        return None

    def _ensure_table(self) -> None:
        try:
            db = self._get_db()
            if not db:
                logger.warning("No database configured for audit service, skipping table creation")
                return
            self.connector.execute_non_query(
                f"CREATE SCHEMA IF NOT EXISTS {db}.{SCHEMA}"
            )
            # Align with DDL from sql/001_governance_schema.sql (AUDIT_LOG)
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {db}.{SCHEMA}.{TABLE} (
                  TIMESTAMP TIMESTAMP_NTZ,
                  USER_ID STRING,
                  ACTION STRING,
                  RESOURCE_TYPE STRING,
                  RESOURCE_ID STRING,
                  DETAILS VARIANT
                )
                """
            )
            # Daily digests for tamper-evident summaries
            self.connector.execute_non_query(
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
            # Attempt to add missing columns if table pre-existed
            for col, typ in [("PREV_SHA256_HEX","STRING"),("CHAIN_SHA256_HEX","STRING")]:
                try:
                    self.connector.execute_non_query(
                        f"ALTER TABLE {db}.{SCHEMA}.{DIGEST_TABLE} ADD COLUMN {col} {typ}"
                    )
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Failed to ensure audit table: {e}")

    def log(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        db = self._get_db()
        if not db:
            logger.warning("No database configured for audit service, skipping log")
            return
        details_sql = "TO_VARIANT(PARSE_JSON(%(details)s))" if details is not None else "NULL"
        try:
            self.connector.execute_non_query(
                f"""
                INSERT INTO {db}.{SCHEMA}.{TABLE} (TIMESTAMP, USER_ID, ACTION, RESOURCE_TYPE, RESOURCE_ID, DETAILS)
                SELECT CURRENT_TIMESTAMP, %(user)s, %(action)s, %(rtype)s, %(rid)s, {details_sql}
                """,
                {
                    "user": user_id,
                    "action": action,
                    "rtype": resource_type,
                    "rid": resource_id,
                    "details": (None if details is None else __import__("json").dumps(details)),
                },
            )
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
            raise

    def query(self, limit: int = 100) -> List[Dict[str, Any]]:
        db = self._get_db()
        if not db:
            logger.warning("No database configured for audit service")
            return []
        try:
            return self.connector.execute_query(
                f"SELECT * FROM {db}.{SCHEMA}.{TABLE} ORDER BY TIMESTAMP DESC LIMIT %(limit)s",
                {"limit": limit},
            )
        except Exception as e:
            logger.error(f"Failed to query audit logs: {e}")
            return []

    def compute_daily_digest(self, day: Optional[str] = None) -> Dict[str, Any]:
        """Compute SHA256 digest of all audit rows for a given UTC day and persist to DAILY_AUDIT_DIGESTS.
        day format: 'YYYY-MM-DD'. If None, uses current UTC date.
        Returns a dict with date_key, count, sha256.
        """
        db = self._get_db()
        if not db:
            logger.warning("No database configured for audit service")
            return {"date_key": day or "", "count": 0, "sha256": "", "prev_sha256": None, "chain_sha256": ""}
        from hashlib import sha256
        from datetime import datetime as _dt
        if not day:
            day = _dt.utcnow().strftime("%Y-%m-%d")
        try:
            rows = self.connector.execute_query(
                f"""
                SELECT TO_CHAR(TIMESTAMP, 'YYYY-MM-DD HH24:MI:SS.FF3') AS TS,
                       COALESCE(USER_ID,'' ) AS U,
                       COALESCE(ACTION,'' ) AS A,
                       COALESCE(RESOURCE_TYPE,'' ) AS RT,
                       COALESCE(RESOURCE_ID,'' ) AS RID,
                       COALESCE(TO_JSON(DETAILS),'') AS D
                FROM {db}.{SCHEMA}.{TABLE}
                WHERE TO_DATE(TIMESTAMP) = TO_DATE(%(d)s)
                ORDER BY TS, U, A, RT, RID
                """,
                {"d": day},
            ) or []
            h = sha256()
            for r in rows:
                line = "|".join([str(r.get(k, "")) for k in ["TS","U","A","RT","RID","D"]])
                h.update(line.encode("utf-8"))
            digest = h.hexdigest()
            cnt = len(rows)
            # Get previous day's digest (for chaining)
            from datetime import datetime as _dt2, timedelta as _td
            dt = _dt2.strptime(day, "%Y-%m-%d")
            prev_day = (dt - _td(days=1)).strftime("%Y-%m-%d")
            prev = self.get_daily_digest(prev_day) or {}
            prev_sha = prev.get("SHA256_HEX") or prev.get("SHA256") or prev.get("SHA256_HEX".lower())
            chain_h = sha256()
            chain_h.update((prev_sha or "").encode("utf-8"))
            chain_h.update(digest.encode("utf-8"))
            chain_digest = chain_h.hexdigest()

            # Upsert digest for the day (idempotent overwrite)
            self.connector.execute_non_query(
                f"""
                MERGE INTO {db}.{SCHEMA}.{DIGEST_TABLE} t
                USING (
                  SELECT TO_DATE(%(d)s) AS DATE_KEY, %(c)s AS RECORD_COUNT, %(s)s AS SHA256_HEX,
                         %(ps)s AS PREV_SHA256_HEX, %(cs)s AS CHAIN_SHA256_HEX
                ) s 
                ON t.DATE_KEY = s.DATE_KEY
                WHEN MATCHED THEN UPDATE SET RECORD_COUNT = s.RECORD_COUNT, SHA256_HEX = s.SHA256_HEX,
                                            PREV_SHA256_HEX = s.PREV_SHA256_HEX, CHAIN_SHA256_HEX = s.CHAIN_SHA256_HEX,
                                            CREATED_AT = CURRENT_TIMESTAMP
                WHEN NOT MATCHED THEN INSERT (DATE_KEY, RECORD_COUNT, SHA256_HEX, PREV_SHA256_HEX, CHAIN_SHA256_HEX)
                                      VALUES (s.DATE_KEY, s.RECORD_COUNT, s.SHA256_HEX, s.PREV_SHA256_HEX, s.CHAIN_SHA256_HEX)
                """,
                {"d": day, "c": cnt, "s": digest, "ps": (prev_sha or None), "cs": chain_digest},
            )
            return {"date_key": day, "count": cnt, "sha256": digest, "prev_sha256": prev_sha, "chain_sha256": chain_digest}
        except Exception as e:
            logger.error(f"Failed to compute daily digest: {e}")
            raise

    def get_daily_digest(self, day: str) -> Optional[Dict[str, Any]]:
        db = self._get_db()
        if not db:
            logger.warning("No database configured for audit service")
            return None
        try:
            res = self.connector.execute_query(
                f"SELECT DATE_KEY, RECORD_COUNT, SHA256_HEX, PREV_SHA256_HEX, CHAIN_SHA256_HEX, CREATED_AT FROM {db}.{SCHEMA}.{DIGEST_TABLE} WHERE DATE_KEY = TO_DATE(%(d)s) LIMIT 1",
                {"d": day},
            ) or []
            return res[0] if res else None
        except Exception as e:
            logger.error(f"Failed to get daily digest: {e}")
            return None

    def render_snowflake_task_sql(self, task_name: str = "DAILY_AUDIT_DIGEST_TASK", schedule: str = "USING CRON 0 0 * * * UTC") -> str:
        """Return a Snowflake SQL snippet to create a daily task that persists a digest chain using HASH_AGG as a compact in-DB approximation.
        Note: This is best-effort; application-level SHA256 remains the source of truth for tamper-evidence.
        """
        db = DB
        schema = SCHEMA
        table = TABLE
        dig = DIGEST_TABLE
        # HASH_AGG provides 64-bit hash; useful for a quick in-DB marker
        return f"""
CREATE OR REPLACE TASK {task_name}
{schedule}
AS
BEGIN
  -- Compute compact in-DB digest marker for UTC current_date
  CREATE TEMP TABLE IF NOT EXISTS TMP_AUDIT_{'{'}TO_CHAR(CURRENT_DATE, 'YYYYMMDD'){'}'} AS
  SELECT HASH_AGG(OBJECT_CONSTRUCT('ts',TO_CHAR(TIMESTAMP,'YYYY-MM-DD HH24:MI:SS.FF3'),'u',USER_ID,'a',ACTION,'rt',RESOURCE_TYPE,'rid',RESOURCE_ID,'d',DETAILS)) AS H, COUNT(*) AS C
  FROM {db}.{schema}.{table}
  WHERE TO_DATE(TIMESTAMP) = CURRENT_DATE;
  MERGE INTO {db}.{schema}.{dig} t
  USING (
    SELECT CURRENT_DATE AS DATE_KEY,
           C AS RECORD_COUNT,
           TO_VARCHAR(H) AS SHA256_HEX
    FROM TMP_AUDIT_{'{'}TO_CHAR(CURRENT_DATE, 'YYYYMMDD'){'}'}
  ) s
  ON t.DATE_KEY = s.DATE_KEY
  WHEN MATCHED THEN UPDATE SET t.RECORD_COUNT = s.RECORD_COUNT, t.SHA256_HEX = s.SHA256_HEX, t.CREATED_AT = CURRENT_TIMESTAMP
  WHEN NOT MATCHED THEN INSERT (DATE_KEY, RECORD_COUNT, SHA256_HEX) VALUES (s.DATE_KEY, s.RECORD_COUNT, s.SHA256_HEX);
END;
"""


audit_service = AuditService()
