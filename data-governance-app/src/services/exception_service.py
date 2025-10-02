"""
Exception Management Service
- Submit, list, approve, reject, and auto-expire policy exceptions
- Persists artifacts in <DB>.DATA_GOVERNANCE.EXCEPTIONS (DB from settings)
"""
from typing import List, Dict, Any, Optional
import logging
import uuid
from datetime import datetime, timedelta

from src.connectors.snowflake_connector import snowflake_connector
from src.services.audit_service import audit_service
from src.config.settings import settings

logger = logging.getLogger(__name__)

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_GOVERNANCE"
TABLE = "EXCEPTIONS"
NTF_TABLE = "NOTIFICATIONS"


class ExceptionService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        self._ensure_table()

    def _ensure_table(self) -> None:
        try:
            self.connector.execute_non_query(
                f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}"
            )
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE} (
                    ID STRING,
                    ASSET_FULL_NAME STRING,
                    REGULATORY STRING,
                    JUSTIFICATION STRING,
                    RISK_LEVEL STRING,
                    STATUS STRING,
                    REQUESTED_BY STRING,
                    REQUESTED_AT TIMESTAMP_NTZ,
                    APPROVED_BY STRING,
                    APPROVED_AT TIMESTAMP_NTZ,
                    EXPIRES_AT TIMESTAMP_NTZ,
                    DETAILS VARIANT,
                    EVIDENCE_URL STRING
                )
                """
            )
            # Best-effort add columns if older table exists
            try:
                self.connector.execute_non_query(
                    f"ALTER TABLE {DB}.{SCHEMA}.{TABLE} ADD COLUMN EVIDENCE_URL STRING"
                )
            except Exception:
                pass
            # Ensure notifications table for reminders
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{NTF_TABLE} (
                    ID STRING,
                    EXCEPTION_ID STRING,
                    RECIPIENT STRING,
                    MESSAGE STRING,
                    CREATED_AT TIMESTAMP_NTZ,
                    TYPE STRING
                )
                """
            )
        except Exception as e:
            logger.error(f"Failed to ensure exceptions table: {e}")

    def submit(
        self,
        asset_full_name: str,
        regulatory: str,
        justification: str,
        risk_level: str,
        requested_by: str,
        days_valid: int = 90,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        eid = str(uuid.uuid4())
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        expires = (datetime.utcnow() + timedelta(days=days_valid)).strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.connector.execute_non_query(
                f"""
                INSERT INTO {DB}.{SCHEMA}.{TABLE}
                (ID, ASSET_FULL_NAME, REGULATORY, JUSTIFICATION, RISK_LEVEL, STATUS, REQUESTED_BY, REQUESTED_AT, EXPIRES_AT, DETAILS)
                SELECT %(id)s, %(full)s, %(reg)s, %(just)s, %(risk)s, 'Pending', %(req)s, %(ts)s, %(exp)s, TO_VARIANT(PARSE_JSON(%(det)s))
                """,
                {
                    "id": eid,
                    "full": asset_full_name,
                    "reg": regulatory,
                    "just": justification,
                    "risk": risk_level,
                    "req": requested_by,
                    "ts": now,
                    "exp": expires,
                    "det": (None if details is None else __import__("json").dumps(details)),
                },
            )
            audit_service.log(requested_by, "EXCEPTION_SUBMIT", "ASSET", asset_full_name, {"exception_id": eid, "regulatory": regulatory})
            return eid
        except Exception as e:
            logger.error(f"Failed to submit exception: {e}")
            raise

    def list(
        self,
        status: Optional[str] = None,
        limit: int = 200,
        asset_full_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        where = ["1=1"]
        params: Dict[str, Any] = {"lim": limit}
        if status and status != "All":
            where.append("STATUS = %(status)s")
            params["status"] = status
        if asset_full_name:
            where.append("UPPER(ASSET_FULL_NAME) = UPPER(%(full)s)")
            params["full"] = asset_full_name
        sql = f"SELECT * FROM {DB}.{SCHEMA}.{TABLE} WHERE {' AND '.join(where)} ORDER BY REQUESTED_AT DESC LIMIT %(lim)s"
        try:
            return self.connector.execute_query(sql, params)
        except Exception as e:
            logger.error(f"Failed to list exceptions: {e}")
            return []

    def approve(self, exception_id: str, approver: str) -> None:
        try:
            self.connector.execute_non_query(
                f"""
                UPDATE {DB}.{SCHEMA}.{TABLE}
                SET STATUS = 'Approved', APPROVED_BY = %(ap)s, APPROVED_AT = CURRENT_TIMESTAMP
                WHERE ID = %(id)s
                """,
                {"id": exception_id, "ap": approver},
            )
            audit_service.log(approver, "EXCEPTION_APPROVE", "EXCEPTION", exception_id, None)
        except Exception as e:
            logger.error(f"Failed to approve exception: {e}")
            raise

    def reject(self, exception_id: str, approver: str, justification: Optional[str] = None) -> None:
        try:
            self.connector.execute_non_query(
                f"""
                UPDATE {DB}.{SCHEMA}.{TABLE}
                SET STATUS = 'Rejected', APPROVED_BY = %(ap)s, APPROVED_AT = CURRENT_TIMESTAMP,
                    DETAILS = OBJECT_CONSTRUCT('rejection_reason', %(just)s)
                WHERE ID = %(id)s
                """,
                {"id": exception_id, "ap": approver, "just": justification or ""},
            )
            audit_service.log(approver, "EXCEPTION_REJECT", "EXCEPTION", exception_id, {"reason": justification})
        except Exception as e:
            logger.error(f"Failed to reject exception: {e}")
            raise

    def expire_auto(self) -> int:
        """Mark exceptions whose EXPIRES_AT < now as Expired. Returns count updated."""
        try:
            res = self.connector.execute_query(
                f"""
                SELECT COUNT(*) AS C FROM {DB}.{SCHEMA}.{TABLE}
                WHERE STATUS IN ('Pending','Approved') AND COALESCE(EXPIRES_AT, CURRENT_TIMESTAMP) < CURRENT_TIMESTAMP
                """
            )
            count = int(res[0]["C"]) if res else 0
            self.connector.execute_non_query(
                f"""
                UPDATE {DB}.{SCHEMA}.{TABLE}
                SET STATUS = 'Expired'
                WHERE STATUS IN ('Pending','Approved') AND COALESCE(EXPIRES_AT, CURRENT_TIMESTAMP) < CURRENT_TIMESTAMP
                """
            )
            return count
        except Exception as e:
            logger.error(f"Failed to expire exceptions: {e}")
            return 0

    def remind_upcoming(self, days_ahead: int = 7) -> int:
        """Create reminder notifications for exceptions expiring within days_ahead.
        Returns number of notifications created.
        """
        try:
            rows = self.connector.execute_query(
                f"""
                SELECT ID, REQUESTED_BY, EXPIRES_AT
                FROM {DB}.{SCHEMA}.{TABLE}
                WHERE STATUS IN ('Pending','Approved')
                  AND EXPIRES_AT IS NOT NULL
                  AND EXPIRES_AT <= DATEADD('day', %(ahead)s, CURRENT_TIMESTAMP)
                """,
                {"ahead": int(days_ahead)},
            ) or []
            created = 0
            for r in rows:
                try:
                    nid = str(uuid.uuid4())
                    msg = f"Exception {r['ID']} expires at {r.get('EXPIRES_AT')}"
                    self.connector.execute_non_query(
                        f"""
                        INSERT INTO {DB}.{SCHEMA}.{NTF_TABLE}
                        (ID, EXCEPTION_ID, RECIPIENT, MESSAGE, CREATED_AT, TYPE)
                        SELECT %(id)s, %(eid)s, %(rcpt)s, %(msg)s, CURRENT_TIMESTAMP, 'EXCEPTION_REMINDER'
                        """,
                        {"id": nid, "eid": r["ID"], "rcpt": r.get("REQUESTED_BY"), "msg": msg},
                    )
                    created += 1
                except Exception:
                    continue
            return created
        except Exception as e:
            logger.error(f"Failed to create reminders: {e}")
            return 0

    def set_evidence_link(self, exception_id: str, url: str) -> None:
        """Attach an evidence URL to the exception record."""
        try:
            self.connector.execute_non_query(
                f"""
                UPDATE {DB}.{SCHEMA}.{TABLE}
                SET EVIDENCE_URL = %(url)s
                WHERE ID = %(id)s
                """,
                {"id": exception_id, "url": url},
            )
            audit_service.log("system", "EXCEPTION_EVIDENCE_ATTACH", "EXCEPTION", exception_id, {"url": url})
        except Exception as e:
            logger.error(f"Failed to set evidence link: {e}")
            raise

    def maintain(self) -> dict:
        """Run lifecycle maintenance: reminders for upcoming expiry and auto-expire past due."""
        reminders = self.remind_upcoming(days_ahead=7)
        expired = self.expire_auto()
        return {"reminders": reminders, "expired": expired}


exception_service = ExceptionService()
