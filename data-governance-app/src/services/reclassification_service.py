"""
Reclassification Management Service
- Detects triggers (DDL changes, size/rowcount growth, lineage changes) and queues reclassification
- Manages approval workflow with versioning and applies approved changes via tagging
"""
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
import logging
import uuid

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_GOVERNANCE"
TABLE = "RECLASSIFICATION_REQUESTS"


class ReclassificationService:
    def __init__(self):
        self.connector = snowflake_connector
        self._ensure_table()

    def _ensure_table(self) -> None:
        try:
            self.connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}")
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE} (
                    ID STRING,
                    ASSET_FULL_NAME STRING,
                    TRIGGER_TYPE STRING,
                    CURRENT_CLASSIFICATION STRING,
                    CURRENT_C NUMBER,
                    CURRENT_I NUMBER,
                    CURRENT_A NUMBER,
                    PROPOSED_CLASSIFICATION STRING,
                    PROPOSED_C NUMBER,
                    PROPOSED_I NUMBER,
                    PROPOSED_A NUMBER,
                    STATUS STRING,
                    VERSION NUMBER,
                    JUSTIFICATION STRING,
                    CREATED_BY STRING,
                    APPROVED_BY STRING,
                    CREATED_AT TIMESTAMP_NTZ,
                    UPDATED_AT TIMESTAMP_NTZ
                )
                """
            )
            # Backfill missing columns if the table pre-existed with an older schema
            try:
                cols = self.connector.execute_query(
                    f"DESCRIBE TABLE {DB}.{SCHEMA}.{TABLE}"
                )
                existing = {str(c.get("name") or c.get("NAME") or "").upper() for c in (cols or [])}
                # Add CREATED_AT if missing
                if "CREATED_AT" not in existing:
                    self.connector.execute_non_query(
                        f"ALTER TABLE {DB}.{SCHEMA}.{TABLE} ADD COLUMN CREATED_AT TIMESTAMP_NTZ"
                    )
                if "UPDATED_AT" not in existing:
                    self.connector.execute_non_query(
                        f"ALTER TABLE {DB}.{SCHEMA}.{TABLE} ADD COLUMN UPDATED_AT TIMESTAMP_NTZ"
                    )
            except Exception as ie:
                logger.warning(f"Column backfill check failed for {DB}.{SCHEMA}.{TABLE}: {ie}")
        except Exception as e:
            logger.error(f"Failed to ensure reclassification table: {e}")

    def submit_request(
        self,
        asset_full_name: str,
        proposed: Tuple[str, int, int, int],
        justification: str,
        created_by: str,
        trigger_type: str = "MANUAL",
        current: Optional[Tuple[str, int, int, int]] = None,
    ) -> str:
        req_id = str(uuid.uuid4())
        cls, c, i, a = (current or (None, None, None, None))
        pcls, pc, pi, pa = proposed
        try:
            self.connector.execute_non_query(
                f"""
                INSERT INTO {DB}.{SCHEMA}.{TABLE}
                (ID, ASSET_FULL_NAME, TRIGGER_TYPE, CURRENT_CLASSIFICATION, CURRENT_C, CURRENT_I, CURRENT_A,
                 PROPOSED_CLASSIFICATION, PROPOSED_C, PROPOSED_I, PROPOSED_A, STATUS, VERSION, JUSTIFICATION, CREATED_BY,
                 CREATED_AT, UPDATED_AT)
                SELECT %(id)s, %(full)s, %(trig)s, %(ccls)s, %(cc)s, %(ci)s, %(ca)s,
                       %(pcls)s, %(pc)s, %(pi)s, %(pa)s, 'Pending', 1, %(just)s, %(user)s,
                       CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                """,
                {
                    "id": req_id,
                    "full": asset_full_name,
                    "trig": trigger_type,
                    "ccls": cls,
                    "cc": c,
                    "ci": i,
                    "ca": a,
                    "pcls": pcls,
                    "pc": pc,
                    "pi": pi,
                    "pa": pa,
                    "just": justification,
                    "user": created_by,
                },
            )
            # Local import to avoid import-time cycles/issues
            from src.services.audit_service import audit_service
            audit_service.log(created_by, "RECLASS_REQUEST_SUBMIT", "ASSET", asset_full_name, {"request_id": req_id})
            return req_id
        except Exception as e:
            logger.error(f"Failed to submit reclassification request: {e}")
            raise

    def approve(self, request_id: str, approver: str) -> None:
        # Fetch request
        rows = self.connector.execute_query(
            f"SELECT * FROM {DB}.{SCHEMA}.{TABLE} WHERE ID = %(id)s",
            {"id": request_id},
        )
        if not rows:
            raise ValueError("Request not found")
        r = rows[0]
        asset = r["ASSET_FULL_NAME"]
        pcls, pc, pi, pa = r["PROPOSED_CLASSIFICATION"], r["PROPOSED_C"], r["PROPOSED_I"], r["PROPOSED_A"]
        # Apply tags
        # Local imports to avoid import-time cycles/issues
        from src.services.tagging_service import tagging_service
        from src.services.discovery_service import discovery_service
        tagging_service.apply_tags_to_object(
            asset, "TABLE", {
                "DATA_CLASSIFICATION": pcls,
                "CONFIDENTIALITY_LEVEL": str(int(pc) if pc is not None else 0),
                "INTEGRITY_LEVEL": str(int(pi) if pi is not None else 0),
                "AVAILABILITY_LEVEL": str(int(pa) if pa is not None else 0),
            }
        )
        # Update inventory
        discovery_service.mark_classified(asset, pcls, int(pc or 0), int(pi or 0), int(pa or 0))
        # Update request
        self.connector.execute_non_query(
            f"""
            UPDATE {DB}.{SCHEMA}.{TABLE}
            SET STATUS = 'Approved', APPROVED_BY = %(ap)s, UPDATED_AT = CURRENT_TIMESTAMP
            WHERE ID = %(id)s
            """,
            {"ap": approver, "id": request_id},
        )
        from src.services.audit_service import audit_service
        audit_service.log(approver, "RECLASS_REQUEST_APPROVE", "ASSET", asset, {"request_id": request_id})
        # Record decision
        try:
            from src.services.classification_decision_service import classification_decision_service
            classification_decision_service.record(
                asset_full_name=asset,
                decision_by=approver,
                source="APPROVAL",
                status="Approved",
                label=pcls,
                c=int(pc or 0),
                i=int(pi or 0),
                a=int(pa or 0),
                rationale="Reclassification approved",
                details={"request_id": request_id},
            )
        except Exception:
            pass

    def reject(self, request_id: str, approver: str, justification: Optional[str] = None) -> None:
        # Local import to avoid import-time cycles/issues
        from src.services.audit_service import audit_service
        self.connector.execute_non_query(
            f"""
            UPDATE {DB}.{SCHEMA}.{TABLE}
            SET STATUS = 'Rejected', APPROVED_BY = %(ap)s, JUSTIFICATION = COALESCE(JUSTIFICATION, '') || ' | ' || %(just)s,
                UPDATED_AT = CURRENT_TIMESTAMP
            WHERE ID = %(id)s
            """,
            {"ap": approver, "id": request_id, "just": justification or ""},
        )
        audit_service.log(approver, "RECLASS_REQUEST_REJECT", "REQUEST", request_id, {"justification": justification})

    def detect_triggers(self) -> int:
        """Detect basic triggers based on DDL changes and unclassified assets; enqueue pending requests.
        Return count created.
        """
        created = 0
        # Unclassified assets older than 5 days
        rows = self.connector.execute_query(
            f"""
            SELECT FULL_NAME
            FROM {DB}.{SCHEMA}.ASSET_INVENTORY
            WHERE COALESCE(CLASSIFIED, FALSE) = FALSE
              AND FIRST_DISCOVERED < DATEADD(day, -5, CURRENT_TIMESTAMP)
            LIMIT 100
            """
        )
        for r in rows:
            full = r["FULL_NAME"]
            try:
                self.submit_request(
                    full,
                    ("Internal", 1, 1, 1),
                    justification="Auto-trigger: Overdue classification (SLA 5 days)",
                    created_by="system",
                    trigger_type="SLA_OVERDUE",
                )
                created += 1
            except Exception as e:
                logger.warning(f"Failed to submit overdue trigger for {full}: {e}")
        # DDL changes in last day -> re-evaluate
        rows2 = self.connector.execute_query(
            f"""
            SELECT FULL_NAME
            FROM {DB}.{SCHEMA}.ASSET_INVENTORY
            WHERE LAST_DDL_TIME > DATEADD(day, -1, CURRENT_TIMESTAMP)
            LIMIT 100
            """
        )
        for r in rows2:
            full = r["FULL_NAME"]
            try:
                self.submit_request(
                    full,
                    ("Internal", 1, 1, 1),
                    justification="Auto-trigger: Recent DDL change",
                    created_by="system",
                    trigger_type="DDL_CHANGE",
                )
                created += 1
            except Exception as e:
                logger.warning(f"Failed to submit DDL trigger for {full}: {e}")
        return created

    def list_requests(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        if status:
            return self.connector.execute_query(
                f"SELECT * FROM {DB}.{SCHEMA}.{TABLE} WHERE STATUS = %(st)s ORDER BY CREATED_AT DESC LIMIT %(lim)s",
                {"st": status, "lim": limit},
            )
        return self.connector.execute_query(
            f"SELECT * FROM {DB}.{SCHEMA}.{TABLE} ORDER BY CREATED_AT DESC LIMIT %(lim)s",
            {"lim": limit},
        )

class _LazyReclassificationService:
    """
    Lazily instantiate the real service on first attribute access.
    This avoids executing Snowflake DDL/DML at import time, which can
    raise and cause `ImportError: cannot import name 'reclassification_service'`.
    """
    def __init__(self):
        self._instance = None
        self._init_error = None

    def _ensure_instance(self):
        if self._instance is None and self._init_error is None:
            try:
                self._instance = ReclassificationService()
            except Exception as e:
                self._init_error = e
                logger.error(f"Failed to initialize ReclassificationService lazily: {e}")
                raise

    def __getattr__(self, item):
        self._ensure_instance()
        return getattr(self._instance, item)


reclassification_service = _LazyReclassificationService()
