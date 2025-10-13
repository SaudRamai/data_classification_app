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
from src.services.governance_db_resolver import resolve_governance_db
try:
    import streamlit as st
except Exception:  # allow service use outside Streamlit
    st = None

logger = logging.getLogger(__name__)

SCHEMA = "DATA_GOVERNANCE"  # default; will be overridden by session if provided
TABLE = "RECLASSIFICATION_REQUESTS"


class ReclassificationService:
    def __init__(self):
        self.connector = snowflake_connector
        self._ensure_table()

    def _schema(self) -> str:
        """Resolve governance schema: session → default."""
        try:
            if st is not None:
                v = st.session_state.get("governance_schema")
                if v and str(v).strip():
                    return str(v).strip()
        except Exception:
            pass
        return SCHEMA

    def _get_db(self) -> Optional[str]:
        """Resolve active database: session → settings → CURRENT_DATABASE()."""
        # Try dynamic governance DB resolver first
        try:
            db_res = resolve_governance_db()
            if db_res and str(db_res).strip():
                return str(db_res).strip()
        except Exception:
            pass
        # Session
        try:
            if st is not None:
                db = st.session_state.get("sf_database")
                # Treat common placeholders as invalid
                if db and str(db).strip() and str(db).strip().upper() not in {"NONE", "NULL", "UNKNOWN", "(NONE)"}:
                    return str(db).strip()
        except Exception:
            pass
        # Settings fallback
        try:
            dbs = getattr(settings, "SNOWFLAKE_DATABASE", None)
            if dbs:
                vv = str(dbs).strip()
                if vv and vv.upper() not in {"NONE", "NULL", "UNKNOWN", "(NONE)"}:
                    return vv
        except Exception:
            pass
        # Query CURRENT_DATABASE() last
        try:
            row = self.connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
            dbq = row[0].get("DB") if row else None
            if dbq:
                vv = str(dbq).strip()
                # Guard against placeholder values like 'NONE'
                if vv and vv.upper() not in {"NONE", "NULL", "UNKNOWN", "(NONE)"}:
                    return vv
        except Exception:
            pass
        # Fallback: pick the first available database and set context
        try:
            rows = self.connector.execute_query("SHOW DATABASES") or []
            first = None
            for r in rows:
                n = r.get("name") or r.get("NAME")
                if n and str(n).strip() and str(n).strip().upper() not in {"NONE", "NULL", "UNKNOWN", "(NONE)"}:
                    first = str(n).strip()
                    break
            if first:
                try:
                    self.connector.execute_non_query(f"USE DATABASE {first}")
                except Exception:
                    pass
                try:
                    if st is not None:
                        st.session_state['sf_database'] = first
                except Exception:
                    pass
                return first
        except Exception:
            pass
        return None

    def _tasks_name(self) -> str:
        """Resolve tasks table/view name: session override → default."""
        try:
            if st is not None:
                v = st.session_state.get("governance_tasks_view")
                if v and str(v).strip():
                    return str(v).strip()
        except Exception:
            pass
        return "CLASSIFICATION_TASKS"

    def _ensure_table(self) -> None:
        try:
            db = self._get_db()
            if not db:
                # No active DB context; skip ensure without failing
                return
            self.connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db}.{self._schema()}")
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {db}.{self._schema()}.{TABLE} (
                    ID VARCHAR(16777216),
                    ASSET_FULL_NAME VARCHAR(16777216),
                    TRIGGER_TYPE VARCHAR(16777216),
                    CURRENT_CLASSIFICATION VARCHAR(16777216),
                    CURRENT_C NUMBER(38,0),
                    CURRENT_I NUMBER(38,0),
                    CURRENT_A NUMBER(38,0),
                    PROPOSED_CLASSIFICATION VARCHAR(16777216),
                    PROPOSED_C NUMBER(38,0),
                    PROPOSED_I NUMBER(38,0),
                    PROPOSED_A NUMBER(38,0),
                    STATUS VARCHAR(16777216),
                    VERSION NUMBER(38,0),
                    JUSTIFICATION VARCHAR(16777216),
                    CREATED_BY VARCHAR(16777216),
                    APPROVED_BY VARCHAR(16777216),
                    CREATED_AT TIMESTAMP_NTZ(9),
                    UPDATED_AT TIMESTAMP_NTZ(9)
                )
                """
            )
            # Backfill missing columns if the table pre-existed with an older schema
            try:
                cols = self.connector.execute_query(
                    f"DESCRIBE TABLE {db}.{self._schema()}.{TABLE}"
                )
                existing = {str(c.get("name") or c.get("NAME") or "").upper() for c in (cols or [])}
                # Add CREATED_AT if missing
                if "CREATED_AT" not in existing:
                    self.connector.execute_non_query(
                        f"ALTER TABLE {db}.{self._schema()}.{TABLE} ADD COLUMN CREATED_AT TIMESTAMP_NTZ"
                    )
                if "UPDATED_AT" not in existing:
                    self.connector.execute_non_query(
                        f"ALTER TABLE {db}.{self._schema()}.{TABLE} ADD COLUMN UPDATED_AT TIMESTAMP_NTZ"
                    )
            except Exception as ie:
                logger.warning(f"Column backfill check failed for {self._schema()}.{TABLE}: {ie}")
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
            db = self._get_db()
            if not db:
                # Derive DB from asset_full_name (DB.SCHEMA.TABLE) and set session context
                try:
                    db = asset_full_name.split('.')[0]
                    # Validate derived DB against placeholder values
                    if db and str(db).strip().upper() not in {"NONE", "NULL", "UNKNOWN", "(NONE)"}:
                        self.connector.execute_non_query(f"USE DATABASE {db}")
                        try:
                            if st is not None:
                                st.session_state['sf_database'] = db
                        except Exception:
                            pass
                    else:
                        db = None
                except Exception:
                    db = None
            if not db:
                raise RuntimeError("No active database. Provide a DB in session/settings or use a fully qualified asset name.")
            self.connector.execute_non_query(
                f"""
                INSERT INTO {db}.{self._schema()}.{TABLE}
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
        db = self._get_db()
        if not db:
            raise RuntimeError("No active database. Set session sf_database or default SNOWFLAKE_DATABASE.")
        rows = self.connector.execute_query(
            f"SELECT * FROM {db}.{self._schema()}.{TABLE} WHERE ID = %(id)s",
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
            UPDATE {db}.{self._schema()}.{TABLE}
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
        db = self._get_db()
        if not db:
            raise RuntimeError("No active database. Set session sf_database or default SNOWFLAKE_DATABASE.")
        self.connector.execute_non_query(
            f"""
            UPDATE {db}.{self._schema()}.{TABLE}
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
        db = self._get_db()
        if not db:
            return 0

        # Helper: add N business days (Mon-Fri)
        def _add_business_days(start: datetime, days: int) -> datetime:
            cur = start
            added = 0
            while added < int(days):
                cur += timedelta(days=1)
                if cur.weekday() < 5:
                    added += 1
            return cur

        # Load unclassified assets and compute business-day SLA in Python
        try:
            inv_rows = self.connector.execute_query(
                f"""
                SELECT FULL_NAME, FIRST_DISCOVERED, OWNER
                FROM {db}.{self._schema()}.ASSET_INVENTORY
                WHERE COALESCE(CLASSIFIED, FALSE) = FALSE
                LIMIT 1000
                """
            ) or []
        except Exception as e:
            logger.warning(f"Inventory fetch failed: {e}")
            inv_rows = []

        now = datetime.utcnow()
        to_escalate: List[Dict[str, Any]] = []
        for r in inv_rows:
            full = r.get("FULL_NAME")
            fd = r.get("FIRST_DISCOVERED")
            try:
                first_discovered = fd if isinstance(fd, datetime) else datetime.fromisoformat(str(fd)) if fd else None
            except Exception:
                first_discovered = None
            if not first_discovered:
                continue
            due_5 = _add_business_days(first_discovered, 5)
            due_10 = _add_business_days(first_discovered, 10)
            # Create overdue request if past 5 business days
            if now > due_5:
                try:
                    self.submit_request(
                        full,
                        ("Internal", 1, 1, 1),
                        justification="Auto-trigger: Overdue classification (SLA 5 business days)",
                        created_by="system",
                        trigger_type="SLA_OVERDUE",
                    )
                    created += 1
                except Exception as e:
                    logger.warning(f"Failed to submit overdue trigger for {full}: {e}")
                # Auto-assign a task to the data owner
                try:
                    owner = (r.get("OWNER") or "").strip()
                    tasks = self._tasks_name()
                    # Ensure tasks table and upsert assignment
                    self.connector.execute_non_query(
                        f"""
                        create table if not exists {db}.{self._schema()}.{tasks} (
                          ASSET_FULL_NAME string,
                          ASSIGNED_TO string,
                          STATUS string,
                          DUE_DATE date,
                          CLASSIFICATION_LEVEL string
                        );
                        """
                    )
                    self.connector.execute_non_query(
                        f"""
                        merge into {db}.{self._schema()}.{tasks} t
                        using (select %(full)s as ASSET_FULL_NAME) s
                        on t.ASSET_FULL_NAME = s.ASSET_FULL_NAME
                        when matched then update set ASSIGNED_TO = %(assignee)s, STATUS = 'Pending', DUE_DATE = %(due)s
                        when not matched then insert (ASSET_FULL_NAME, ASSIGNED_TO, STATUS, DUE_DATE)
                        values (%(full)s, %(assignee)s, 'Pending', %(due)s)
                        """,
                        {"full": full, "assignee": owner or "", "due": due_5.date()}
                    )
                except Exception as e:
                    logger.warning(f"Failed to assign task for {full}: {e}")
            # Queue escalation notifications if past 10 business days
            if now > due_10:
                to_escalate.append({"FULL_NAME": full, "OWNER": (r.get("OWNER") or "").strip()})
                # Mark task as Overdue
                try:
                    tasks = self._tasks_name()
                    self.connector.execute_non_query(
                        f"""
                        update {db}.{self._schema()}.{tasks}
                        set STATUS = 'Overdue'
                        where ASSET_FULL_NAME = %(full)s
                        """,
                        {"full": full},
                    )
                except Exception:
                    pass

        # Send escalation notifications
        for er in to_escalate:
            owner = er.get("OWNER")
            full = er.get("FULL_NAME")
            subj = "Escalation: Classification Overdue >10 business days"
            body = f"Asset {full} remains unclassified beyond 10 business days. Please classify immediately or request an exception."
            if owner:
                try:
                    self.connector.execute_non_query(
                        f"""
                        INSERT INTO {db}.DATA_GOVERNANCE.NOTIFICATIONS_OUTBOX (ID, CHANNEL, TARGET, SUBJECT, BODY)
                        SELECT %(id)s, 'EMAIL', %(target)s, %(sub)s, %(body)s
                        """,
                        {"id": str(uuid.uuid4()), "target": owner, "sub": subj, "body": body},
                    )
                except Exception:
                    pass
            try:
                self.connector.execute_non_query(
                    f"""
                    INSERT INTO {db}.DATA_GOVERNANCE.NOTIFICATIONS_OUTBOX (ID, CHANNEL, TARGET, SUBJECT, BODY)
                    SELECT %(id)s, 'SLACK', '', %(sub)s, %(body)s
                    """,
                    {"id": str(uuid.uuid4()), "sub": subj, "body": body},
                )
            except Exception:
                pass

        rows2 = self.connector.execute_query(
            f"""
            SELECT FULL_NAME
            FROM {db}.{self._schema()}.ASSET_INVENTORY
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
        db = self._get_db()
        if not db:
            return []
        lim = int(limit or 100)
        if status:
            return self.connector.execute_query(
                f"SELECT * FROM {db}.{self._schema()}.{TABLE} WHERE STATUS = %(st)s ORDER BY CREATED_AT DESC LIMIT {lim}",
                {"st": status},
            )
        return self.connector.execute_query(
            f"SELECT * FROM {db}.{self._schema()}.{TABLE} ORDER BY CREATED_AT DESC LIMIT {lim}",
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
