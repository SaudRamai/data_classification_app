"""
Classification Decision Service
- Persists classification decisions and rationale for auditability (Policy 4.2.4, 6.1.2)
- Table: <DB>.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
"""
from typing import Optional, Dict, Any, Set
import uuid
import logging
from datetime import datetime

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.decision_matrix_service import compute_risk, validate
try:
    import streamlit as st  # type: ignore
except Exception:  # pragma: no cover
    st = None
try:
    from src.services.governance_db_resolver import resolve_governance_db
except Exception:
    resolve_governance_db = None  # fallback

logger = logging.getLogger(__name__)

SCHEMA = "DATA_GOVERNANCE"
TABLE = "CLASSIFICATION_DECISIONS"


class ClassificationDecisionService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        # Track ensured databases to avoid redundant DDL
        self._ensured_dbs: Set[str] = set()

    def _resolve_db(self) -> str:
        """Resolve target governance database: session -> resolver -> settings."""
        # 1) Session state (active DB)
        try:
            if st is not None:
                db = st.session_state.get("sf_database")
                if db and str(db).strip():
                    return str(db).strip()
        except Exception:
            pass
        # 2) Resolver service
        try:
            if resolve_governance_db is not None:
                db = resolve_governance_db()
                if db and str(db).strip():
                    return str(db).strip()
        except Exception:
            pass
        # 3) Settings fallback
        try:
            if getattr(settings, "SNOWFLAKE_DATABASE", None):
                return str(settings.SNOWFLAKE_DATABASE)
        except Exception:
            pass
        raise ValueError("Snowflake database is not set in session, resolver, or settings.")

    def _ensure_table_once(self, db: str) -> None:
        if db in self._ensured_dbs:
            return
        try:
            self.connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db}.{SCHEMA}")
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {db}.{SCHEMA}.{TABLE} (
                    ID STRING,
                    ASSET_FULL_NAME STRING,
                    DECISION_BY STRING,
                    DECISION_AT TIMESTAMP_NTZ,
                    SOURCE STRING,                 -- MANUAL, AI_SUGGESTED, AUTO, APPROVAL
                    STATUS STRING,                 -- Applied, Submitted, Approved, Rejected
                    LABEL STRING,                  -- Public, Internal, Restricted, Confidential
                    C NUMBER,
                    I NUMBER,
                    A NUMBER,
                    RISK_LEVEL STRING,             -- Low, Medium, High (computed)
                    RATIONALE STRING,
                    DETAILS VARIANT
                )
                """
            )
            self._ensured_dbs.add(db)
        except Exception as e:
            logger.error(f"Failed to ensure classification decisions table: {e}")

    def record(
        self,
        asset_full_name: str,
        decision_by: str,
        source: str,
        status: str,
        label: str,
        c: int,
        i: int,
        a: int,
        rationale: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        database: Optional[str] = None,
    ) -> str:
        # Resolve target DB and ensure table
        db = (str(database).strip() if database and str(database).strip() else self._resolve_db())
        self._ensure_table_once(db)
        did = str(uuid.uuid4())
        # Guardrails and risk computation
        ok, reasons = validate(label, c, i, a)
        if not ok:
            raise ValueError("; ".join(reasons))
        # Rationale is mandatory per policy; require non-empty string after strip
        if not rationale or not str(rationale).strip():
            raise ValueError("Rationale is required for classification decisions (Policy 6.1.2). Please provide justification.")
        risk = compute_risk(c, i, a)
        try:
            self.connector.execute_non_query(
                f"""
                INSERT INTO {db}.{SCHEMA}.{TABLE}
                (ID, ASSET_FULL_NAME, DECISION_BY, DECISION_AT, SOURCE, STATUS, LABEL, C, I, A, RISK_LEVEL, RATIONALE, DETAILS)
                SELECT %(id)s, %(full)s, %(by)s, CURRENT_TIMESTAMP, %(src)s, %(st)s, %(lab)s, %(c)s, %(i)s, %(a)s, %(risk)s, %(rat)s, TO_VARIANT(PARSE_JSON(%(det)s))
                """,
                {
                    "id": did,
                    "full": asset_full_name,
                    "by": decision_by,
                    "src": source,
                    "st": status,
                    "lab": label,
                    "c": int(c),
                    "i": int(i),
                    "a": int(a),
                    "risk": risk,
                    "rat": str(rationale).strip(),
                    "det": None if details is None else __import__("json").dumps(details),
                },
            )
            return did
        except Exception as e:
            logger.error(f"Failed to record classification decision: {e}")
            raise


classification_decision_service = ClassificationDecisionService()
