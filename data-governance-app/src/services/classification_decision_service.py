"""
Classification Decision Service
- Persists classification decisions and rationale for auditability (Policy 4.2.4, 6.1.2)
- Table: <DB>.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
"""
from typing import Optional, Dict, Any
import uuid
import logging
from datetime import datetime

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.decision_matrix_service import compute_risk, validate

logger = logging.getLogger(__name__)

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_GOVERNANCE"
TABLE = "CLASSIFICATION_DECISIONS"


class ClassificationDecisionService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        # Defer table creation until first use to avoid import-time DB connections
        self._ensured = False

    def _ensure_table_once(self) -> None:
        if self._ensured:
            return
        try:
            self.connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}")
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE} (
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
            self._ensured = True
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
    ) -> str:
        # Ensure the table exists before recording
        self._ensure_table_once()
        did = str(uuid.uuid4())
        # Guardrails and risk computation
        ok, reasons = validate(label, c, i, a)
        if not ok:
            raise ValueError("; ".join(reasons))
        risk = compute_risk(c, i, a)
        try:
            self.connector.execute_non_query(
                f"""
                INSERT INTO {DB}.{SCHEMA}.{TABLE}
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
                    "rat": rationale or "",
                    "det": None if details is None else __import__("json").dumps(details),
                },
            )
            return did
        except Exception as e:
            logger.error(f"Failed to record classification decision: {e}")
            raise


classification_decision_service = ClassificationDecisionService()
