"""
AI Audit Service
- Persists AI recommendations and user actions into DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
- Enables compliance/audit trails of AI-driven classification
"""
from __future__ import annotations

from typing import Dict, Any, Optional
from datetime import datetime
import json

from src.connectors.snowflake_connector import snowflake_connector


def _esc(v: Optional[str]) -> str:
    s = "" if v is None else str(v)
    return s.replace("'", "''")


def _num_str_to_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v))
    except Exception:
        return default


class AIAuditService:
    def log_decision(
        self,
        asset_full_name: str,
        user_id: str,
        action: str,
        tags: Optional[Dict[str, Any]] = None,
        rationale: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        t = tags or {}
        cia_conf = _num_str_to_int(t.get("CONFIDENTIALITY_LEVEL"), 0)
        cia_int = _num_str_to_int(t.get("INTEGRITY_LEVEL"), 0)
        cia_avail = _num_str_to_int(t.get("AVAILABILITY_LEVEL"), 0)
        classification = t.get("DATA_CLASSIFICATION") or ""
        rj = json.dumps(details or {}, default=str)
        sql = f"""
            INSERT INTO DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
            (ID, ASSET_FULL_NAME, USER_ID, ACTION, CLASSIFICATION_LEVEL, CIA_CONF, CIA_INT, CIA_AVAIL, RATIONALE, CREATED_AT, DETAILS)
            SELECT UUID_STRING(), '{_esc(asset_full_name)}', '{_esc(user_id)}', '{_esc(action)}', '{_esc(classification)}',
                   {cia_conf}, {cia_int}, {cia_avail}, '{_esc(rationale or '')}', CURRENT_TIMESTAMP,
                   PARSE_JSON('{_esc(rj)}')
        """
        snowflake_connector.execute_non_query(sql)


ai_audit = AIAuditService()
