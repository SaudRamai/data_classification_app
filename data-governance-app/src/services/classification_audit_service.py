"""
Classification Audit Service

- Fetches audit trail of classification events from Snowflake table CLASSIFICATION_AUDIT
  with filters for date range, dataset, classification level, and owner.
- Falls back to mock data when Snowflake is unavailable or table is missing.
- Keep this module pure (no Streamlit UI). UI lives in src/ui/classification_history_tab.py

Expected columns (target UI schema):
- dataset (DB.SCHEMA.OBJECT)
- prev_cia ("C/I/A" string)
- curr_cia ("C/I/A" string)
- overall_risk (string)
- approver_comments (string)
- submitted_at (timestamp)
- approved_at (timestamp)
- owner (string)
- classification_level (string)

Snowflake mapping notes:
- Replace the SELECT below to match your table/column names in {db}.{schema}.CLASSIFICATION_AUDIT
- If your schema differs (e.g., NEW_C, NEW_I, NEW_A, PREV_C, PREV_I, PREV_A, RISK, COMMENTS, SUBMITTED_AT, APPROVED_AT,
  OWNER, DATASET_NAME, CLASSIFICATION_LEVEL), map them into the returned dict shape.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

import logging

from src.services.repositories.classification_audit_repository import fetch_audit_rows as _repo_fetch

try:
    import streamlit as st
except Exception:  # pragma: no cover
    st = None

logger = logging.getLogger(__name__)


def _get_context() -> Tuple[str, str]:
    """Resolve database and governance schema from session or settings. No hardcoded DB default."""
    db = None
    schema = None
    try:
        if st is not None:
            db = st.session_state.get("sf_database")
            schema = st.session_state.get("governance_schema")
    except Exception:
        pass
    # Fallback to settings if provided (no hardcoded DB name)
    try:
        if not db:
            from src.config import settings  # type: ignore
            db = getattr(settings, "SNOWFLAKE_DATABASE", None)
    except Exception:
        pass
    # Schema can still default to a known governance schema name if unset
    if not db or not str(db).strip():
        raise ValueError("Snowflake database is not set in session or settings.")
    schema = (schema or "DATA_GOVERNANCE").strip()
    return str(db).strip(), schema


def fetch_audit(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    dataset_name: Optional[str] = None,
    classification_levels: Optional[List[str]] = None,
    owner: Optional[str] = None,
    limit: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Fetch audit rows using the Snowflake repository. Returns a list of dicts in the UI schema.

    If the Snowflake query fails (e.g., table missing, connection issues), returns mock data.
    """
    try:
        db, schema = _get_context()
        return _repo_fetch(
            database=db,
            schema=schema,
            start_date=start_date,
            end_date=end_date,
            dataset_name=dataset_name,
            classification_levels=classification_levels,
            owner=owner,
            limit=limit,
        )
    except Exception as e:
        logger.warning(
            "Falling back to mock audit data (Snowflake unavailable or table missing): %s",
            e,
        )
        # Mock dataset for UI development/testing
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        mock: List[Dict[str, Any]] = [
            {
                "dataset": "GOV_DB.PUBLIC.CUSTOMERS",
                "prev_cia": "1/1/1",
                "curr_cia": "2/2/2",
                "overall_risk": "High",
                "approver_comments": "PII detected; raising classification",
                "submitted_at": now,
                "approved_at": now,
                "owner": "owner@example.com",
                "classification_level": "Restricted",
            },
            {
                "dataset": "GOV_DB.SALES.ORDERS",
                "prev_cia": "0/1/1",
                "curr_cia": "1/1/1",
                "overall_risk": "Medium",
                "approver_comments": "Operational need",
                "submitted_at": now,
                "approved_at": now,
                "owner": "sales.owner@example.com",
                "classification_level": "Internal",
            },
        ]
        # Apply in-memory filters for mock to mimic behavior
        def _pass(row: Dict[str, Any]) -> bool:
            if dataset_name and dataset_name.lower() not in str(row["dataset"]).lower():
                return False
            if owner and owner.lower() not in str(row["owner"]).lower():
                return False
            if classification_levels and str(row.get("classification_level","")) not in classification_levels:
                return False
            # Date range filter is not applied for mock rows with string timestamps; skip for simplicity
            return True

        return [r for r in mock if _pass(r)][:limit]
