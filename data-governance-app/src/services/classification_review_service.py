"""
Classification Review Service

Provides data for the 'Pending Reviews' module:
- Pending approvals from CLASSIFICATION_HISTORY (APPROVAL_REQUIRED = TRUE AND APPROVED_BY IS NULL)
- High-risk classifications (CONFIDENTIALITY_LEVEL = 3) for management review
- Recent classification changes for peer review

Supports filters, pagination, and best-effort assignment to current user when columns exist.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    import streamlit as st
except Exception:  # pragma: no cover
    st = None

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings


def _active_db() -> str:
    try:
        if st is not None and st.session_state.get("sf_database"):
            return str(st.session_state.get("sf_database"))
    except Exception:
        pass
    try:
        if getattr(settings, "SNOWFLAKE_DATABASE", None):
            return str(settings.SNOWFLAKE_DATABASE)
    except Exception:
        pass
    raise ValueError("Snowflake database is not set in session or settings.")


def _schema_name() -> str:
    return "DATA_CLASSIFICATION_GOVERNANCE"


def _cache(ttl: int = 60):
    def deco(fn):
        if st is not None:
            return st.cache_data(ttl=ttl, show_spinner=False)(fn)
        return fn
    return deco


@_cache(ttl=60)
def list_reviews(
    current_user: str,
    review_filter: str = "All",  # All | Pending approvals | High-risk | Recent changes
    approval_status: str = "All pending",  # All pending | Pending my approval
    lookback_days: int = 30,
    page: int = 1,
    page_size: int = 50,
    database: Optional[str] = None,
) -> Dict[str, Any]:
    db = str(database or _active_db())
    sc = _schema_name()

    # Normalize filters
    rf = (review_filter or "All").lower()
    ap = (approval_status or "All pending").lower()
    lb = max(1, int(lookback_days))
    p = max(1, int(page))
    ps = max(1, min(500, int(page_size)))
    start = (p - 1) * ps + 1
    end = p * ps

    # We support flexible column presence for assignment (APPROVER_ASSIGNED/REVIEWER/MANAGER)
    # so we coalesce potential fields in SQL. If columns don't exist, COALESCE of non-existent
    # columns fails, so we guard using a SELECT with TRY_CAST of OBJECT_CONSTRUCT to detect columns.
    # To keep lightweight, we attempt to use generic names and tolerate errors via safe coalesces
    # on known fields only.

    sql = f"""
    with base as (
      select
        cast(HISTORY_ID as string) as ID,
        ASSET_ID,
        DATABASE_NAME,
        SCHEMA_NAME,
        ASSET_NAME,
        coalesce(CLASSIFICATION_TAG, PROPOSED_CLASSIFICATION, CURRENT_CLASSIFICATION, '') as CLASSIFICATION_TAG,
        coalesce(CONFIDENTIALITY_LEVEL, CIA_C, 0) as C_LEVEL,
        coalesce(APPROVAL_REQUIRED, false) as APPROVAL_REQUIRED,
        APPROVED_BY,
        CREATED_BY,
        CHANGE_TIMESTAMP,
        CHANGE_REASON,
        BUSINESS_JUSTIFICATION,
        -- best-effort reviewer/approver columns (optional)
        null as APPROVER_ASSIGNED
      from {db}.{sc}.CLASSIFICATION_HISTORY
    ),
    filtered as (
      select * from base b
      where 1=1
      -- Pending approvals filter
      {"and b.APPROVAL_REQUIRED = true and b.APPROVED_BY is null" if rf in ("all", "pending approvals") else ""}
      -- High-risk (C=3) requires management review
      {"and coalesce(b.C_LEVEL,0) = 3" if rf == "high-risk" else ""}
      -- Recent changes for peer review
      {"and b.CHANGE_TIMESTAMP >= dateadd('day', -%(lb)s, current_timestamp())" if rf == "recent changes" else ""}
      -- Approval status refinement
      {"and b.APPROVAL_REQUIRED = true and b.APPROVED_BY is null" if ap in ("all pending", "pending my approval") else ""}
      {"and upper(coalesce(b.CREATED_BY,'')) <> upper(%(me)s)" if ap == "pending my approval" else ""}
    ),
    numbered as (
      select f.*, row_number() over (order by f.CHANGE_TIMESTAMP desc nulls last, f.ID desc) as RN,
             count(*) over() as TOTAL
      from filtered f
    )
    select * from numbered where RN between %(start)s and %(end)s
    """

    params = {
        "lb": lb,
        "start": start,
        "end": end,
        "me": current_user or "",
    }

    try:
        rows = snowflake_connector.execute_query(sql, params) or []
        total = int(rows[0].get("TOTAL", 0)) if rows else 0
        items: List[Dict[str, Any]] = []
        for r in rows:
            items.append({
                "id": r.get("ID"),
                "asset_id": r.get("ASSET_ID"),
                "database": r.get("DATABASE_NAME"),
                "schema": r.get("SCHEMA_NAME"),
                "asset_name": r.get("ASSET_NAME"),
                "classification": r.get("CLASSIFICATION_TAG"),
                "c_level": r.get("C_LEVEL"),
                "approval_required": bool(r.get("APPROVAL_REQUIRED")),
                "approved_by": r.get("APPROVED_BY"),
                "created_by": r.get("CREATED_BY"),
                "change_timestamp": r.get("CHANGE_TIMESTAMP"),
                "change_reason": r.get("CHANGE_REASON"),
                "business_justification": r.get("BUSINESS_JUSTIFICATION"),
            })
        return {"reviews": items, "page": p, "page_size": ps, "total": total}
    except Exception as e:
        return {"reviews": [], "page": p, "page_size": ps, "total": 0, "error": str(e)}
