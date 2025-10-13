"""
Classification History & Audit Service

Provides a timeline of classification changes from CLASSIFICATION_HISTORY with filters:
- Date range
- Users (created_by / approved_by)
- Classification levels (label and/or C level)
Includes business justification and change reasons.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    import streamlit as st
except Exception:  # pragma: no cover
    st = None

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.governance_db_resolver import resolve_governance_db


def _active_db() -> str:
    # Try dynamic governance DB resolver first
    try:
        db_res = resolve_governance_db()
        if db_res and str(db_res).strip():
            return str(db_res)
    except Exception:
        pass
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
    raise ValueError("Snowflake database is not set in session, resolver, or settings.")


def _cache(ttl: int = 60):
    def deco(fn):
        if st is not None:
            return st.cache_data(ttl=ttl, show_spinner=False)(fn)
        return fn
    return deco


@_cache(ttl=60)
def query_history(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    users: Optional[List[str]] = None,
    levels: Optional[List[str]] = None,  # classification labels like Public/Internal/Restricted/Confidential
    c_levels: Optional[List[int]] = None,  # numeric C levels
    page: int = 1,
    page_size: int = 100,
    database: Optional[str] = None,
) -> Dict[str, Any]:
    db = str(database or _active_db())
    sc = "DATA_CLASSIFICATION_GOVERNANCE"
    p = max(1, int(page))
    ps = max(1, min(1000, int(page_size)))
    start = (p - 1) * ps + 1
    end = p * ps

    where_clauses: List[str] = []
    params: Dict[str, Any] = {"start": start, "end": end}
    if start_date and end_date:
        where_clauses.append("h.CHANGE_TIMESTAMP between %(sd)s and %(ed)s")
        params["sd"] = start_date
        params["ed"] = end_date
    if users:
        # Build IN list directly to avoid binding as a single literal
        users_in = ",".join([f"'{str(u).upper()}".replace("'","''") + "'" for u in users if u]) or "''"
        where_clauses.append(
            f"(upper(coalesce(h.CHANGED_BY,'')) in ({users_in}) or upper(coalesce(h.APPROVED_BY,'')) in ({users_in}))"
        )
    if levels:
        levels_in = ",".join([f"'{str(l).upper()}".replace("'","''") + "'" for l in levels if l]) or "''"
        # Prefer NEW_CLASSIFICATION, fallback to PREVIOUS_CLASSIFICATION
        where_clauses.append(
            f"upper(coalesce(h.NEW_CLASSIFICATION, h.PREVIOUS_CLASSIFICATION, '')) in ({levels_in})"
        )
    if c_levels:
        cls_in = ",".join([str(int(c)) for c in c_levels if c is not None]) or "-1"
        where_clauses.append(
            f"coalesce(h.NEW_CONFIDENTIALITY, h.PREVIOUS_CONFIDENTIALITY, 0) in ({cls_in})"
        )

    where_sql = (" where " + " and ".join(where_clauses)) if where_clauses else ""

    sql = f"""
      with base as (
        select
          cast(h.HISTORY_ID as string) as ID,
          h.ASSET_ID,
          a.DATABASE_NAME,
          a.SCHEMA_NAME,
          a.ASSET_NAME,
          coalesce(h.NEW_CLASSIFICATION, h.PREVIOUS_CLASSIFICATION, '') as CLASSIFICATION_TAG,
          coalesce(h.NEW_CONFIDENTIALITY, h.PREVIOUS_CONFIDENTIALITY, 0) as C_LEVEL,
          coalesce(h.APPROVAL_REQUIRED, false) as APPROVAL_REQUIRED,
          h.APPROVED_BY,
          h.CHANGED_BY as CREATED_BY,
          h.CHANGE_TIMESTAMP,
          h.CHANGE_REASON,
          h.BUSINESS_JUSTIFICATION
        from {db}.{sc}.CLASSIFICATION_HISTORY h
        left join {db}.{sc}.ASSETS a on a.ASSET_ID = h.ASSET_ID
        {where_sql}
      ),
      numbered as (
        select b.*, row_number() over (order by b.CHANGE_TIMESTAMP desc, b.ID desc) as RN,
               count(*) over() as TOTAL
        from base b
      )
      select * from numbered where RN between %(start)s and %(end)s
    """

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
            "approval_required": r.get("APPROVAL_REQUIRED"),
            "approved_by": r.get("APPROVED_BY"),
            "created_by": r.get("CREATED_BY"),
            "change_timestamp": r.get("CHANGE_TIMESTAMP"),
            "change_reason": r.get("CHANGE_REASON"),
            "business_justification": r.get("BUSINESS_JUSTIFICATION"),
        })
    return {"history": items, "total": total, "page": p, "page_size": ps}
