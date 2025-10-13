"""
Classification Tasks Service

Provides a unified data integration layer for:
- My Classification Tasks (CRITICAL priority)

Data sources (Snowflake):
- DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
- DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ALERT_LOGS

Implements mapping and filtering per requirements:
- Unclassified assets (CLASSIFICATION_TAG is NULL/empty)
- Overdue reviews (NEXT_REVIEW_DATE <= CURRENT_DATE)
- Alert-based tasks (ALERT_TYPE = 'CLASSIFICATION_OVERDUE')
- Assignment logic via DATA_OWNER/DATA_STEWARD matching current user

Returned API structure:
{
  "tasks": [
    {
      "id": "ASSET_ID or ALERT_ID",
      "asset_name": "ASSET_NAME",
      "object_type": "TABLE_TYPE",
      "database": "DATABASE_NAME",
      "schema": "SCHEMA_NAME",
      "current_classification": "CLASSIFICATION_TAG",
      "due_date": "NEXT_REVIEW_DATE or computed",
      "priority": "High/Medium/Low",
      "status": "NEW/OVERDUE/IN_PROGRESS",
      "assigned_to": "DATA_OWNER",
      "pii_detected": bool,
      "risk_score": number
    }
  ],
  "page": int,
  "page_size": int,
  "total": int
}
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

try:
    import streamlit as st  # for caching (optional)
except Exception:  # pragma: no cover
    st = None

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.governance_db_resolver import resolve_governance_db


def _active_db() -> str:
    """Resolve active database with fallbacks."""
    # Try dynamic governance DB resolver first
    try:
        db_res = resolve_governance_db()
        if db_res and str(db_res).strip():
            return str(db_res)
    except Exception:
        pass
    # Prefer session override
    try:
        if st is not None:
            db = st.session_state.get("sf_database")
            if db:
                return str(db)
    except Exception:
        pass
    # Settings fallback
    try:
        if getattr(settings, "SNOWFLAKE_DATABASE", None):
            return str(settings.SNOWFLAKE_DATABASE)
    except Exception:
        pass
    # No hardcoded default
    raise ValueError("Snowflake database is not set in session, resolver, or settings.")


def _schema_name() -> str:
    # Fixed per requirements
    return "DATA_CLASSIFICATION_GOVERNANCE"


def _cache(ttl: int = 60):
    """Lightweight caching decorator using Streamlit when available."""
    def deco(fn):
        if st is not None:
            return st.cache_data(ttl=ttl, show_spinner=False)(fn)
        return fn
    return deco


def _sanitize_assignment_filter(assignment: Optional[str]) -> str:
    v = (assignment or "All").strip().lower()
    if v in ("assigned to me", "assigned", "me"):
        return "assigned"
    if v in ("unassigned",):
        return "unassigned"
    return "all"


def _sanitize_priority_filter(priority: Optional[str]) -> Optional[str]:
    v = (priority or "All").strip().lower()
    if v in ("high", "medium", "low"):
        return v
    return None


def _sanitize_task_type(task_type: Optional[str]) -> Optional[str]:
    v = (task_type or "All").strip().lower()
    # canonical: classification, reclassification, review
    if v in ("classification", "reclassification", "review"):
        return v
    return None


def _sanitize_due_bucket(due_bucket: Optional[str]) -> Optional[str]:
    v = (due_bucket or "All").strip().lower()
    mappings = {
        "overdue": "overdue",
        "this week": "this_week",
        "next week": "next_week",
    }
    return mappings.get(v)


@_cache(ttl=60)
def get_my_tasks(
    current_user: str,
    assignment: str = "All",
    priority: str = "All",
    task_type: str = "All",
    due_date: str = "All",
    page: int = 1,
    page_size: int = 50,
    database: Optional[str] = None,
) -> Dict[str, Any]:
    """Return paginated tasks for the current user from unified sources.

    Filters:
    - assignment: Assigned to me | Unassigned | All
    - priority: High | Medium | Low | All
    - task_type: Classification | Reclassification | Review | All
    - due_date: Overdue | This week | Next week | All
    """
    db = str(database or _active_db())
    sc = _schema_name()

    # Normalized filters
    f_assignment = _sanitize_assignment_filter(assignment)
    f_priority = _sanitize_priority_filter(priority)
    f_type = _sanitize_task_type(task_type)
    f_due = _sanitize_due_bucket(due_date)

    # Compute pagination bounds
    p = max(1, int(page))
    ps = max(1, min(500, int(page_size)))
    start = (p - 1) * ps + 1
    end = p * ps

    # Build unified source as CTEs and UNION ALL
    # Priority calc: high if PII_DETECTED or RISK_SCORE>=8; medium if RISK_SCORE>=5
    # Due date calc: coalesce(NEXT_REVIEW_DATE, dateadd('day', 30, current_date()))
    # Status: OVERDUE if due_date < current_date; NEW otherwise; IN_PROGRESS for alerts with OPEN status

    sql = f"""
    with
    assets as (
      select
        cast(ASSET_ID as string) as ID,
        ASSET_NAME,
        coalesce(TABLE_TYPE, 'TABLE') as OBJECT_TYPE,
        DATABASE_NAME,
        SCHEMA_NAME,
        coalesce(CLASSIFICATION_TAG, '') as CLASSIFICATION_TAG,
        coalesce(NEXT_REVIEW_DATE, dateadd('day', 30, current_date())) as DUE_DATE,
        case when PII_DETECTED = true or nvl(RISK_SCORE,0) >= 8 then 'High'
             when nvl(RISK_SCORE,0) >= 5 then 'Medium'
             else 'Low' end as PRIORITY,
        case when coalesce(NEXT_REVIEW_DATE, dateadd('day', 30, current_date())) < current_date() then 'OVERDUE' else 'NEW' end as STATUS,
        coalesce(DATA_OWNER, DATA_STEWARD, '') as ASSIGNED_TO,
        nvl(PII_DETECTED,false) as PII_DETECTED,
        nvl(RISK_SCORE,0) as RISK_SCORE,
        'Classification' as TASK_TYPE,
        1 as SRC_ORDER
      from {db}.{sc}.ASSETS
      where coalesce(CLASSIFICATION_TAG,'') = ''
    ),
    overdue_reviews as (
      select
        cast(ASSET_ID as string) as ID,
        ASSET_NAME,
        coalesce(TABLE_TYPE, 'TABLE') as OBJECT_TYPE,
        DATABASE_NAME,
        SCHEMA_NAME,
        coalesce(CLASSIFICATION_TAG, '') as CLASSIFICATION_TAG,
        NEXT_REVIEW_DATE as DUE_DATE,
        case when PII_DETECTED = true or nvl(RISK_SCORE,0) >= 8 then 'High'
             when nvl(RISK_SCORE,0) >= 5 then 'Medium'
             else 'Low' end as PRIORITY,
        'OVERDUE' as STATUS,
        coalesce(DATA_OWNER, DATA_STEWARD, '') as ASSIGNED_TO,
        nvl(PII_DETECTED,false) as PII_DETECTED,
        nvl(RISK_SCORE,0) as RISK_SCORE,
        'Review' as TASK_TYPE,
        2 as SRC_ORDER
      from {db}.{sc}.ASSETS
      where NEXT_REVIEW_DATE is not null and NEXT_REVIEW_DATE <= current_date()
    ),
    alert_tasks as (
      select
        cast(ALERT_ID as string) as ID,
        coalesce(ASSET_NAME, 'Unknown') as ASSET_NAME,
        coalesce(TABLE_TYPE, 'TABLE') as OBJECT_TYPE,
        DATABASE_NAME,
        SCHEMA_NAME,
        coalesce(CLASSIFICATION_TAG, '') as CLASSIFICATION_TAG,
        coalesce(ALERT_DUE_DATE, current_date()) as DUE_DATE,
        coalesce(ALERT_PRIORITY, 'Medium') as PRIORITY,
        case when upper(coalesce(ALERT_STATUS,'')) in ('OPEN','ACTIVE','NEW') then 'IN_PROGRESS' else 'NEW' end as STATUS,
        coalesce(DATA_OWNER, DATA_STEWARD, '') as ASSIGNED_TO,
        nvl(PII_DETECTED,false) as PII_DETECTED,
        nvl(RISK_SCORE,0) as RISK_SCORE,
        'Reclassification' as TASK_TYPE,
        3 as SRC_ORDER
      from {db}.{sc}.ALERT_LOGS
      where upper(coalesce(ALERT_TYPE,'')) = 'CLASSIFICATION_OVERDUE'
    ),
    unified as (
      select * from assets
      union all
      select * from overdue_reviews
      union all
      select * from alert_tasks
    ),
    filtered as (
      select *
      from unified u
      where 1=1
      -- assignment filter
      {"and (upper(coalesce(u.ASSIGNED_TO,'')) = upper(%(me)s))" if f_assignment == 'assigned' else ''}
      {"and (coalesce(u.ASSIGNED_TO,'') = '')" if f_assignment == 'unassigned' else ''}
      -- priority filter
      {"and upper(u.PRIORITY) = upper(%(priority)s)" if f_priority else ''}
      -- task type filter
      {"and lower(u.TASK_TYPE) = lower(%(task_type)s)" if f_type else ''}
      -- due bucket filter
      {"and u.DUE_DATE < current_date()" if f_due == 'overdue' else ''}
      {"and u.DUE_DATE between current_date() and dateadd('day', 7, current_date())" if f_due == 'this_week' else ''}
      {"and u.DUE_DATE between dateadd('day', 7, current_date()) and dateadd('day', 14, current_date())" if f_due == 'next_week' else ''}
    ),
    numbered as (
      select u.*, row_number() over (
        order by 
          case when u.PRIORITY = 'High' then 3 when u.PRIORITY = 'Medium' then 2 else 1 end desc,
          u.DUE_DATE asc,
          SRC_ORDER asc
      ) as RN,
      count(*) over() as TOTAL
      from filtered u
    )
    select * from numbered where RN between %(start)s and %(end)s
    """

    params: Dict[str, Any] = {
        "start": start,
        "end": end,
        "me": current_user or "",
        "priority": (f_priority.capitalize() if f_priority else None),
        "task_type": (f_type if f_type else None),
    }
    # Remove unused params (None) to avoid binding issues
    params = {k: v for k, v in params.items() if v is not None}

    try:
        rows = snowflake_connector.execute_query(sql, params) or []
        total = int(rows[0].get("TOTAL", 0)) if rows else 0
        tasks: List[Dict[str, Any]] = []
        for r in rows:
            tasks.append({
                "id": r.get("ID"),
                "asset_name": r.get("ASSET_NAME"),
                "object_type": r.get("OBJECT_TYPE"),
                "database": r.get("DATABASE_NAME"),
                "schema": r.get("SCHEMA_NAME"),
                "current_classification": r.get("CLASSIFICATION_TAG"),
                "due_date": r.get("DUE_DATE"),
                "priority": r.get("PRIORITY"),
                "status": r.get("STATUS"),
                "assigned_to": r.get("ASSIGNED_TO"),
                "pii_detected": bool(r.get("PII_DETECTED")),
                "risk_score": r.get("RISK_SCORE"),
                "task_type": r.get("TASK_TYPE"),
            })
        return {
            "tasks": tasks,
            "page": p,
            "page_size": ps,
            "total": total,
        }
    except Exception as e:
        # Graceful fallback
        return {"tasks": [], "page": p, "page_size": ps, "total": 0, "error": str(e)}
