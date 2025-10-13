"""
Dataset Explorer Service

Fetches datasets, metadata, and tags from Snowflake with dynamic filters.
Real-time Snowflake only. No mock fallback.

Filters supported:
- dataset_type: [TABLE, VIEW, EXTERNAL_TABLE] (string or list)
- classification_level: 0,1,2,3 (int) or None
- owner_contains: substring match on owner/email
- status: [All, Tagged, Untagged, Pending Review]
- date_from/date_to: filter on created/last_altered
- database/schema/name patterns from session filters optional

TODO Snowflake:
- Replace the tag acquisition logic with your canonical tagging source.
  Options:
    - TAG_REFERENCES: ACCOUNT_USAGE or INFORMATION_SCHEMA (requires ACCOUNTADMIN/usage grants)
    - Governance tables/views (e.g., <DB>.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_HISTORY / TAGS)
- Align classification level mapping (C/I/A) if available, or use a dedicated CLASSIFICATION tag.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import datetime as _dt

try:
    import streamlit as st
except Exception:  # pragma: no cover
    st = None

import pandas as pd

from src.connectors.snowflake_connector import snowflake_connector


def _active_db() -> Optional[str]:
    try:
        if st is not None and st.session_state.get("sf_database"):
            return str(st.session_state.get("sf_database"))
    except Exception:
        pass
    return None


def _to_list(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, (list, tuple, set)):
        return [str(x) for x in val]
    return [str(val)]


def fetch_datasets(
    dataset_type: Optional[List[str]] = None,
    classification_level: Optional[int] = None,
    owner_contains: Optional[str] = None,
    status: str = "All",
    date_from: Optional[_dt.date] = None,
    date_to: Optional[_dt.date] = None,
    database: Optional[str] = None,
    schema_like: Optional[str] = None,
    name_like: Optional[str] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    db = database or _active_db()
    ds_types = [s.upper() for s in _to_list(dataset_type)]
    owner_like = (owner_contains or "").strip()
    status = (status or "All").strip()
    limit = max(1, min(1000, int(limit)))

    if not db:
        # No active DB; return empty with hint
        return {"items": [], "total": 0, "warning": "No active database set. Select a DB from the sidebar."}

    # Build base datasets query across TABLES and VIEWS
    # Note: LAST_ALTERED exists on INFORMATION_SCHEMA.TABLES/Views
    where_clauses = [
        't."TABLE_SCHEMA" <> "INFORMATION_SCHEMA"'
    ]
    if schema_like:
        where_clauses.append('upper(t."TABLE_SCHEMA") like upper(%(schema_like)s)')
    if name_like:
        where_clauses.append('upper(t."TABLE_NAME") like upper(%(name_like)s)')

    type_where = []
    if not ds_types or "TABLE" in ds_types:
        type_where.append("'TABLE'")
    if "VIEW" in ds_types:
        type_where.append("'VIEW'")
    if "EXTERNAL_TABLE" in ds_types:
        type_where.append("'EXTERNAL_TABLE'")

    if not type_where:
        type_where = ["'TABLE'", "'VIEW'"]

    # Date filters
    date_filters = []
    if date_from:
        date_filters.append("coalesce(x.LAST_ALTERED, x.CREATED) >= %(date_from_ts)s")
    if date_to:
        date_filters.append("coalesce(x.LAST_ALTERED, x.CREATED) < %(date_to_ts)s")

    # Owner filter (best-effort using TABLE_OWNER/VIEW_OWNER)
    owner_filter_sql = ""
    if owner_like:
        owner_filter_sql = "and (upper(x.OWNER) like upper(%(owner_like)s))"

    # Tag join: best-effort placeholder.
    # TODO Snowflake: Replace with governance tables or TAG_REFERENCES join to pull CLASSIFICATION tag and CIA levels.
    sql = f"""
    with base as (
      select 
        '{db}' as DATABASE_NAME,
        t."TABLE_SCHEMA" as SCHEMA_NAME,
        t."TABLE_NAME" as ASSET_NAME,
        case when x.TYPE = 'VIEW' then 'VIEW' when x.TYPE = 'EXTERNAL_TABLE' then 'EXTERNAL_TABLE' else 'TABLE' end as OBJECT_TYPE,
        x.OWNER,
        x.CREATED,
        x.LAST_ALTERED
      from {db}.INFORMATION_SCHEMA.TABLES t
      join (
        select 'TABLE' as TYPE, "TABLE_SCHEMA" as SCH, "TABLE_NAME" as NM, coalesce("CREATED", current_timestamp()) as CREATED, coalesce("LAST_ALTERED", current_timestamp()) as LAST_ALTERED,
               coalesce("TABLE_OWNER", '') as OWNER
        from {db}.INFORMATION_SCHEMA.TABLES
        union all
        select 'VIEW' as TYPE, "TABLE_SCHEMA" as SCH, "TABLE_NAME" as NM, coalesce("CREATED", current_timestamp()), coalesce("LAST_ALTERED", current_timestamp()),
               coalesce("VIEW_OWNER", '') as OWNER
        from {db}.INFORMATION_SCHEMA.VIEWS
      ) x on x.SCH = t."TABLE_SCHEMA" and x.NM = t."TABLE_NAME"
      where {' and '.join(where_clauses)}
    ),
    typed as (
      select b.*, OBJECT_TYPE from base b
      where OBJECT_TYPE in ({', '.join(type_where)})
    ),
    -- Placeholder tag mapping; replace with TAG_REFERENCES or governance view join
    enriched as (
      select 
        t.DATABASE_NAME,
        t.SCHEMA_NAME,
        t.ASSET_NAME,
        t.OBJECT_TYPE,
        t.OWNER,
        t.CREATED,
        t.LAST_ALTERED,
        null::string as CLASSIFICATION,     -- TODO Snowflake: fill from tag value
        null::int as C_LEVEL,               -- TODO Snowflake
        null::int as I_LEVEL,               -- TODO Snowflake
        null::int as A_LEVEL,               -- TODO Snowflake
        null::string as STATUS              -- TODO: derive from governance state if available
      from typed t
    ),
    filtered as (
      select * from enriched x
      where 1=1
      {(' and ' + ' and '.join(date_filters)) if date_filters else ''}
      {owner_filter_sql}
    ),
    numbered as (
      select f.*, row_number() over (order by coalesce(f.LAST_ALTERED, f.CREATED) desc, f.SCHEMA_NAME, f.ASSET_NAME) as RN,
             count(*) over() as TOTAL
      from filtered f
    )
    select * from numbered where RN <= %(limit)s
    """

    params: Dict[str, Any] = {
        "limit": limit,
        "schema_like": f"%{schema_like}%" if schema_like else None,
        "name_like": f"%{name_like}%" if name_like else None,
    }
    if date_from:
        params["date_from_ts"] = f"{date_from} 00:00:00"
    if date_to:
        params["date_to_ts"] = f"{date_to} 00:00:00"
    if owner_like:
        params["owner_like"] = f"%{owner_like}%"

    try:
        rows = snowflake_connector.execute_query(sql, params) or []
        # Apply client-side filters not handled in SQL
        df = pd.DataFrame(rows)
        if classification_level is not None:
            df = df[df.get("C_LEVEL").fillna(-1).astype(int) == int(classification_level)]
        if status and status != "All":
            if status == "Tagged":
                df = df[df.get("CLASSIFICATION").notna() & (df.get("CLASSIFICATION") != "")]
            elif status == "Untagged":
                df = df[df.get("CLASSIFICATION").isna() | (df.get("CLASSIFICATION") == "")]
            elif status == "Pending Review":
                # TODO: replace with governance-based state if available
                df = df[df.get("STATUS").fillna("") == "PENDING"]
        items = df.to_dict(orient="records")
        total = int(rows[0].get("TOTAL", len(items))) if rows else 0
        return {"items": items, "total": total, "sql": sql}
    except Exception as e:
        # No mock: return explicit error
        return {"items": [], "total": 0, "error": str(e)}
