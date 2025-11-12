"""
My Tasks Service

- Provides functions to fetch and update classification tasks assigned to the current user.
- Separates UI from backend logic and Snowflake integration.

Returned task structure (list of dicts):
{
  "asset_full_name": "DB.SCHEMA.TABLE",
  "dataset_name": "TABLE",
  "database": "DB",
  "schema": "SCHEMA",
  "owner": "user@company.com",
  "classification_level": "Internal",
  "c": 1, "i": 1, "a": 1,
  "overall_risk": "Low|Medium|High",
  "status": "Draft|Pending|Completed|Overdue|In Progress",
  "due_date": "2025-01-01"
}

Snowflake integration placeholders are marked with TODO comments.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from datetime import datetime

from src.connectors.snowflake_connector import snowflake_connector
from src.services.governance_db_resolver import resolve_governance_db

try:
    import streamlit as st
except Exception:  # pragma: no cover
    st = None


def _resolve_objects() -> Dict[str, Optional[str]]:
    """
    Resolve dynamic database, schema, and object names for the classification module.

    Supports the following Streamlit session overrides (optional):
      - sf_database: active Snowflake database
      - governance_schema: governance schema name (default: DATA_GOVERNANCE)
      - governance_tasks_view: tasks table/view name (default: CLASSIFICATION_TASKS)
      - governance_decisions_table: decisions table name (default: CLASSIFICATION_DECISIONS)

    Falls back to `resolve_governance_db()` for database.
    """
    db: Optional[str] = None
    schema: Optional[str] = None
    tasks_name: Optional[str] = None
    decisions_name: Optional[str] = None

    # Database from session or resolver
    try:
        if st is not None:
            db = st.session_state.get("sf_database") or None
        if not db:
            db = resolve_governance_db()
    except Exception:
        db = None

    # Schema and object names from session overrides
    try:
        if st is not None:
            schema = st.session_state.get("governance_schema") or None
            tasks_name = st.session_state.get("governance_tasks_view") or None
            decisions_name = st.session_state.get("governance_decisions_table") or None
    except Exception:
        pass

    # Defaults if not provided
    schema = schema or "DATA_CLASSIFICATION_GOVERNANCE"
    tasks_name = tasks_name or "CLASSIFICATION_TASKS"
    decisions_name = decisions_name or "CLASSIFICATION_DECISIONS"

    return {
        "db": (str(db) if db else None),
        "schema": str(schema),
        "tasks": str(tasks_name),
        "decisions": str(decisions_name),
    }


def _risk_from_cia(c: int, i: int, a: int) -> str:
    highest = max(int(c or 0), int(i or 0), int(a or 0))
    return "Low" if highest <= 1 else ("Medium" if highest == 2 else "High")


def fetch_assigned_tasks(
    current_user: str,
    status: Optional[str] = None,  # draft|pending|completed or None
    owner: Optional[str] = None,
    classification_level: Optional[str] = None,
    date_range: Optional[Tuple[Optional[str], Optional[str]]] = None,  # (start_iso, end_iso)
    limit: int = 500,
) -> List[Dict]:
    """
    Fetch datasets assigned to the current user with CIA scores, risk, status, and due date.

    Live-only: This function does not return mock data.
    TODO Snowflake: Replace the example query with production sources/views as needed.
    Suggested sources: {db}.{schema}.CLASSIFICATION_TASKS or unified views joining
      - ASSETS (for ownership and object coordinates)
      - CLASSIFICATION_DECISIONS / HISTORY (for latest CIA)
      - WORKLIST / TASKS (for status and due dates)
    """
    objs = _resolve_objects()
    db = objs.get("db")
    schema = objs.get("schema")
    tasks = objs.get("tasks")
    decisions = objs.get("decisions")

    where_clauses = ["1=1"]
    params: Dict[str, object] = {"me": current_user or ""}

    # Filter: assigned to current user
    where_clauses.append("upper(coalesce(ASSIGNED_TO,'')) = upper(%(me)s)")

    # Optional filters
    if status:
        s = status.strip().lower()
        # Map UI statuses to canonical task statuses
        if s in ("draft", "pending", "completed"):
            where_clauses.append("lower(coalesce(STATUS,'')) = %(status)s")
            params["status"] = s.capitalize() if s != "pending" else "Pending"
    if owner:
        where_clauses.append("upper(coalesce(ASSIGNED_TO,'')) like upper(%(owner)s)")
        params["owner"] = f"%{owner}%"
    if classification_level:
        where_clauses.append("upper(coalesce(CLASSIFICATION_LEVEL,'')) = upper(%(level)s)")
        params["level"] = classification_level
    if date_range:
        sd, ed = date_range
        if sd:
            where_clauses.append("DUE_DATE >= %(sd)s")
            params["sd"] = sd
        if ed:
            where_clauses.append("DUE_DATE <= %(ed)s")
            params["ed"] = ed

    if db and schema and tasks and decisions:
        try:
            # TODO: Replace this with your canonical governance view/table
            # Example structure using hypothetical TASKS view and DECISIONS for CIA
            sql = f"""
            with latest_cia as (
              select
                d.ASSET_FULL_NAME,
                try_to_number(d.C) as C,
                try_to_number(d.I) as I,
                try_to_number(d.A) as A,
                row_number() over (partition by d.ASSET_FULL_NAME order by d.DECIDED_AT desc) as rn
              from {db}.{schema}.{decisions} d
            )
            select
              t.ASSET_FULL_NAME,
              split_part(t.ASSET_FULL_NAME, '.', 1) as DATABASE,
              split_part(t.ASSET_FULL_NAME, '.', 2) as SCHEMA,
              split_part(t.ASSET_FULL_NAME, '.', 3) as DATASET_NAME,
              coalesce(t.ASSIGNED_TO, '') as OWNER,
              coalesce(t.CLASSIFICATION_LEVEL, '') as CLASSIFICATION_LEVEL,
              coalesce(l.C, 0) as C,
              coalesce(l.I, 0) as I,
              coalesce(l.A, 0) as A,
              coalesce(t.STATUS, 'Draft') as STATUS,
              coalesce(t.DUE_DATE, current_date()) as DUE_DATE
            from {db}.{schema}.{tasks} t
            left join latest_cia l on l.ASSET_FULL_NAME = t.ASSET_FULL_NAME and l.rn = 1
            where {' and '.join(where_clauses)}
            qualify row_number() over (
              partition by t.ASSET_FULL_NAME order by coalesce(t.DUE_DATE, current_date()) asc
            ) = 1
            limit {int(limit)}
            """
            rows = snowflake_connector.execute_query(sql, params) or []
            out: List[Dict] = []
            for r in rows:
                c = int(r.get("C") or 0)
                i = int(r.get("I") or 0)
                a = int(r.get("A") or 0)
                out.append({
                    "asset_full_name": r.get("ASSET_FULL_NAME"),
                    "dataset_name": r.get("DATASET_NAME"),
                    "database": r.get("DATABASE"),
                    "schema": r.get("SCHEMA"),
                    "owner": r.get("OWNER"),
                    "classification_level": r.get("CLASSIFICATION_LEVEL"),
                    "c": c, "i": i, "a": a,
                    "overall_risk": _risk_from_cia(c, i, a),
                    "status": r.get("STATUS"),
                    "due_date": r.get("DUE_DATE"),
                })
            return out
        except Exception:
            # Live-only: on error, return empty list
            return []

    # Live-only: if connection/objects are not resolvable, return empty list
    return []


def update_or_submit_classification(
    asset_full_name: str,
    c: int,
    i: int,
    a: int,
    label: str,
    action: str,  # "update" | "submit"
    comments: str,
    user: str,
) -> bool:
    """
    Update or submit a classification decision for a given asset.

    TODO Snowflake: Implement INSERT/UPDATE into governance tables and apply Snowflake tags.
    This function should:
      1) Record decision into {DB}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
      2) Optionally update {DB}.DATA_GOVERNANCE.CLASSIFICATION_TASKS status
      3) Apply tags on the object (ALTER ... SET TAG ...) or via tagging_service
    """
    try:
        objs = _resolve_objects()
        db = objs.get("db")
        schema = objs.get("schema")
        tasks = objs.get("tasks")
        decisions = objs.get("decisions")
        # 1) Record decision (placeholder)
        if db and schema and decisions:
            try:
                snowflake_connector.execute_non_query(
                    f"""
                    create schema if not exists {db}.{schema};
                    create table if not exists {db}.{schema}.{decisions} (
                      ID string,
                      ASSET_FULL_NAME string,
                      DECISION_BY string,
                      DECIDED_AT timestamp_ntz default current_timestamp,
                      LABEL string,
                      C number, I number, A number,
                      RATIONALE string,
                      SOURCE string
                    );
                    insert into {db}.{schema}.{decisions}
                      (ID, ASSET_FULL_NAME, DECISION_BY, LABEL, C, I, A, RATIONALE, SOURCE)
                    select UUID_STRING(), %(a)s, %(by)s, %(label)s, %(c)s, %(i)s, %(aa)s, %(rat)s, %(src)s
                    """,
                    {"a": asset_full_name, "by": user or "user", "label": label, "c": int(c), "i": int(i), "aa": int(a), "rat": comments or "", "src": action.upper()},
                )
            except Exception:
                pass
        # 2) Update task status (placeholder)
        if db and schema and tasks:
            try:
                snowflake_connector.execute_non_query(
                    f"""
                    create schema if not exists {db}.{schema};
                    create table if not exists {db}.{schema}.{tasks} (
                      ASSET_FULL_NAME string,
                      ASSIGNED_TO string,
                      STATUS string,
                      DUE_DATE date,
                      CLASSIFICATION_LEVEL string
                    );
                    update {db}.{schema}.{tasks}
                    set STATUS = %(st)s
                    where ASSET_FULL_NAME = %(a)s
                    """,
                    {"st": ("Completed" if action == "submit" else "Draft"), "a": asset_full_name},
                )
            except Exception:
                pass
        # 3) Apply tags (placeholder)
        try:
            from src.services.tagging_service import tagging_service
            tags = {
                "data_classification": label,
                "confidentiality_level": f"C{int(c)}",
                "integrity_level": f"I{int(i)}",
                "availability_level": f"A{int(a)}",
            }
            tagging_service.apply_tags_to_object(asset_full_name, "TABLE", tags)
        except Exception:
            # In environments without tagging permissions, ignore
            pass
        return True
    except Exception:
        return False
