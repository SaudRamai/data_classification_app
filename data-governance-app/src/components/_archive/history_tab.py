"""
Classification Management - History sub-tab (Streamlit component)

Provides a complete audit trail of classification events with filters, sorting,
searching, and download. Designed to be imported and rendered inside the
Management panel tabs.

Modular layout inside this file:
- Snowflake access helpers (sf_*)
- Backend helpers (backend_*)
- UI renderer (render_history_tab)

Snowflake source of truth (preferred): CLASSIFICATION_AUDIT
Expected columns in that table/view (or adapt the SELECT accordingly):
- DATASET_FULL_NAME (e.g., DATABASE.SCHEMA.OBJECT)
- PREV_C, PREV_I, PREV_A (previous CIA scores, integers 0-3)
- CURR_C, CURR_I, CURR_A (current CIA scores, integers 0-3)
- OVERALL_RISK (LOW/MEDIUM/HIGH or equivalent)
- APPROVER_COMMENTS (text)
- SUBMITTED_AT (timestamp)
- APPROVED_AT (timestamp)
- OWNER (data owner or submitter)
- CLASSIFICATION_LEVEL (optional label, e.g., Public/Internal/Confidential)

If the Snowflake table is not available, this component will fall back to mock
sample data to keep the UI usable in dev/demo.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import List, Optional, Dict, Any

import pandas as pd
import streamlit as st

# Local project imports
from src.connectors.snowflake_connector import snowflake_connector
from src.services.governance_db_resolver import resolve_governance_db
from src.config import settings


# ----------------------------- Snowflake helpers -----------------------------

def sf_get_active_db() -> Optional[str]:
    """Resolve the active governance database for audit queries."""
    try:
        db = resolve_governance_db()
        if db:
            return db
    except Exception:
        pass
    try:
        return st.session_state.get("sf_database")
    except Exception:
        return None


def sf_fetch_classification_audit(
    start_dt: Optional[date],
    end_dt: Optional[date],
    dataset_like: Optional[str],
    class_levels: Optional[List[str]],
    owner_like: Optional[str],
    limit: int = 1000,
) -> List[Dict[str, Any]]:
    """Fetch audit trail rows from Snowflake CLASSIFICATION_AUDIT.

    NOTE: Replace the SELECT below with your exact schema/column names.
    Insert appropriate WHERE clauses. Use parameter binding to avoid SQL injection.

    Example target structure (adapt as needed):
      SELECT
        DATASET_FULL_NAME,
        PREV_C, PREV_I, PREV_A,
        CURR_C, CURR_I, CURR_A,
        OVERALL_RISK,
        APPROVER_COMMENTS,
        SUBMITTED_AT,
        APPROVED_AT,
        OWNER,
        CLASSIFICATION_LEVEL
      FROM <DB>.DATA_GOVERNANCE.CLASSIFICATION_AUDIT
      WHERE 1=1
        AND (SUBMITTED_AT BETWEEN %(sd)s AND %(ed)s)
        AND (UPPER(DATASET_FULL_NAME) LIKE %(ds)s)
        AND (UPPER(CLASSIFICATION_LEVEL) IN (%(levels)s))
        AND (UPPER(OWNER) LIKE %(own)s)
      ORDER BY COALESCE(APPROVED_AT, SUBMITTED_AT) DESC
      LIMIT %(lim)s
    """
    db = sf_get_active_db()
    if not db:
        raise RuntimeError("No active database context for audit query.")

    where_clauses = ["1=1"]
    params: Dict[str, Any] = {"lim": int(limit)}

    if start_dt and end_dt:
        where_clauses.append("(SUBMITTED_AT BETWEEN %(sd)s AND %(ed)s OR APPROVED_AT BETWEEN %(sd)s AND %(ed)s)")
        # Normalize to full-day range
        start_ts = datetime.combine(start_dt, datetime.min.time())
        end_ts = datetime.combine(end_dt, datetime.max.time())
        params["sd"], params["ed"] = start_ts, end_ts

    if dataset_like:
        where_clauses.append("UPPER(DATASET_FULL_NAME) LIKE %(ds)s")
        params["ds"] = f"%{dataset_like.strip().upper()}%"

    if class_levels:
        # Build IN list as comma separated quoted literals
        # Use concatenation to avoid nested quote escaping issues in f-strings
        levels_in = ",".join(["'" + str(x).upper().replace("'", "''") + "'" for x in class_levels if x]) or "''"
        where_clauses.append(f"UPPER(COALESCE(CLASSIFICATION_LEVEL, '')) IN ({levels_in})")

    if owner_like:
        where_clauses.append("UPPER(COALESCE(OWNER,'')) LIKE %(own)s")
        params["own"] = f"%{owner_like.strip().upper()}%"

    where_sql = " AND ".join(where_clauses)

    # Get the schema name from settings or use default
    schema = getattr(settings, 'SNOWFLAKE_SCHEMA', 'DATA_CLASSIFICATION_GOVERNANCE')
    
    sql = f"""
        SELECT
          DATASET_FULL_NAME,
          PREV_C, PREV_I, PREV_A,
          CURR_C, CURR_I, CURR_A,
          OVERALL_RISK,
          APPROVER_COMMENTS,
          SUBMITTED_AT,
          APPROVED_AT,
          OWNER,
          CLASSIFICATION_LEVEL
        FROM {db}.{schema}.CLASSIFICATION_AUDIT
        WHERE {where_sql}
        ORDER BY COALESCE(APPROVED_AT, SUBMITTED_AT) DESC
        LIMIT %(lim)s
    """

    # Execute against Snowflake; if it fails (e.g., table missing), let caller decide to mock.
    rows = snowflake_connector.execute_query(sql, params) or []
    # Convert keys to expected format/casing if needed
    return [
        {
            "Dataset": r.get("DATASET_FULL_NAME"),
            "Previous CIA": (r.get("PREV_C"), r.get("PREV_I"), r.get("PREV_A")),
            "Current CIA": (r.get("CURR_C"), r.get("CURR_I"), r.get("CURR_A")),
            "Overall Risk": r.get("OVERALL_RISK"),
            "Approver Comments": r.get("APPROVER_COMMENTS"),
            "Submitted At": r.get("SUBMITTED_AT"),
            "Approved At": r.get("APPROVED_AT"),
            "Owner": r.get("OWNER"),
            "Classification Level": r.get("CLASSIFICATION_LEVEL"),
        }
        for r in rows
    ]


# ------------------------------ Backend helpers ------------------------------

@dataclass
class Filters:
    start_date: Optional[date]
    end_date: Optional[date]
    dataset_query: Optional[str]
    class_levels: List[str]
    owner_query: Optional[str]


def backend_mock_data() -> pd.DataFrame:
    """Return mock audit data for dev/demo when Snowflake is unavailable."""
    now = datetime.utcnow()
    data = [
        {
            "Dataset": "SALES.PUBLIC.ORDERS",
            "Previous CIA": (1, 1, 1),
            "Current CIA": (2, 2, 1),
            "Overall Risk": "Medium",
            "Approver Comments": "Aligned with PCI scope",
            "Submitted At": now - timedelta(days=7),
            "Approved At": now - timedelta(days=6),
            "Owner": "alice@company.com",
            "Classification Level": "Internal",
        },
        {
            "Dataset": "HR.SECURE.EMPLOYEES",
            "Previous CIA": (2, 1, 1),
            "Current CIA": (3, 2, 2),
            "Overall Risk": "High",
            "Approver Comments": "Contains PII; set to Confidential",
            "Submitted At": now - timedelta(days=3),
            "Approved At": now - timedelta(days=2),
            "Owner": "bob@company.com",
            "Classification Level": "Confidential",
        },
    ]
    df = pd.DataFrame(data)
    return df


def backend_fetch_df(f: Filters, use_mock_on_error: bool = True) -> pd.DataFrame:
    """Fetch and normalize audit data into a DataFrame.

    Attempts Snowflake first; if unavailable and fallback allowed, returns mock data.
    """
    try:
        rows = sf_fetch_classification_audit(
            start_dt=f.start_date,
            end_dt=f.end_date,
            dataset_like=f.dataset_query,
            class_levels=f.class_levels,
            owner_like=f.owner_query,
            limit=2000,
        )
        df = pd.DataFrame(rows)
        if df.empty:
            return df
        # Normalize CIA columns into pretty strings and search keys
        df["Previous CIA Scores"] = df["Previous CIA"].apply(lambda t: f"C{t[0]}/I{t[1]}/A{t[2]}" if isinstance(t, (tuple, list)) and len(t)==3 else None)
        df["Current CIA Scores"] = df["Current CIA"].apply(lambda t: f"C{t[0]}/I{t[1]}/A{t[2]}" if isinstance(t, (tuple, list)) and len(t)==3 else None)
        # Column aliases for display
        df.rename(columns={
            "Overall Risk": "Overall Risk",
            "Approver Comments": "Approver Comments",
            "Submitted At": "Submitted",
            "Approved At": "Approved",
            "Owner": "Owner",
            "Classification Level": "Classification Level",
        }, inplace=True)
        return df
    except Exception:
        if not use_mock_on_error:
            raise
        df = backend_mock_data()
        df["Previous CIA Scores"] = df["Previous CIA"].apply(lambda t: f"C{t[0]}/I{t[1]}/A{t[2]}")
        df["Current CIA Scores"] = df["Current CIA"].apply(lambda t: f"C{t[0]}/I{t[1]}/A{t[2]}")
        df.rename(columns={
            "Submitted At": "Submitted",
            "Approved At": "Approved",
        }, inplace=True)
        return df


def backend_search(df: pd.DataFrame, query: str) -> pd.DataFrame:
    """Simple case-insensitive contains search across key text columns."""
    if not query:
        return df
    q = query.strip().lower()
    cols = [
        "Dataset",
        "Previous CIA Scores",
        "Current CIA Scores",
        "Overall Risk",
        "Approver Comments",
        "Owner",
        "Classification Level",
    ]
    existing = [c for c in cols if c in df.columns]
    mask = pd.Series(False, index=df.index)
    for c in existing:
        mask = mask | df[c].astype(str).str.lower().str.contains(q, na=False)
    return df[mask]


# ------------------------------------ UI -------------------------------------

def render_history_tab(key_prefix: str = "hist") -> None:
    """Render the History sub-tab. Place this in your Management tab set as:
        from src.components.history_tab import render_history_tab
        with tab_history:
            render_history_tab()
    """
    st.caption("Complete audit trail of classification events.")

    # Filters
    today = date.today()
    default_start = today - timedelta(days=30)

    f1, f2, f3 = st.columns([1.4, 1.4, 2])
    with f1:
        start_date = st.date_input("Start date", value=default_start, key=f"{key_prefix}_start")
    with f2:
        end_date = st.date_input("End date", value=today, key=f"{key_prefix}_end")
    with f3:
        dataset_query = st.text_input("Dataset contains", placeholder="DATABASE.SCHEMA or object", key=f"{key_prefix}_dataset")

    g1, g2, g3 = st.columns([1.5, 1.2, 1.3])
    with g1:
        class_levels = st.multiselect("Classification level", options=["Public","Internal","Restricted","Confidential"], key=f"{key_prefix}_lvl")
    with g2:
        owner_query = st.text_input("Owner contains", placeholder="name@company.com", key=f"{key_prefix}_owner")
    with g3:
        search_text = st.text_input("Search", placeholder="Search all columns", key=f"{key_prefix}_search")

    # Fetch data
    filt = Filters(
        start_date=start_date,
        end_date=end_date,
        dataset_query=dataset_query,
        class_levels=class_levels or [],
        owner_query=owner_query,
    )

    with st.spinner("Loading history..."):
        df = backend_fetch_df(filt, use_mock_on_error=True)

    # Apply search filter
    df = backend_search(df, search_text)

    # Reorder/limit columns for display
    desired_cols = [
        "Dataset",
        "Previous CIA Scores",
        "Current CIA Scores",
        "Overall Risk",
        "Approver Comments",
        "Submitted",
        "Approved",
        "Owner",
        "Classification Level",
    ]
    for c in desired_cols:
        if c not in df.columns:
            df[c] = None

    st.dataframe(df[desired_cols].sort_values(by=["Approved","Submitted"], ascending=[False, False]), use_container_width=True)

    # Download
    try:
        csv = df[desired_cols].to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name="classification_history.csv",
            mime="text/csv",
            key=f"{key_prefix}_dl",
        )
    except Exception:
        pass

    st.markdown("---")
    st.caption("Queries source: DATA_GOVERNANCE.CLASSIFICATION_AUDIT. Update SELECT in sf_fetch_classification_audit to match your environment.")
