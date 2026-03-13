"""
Reusable multi-level data filters for Database -> Schema -> Table -> Column selection,
with compliance hooks (tagging/classification/masking-aware).
"""
from __future__ import annotations

import streamlit as st
import pandas as pd
from typing import Dict, List, Tuple, Optional

try:
    from src.connectors.snowflake_connector import snowflake_connector as _conn
except Exception:  # During docs/build
    _conn = None



def _safe_query(sql: str, params: Optional[Dict] = None) -> List[Dict]:
    try:
        if _conn is None:
            return []
        return _conn.execute_query(sql, params) or []
    except Exception:
        return []


def render_global_filters(key_prefix: str = "global") -> Dict[str, str]:
    """
    Standardize Global Filters UI across all pages.
    Includes Warehouse selection and the cascading Database selectors.
    """
    st.subheader("Global Filters")
    # Warehouse selector
    wh_opts = []
    try:
        wh_rows = _safe_query("SHOW WAREHOUSES")
        wh_opts = [r.get("name") or r.get("NAME") for r in wh_rows if (r.get("name") or r.get("NAME"))]
    except Exception:
        wh_opts = []
        
    cur_wh = st.session_state.get('sf_warehouse')
    
    # Build unique display list
    wh_display = []
    if cur_wh:
        wh_display.append(cur_wh)
    for w in wh_opts:
        if w not in wh_display:
            wh_display.append(w)
            
    sel_wh = st.selectbox(
        "Warehouse",
        options=(wh_display or [""]),
        index=0 if wh_display else 0,
        key=f"{key_prefix}_wh",
        help="Select a Snowflake warehouse to run queries",
    )
    if sel_wh and sel_wh != cur_wh:
        try:
            if _conn:
                _conn.execute_non_query(f"USE WAREHOUSE {sel_wh}")
            st.session_state['sf_warehouse'] = sel_wh
        except Exception as e:
            st.error(f"Failed to switch to warehouse {sel_wh}: {str(e)}")

    # Cascading selectors
    filters = render_data_filters(key_prefix=key_prefix)
    
    st.markdown("---")
    # Refresh / apply actions
    col_a, col_b = st.columns(2)
    if col_a.button("Refresh", key=f"{key_prefix}_refresh_btn", use_container_width=True):
        st.rerun()
    if col_b.button("Clear", key=f"{key_prefix}_clear_btn", help="Clear cache and refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    # Common Persistence Logic
    try:
        if filters.get("database"):
            db = filters["database"]
            st.session_state["sf_database"] = db
            if _conn:
                _conn.execute_non_query(f"USE DATABASE {db}")
                
        if filters.get("schema"):
            st.session_state["sf_schema"] = filters["schema"]
            
        st.session_state["global_filters"] = filters
    except Exception:
        pass
    
    return filters



def render_data_filters(key_prefix: str = "filters") -> Dict[str, str]:
    """
    Render cascading selectors for Database, Schema, Table and Column.

    Returns a dict with keys: database, schema, table, column.
    All values are strings (may be empty if nothing selected).
    """
    # Databases (best-effort) with 'All'
    db_rows = _safe_query("SHOW DATABASES")
    dbs = [r.get("name") or r.get("NAME") for r in db_rows if (r.get("name") or r.get("NAME"))]
    db_options = (["All"] + dbs) if dbs else ["All"]

    # Default selection comes from app-wide session context, but a page can override
    # by setting its own {key_prefix}_* values.
    prev_db = st.session_state.get(f"{key_prefix}_db")
    if prev_db is None:
        prev_db = st.session_state.get("sf_database") or "All"
    prev_db = prev_db or "All"
    try:
        db_index = db_options.index(prev_db) if prev_db in db_options else 0
    except Exception:
        db_index = 0
    sel_db_raw = st.selectbox(
        "Database",
        options=db_options,
        index=db_index,
        key=f"{key_prefix}_db",
    )
    # Sanitize 'NONE' or similar invalid selections
    if str(sel_db_raw).upper() in ("NONE", "NULL", "(NONE)", "UNKNOWN", ""):
        sel_db = ""
    else:
        sel_db = "" if sel_db_raw == "All" else sel_db_raw

    # Schemas with 'All' - if no database selected, list account-level schemas
    schemas: List[str] = []
    if sel_db:
        try:
            schemas = [r.get("name") or r.get("NAME") for r in _safe_query(f"SHOW SCHEMAS IN DATABASE {sel_db}") if (r.get("name") or r.get("NAME"))]
        except Exception:
            schemas = []
    else:
        # No database selected: show schemas available in the account (best-effort)
        schemas = [r.get("name") or r.get("NAME") for r in _safe_query("SHOW SCHEMAS IN ACCOUNT") if (r.get("name") or r.get("NAME"))]
    schema_options = (["All"] + schemas) if schemas else ["All"]

    prev_schema = st.session_state.get(f"{key_prefix}_schema")
    if prev_schema is None:
        prev_schema = st.session_state.get("sf_schema") or "All"
    prev_schema = prev_schema or "All"
    try:
        schema_index = schema_options.index(prev_schema) if prev_schema in schema_options else 0
    except Exception:
        schema_index = 0
    sel_schema_raw = st.selectbox(
        "Schema",
        options=schema_options,
        index=schema_index,
        key=f"{key_prefix}_schema",
    )
    sel_schema = "" if sel_schema_raw == "All" else sel_schema_raw

    # Tables with 'All'
    tables = []
    if sel_db and sel_schema:
        try:
            trows = _safe_query(f"SHOW TABLES IN {sel_db}.{sel_schema}")
            # Include views as well for broader coverage
            vrows = _safe_query(f"SHOW VIEWS IN {sel_db}.{sel_schema}")
            tables = [r.get("name") or r.get("NAME") for r in (trows + vrows) if (r.get("name") or r.get("NAME"))]
        except Exception:
            tables = []
    table_options = (["All"] + tables) if tables else ["All"]

    prev_table = st.session_state.get(f"{key_prefix}_table")
    if prev_table is None:
        prev_table = st.session_state.get("sf_table") or "All"
    prev_table = prev_table or "All"
    try:
        table_index = table_options.index(prev_table) if prev_table in table_options else 0
    except Exception:
        table_index = 0
    sel_table_raw = st.selectbox(
        "Table / View",
        options=table_options,
        index=table_index,
        key=f"{key_prefix}_table",
    )
    sel_table = "" if sel_table_raw == "All" else sel_table_raw

    # Columns with 'All'
    columns: List[str] = []
    if sel_db and sel_schema and sel_table:
        try:
            crow = _safe_query(
                f"SELECT COLUMN_NAME FROM {sel_db}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%(s)s AND TABLE_NAME=%(t)s ORDER BY ORDINAL_POSITION",
                {"s": sel_schema, "t": sel_table},
            )
            columns = [c.get("COLUMN_NAME") for c in crow]
        except Exception:
            columns = []
    col_options = (["All"] + columns) if columns else ["All"]

    prev_col = st.session_state.get(f"{key_prefix}_column")
    if prev_col is None:
        prev_col = st.session_state.get("sf_column") or "All"
    prev_col = prev_col or "All"
    try:
        col_index = col_options.index(prev_col) if prev_col in col_options else 0
    except Exception:
        col_index = 0
    sel_col_raw = st.selectbox(
        "Column (optional)",
        options=col_options,
        index=col_index,
        key=f"{key_prefix}_column",
    )
    sel_col = "" if sel_col_raw == "All" else sel_col_raw

    return {
        "database": sel_db or "",
        "schema": sel_schema or "",
        "table": sel_table or "",
        "column": sel_col or "",
    }



