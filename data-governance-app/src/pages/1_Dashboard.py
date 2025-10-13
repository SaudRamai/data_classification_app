import os
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Set

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

# Ensure project root is on path for imports
_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))  # .../src
_project_root = os.path.dirname(_src_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.connectors.snowflake_connector import snowflake_connector
from src.ui.theme import apply_global_theme
from src.config.settings import settings
from src.services.metrics_service import metrics_service
from src.services.tag_drift_service import analyze_tag_drift
try:
    from src.services.authorization_service import authz as _authz
except Exception:
    _authz = None

# ==============================
# Real-time Dashboard (embedded)
# ==============================
DEFAULT_TTL = int(os.getenv("DASHBOARD_CACHE_TTL", "120"))
# Feature flag to revert recent advanced additions for a simpler dashboard view
# Set to True to hide Compliance Diagnostics and High-Risk/High-Cost sections
REVERT_SIMPLE_DASHBOARD = True

@st.cache_data(ttl=DEFAULT_TTL, show_spinner=False)
def _rt_run_query(sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return snowflake_connector.execute_query(sql, params)

def _rt_ensure_session_context() -> None:
    try:
        wh = st.session_state.get("sf_warehouse")
        if wh:
            try:
                snowflake_connector.execute_non_query(f"ALTER WAREHOUSE {wh} RESUME")
            except Exception:
                pass
            try:
                snowflake_connector.execute_non_query(f"USE WAREHOUSE {wh}")
            except Exception:
                pass
    except Exception:
        pass
    try:
        db = st.session_state.get("sf_database") or getattr(settings, "SNOWFLAKE_DATABASE", None)
        if db:
            snowflake_connector.execute_non_query(f"USE DATABASE {db}")
    except Exception:
        pass

def _rt_show_error(msg: str, exc: Optional[Exception] = None):
    text = f"{msg}{(': ' + str(exc)) if exc else ''}"
    st.error(text)
    if exc and "User is empty" in str(exc):
        st.info("Snowflake credentials are not set. Please sign in on the Home page (app) to establish a session.")

@st.cache_data(ttl=DEFAULT_TTL, show_spinner=False)
def _rt_get_table_columns(table_fqn: str) -> Set[str]:
    try:
        parts = table_fqn.split(".")
        if len(parts) != 3:
            return set()
        db, sch, tbl = parts
        rows = _rt_run_query(
            """
            select column_name as C
            from IDENTIFIER(%(db)s).information_schema.columns
            where table_schema = %(sch)s and table_name = %(tbl)s
            """,
            {"db": db, "sch": sch, "tbl": tbl}
        )
        return {r.get("C") for r in (rows or []) if r.get("C")}
    except Exception:
        return set()

def _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk, start_date, end_date,
                          table_fqn: str, time_candidates: Optional[List[str]] = None) -> Tuple[str, Dict[str, Any]]:
    cols = _rt_get_table_columns(table_fqn)
    conds = []
    params: Dict[str, Any] = {}
    if sel_bu and sel_bu != "All" and "BUSINESS_UNIT" in cols:
        conds.append("BUSINESS_UNIT = %(bu)s")
        params["bu"] = sel_bu
    if sel_db and "DATABASE_NAME" in cols:
        conds.append("DATABASE_NAME = %(db)s")
        params["db"] = sel_db
    if sel_schema and sel_schema != "All" and "SCHEMA_NAME" in cols:
        conds.append("SCHEMA_NAME = %(schema)s")
        params["schema"] = sel_schema
    # Support both legacy ASSET_TYPE and current TABLE_TYPE
    if sel_asset_type and sel_asset_type != "All":
        if "TABLE_TYPE" in cols:
            conds.append("TABLE_TYPE = %(atype)s")
            params["atype"] = sel_asset_type
        elif "ASSET_TYPE" in cols:
            conds.append("ASSET_TYPE = %(atype)s")
            params["atype"] = sel_asset_type
    # Classification status via presence of CLASSIFICATION_TAG
    if sel_class_status and sel_class_status != "All" and "CLASSIFICATION_TAG" in cols:
        if sel_class_status == "Classified":
            conds.append("coalesce(CLASSIFICATION_TAG,'') <> ''")
        else:
            conds.append("coalesce(CLASSIFICATION_TAG,'') = ''")
    if sel_risk and sel_risk != "All" and "RISK_LEVEL" in cols:
        conds.append("RISK_LEVEL = %(risk)s")
        params["risk"] = sel_risk
    # Global compliance filters (if present in target table)
    try:
        sel_framework = st.session_state.get("rt_framework")
        if sel_framework and sel_framework != "All" and "FRAMEWORK_NAME" in cols:
            conds.append("FRAMEWORK_NAME = %(fw)s")
            params["fw"] = sel_framework
    except Exception:
        pass
    try:
        sel_cstatus = st.session_state.get("rt_cstatus")
        if sel_cstatus and sel_cstatus != "All" and "COMPLIANCE_STATUS" in cols:
            conds.append("upper(coalesce(COMPLIANCE_STATUS,'')) = %(cstat)s")
            params["cstat"] = str(sel_cstatus).upper()
    except Exception:
        pass
    if start_date and end_date and time_candidates:
        ts_col = next((c for c in time_candidates if c in cols), None)
        if ts_col:
            conds.append(f"{ts_col} BETWEEN %(start_ts)s AND %(end_ts)s")
            params["start_ts"] = start_date
            params["end_ts"] = end_date
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    return where, params

def _rt_apply_compliance_filter(base_where: str, base_params: Dict[str, Any], asset_id_ref: str, T_CMAP: str) -> Tuple[str, Dict[str, Any]]:
    """Append EXISTS compliance clause to the base where for asset-based queries.

    asset_id_ref: the column reference for ASSET_ID in the outer query (e.g., 'a.ASSET_ID' or 'h.ASSET_ID').
    """
    try:
        fw = st.session_state.get("rt_framework")
        cs = st.session_state.get("rt_cstatus")
    except Exception:
        fw, cs = None, None
    # Normalize values
    fw = fw if fw and fw != "All" else None
    cs_up = str(cs).upper() if cs and cs != "All" else None
    if not fw and not cs_up:
        return base_where, base_params
    conds = [f"cm.ASSET_ID = {asset_id_ref}"]
    params = dict(base_params)
    if fw:
        conds.append("upper(coalesce(cm.FRAMEWORK_NAME,'')) = %(fw_up)s")
        params["fw_up"] = str(fw).upper()
    if cs_up:
        # Flexible status mapping
        if cs_up == "NON-COMPLIANT":
            conds.append("upper(coalesce(cm.COMPLIANCE_STATUS,'')) <> 'COMPLIANT'")
        elif cs_up == "PARTIAL":
            conds.append("upper(coalesce(cm.COMPLIANCE_STATUS,'')) like '%PARTIAL%'")
        else:
            conds.append("upper(coalesce(cm.COMPLIANCE_STATUS,'')) = %(cstat)s")
            params["cstat"] = cs_up
    exists_sql = f"EXISTS (select 1 from {T_CMAP} cm where {' AND '.join(conds)})"
    where = base_where + ((" AND " if base_where else " WHERE ") + exists_sql)
    return where, params

def _rt_paginate_df(df: pd.DataFrame, page: int, page_size: int) -> Tuple[pd.DataFrame, int]:
    if df is None or df.empty:
        return df, 0
    total = len(df)
    start = max(0, (page - 1) * page_size)
    end = min(total, start + page_size)
    return df.iloc[start:end], total

def render_realtime_dashboard():
    st.set_page_config(page_title="Dashboard", page_icon="📊", layout="wide")
    apply_global_theme()
    st.title("Dashboard")

    # Require Snowflake session before any queries
    has_session = False
    try:
        if _authz is not None:
            ident = _authz.get_current_identity()
            has_session = bool(getattr(ident, 'user', None))
    except Exception:
        has_session = False
    # Fallback: check Streamlit session creds
    if not has_session:
        has_session = bool(st.session_state.get("sf_user") and st.session_state.get("sf_account"))
    # If Snowflake session is missing but app user exists, do NOT redirect or stop.
    if not has_session:
        if st.session_state.get("user") is not None:
            st.warning("Snowflake session is not active. Some data may not load. Use Home to re-authenticate when ready.")
        else:
            st.warning("Please sign in to Snowflake to view the dashboard.")
            st.caption("Go to the Home page and login with your Snowflake account or SSO.")
            try:
                if hasattr(st, "switch_page"):
                    st.switch_page("app.py")
            except Exception:
                pass
            st.stop()

    # Resolve active database for all queries (fallback to settings or default)
    active_db = (
        st.session_state.get("sf_database")
        or getattr(settings, "SNOWFLAKE_DATABASE", None)
        or "DATA_CLASSIFICATION_DB"
    )
    # Centralized FQNs (initial; may be overridden after sidebar selection)
    _SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
    T_ASSETS = f"{active_db}.{_SCHEMA}.ASSETS"
    T_CMAP = f"{active_db}.{_SCHEMA}.COMPLIANCE_MAPPING"
    T_CHIST = f"{active_db}.{_SCHEMA}.CLASSIFICATION_HISTORY"
    T_ALERTS = f"{active_db}.{_SCHEMA}.ALERT_LOGS"
    T_RISK = f"{active_db}.{_SCHEMA}.RISK_ASSESSMENTS"
    T_DQ = f"{active_db}.{_SCHEMA}.DATA_QUALITY_METRICS"

    # Global Filters sidebar (restored)
    _rt_ensure_session_context()
    with st.sidebar:
        st.header("filters")
        # Load selectable options from Snowflake (best-effort)
        try:
            db_rows = snowflake_connector.execute_query("SHOW DATABASES") or []
            db_opts = [r.get("name") or r.get("NAME") for r in db_rows if (r.get("name") or r.get("NAME"))]
        except Exception:
            db_opts = []

        # Database
        cur_db = st.session_state.get("sf_database") or (db_opts[0] if db_opts else None)
        sel_db = st.selectbox("Database", options=db_opts or ([cur_db] if cur_db else []), index=((db_opts.index(cur_db)) if (cur_db in db_opts) else 0) if (db_opts) else None, key="rt_db")

        # Schemas for selected database
        try:
            sch_rows = snowflake_connector.execute_query(f"SELECT SCHEMA_NAME FROM {sel_db}.INFORMATION_SCHEMA.SCHEMATA ORDER BY 1") if sel_db else []
            schema_opts = ["All"] + [r.get("SCHEMA_NAME") for r in (sch_rows or []) if r.get("SCHEMA_NAME")]
        except Exception:
            schema_opts = ["All"]
        sel_schema = st.selectbox("Schema", options=schema_opts, index=0, key="rt_schema")

        # Business Unit options from ASSETS
        try:
            bu_rows = snowflake_connector.execute_query(f"SELECT DISTINCT BUSINESS_UNIT FROM {sel_db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS WHERE BUSINESS_UNIT IS NOT NULL ORDER BY 1") if sel_db else []
            bu_opts = ["All"] + [r.get("BUSINESS_UNIT") for r in (bu_rows or []) if r.get("BUSINESS_UNIT")]
        except Exception:
            bu_opts = ["All"]
        sel_bu = st.selectbox("Business Unit", options=bu_opts, index=0, key="rt_bu")

        # Asset Type from ASSETS (TABLE_TYPE or ASSET_TYPE)
        try:
            # Prefer TABLE_TYPE
            at_rows = snowflake_connector.execute_query(
                f"""
                with s as (
                  select distinct TABLE_TYPE as T from {sel_db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS where TABLE_TYPE is not null
                  union
                  select distinct ASSET_TYPE as T from {sel_db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS where ASSET_TYPE is not null
                ) select T from s order by 1
                """
            ) if sel_db else []
            at_opts = ["All"] + [r.get("T") for r in (at_rows or []) if r.get("T")]
        except Exception:
            at_opts = ["All"]
        sel_asset_type = st.selectbox("Asset Type", options=at_opts, index=0, key="rt_asset_type")

        # Classification Status
        sel_class_status = st.selectbox("Classification Status", options=["All", "Classified", "Unclassified"], index=0, key="rt_cls_status")

        # Risk Level from ASSETS
        try:
            rk_rows = snowflake_connector.execute_query(f"SELECT DISTINCT RISK_LEVEL FROM {sel_db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS WHERE RISK_LEVEL IS NOT NULL ORDER BY 1") if sel_db else []
            rk_opts = ["All"] + [r.get("RISK_LEVEL") for r in (rk_rows or []) if r.get("RISK_LEVEL")]
        except Exception:
            rk_opts = ["All"]
        sel_risk = st.selectbox("Risk Level", options=rk_opts, index=0, key="rt_risk")

        # Date range (optional)
        tp = st.radio("Time", options=["All", "Date range"], horizontal=True, index=0, key="rt_timepick")
        start_date: Optional[datetime] = None
        end_date: Optional[datetime] = None
        if tp == "Date range":
            dr = st.date_input("Date range", value=(datetime.today() - timedelta(days=30), datetime.today()))
            try:
                if isinstance(dr, tuple) and len(dr) == 2:
                    start_date, end_date = dr[0], dr[1]
            except Exception:
                start_date, end_date = None, None

        # Save current selections to session
        st.session_state["sf_database"] = sel_db
        st.session_state["rt_filters"] = {
            "bu": sel_bu,
            "db": sel_db,
            "schema": sel_schema,
            "atype": sel_asset_type,
            "cstatus": sel_class_status,
            "risk": sel_risk,
            "start": start_date,
            "end": end_date,
        }

        # Compliance filter defaults remain All
        st.session_state.setdefault("rt_framework", "All")
        st.session_state.setdefault("rt_cstatus", "All")

        # Refresh / apply actions
        colA1, colA2 = st.columns(2)
        refresh = colA1.button("Apply / Refresh")
        if colA2.button("Clear Cache"):
            st.cache_data.clear()
            refresh = True

    if refresh:
        st.cache_data.clear()
        try:
            st.rerun()
        except Exception:
            pass

    # If user selected a database filter, switch session and rebuild FQNs
    try:
        if sel_db:
            # Switch session database
            try:
                snowflake_connector.execute_non_query(f"USE DATABASE {sel_db}")
            except Exception:
                pass
            # Persist in session for consistency
            st.session_state["sf_database"] = sel_db
            # Recompute active DB and FQNs
            active_db = sel_db
            T_ASSETS = f"{active_db}.{_SCHEMA}.ASSETS"
            T_CMAP = f"{active_db}.{_SCHEMA}.COMPLIANCE_MAPPING"
            T_CHIST = f"{active_db}.{_SCHEMA}.CLASSIFICATION_HISTORY"
            T_ALERTS = f"{active_db}.{_SCHEMA}.ALERT_LOGS"
            T_RISK = f"{active_db}.{_SCHEMA}.RISK_ASSESSMENTS"
            T_DQ = f"{active_db}.{_SCHEMA}.DATA_QUALITY_METRICS"
    except Exception:
        pass

    # Placeholders
    col1, col2, col3 = st.columns([1,1,1])
    pl_metrics = col1.empty()
    pl_breakdown = col2.empty()
    pl_unclassified = col3.empty()
    pl_compliance = st.container()
    pl_risk = st.container()
    pl_kpis = st.container()
    pl_sot = st.container()
    pl_alerts = st.container()
    pl_priority_cost = st.container()
    pl_quick = st.container()
    pl_tag_drift = st.container()

    # Component 1: Health (from ASSETS)
    try:
        where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                              start_date, end_date,
                                              T_ASSETS, ["UPDATED_TIMESTAMP", "CREATED_TIMESTAMP", "LAST_CLASSIFIED_DATE", "LAST_MODIFIED_DATE"])
        # Apply compliance filter to asset scope
        where, params = _rt_apply_compliance_filter(where, params, "ASSET_ID", T_CMAP)
        rows = _rt_run_query(f"""
            select
              count(*) as TOTAL_ASSETS,
              sum(case when coalesce(CLASSIFICATION_TAG,'') <> '' then 1 else 0 end) as CLASSIFIED_COUNT,
              sum(case when coalesce(CLASSIFICATION_TAG,'') = '' then 1 else 0 end) as UNCLASSIFIED_COUNT,
              iff(count(*)=0, 0, round(100.0 * sum(case when coalesce(CLASSIFICATION_TAG,'') <> '' then 1 else 0 end)/count(*),2)) as COVERAGE_PCT
            from {T_ASSETS}
            {where}
        """, params)
        m = rows[0] if rows else {"TOTAL_ASSETS":0,"CLASSIFIED_COUNT":0,"UNCLASSIFIED_COUNT":0,"COVERAGE_PCT":0}
        with pl_metrics:
            st.subheader("Classification Health")
            k1, k2, k3, k4 = st.columns(4)
            safe_int = lambda v: int(v) if isinstance(v, (int, float)) else int((v or 0))
            k1.metric("Total Assets", f"{safe_int(m.get('TOTAL_ASSETS')):,}")
            k2.metric("Classified", f"{safe_int(m.get('CLASSIFIED_COUNT')):,}")
            k3.metric("Unclassified", f"{safe_int(m.get('UNCLASSIFIED_COUNT')):,}")
            cov = m.get('COVERAGE_PCT', 0) or 0
            try:
                cov_int = int(float(cov))
            except Exception:
                cov_int = 0
            k4.progress(min(100, max(0, cov_int)), text=f"Coverage {cov}%")
    except Exception as e:
        with pl_metrics:
            _rt_show_error("Failed to load Classification Health", e)

    # Component 2: Breakdown
    try:
        where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                              start_date, end_date,
                                              T_ASSETS, ["UPDATED_TIMESTAMP", "CREATED_TIMESTAMP", "LAST_CLASSIFIED_DATE", "LAST_MODIFIED_DATE"])
        where, params = _rt_apply_compliance_filter(where, params, "ASSET_ID", T_CMAP)
        rows = _rt_run_query(f"""
            select coalesce(CLASSIFICATION_TAG,'Unclassified') as LEVEL, count(*) as CNT
            from {T_ASSETS}
            {where}
            group by 1
            order by 1
        """, params)
        df = pd.DataFrame(rows or [])
        with pl_breakdown:
            st.subheader("Classification Breakdown")
            if df.empty:
                st.info("No data available for breakdown.")
            else:
                fig = px.pie(df, names="LEVEL", values="CNT", hole=0.4)
                st.plotly_chart(fig, use_container_width=True)
    except Exception as e:
        with pl_breakdown:
            _rt_show_error("Failed to load Classification Breakdown", e)

    # Component 3: Unclassified Priority
    try:
        where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                              start_date, end_date,
                                              T_ASSETS, ["UPDATED_TIMESTAMP", "CREATED_TIMESTAMP", "LAST_CLASSIFIED_DATE", "LAST_MODIFIED_DATE"])
        where, params = _rt_apply_compliance_filter(where, params, "ASSET_ID", T_CMAP)
        where_u = (where + ((" AND " if where else " WHERE ") + "coalesce(CLASSIFICATION_TAG,'') = ''"))
        rows = _rt_run_query(f"""
            select DATABASE_NAME, SCHEMA_NAME, ASSET_NAME, TABLE_TYPE,
                   PII_DETECTED as PII_FLAG,
                   FINANCIAL_DATA_DETECTED as FINANCIAL_FLAG,
                   (REGULATORY_FLAGS > 0) as REGULATORY_FLAG,
                   case upper(coalesce(USAGE_FREQUENCY,'')) when 'HIGH' then 2 when 'MEDIUM' then 1 else 0 end as USAGE_SCORE,
                   datediff('day', coalesce(LAST_CLASSIFIED_DATE, CREATED_DATE), current_date()) as DAYS_UNCLASSIFIED,
                   ((case when PII_DETECTED then 3 else 0 end) +
                    (case when FINANCIAL_DATA_DETECTED then 2 else 0 end) +
                    (case when REGULATORY_FLAGS > 0 then 2 else 0 end) +
                    case upper(coalesce(USAGE_FREQUENCY,'')) when 'HIGH' then 2 when 'MEDIUM' then 1 else 0 end +
                    least(3, nvl(datediff('day', coalesce(LAST_CLASSIFIED_DATE, CREATED_DATE), current_date()),0)/30)) as PRIORITY
            from {T_ASSETS}
            {where_u}
            qualify row_number() over (order by PRIORITY desc) <= 500
        """, params)
        df = pd.DataFrame(rows or [])
        with pl_unclassified:
            st.subheader("Unclassified Assets Priority")
            if df.empty:
                st.info("No unclassified assets found.")
            else:
                c1, c2, c3 = st.columns(3)
                pr_level = c1.selectbox("Priority Level", ["All", "High (>=6)", "Medium (3-5)", "Low (<3)"])
                # Robust max days computation
                md_series = pd.to_numeric(df["DAYS_UNCLASSIFIED"], errors="coerce") if "DAYS_UNCLASSIFIED" in df.columns else pd.Series(dtype="float64")
                max_days = int(md_series.max()) if md_series.notna().any() else 0
                if max_days > 0:
                    day_range = c2.slider("Days Unclassified", 0, max_days, (0, max_days))
                else:
                    day_range = (0, 0)
                    c2.caption("No day range available")
                domain = c3.selectbox("Data Domain", ["All", "PII", "Financial", "Regulatory"])
                f = df.copy()
                if pr_level == "High (>=6)":
                    f = f[f["PRIORITY"] >= 6]
                elif pr_level == "Medium (3-5)":
                    f = f[(f["PRIORITY"] >= 3) & (f["PRIORITY"] <= 5)]
                elif pr_level == "Low (<3)":
                    f = f[f["PRIORITY"] < 3]
                f = f[(f["DAYS_UNCLASSIFIED"] >= day_range[0]) & (f["DAYS_UNCLASSIFIED"] <= day_range[1])]
                if domain == "PII":
                    f = f[f["PII_FLAG"] == True]
                elif domain == "Financial":
                    f = f[f["FINANCIAL_FLAG"] == True]
                elif domain == "Regulatory":
                    f = f[f["REGULATORY_FLAG"] == True]
                page_size = 25
                page = st.number_input("Page", min_value=1, value=1, step=1)
                page_df, total = _rt_paginate_df(f, page, page_size)
                st.caption(f"Showing {len(page_df)} of {total} items")
                st.dataframe(page_df, use_container_width=True, hide_index=True)
    except Exception as e:
        with pl_unclassified:
            _rt_show_error("Failed to load Unclassified Priority", e)

    # Component 3b: High-Risk/High-Cost Unclassified Priority (hidden when REVERT_SIMPLE_DASHBOARD is True)
    if not REVERT_SIMPLE_DASHBOARD:
        try:
            with pl_priority_cost:
                st.subheader("High-Risk / High-Cost Unclassified")
                # Build base where with global filters + unclassified
                where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                                      start_date, end_date,
                                                      T_ASSETS, ["UPDATED_TIMESTAMP", "CREATED_TIMESTAMP", "LAST_MODIFIED_DATE"])
                where, params = _rt_apply_compliance_filter(where, params, "ASSET_ID", T_CMAP)
                where_u = (where + ((" AND " if where else " WHERE ") + "coalesce(CLASSIFICATION_TAG,'') = ''"))

                cols = _rt_get_table_columns(T_ASSETS)
                has_cost = "ESTIMATED_MONTHLY_COST" in cols
                has_storage = "STORAGE_BYTES" in cols
                # Cost term selection: prefer ESTIMATED_MONTHLY_COST, else rough from STORAGE_BYTES
                if has_cost:
                    cost_term = "coalesce(ESTIMATED_MONTHLY_COST,0)"
                elif has_storage:
                    # 0.023 $/GB-month heuristic
                    cost_term = "round(nvl(STORAGE_BYTES,0)/power(1024,3)*0.023,6)"
                else:
                    cost_term = "0.0"

                # Risk numeric mapping (fallback to 0)
                risk_score = (
                    "case upper(coalesce(RISK_LEVEL,'')) when 'CRITICAL' then 4 when 'HIGH' then 3 when 'MEDIUM' then 2 when 'LOW' then 1 else 0 end"
                    if "RISK_LEVEL" in cols else "0"
                )

                # Priority score combining risk and cost (scaled)
                sql = f"""
                    select DATABASE_NAME, SCHEMA_NAME, ASSET_NAME, TABLE_TYPE,
                           {risk_score} as RISK_SCORE,
                           {cost_term} as MONTHLY_COST,
                           ({risk_score} * 2 + least(5, {cost_term}/100.0)) as PRIORITY_SCORE
                    from {T_ASSETS}
                    {where_u}
                    qualify row_number() over (order by PRIORITY_SCORE desc) <= 500
                """
                rows = _rt_run_query(sql, params)
                df = pd.DataFrame(rows or [])
                c1, c2 = st.columns([3,1])
                with c1:
                    if df.empty:
                        st.info("No unclassified assets with risk/cost signals.")
                    else:
                        st.dataframe(df, use_container_width=True, hide_index=True)
                with c2:
                    if not df.empty:
                        # Quick summary
                        st.metric("Avg Cost", f"${float(df['MONTHLY_COST'].mean()):,.2f}")
                        st.metric("Avg Risk Score", f"{float(df['RISK_SCORE'].mean()):.2f}")
        except Exception as e:
            with pl_priority_cost:
                _rt_show_error("Failed to load High-Risk/High-Cost Priorities", e)

    # Component 4: Compliance Status (from COMPLIANCE_MAPPING)
    try:
        where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                              start_date, end_date,
                                              T_CMAP, ["UPDATED_TIMESTAMP", "LAST_AUDIT_DATE", "NEXT_AUDIT_DATE"])
        rows = _rt_run_query(f"""
            with base as (
              select * from {T_CMAP} {where}
            ),
            by_fw as (
              select FRAMEWORK_NAME as FRAMEWORK,
                     count(*) as TOTAL,
                     sum(case when upper(COALESCE(COMPLIANCE_STATUS,'')) = 'COMPLIANT' then 1 else 0 end) as COMPLIANT,
                     max(NEXT_AUDIT_DATE) as NEXT_AUDIT_DATE,
                     sum(case when upper(COALESCE(COMPLIANCE_STATUS,'')) <> 'COMPLIANT' then 1 else 0 end) as GAPS
              from base
              group by 1
            )
            select FRAMEWORK,
                   iff(TOTAL=0,0, round(100.0*COMPLIANT/TOTAL,2)) as COMPLIANCE_PCT,
                   NEXT_AUDIT_DATE,
                   GAPS,
                   100 as COVERAGE_PCT
            from by_fw
        """, params)
        df = pd.DataFrame(rows or [])
        with pl_compliance:
            st.subheader("Compliance Status")
            if df.empty:
                st.info("No compliance status available.")
            else:
                c1, c2 = st.columns([2,1])
                with c1:
                    fig = px.bar(df, x="FRAMEWORK", y="COMPLIANCE_PCT", color="FRAMEWORK", range_y=[0,100])
                    st.plotly_chart(fig, use_container_width=True)
                with c2:
                    for _, r in df.sort_values("COMPLIANCE_PCT", ascending=False).iterrows():
                        st.metric(r["FRAMEWORK"], f"{r['COMPLIANCE_PCT']}%", help=f"Coverage: {r.get('COVERAGE_PCT','-')}% | Next audit: {r.get('NEXT_AUDIT_DATE','-')} | Gaps: {r.get('GAPS','-')}")
    except Exception as e:
        with pl_compliance:
            _rt_show_error("Failed to load Compliance Status", e)

    # Component 5: Risk Distribution (from RISK_ASSESSMENTS join ASSETS)
    try:
        # Build where for assets and risk assessments
        where_a, params_a = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                                  start_date, end_date, T_ASSETS,
                                                  ["UPDATED_TIMESTAMP", "CREATED_TIMESTAMP", "LAST_MODIFIED_DATE"])
        # Apply compliance filter on assets side (alias a)
        where_a, params_a = _rt_apply_compliance_filter(where_a, params_a, "a.ASSET_ID", T_CMAP)
        rows = _rt_run_query(f"""
            select a.BUSINESS_UNIT,
                   r.RISK_CATEGORY,
                   r.RISK_LEVEL,
                   count(*) as CNT
            from {T_RISK} r
            join {T_ASSETS} a on a.ASSET_ID = r.ASSET_ID
            {where_a}
            group by 1,2,3
        """, params_a)
        df = pd.DataFrame(rows or [])
        with pl_risk:
            st.subheader("Risk Distribution")
            c1, c2 = st.columns(2)
            risk_lv = c1.selectbox("Risk Level", ["All", "Low", "Medium", "High", "Critical"], index=0, key="rt_risk_lv")
            bu_lv = c2.selectbox("Business Unit", ["All"] + sorted(df.get("BUSINESS_UNIT", pd.Series(dtype=str)).dropna().unique().tolist()))
            f = df.copy()
            if risk_lv != "All":
                f = f[f["RISK_LEVEL"] == risk_lv]
            if bu_lv != "All":
                f = f[f["BUSINESS_UNIT"] == bu_lv]
            if f.empty:
                st.info("No risk data available.")
            else:
                pivot = f.pivot_table(index="RISK_CATEGORY", columns="RISK_LEVEL", values="CNT", aggfunc="sum", fill_value=0)
                fig = px.imshow(pivot, color_continuous_scale="YlOrRd", aspect="auto")
                st.plotly_chart(fig, use_container_width=True)
    except Exception as e:
        with pl_risk:
            _rt_show_error("Failed to load Risk Distribution", e)

    # Component 6: KPIs
    try:
        # Derived metrics from current tables
        r1 = _rt_run_query(f"""
            select count(*) as CNT
            from {T_ALERTS}
            where upper(coalesce(ALERT_TYPE,'')) like '%POLICY%'
              and upper(coalesce(ALERT_STATUS,'')) in ('OPEN','NEW','ACTIVE')
        """)
        r2 = _rt_run_query(f"""
            select count(*) as CNT
            from {T_ASSETS}
            where NEXT_REVIEW_DATE is not null and NEXT_REVIEW_DATE < current_date()
        """)
        r3 = _rt_run_query(f"""
            select round(avg(OVERALL_QUALITY_SCORE),2) as AVG_SCORE
            from {T_DQ}
        """)
        r4 = _rt_run_query(f"""
            with recent as (
              select count(*) as CHG
              from {T_CHIST}
              where CHANGE_TIMESTAMP >= dateadd('day', -7, current_timestamp())
            )
            select round((select CHG from recent)/7.0, 2) as VELOCITY
        """)
        r = {
            "POLICY_VIOLATIONS": (r1[0].get("CNT") if r1 else 0) or 0,
            "OVERDUE_REVIEWS": (r2[0].get("CNT") if r2 else 0) or 0,
            "DATA_QUALITY_SCORE": (r3[0].get("AVG_SCORE") if r3 else 0) or 0,
            "CLASSIFICATION_VELOCITY": (r4[0].get("VELOCITY") if r4 else 0) or 0,
        }
        with pl_kpis:
            st.subheader("Key Performance Indicators")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Policy Violations", f"{int(r.get('POLICY_VIOLATIONS',0)):,}")
            c2.metric("Overdue Reviews", f"{int(r.get('OVERDUE_REVIEWS',0)):,}")
            c3.metric("Data Quality Score", f"{r.get('DATA_QUALITY_SCORE',0)}")
            c4.metric("Classification Velocity", f"{r.get('CLASSIFICATION_VELOCITY',0)} /day")
    except Exception as e:
        with pl_kpis:
            _rt_show_error("Failed to load KPIs", e)

    # Component 6b: Source-of-Truth Metrics (Tags + Governance Tables)
    try:
        with pl_sot:
            st.subheader("Source-of-Truth Metrics (Tags + Governance)")
            cov = metrics_service.classification_coverage(database=active_db)
            fw_counts = metrics_service.framework_counts(database=active_db)
            hist = metrics_service.historical_classifications(database=active_db, days=30)
            overdue = metrics_service.overdue_unclassified(database=active_db)

            k1, k2, k3, k4 = st.columns(4)
            k1.metric("Inventoried Assets", f"{int(cov.get('total_assets',0)):,}")
            k2.metric("Tagged Assets", f"{int(cov.get('tagged_assets',0)):,}")
            k3.metric("Coverage (Tags)", f"{cov.get('coverage_pct',0.0)}%")
            k4.metric("Overdue Unclassified (\u22655d)", f"{int(overdue):,}")

            # Framework counts table (best-effort from COMPLIANCE_CATEGORY)
            import pandas as _pd
            fdf = _pd.DataFrame([fw_counts])
            st.caption("Framework Counts (from COMPLIANCE_CATEGORY tag)")
            st.dataframe(fdf, use_container_width=True, hide_index=True)

            # Classification decisions time series (last 30 days)
            try:
                if hist:
                    hdf = _pd.DataFrame(hist)
                    import plotly.express as _px
                    fig = _px.line(hdf, x="DAY", y="DECISIONS", title="Classification Decisions (30d)")
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No recent classification decisions recorded.")
            except Exception:
                pass
    except Exception as e:
        with pl_sot:
            _rt_show_error("Failed to load Source-of-Truth Metrics", e)

    # Component 6c: Tag Drift & Sync Status (ASSETS vs Snowflake tag references)
    try:
        with pl_tag_drift:
            st.subheader("Tag Drift & Sync Status")
            with st.spinner("Analyzing tag drift..."):
                drift = analyze_tag_drift(database=active_db, limit=1000)
            summary = drift.get("summary", {}) if drift else {}
            items = drift.get("items", []) if drift else []
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Assets Sampled", f"{int(summary.get('total_assets_sampled', 0)):,}")
            c2.metric("Tagged Assets", f"{int(summary.get('tagged_assets', 0)):,}")
            c3.metric("Drifted Assets", f"{int(summary.get('drift_assets', 0)):,}")
            c4.metric("Drift %", f"{float(summary.get('drift_pct', 0.0)):.2f}%")
            if items:
                df = pd.DataFrame(items)
                # Filters
                fcol1, fcol2 = st.columns([1.2, 1.2])
                with fcol1:
                    only_drift = st.checkbox("Show drift only", value=True, key="td_only")
                with fcol2:
                    schema_sel = st.selectbox("Schema", options=["All"] + sorted(df["schema"].dropna().unique().tolist()))
                fdf = df.copy()
                if only_drift:
                    fdf = fdf[fdf["drift"] == True]
                if schema_sel and schema_sel != "All":
                    fdf = fdf[fdf["schema"] == schema_sel]
                st.dataframe(fdf, use_container_width=True, hide_index=True)
            else:
                st.info("No items to display or insufficient privileges to read tag references.")
    except Exception as e:
        with pl_tag_drift:
            _rt_show_error("Failed to analyze Tag Drift", e)

    # Component 7: Alerts (from ALERT_LOGS)
    try:
        where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                              start_date, end_date,
                                              T_ALERTS, ["CREATED_TIMESTAMP"])
        rows = _rt_run_query(f"""
            select ALERT_TYPE, ALERT_PRIORITY as PRIORITY, ALERT_STATUS as STATUS, ALERT_MESSAGE as MESSAGE, CREATED_TIMESTAMP as CREATED_AT
            from {T_ALERTS}
            {where}
            order by CREATED_AT desc
            limit 500
        """, params)
        df = pd.DataFrame(rows or [])
        with pl_alerts:
            st.subheader("Alerts & Notifications")
            if df.empty:
                st.info("No active alerts.")
            else:
                c1, c2, c3 = st.columns(3)
                a_type = c1.selectbox("Alert Type", ["All"] + sorted(df["ALERT_TYPE"].dropna().unique().tolist()))
                pri = c2.selectbox("Priority", ["All"] + sorted(df["PRIORITY"].dropna().unique().tolist()))
                stat = c3.selectbox("Status", ["All"] + sorted(df["STATUS"].dropna().unique().tolist()))
                f = df.copy()
                if a_type != "All":
                    f = f[f["ALERT_TYPE"] == a_type]
                if pri != "All":
                    f = f[f["PRIORITY"] == pri]
                if stat != "All":
                    f = f[f["STATUS"] == stat]
                st.dataframe(f, use_container_width=True, hide_index=True)
    except Exception as e:
        with pl_alerts:
            _rt_show_error("Failed to load Alerts", e)

    # Component 8: Quick Access (from ASSETS, CLASSIFICATION_HISTORY)
    try:
        where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                              start_date, end_date,
                                              T_ASSETS, ["LAST_CLASSIFIED_DATE", "UPDATED_TIMESTAMP", "CREATED_TIMESTAMP"]) 
        with pl_quick:
            st.subheader("Quick Access")
            t1, t2, t3, t4 = st.tabs(["Recently Classified", "Top Risk Assets", "Pending Approvals", "Upcoming Reviews"]) 
            with t1:
                where, params = _rt_apply_compliance_filter(where, params, "ASSET_ID", T_CMAP)
                where_cls = where + ((" AND " if where else " WHERE ") + "coalesce(CLASSIFICATION_TAG,'') <> ''")
                rows = _rt_run_query(f"""
                    select DATABASE_NAME, SCHEMA_NAME, ASSET_NAME, TABLE_TYPE as ASSET_TYPE, CLASSIFICATION_TAG as CLASSIFICATION_LEVEL, LAST_CLASSIFIED_DATE as LAST_CLASSIFIED_AT
                    from {T_ASSETS}
                    {where_cls}
                    order by LAST_CLASSIFIED_AT desc
                    limit 200
                """, params)
                df = pd.DataFrame(rows or [])
                st.info("No recent classifications.") if df.empty else st.dataframe(df, use_container_width=True, hide_index=True)
            with t2:
                where, params = _rt_apply_compliance_filter(where, params, "ASSET_ID", T_CMAP)
                rows = _rt_run_query(f"""
                    select DATABASE_NAME, SCHEMA_NAME, ASSET_NAME, TABLE_TYPE as ASSET_TYPE, RISK_SCORE,
                           case 
                             when RISK_SCORE >= 8 then 'Critical'
                             when RISK_SCORE >= 6 then 'High'
                             when RISK_SCORE >= 3 then 'Medium'
                             else 'Low'
                           end as RISK_LEVEL
                    from {T_ASSETS}
                    {where}
                    order by RISK_SCORE desc nulls last
                    limit 200
                """, params)
                df = pd.DataFrame(rows or [])
                st.info("No high-risk assets.") if df.empty else st.dataframe(df, use_container_width=True, hide_index=True)
            with t3:
                where_appr, params_appr = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                                                start_date, end_date,
                                                                T_CHIST, ["CHANGE_TIMESTAMP"]) 
                # Apply compliance exists using ASSET_ID from history
                where_appr, params_appr = _rt_apply_compliance_filter(where_appr, params_appr, "ASSET_ID", T_CMAP)
                extra = (" AND " if where_appr else " WHERE ") + "APPROVAL_REQUIRED = TRUE AND APPROVAL_TIMESTAMP IS NULL"
                rows = _rt_run_query(f"""
                    select HISTORY_ID, ASSET_ID, PREVIOUS_CLASSIFICATION, NEW_CLASSIFICATION,
                           APPROVAL_REQUIRED, APPROVED_BY, APPROVAL_TIMESTAMP, CHANGE_TIMESTAMP
                    from {T_CHIST}
                    {where_appr}{extra}
                    order by CHANGE_TIMESTAMP desc
                    limit 200
                """, params_appr)
                df = pd.DataFrame(rows or [])
                st.info("No pending approvals.") if df.empty else st.dataframe(df, use_container_width=True, hide_index=True)
            with t4:
                where_rev, params_rev = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                                              start_date, end_date,
                                                              T_ASSETS, ["NEXT_REVIEW_DATE"]) 
                where_rev, params_rev = _rt_apply_compliance_filter(where_rev, params_rev, "ASSET_ID", T_CMAP)
                extra_rev = (" AND " if where_rev else " WHERE ") + "NEXT_REVIEW_DATE >= current_date()"
                rows = _rt_run_query(f"""
                    select ASSET_ID, ASSET_NAME, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, NEXT_REVIEW_DATE as REVIEW_DATE
                    from {T_ASSETS}
                    {where_rev}{extra_rev}
                    order by REVIEW_DATE
                    limit 200
                """, params_rev)
                df = pd.DataFrame(rows or [])
                st.info("No upcoming reviews.") if df.empty else st.dataframe(df, use_container_width=True, hide_index=True)
    except Exception as e:
        with pl_quick:
            _rt_show_error("Failed to load Quick Access", e)

    st.caption("Data updates live from Snowflake. Use Refresh to fetch latest.")

# Render dashboard
render_realtime_dashboard()
