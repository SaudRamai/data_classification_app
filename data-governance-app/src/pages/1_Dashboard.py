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
try:
    from src.services.authorization_service import authz as _authz
except Exception:
    _authz = None

# ==============================
# Real-time Dashboard (embedded)
# ==============================
DEFAULT_TTL = int(os.getenv("DASHBOARD_CACHE_TTL", "120"))

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

    with st.sidebar:
        st.header("Global Filters")
        _rt_ensure_session_context()

        # Business Unit
        try:
            bu_rows = _rt_run_query(
                f"""
                select distinct BUSINESS_UNIT as BU
                from {T_ASSETS}
                order by 1
                """
            )
            bu_options = [r.get("BU") for r in (bu_rows or []) if r.get("BU")]
        except Exception:
            bu_options = []
        sel_bu = st.selectbox("Business Unit", options=["All"] + bu_options, index=0, key="rt_bu")

        # Time period
        tp = st.selectbox("Time Period", ["Real-time", "Today", "Week", "Month", "Quarter", "Custom"], index=0, key="rt_tp")
        start_date: Optional[datetime] = None
        end_date: Optional[datetime] = None
        now = datetime.utcnow()
        if tp == "Today":
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = now
        elif tp == "Week":
            start_date = now - timedelta(days=7)
            end_date = now
        elif tp == "Month":
            start_date = now - timedelta(days=30)
            end_date = now
        elif tp == "Quarter":
            start_date = now - timedelta(days=90)
            end_date = now
        elif tp == "Custom":
            c1, c2 = st.columns(2)
            with c1:
                start_date = st.date_input("Start", value=now.date() - timedelta(days=7), key="rt_start")
            with c2:
                end_date = st.date_input("End", value=now.date(), key="rt_end")
            if start_date and not isinstance(start_date, datetime):
                start_date = datetime.combine(start_date, datetime.min.time())
            if end_date and not isinstance(end_date, datetime):
                end_date = datetime.combine(end_date, datetime.max.time())

        # Database/Schema
        try:
            db_rows = _rt_run_query("show databases")
            db_opts = [r.get("name") or r.get("NAME") for r in (db_rows or []) if (r.get("name") or r.get("NAME"))]
        except Exception:
            db_opts = []
        sel_db = st.selectbox("Database", options=[st.session_state.get("sf_database", "")] + [d for d in db_opts if d != st.session_state.get("sf_database", "")], key="rt_db")

        # Warehouse selection (applies at session level)
        try:
            wh_rows = _rt_run_query("SHOW WAREHOUSES") or []
            wh_opts = [w.get('name') or w.get('NAME') for w in wh_rows if (w.get('name') or w.get('NAME'))]
        except Exception:
            wh_opts = []
        cur_wh = st.session_state.get("sf_warehouse", "")
        sel_wh = st.selectbox("Warehouse", options=[cur_wh] + [w for w in wh_opts if w != cur_wh] if cur_wh else wh_opts, key="rt_wh")
        if st.button("Set Warehouse", key="btn_rt_set_wh") and sel_wh:
            try:
                # Best-effort resume then use
                try:
                    snowflake_connector.execute_non_query(f"ALTER WAREHOUSE {sel_wh} RESUME")
                except Exception:
                    pass
                snowflake_connector.execute_non_query(f"USE WAREHOUSE {sel_wh}")
                st.session_state["sf_warehouse"] = sel_wh
                st.success(f"Warehouse set to {sel_wh}.")
                st.rerun()
            except Exception as _wh_err:
                st.warning(f"Failed to set warehouse: {_wh_err}")

        try:
            sc_rows = _rt_run_query("show schemas")
            sc_opts = [r.get("name") or r.get("NAME") for r in (sc_rows or []) if (r.get("name") or r.get("NAME"))]
        except Exception:
            sc_opts = []
        sel_schema = st.selectbox("Schema", options=["All"] + sc_opts, index=0, key="rt_schema")

        # Asset Type / Class Status / Risk
        try:
            at_rows = _rt_run_query(f"select distinct TABLE_TYPE as AT from {T_ASSETS} order by 1")
            asset_types = [r.get("AT") for r in (at_rows or []) if r.get("AT")]
        except Exception:
            asset_types = []
        sel_asset_type = st.selectbox("Asset Type", options=["All"] + asset_types, index=0, key="rt_at")
        sel_class_status = st.selectbox("Classification Status", options=["All", "Classified", "Unclassified"], index=0, key="rt_cls")
        sel_risk = st.selectbox("Risk Level", options=["All", "Low", "Medium", "High", "Critical"], index=0, key="rt_risk")

        # Compliance filters (Framework, Status)
        try:
            fw_rows = _rt_run_query(f"select distinct FRAMEWORK_NAME as FW from {T_CMAP} order by 1")
            fw_opts = [r.get("FW") for r in (fw_rows or []) if r.get("FW")]
        except Exception:
            fw_opts = []
        # Ensure common frameworks are always offered (including SOC)
        common_fw = ["SOC", "SOC 2", "GDPR", "HIPAA", "PCI DSS", "SOX"]
        fw_all = sorted({*(fw_opts or []), *common_fw})
        sel_framework = st.selectbox("Compliance Framework", options=["All"] + fw_all, index=0, key="rt_framework")

        # Dynamic Compliance Status options from mapping table
        try:
            st_rows = _rt_run_query(f"select distinct upper(coalesce(COMPLIANCE_STATUS,'')) as S from {T_CMAP} order by 1")
            # Normalize common variants
            raw_status = [r.get("S") for r in (st_rows or []) if r.get("S")]
            cstatus_opts = ["All"] + sorted(set(raw_status))
        except Exception:
            cstatus_opts = ["All", "COMPLIANT", "PARTIAL", "NON-COMPLIANT"]
        sel_cstatus = st.selectbox("Compliance Status", options=cstatus_opts, index=0, key="rt_cstatus")

        # Compliance Diagnostics
        with st.expander("Compliance Diagnostics", expanded=False):
            fw_disp = st.session_state.get("rt_framework", "All") or "All"
            cs_disp = st.session_state.get("rt_cstatus", "All") or "All"
            st.caption(f"Selected Framework: {fw_disp} | Status: {cs_disp}")

            # Build compliance-only filter and show counts/top ASSET_IDs
            try:
                where_diag, params_diag = _rt_apply_compliance_filter("", {}, "ASSET_ID", T_CMAP)
                cnt_rows = _rt_run_query(f"select count(*) as CNT from {T_ASSETS} {where_diag}", params_diag)
                cnt = int(cnt_rows[0].get("CNT", 0)) if cnt_rows else 0
                st.metric("Matching Assets", f"{cnt:,}")
                if cnt > 0:
                    ids = _rt_run_query(f"select ASSET_ID from {T_ASSETS} {where_diag} limit 10", params_diag)
                    id_list = [r.get("ASSET_ID") for r in (ids or []) if r.get("ASSET_ID")]
                    st.dataframe(pd.DataFrame({"ASSET_ID": id_list}), use_container_width=True, hide_index=True)
                else:
                    st.info("No assets match the current compliance filter.")
            except Exception as _diag_err:
                st.warning(f"Diagnostics unavailable: {_diag_err}")

        refresh = st.button("Refresh Now", type="primary")

    if refresh:
        st.cache_data.clear()

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
    pl_alerts = st.container()
    pl_quick = st.container()

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
