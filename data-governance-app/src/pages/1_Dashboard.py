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
import io

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
    # Asset type filter (prefer ASSET_TYPE, fallback to TABLE_TYPE if present)
    if sel_asset_type and sel_asset_type != "All":
        if "ASSET_TYPE" in cols:
            conds.append("ASSET_TYPE = %(atype)s")
            params["atype"] = sel_asset_type
        elif "TABLE_TYPE" in cols:
            conds.append("TABLE_TYPE = %(atype)s")
            params["atype"] = sel_asset_type
    # Classification status via CLASSIFICATION_LABEL presence
    if sel_class_status and sel_class_status != "All" and "CLASSIFICATION_LABEL" in cols:
        if sel_class_status == "Classified":
            conds.append("coalesce(CLASSIFICATION_LABEL,'') <> ''")
        else:
            conds.append("coalesce(CLASSIFICATION_LABEL,'') = ''")
    if sel_risk and sel_risk != "All" and "OVERALL_RISK_CLASSIFICATION" in cols:
        conds.append("OVERALL_RISK_CLASSIFICATION = %(risk)s")
        params["risk"] = sel_risk
    # Global compliance filters (if present in target table)
    try:
        sel_framework = st.session_state.get("rt_framework")
        if sel_framework and sel_framework != "All":
            fw_col = None
            if "FRAMEWORK_NAME" in cols:
                fw_col = "FRAMEWORK_NAME"
            elif "COMPLIANCE_STANDARD" in cols:
                fw_col = "COMPLIANCE_STANDARD"
            if fw_col:
                conds.append(f"{fw_col} = %(fw)s")
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
    cmap_cols = _rt_get_table_columns(T_CMAP)
    fw_col = "FRAMEWORK_NAME" if "FRAMEWORK_NAME" in cmap_cols else ("COMPLIANCE_STANDARD" if "COMPLIANCE_STANDARD" in cmap_cols else None)
    if fw and fw_col:
        conds.append(f"upper(coalesce(cm.{fw_col},'')) = %(fw_up)s")
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
            # Get distinct ASSET_TYPE values from ASSETS
            at_rows = snowflake_connector.execute_query(
                f"""
                SELECT DISTINCT ASSET_TYPE as T 
                FROM {sel_db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS 
                WHERE ASSET_TYPE IS NOT NULL
                ORDER BY 1
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
            rk_rows = snowflake_connector.execute_query(f"SELECT DISTINCT OVERALL_RISK_CLASSIFICATION FROM {sel_db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS WHERE OVERALL_RISK_CLASSIFICATION IS NOT NULL ORDER BY 1") if sel_db else []
            rk_opts = ["All"] + [r.get("OVERALL_RISK_CLASSIFICATION") for r in (rk_rows or []) if r.get("OVERALL_RISK_CLASSIFICATION")]
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

    # 🟢 Classification Health Score
    st.header("🟢 Classification Health Score")
    try:
        # Build filters for the query
        where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                            start_date, end_date,
                                            T_ASSETS, ["CLASSIFICATION_DATE", "CREATED_TIMESTAMP", "LAST_MODIFIED_TIMESTAMP"])
        where, params = _rt_apply_compliance_filter(where, params, "ASSET_ID", T_CMAP)
        
        # Use the centralized asset counting function
        from src.services.asset_utils import get_asset_counts
        
        # Get asset counts with the current filters
        counts = get_asset_counts(
            assets_table=T_ASSETS,
            where_clause=where.replace("T_ASSETS.", ""),  # Remove table prefix if present
            params=params,
            snowflake_connector=snowflake_connector
        )
        
        # Display the metrics
        k1, k2, k3, k4 = st.columns(4)
        safe_int = lambda v: int(v) if isinstance(v, (int, float)) else int((v or 0))
        
        k1.metric("Total Assets", f"{safe_int(counts['total_assets']):,}")
        k2.metric("Classified", f"{safe_int(counts['classified_count']):,}")
        k3.metric("Unclassified", f"{safe_int(counts['unclassified_count']):,}")
        
        cov = counts['coverage_pct'] or 0
        try:
            cov_int = int(float(cov))
        except Exception:
            cov_int = 0
            
        k4.progress(min(100, max(0, cov_int)), text=f"Coverage {cov}%")
        
    except Exception as e:
        _rt_show_error("Failed to load Classification Health", e)
        # Log the full error for debugging
        import traceback
        st.error(f"Error details: {str(e)}\n\n{traceback.format_exc()}")

    # 📈 Data Sensitivity Overview
    st.header("📈 Data Sensitivity Overview")

    # Assets by Classification Level (pie)
    st.subheader("Assets by Classification Level")
    try:
        where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                              start_date, end_date,
                                              T_ASSETS, ["CLASSIFICATION_DATE", "CREATED_TIMESTAMP", "LAST_MODIFIED_TIMESTAMP"])
        where, params = _rt_apply_compliance_filter(where, params, "ASSET_ID", T_CMAP)
        rows = _rt_run_query(f"""
                    select coalesce(CLASSIFICATION_LABEL,'Unclassified') as LEVEL, count(*) as CNT
                    from {T_ASSETS}
                    {where}
                    group by 1
                    order by 1
                """, params)
        df = pd.DataFrame(rows or [])
        if df.empty:
            st.info("No data available for breakdown.")
        else:
            fig = px.pie(df, names="LEVEL", values="CNT", hole=0.4)
            st.plotly_chart(fig, use_container_width=True)
    except Exception as e:
        _rt_show_error("Failed to load Classification Breakdown", e)

    # Unclassified Assets Alert (priority list)
    st.subheader("Unclassified Assets Alert")
    try:
        where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                              start_date, end_date,
                                              T_ASSETS, ["CLASSIFICATION_DATE", "CREATED_TIMESTAMP", "LAST_MODIFIED_TIMESTAMP"])
        # Build base where clause for unclassified/non-compliant assets
        base_where = (where + (" AND " if where else " WHERE ") + 
                     "(CLASSIFICATION_LABEL IS NULL OR COMPLIANCE_STATUS = 'NON_COMPLIANT')")
        where_u, params = _rt_apply_compliance_filter(base_where, params, "ASSET_ID", T_CMAP)
        
        # Execute the new query for unclassified/non-compliant assets
        rows = _rt_run_query(f"""
            SELECT
                ASSET_ID,
                ASSET_NAME,
                ASSET_TYPE,
                DATABASE_NAME,
                SCHEMA_NAME,
                OBJECT_NAME,
                CONCAT_WS('.', NULLIF(DATABASE_NAME,''), NULLIF(SCHEMA_NAME,''), OBJECT_NAME) as FULLY_QUALIFIED_NAME,
                DATA_OWNER,
                CLASSIFICATION_LABEL,
                CLASSIFICATION_DATE,
                COMPLIANCE_STATUS,
                CONTAINS_PII,
                CONTAINS_FINANCIAL_DATA,
                SOX_RELEVANT,
                SOC_RELEVANT,
                REGULATORY_DATA,
                DATEDIFF('day', CLASSIFICATION_DATE, CURRENT_TIMESTAMP()) AS DAYS_UNCLASSIFIED,
                CASE 
                    WHEN CLASSIFICATION_DATE IS NULL THEN 'High'
                    WHEN DATEDIFF('day', CLASSIFICATION_DATE, CURRENT_TIMESTAMP()) <= 3 THEN 'Low'
                    WHEN DATEDIFF('day', CLASSIFICATION_DATE, CURRENT_TIMESTAMP()) BETWEEN 4 AND 7 THEN 'Medium'
                    ELSE 'High'
                END AS PRIORITY_LEVEL
            FROM {T_ASSETS}
            {where_u}
            ORDER BY 
                CASE PRIORITY_LEVEL
                    WHEN 'High' THEN 1
                    WHEN 'Medium' THEN 2
                    WHEN 'Low' THEN 3
                    ELSE 4
                END,
                DAYS_UNCLASSIFIED DESC,
                DATABASE_NAME, 
                SCHEMA_NAME, 
                ASSET_NAME
            LIMIT 500
        """, params)
        
        df = pd.DataFrame(rows or [])
        # Fallback to demo data if empty
        if df.empty:
            try:
                from src.demo_data import UNCLASSIFIED_ASSETS_TSV
                if UNCLASSIFIED_ASSETS_TSV:
                    demo_df = pd.read_csv(io.StringIO(UNCLASSIFIED_ASSETS_TSV), sep='\t')
                    if not demo_df.empty:
                        # Ensure required columns for filters exist
                        if "PRIORITY_LEVEL" not in demo_df.columns:
                            demo_df["PRIORITY_LEVEL"] = "High"
                        if "DAYS_UNCLASSIFIED" not in demo_df.columns:
                            demo_df["DAYS_UNCLASSIFIED"] = 5
                        
                        # Parse FQN for display if needed
                        if "FULLY_QUALIFIED_NAME" in demo_df.columns and "DATABASE_NAME" not in demo_df.columns:
                            # flexible split
                            def parse_fqn(f):
                                p = str(f).split('.')
                                return pd.Series([p[0] if len(p)>0 else '', p[1] if len(p)>1 else '', p[2] if len(p)>2 else ''])
                            demo_df[["DATABASE_NAME", "SCHEMA_NAME", "OBJECT_NAME"]] = demo_df["FULLY_QUALIFIED_NAME"].apply(parse_fqn)

                        # Default boolean flags for domain filters
                        for col in ["CONTAINS_PII", "CONTAINS_FINANCIAL_DATA", "SOX_RELEVANT", "SOC_RELEVANT", "REGULATORY_DATA"]:
                            if col not in demo_df.columns:
                                demo_df[col] = False
                        
                        df = demo_df
            except Exception as ex:
                pass # Fallback failed, stick with empty df
        if df.empty:
            st.info("No unclassified or non-compliant assets found.")
        else:
            c1, c2, c3 = st.columns(3)
            
            # Priority level filter
            pr_level = c1.selectbox("Priority Level", ["All", "High", "Medium", "Low"])
            
            # Days unclassified filter
            md_series = pd.to_numeric(df["DAYS_UNCLASSIFIED"], errors="coerce") 
            if not md_series.empty and not md_series.isna().all():
                max_days = int(md_series.max())
                day_range = c2.slider("Days Unclassified", 0, max(1, max_days), (0, max_days))
            else:
                day_range = (0, 0)
                c2.caption("No classification date available")
            
            # Domain filter
            domain = c3.selectbox("Compliance", ["All", "PII", "SOX", "SOC2"])
            
            # Apply filters
            f = df.copy()
            
            # Apply priority filter
            if pr_level != "All":
                f = f[f["PRIORITY_LEVEL"] == pr_level]
            
            # Apply days unclassified filter
            if "DAYS_UNCLASSIFIED" in f.columns:
                f = f[
                    (f["DAYS_UNCLASSIFIED"] >= day_range[0]) & 
                    (f["DAYS_UNCLASSIFIED"] <= day_range[1])
                ]
            
            # Apply domain filter
            if domain == "PII":
                f = f[f["CONTAINS_PII"] == True]
            elif domain == "Financial":
                f = f[f["CONTAINS_FINANCIAL_DATA"] == True]
            elif domain == "Regulatory":
                f = f[f["REGULATORY_DATA"] == True]
            elif domain == "SOX":
                f = f[f["SOX_RELEVANT"] == True]
            elif domain == "SOC":
                f = f[f["SOC_RELEVANT"] == True]
            page_size = 25
            page = st.number_input("Page", min_value=1, value=1, step=1)
            page_df, total = _rt_paginate_df(f, page, page_size)
            st.caption(f"Showing {len(page_df)} of {total} items")
            st.dataframe(page_df, use_container_width=True, hide_index=True)
    except Exception as e:
        _rt_show_error("Failed to load Unclassified Priority", e)

    # Classification Progress Tracking
    st.subheader("Classification Progress Tracking")
    try:
        # Detailed Classification Progress Tracking query
        query = """
        WITH CLASSIFICATION_METRICS AS (
            -- Total assets in the database - Table Count
            SELECT 
                COUNT(*) AS TOTAL_ASSETS,
                COUNT(DISTINCT TABLE_SCHEMA) AS TOTAL_SCHEMAS,
                'TABLE' AS METRIC_TYPE
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_CATALOG = CURRENT_DATABASE()
              AND TABLE_TYPE = 'BASE TABLE'
              AND TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA')
            
            UNION ALL
            
            -- Total columns with potential PII - Column Count
            SELECT 
                COUNT(*) AS TOTAL_ASSETS,
                COUNT(DISTINCT TABLE_SCHEMA) AS TOTAL_SCHEMAS,
                'COLUMN' AS METRIC_TYPE
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_CATALOG = CURRENT_DATABASE()
              AND TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA')
              AND (UPPER(COLUMN_NAME) LIKE '%EMAIL%' 
                   OR UPPER(COLUMN_NAME) LIKE '%PHONE%' 
                   OR UPPER(COLUMN_NAME) LIKE '%SSN%' 
                   OR UPPER(COLUMN_NAME) LIKE '%ADDRESS%'
                   OR UPPER(COLUMN_NAME) LIKE '%BIRTH%'
                   OR UPPER(COLUMN_NAME) LIKE '%SALARY%'
                   OR UPPER(COLUMN_NAME) LIKE '%CREDIT%'
                   OR UPPER(COLUMN_NAME) LIKE '%PASSWORD%'
                   OR UPPER(COLUMN_NAME) LIKE '%ACCOUNT%')
        ),

        TAGGED_ASSETS AS (
            -- Count tagged tables
            SELECT 
                COUNT(DISTINCT OBJECT_DATABASE || '.' || OBJECT_SCHEMA || '.' || OBJECT_NAME) AS TAGGED_COUNT,
                'TABLE' AS ASSET_TYPE
            FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
            WHERE OBJECT_DATABASE = CURRENT_DATABASE()
              AND DOMAIN = 'TABLE'
            
            UNION ALL
            
            -- Count tagged columns
            SELECT 
                COUNT(DISTINCT OBJECT_DATABASE || '.' || OBJECT_SCHEMA || '.' || OBJECT_NAME || '.' || COLUMN_NAME) AS TAGGED_COUNT,
                'COLUMN' AS ASSET_TYPE
            FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
            WHERE OBJECT_DATABASE = CURRENT_DATABASE()
              AND DOMAIN = 'COLUMN'
        ),

        CLASSIFICATION_PROGRESS AS (
            SELECT 
                CASE 
                    WHEN m.METRIC_TYPE = 'TABLE' THEN 'TABLES'
                    WHEN m.METRIC_TYPE = 'COLUMN' THEN 'SENSITIVE_COLUMNS'
                END AS ASSET_CATEGORY,
                m.TOTAL_ASSETS,
                COALESCE(t.TAGGED_COUNT, 0) AS CLASSIFIED_ASSETS,
                m.TOTAL_ASSETS - COALESCE(t.TAGGED_COUNT, 0) AS UNCLASSIFIED_ASSETS
            FROM CLASSIFICATION_METRICS m
            LEFT JOIN TAGGED_ASSETS t ON m.METRIC_TYPE = t.ASSET_TYPE
        )

        SELECT 
            ASSET_CATEGORY,
            TOTAL_ASSETS,
            CLASSIFIED_ASSETS,
            UNCLASSIFIED_ASSETS,
            ROUND((CLASSIFIED_ASSETS * 100.0 / NULLIF(TOTAL_ASSETS, 0)), 2) AS COMPLETION_PERCENTAGE,
            CASE 
                WHEN ROUND((CLASSIFIED_ASSETS * 100.0 / NULLIF(TOTAL_ASSETS, 0)), 2) = 0 THEN '❌ NOT STARTED'
                WHEN ROUND((CLASSIFIED_ASSETS * 100.0 / NULLIF(TOTAL_ASSETS, 0)), 2) < 25 THEN '🔴 POOR'
                WHEN ROUND((CLASSIFIED_ASSETS * 100.0 / NULLIF(TOTAL_ASSETS, 0)), 2) < 50 THEN '🟠 FAIR'
                WHEN ROUND((CLASSIFIED_ASSETS * 100.0 / NULLIF(TOTAL_ASSETS, 0)), 2) < 75 THEN '🟡 GOOD'
                WHEN ROUND((CLASSIFIED_ASSETS * 100.0 / NULLIF(TOTAL_ASSETS, 0)), 2) < 90 THEN '🟢 VERY GOOD'
                ELSE '✅ EXCELLENT'
            END AS PROGRESS_STATUS,
            CASE 
                WHEN ROUND((CLASSIFIED_ASSETS * 100.0 / NULLIF(TOTAL_ASSETS, 0)), 2) < 100 
                THEN 'Need to classify ' || UNCLASSIFIED_ASSETS || ' more ' || 
                     CASE WHEN ASSET_CATEGORY = 'TABLES' THEN 'tables' ELSE 'columns' END
                ELSE 'Classification Complete!'
            END AS NEXT_ACTION
        FROM CLASSIFICATION_PROGRESS
        ORDER BY 
            CASE ASSET_CATEGORY 
                WHEN 'TABLES' THEN 1 
                WHEN 'SENSITIVE_COLUMNS' THEN 2 
            END
        """
        
        # Execute the query
        results = _rt_run_query(query)
        
        if not results:
             st.info("No classification progress data available for the current database.")
        else:
            # Render updated UI
            for row in results:
                # Handle dictionary keys robustly (upper case expected)
                row_up = {k.upper(): v for k, v in row.items()}
                
                category = row_up.get('ASSET_CATEGORY', 'Unknown')
                total = int(row_up.get('TOTAL_ASSETS') or 0)
                classified = int(row_up.get('CLASSIFIED_ASSETS') or 0)
                pct = float(row_up.get('COMPLETION_PERCENTAGE') or 0.0)
                status = row_up.get('PROGRESS_STATUS', '')
                action = row_up.get('NEXT_ACTION', '')

                # Visual container for each category
                with st.container():
                    c1, c2 = st.columns([3, 1])
                    with c1:
                         label_map = {'TABLES': 'Tables', 'SENSITIVE_COLUMNS': 'Sensitive Columns'}
                         display_name = label_map.get(category, category)
                         st.markdown(f"**{display_name}**  <span style='color:gray; font-size:0.9em'>({classified} / {total} classified)</span>", unsafe_allow_html=True)
                         st.progress(min(100, max(0, int(pct))))
                         if action:
                             st.caption(f"Action: {action}")
                    with c2:
                        st.markdown(f"### {pct}%")
                        st.markdown(f"{status}")
                    st.divider()
            
    except Exception as e:
        _rt_show_error("Failed to load Classification Progress", e)

    # ⚖️ Compliance Status Widget
    st.header("⚖️ Compliance Status Widget")

    # Policy Compliance Score
    st.subheader("Policy Compliance Score")
    try:
        # Build filters from sidebar selections
        where_clause, params = _rt_build_filters_for(
            sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
            start_date, end_date,
            f"{sel_db}.{_SCHEMA}.ASSETS" if sel_db else "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS",
            ["CREATED_AT", "UPDATED_AT"]
        )
        
        # Base query with dynamic table reference
        base_table = f"{sel_db}.{_SCHEMA}.ASSETS" if sel_db else "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS"
        
        # Execute the Policy Compliance Score query with filters
        query = f"""
        WITH filtered_assets AS (
            SELECT * 
            FROM {base_table}
            {where_clause}
        )
        SELECT
            COUNT(*) AS total_assets,
            COUNT(CASE WHEN UPPER(COALESCE(compliance_status,'')) = 'COMPLIANT' THEN 1 END) AS compliant_assets,
            ROUND(
                100.0 * COUNT(CASE WHEN UPPER(COALESCE(compliance_status,'')) = 'COMPLIANT' THEN 1 END) 
                / NULLIF(COUNT(*), 0), 2
            ) AS policy_compliance_score_percent
        FROM filtered_assets
        """
        
        # Execute the query
        result = _rt_run_query(query)
        
        if result and result[0]:
            total_assets = result[0].get('TOTAL_ASSETS', 0) or 0
            compliant_assets = result[0].get('COMPLIANT_ASSETS', 0) or 0
            compliance_score = result[0].get('POLICY_COMPLIANCE_SCORE_PERCENT', 0) or 0
            
            # Display key metrics
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Assets", f"{int(total_assets):,}")
            col2.metric("Compliant Assets", f"{int(compliant_assets):,}")
            col3.metric("Compliance Score", f"{float(compliance_score)}%")
            
            # Simple progress bar for visualization
            progress_value = min(100, max(0, float(compliance_score)))
            st.progress(progress_value / 100.0)
            
            # Add some spacing
            st.write("")
        else:
            st.info("No compliance data available.")
    except Exception as e:
        _rt_show_error("Failed to load Compliance Status", e)

    # Review Completion Rate
    st.subheader("Review Completion Rate")
    try:
        # Build filters from sidebar selections
        where_clause, params = _rt_build_filters_for(
            sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
            start_date, end_date,
            f"{sel_db}.{_SCHEMA}.ASSETS" if sel_db else "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS",
            ["CREATED_AT", "UPDATED_AT", "NEXT_REVIEW_DATE"]
        )
        
        # Base table with dynamic reference
        base_table = f"{sel_db}.{_SCHEMA}.ASSETS" if sel_db else "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS"
        
        # Execute the Review Completion Rate query with filters
        query = f"""
        WITH filtered_assets AS (
            SELECT * 
            FROM {base_table}
            {where_clause}
        )
        SELECT
            COUNT(*) AS total_assets,
            COUNT(CASE 
                     WHEN peer_review_completed = TRUE 
                          AND management_review_completed = TRUE 
                          AND technical_review_completed = TRUE 
                     THEN 1 
                 END) AS completed_reviews,
            ROUND(
                100.0 * COUNT(CASE 
                                 WHEN peer_review_completed = TRUE 
                                      AND management_review_completed = TRUE 
                                      AND technical_review_completed = TRUE 
                                 THEN 1 
                             END) 
                / NULLIF(COUNT(*), 0), 2
            ) AS completion_rate_percent,
            COUNT(CASE 
                     WHEN next_review_date > CURRENT_DATE 
                     THEN 1 
                 END) AS upcoming_reviews,
            COUNT(CASE 
                     WHEN next_review_date <= CURRENT_DATE 
                          AND COALESCE(review_status, '') != 'CURRENT' 
                     THEN 1 
                 END) AS overdue_reviews
        FROM filtered_assets
        """
        
        # Execute the query
        result = _rt_run_query(query, params)
        
        if result and result[0]:
            total_assets = result[0].get('TOTAL_ASSETS', 0) or 0
            completed_reviews = result[0].get('COMPLETED_REVIEWS', 0) or 0
            completion_rate = result[0].get('COMPLETION_RATE_PERCENT', 0) or 0
            upcoming_reviews = result[0].get('UPCOMING_REVIEWS', 0) or 0
            overdue_reviews = result[0].get('OVERDUE_REVIEWS', 0) or 0
            
            # Display metrics in columns
            col1, col2, col3 = st.columns(3)
            col1.metric("Completed Reviews", f"{int(completed_reviews):,}")
            col2.metric("Upcoming Reviews", f"{int(upcoming_reviews):,}")
            col3.metric("Completion Rate", f"{float(completion_rate)}%")
            
            # Show overdue reviews as a warning below
            if overdue_reviews > 0:
                st.warning(f"⚠️ {int(overdue_reviews):,} reviews are overdue")
            
            # Add a progress bar for completion rate
            progress_value = min(100, max(0, float(completion_rate)))
            st.progress(progress_value / 100.0)
        else:
            st.info("No review data available.")
    except Exception as e:
        _rt_show_error("Failed to load Review Completion Rate", e)

    # Exception Count (policy-related alerts)
    st.subheader("Exception Count")
    try:
        # Build filters from sidebar selections
        where_clause, params = _rt_build_filters_for(
            sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
            start_date, end_date,
            f"{sel_db}.{_SCHEMA}.ASSETS" if sel_db else "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS",
            ["CREATED_AT", "UPDATED_AT"]
        )
        
        # Base table with dynamic reference
        base_table = f"{sel_db}.{_SCHEMA}.ASSETS" if sel_db else "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS"
        
        # Execute the Exception Count query with filters
        query = f"""
        WITH filtered_assets AS (
            SELECT * 
            FROM {base_table}
            {where_clause}
        )
        SELECT
            COUNT(CASE WHEN has_exception = TRUE THEN 1 END) AS total_assets_with_exceptions,
            COUNT(CASE 
                     WHEN has_exception = TRUE 
                          AND (exception_expiry_date IS NULL OR exception_expiry_date >= CURRENT_DATE)
                     THEN 1 
                 END) AS open_policy_exceptions
        FROM filtered_assets
        """
        
        # Execute the query
        result = _rt_run_query(query, params)
        
        if result and result[0]:
            total_exceptions = result[0].get('TOTAL_ASSETS_WITH_EXCEPTIONS', 0) or 0
            open_exceptions = result[0].get('OPEN_POLICY_EXCEPTIONS', 0) or 0
            
            # Display metrics in columns
            col1, col2 = st.columns(2)
            col1.metric("Total Assets with Exceptions", f"{int(total_exceptions):,}")
            
            # Show open exceptions with a warning if there are any
            if open_exceptions > 0:
                col2.metric("Open Policy Exceptions", 
                          f"{int(open_exceptions):,}",
                          delta=None,
                          help="Exceptions that are either not expired or have no expiry date")
                if open_exceptions > 0:
                    st.warning(f"⚠️ {int(open_exceptions):,} active policy exceptions need attention")
            else:
                col2.metric("Open Policy Exceptions", "0", delta=None, help="No active policy exceptions")
                
        else:
            st.info("No exception data available.")
            
    except Exception as e:
        _rt_show_error("Failed to load Exception Count", e)

    # 🔄 Recent Activity Feed
    st.header("🔄 Recent Activity Feed")

    # New Classifications
    st.subheader("New Classifications")
    try:
        where, params = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                              start_date, end_date,
                                              T_ASSETS, ["CLASSIFICATION_DATE", "CREATED_TIMESTAMP", "LAST_MODIFIED_TIMESTAMP"])
        where, params = _rt_apply_compliance_filter(where, params, "ASSET_ID", T_CMAP)
        where_cls = where + ((" AND " if where else " WHERE ") + "coalesce(CLASSIFICATION_LABEL,'') <> ''")
        rows = _rt_run_query(f"""
            select DATABASE_NAME, SCHEMA_NAME, ASSET_NAME, ASSET_TYPE as ASSET_TYPE, CLASSIFICATION_LABEL as CLASSIFICATION_LEVEL, CLASSIFICATION_DATE as LAST_CLASSIFIED_AT
            from {T_ASSETS}
            {where_cls}
            order by LAST_CLASSIFIED_AT desc
            limit 200
        """, params)
        df = pd.DataFrame(rows or [])
        if df.empty:
            st.info("No recent classifications.")
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)
    except Exception as e:
        _rt_show_error("Failed to load New Classifications", e)

    # Reclassification Requests (pending approvals)
    st.subheader("Reclassification Requests")
    try:
        where_appr, params_appr = _rt_build_filters_for(sel_bu, sel_db, sel_schema, sel_asset_type, sel_class_status, sel_risk,
                                                        start_date, end_date,
                                                        T_CHIST, ["CHANGE_TIMESTAMP"])
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
        if df.empty:
            st.info("No reclassification requests pending.")
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)
    except Exception as e:
        _rt_show_error("Failed to load Reclassification Requests", e)

    # Policy Updates (alerts filtered by policy)
    st.subheader("Policy Updates")
    try:
        T_POLICIES = f"{active_db}.{_SCHEMA}.POLICIES"
        rows = _rt_run_query(f"""
             SELECT
                POLICY_ID,
                POLICY_NAME,
                POLICY_VERSION,
                POLICY_TYPE,
                UPDATED_AT,
                UPDATED_BY,
                STATUS,
                'RECENTLY_UPDATED' AS UPDATE_TYPE
            FROM {T_POLICIES}
            WHERE UPDATED_AT >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
            ORDER BY UPDATED_AT DESC
        """)
        df = pd.DataFrame(rows or [])
        if df.empty:
            st.info("No recent policy updates found.")
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)
    except Exception as e:
        _rt_show_error("Failed to load Policy Updates", e)

    # ⚡ Quick Actions & Recent Activity
    st.header("Actions & Activity")
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("⚡ Quick Actions")
        if st.button("🏷️ Classify New Asset", use_container_width=True):
            st.switch_page("pages/3_Classification.py")
        
        if st.button("📄 Run Compliance Report", use_container_width=True):
             st.switch_page("pages/4_Compliance.py")

        if st.button("⏰ Review Overdue Tasks", use_container_width=True):
             # Navigate to Data Assets for detailed review
             st.switch_page("pages/2_Data_Assets.py")
             
        if st.button("📖 View Policy Guidelines", use_container_width=True):
             st.switch_page("pages/12_Policy_Guidance.py")
    
    with col2:
        st.subheader("🔔 Recent Activity")
        try:
             # Fetch real activity from history and updates
             # 1. Recent History (Classifications)
             hist_rows = _rt_run_query(f"""
                select TOP 5 
                    UPPER(a.ASSET_NAME) as NAME, 
                    h.NEW_CLASSIFICATION as DETAIL, 
                    h.CHANGED_BY as USER, 
                    h.CHANGE_TIMESTAMP as TS,
                    'Classification Change' as TYPE
                from {T_CHIST} h
                left join {T_ASSETS} a on h.ASSET_ID = a.ASSET_ID
                where h.CHANGE_TIMESTAMP >= dateadd('day', -7, current_timestamp())
                order by TS desc
             """)
             
             # 2. Recent Asset Updates (e.g. Reviews)
             # Simulate review activity from ASSETS modified timestamp if history is empty or for variety
             asset_rows = _rt_run_query(f"""
                select TOP 5
                    UPPER(ASSET_NAME) as NAME,
                    'Asset Updated' as DETAIL,
                    LAST_MODIFIED_BY as USER,
                    LAST_MODIFIED_TIMESTAMP as TS,
                    'Update' as TYPE
                from {T_ASSETS}
                where LAST_MODIFIED_TIMESTAMP >= dateadd('day', -7, current_timestamp())
                order by TS desc
             """)
             
             # Combine and sort
             combined = (hist_rows or []) + (asset_rows or [])
             combined.sort(key=lambda x: x['TS'] if x['TS'] else datetime.min, reverse=True)
             
             if not combined:
                 st.info("No recent activity found.")
             else:
                 for item in combined[:4]:
                     name = item.get('NAME') or 'Unknown Asset'
                     detail = item.get('DETAIL') or 'Updated'
                     user = item.get('USER') or 'System'
                     ts = item.get('TS')
                     
                     # Calculate friendly time diff
                     time_str = "Recently"
                     if ts:
                         try:
                             now = datetime.now(ts.tzinfo)
                             diff = now - ts
                             if diff.days > 0: time_str = f"{diff.days} days ago"
                             elif diff.seconds > 3600: time_str = f"{diff.seconds//3600} hours ago"
                             else: time_str = f"{diff.seconds//60} mins ago"
                         except: pass

                     st.info(f"**{name}**\n{detail}\n{user} • {time_str}")

        except Exception as e:
            st.error(f"Failed to load activity: {e}")

    st.caption("Data updates live from Snowflake. Use Refresh to fetch latest.")

# Render dashboard
render_realtime_dashboard()
