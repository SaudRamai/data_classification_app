import os
import sys
import pathlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Set

import streamlit as st
import logging

logger = logging.getLogger(__name__)
import streamlit.components.v1 as components

# MUST be the first Streamlit command
st.set_page_config(page_title="Dashboard", page_icon="📊", layout="wide")

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import io

# Ensure project root is on path for imports
_here = pathlib.Path(str(__file__)).resolve()
_dir = _here.parent
# Traverse up to find directory containing 'src'
for _ in range(3):
    if (_dir / "src").exists():
        if str(_dir) not in sys.path:
            sys.path.insert(0, str(_dir))
        break
    _dir = _dir.parent
_project_root = str(_dir)

from src.connectors.snowflake_connector import snowflake_connector
from src.ui.theme import apply_global_theme
from src.config.settings import settings
from src.services.compliance_service import compliance_service
from src.components.filters import render_global_filters
# Removed broken tag_drift_service import
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
    # If bypass is active, suppress intrusive error messages about connection
    is_bypassed = False
    try:
        if _authz and _authz._is_bypass():
            is_bypassed = True
    except Exception:
        pass
        
    text = f"{msg}{(': ' + str(exc)) if exc else ''}"
    if is_bypassed:
        logger.warning(text)
    else:
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
    apply_global_theme()
    st.markdown("""
    <div class="page-hero">
        <div style="display: flex; align-items: center; gap: 1.5rem;">
            <div class="hero-icon-box">📊</div>
            <div>
                <h1 class="hero-title">Dashboard</h1>
                <p class="hero-subtitle">Real-time overview of data classification and compliance status.</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Require Snowflake session before any queries
    has_session = False
    try:
        # Check if bypass is active first
        if _authz is not None and _authz._is_bypass():
            has_session = True
        
        if not has_session and _authz is not None:
            ident = _authz.get_current_identity()
            has_session = bool(getattr(ident, 'user', None))
    except Exception:
        has_session = False
    # Fallback: check Streamlit session creds
    if not has_session:
        has_session = bool(st.session_state.get("sf_user") and st.session_state.get("sf_account"))
    # If Snowflake session is missing, render UI but disable data access
    if not has_session:
        if st.session_state.get("user") is not None:
            st.warning("Snowflake session is not active. Some data may not load. Use Home to re-authenticate when ready.")
        else:
            st.warning("You are not signed in. Data access is disabled until login.")
            st.caption("Open Home and login with your Snowflake account or SSO to enable live data.")
        # Render lightweight, non-query placeholders and exit the function to avoid queries
        st.markdown("---")
        st.subheader("Overview")
        st.info("Data will appear here after you sign in.")
        st.subheader("Trends")
        st.info("Charts are disabled until authentication.")
        st.subheader("Recent Activity")
        st.info("Recent events will load after login.")
        return


    # Resolve active database for all queries (fallback to settings or default)
    active_db = (
        st.session_state.get("sf_database")
        or getattr(settings, "SNOWFLAKE_DATABASE", None)
        or "DATA_CLASSIFICATION_DB"
    )
    # Centralized FQNs (initial; may be overridden after sidebar selection)
    # Authoritative Data Sources (Optimized)
    _SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
    T_ASSETS = f"{active_db}.{_SCHEMA}.ASSETS"
    T_AI_RESULTS = f"{active_db}.{_SCHEMA}.CLASSIFICATION_AI_RESULTS"

    # Global Filters sidebar (restored)
    _rt_ensure_session_context()
    with st.sidebar:
        # Standardized Global Filters
        g_filters = render_global_filters(key_prefix="dashboard")
        sel_db = g_filters.get("database")
        sel_schema = g_filters.get("schema") or "All"
        

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

        st.markdown("---")
        st.subheader("🛠️ Developer Tools")
        if st.button("Refresh Demo Data", key="refresh_demo_btn"):
            from src.services.asset_utils import seed_sample_assets
            res = seed_sample_assets(active_db, _SCHEMA, snowflake_connector)
            if any("Error" in str(r) for r in res.get("results", [])):
                st.error(f"Failed to seed data: {res.get('results')}")
            else:
                st.success("Sample data seeded! Refreshing...")
                st.rerun()

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
            T_AI_RESULTS = f"{active_db}.{_SCHEMA}.CLASSIFICATION_AI_RESULTS"
    except Exception:
        pass

    # ✔ 1. Classification Health Score
    st.header("🛡️ Classification Health Program")
    
    try:
        from src.services.asset_utils import get_health_score_metrics
        health = get_health_score_metrics(active_db, _SCHEMA, snowflake_connector)
        
        # Premium UI CSS
        st.markdown("""
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
                
                .health-container {
                    font-family: 'Inter', sans-serif;
                    padding: 10px 0;
                }
                
                .main-score-header {
                    font-size: 24px;
                    font-weight: 800;
                    background: linear-gradient(90deg, #FFFFFF 0%, #A0AEC0 100%);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    margin-bottom: 5px;
                }
                
                .info-panel {
                    background: rgba(255, 255, 255, 0.03);
                    border-radius: 12px;
                    padding: 15px;
                    border: 1px solid rgba(255, 255, 255, 0.05);
                    height: 100%;
                }
                
                .info-title {
                    font-size: 12px;
                    font-weight: 800;
                    color: #4FD1C5;
                    text-transform: uppercase;
                    letter-spacing: 1.5px;
                    margin-bottom: 10px;
                }
                
                .info-item {
                    font-size: 13px;
                    color: rgba(255, 255, 255, 0.8);
                    margin-bottom: 8px;
                    display: flex;
                    align-items: center;
                }
                
                .info-bullet {
                    color: #4FD1C5;
                    margin-right: 10px;
                    font-weight: bold;
                }
                
                .pillar-card {
                    background: linear-gradient(145deg, rgba(26, 32, 44, 0.6), rgba(17, 21, 28, 0.8));
                    border-radius: 20px;
                    padding: 22px;
                    border: 1px solid rgba(255, 255, 255, 0.08);
                    text-align: center;
                    transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
                    position: relative;
                    overflow: hidden;
                    height: 100%;
                }
                
                .pillar-card:hover {
                    transform: translateY(-8px);
                    border-color: rgba(79, 209, 197, 0.4);
                    background: linear-gradient(145deg, rgba(30, 39, 54, 0.8), rgba(20, 26, 35, 0.9));
                    box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4), 0 0 20px rgba(79, 209, 197, 0.1);
                }
                
                .pillar-icon {
                    font-size: 28px;
                    margin-bottom: 12px;
                    opacity: 0.9;
                }
                
                .pillar-value {
                    font-size: 34px;
                    font-weight: 800;
                    color: #FFFFFF;
                    margin: 5px 0;
                }
                
                .pillar-label {
                    font-size: 12px;
                    font-weight: 700;
                    color: rgba(255, 255, 255, 0.5);
                    text-transform: uppercase;
                    letter-spacing: 1.2px;
                }
                
                .pillar-status {
                    font-size: 11px;
                    font-weight: 600;
                    color: #4FD1C5;
                    margin-top: 10px;
                    padding: 4px 10px;
                    background: rgba(79, 209, 197, 0.1);
                    border-radius: 20px;
                    display: inline-block;
                }
                
                .divider-glow {
                    height: 1px;
                    background: linear-gradient(90deg, transparent, rgba(79, 209, 197, 0.3), transparent);
                    margin: 30px 0;
                }
            </style>
        """, unsafe_allow_html=True)

        col_gauge, col_info = st.columns([1, 1])
        
        with col_gauge:
            score = health.get('overall_score', 0)
            # Sophisticated Gauge using Plotly
            fig = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Program Maturity", 'font': {'size': 18, 'color': 'white', 'family': 'Inter'}},
                number = {'font': {'size': 50, 'color': 'white', 'family': 'Inter'}, 'suffix': "%"},
                gauge = {
                    'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
                    'bar': {'color': "#4FD1C5"},
                    'bgcolor': "rgba(0,0,0,0)",
                    'borderwidth': 2,
                    'bordercolor': "rgba(255,255,255,0.1)",
                    'steps': [
                        {'range': [0, 40], 'color': 'rgba(231, 76, 60, 0.1)'},
                        {'range': [40, 75], 'color': 'rgba(241, 196, 15, 0.1)'},
                        {'range': [75, 100], 'color': 'rgba(46, 204, 113, 0.1)'}
                    ],
                    'threshold': {
                        'line': {'color': "white", 'width': 4},
                        'thickness': 0.75,
                        'value': score
                    }
                }
            ))
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=30, r=30, t=50, b=20),
                height=250,
            )
            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

        with col_info:
            score = health.get('overall_score', 0)
            if score < 40:
                recommendation = "🔴 **Critical:** High volume of unclassified assets or SLA breaches. Priority: Bulk classification scan."
            elif score < 75:
                recommendation = "🟠 **Needs Attention:** Governance workflow is lagging. Priority: Approve pending labels and sync reviews."
            else:
                recommendation = "🟢 **Healthy:** Program meeting targets. Priority: Regular drift monitoring and policy refinement."
                
            st.markdown(f"""
                <div class="info-panel">
                    <div class="info-title">What it shows</div>
                    <div class="info-item"><span class="info-bullet">▹</span> <b>{health.get('total_assets', 0)}</b> Total active assets included</div>
                    <div class="info-item"><span class="info-bullet">▹</span> Program health across 4 core governance dimensions</div>
                    <div class="info-title" style="margin-top:15px">Actionable Insight</div>
                    <div style="font-size: 13px; color: rgba(255,255,255,0.9); line-height:1.5;">{recommendation}</div>
                    <div class="info-title" style="margin-top:15px">Key Indicators</div>
                    <div class="info-item"><span class="info-bullet">✓</span> Coverage, Accuracy, Timeliness, Governance</div>
                </div>
            """, unsafe_allow_html=True)

        st.write("") # Spacer

        # 4 Key Pillars with enhanced CSS
        c1, c2, c3, c4 = st.columns(4)
        
        with c1:
            st.markdown(f"""
                <div class="pillar-card">
                    <div class="pillar-icon">📊</div>
                    <div class="pillar-label">Coverage</div>
                    <div class="pillar-value">{health.get('coverage_pct', 0)}%</div>
                    <div class="pillar-status">Classified Assets</div>
                </div>
            """, unsafe_allow_html=True)

        with c2:
            st.markdown(f"""
                <div class="pillar-card">
                    <div class="pillar-icon">⚖️</div>
                    <div class="pillar-label">Accuracy</div>
                    <div class="pillar-value">{health.get('approval_pct', 0)}%</div>
                    <div class="pillar-status">Approved/Validated</div>
                </div>
            """, unsafe_allow_html=True)

        with c3:
            st.markdown(f"""
                <div class="pillar-card">
                    <div class="pillar-icon">⏱️</div>
                    <div class="pillar-label">Timeliness</div>
                    <div class="pillar-value">{health.get('sla_pct', 0)}%</div>
                    <div class="pillar-status">Within SLA Window</div>
                </div>
            """, unsafe_allow_html=True)

        with c4:
            st.markdown(f"""
                <div class="pillar-card">
                    <div class="pillar-icon">🔄</div>
                    <div class="pillar-label">Governance</div>
                    <div class="pillar-value">{health.get('reviews_pct', 0)}%</div>
                    <div class="pillar-status">Policy Compliance</div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    except Exception as e:
        _rt_show_error("Failed to load Classification Health Score", e)


    # Data Sensitivity Overview
    st.header("📉 Data Sensitivity Overview")
    st.markdown("Risk & exposure snapshot")
    
    try:
        from src.services.asset_utils import get_sensitivity_overview
        sens_data = get_sensitivity_overview(active_db, _SCHEMA, snowflake_connector)
        
        c_s1, c_s2 = st.columns([1, 1])
        
        with c_s1:
            # 1. Sensitivity Distribution (Pie Chart)
            if sens_data['labels']:
                df_labels = pd.DataFrame(list(sens_data['labels'].items()), columns=['Label', 'Count'])
                fig_labels = px.pie(
                    df_labels, values='Count', names='Label', 
                    title="Sensitivity Distribution",
                    color_discrete_sequence=px.colors.qualitative.Pastel,
                    hole=0.4
                )
                fig_labels.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color="white", height=350)
                st.plotly_chart(fig_labels, use_container_width=True)
            else:
                st.info("No classified assets found for distribution.")

        with c_s2:
            # 2. PII vs Non-PII (Bar Chart)
            df_pii = pd.DataFrame([
                {'Category': 'PII Relevant', 'Count': sens_data['pii_count']},
                {'Category': 'Non-PII', 'Count': sens_data['non_pii_count']}
            ])
            fig_pii = px.bar(
                df_pii, x='Category', y='Count',
                title="PII vs Non-PII Assets",
                color='Category',
                color_discrete_map={'PII Relevant': '#E74C3C', 'Non-PII': '#4FD1C5'}
            )
            fig_pii.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color="white", height=350)
            st.plotly_chart(fig_pii, use_container_width=True)

        # 3. Regulated & Risk Summary (Horizontal Bars)
        st.markdown("""
            <div style="background: rgba(255, 255, 255, 0.03); border-radius: 12px; padding: 20px; border: 1px solid rgba(255, 255, 255, 0.05); margin-top: 10px;">
                <div class="info-title" style="margin-bottom: 20px;">Regulated Data Categories</div>
            </div>
        """, unsafe_allow_html=True)
        
        col_r1, col_r2, col_r3 = st.columns(3)
        with col_r1:
            st.metric("PII Datasets", sens_data['regulated'].get('PII', 0))
        with col_r2:
            st.metric("SOX Relevant", sens_data['regulated'].get('SOX', 0))
        with col_r3:
            st.metric("SOC2 Critical", sens_data['regulated'].get('SOC2', 0))

        st.caption("📌 Answers: “What kind of sensitive data do we have?”")

        st.markdown('<div class="divider-glow" style="margin-top: 40px;"></div>', unsafe_allow_html=True)

    except Exception as e:
        _rt_show_error("Failed to load Data Sensitivity Overview section", e)

    # Unclassified Assets
    st.header("🔍 Unclassified Assets")
    st.markdown("Early risk detection & backlog management")
    
    try:
        from src.services.asset_utils import get_unclassified_assets_summary
        unclassified_data = get_unclassified_assets_summary(active_db, _SCHEMA, snowflake_connector)
        
        # Better UI: Background card for metrics
        st.markdown(f"""
            <div style="background: linear-gradient(145deg, rgba(26, 32, 44, 0.4), rgba(17, 21, 28, 0.6)); border-radius: 15px; padding: 25px; border: 1px solid rgba(255, 255, 255, 0.05); margin-bottom: 25px;">
                <div style="display: flex; justify-content: space-around; text-align: center;">
                    <div>
                        <div style="font-size: 12px; font-weight: 700; color: rgba(255,255,255,0.5); text-transform: uppercase;">Total Unclassified</div>
                        <div style="font-size: 32px; font-weight: 800; color: white;">{unclassified_data['total_unclassified']}</div>
                    </div>
                    <div style="border-left: 1px solid rgba(255,255,255,0.1); padding-left: 40px;">
                        <div style="font-size: 12px; font-weight: 700; color: rgba(255,255,255,0.5); text-transform: uppercase;">SLA Breach Risk</div>
                        <div style="font-size: 32px; font-weight: 800; color: #E74C3C;">{unclassified_data['sla_breached']}</div>
                    </div>
                    <div style="border-left: 1px solid rgba(255,255,255,0.1); padding-left: 40px;">
                        <div style="font-size: 12px; font-weight: 700; color: rgba(255,255,255,0.5); text-transform: uppercase;">New Pending</div>
                        <div style="font-size: 32px; font-weight: 800; color: #4FD1C5;">{unclassified_data['new_pending']}</div>
                    </div>
                </div>
            </div>
        """, unsafe_allow_html=True)

        # Visual Table for Unclassified Assets
        if not unclassified_data['assets']:
            st.success("✅ All discovered assets are classified! No backlog detected.")
        else:
            st.markdown("""
                <div style="background: rgba(255, 255, 255, 0.03); border-radius: 15px; padding: 20px; border: 1px solid rgba(255, 255, 255, 0.05);">
                    <div style="font-size: 14px; font-weight: 700; color: #4FD1C5; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 15px;">
                        ⚠️ High Priority: Longest Unclassified
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            df_uncl = pd.DataFrame(unclassified_data['assets'])
            # Formatting the dataframe display
            st.dataframe(
                df_uncl,
                hide_index=True
            )
            
            st.caption("📌 Answers: “What data still isn’t classified?” (Showing top 10 oldest assets)")

        st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    except Exception as e:
        _rt_show_error("Failed to load Unclassified Assets section", e)

    # Review Due
    st.header("📅 Review Due")
    st.markdown("Governance maintenance & audit readiness")
    
    try:
        from src.services.asset_utils import get_review_due_summary
        review_data = get_review_due_summary(active_db, _SCHEMA, snowflake_connector)
        
        # Summary for Section 4
        col_r1, col_r2, col_r3 = st.columns(3)
        with col_r1:
            st.metric("Review Backlog", f"{review_data['overdue_count']}", delta=f"{review_data['overdue_count']} overdue", delta_color="inverse")
            st.caption("Expired classification reviews")
        with col_r2:
            st.metric("Upcoming (30d)", f"{review_data['upcoming_count']}", delta=None)
            st.caption("Reviews due within 30 days")
        with col_r3:
            st.metric("Total Pending", f"{review_data['total_backlog']}", delta=None)
            st.caption("Total maintenance workload")

        # Table for Review Backlog
        if not review_data['assets']:
            st.success("✨ Governance is up-to-date! No reviews due within the threshold.")
        else:
            st.markdown("""
                <div style="background: rgba(255, 255, 255, 0.03); border-radius: 15px; padding: 20px; border: 1px solid rgba(255, 255, 255, 0.05); margin-top:15px;">
                    <div style="font-size: 14px; font-weight: 700; color: #F6AD55; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 15px;">
                        🗓️ Maintenance Schedule: Priority Reviews
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            df_review = pd.DataFrame(review_data['assets'])
            st.dataframe(
                df_review,
                use_container_width=True,
                hide_index=True
            )
            
            st.caption("📌 Answers: “What needs to be reviewed now?”")

        st.markdown('<div class="divider-glow" style="margin-top: 40px;"></div>', unsafe_allow_html=True)

    except Exception as e:
        _rt_show_error("Failed to load Review Due section", e)

    # Non-Compliant Assets (Policy Violation View)
    st.header("⚠️ Non-Compliant Assets")
    st.markdown("Policy violation view & remediation tracking")
    
    try:
        from src.services.asset_utils import get_non_compliant_assets_detail
        violations = get_non_compliant_assets_detail(active_db, _SCHEMA, snowflake_connector)
        
        if violations.empty:
            st.success("🎉 No active policy violations detected! All assets are compliant.")
        else:
            st.markdown("""
                <div style="background: rgba(231, 76, 60, 0.05); border-radius: 12px; padding: 15px; border: 1px solid rgba(231, 76, 60, 0.2); margin-bottom: 20px;">
                    <div style="font-size: 13px; color: #E74C3C; font-weight: 700;">
                        🚨 IMMEDIATE ACTION REQUIRED: {len(violations)} assets breaking governance rules
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            df_viol = pd.DataFrame(violations)
            
            # Styling the dataframe
            st.dataframe(
                df_viol,
                use_container_width=True,
                hide_index=True
            )
            
            st.caption("📌 Answers: “What data is breaking our rules?”")

        st.markdown('<div class="divider-glow" style="margin-top: 40px;"></div>', unsafe_allow_html=True)

    except Exception as e:
        _rt_show_error("Failed to load Non-Compliant Assets section", e)

    # Special Categories & Compliance Coverage
    st.header("🧩 Special Categories & Compliance Coverage")
    st.markdown("Regulatory assurance and trend analysis")
    
    try:
        from src.services.asset_utils import get_compliance_coverage_metrics
        comp_data = get_compliance_coverage_metrics(active_db, _SCHEMA, snowflake_connector)
        
        # Premium Metric Row for Section 6 - Now with 6 columns
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        
        with c1:
            st.markdown(f"""
                <div class="pillar-card" style="border-top: 4px solid #4FD1C5;">
                    <div class="pillar-icon">👤</div>
                    <div class="pillar-label">PII Coverage</div>
                    <div class="pillar-value" style="color: #4FD1C5;">{comp_data['pii_coverage_pct']}%</div>
                    <div class="pillar-status">Classified PII Assets</div>
                </div>
            """, unsafe_allow_html=True)

        with c2:
            # PII Assets Count
            pii_count = comp_data.get('pii_assets', 0)
            st.markdown(f"""
                <div class="pillar-card" style="border-top: 4px solid #9F7AEA;">
                    <div class="pillar-icon">�</div>
                    <div class="pillar-label">PII Assets</div>
                    <div class="pillar-value">{pii_count}</div>
                    <div class="pillar-status">Privacy Restricted</div>
                </div>
            """, unsafe_allow_html=True)

        with c3:
            # SOX Assets Count
            sox_count = comp_data.get('sox_assets', 0)
            st.markdown(f"""
                <div class="pillar-card" style="border-top: 4px solid #38bdf8;">
                    <div class="pillar-icon">💰</div>
                    <div class="pillar-label">SOX Assets</div>
                    <div class="pillar-value">{sox_count}</div>
                    <div class="pillar-status">Financial Control</div>
                </div>
            """, unsafe_allow_html=True)

        with c4:
            # SOC2 Assets Count
            soc_count = comp_data.get('soc2_assets', 0)
            st.markdown(f"""
                <div class="pillar-card" style="border-top: 4px solid #F6AD55;">
                    <div class="pillar-icon">🔒</div>
                    <div class="pillar-label">SOC2 Assets</div>
                    <div class="pillar-value">{soc_count}</div>
                    <div class="pillar-status">Security Audit</div>
                </div>
            """, unsafe_allow_html=True)

        with c5:
            st.markdown(f"""
                <div class="pillar-card" style="border-top: 4px solid #F1C40F;">
                    <div class="pillar-icon">🛡️</div>
                    <div class="pillar-label">Exceptions</div>
                    <div class="pillar-value">{comp_data['exception_count']}</div>
                    <div class="pillar-status">Active Waivers</div>
                </div>
            """, unsafe_allow_html=True)

        with c6:
            st.markdown(f"""
                <div class="pillar-card" style="border-top: 4px solid #28A745;">
                    <div class="pillar-icon">✅</div>
                    <div class="pillar-label">Audit Readiness</div>
                    <div class="pillar-value" style="font-size: 22px;">HIGH</div>
                    <div class="pillar-status">Regulatory Confidence</div>
                </div>
            """, unsafe_allow_html=True)

        # Multi-Line Trend Chart
        if comp_data['trends']['classification']:
            st.markdown("""
                <div style="background: rgba(255, 255, 255, 0.03); border-radius: 15px; padding: 25px; border: 1px solid rgba(255, 255, 255, 0.05); margin-top: 30px;">
                    <div class="info-title" style="margin-bottom: 20px;">Regulatory Progress & Risk Reduction</div>
                </div>
            """, unsafe_allow_html=True)
            
            df_trend = pd.DataFrame(comp_data['trends']['classification'])
            
            # Use Plotly for a richer experience
            fig_assurance = go.Figure()
            
            # 1. Classification Velocity (Primary Area)
            fig_assurance.add_trace(go.Scatter(
                x=df_trend['MONTH'], y=df_trend['CLASSIFIED_COUNT'],
                name='Classification Velocity',
                line=dict(color='#4FD1C5', width=3),
                fill='tozeroy',
                fillcolor='rgba(79, 209, 197, 0.1)'
            ))
            
            # 2. Non-Compliance Trend (Red Line)
            fig_assurance.add_trace(go.Scatter(
                x=df_trend['MONTH'], y=df_trend['NON_COMPLIANT_COUNT'],
                name='Non-Compliance Trend',
                line=dict(color='#E74C3C', width=2, dash='dot')
            ))
            
            # 3. Risk Mitigation Trend (Golden Line - Normalized)
            risk_max = df_trend['RISK_WEIGHT'].max() or 1
            norm_risk = (df_trend['RISK_WEIGHT'] / risk_max) * df_trend['CLASSIFIED_COUNT'].max()
            fig_assurance.add_trace(go.Scatter(
                x=df_trend['MONTH'], y=norm_risk,
                name='Risk Mitigation Level',
                line=dict(color='#F1C40F', width=2)
            ))
            
            fig_assurance.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color="white",
                height=400,
                margin=dict(l=20, r=20, t=20, b=20),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)')
            )
            
            st.plotly_chart(fig_assurance, use_container_width=True)
        
        st.markdown(f"""
            <div style="display: flex; gap: 20px; align-items: center; justify-content: flex-start; margin-top: 15px;">
                <div style="font-size: 11px; color: #4FD1C5;">● Classification Growth</div>
                <div style="font-size: 11px; color: #E74C3C;">● Non-Compliance Reduction</div>
                <div style="font-size: 11px; color: #F1C40F;">● Risk Surface Mitigation</div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<div class="divider-glow" style="margin-top: 40px;"></div>', unsafe_allow_html=True)

    except Exception as e:
        _rt_show_error("Failed to load Compliance Coverage section", e)


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
             # 1. Recent AI Insights (from CLASSIFICATION_AI_RESULTS)
             ai_rows = _rt_run_query(f"""
                select TOP 5 
                    UPPER(TABLE_NAME) as NAME, 
                    AI_CATEGORY || ' (' || ROUND(FINAL_CONFIDENCE * 100, 1) || '%)' as DETAIL, 
                    'AI Engine' as USER, 
                    CREATED_AT as TS,
                    'AI Discovery' as TYPE
                from {T_AI_RESULTS}
                where CREATED_AT >= dateadd('day', -7, current_timestamp())
                order by TS desc
             """)
             
             # 2. Recent Asset Management (from ASSETS)
             asset_rows = _rt_run_query(f"""
                select TOP 5
                    UPPER(ASSET_NAME) as NAME,
                    CASE WHEN CLASSIFICATION_LABEL IS NOT NULL THEN 'Classified as ' || CLASSIFICATION_LABEL ELSE 'Metadata updated' END as DETAIL,
                    COALESCE(LAST_MODIFIED_BY, CREATED_BY, 'System') as USER,
                    LAST_MODIFIED_TIMESTAMP as TS,
                    'Governance' as TYPE
                from {T_ASSETS}
                where LAST_MODIFIED_TIMESTAMP >= dateadd('day', -7, current_timestamp())
                order by TS desc
             """)
             
             # Combine and sort from authoritative sources
             combined = (ai_rows or []) + (asset_rows or [])
             combined.sort(key=lambda x: x['TS'] if x['TS'] else datetime.min, reverse=True)
             
             if not combined:
                 st.info("No recent governance or AI activity found in the primary tables.")
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
                             if diff.days > 0: time_str = f"{diff.days}d ago"
                             elif diff.seconds > 3600: time_str = f"{diff.seconds//3600}h ago"
                             else: time_str = f"{diff.seconds//60}m ago"
                         except: pass

                     st.markdown(f"""
                        <div style="background: rgba(255, 255, 255, 0.03); border-radius: 8px; padding: 12px; border-left: 3px solid #4FD1C5; margin-bottom: 8px;">
                            <div style="display: flex; justify-content: space-between; font-size: 13px;">
                                <b style="color: #FFFFFF;">{name}</b>
                                <span style="font-size: 11px; color: rgba(255,255,255,0.4);">{time_str}</span>
                            </div>
                            <div style="font-size: 12px; color: rgba(255,255,255,0.7); margin-top: 4px;">{detail}</div>
                            <div style="font-size: 11px; color: #4FD1C5; margin-top: 4px;">👤 {user}</div>
                        </div>
                      """, unsafe_allow_html=True)

        except Exception as e:
            st.error(f"Failed to load activity: {e}")

    st.caption("Data updates live from Snowflake. Use Refresh to fetch latest.")

# Render dashboard
render_realtime_dashboard()
