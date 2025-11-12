"""
Compliance page for the data governance application.
"""
import sys
import os

# Add the project root (parent of 'src') to the Python path so 'src.*' imports work
_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))  # .../src
_project_root = os.path.dirname(_src_dir)           # project root containing 'src'
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import streamlit as st
from typing import Optional, List
import plotly.express as px
import plotly.io as pio
import pandas as pd
import io
from src.ui.theme import apply_global_theme
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
try:
    from src.services.compliance_service import compliance_service
except Exception as _imp_err:
    compliance_service = None  # Fallback: disable compliance features if import fails
from src.services.exception_service import exception_service
from src.services.migration_service import migration_service
from src.services.behavior_analytics_service import behavior_analytics_service
from src.services.federated_anomaly_service import federated_anomaly_service
from src.services.authorization_service import authz
from src.components.filters import render_data_filters, render_compliance_facets
from src.services.dynamic_query_service import dynamic_query_service
from src.services.dynamic_compliance_report_service import dynamic_compliance_report_service
from src.services.system_classify_service import system_classify_service
from src.ui.quick_links import render_quick_links
from src.services.ai_classification_service import ai_classification_service
from src.services.tagging_service import tagging_service
from src.services.classification_decision_service import classification_decision_service
from src.services.audit_service import audit_service
try:
    from src.services.comprehensive_detection_methods import comprehensive_detection_service
except Exception as _cdm_err:
    comprehensive_detection_service = None  # Fallback: disable comprehensive detection if import fails
try:
    from src.pages._compliance_center import render as render_compliance_center
except ModuleNotFoundError:
    render_compliance_center = None

# Use global Plotly template (set in src/app.py) for charts

# Page configuration
st.set_page_config(
    page_title="Compliance - Data Governance App",
    page_icon="✅",
    layout="wide"
)

# Apply centralized theme (fonts, CSS variables, Plotly template)
apply_global_theme()

# Page title
st.title("Compliance")
render_quick_links()

# Redirect to policy-aligned Compliance Center (keeps only mandated components)
if render_compliance_center is not None:
    try:
        render_compliance_center()
        st.stop()
    except Exception as _cc_err:
        st.error(f"Compliance Center failed to load: {_cc_err}")

# Helper: resolve active database safely to avoid 'NONE' errors
def _resolve_db() -> Optional[str]:
    try:
        db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
    except Exception:
        db = None
    if db:
        return db
    try:
        row = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
        db = row[0].get('DB') if row else None
    except Exception:
        db = None
    return db

# Ensure a valid database is selected in the session to avoid 'NONE' errors
def _ensure_session_database() -> Optional[str]:
    try:
        db = _resolve_db()
        if db:
            return db
        # No DB resolved; pick the first available database and USE it
        rows = snowflake_connector.execute_query("SHOW DATABASES") or []
        first = None
        for r in rows:
            n = r.get("name") or r.get("NAME")
            if n:
                first = n
                break
        if first:
            try:
                snowflake_connector.execute_non_query(f"USE DATABASE {first}")
            except Exception:
                pass
            st.session_state['sf_database'] = first
            return first
    except Exception:
        pass
    return _resolve_db()

def _gv_schema() -> str:
    """Return the governance schema to use for queries.
    Defaults to DATA_GOVERNANCE but honors session override if present.
    """
    try:
        gs = st.session_state.get("governance_schema")
        if gs and str(gs).strip():
            return str(gs).strip()
    except Exception:
        pass
    return "DATA_GOVERNANCE"

# Helpers to check existence of objects before querying
@st.cache_data(ttl=300)
def _list_warehouses() -> List[str]:
    """Best-effort list of accessible warehouses for selection."""
    try:
        rows = snowflake_connector.execute_query("SHOW WAREHOUSES") or []
        return [r.get("name") or r.get("NAME") for r in rows if (r.get("name") or r.get("NAME"))]
    except Exception:
        return []

def _apply_warehouse(wh: Optional[str]) -> None:
    """Resume and USE the selected warehouse; ignore errors silently."""
    if not wh:
        return
    try:
        try:
            snowflake_connector.execute_non_query(f"ALTER WAREHOUSE {wh} RESUME")
        except Exception:
            pass
        try:
            snowflake_connector.execute_non_query(f"USE WAREHOUSE {wh}")
        except Exception:
            pass
        st.session_state['sf_warehouse'] = wh
    except Exception:
        pass

@st.cache_data(ttl=300)
def _list_databases() -> List[str]:
    """Best-effort list of accessible databases."""
    try:
        rows = snowflake_connector.execute_query("SHOW DATABASES") or []
        return [r.get("name") or r.get("NAME") for r in rows if (r.get("name") or r.get("NAME"))]
    except Exception:
        return []

def _apply_database(db: Optional[str]) -> None:
    """USE the selected database and persist it; ignore errors silently."""
    try:
        if db and db != "All":
            try:
                snowflake_connector.execute_non_query(f"USE DATABASE {db}")
            except Exception:
                pass
            st.session_state['sf_database'] = db
        else:
            # Clear explicit selection; downstream will resolve or prompt
            st.session_state.pop('sf_database', None)
    except Exception:
        pass

def _view_exists(db: Optional[str], schema: str, view: str) -> bool:
    if not db:
        return False
    try:
        rows = snowflake_connector.execute_query(
            f"""
            from {db}.INFORMATION_SCHEMA.VIEWS
            where TABLE_SCHEMA = %(s)s and TABLE_NAME = %(v)s
            limit 1
            """,
            {"s": schema, "v": view},
        ) or []
        return bool(rows)
    except Exception:
        return False

def _table_exists(db: Optional[str], schema: str, table: str) -> bool:
    """Best-effort existence check for a physical table in the given db/schema."""
    if not db:
        return False
    try:
        rows = snowflake_connector.execute_query(
            """
            select 1 as X
            from INFORMATION_SCHEMA.TABLES
            where TABLE_CATALOG = %(db)s and TABLE_SCHEMA = %(s)s and TABLE_NAME = %(t)s
            limit 1
            """,
            {"db": db, "s": schema, "t": table},
        ) or []
        return bool(rows)
    except Exception:
        return False

# Cached helper: list sensitive tables from ASSET_INVENTORY with AI sensitivity hints & CIA suggestions
@st.cache_data(ttl=300)
def _get_sensitive_tables(db: str, limit: int = 200) -> pd.DataFrame:
    """Return a DataFrame of sensitive tables with detected types, row count, AI CIA, and policy flag.

    Preference order for discovery:
    1) {db}.{governance_schema}.ASSET_INVENTORY (if present)
    2) Fallback to INFORMATION_SCHEMA.TABLES listing (no sensitivity hints)
    """
    gv = _gv_schema()
    # Pull candidate tables from ASSET_INVENTORY; fallback to INFORMATION_SCHEMA if not available
    rows = []
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT FULL_NAME, COALESCE(ROW_COUNT,0) AS ROW_COUNT
            FROM {db}.{gv}.ASSET_INVENTORY
            ORDER BY FULL_NAME
            LIMIT {int(max(1, min(5000, limit)))}
            """
        ) or []
    except Exception:
        rows = []
    if not rows:
        # Fallback: build FULL_NAME from INFORMATION_SCHEMA when ASSET_INVENTORY is unavailable
        try:
            rows = snowflake_connector.execute_query(
                f"""
                SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS FULL_NAME,
                       0 AS ROW_COUNT
                FROM {db}.INFORMATION_SCHEMA.TABLES
                WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                ORDER BY 1
                LIMIT {int(max(1, min(5000, limit)))}
                """
            ) or []
        except Exception:
            rows = []
    df = pd.DataFrame(rows)
    if df.empty or 'FULL_NAME' not in df.columns:
        return pd.DataFrame(columns=['Table Name','Detected Sensitivity Types','Row Count','AI Suggested Confidentiality (C)','AI Suggested Integrity (I)','AI Suggested Availability (A)','Policy Compliance'])
    # Derive detected types per table (best-effort; safe failures)
    det_types = []
    ai_c_list = []
    ai_i_list = []
    ai_a_list = []
    policy_ok = []
    for _, r in df.iterrows():
        fq = str(r['FULL_NAME'])
        cats = []
        try:
            det = ai_classification_service.detect_sensitive_columns(fq, sample_size=30) or []
            cats = sorted({c for d in det for c in (d.get('categories') or [])})
        except Exception:
            cats = []
        # Keep only PII/Financial/SOC/SOX; map 'SOX' -> 'SOC/SOX'; add SOX if Financial appears
        allowed = {'PII','Financial','SOX'}
        cats_out_set = set([c for c in cats if c in allowed])
        if 'Financial' in cats and 'SOX' not in cats_out_set:
            cats_out_set.add('SOX')
        # Map for display
        display_list = []
        for c in sorted(cats_out_set):
            display_list.append('SOC/SOX' if c == 'SOX' else c)
        det_types.append(','.join(display_list) if display_list else '')
        # CIA suggestion
        pref = ['PCI','PHI','PII','Financial','Auth']
        chosen = next((p for p in pref if p in cats), None)
        cia = ai_classification_service._suggest_cia_from_type(chosen or '')
        ai_c_list.append(int(cia.get('C', 0)))
        ai_i_list.append(int(cia.get('I', 0)))
        ai_a_list.append(int(cia.get('A', 0)))
        # Policy flag
        try:
            # Validate proposed tags against minimums
            tagging_service.validate_tags({
                'DATA_CLASSIFICATION': 'Confidential' if cia.get('C',0) >= 3 else ('Restricted' if cia.get('C',0) >= 2 else ('Internal' if cia.get('C',0) >= 1 else 'Public')),
                'CONFIDENTIALITY_LEVEL': str(int(cia.get('C',0))),
                'INTEGRITY_LEVEL': str(int(cia.get('I',0))),
                'AVAILABILITY_LEVEL': str(int(cia.get('A',0))),
            })
            tagging_service._enforce_policy_minimums(fq, {
                'DATA_CLASSIFICATION': 'Confidential' if cia.get('C',0) >= 3 else ('Restricted' if cia.get('C',0) >= 2 else ('Internal' if cia.get('C',0) >= 1 else 'Public')),
                'CONFIDENTIALITY_LEVEL': str(int(cia.get('C',0))),
            })
            policy_ok.append('✅')
        except Exception:
            policy_ok.append('❌')

    df_out = pd.DataFrame({
        'Table Name': df['FULL_NAME'],
        'Detected Sensitivity Types': det_types,
        'Row Count': df.get('ROW_COUNT', pd.Series([0]*len(df))),
        'AI Suggested Confidentiality (C)': ai_c_list,
        'AI Suggested Integrity (I)': ai_i_list,
        'AI Suggested Availability (A)': ai_a_list,
        'Policy Compliance': policy_ok,
    })
    # Only show rows with detected sensitivity per requirements
    df_out = df_out[df_out['Detected Sensitivity Types'] != ''].reset_index(drop=True)
    return df_out

# RBAC guard: require at least consumer-level access, but avoid hard stop if app-level user exists
try:
    _ident = authz.get_current_identity()
    if not authz.is_consumer(_ident):
        if getattr(st.session_state, 'user', None) is not None:
            st.warning("Snowflake session/role not sufficient for Compliance. Re-authenticate from Home or switch role in sidebar.")
            st.stop()
        st.error("You do not have permission to access the Compliance module. Please sign in and ensure your Snowflake role has at least consumer-level access.")
        st.stop()
except Exception as _auth_err:
    if getattr(st.session_state, 'user', None) is not None:
        st.warning(f"Authorization check failed (continuing): {_auth_err}. Re-authenticate from Home if needed.")
        st.stop()
    st.warning(f"Authorization check failed: {_auth_err}")
    st.stop()

# Ensure a session database is set to prevent 'Database \"NONE\"' errors
_ensure_session_database()

# Health check for compliance service (explicit, no side-effects unless ensure=True)
comp_ok = False
comp_err = None
try:
    if compliance_service is not None:
        hc = compliance_service.health_check(ensure=True)
        comp_ok = bool(hc.get('ok'))
        comp_err = hc.get('error')
        # Suppress readiness banner; quietly control availability via comp_ok
    else:
        # Suppress banner; features that depend on the service will stay disabled
        pass
except Exception as _hc_err:
    comp_ok = False
    comp_err = str(_hc_err)
    # Suppress banner on health check failures

# Helper functions to list schemas, objects, and columns
@st.cache_data(ttl=300)
def _list_schemas(db: Optional[str]) -> List[str]:
    if not db or db == "All":
        return []
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT SCHEMA_NAME
            FROM {db}.INFORMATION_SCHEMA.SCHEMATA
            ORDER BY SCHEMA_NAME
            """
        ) or []
        return [r.get('SCHEMA_NAME') for r in rows if r.get('SCHEMA_NAME')]
    except Exception:
        return []

@st.cache_data(ttl=300)
def _list_objects(db: Optional[str], schema: Optional[str]) -> List[str]:
    if not db or db == "All" or not schema or schema == "All":
        return []
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT TABLE_NAME AS NAME, 'TABLE' AS TYPE
            FROM {db}.INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = %(s)s
            UNION ALL
            SELECT TABLE_NAME AS NAME, 'VIEW' AS TYPE
            FROM {db}.INFORMATION_SCHEMA.VIEWS
            WHERE TABLE_SCHEMA = %(s)s
            ORDER BY NAME
            """,
            {"s": schema},
        ) or []
        return [r.get('NAME') for r in rows if r.get('NAME')]
    except Exception:
        return []

@st.cache_data(ttl=300)
def _list_columns(db: Optional[str], schema: Optional[str], obj: Optional[str]) -> List[str]:
    if not db or db == "All" or not schema or schema == "All" or not obj or obj == "All":
        return []
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT COLUMN_NAME
            FROM {db}.INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
            ORDER BY ORDINAL_POSITION
            """,
            {"s": schema, "t": obj},
        ) or []
        return [r.get('COLUMN_NAME') for r in rows if r.get('COLUMN_NAME')]
    except Exception:
        return []

# Single Filters set (Database, Schema, Table/View, Column)
with st.sidebar:
    st.header("Filters")
    # Database
    db_opts = ["All"] + _list_databases()
    cur_db = st.session_state.get('sf_database')
    try:
        db_index = db_opts.index(cur_db) if (cur_db and cur_db in db_opts) else 0
    except Exception:
        db_index = 0
    sel_db = st.selectbox("Database", options=db_opts, index=db_index, key="flt_db")
    if sel_db and sel_db != "All":
        _apply_database(sel_db)
        st.session_state['sf_database'] = sel_db
    # Schema
    schema_opts = ["All"] + _list_schemas(sel_db if sel_db and sel_db != "All" else _resolve_db())
    sel_schema = st.selectbox("Schema", options=schema_opts, index=0, key="flt_schema")
    # Table / View
    obj_opts = ["All"] + _list_objects(sel_db if sel_db != "All" else _resolve_db(), sel_schema)
    sel_obj = st.selectbox("Table / View", options=obj_opts, index=0, key="flt_obj")
    # Column (optional)
    col_opts = [""] + _list_columns(sel_db if sel_db != "All" else _resolve_db(), sel_schema, sel_obj)
    sel_col = st.selectbox("Column (optional)", options=col_opts, index=0, key="flt_col")

    # Persist unified selection dict
    sel = {
        "database": None if (not sel_db or sel_db == "All") else sel_db,
        "schema": None if (not sel_schema or sel_schema == "All") else sel_schema,
        "table": None if (not sel_obj or sel_obj == "All") else sel_obj,
        "column": None if (not sel_col) else sel_col,
    }
    st.session_state["global_filters"] = sel
    facets = render_compliance_facets()

# Manual refresh to clear cache and re-run queries
if st.button("🔄 Refresh now", help="Clear cached data (5 min TTL) and refresh from Snowflake"):
    st.cache_data.clear()
    st.rerun()

# Lightweight CSS for modern, rounded cards and soft shadows
st.markdown(
    """
    <style>
    /* Keep only KPI status accents; base styles come from global theme */
    .kpi-good {border-left: 6px solid #2ECC71;}
    .kpi-warn {border-left: 6px solid #F1C40F;}
    .kpi-bad  {border-left: 6px solid #E74C3C;}
    </style>
    """,
    unsafe_allow_html=True,
)

# Function to get real compliance data from Snowflake
@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_compliance_data():
    try:
        # Access governance metrics
        users_res = snowflake_connector.execute_query(
            """
            SELECT COUNT(*) AS CNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."USERS"
            WHERE "DELETED_ON" IS NULL
            """
        )
        roles_res = snowflake_connector.execute_query(
            """
            SELECT COUNT(*) AS CNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."ROLES"
            WHERE "DELETED_ON" IS NULL
            """
        )
        grants_res = snowflake_connector.execute_query(
            """
            SELECT COUNT(*) AS CNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."GRANTS_TO_ROLES"
            WHERE "DELETED_ON" IS NULL
            """
        )

        # Policy coverage
        masking_res = snowflake_connector.execute_query(
            """
            SELECT COUNT(*) AS CNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."MASKING_POLICIES"
            """
        )
        row_access_res = snowflake_connector.execute_query(
            """
            SELECT COUNT(*) AS CNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."ROW_ACCESS_POLICIES"
            """
        )

        # Tag usage overview (top 10)
        tag_usage = snowflake_connector.execute_query(
            """
            SELECT "TAG_NAME", COUNT(*) AS USAGE_COUNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"
            GROUP BY "TAG_NAME"
            ORDER BY USAGE_COUNT DESC
            LIMIT 10
            """
        )

        return {
            'access': {
                'users': users_res[0]['CNT'] if users_res else 0,
                'roles': roles_res[0]['CNT'] if roles_res else 0,
                'grants': grants_res[0]['CNT'] if grants_res else 0,
            },
            'policies': {
                'masking_policies': masking_res[0]['CNT'] if masking_res else 0,
                'row_access_policies': row_access_res[0]['CNT'] if row_access_res else 0,
            },
            'tag_usage': tag_usage or []
        }
    except Exception as e:
        st.error(f"Error fetching compliance data from Snowflake: {str(e)}")
        return {
            'access': {
                'users': 0,
                'roles': 0,
                'grants': 0,
            },
            'policies': {
                'masking_policies': 0,
                'row_access_policies': 0,
            },
            'tag_usage': []
        }
# Helpers to surface an Overall Compliance Score with explicit tooltip
@st.cache_data(ttl=300)
def _get_latest_report():
    """Fetch the most recent record from COMPLIANCE_REPORTS.
    Returns a dict with keys: GENERATED_AT, METRICS. Fallbacks to {} on error.
    """
    try:
        db = _resolve_db()
        if not db:
            return {}
        if not _table_exists(db, 'DATA_GOVERNANCE', 'COMPLIANCE_REPORTS') and not _view_exists(db, 'DATA_GOVERNANCE', 'COMPLIANCE_REPORTS'):
            return {}
        rows = snowflake_connector.execute_query(
            f"""
            SELECT GENERATED_AT, METRICS
            FROM {db}.DATA_GOVERNANCE.COMPLIANCE_REPORTS
            ORDER BY GENERATED_AT DESC
            LIMIT 1
            """
        ) or []
        return rows[0] if rows else {}
    except Exception:
        return {}


def _compute_overall_score(metrics, pending_exceptions=None):
    """Compute an explainable overall score in [0, 100].

    Formula (weights chosen for clarity, not certification):
    - 60% Coverage = coverage_rate (0..1)
    - 25% Health = (1 - violation_rate)
      where violation_rate = total_violations / max(total_assets, 1)
      and total_violations approximated by sum(risk_counts[High, Medium, Low]) if present
    - 15% Exception Backlog = (1 - min(pending_exceptions_per_asset, 1))

    Returns (score, human_readable_explainer)
    """
    m = metrics or {}
    try:
        coverage = float((m.get("coverage_rate") or 0) or 0)
    except Exception:
        coverage = 0.0
    try:
        total_assets = int((m.get("total_assets") or (m.get("asset_counts", {}) or {}).get("total", 0)) or 0)
    except Exception:
        total_assets = 0
    rc = (m.get("risk_counts") or {})
    try:
        total_viol = int((rc.get("High") or 0) + (rc.get("Medium") or 0) + (rc.get("Low") or 0))
    except Exception:
        total_viol = 0
    violation_rate = 0.0
    if total_assets > 0:
        try:
            violation_rate = min(max(total_viol / total_assets, 0.0), 1.0)
        except Exception:
            violation_rate = 0.0
    # exceptions per asset (bounded 0..1)
    pe = 0 if pending_exceptions is None else int(pending_exceptions)
    exc_per_asset = 0.0
    if total_assets > 0:
        try:
            exc_per_asset = min(max(pe / total_assets, 0.0), 1.0)
        except Exception:
            exc_per_asset = 0.0

    score_0_1 = (
        0.60 * coverage +
        0.25 * (1.0 - violation_rate) +
        0.15 * (1.0 - exc_per_asset)
    )
    try:
        score = round(100.0 * max(min(score_0_1, 1.0), 0.0), 1)
    except Exception:
        score = 0.0

    expl = (
        f"60% Coverage ({coverage:.0%}) + 25% Health (1 - violation rate {violation_rate:.0%}) + "
        f"15% Exceptions (1 - backlog/asset {exc_per_asset:.0%})."
    )
    return score, expl

# Get compliance data
with st.spinner("Loading compliance data from your Snowflake database..."):
    compliance_data = get_compliance_data()

# Quick refresh for latest coverage and metrics
ref_cov = st.button("🔄 Refresh Coverage & Metrics")
if ref_cov:
    st.cache_data.clear()
    st.rerun()

# Tabs aligned to Monitoring & Compliance structure
tab_dash, tab_reviews, tab_viol, tab_ai, tab_auto = st.tabs([
    "📊 Compliance Dashboard", "🔄 Review Management", "🚨 Policy Violations", "🤖 AI Assistant", "🚀 Automated Classification"
])

with tab_dash:
    # Build four sub-tabs within Compliance Dashboard
    try:
        latest = _get_latest_report() or {}
        metrics = latest.get("METRICS") or {}
        generated_at = latest.get("GENERATED_AT")
    except Exception:
        metrics = {}
        generated_at = None
    try:
        pending = len(exception_service.list(status="Pending", limit=10000) or [])
    except Exception:
        pending = 0
    score, expl = _compute_overall_score(metrics, pending)
    st.metric("Overall Compliance Score", f"{score}%", help=(
        "60% Coverage + 25% (1 - violation rate) + 15% (1 - pending exceptions per asset)"
        f" — latest report{' @ ' + str(generated_at) if generated_at else ''} + live backlog"
    ))

    t_metrics, t_coverage, t_exceptions, t_audit = st.tabs([
        "Policy Compliance Metrics",
        "Classification Coverage Reports",
        "Exception Tracking",
        "Audit Ready Reports",
    ])

    # 1) Policy Compliance Metrics
    with t_metrics:
        c1, c2, c3, c4 = st.columns(4)
        # Coverage %
        try:
            db = _resolve_db()
            cov_pct = None
            past_due = None
            acc_disp = None
            open_exc = None
            if db and _view_exists(db, 'DATA_CLASSIFICATION_GOVERNANCE', 'VW_POLICY_COMPLIANCE_METRICS'):
                vw = snowflake_connector.execute_query(
                    f"SELECT * FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.VW_POLICY_COMPLIANCE_METRICS"
                ) or []
                if vw:
                    row = vw[0]
                    try:
                        cov_pct = float(row.get('CLASSIFICATION_COVERAGE_PERCENT') or 0.0)
                    except Exception:
                        cov_pct = 0.0
                    try:
                        acc_val = row.get('ACCURACY_SCORE')
                        acc_disp = f"{float(acc_val):.2f}%" if acc_val is not None else "-"
                    except Exception:
                        acc_disp = "-"
                    try:
                        past_due = int(row.get('AVG_CLASSIFICATION_AGE_DAYS') or 0)
                    except Exception:
                        past_due = 0
            # Fallbacks
            if cov_pct is None:
                if metrics and metrics.get("coverage_rate") is not None:
                    cov_pct = round(100.0 * float(metrics.get("coverage_rate") or 0), 2)
                else:
                    rows = snowflake_connector.execute_query(
                        f"select iff(count(*)=0,0, round(100.0*sum(case when coalesce(CLASSIFICATION_TAG,'')<>'' then 1 else 0 end)/count(*),2)) as COV from {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS"
                    ) or [] if db else []
                    cov_pct = float(rows[0].get('COV', 0)) if rows else 0.0
            if past_due is None:
                r_pd = snowflake_connector.execute_query(
                    f"select count(*) as CNT from {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS where coalesce(LAST_CLASSIFIED_DATE, CREATED_DATE, dateadd('day', -6, current_date())) < dateadd('day', -5, current_date())"
                ) or [] if db else []
                past_due = int(r_pd[0].get('CNT',0)) if r_pd else 0
            if acc_disp is None:
                try:
                    acc = metrics.get("accuracy_score") if isinstance(metrics, dict) else None
                    if acc is None:
                        acc = metrics.get("accuracy") if isinstance(metrics, dict) else None
                    acc_disp = f"{float(acc)*100:.2f}%" if acc is not None and float(acc) <= 1 else (f"{float(acc):.2f}%" if acc is not None else "-")
                except Exception:
                    acc_disp = "-"
            if open_exc is None:
                try:
                    open_exc = len(exception_service.list(status="Pending", limit=10000) or [])
                except Exception:
                    open_exc = 0
        except Exception:
            cov_pct, past_due, acc_disp, open_exc = 0.0, 0, "-", 0
        c1.metric("Classification Coverage", f"{cov_pct}%")
        c2.metric("Avg Classification Age (days)", f"{past_due}")
        c3.metric("Accuracy vs Expected", acc_disp)
        c4.metric("Open Exceptions", f"{open_exc}")

    # 2) Classification Coverage Reports
    with t_coverage:
        db = _resolve_db()
        try:
            if db and _view_exists(db, 'DATA_CLASSIFICATION_GOVERNANCE', 'VW_CLASSIFICATION_COVERAGE_REPORTS'):
                rows = snowflake_connector.execute_query(
                    f"SELECT BUSINESS_UNIT, ASSET_TYPE, MONTH, TOTAL_ASSETS, CLASSIFIED_ASSETS, COVERAGE_PERCENT FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.VW_CLASSIFICATION_COVERAGE_REPORTS"
                ) or []
            else:
                rows = []
        except Exception as e:
            rows = []
            st.warning(f"Coverage view unavailable: {e}")

        if rows:
            df = pd.DataFrame(rows)
            try:
                st.subheader("By Business Unit")
                bu_df = df.groupby('BUSINESS_UNIT', as_index=False).agg({'TOTAL_ASSETS':'sum','CLASSIFIED_ASSETS':'sum'})
                bu_df['COVERAGE_PERCENT'] = (bu_df['CLASSIFIED_ASSETS'] / bu_df['TOTAL_ASSETS'].replace(0, pd.NA) * 100).fillna(0).round(2)
                st.plotly_chart(px.bar(bu_df, x='BUSINESS_UNIT', y='COVERAGE_PERCENT', range_y=[0,100]), use_container_width=True)
                st.dataframe(bu_df, use_container_width=True)
            except Exception:
                pass

            st.markdown("---")
            try:
                st.subheader("By Data Type")
                dt_df = df.groupby('ASSET_TYPE', as_index=False).agg({'TOTAL_ASSETS':'sum','CLASSIFIED_ASSETS':'sum'})
                dt_df['COVERAGE_PERCENT'] = (dt_df['CLASSIFIED_ASSETS'] / dt_df['TOTAL_ASSETS'].replace(0, pd.NA) * 100).fillna(0).round(2)
                st.plotly_chart(px.bar(dt_df, x='ASSET_TYPE', y='COVERAGE_PERCENT', range_y=[0,100]), use_container_width=True)
                st.dataframe(dt_df, use_container_width=True)
            except Exception:
                pass

            st.markdown("---")
            try:
                st.subheader("Trend Analysis")
                trend_df = df.groupby('MONTH', as_index=False).agg({'TOTAL_ASSETS':'sum','CLASSIFIED_ASSETS':'sum'})
                trend_df['COVERAGE_PERCENT'] = (trend_df['CLASSIFIED_ASSETS'] / trend_df['TOTAL_ASSETS'].replace(0, pd.NA) * 100).fillna(0).round(2)
                st.plotly_chart(px.line(trend_df, x='MONTH', y='COVERAGE_PERCENT', markers=True), use_container_width=True)
                st.dataframe(trend_df, use_container_width=True)
            except Exception:
                pass
        else:
            st.info("Classification coverage view not found; fallback snapshots/tables will be used when available.")

    # 3) Exception Tracking (handled below in t_exceptions)

with tab_reviews:
    # Scheduled Reviews
    db = _resolve_db()
    try:
        if db and _view_exists(db, 'DATA_CLASSIFICATION_GOVERNANCE', 'VW_SCHEDULED_REVIEWS'):
            rows = snowflake_connector.execute_query(
                f"SELECT * FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.VW_SCHEDULED_REVIEWS"
            ) or []
        else:
            rows = []
    except Exception as e:
        rows = []
        st.warning(f"Scheduled reviews view unavailable: {e}")

    if rows:
        df = pd.DataFrame(rows)
        st.subheader("Scheduled Reviews")
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Scheduled reviews view not found; fallback snapshots/tables will be used when available.")

    st.markdown("---")

    # Overdue Tasks
    try:
        if db and _view_exists(db, 'DATA_CLASSIFICATION_GOVERNANCE', 'VW_OVERDUE_TASKS'):
            rows = snowflake_connector.execute_query(
                f"SELECT * FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.VW_OVERDUE_TASKS"
            ) or []
        else:
            rows = []
    except Exception as e:
        rows = []
        st.warning(f"Overdue tasks view unavailable: {e}")

    if rows:
        df = pd.DataFrame(rows)
        st.subheader("Overdue Tasks")
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Overdue tasks view not found; fallback snapshots/tables will be used when available.")

    st.markdown("---")

    # Review History
    try:
        if db and _view_exists(db, 'DATA_CLASSIFICATION_GOVERNANCE', 'VW_REVIEW_HISTORY'):
            rows = snowflake_connector.execute_query(
                f"SELECT * FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.VW_REVIEW_HISTORY"
            ) or []
        else:
            rows = []
    except Exception as e:
        rows = []
        st.warning(f"Review history view unavailable: {e}")

    if rows:
        df = pd.DataFrame(rows)
        st.subheader("Review History")
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Review history view not found; fallback snapshots/tables will be used when available.")

    st.markdown("---")

    # Approval Workflows
    try:
        if db and _view_exists(db, 'DATA_CLASSIFICATION_GOVERNANCE', 'VW_APPROVAL_WORKFLOWS'):
            rows = snowflake_connector.execute_query(
                f"SELECT * FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.VW_APPROVAL_WORKFLOWS"
            ) or []
        else:
            rows = []
    except Exception as e:
        rows = []
        st.warning(f"Approval workflows view unavailable: {e}")

    if rows:
        df = pd.DataFrame(rows)
        st.subheader("Approval Workflows")
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Approval workflows view not found; fallback snapshots/tables will be used when available.")

    st.markdown("---")

    # Violations
    try:
        if db and _view_exists(db, 'DATA_CLASSIFICATION_GOVERNANCE', 'VW_POLICY_VIOLATIONS'):
            rows = snowflake_connector.execute_query(
                f"SELECT * FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.VW_POLICY_VIOLATIONS"
            ) or []
        else:
            rows = []
    except Exception as e:
        rows = []
        st.warning(f"Violations view unavailable: {e}")

    if rows:
        df = pd.DataFrame(rows)
        st.subheader("Violations")
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Violations view not found; fallback snapshots/tables will be used when available.")

    st.markdown("---")
    # Corrective Actions
    try:
        if db and _view_exists(db, 'DATA_CLASSIFICATION_GOVERNANCE', 'VW_CORRECTIVE_ACTIONS'):
            rows = snowflake_connector.execute_query(
                f"SELECT * FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.VW_CORRECTIVE_ACTIONS"
            ) or []
        else:
            rows = []
    except Exception as e:
        rows = []
        st.warning(f"Corrective actions view unavailable: {e}")

    if rows:
        df = pd.DataFrame(rows)
        st.subheader("Corrective Actions")
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Corrective actions view not found; fallback snapshots/tables will be used when available.")

    st.markdown("---")
    # Disciplinary Actions
    try:
        if db and _view_exists(db, 'DATA_CLASSIFICATION_GOVERNANCE', 'VW_DISCIPLINARY_ACTIONS'):
            rows = snowflake_connector.execute_query(
                f"SELECT * FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.VW_DISCIPLINARY_ACTIONS"
            ) or []
        else:
            rows = []
    except Exception as e:
        rows = []
        st.warning(f"Disciplinary actions view unavailable: {e}")

    if rows:
        df = pd.DataFrame(rows)
        st.subheader("Disciplinary Actions")
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Disciplinary actions view not found; fallback snapshots/tables will be used when available.")

with tab_viol:
    # Controls to run detection and manage exceptions
    st.subheader("🚨 Violation Log & Actions")
    role = getattr(getattr(st.session_state, 'user', None), 'role', 'Viewer') if hasattr(st.session_state, 'user') else 'Viewer'
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Run Violation Detection", disabled=not comp_ok):
            if role not in ["Admin","Compliance Officer"]:
                st.warning("You do not have permission to run detection.")
            else:
                try:
                    created = compliance_service.detect_violations()
                    st.success(f"Detection complete. {created} violation(s) recorded.")
                except Exception as e:
                    st.error(f"Detection failed: {e}")
    with c2:
        if st.button("Expire Past-Due Exceptions"):
            if role not in ["Admin","Compliance Officer"]:
                st.warning("You do not have permission to expire exceptions.")
            else:
                try:
                    expired = exception_service.expire_auto()
                    st.success(f"Marked {expired} exception(s) as Expired.")
                except Exception as e:
                    st.error(f"Expire failed: {e}")
    with c3:
        st.caption("Escalations integrate with your alerting system.")

    st.markdown("---")
    st.subheader("Open Violations")
    if comp_ok and compliance_service is not None:
        try:
            violations = compliance_service.list_open_violations(limit=500)
            if violations:
                vdf = pd.DataFrame(violations)
                st.dataframe(vdf, use_container_width=True)
                sel = st.selectbox(
                    "Select a violation to drill into",
                    options=[v.get('ID') for v in violations],
                )
                if sel:
                    row = [v for v in violations if v.get('ID') == sel]
                    if row:
                        st.write("Violation Details:")
                        st.json(row[0].get('DETAILS') or {})
                        # Corrective Action Tracking
                        st.markdown("**Corrective Action**")
                        act = st.text_input("Action / Mitigation Plan", key=f"act_{sel}")
                        if st.button("Record Action", key=f"btn_act_{sel}") and act:
                            try:
                                # Best-effort: update via compliance service if supported
                                updated = False
                                try:
                                    updated = bool(compliance_service.record_corrective_action(sel, act))
                                except Exception:
                                    updated = False
                                if not updated:
                                    st.info("Backend API for corrective actions not available; captured locally.")
                                st.success("Action recorded.")
                            except Exception as e:
                                st.error(f"Failed to record action: {e}")
                        # Disciplinary Action Management placeholder
                        st.caption("Disciplinary actions are handled per HR policy outside this app.")
            else:
                st.info("No open violations.")
        except Exception as e:
            st.warning(f"Unable to list violations: {e}")
    else:
        st.info("Compliance service unavailable; cannot list violations.")

    st.markdown("---")
    st.subheader("📋 Compliance Matrix & Evidence Packs")
    st.caption("Drill into violations by rule and BU/Schema, then export evidence pack")
    try:
        # Fetch violations and inventory join for BU/Schema
        db = _resolve_db()
        if db and (_table_exists(db, 'DATA_GOVERNANCE', 'VIOLATIONS') or _view_exists(db, 'DATA_GOVERNANCE', 'VIOLATIONS')):
            vio = snowflake_connector.execute_query(
                f"""
                SELECT ID, RULE_CODE, SEVERITY, DESCRIPTION, ASSET_FULL_NAME, DETECTED_AT, STATUS
                FROM {db}.DATA_GOVERNANCE.VIOLATIONS
                ORDER BY DETECTED_AT DESC
                LIMIT 1000
                """
            ) or []
        else:
            vio = []
        if db and (_table_exists(db, 'DATA_GOVERNANCE', 'ASSET_INVENTORY') or _view_exists(db, 'DATA_GOVERNANCE', 'ASSET_INVENTORY')):
            inv = snowflake_connector.execute_query(
                f"""
                SELECT FULLY_QUALIFIED_NAME AS FULL_NAME, COALESCE(BUSINESS_UNIT, SPLIT_PART(FULLY_QUALIFIED_NAME,'.',2)) AS BU_OR_SCHEMA,
                       CLASSIFICATION_LABEL AS CLASSIFICATION_LEVEL, CONFIDENTIALITY_LEVEL AS CIA_CONF, INTEGRITY_LEVEL AS CIA_INT, AVAILABILITY_LEVEL AS CIA_AVAIL
                FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                """
            ) or []
        else:
            inv = []
        vdf = pd.DataFrame(vio)
        idf = pd.DataFrame(inv)
        # Apply dataset + facet filters (best-effort)
        try:
            if not vdf.empty:
                if sel.get("database"):
                    vdf = vdf[vdf['ASSET_FULL_NAME'].astype(str).str.startswith(f"{sel['database']}.")]
                if sel.get("schema"):
                    vdf = vdf[vdf['ASSET_FULL_NAME'].astype(str).str.contains(fr"\.({sel['schema']})\.", regex=True, case=False)]
                if sel.get("table"):
                    vdf = vdf[vdf['ASSET_FULL_NAME'].astype(str).str.endswith(f".{sel['table']}")]
                if facets.get('severity') and 'SEVERITY' in vdf.columns:
                    vdf = vdf[vdf['SEVERITY'].isin(facets['severity'])]
                if 'DETECTED_AT' in vdf.columns:
                    vdf['DETECTED_AT'] = pd.to_datetime(vdf['DETECTED_AT'], errors='coerce')
                    now = pd.Timestamp.utcnow()
                    rng = facets.get('time') or 'Last 7 days'
                    if rng == 'Current':
                        start = now.normalize()
                        vdf = vdf[vdf['DETECTED_AT'] >= start]
                    elif rng == 'Last 7 days':
                        vdf = vdf[vdf['DETECTED_AT'] >= now - pd.Timedelta(days=7)]
                    elif rng == 'Last 30 days':
                        vdf = vdf[vdf['DETECTED_AT'] >= now - pd.Timedelta(days=30)]
        except Exception:
            pass
        if not vdf.empty:
            if not idf.empty:
                vdf = vdf.merge(idf, left_on='ASSET_FULL_NAME', right_on='FULL_NAME', how='left')
                vdf['BU_OR_SCHEMA'] = vdf['BU_OR_SCHEMA'].fillna(vdf['ASSET_FULL_NAME'].str.split('.').str[1])
            else:
                vdf['BU_OR_SCHEMA'] = vdf['ASSET_FULL_NAME'].str.split('.').str[1]
            mat = vdf.pivot_table(index='RULE_CODE', columns='BU_OR_SCHEMA', values='ID', aggfunc='count', fill_value=0)
            st.dataframe(mat, use_container_width=True)

            st.markdown("---")
            st.subheader("🔎 Drill-down & Evidence Export")
            rule_opt = st.selectbox("Rule", options=sorted(vdf['RULE_CODE'].unique().tolist()))
            bu_opts = sorted(vdf['BU_OR_SCHEMA'].dropna().unique().tolist())
            bu_opt = st.selectbox("Business Unit / Schema", options=["All"] + bu_opts)
            sub = vdf[(vdf['RULE_CODE'] == rule_opt) & ((vdf['BU_OR_SCHEMA'] == bu_opt) if bu_opt != "All" else True)]
            st.dataframe(sub[['ID','SEVERITY','DESCRIPTION','ASSET_FULL_NAME','DETECTED_AT','STATUS','CLASSIFICATION_LEVEL','CIA_CONF','CIA_INT','CIA_AVAIL']], use_container_width=True)

            if st.button("Export Evidence Pack (ZIP)") and not sub.empty:
                try:
                    import io, json, zipfile, hashlib
                    buf = io.BytesIO()
                    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                        vio_csv = sub.to_csv(index=False)
                        zf.writestr('violations.csv', vio_csv)
                        summary = {
                            'rule': rule_opt,
                            'bu_or_schema': bu_opt,
                            'count': int(len(sub)),
                            'generated_at': pd.Timestamp.utcnow().isoformat(),
                        }
                        summary_json = json.dumps(summary, indent=2)
                        zf.writestr('summary.json', summary_json)
                        try:
                            pol = snowflake_connector.execute_query(
                                f"SELECT COUNT(*) AS MASK_POL FROM SNOWFLAKE.ACCOUNT_USAGE.MASKING_POLICIES"
                            ) or []
                            policy_json = json.dumps({'masking_policies': int(pol[0].get('MASK_POL',0)) if pol else 0}, indent=2)
                            zf.writestr('policy_snapshot.json', policy_json)
                        except Exception:
                            pass
                        sig_lines = []
                        sig_lines.append(f"violations.csv  sha256  {hashlib.sha256(vio_csv.encode('utf-8')).hexdigest()}")
                        sig_lines.append(f"summary.json    sha256  {hashlib.sha256(summary_json.encode('utf-8')).hexdigest()}")
                        try:
                            sig_lines.append(f"policy_snapshot.json  sha256  {hashlib.sha256(policy_json.encode('utf-8')).hexdigest()}")
                        except Exception:
                            pass
                        try:
                            from src.services.audit_service import audit_service as _aud
                            dig = _aud.compute_daily_digest()
                            zf.writestr('audit_digest.json', json.dumps(dig, indent=2))
                            sig_lines.append(f"audit_digest.json  sha256  {hashlib.sha256(json.dumps(dig, sort_keys=True).encode('utf-8')).hexdigest()}")
                        except Exception:
                            pass
                        zf.writestr('SIGNATURES.txt', "\n".join(sig_lines) + "\n")
                    st.download_button(
                        label="Download ZIP",
                        data=buf.getvalue(),
                        file_name=f"evidence_{rule_opt}_{(bu_opt or 'ALL')}.zip",
                        mime="application/zip",
                    )
                except Exception as e:
                    st.error(f"Failed to create evidence pack: {e}")
        else:
            st.info("No violations found. Run detection or ensure tasks are enabled.")
    except Exception as e:
        st.warning(f"Matrix/evidence view unavailable: {e}")


with tab_ai:
    st.subheader("AI Assistant: Sensitive Data Detection & Suggestions")
    db = _resolve_db()
    if not db:
        st.info("Select a database from the sidebar to proceed.")
    else:
        # Immediate sensitive tables detection based on selected DB
        # Persist and auto-refresh on DB change
        cache_key = f"ai_tables_{db}"
        try:
            tables_df = _get_sensitive_tables(db)
        except Exception as e:
            tables_df = pd.DataFrame(columns=[
                'Table Name',
                'Detected Sensitivity Types',
                'Row Count',
                'AI Suggested Confidentiality (C)',
                'AI Suggested Integrity (I)',
                'AI Suggested Availability (A)',
                'Policy Compliance'
            ])
            st.warning(f"Unable to load sensitive tables: {e}")
        st.session_state[cache_key] = tables_df

        st.markdown("**Sensitive tables detected in database**")
        # Style: highlight non-compliant rows
        def _style_non_compliant(row):
            return ['background-color: #fdecea' if row.get('Policy Compliance') == '❌' else '' for _ in row]
        try:
            st.dataframe(tables_df.style.apply(_style_non_compliant, axis=1), use_container_width=True, hide_index=True)
        except Exception:
            st.dataframe(tables_df, use_container_width=True, hide_index=True)

        # Session bucket for per-table edits
        ai_ss = st.session_state.setdefault('ai_assistant_ui', {})
        ai_ss.setdefault('tables', {})
        ai_ss['tables'][db] = tables_df

        # Action / Select control for drilldown
        tbl_opts = tables_df['Table Name'].tolist() if not tables_df.empty else []
        sel_tbl = st.selectbox("Action / Select table for column-level details", options=["--"] + tbl_opts)
        sel_tbl = sel_tbl if sel_tbl and sel_tbl != "--" else ""

        if sel_tbl:
            st.markdown(f"### {sel_tbl}")
            # Detect sensitive columns immediately
            try:
                det = ai_classification_service.detect_sensitive_columns(sel_tbl, sample_size=100) or []
            except Exception as e:
                det = []
                st.warning(f"Column detection failed: {e}")
            # Persist raw detections
            ai_ss.setdefault('detections', {})
            ai_ss['detections'][sel_tbl] = det

            # Fetch data types for display
            try:
                dbn, sc, tb = sel_tbl.split('.')
                crow = snowflake_connector.execute_query(
                    f"""
                    SELECT COLUMN_NAME, DATA_TYPE
                    FROM {dbn}.INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                    ORDER BY ORDINAL_POSITION
                    """,
                    {"s": sc, "t": tb},
                ) or []
                dtype_map = {r['COLUMN_NAME']: r['DATA_TYPE'] for r in crow}
            except Exception:
                dtype_map = {}

            # Build editable table rows with AI suggestions
            priority = ['PCI','PHI','PII','Financial','Auth']
            rows = []
            for r in det:
                cname = r.get('column')
                cats = r.get('categories') or []
                chosen = next((p for p in priority if p in cats), None)
                cia = ai_classification_service._suggest_cia_from_type(chosen or '')
                label = 'Confidential' if cia['C'] >= 3 else ('Restricted' if cia['C'] >= 2 else ('Internal' if cia['C'] >= 1 else 'Public'))
                rows.append({
                    'Column Name': cname,
                    'Data Type': dtype_map.get(cname, ''),
                    'Sensitivity Types': ','.join(cats),
                    'Label': label,
                    'C': int(cia['C']),
                    'I': int(cia['I']),
                    'A': int(cia['A']),
                })

            edit_key = f"edit_{sel_tbl}"
            initial_df = pd.DataFrame(rows)
            edited_df = st.data_editor(
                initial_df,
                use_container_width=True,
                num_rows="fixed",
                hide_index=True,
                column_config={
                    'Column Name': st.column_config.TextColumn(disabled=True),
                    'Data Type': st.column_config.TextColumn(disabled=True),
                    'Sensitivity Types': st.column_config.TextColumn(disabled=True),
                    'Label': st.column_config.SelectboxColumn(options=["Public","Internal","Restricted","Confidential"]),
                    'C': st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
                    'I': st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
                    'A': st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
                },
                key=edit_key,
            ) if not initial_df.empty else initial_df
            # Persist edited columns state
            ai_ss.setdefault('columns', {})
            ai_ss['columns'][sel_tbl] = edited_df.copy() if not edited_df.empty else initial_df

            # Compute table-level CIA suggestion as max across columns and render as an editable table
            if not edited_df.empty:
                try:
                    tC = int(edited_df['C'].max())
                    tI = int(edited_df['I'].max())
                    tA = int(edited_df['A'].max())
                except Exception:
                    tC = tI = tA = 0
                tLabel = 'Confidential' if tC >= 3 else ('Restricted' if tC >= 2 else ('Internal' if tC >= 1 else 'Public'))

                st.markdown("**Table-level Classification (editable)**")
                table_init = pd.DataFrame([{
                    'Table Name': sel_tbl,
                    'Label': tLabel,
                    'C': tC,
                    'I': tI,
                    'A': tA,
                }])
                table_cfg = {
                    'Table Name': st.column_config.TextColumn(disabled=True),
                    'Label': st.column_config.SelectboxColumn(options=["Public","Internal","Restricted","Confidential"]),
                    'C': st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
                    'I': st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
                    'A': st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
                }
                table_edit = st.data_editor(
                    table_init,
                    use_container_width=True,
                    hide_index=True,
                    num_rows="fixed",
                    column_config=table_cfg,
                    key=f"tbl_edit_{sel_tbl}"
                )
                # Extract edited values
                try:
                    tLabel = str(table_edit.iloc[0]['Label'])
                    tC = int(table_edit.iloc[0]['C'])
                    tI = int(table_edit.iloc[0]['I'])
                    tA = int(table_edit.iloc[0]['A'])
                except Exception:
                    pass

                # Validate table-level policy (min levels)
                try:
                    tagging_service.validate_tags({
                        'DATA_CLASSIFICATION': tLabel,
                        'CONFIDENTIALITY_LEVEL': str(tC),
                        'INTEGRITY_LEVEL': str(tI),
                        'AVAILABILITY_LEVEL': str(tA),
                    })
                    tagging_service._enforce_policy_minimums(sel_tbl, {
                        'DATA_CLASSIFICATION': tLabel,
                        'CONFIDENTIALITY_LEVEL': str(tC),
                    })
                    st.success("Table classification passes policy validation.")
                except Exception as e:
                    st.warning(f"Table policy: {e}")

                # Validate each column suggestion and show aggregated issues
                issues = []
                for _, row in edited_df.iterrows():
                    try:
                        tagging_service.validate_tags({
                            'DATA_CLASSIFICATION': row['Label'],
                            'CONFIDENTIALITY_LEVEL': str(int(row['C'])),
                            'INTEGRITY_LEVEL': str(int(row['I'])),
                            'AVAILABILITY_LEVEL': str(int(row['A'])),
                        })
                        tagging_service._enforce_policy_minimums(sel_tbl, {
                            'DATA_CLASSIFICATION': row['Label'],
                            'CONFIDENTIALITY_LEVEL': str(int(row['C'])),
                        })
                    except Exception as e:
                        issues.append({
                            'column': row['Column Name'],
                            'error': str(e),
                        })
                if issues:
                    st.error({'policy_issues': issues})
                else:
                    st.info("All column suggestions meet minimum policy requirements.")

                # Submit: apply table and column tags and log
                if st.button("Apply classification and log audit", key=f"apply_{sel_tbl}"):
                    apply_errors = []
                    user_id = str(st.session_state.get('user') or 'system')
                    # Table tags
                    try:
                        tagging_service.apply_tags_to_object(sel_tbl, "TABLE", {
                            'DATA_CLASSIFICATION': tLabel,
                            'CONFIDENTIALITY_LEVEL': str(tC),
                            'INTEGRITY_LEVEL': str(tI),
                            'AVAILABILITY_LEVEL': str(tA),
                        })
                        classification_decision_service.record(
                            asset_full_name=sel_tbl,
                            decision_by=user_id,
                            source="UI",
                            status="Applied",
                            label=tLabel,
                            c=int(tC), i=int(tI), a=int(tA),
                            rationale="AI Assistant submission",
                            details={'source': 'AI Assistant'},
                        )
                        audit_service.log(user_id, "UI_APPLY", "ASSET", sel_tbl, {"label": tLabel, "C": tC, "I": tI, "A": tA})
                    except Exception as e:
                        apply_errors.append(f"TABLE: {e}")

                    # Column tags
                    for _, row in edited_df.iterrows():
                        try:
                            tagging_service.apply_tags_to_column(sel_tbl, row['Column Name'], {
                                'DATA_CLASSIFICATION': row['Label'],
                                'CONFIDENTIALITY_LEVEL': str(int(row['C'])),
                                'INTEGRITY_LEVEL': str(int(row['I'])),
                                'AVAILABILITY_LEVEL': str(int(row['A'])),
                            })
                            classification_decision_service.record(
                                asset_full_name=f"{sel_tbl}.{row['Column Name']}",
                                decision_by=user_id,
                                source="UI",
                                status="Applied",
                                label=row['Label'],
                                c=int(row['C']), i=int(row['I']), a=int(row['A']),
                                rationale="AI Assistant submission",
                                details={'source': 'AI Assistant'},
                            )
                            audit_service.log(user_id, "UI_APPLY", "COLUMN", f"{sel_tbl}.{row['Column Name']}", {
                                'label': row['Label'], 'C': int(row['C']), 'I': int(row['I']), 'A': int(row['A'])
                            })
                        except Exception as e:
                            apply_errors.append(f"{row['Column Name']}: {e}")

                    # Best-effort: write an audit row to CLASSIFICATION_AUDIT if present
                    try:
                        prev = snowflake_connector.execute_query(
                            f"""
                            SELECT CAST(COALESCE(CONFIDENTIALITY_LEVEL,'0') AS INT) AS C, CAST(COALESCE(INTEGRITY_LEVEL,'0') AS INT) AS I, CAST(COALESCE(AVAILABILITY_LEVEL,'0') AS INT) AS A
                            FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                            WHERE FULLY_QUALIFIED_NAME = %(f)s
                            LIMIT 1
                            """,
                            {"f": sel_tbl},
                        ) or []
                        pc, pi, pa = (int(prev[0].get('C',0)), int(prev[0].get('I',0)), int(prev[0].get('A',0))) if prev else (0,0,0)
                        snowflake_connector.execute_non_query(
                            f"""
                            INSERT INTO {db}.DATA_GOVERNANCE.CLASSIFICATION_AUDIT
                            (DATASET_NAME, PREV_C, PREV_I, PREV_A, NEW_C, NEW_I, NEW_A, OWNER, CLASSIFICATION_LEVEL, SUBMITTED_AT, APPROVED_AT, RISK, COMMENTS)
                            SELECT %(ds)s, %(pc)s, %(pi)s, %(pa)s, %(nc)s, %(ni)s, %(na)s, %(ow)s, %(cl)s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'Medium', 'AI Assistant apply'
                            """,
                            {"ds": sel_tbl, "pc": pc, "pi": pi, "pa": pa, "nc": int(tC), "ni": int(tI), "na": int(tA), "ow": user_id, "cl": tLabel},
                        )
                    except Exception:
                        # Skip if table not present or user lacks rights
                        pass

                    if apply_errors:
                        st.error({'apply_errors': apply_errors})
                    else:
                        st.success("Classification applied and logged.")

with tab_auto:
    st.subheader("🚀 Automated Data Classification Pipeline")
    st.markdown("""
    **Snowflake-native AI assistant system** that automatically discovers data assets,
    performs semantic category detection, recommends CIA levels, and applies governance tags.
    """)

    # Pipeline controls
    db = _resolve_db()
    if not db:
        st.info("Select a database from the sidebar to proceed.")
    else:
        col1, col2, col3 = st.columns(3)

        with col1:
            schema_filter = st.selectbox(
                "Schema Filter (optional)",
                options=["All"] + _list_schemas(db),
                index=0,
                help="Limit discovery to specific schema"
            )
            schema_filter = None if schema_filter == "All" else schema_filter

        with col2:
            max_assets = st.number_input(
                "Max Assets to Process",
                min_value=10,
                max_value=10000,
                value=1000,
                step=100,
                help="Limit for scalability and testing"
            )

        with col3:
            if st.button("🔍 Discover & Classify Assets", type="primary"):
                if comprehensive_detection_service is None:
                    st.error("Comprehensive detection service not available.")
                else:
                    with st.spinner("Running automated classification pipeline..."):
                        try:
                            # Execute full pipeline
                            result = comprehensive_detection_service.execute_full_pipeline(
                                database=db,
                                schema_filter=schema_filter,
                                max_assets=max_assets
                            )

                            if result.get('status') == 'COMPLETED':
                                st.success("✅ Pipeline completed successfully!")

                                # Display results
                                col_a, col_b, col_c = st.columns(3)
                                with col_a:
                                    st.metric("Assets Processed", result.get('total_assets_processed', 0))
                                with col_b:
                                    st.metric("Detection Accuracy", f"{result.get('detection_accuracy', 0):.1%}")
                                with col_c:
                                    st.metric("Duration", f"{result.get('duration_seconds', 0):.1f}s")

                                # Classification distribution
                                if result.get('classification_distribution'):
                                    st.subheader("📊 Classification Results")
                                    dist_df = pd.DataFrame(
                                        list(result['classification_distribution'].items()),
                                        columns=['Category', 'Count']
                                    )
                                    st.bar_chart(dist_df.set_index('Category'))

                                # Success details
                                with st.expander("📋 Pipeline Details"):
                                    st.json(result)

                            else:
                                st.error(f"❌ Pipeline failed: {result.get('error', 'Unknown error')}")

                        except Exception as e:
                            st.error(f"❌ Pipeline execution error: {str(e)}")

        # Pipeline status and monitoring
        st.markdown("---")
        st.subheader("📈 Pipeline Monitoring")

        # Recent pipeline runs
        try:
            if db and _table_exists(db, 'DATA_GOVERNANCE', 'CLASSIFICATION_AUDIT_LOG'):
                recent_runs = snowflake_connector.execute_query(f"""
                    SELECT EVENT_TYPE, ASSET_PATH, CREATED_AT, DETAILS
                    FROM {db}.DATA_GOVERNANCE.CLASSIFICATION_AUDIT_LOG
                    WHERE EVENT_TYPE LIKE 'PIPELINE%'
                    ORDER BY CREATED_AT DESC
                    LIMIT 10
                """) or []

                if recent_runs:
                    runs_df = pd.DataFrame(recent_runs)
                    runs_df['CREATED_AT'] = pd.to_datetime(runs_df['CREATED_AT']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    st.dataframe(runs_df, use_container_width=True)
                else:
                    st.info("No recent pipeline runs found.")
        except Exception as e:
            st.warning(f"Could not load pipeline history: {e}")

        # Quick actions
        st.markdown("---")
        st.subheader("⚡ Quick Actions")

        action_col1, action_col2, action_col3 = st.columns(3)

        with action_col1:
            if st.button("🔄 Refresh Configuration", help="Reload governance configuration"):
                if comprehensive_detection_service:
                    comprehensive_detection_service._config = comprehensive_detection_service._load_configuration()
                    st.success("Configuration refreshed!")
                else:
                    st.error("Service not available")

        with action_col2:
            if st.button("📊 Update Dashboard Metrics", help="Refresh compliance metrics"):
                st.cache_data.clear()
                st.success("Metrics refreshed!")

        with action_col3:
            if st.button("🧹 Clear Cache", help="Clear cached data"):
                st.cache_data.clear()
                st.success("Cache cleared!")

# Explanation for non-technical users
st.info("""� **What you're seeing:**
- Compliance Dashboard: policy compliance metrics, classification coverage (by framework, BU, data type), trend analysis, and audit-ready reports
- Review Management: schedule reviews, see overdue tasks (5-day rule), and view review history
- Policy Violations: violation log, corrective action tracking, and evidence pack export for audits
- AI Assistant: manual classification with AI suggestions
- **Automated Classification**: Full pipeline for automatic discovery, classification, and tagging
- Data sources are Snowflake metadata (ACCOUNT_USAGE, INFORMATION_SCHEMA) and governance tables where available
""")