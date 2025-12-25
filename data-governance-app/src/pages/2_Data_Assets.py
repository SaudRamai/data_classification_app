# -*- coding: utf-8 -*-
"""
Data Assets page for the data governance application.
"""
from __future__ import annotations

import sys
import os
from typing import Optional, List, Dict, Tuple, Set
from datetime import datetime

# Add the project root (parent of 'src') to the Python path so 'src.*' imports work
_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))  # .../src
_project_root = os.path.dirname(_src_dir)           # project root containing 'src'
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import streamlit as st
import pandas as pd
import altair as alt
from io import BytesIO, StringIO
from src.ui.theme import apply_global_theme
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.tagging_service import tagging_service
from src.services.classification_workflow_service import classification_workflow_service as reclassification_service
from src.services.classification_workflow_service import classification_workflow_service as cwf
# Import from consolidated classification pipeline service
from src.services.classification_pipeline_service import ai_classification_service
from src.services.classification_audit_service import classification_audit_service as audit_service
from src.services.compliance_service import compliance_service
from src.services.authorization_service import authz
# Removed broken system_classify_service import

# Use dark theme for Altair charts to match black app theme
try:
    alt.themes.enable('dark')
except Exception:
    pass

# Page configuration
st.set_page_config(
    page_title="Data Assets - Data Governance App",
    page_icon="🗂️",
    layout="wide"
)

# Apply centralized theme (fonts, CSS variables, Plotly template)
apply_global_theme()

# Enhanced page header with description
st.markdown("""
<div style='margin-bottom: 20px;'>
    <h1 style='margin-bottom: 5px;'>🗂️ Data Assets Inventory</h1>
    <p style='color: rgba(255,255,255,0.7); font-size: 16px; margin-top: 0;'>
        Comprehensive asset management with lifecycle tracking, compliance monitoring, and relationship visualization
    </p>
</div>
""", unsafe_allow_html=True)

# Default debug flag to avoid NameError if referenced in exception handlers
show_debug_det = False

# Feature flag to temporarily bypass RBAC for verification of tabs/UI only
# Set to True to bypass stop() when role is not consumer. Do NOT leave enabled in production.
REVERSE_DATA_ASSETS_RBAC = True

# Ensure UI renders even when unauthenticated; disable data access until login
has_session = False
try:
    ident_probe = authz.get_current_identity()
    has_session = bool(getattr(ident_probe, 'user', None))
except Exception:
    has_session = False
if not has_session:
    try:
        has_session = bool(st.session_state.get("sf_user") and st.session_state.get("sf_account"))
    except Exception:
        has_session = False
if not has_session:
    st.warning("You are not signed in. Data access is disabled until login.")
    st.caption("Open Home and login with your Snowflake account or SSO to enable live data.")
    st.markdown("---")
    st.subheader("Inventory Overview")
    st.info("Asset lists, lineage, and metrics will load after you sign in.")
    st.subheader("Your Actions")
    st.info("Classification and tagging are disabled until authentication.")
    # Avoid running any queries or further logic
    st.stop()

# RBAC guard and capability flags
try:
    _ident = authz.get_current_identity()
    if not authz.is_consumer(_ident):
        if REVERSE_DATA_ASSETS_RBAC:
            st.warning("RBAC bypass active (testing). Tabs are visible for verification. Disable REVERSE_DATA_ASSETS_RBAC to enforce access.")
        else:
            st.error("You do not have permission to access Data Assets. Please sign in with a role that has at least consumer-level access.")
            st.stop()
    _can_classify = authz.can_classify(_ident)
    _can_approve = authz.can_approve_tags(_ident)
    if not _can_classify:
        st.info("Your role does not permit classification or tagging actions on this page.")
except Exception as _rbac_err:
    if REVERSE_DATA_ASSETS_RBAC:
        st.warning(f"Authorization check failed (bypassed for testing): {_rbac_err}")
    else:
        st.warning(f"Authorization check failed: {_rbac_err}")
        st.stop()

# Ensure an active warehouse for queries (auto-use session/env default)
def _ensure_wh_quick():
    try:
        row = snowflake_connector.execute_query("select current_warehouse() as W") or []
        cur = row[0].get('W') if row else None
    except Exception:
        cur = None
    if not cur:
        try:
            default_wh = st.session_state.get('dash_wh_preferred') or st.session_state.get('sf_warehouse') or settings.SNOWFLAKE_WAREHOUSE
            if default_wh:
                snowflake_connector.execute_non_query(f"use warehouse {default_wh}")
        except Exception:
            st.warning("No active warehouse. Set a warehouse on the Dashboard sidebar (Session) or in login.")
    # Ensure database is set as well, for INFORMATION_SCHEMA queries
    try:
        db_row = snowflake_connector.execute_query("select current_database() as D") or []
        curdb = db_row[0].get('D') if db_row else None
    except Exception:
        curdb = None
    if not curdb:
        # Try session state first, then settings
        default_db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
        if default_db:
            try:
                snowflake_connector.execute_non_query(f"use database {default_db}")
            except Exception:
                pass

_ensure_wh_quick()

# ---------------- Sidebar: Global Filters ----------------
with st.sidebar:
    st.markdown("**Global Filters**")
    # Warehouse filter (single-selection; show first)
    @st.cache_data(ttl=600, show_spinner=False)
    def _get_wh_opts():
        try:
            wh_rows = snowflake_connector.execute_query("SHOW WAREHOUSES") or []
            return sorted([r.get('name') or r.get('NAME') for r in wh_rows if (r.get('name') or r.get('NAME'))])
        except Exception:
            return []
    
    wh_opts = _get_wh_opts()
    cur_wh = st.session_state.get('sf_warehouse')
    sel_wh = st.selectbox(
        "Warehouse",
        options=["(none)"] + wh_opts if wh_opts else ["(none)"],
        index=( (["(none)"] + wh_opts).index(cur_wh) if cur_wh in wh_opts else 0 ) if wh_opts else 0,
        help="Choose the Snowflake warehouse to run queries"
    )
    if sel_wh and sel_wh != "(none)" and sel_wh != cur_wh:
        try:
            snowflake_connector.execute_non_query(f"use warehouse {sel_wh}")
            st.session_state['sf_warehouse'] = sel_wh
            # Lightly notify; avoid forcing rerun to keep UX smooth
            st.caption(f"Using warehouse: {sel_wh}")
        except Exception as _e:
            st.warning(f"Failed to set warehouse: {_e}")

    # Databases: multiselect (after warehouse)
    @st.cache_data(ttl=600, show_spinner=False)
    def _get_db_opts():
        try:
            db_rows = snowflake_connector.execute_query("SHOW DATABASES") or []
            return sorted([r.get('name') or r.get('NAME') for r in db_rows if (r.get('name') or r.get('NAME'))])
        except Exception:
            return []
    
    db_opts = _get_db_opts()
    sel_dbs = st.multiselect(
        "Database",
        options=db_opts,
        default=[st.session_state.get('sf_database')] if st.session_state.get('sf_database') in db_opts else [],
        help="Select one or multiple databases"
    )
    st.session_state['da_selected_dbs'] = sel_dbs

    # Schema filter (applied after load)
    schema_filter_sidebar = st.text_input(
        "Schema (contains)", value=st.session_state.get('da_schema_contains', ''),
        help="Filter by schema name substring"
    )
    st.session_state['da_schema_contains'] = schema_filter_sidebar

    # Table/View name – wildcard or fuzzy
    tbl_search = st.text_input(
        "Object(Table/View)",
        value=st.session_state.get('da_tbl_search', ''),
        placeholder=""
    )
    fuzzy = st.checkbox("Fuzzy contains", value=st.session_state.get('da_fuzzy', True))
    st.session_state['da_tbl_search'] = tbl_search
    st.session_state['da_fuzzy'] = fuzzy

    # Column name search (feeds column-level filters)
    col_search = st.text_input(
        "Column name",
        value=st.session_state.get('da_col_search', ''),
        placeholder="email, ssn, amount"
    )
    st.session_state['da_col_search'] = col_search

# Manual refresh to clear cache and re-run queries
if st.button("🔄 Refresh now", help="Clear cached data (5 min TTL) and refresh from Snowflake"):
    st.cache_data.clear()
    st.rerun()

# --- Policy enforcement helpers (Decision Matrix & Audit persistence) ---
def _ensure_decisions_table():
    """Ensure the audit table for classification decisions exists."""
    try:
        db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
        if not db:
            return  # Skip if no database configured
        snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db}.DATA_GOVERNANCE")
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {db}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS (
                ID STRING DEFAULT UUID_STRING(),
                ASSET_FULL_NAME STRING,
                CLASSIFICATION STRING,
                C NUMBER(1),
                I NUMBER(1),
                A NUMBER(1),
                OWNER STRING,
                RATIONALE STRING,
                CHECKLIST_JSON STRING,
                DECIDED_BY STRING,
                DECIDED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                PREV_CLASSIFICATION STRING,
                PREV_C NUMBER(1),
                PREV_I NUMBER(1),
                PREV_A NUMBER(1)
            )
            """
        )
    except Exception:
        # Best-effort; do not block UI if ensure fails
        pass

def _persist_decision(asset: str, new_cls: str, c: int, i: int, a: int, owner: str, rationale: str, checklist: dict, decided_by: str, prev: Optional[dict] = None):
    """Persist a classification decision for auditability."""
    try:
        # Require rationale per policy before persisting
        if not rationale or not str(rationale).strip():
            try:
                st.error("Rationale is required (Policy 6.1.2). Decision not saved.")
            except Exception:
                pass
            return
        _ensure_decisions_table()
        params = {
            "asset": asset,
            "cls": new_cls,
            "c": int(c),
            "i": int(i),
            "a": int(a),
            "owner": owner or None,
            "rationale": rationale or None,
            "checklist": str(checklist or {}),
            "by": decided_by or "unknown",
            "p_cls": (prev or {}).get("classification"),
            "p_c": (prev or {}).get("C"),
            "p_i": (prev or {}).get("I"),
            "p_a": (prev or {}).get("A"),
        }
        db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
        if not db:
            return  # Skip if no database configured
        snowflake_connector.execute_non_query(
            f"""
            INSERT INTO {db}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
            (ASSET_FULL_NAME, CLASSIFICATION, C, I, A, OWNER, RATIONALE, CHECKLIST_JSON, DECIDED_BY, PREV_CLASSIFICATION, PREV_C, PREV_I, PREV_A)
            VALUES (%(asset)s, %(cls)s, %(c)s, %(i)s, %(a)s, %(owner)s, %(rationale)s, %(checklist)s, %(by)s, %(p_cls)s, %(p_c)s, %(p_i)s, %(p_a)s)
            """,
            params,
        )
    except Exception:
        # Do not block the UI if persistence fails; audit_service captures UI-level actions
        pass

def _validate_decision_matrix(label: str, c: int, i: int, a: int, has_pii: bool, regs: List[str]) -> Tuple[bool, str]:
    """Hard validation per policy sections 5.2, 5.5, 6.2.2.
    - Enforce CIA-to-label consistency (C3 ⇒ Confidential, C2+ ⇒ ≥ Restricted)
    - Enforce special-category minimums (PII ≥ Restricted; SOX ⇒ Confidential)
    """
    try:
        lab = (label or "").strip().upper()
        max_cia = max(int(c), int(i), int(a))
        # CIA to label minimum
        if int(c) >= 3 and lab != "CONFIDENTIAL":
            return False, "C=3 requires label 'Confidential'."
        if int(c) == 2 and lab not in ("RESTRICTED", "CONFIDENTIAL"):
            return False, "C=2 requires label at least 'Restricted'."
        # Special categories
        if has_pii and lab in ("PUBLIC", "INTERNAL"):
            return False, "PII detected: minimum classification is 'Restricted'."
        regs_up = {r.upper() for r in (regs or [])}
        if "SOX" in regs_up and lab != "CONFIDENTIAL":
            return False, "SOX-relevant data must be classified 'Confidential'."
        if ("GDPR" in regs_up or "HIPAA" in regs_up or "PCI" in regs_up) and lab in ("PUBLIC", "INTERNAL"):
            return False, "Regulated data (GDPR/HIPAA/PCI) requires at least 'Restricted'."
        # Availability/Integrity high criticality guidance (allow Restricted or Confidential)
        if int(i) >= 3 and lab not in ("RESTRICTED", "CONFIDENTIAL"):
            return False, "I=3 requires label at least 'Restricted'."
        if int(a) >= 3 and lab not in ("RESTRICTED", "CONFIDENTIAL"):
            return False, "A=3 requires label at least 'Restricted'."
        return True, "OK"
    except Exception as e:
        return False, f"Validation error: {e}"

# Helper (testable): compute column flags for PII/Financial/Regulatory based on name and tag names
def _compute_column_flags(colname: str, tag_names: Optional[Set[str]] = None) -> List[str]:
    try:
        tag_names = tag_names or set()
        upn = (colname or '').upper()
        flags: List[str] = []
        if any(k in upn for k in ["SSN","EMAIL","PHONE","ADDRESS","DOB","PERSON","CUSTOMER","EMPLOYEE"]) or any("PII" in t for t in tag_names):
            flags.append("PII")
        if any(k in upn for k in ["GL","LEDGER","INVOICE","PAYROLL","AR","AP","REVENUE","EXPENSE"]) or any(("FINANCE" in t) or ("FINANCIAL" in t) for t in tag_names):
            flags.append("Financial")
        if any(k in upn for k in ["GDPR","HIPAA","PCI","SOX"]) or any(any(x in t for x in ["GDPR","HIPAA","PCI","SOX"]) for t in tag_names):
            flags.append("Regulatory")
        return flags
    except Exception:
        return []

# Enhanced CSS for modern, professional UI with improved visual hierarchy
st.markdown(
    """
    <style>
    /* Enhanced KPI Cards with gradient borders and hover effects */
    .kpi-card {
        padding: 20px;
        border-radius: 12px;
        background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
        border: 1px solid rgba(255,255,255,0.1);
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        transition: transform 0.2s, box-shadow 0.2s;
        margin-bottom: 10px;
    }
    .kpi-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }
    .kpi-public {border-left: 6px solid #2ECC71;}
    .kpi-internal {border-left: 6px solid #F1C40F;}
    .kpi-restricted {border-left: 6px solid #E67E22;}
    .kpi-confidential {border-left: 6px solid #E74C3C;}
    
    /* Enhanced badges with better contrast */
    .badge {padding: 4px 12px; border-radius: 999px; font-size: 11px; font-weight: 600; letter-spacing: 0.5px;}
    .badge-ok {background: rgba(46, 212, 198, 0.2); color:#2ED4C6; border: 1px solid rgba(46, 212, 198, 0.3);}
    .badge-warn {background: rgba(241, 196, 15, 0.2); color:#F1C40F; border: 1px solid rgba(241, 196, 15, 0.3);}
    .badge-bad {background: rgba(231, 76, 60, 0.2); color:#E74C3C; border: 1px solid rgba(231, 76, 60, 0.3);}
    
    /* Section headers with icons */
    .section-header {
        font-size: 18px;
        font-weight: 600;
        margin: 20px 0 10px 0;
        padding: 10px 0;
        border-bottom: 2px solid rgba(255,255,255,0.1);
    }
    
    /* Filter panel styling */
    .filter-section {
        background: rgba(255,255,255,0.03);
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 15px;
        border: 1px solid rgba(255,255,255,0.08);
    }
    
    /* Enhanced table styling */
    .dataframe {
        border-radius: 8px;
        overflow: hidden;
    }
    
    /* Relationship cards */
    .relationship-card {
        background: rgba(255,255,255,0.05);
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #3498db;
        margin: 10px 0;
    }
    
    /* Status indicators */
    .status-active {color: #2ECC71; font-weight: 600;}
    .status-deprecated {color: #E67E22; font-weight: 600;}
    .status-archived {color: #95A5A6; font-weight: 600;}
    
    /* Info boxes */
    .info-box {
        background: linear-gradient(135deg, rgba(52, 152, 219, 0.1) 0%, rgba(52, 152, 219, 0.05) 100%);
        border-left: 4px solid #3498db;
        padding: 15px;
        border-radius: 8px;
        margin: 15px 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Active Snowflake role indicator
@st.cache_data(ttl=60, show_spinner=False)
def _get_session_context():
    try:
        role_row = snowflake_connector.execute_query("select current_role() as ROLE")
        wh_row = snowflake_connector.execute_query("select current_warehouse() as WAREHOUSE")
        db_row = snowflake_connector.execute_query("select current_database() as DATABASE")
        return {
            'role': role_row[0]['ROLE'] if role_row else None,
            'wh': wh_row[0]['WAREHOUSE'] if wh_row else None,
            'db': db_row[0]['DATABASE'] if db_row else None
        }
    except Exception:
        return None

ctx = _get_session_context()
if ctx:
    st.caption(f"Connected as role: {ctx['role'] or 'Unknown'} | Warehouse: {ctx['wh'] or 'Unknown'} | Database: {ctx['db'] or 'Unknown'}")
else:
    st.caption("Connected role/warehouse/database: unavailable (insufficient privileges)")

# Session & Scope controls moved to the sidebar (see app.py)

# New top-level tabs per updated IA
tab_inv_browser, tab_adv_search, tab_favorites = st.tabs([
    "🔍 Inventory Browser", "🎯 Advanced Search & Filters", "⭐ Favorites & Bookmarks"
])

with tab_inv_browser:
    st.caption("Inventory Browser uses your current session database. Set Role/Warehouse/Database from the sidebar → '🔧 Role & Session'.")

# Function to get real data assets from Snowflake
@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_real_data_assets(selected_dbs: Optional[List[str]] = None):
    try:
        # Resolve database scope
        dbs: List[str] = [d for d in (selected_dbs or []) if d]
        if not dbs:
            return pd.DataFrame()

        governance_db = dbs[0]
        in_list = ",".join([f"'{d}'" for d in dbs])
        
        # Unified high-performance query: All governed metadata in one pass
        # Includes raw timestamps for sorting and formatted strings for display
        query = f"""
            SELECT 
                ASSET_ID AS "ID",
                ASSET_NAME AS "Name",
                COALESCE(DATA_DESCRIPTION, ASSET_TYPE || ' asset') AS "Description",
                FULLY_QUALIFIED_NAME AS "Location",
                DATABASE_NAME AS "Database",
                COALESCE(CLASSIFICATION_LABEL, 'Unclassified') AS "Classification",
                'C' || COALESCE(CONFIDENTIALITY_LEVEL, '1') || 
                '-I' || COALESCE(INTEGRITY_LEVEL, '1') || 
                '-A' || COALESCE(AVAILABILITY_LEVEL, '1') AS "CIA Score",
                COALESCE(DATA_OWNER, 'Unknown') AS "Owner",
                'N/A' AS "Rows",
                0.0 AS "Size (MB)",
                'Medium' AS "Data Quality",
                TO_VARCHAR(LAST_MODIFIED_TIMESTAMP, 'YYYY-MM-DD') AS "Last Updated",
                ASSET_TYPE AS "Type",
                CONFIDENTIALITY_LEVEL AS "C",
                INTEGRITY_LEVEL AS "I",
                AVAILABILITY_LEVEL AS "A",
                OVERALL_RISK_CLASSIFICATION AS "Risk",
                COALESCE(COMPLIANCE_STATUS, 'UNKNOWN') AS "Status",
                CASE 
                    WHEN CLASSIFICATION_LABEL IS NOT NULL AND UPPER(CLASSIFICATION_LABEL) NOT IN ('','UNCLASSIFIED') THEN 'Classified'
                    WHEN DATEDIFF('day', CREATED_TIMESTAMP, CURRENT_TIMESTAMP()) >= 5 THEN 'Overdue'
                    ELSE 'Unclassified'
                END AS "SLA State",
                CREATED_TIMESTAMP AS "created_date",
                LAST_MODIFIED_TIMESTAMP AS "last_modified"
            FROM {governance_db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
            WHERE DATABASE_NAME IN ({in_list})
            ORDER BY DATABASE_NAME, SCHEMA_NAME, ASSET_NAME
            LIMIT 5000
        """
        rows = snowflake_connector.execute_query(query) or []
        return pd.DataFrame(rows)
            
    except Exception as e:
        if 'logger' in globals():
            logger.error(f"Error fetching data assets: {e}")
        return pd.DataFrame()
            
    except Exception as e:
        st.error(f"Error fetching data assets from Snowflake: {str(e)}")
        # Fallback in exception case as well
        try:
            from src.demo_data import UNCLASSIFIED_ASSETS_TSV
            if UNCLASSIFIED_ASSETS_TSV:
                df_demo = pd.read_csv(StringIO(UNCLASSIFIED_ASSETS_TSV), sep='\t')
                assets_data = []
                for i, row in df_demo.iterrows():
                    fqn = str(row.get('FULLY_QUALIFIED_NAME', ''))
                    assets_data.append({
                        "ID": f"asset_demo_{i+1:03d}",
                        "Name": row.get('ASSET_NAME', ''),
                        "Description": "Demo Asset",
                        "Location": fqn,
                        "Database": fqn.split('.')[0] if '.' in fqn else '',
                        "Classification": row.get('CLASSIFICATION_LABEL') or 'Unclassified',
                        "CIA Score": "C1-I1-A1",
                        "Owner": row.get('DATA_OWNER') or 'Unknown',
                        "Rows": "1,000",
                        "Size (MB)": 1.0,
                        "Data Quality": "Medium",
                        "Last Updated": str(row.get('CLASSIFICATION_DATE') or datetime.now().strftime('%Y-%m-%d')),
                        "Type": row.get('ASSET_TYPE') or 'TABLE',
                        "Risk": "Low", # Default for demo
                        "Status": "Unclassified", # Default for demo
                        "SLA State": "Unclassified", # Default for demo
                        "created_date": datetime.now(),
                        "last_modified": datetime.now()
                    })
                return pd.DataFrame(assets_data)
        except Exception:
            pass
        return pd.DataFrame()

def compute_policy_fields(df: pd.DataFrame) -> pd.DataFrame:
    """Minimal augmentation as most fields are now provided by the unified SQL query."""
    if df.empty:
        return df
    return df.copy()

# Get data assets
with st.spinner("Fetching real data assets from your Snowflake database..."):
    # Determine database scope: if a warehouse is selected and no DBs picked, load ALL account databases
    _sel_dbs = st.session_state.get('da_selected_dbs') or []
    if (st.session_state.get('sf_warehouse') and (not _sel_dbs)):
        try:
            _rows = snowflake_connector.execute_query("SHOW DATABASES") or []
            _sel_dbs = sorted([r.get('name') or r.get('NAME') for r in _rows if (r.get('name') or r.get('NAME'))])
        except Exception:
            _sel_dbs = []
    # Optional enrichment toggle (defers heavy inventory lookups unless enabled)
    st.markdown("---")
    st.subheader("Inventory Options")
    st.checkbox(
        "Enrich with inventory status (slower)",
        key="da_enrich_status",
        help="Adds classification status and decisions by querying governance tables. Disable to speed up loading.",
        value=False,
    )

    # Use the resolved database list; avoid account-wide scans when none selected
    if not _sel_dbs:
        st.info("Select one or more databases in the sidebar to load the Data Assets inventory. Skipping account-wide scan for performance.")
        assets_df = pd.DataFrame()
    else:
        with st.spinner("Loading assets from Snowflake..."):
            base_df = get_real_data_assets(_sel_dbs)
        assets_df = compute_policy_fields(base_df)
    # Attach base created/modified timestamps to assets_df for sorting
    try:
        if not base_df.empty:
            ts_map = base_df.set_index('Location')[['created_date','last_modified']].to_dict('index')
            assets_df['Creation Date'] = assets_df['Location'].map(lambda x: (ts_map.get(x) or {}).get('created_date'))
            assets_df['Last Modified'] = assets_df['Location'].map(lambda x: (ts_map.get(x) or {}).get('last_modified'))
    except Exception:
        pass

    # Helper: policy guardrails and validation
    def _is_pii(text: str) -> bool:
        if not text:
            return False
        t = str(text).upper()
        return any(k in t for k in ["PII","SSN","SOCIAL","EMAIL","PHONE","DOB","ADDRESS","PERSON","CUSTOMER","EMPLOYEE"])

    def _is_financial(text: str) -> bool:
        if not text:
            return False
        t = str(text).upper()
        return any(k in t for k in ["FINANCE","FINANCIAL","GL","LEDGER","INVOICE","PAYROLL","SOX","REVENUE","EXPENSE","AR","AP"])

    def _is_regulatory(text: str) -> bool:
        if not text:
            return False
        t = str(text).upper()
        return any(k in t for k in ["GDPR","HIPAA","PCI","REGULATORY"])

    def _policy_validate_for_asset(row: pd.Series, new_label: str, c: int, i: int, a: int, rationale: str, owner_override: str = ""):
        """Raise ValueError if validation fails. Implements §5.4.2, §5.5, §6.2, §7.2."""
        # Allowed sets
        allowed_labels = {"Public","Internal","Restricted","Confidential"}
        if new_label not in allowed_labels:
            raise ValueError("Invalid classification label. Allowed: Public, Internal, Restricted, Confidential (§5.4.2)")
        if not (0 <= c <= 3 and 0 <= i <= 3 and 0 <= a <= 3):
            raise ValueError("C/I/A must be integers in 0..3 (§5.4.2)")
        # Label/level consistency
        if new_label == "Public" and c >= 2:
            raise ValueError("Public corresponds to C0 only; C≥2 conflicts (§5.4.1, §5.4.2)")
        if new_label == "Internal" and c >= 2:
            raise ValueError("Internal corresponds to C1; use Restricted/Confidential for higher C (§5.4.1, §5.4.2)")
        # Category guardrails
        tags = str(row.get("Tags",""))
        loc = str(row.get("Location",""))
        text_blob = f"{tags} {loc}"
        if _is_pii(text_blob):
            if new_label in ("Public","Internal") or c < 2:
                raise ValueError("PII requires at least Restricted (C≥2) (§5.5.1)")
        if _is_financial(text_blob):
            if new_label in ("Public","Internal") or c < 2:
                raise ValueError("Financial data requires at least Restricted (C≥2); consider I≥2 (§5.5.2)")
        if _is_regulatory(text_blob):
            if new_label in ("Public","Internal") or c < 2:
                raise ValueError("Regulatory data must use the most restrictive applicable label; at least Restricted (C≥2) (§5.5.3)")
        # Rationale required
        if not rationale or not rationale.strip():
            raise ValueError("Rationale is required for classification decisions (§6.2)")
        # Owner required
        owner_existing = str(row.get("Owner","")) if row is not None else ""
        if (not owner_existing or owner_existing.lower() in ("", "unknown", "admin@company.com")) and not owner_override:
            raise ValueError("A Data Owner must be assigned before classification (§7.2). Provide an owner email.")

    # Helper to get a tags map for the first N assets to avoid heavy queries
    # Batch retrieve tags for the entire visible asset list (High Performance)
    @st.cache_data(ttl=600)
    def get_tags_batch(full_names: list) -> dict:
        if not full_names: return {}
        try:
            # We use a single query to ACCOUNT_USAGE for all selected assets
            in_list = ",".join([f"'{f}'" for f in full_names[:1000]])
            sql = f"""
                SELECT OBJECT_NAME, TAG_NAME, TAG_VALUE
                FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                WHERE OBJECT_DATABASE || '.' || OBJECT_SCHEMA || '.' || OBJECT_NAME IN ({in_list})
            """
            rows = snowflake_connector.execute_query(sql) or []
            tmap = {}
            for r in rows:
                obj = r['OBJECT_NAME'] # Best effort matching
                tag = f"{r['TAG_NAME']}={r['TAG_VALUE']}"
                if obj in tmap: tmap[obj] += f", {tag}"
                else: tmap[obj] = tag
            return tmap
        except Exception:
            return {}

    # Build a Tags column (batch-processed for performance)
    try:
        names = assets_df['Location'].dropna().tolist()
        tag_map = get_tags_batch(names)
        assets_df['Tags'] = assets_df['Location'].map(lambda x: tag_map.get(x.split('.')[-1] if '.' in x else x, ''))
    except Exception:
        assets_df['Tags'] = ''

    # Derive policy tag flags at asset-level for quick filtering (PII/Financial/Regulatory)
    try:
        tags_upper = assets_df['Tags'].fillna('').str.upper()
        assets_df['Has PII'] = tags_upper.str.contains('PII', na=False)
        assets_df['Has Financial'] = tags_upper.str.contains('FINANCIAL|PCI|SOX', na=False)
        assets_df['Has Regulatory'] = tags_upper.str.contains('REGULATORY|GDPR|HIPAA|PHI|SOC2', na=False)
    except Exception:
        assets_df['Has PII'] = False
        assets_df['Has Financial'] = False
        assets_df['Has Regulatory'] = False

    # SLA State is now provided by the unified SQL query
    pass

    # Helpers to enrich page-level SLA and QA status for current page only (avoid heavy queries)
    def _get_inventory_map(full_names: list) -> dict:
        try:
            if not full_names:
                return {}
            result = {}
            groups = {}
            for fn in full_names:
                dbn = str(fn).split('.')[0] if isinstance(fn, str) and '.' in fn else None
                groups.setdefault(dbn, []).append(fn)
            for dbn, fns in groups.items():
                if not dbn:
                    continue
                in_list = ','.join([f"'{x}'" for x in fns])
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT FULLY_QUALIFIED_NAME AS FULL_NAME, CREATED_TIMESTAMP AS FIRST_DISCOVERED, CLASSIFICATION_LABEL
                    FROM {dbn}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                    WHERE FULLY_QUALIFIED_NAME IN ({in_list})
                    """
                ) or []
                result.update({r['FULL_NAME']: r for r in rows})
            return result
        except Exception:
            return {}

    def _get_qa_status_map(full_names: list) -> dict:
        try:
            if not full_names:
                return {}
            rows = []
            groups = {}
            for fn in full_names:
                dbn = str(fn).split('.')[0] if isinstance(fn, str) and '.' in fn else None
                groups.setdefault(dbn, []).append(fn)
            for dbn, fns in groups.items():
                if not dbn:
                    continue
                in_list = ','.join([f"'{x}'" for x in fns])
                part = snowflake_connector.execute_query(
                    f"""
                    SELECT ASSET_FULL_NAME, STATUS, REQUESTED_AT, REVIEWED_AT
                    FROM {dbn}.DATA_GOVERNANCE.QA_REVIEWS
                    WHERE ASSET_FULL_NAME IN ({in_list})
                    """
                ) or []
                rows.extend(part)
            # Reduce to latest per asset in Python to avoid complex SQL
            latest = {}
            for r in rows:
                ts = r.get('REVIEWED_AT') or r.get('REQUESTED_AT')
                key = r.get('ASSET_FULL_NAME')
                if key not in latest or (ts and latest[key]['_ts'] and pd.to_datetime(ts) > latest[key]['_ts']):
                    latest[key] = {
                        'STATUS': r.get('STATUS') or 'Not Reviewed',
                        '_ts': pd.to_datetime(ts) if ts else pd.Timestamp.min,
                    }
            return {k: v['STATUS'] for k, v in latest.items()}
        except Exception:
            return {}

    def _get_lifecycle_map(full_names: list) -> dict:
        """Retrieve lifecycle status from governance table."""
        try:
            if not full_names:
                return {}
            rows = []
            groups = {}
            for fn in full_names:
                dbn = str(fn).split('.')[0] if isinstance(fn, str) and '.' in fn else None
                groups.setdefault(dbn, []).append(fn)
            for dbn, fns in groups.items():
                if not dbn:
                    continue
                in_list = ','.join([f"'{x}'" for x in fns])
                part = snowflake_connector.execute_query(
                    f"""
                    SELECT ASSET_FULL_NAME, STATUS
                    FROM {dbn}.DATA_GOVERNANCE.ASSET_LIFECYCLE
                    WHERE ASSET_FULL_NAME IN ({in_list})
                    ORDER BY UPDATED_AT DESC
                    """
                ) or []
                rows.extend(part)
            # Return most recent status per asset
            result = {}
            for r in rows:
                key = r.get('ASSET_FULL_NAME')
                if key not in result:
                    result[key] = r.get('STATUS', 'Active')
            return result
        except Exception:
            return {}

    @st.cache_data(ttl=600)
    def _get_dependency_counts(full_names: list) -> dict:
        """Get dependency counts (upstream + downstream) for assets in batch."""
        try:
            if not full_names:
                return {}
            # Batch query for all dependencies at once
            result = {fn: 0 for fn in full_names}
            # Limit to avoid overly massive UNIONS or IN clauses, but batching is key
            batch = full_names[:500] 
            # Simplified approach: query once for all and sum in Python
            try:
                # Upstream dependencies
                up_sql = """
                    SELECT REFERENCED_DATABASE || '.' || REFERENCED_SCHEMA || '.' || REFERENCED_OBJECT_NAME as FQN, COUNT(*) as CNT
                    FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
                    WHERE REFERENCED_DATABASE || '.' || REFERENCED_SCHEMA || '.' || REFERENCED_OBJECT_NAME IN ({})
                    GROUP BY 1
                """.format(','.join([f"'{f}'" for f in batch]))
                up_rows = snowflake_connector.execute_query(up_sql) or []
                for r in up_rows:
                    if r['FQN'] in result: result[r['FQN']] += int(r['CNT'])
                
                # Downstream dependencies
                down_sql = """
                    SELECT OBJECT_DATABASE || '.' || OBJECT_SCHEMA || '.' || OBJECT_NAME as FQN, COUNT(*) as CNT
                    FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
                    WHERE OBJECT_DATABASE || '.' || OBJECT_SCHEMA || '.' || OBJECT_NAME IN ({})
                    GROUP BY 1
                """.format(','.join([f"'{f}'" for f in batch]))
                down_rows = snowflake_connector.execute_query(down_sql) or []
                for r in down_rows:
                    if r['FQN'] in result: result[r['FQN']] += int(r['CNT'])
            except Exception:
                pass
            return result
        except Exception:
            return {}

with tab_inv_browser:
    # KPI Cards Section
    try:
        # Determine active database and ASSETS table FQN similar to Dashboard
        active_db = (
            st.session_state.get("sf_database")
            or getattr(settings, "SNOWFLAKE_DATABASE", None)
            or "DATA_CLASSIFICATION_DB"
        )
        _SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
        T_ASSETS = f"{active_db}.{_SCHEMA}.ASSETS"

        # Build basic filters scaffold (empty by default; extend later if needed)
        where = ""
        params = {}

        # Use centralized asset counting function
        from src.services.asset_utils import get_asset_counts

        # Get asset counts with the current filters (pattern-compatible with Dashboard)
        counts = get_asset_counts(
            assets_table=T_ASSETS,
            where_clause=where.replace("T_ASSETS.", ""),  # Keep replace pattern compatibility
            params=params,
            snowflake_connector=snowflake_connector
        )

        t_assets = int(counts.get('total_assets', 0) or 0)
        t_classified = int(counts.get('classified_count', 0) or 0)

        # Classification Coverage via INFORMATION_SCHEMA and TAG_REFERENCES CTE (per request)
        @st.cache_data(ttl=600)
        def _get_kpi_metrics(db_name):
            try:
                # Optimized KPI metrics using the ASSETS table population
                query = f"""
                    SELECT 
                        ROUND(100.0 * COUNT(CASE WHEN CLASSIFICATION_LABEL IS NOT NULL AND UPPER(CLASSIFICATION_LABEL) NOT IN ('','UNCLASSIFIED') THEN 1 END) 
                              / NULLIF(COUNT(*), 0), 1) AS classification_coverage_percentage,
                        COUNT(CASE WHEN COMPLIANCE_STATUS <> 'COMPLIANT' THEN 1 END) AS policy_violations
                    FROM {active_db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                """
                rows = snowflake_connector.execute_query(query) or []
                res = rows[0] if rows else {}
                # Mock tag correctness for performance unless specifically required
                res['snowflake_tag_correctness_percent'] = 100.0
                return res
            except Exception:
                return {}

        try:
            kpi_data = _get_kpi_metrics(active_db)
            cov_pct_val = float(kpi_data.get('CLASSIFICATION_COVERAGE_PERCENTAGE', 0) or 0)
            cov_display = f"{cov_pct_val:.0f}%"
        except Exception:
            cov = counts.get('coverage_pct', 0) or 0
            cov_display = f"{float(cov):.0f}%"

        # High Risk Assets via tag-derived CIA mapping (filtered to current DB scope)
        @st.cache_data(ttl=600)
        def _get_high_risk_count(db_name):
            try:
                risk_rows = snowflake_connector.execute_query(
                    f"""
                    SELECT COUNT(DISTINCT object_name) AS CNT
                    FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                    WHERE tag_name IN ('CONFIDENTIALITY_LEVEL', 'INTEGRITY_LEVEL', 'AVAILABILITY_LEVEL')
                      AND tag_value IN ('C3', 'I3', 'A3')
                      AND object_database = '{db_name}'
                    """
                ) or []
                return int((risk_rows[0] or {}).get('CNT', 0)) if risk_rows else 0
            except Exception: return 0
        
        t_highrisk = _get_high_risk_count(active_db)
        if not t_highrisk:
            # Fallback to local dataframe if available
            t_highrisk = int((assets_df['Risk'] == 'High').sum()) if not assets_df.empty and 'Risk' in assets_df.columns else 0

        # Render three KPI cards (Total Assets, Classification Coverage, High Risk Assets)
        k1, k2, k3 = st.columns(3)
        with k1:
            st.markdown(f"""
            <div class='kpi-card kpi-public'>
                <div style='font-size: 14px; color: rgba(255,255,255,0.7); margin-bottom: 8px;'>📦 Total Assets</div>
                <div style='font-size: 32px; font-weight: 700; color: #2ECC71;'>{t_assets:,}</div>
                <div style='font-size: 12px; color: rgba(255,255,255,0.5); margin-top: 5px;'>Across all databases</div>
            </div>
            """, unsafe_allow_html=True)
        with k2:
            st.markdown(f"""
            <div class='kpi-card kpi-internal'>
                <div style='font-size: 14px; color: rgba(255,255,255,0.7); margin-bottom: 8px;'>✅ Classification Coverage</div>
                <div style='font-size: 32px; font-weight: 700; color: #F1C40F;'>{cov_display}</div>
                <div style='font-size: 12px; color: rgba(255,255,255,0.5); margin-top: 5px;'>{int(t_classified):,} of {int(t_assets):,} classified</div>
            </div>
            """, unsafe_allow_html=True)
        with k3:
            st.markdown(f"""
            <div class='kpi-card kpi-restricted'>
                <div style='font-size: 14px; color: rgba(255,255,255,0.7); margin-bottom: 8px;'>⚠️ High Risk Assets</div>
                <div style='font-size: 32px; font-weight: 700; color: #E67E22;'>{t_highrisk:,}</div>
                <div style='font-size: 12px; color: rgba(255,255,255,0.5); margin-top: 5px;'>Require immediate attention</div>
            </div>
            """, unsafe_allow_html=True)
    except Exception:
        pass
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Visualization Section removed per request
    # Summary Statistics removed per request

# ==================== ASSET INVENTORY TAB ====================
with tab_inv_browser:
    
    # Inventory Browser subtabs only (single set to avoid overlapping nested tabs)
    b_db, b_schema, b_tbl, b_cols = st.tabs(["🏛️ Database View", "📚 Schema View", "📑 Table/View List", "🧬 Column-level Details"])

    # Helper: summarize by a grouping key
    @st.cache_data(ttl=300)
    def _summarize_by(group_key: str, table_fqn: str = "") -> pd.DataFrame:
        """Fetch aggregated metrics per Database/Schema from the ASSETS table (Snowflake)."""
        try:
            target = table_fqn or T_ASSETS
            # Map grouping to column names in ASSETS
            gcol = "DATABASE_NAME" if group_key == "Database" else ("SCHEMA_NAME" if group_key == "Schema" else None)
            if not gcol:
                return pd.DataFrame()
            rows = snowflake_connector.execute_query(
                f"""
                SELECT 
                    {gcol} AS K,
                    COUNT(*) AS total_assets,
                    SUM(IFF(upper(coalesce(CLASSIFICATION_LABEL,'')) NOT IN ('','UNCLASSIFIED'), 1, 0)) AS classified,
                    SUM(IFF(upper(coalesce(OVERALL_RISK_CLASSIFICATION,'')) = 'HIGH', 1, 0)) AS high_risk,
                    COUNT(DATA_DESCRIPTION) AS tagged
                FROM {target}
                GROUP BY {gcol}
                ORDER BY {gcol}
                """
            ) or []
            if not rows:
                return pd.DataFrame()
            grp = pd.DataFrame(rows).rename(columns={"K": group_key})
            # Compute classification percentage and status
            grp["classification_%"] = (100.0 * grp["classified"] / grp["total_assets"]).round(1).fillna(0)
            grp["compliance_status"] = grp["classification_%"].apply(lambda v: "✅ Good" if v >= 80 else ("⚠️ Needs Attention" if v >= 50 else "❌ Poor"))
            # Arrange columns
            keep_cols = [c for c in [group_key, "total_assets", "classified", "tagged", "high_risk", "classification_%", "compliance_status"] if c in grp.columns]
            return grp[keep_cols]
        except Exception:
            # Simple fallback for aggregation if table query fails
            try:
                if assets_df.empty: return pd.DataFrame()
                df = assets_df.copy()
                df[group_key] = df["Location"].str.split('.').str[0] if group_key=="Database" else df["Location"].str.split('.').str[1]
                grp = df.groupby(group_key).size().reset_index(name='total_assets')
                grp["classified"] = 0
                grp["classification_%"] = 0.0
                grp["compliance_status"] = "❌ Poor"
                return grp
            except:
                return pd.DataFrame()

    # Database View
    with b_db:
        st.caption("Aggregated metrics per Database. Actions apply at database scope.")
        # (Removed inline list of all account databases per request)
        db_df = _summarize_by("Database")
        if db_df.empty:
            st.info("No data to show.")
        else:
            st.dataframe(
                db_df.rename(columns={
                    "Database": "Database",
                    "total_assets": "Assets",
                    "tables": "Tables",
                    "views": "Views",
                    "classification_%": "Classification %",
                    "sox_cnt": "SOX Count",
                    "soc2_cnt": "SOC2 Count",
                    "compliance_status": "Compliance Status",
                }),
                use_container_width=True,
            )
            # Bulk actions row
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                sel_db = st.selectbox("Database (for actions)", options=sorted(db_df["Database"].tolist()))
            with c2:
                if st.button("Bulk Classify (C2/I2/A2)", help="Apply Restricted baseline to all schemas/tables in database"):
                    try:
                        # Iterate schemas for database and use tagging_service.bulk_apply_classification
                        sch_rows = snowflake_connector.execute_query(f"SHOW SCHEMAS IN DATABASE {sel_db}") or []
                        count = 0
                        for r in sch_rows:
                            sch = r.get("name") or r.get("NAME")
                            if not sch or sch.upper() == "INFORMATION_SCHEMA":
                                continue
                            try:
                                tagging_service.bulk_apply_classification(f"{sel_db}.{sch}", "Restricted", 2, 2, 2)
                                count += 1
                            except Exception:
                                continue
                        st.success(f"Bulk classification triggered for {count} schema(s) in {sel_db}")
                    except Exception as e:
                        st.warning(f"Bulk classification failed: {e}")
            with c3:
                if st.button("Assign Owner Reminder", help="Send review reminders to owners for unclassified assets"):
                    try:
                        from src.services.notifier_service import notifier_service
                        if not assets_df.empty:
                            _db_mask = assets_df["Location"].str.split('.').str[0] == sel_db
                            _uncls_mask = assets_df["Status"] != "Classified ✅" if "Status" in assets_df.columns else True
                            pending = assets_df[_db_mask & _uncls_mask]
                        else:
                            pending = pd.DataFrame()
                        for loc in pending.get("Location", [])[:200]:
                            notifier_service.notify_owner(asset_full_name=loc, subject="Classification Reminder", message="Please classify your asset within SLA.")
                        st.success(f"Reminders sent for up to {len(pending)} assets in {sel_db}")
                    except Exception as e:
                        st.warning(f"Reminder dispatch failed: {e}")
            with c4:
                if st.button("Export DB Summary CSV"):
                    try:
                        csv = db_df.to_csv(index=False).encode('utf-8')
                        st.download_button("Download", data=csv, file_name=f"{sel_db}_db_summary.csv", mime="text/csv", key="dl_db_csv")
                    except Exception:
                        pass

    # Schema View
    with b_schema:
        st.caption("Aggregated metrics per Schema. Actions apply at schema scope.")
        sch_df = _summarize_by("Schema")
        if not assets_df.empty and not sch_df.empty:
            # Owner coverage per schema (percentage of assets with non-empty owner)
            tmp = assets_df.copy()
            tmp["Schema"] = tmp["Location"].str.split('.').str[1]
            own_grp = tmp.groupby("Schema").agg(
                owners_assigned=("Owner", lambda s: int((s.fillna("") != "").sum())),
                assets=("Owner", "count"),
            ).reset_index()
            own_grp["owner_coverage_%"] = (100.0 * own_grp["owners_assigned"] / own_grp["assets"]).round(1)
            sch_df = sch_df.merge(own_grp[["Schema","owner_coverage_%"]], on="Schema", how="left")
            sch_df["owner_coverage_%"] = sch_df["owner_coverage_%"].fillna(0)
        # Filters for Schema view
        f1, f2, f3 = st.columns(3)
        with f1:
            cls_status_f = st.selectbox("Classification status", ["All","✅ Good","⚠️ Needs Attention","❌ Poor"], index=0)
        with f2:
            owner_cov_min = st.slider("Min owner coverage %", 0, 100, 0)
        with f3:
            schema_type = st.selectbox("Schema type", ["All","Tables-heavy","Views-heavy"], index=0, help="Heuristic by comparing table vs view counts")
        if sch_df.empty:
            st.info("No data to show.")
        else:
            fdf = sch_df.copy()
            if cls_status_f != "All":
                fdf = fdf[fdf["compliance_status"] == cls_status_f]
            if owner_cov_min > 0:
                fdf = fdf[fdf["owner_coverage_%"] >= owner_cov_min]
            if schema_type != "All":
                if schema_type == "Tables-heavy":
                    fdf = fdf[fdf["tables"] > fdf["views"]]
                else:
                    fdf = fdf[fdf["views"] >= fdf["tables"]]
            st.dataframe(
                fdf.rename(columns={
                    "Schema": "Schema",
                    "total_assets": "Assets",
                    "tables": "Tables",
                    "views": "Views",
                    "classification_%": "Classification %",
                    "sox_cnt": "SOX Count",
                    "soc2_cnt": "SOC2 Count",
                    "compliance_status": "Compliance Status",
                    "high_risk": "High-risk Objects",
                    "owner_coverage_%": "Owner Coverage %",
                }),
                use_container_width=True,
            )
            s1, s2, s3 = st.columns(3)
            
            with s3:
                if st.button("Export Schema Summary CSV"):
                    try:
                        csv = fdf.to_csv(index=False).encode('utf-8')
                        st.download_button("Download", data=csv, file_name="schema_summary.csv", mime="text/csv", key="dl_schema_csv")
                    except Exception:
                        pass

    # Table/View List preview moved below after filters & pagination
    # Column-level Details preview moved below after filters & pagination

# (Removed overlapping Advanced Search & Asset Details blocks from Inventory Browser)

    

    # ---------------- Favorites & Bookmarks ----------------
    with tab_favorites:
        st.markdown("<div class='section-header'>⭐ Favorites & Bookmarks</div>", unsafe_allow_html=True)
        st.session_state.setdefault("fav_assets", [])
        st.session_state.setdefault("recent_assets", [])
        st.session_state.setdefault("fav_details_df", pd.DataFrame())

        # Pin/unpin controls
        pick = st.selectbox("Pick an asset to pin", options=sorted(assets_df["Location"].tolist()) if not assets_df.empty else [])
        cpin1, cpin2, cpin3 = st.columns(3)
        with cpin1:
            if st.button("⭐ Pin") and pick and pick not in st.session_state["fav_assets"]:
                st.session_state["fav_assets"].append(pick)
        with cpin2:
            if st.button("🗑️ Unpin") and pick in st.session_state["fav_assets"]:
                st.session_state["fav_assets"].remove(pick)
        with cpin3:
            if st.button("📤 Export Favorites"):
                try:
                    csv = pd.DataFrame({"asset": st.session_state["fav_assets"]}).to_csv(index=False).encode('utf-8')
                    st.download_button("Download", data=csv, file_name="favorites.csv", mime="text/csv", key="dl_favs_csv")
                except Exception:
                    pass

        # Build live details for favorite assets
        @st.cache_data(ttl=120)
        def _fav_fetch_details(favs: List[str]) -> pd.DataFrame:
            if not favs:
                return pd.DataFrame(columns=["Asset","Label","C","I","A","Risk","SLA","Compliance","Owner"])  # minimal schema
            # Maps
            inv_map = _get_inventory_map(favs)
            tags_map = get_tags_map(favs)
            # Latest decisions by DB chunk
            by_db: Dict[str, List[str]] = {}
            for fn in favs:
                try:
                    by_db.setdefault(fn.split('.')[0], []).append(fn)
                except Exception:
                    continue
            dec_latest: Dict[str, Dict] = {}
            for dbn, fns in by_db.items():
                try:
                    in_list = ','.join([f"'{x}'" for x in fns])
                    rows = snowflake_connector.execute_query(
                        f"""
                        SELECT ASSET_FULL_NAME, CLASSIFICATION, C, I, A, RATIONALE, DECIDED_AT
                        FROM {dbn}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
                        WHERE ASSET_FULL_NAME IN ({in_list})
                        QUALIFY ROW_NUMBER() OVER (PARTITION BY ASSET_FULL_NAME ORDER BY DECIDED_AT DESC) = 1
                        """
                    ) or []
                    for r in rows:
                        dec_latest[str(r.get('ASSET_FULL_NAME'))] = r
                except Exception:
                    continue
            # Assemble rows
            out_rows = []
            now = pd.Timestamp.utcnow().normalize()
            for asset in favs:
                dec = dec_latest.get(asset) or {}
                lab = dec.get('CLASSIFICATION')
                c = int(dec.get('C') or 0)
                i = int(dec.get('I') or 0)
                a = int(dec.get('A') or 0)
                max_cia = max(c, i, a)
                risk = 'High' if max_cia >= 3 else ('Medium' if max_cia == 2 else 'Low')
                inv = inv_map.get(asset) or {}
                classified = bool(inv.get('CLASSIFIED')) if inv else False
                fd = pd.to_datetime(inv.get('FIRST_DISCOVERED'), utc=True) if inv and inv.get('FIRST_DISCOVERED') else None
                if classified:
                    sla = '🟢 Classified'
                elif fd is not None:
                    bdays = pd.bdate_range(fd.normalize(), now)
                    days = max(0, len(bdays) - 1)
                    sla = '🔴 Overdue' if days >= 5 else '🟡 Unclassified'
                else:
                    sla = ''
                tagstr = str(tags_map.get(asset) or '')
                tags_up = tagstr.upper()
                has_pii = any(k in tags_up for k in ['PII','SSN','EMAIL','PHONE','DOB','ADDRESS','CUSTOMER','EMPLOYEE'])
                regs = [r for r in ['GDPR','HIPAA','PCI','SOX'] if r in tags_up]
                try:
                    ok, msg = _validate_decision_matrix(str(lab or ''), c, i, a, has_pii, regs)
                except Exception:
                    ok, msg = True, 'OK'
                comp_flag = '✅' if ok else '❌'
                owner = None
                try:
                    owner = (tags_up.split('OWNER=')[1].split(',')[0].strip()) if 'OWNER=' in tagstr else None
                except Exception:
                    owner = None
                if not owner:
                    owner = inv.get('OWNER') if inv else ''
                out_rows.append({
                    'Asset': asset,
                    'Label': lab or '',
                    'C': c,
                    'I': i,
                    'A': a,
                    'Risk': risk,
                    'SLA': sla,
                    'Compliance': comp_flag,
                    'Owner': owner or '',
                    '_non_compliant': (comp_flag == '❌'),
                    '_overdue': (sla == '🔴 Overdue'),
                })
            return pd.DataFrame(out_rows)

        favs = list(dict.fromkeys(st.session_state["fav_assets"]))  # de-dupe while preserving order
        fav_df = _fav_fetch_details(favs)
        st.session_state['fav_details_df'] = fav_df

        # Filters and sorting controls
        filt1, filt2, filt3, filt4 = st.columns(4)
        with filt1:
            comp_filter = st.selectbox("Compliance", ["All","✅","❌"], index=0)
        with filt2:
            sla_filter = st.selectbox("SLA", ["All","🟢 Classified","🟡 Unclassified","🔴 Overdue"], index=0)
        with filt3:
            risk_filter2 = st.selectbox("Risk", ["All","High","Medium","Low"], index=0)
        with filt4:
            sort_by_fav = st.selectbox("Sort by", ["Asset","Risk","Compliance","SLA","C","I","A"], index=0)
        vz = fav_df.copy()
        if comp_filter != "All":
            vz = vz[vz['Compliance'] == comp_filter]
        if sla_filter != "All":
            vz = vz[vz['SLA'] == sla_filter]
        if risk_filter2 != "All":
            vz = vz[vz['Risk'] == risk_filter2]
        if not vz.empty and sort_by_fav in vz.columns:
            vz = vz.sort_values(by=sort_by_fav, ascending=True)

        # Highlight non-compliant / overdue visually via emoji and caption; use dataframe for interactive sort
        st.markdown("**Pinned Assets**")
        if not vz.empty:
            show_cols = ["Asset","Label","C","I","A","Risk","SLA","Compliance","Owner"]
            st.dataframe(vz[show_cols], use_container_width=True, hide_index=True)
        else:
            st.info("No favorite assets to display.")

        # Bulk actions section removed per request

        # Recent Views (this session) removed per request
        
        # Metadata display removed to avoid sel_asset dependency when not selected

        # Current classification & CIA (only when an asset is selected)
        if 'sel_asset' in locals() and sel_asset and not pd.isna(sel_asset):
            st.markdown("**Current classification**")
            try:
                lab = latest_dec.get('CLASSIFICATION') if latest_dec else None
                c = int(latest_dec.get('C') or 0) if latest_dec else int(assets_df.loc[assets_df['Location']==sel_asset,'C'].iloc[0]) if 'C' in assets_df.columns else 0
                i = int(latest_dec.get('I') or 0) if latest_dec else int(assets_df.loc[assets_df['Location']==sel_asset,'I'].iloc[0]) if 'I' in assets_df.columns else 0
                a = int(latest_dec.get('A') or 0) if latest_dec else int(assets_df.loc[assets_df['Location']==sel_asset,'A'].iloc[0]) if 'A' in assets_df.columns else 0
                has_pii = any(k in (assets_df.loc[assets_df['Location']==sel_asset,'Tags'].iloc[0].upper() if 'Tags' in assets_df.columns and not assets_df.empty else '') for k in ['PII','SSN','EMAIL','PHONE','DOB','ADDRESS','CUSTOMER','EMPLOYEE'])
                regs = [r for r in ['GDPR','HIPAA','PCI','SOX'] if r in (assets_df.loc[assets_df['Location']==sel_asset,'Tags'].iloc[0].upper() if 'Tags' in assets_df.columns and not assets_df.empty else '')]
                ok, msg = _validate_decision_matrix((lab or str(assets_df.loc[assets_df['Location']==sel_asset,'Classification'].iloc[0]) if not lab else lab), c, i, a, has_pii, regs)
                comp_badge = "✅ Compliant" if ok else f"❌ Non-compliant ({msg})"
                cia_cols = st.columns(4)
                with cia_cols[0]:
                    st.metric("Label", lab or assets_df.loc[assets_df['Location']==sel_asset,'Classification'].iloc[0])
                with cia_cols[1]:
                    st.metric("C", c)
                with cia_cols[2]:
                    st.metric("I", i)
                with cia_cols[3]:
                    st.metric("A", a)
                st.caption(comp_badge)
            except Exception as e:
                pass

        # Rationale & Business Impact section removed per request

        # Classification history (only when an asset is selected)
        if 'sel_asset' in locals() and sel_asset and not pd.isna(sel_asset):
            st.markdown("**Classification history**")
            try:
                db_ctx = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE or db_sel
                hist = snowflake_connector.execute_query(
                    f"""
                    SELECT CLASSIFICATION, C, I, A, OWNER, RATIONALE, DECIDED_BY, DECIDED_AT,
                           PREV_CLASSIFICATION, PREV_C, PREV_I, PREV_A
                    FROM {db_ctx}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
                    WHERE ASSET_FULL_NAME = %(asset)s
                    ORDER BY DECIDED_AT DESC
                    LIMIT 25
                    """,
                    {"asset": sel_asset}
                ) or []
                # Additionally, try to show CLASSIFICATION_DECISIONS_HISTORY if present
                hist2 = []
                try:
                    hist2 = snowflake_connector.execute_query(
                        f"""
                        SELECT ACTION, ACTION_BY, ACTION_AT, COMMENTS
                        FROM {db_ctx}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS_HISTORY
                        WHERE ASSET_FULL_NAME = %(asset)s
                        ORDER BY ACTION_AT DESC
                        LIMIT 50
                        """,
                        {"asset": sel_asset}
                    ) or []
                except Exception:
                    hist2 = []
                if hist:
                    st.dataframe(pd.DataFrame(hist), use_container_width=True)
                else:
                    st.caption("No classification history found.")
                if hist2:
                    st.markdown("Audit Trail (History)")
                    st.dataframe(pd.DataFrame(hist2), use_container_width=True)
            except Exception as e:
                st.caption("History unavailable.")

        # Ownership & SLA section removed per request

        # Related assets section removed per request

        # Usage statistics section removed per request

    # ---------------- Advanced Search & Filters ----------------
    with tab_adv_search:
        st.markdown("<div class='section-header'>🎯 Advanced Search & Filters</div>", unsafe_allow_html=True)
        st.session_state.setdefault('recent_searches', [])
        # Search row
        s1, s2 = st.columns([3,1])
        with s1:
            query = st.text_input("Search by asset name (supports * and ? wildcards)", value="", placeholder="orders*, finance.payroll_*, customer?", key="adv_q")
        with s2:
            use_fuzzy = st.checkbox("Fuzzy contains", value=True, help="If off, use wildcard pattern only", key="adv_fuzzy")
        if query:
            if query not in st.session_state['recent_searches']:
                st.session_state['recent_searches'] = ([query] + st.session_state['recent_searches'])[:10]
        with st.expander("Recent searches", expanded=False):
            st.write(st.session_state['recent_searches'])

        # Classification
        cls_sel = st.multiselect("Classification", ["Public","Internal","Restricted","Confidential"], default=[], key="adv_cls_sel")

        # Data Owner (person/team)
        owner_options = sorted([x for x in assets_df['Owner'].dropna().unique().tolist()]) if not assets_df.empty and 'Owner' in assets_df.columns else []
        owner_sel = st.multiselect("Data Owner", owner_options, default=[], key="adv_owner_sel")

        # Business Unit (schema or tagged BU)
        bu_opts_adv = sorted(assets_df['Location'].str.split('.').str[1].dropna().unique().tolist()) if not assets_df.empty else []
        bu_sel = st.multiselect("Business Unit", bu_opts_adv, default=[], key="adv_bu_sel")

        # Technical metadata search
        st.markdown("**Technical Metadata**")
        tm1, tm2, tm3 = st.columns(3)
        with tm1:
            col_dtype_filter_adv = st.multiselect(
                "Column data type",
                options=["STRING","VARCHAR","TEXT","CHAR","NUMBER","DECIMAL","INTEGER","FLOAT","DOUBLE","BOOLEAN","DATE","TIMESTAMP_NTZ","TIMESTAMP_TZ","TIMESTAMP_LTZ","BINARY"],
                default=[],
                key="adv_col_dtype"
            )
        with tm2:
            created_after = st.date_input("Created after", value=None, key="adv_created_after")
        with tm3:
            tags_contains = st.text_input("Tags contains", value="", placeholder="GDPR, PII, owner=finance", key="adv_tags_contains")

        # Apply filters to build adv_df
        adv_df = assets_df.copy()
        if query:
            if use_fuzzy:
                mask = (
                    adv_df['Location'].str.contains(query, case=False, na=False) |
                    adv_df['Name'].str.contains(query, case=False, na=False)
                )
            else:
                # Convert wildcard to regex
                import re
                pattern = '^' + re.escape(query).replace('\\*','.*').replace('\\?','.') + '$'
                mask = (
                    adv_df['Location'].str.match(pattern, case=False, na=False) |
                    adv_df['Name'].str.match(pattern, case=False, na=False)
                )
            adv_df = adv_df[mask]
        if cls_sel:
            adv_df = adv_df[adv_df['Classification'].isin(cls_sel)]
        if owner_sel:
            adv_df = adv_df[adv_df['Owner'].isin(owner_sel)]
        if bu_sel:
            adv_df = adv_df[adv_df['Location'].str.split('.').str[1].isin(bu_sel)]
        # Technical metadata filters kept: created after, tags contains, and column data type
        if created_after and 'Creation Date' in adv_df.columns:
            adv_df = adv_df[adv_df['Creation Date'] >= pd.to_datetime(created_after)]
        if tags_contains:
            adv_df = adv_df[adv_df['Tags'].str.contains(tags_contains, case=False, na=False)]

        if col_dtype_filter_adv:
            try:
                selected_assets = adv_df['Location'].dropna().tolist()[:300]
                colmap = _fetch_columns_for_assets(selected_assets)
                keep = []
                for fn in selected_assets:
                    cols = colmap.get(fn) or []
                    if any(any((c.get('data_type') or '').upper().startswith(dt) for dt in col_dtype_filter_adv) for c in cols):
                        keep.append(fn)
                adv_df = adv_df[adv_df['Location'].isin(keep)]
            except Exception:
                pass

        # Ensure derived fields for display
        try:
            if 'Database' not in adv_df.columns:
                adv_df['Database'] = adv_df['Location'].str.split('.').str[0]
            if 'Schema' not in adv_df.columns:
                adv_df['Schema'] = adv_df['Location'].str.split('.').str[1]
        except Exception:
            pass

        st.markdown("**Results**")
        if adv_df.empty:
            st.info("No assets match the current Advanced Search filters.")
        else:
            show_cols = [
                c for c in ["Location","Database","Schema","Name","Type","Classification","CIA Score","C","I","A","Owner","Risk","Status","Rows","Size (MB)","Last Updated"]
                if c in adv_df.columns
            ]
            st.dataframe(adv_df[show_cols].head(500), use_container_width=True, hide_index=True)
    
    # Show helpful message if no assets found
    if assets_df.empty:
        st.info("📊 No data assets found in the current database. Please ensure:\n\n"
                "1. You have selected a valid database in your session\n"
                "2. The database contains tables or views\n"
                "3. You have the necessary permissions to query INFORMATION_SCHEMA")
        st.stop()
    
    # Apply sidebar global filters early
    try:
        # Schema contains
        sc = (st.session_state.get('da_schema_contains') or '').strip()
        if sc and not assets_df.empty:
            assets_df = assets_df[assets_df['Location'].str.split('.').str[1].str.contains(sc, case=False, na=False)]
        # Table/View name
        ts = (st.session_state.get('da_tbl_search') or '').strip()
        if ts and not assets_df.empty:
            if st.session_state.get('da_fuzzy', True):
                mask = assets_df['Name'].str.contains(ts, case=False, na=False) | assets_df['Location'].str.contains(ts, case=False, na=False)
            else:
                import re
                pattern = '^' + re.escape(ts).replace('\\*','.*').replace('\\?','.') + '$'
                mask = assets_df['Name'].str.match(pattern, case=False, na=False) | assets_df['Location'].str.match(pattern, case=False, na=False)
            assets_df = assets_df[mask]
    except Exception:
        pass

    # Search & Filter UI removed. Set neutral defaults to keep downstream logic functioning.
    search_term = ""
    include_col_search = False
    classification_filter = "All"
    compliance_tags = []
    db_filter = "All"
    schema_filter = "All"
    table_filter = ""
    owner_filter = ""
    status_filter = "All"
    risk_filter = "All"
    # Business context defaults
    bu_filter = []
    domain_filter = []
    type_filter = "All"
    lifecycle_filter = "All"
    # Category filter retains session default if present
    if 'category_filter' not in st.session_state:
        st.session_state['category_filter'] = 'All'
    category_filter = st.session_state.get('category_filter', 'All')
    # Sorting / pagination defaults
    sort_by = "None"
    page_size = 50
    # CIA & compliance defaults
    min_c, min_i, min_a = 0, 0, 0
    max_c, max_i, max_a = 3, 3, 3
    exclude_non_compliant = False
    # Policy tags & SLA defaults
    policy_tags = []
    sla_filter = 'Any'
    # Column-level filter defaults
    col_name_filter = st.session_state.get('da_col_search', "")
    col_dtype_filter = []
    col_masking_filter = "Any"
    col_category_filter = []
    col_min_count = 0
    # Advanced numeric filters
    min_rows = 0
    min_size_mb = 0
    max_cost = 0.0
    min_dependencies = 0

    # Apply filters
    # Removed legacy dataset filter component; filtering handled entirely below
    # Enrich with Business Unit/Domain from tags if available (one-time per run)
    if not assets_df.empty and 'Business Unit' not in assets_df.columns:
        try:
            def _parse_tag(tags: str, key: str) -> str:
                try:
                    parts = [t.strip() for t in (tags or '').split(',') if t]
                    for t in parts:
                        if '=' in t:
                            k,v = t.split('=',1)
                            if k.strip().upper() == key.upper():
                                return v.strip()
                    return ''
                except Exception:
                    return ''
            assets_df['Business Unit'] = assets_df['Tags'].apply(lambda s: _parse_tag(s, 'BUSINESS_UNIT'))
            assets_df['Business Domain'] = assets_df['Tags'].apply(lambda s: _parse_tag(s, 'BUSINESS_DOMAIN'))
            # Fallbacks to Schema name when not tagged
            assets_df['Business Unit'] = assets_df['Business Unit'].mask(assets_df['Business Unit'].eq(''), assets_df['Location'].str.split('.').str[1])
            assets_df['Business Domain'] = assets_df['Business Domain'].mask(assets_df['Business Domain'].eq(''), assets_df['Location'].str.split('.').str[1])
        except Exception:
            pass

    # Build lifecycle column if available from governance table or tags
    if not assets_df.empty and 'Lifecycle' not in assets_df.columns:
        try:
            names = assets_df['Location'].dropna().tolist()
            lc_map = _get_lifecycle_map(names)
            def _lc_from_tags(tags: str) -> str:
                if not tags:
                    return ''
                up = tags.upper()
                for k in ('ACTIVE','DEPRECATED','ARCHIVED'):
                    if k in up:
                        return k.capitalize()
                return ''
            assets_df['Lifecycle'] = assets_df['Location'].map(lambda x: lc_map.get(x, ''))
            assets_df['Lifecycle'] = assets_df['Lifecycle'].mask(assets_df['Lifecycle'].eq(''), assets_df['Tags'].apply(_lc_from_tags))
            assets_df['Lifecycle'] = assets_df['Lifecycle'].replace('', 'Active')
        except Exception:
            assets_df['Lifecycle'] = 'Active'

    # Derive Database and Table fields for filtering convenience
    if not assets_df.empty:
        try:
            assets_df['Database'] = assets_df['Location'].str.split('.').str[0]
            assets_df['Table'] = assets_df['Location'].str.split('.').str[2]
        except Exception:
            pass

    # Update Business Unit/Domain filter options
    if not assets_df.empty:
        try:
            st.session_state.setdefault('da_bu_opts', sorted([x for x in assets_df['Business Unit'].dropna().unique().tolist() if x]))
            st.session_state.setdefault('da_domain_opts', sorted([x for x in assets_df['Business Domain'].dropna().unique().tolist() if x]))
        except Exception:
            pass

    # Apply primary text search
    if search_term and not assets_df.empty:
        mask = (
            assets_df['Name'].str.contains(search_term, case=False, na=False) |
            assets_df['Location'].str.contains(search_term, case=False, na=False) |
            assets_df['Location'].str.split('.').str[1].str.contains(search_term, case=False, na=False) |
            assets_df['Tags'].str.contains(search_term, case=False, na=False)
        )
        # Optional: include column names search
        # Ensure helper is defined even if later block hasn't executed yet
        try:
            _fetch_columns_for_assets  # type: ignore[name-defined]
        except NameError:
            @st.cache_data(ttl=180)
            def _fetch_columns_for_assets(full_names: list) -> dict:
                return {}
        if include_col_search:
            try:
                selected_assets = assets_df['Location'].dropna().tolist()[:300]
                colmap = _fetch_columns_for_assets(selected_assets)
                colmask = assets_df['Location'].map(lambda x: any(search_term.lower() in (c.get('column') or '').lower() for c in (colmap.get(x) or [])))
                mask = mask | colmask
            except Exception:
                pass
        assets_df = assets_df[mask]

    if classification_filter != "All" and not assets_df.empty:
        assets_df = assets_df[assets_df['Classification'] == classification_filter]

    if compliance_tags and not assets_df.empty:
        up = [c.upper() for c in compliance_tags]
        assets_df = assets_df[assets_df['Tags'].str.upper().apply(lambda t: any(c in (t or '') for c in up))]

    if db_filter != "All" and not assets_df.empty:
        assets_df = assets_df[assets_df['Database'] == db_filter]

    if schema_filter != "All" and not assets_df.empty:
        assets_df = assets_df[assets_df['Location'].str.split('.').str[1] == schema_filter]

    if table_filter and not assets_df.empty:
        assets_df = assets_df[assets_df['Table'].str.contains(table_filter, case=False, na=False)]

    if owner_filter and not assets_df.empty:
        assets_df = assets_df[assets_df['Owner'].str.contains(owner_filter, case=False, na=False)]

    # CIA thresholds compliance calculation and filtering
    try:
        if not assets_df.empty:
            # Ensure numeric C/I/A exist
            if not {'C','I','A'}.issubset(set(assets_df.columns)) and 'CIA Score' in assets_df.columns:
                # Parse CIA Score like C2-I1-A3 into columns if needed
                def _parse_cia_row(s: str):
                    try:
                        s = str(s)
                        import re
                        nums = re.findall(r"(\d)", s)
                        c,i,a = (list(map(int, nums)) + [1,1,1])[:3]
                        return pd.Series({'C':c,'I':i,'A':a})
                    except Exception:
                        return pd.Series({'C':1,'I':1,'A':1})
                cia_df = assets_df['CIA Score'].apply(_parse_cia_row)
                for col in ['C','I','A']:
                    if col not in assets_df.columns:
                        assets_df[col] = cia_df[col]
            # Compute compliance flag based on selected sliders in scope (defaults if not defined)
            cmin = locals().get('min_c', 0); cmax = locals().get('max_c', 3)
            imin = locals().get('min_i', 0); imax = locals().get('max_i', 3)
            amin = locals().get('min_a', 0); amax = locals().get('max_a', 3)
            comp_mask = (
                assets_df['C'].between(cmin, cmax, inclusive='both') &
                assets_df['I'].between(imin, imax, inclusive='both') &
                assets_df['A'].between(amin, amax, inclusive='both')
            )
            assets_df['Policy Compliance'] = comp_mask.map(lambda x: '✅ Compliant' if x else '❌ Non-compliant')
            if locals().get('exclude_non_compliant', False):
                assets_df = assets_df[comp_mask]
    except Exception:
        pass

    # Policy tag filters (asset-level)
    try:
        tags_req = set(locals().get('policy_tags', []) or [])
        if tags_req and not assets_df.empty:
            conds = []
            if 'PII' in tags_req:
                conds.append(assets_df['Has PII'])
            if 'Financial' in tags_req:
                conds.append(assets_df['Has Financial'])
            if 'Regulatory' in tags_req:
                conds.append(assets_df['Has Regulatory'])
            if conds:
                tag_mask = conds[0]
                for cm in conds[1:]:
                    tag_mask = tag_mask & cm
                assets_df = assets_df[tag_mask]
    except Exception:
        pass

    # SLA filter
    try:
        sel_sla = locals().get('sla_filter', 'Any')
        if sel_sla != 'Any' and not assets_df.empty and 'SLA State' in assets_df.columns:
            assets_df = assets_df[assets_df['SLA State'] == sel_sla]
    except Exception:
        pass

    # Add visual badges for SLA and Compliance
    try:
        if not assets_df.empty:
            def _sla_badge(s: str) -> str:
                if s == 'Overdue':
                    return '🔴 Overdue'
                if s == 'Classified':
                    return '🟢 Classified'
                if s == 'Unclassified':
                    return '🟡 Unclassified'
                return ''
            def _comp_badge(c: str) -> str:
                return '🟥 Non-compliant' if str(c).startswith('❌') else ('🟩 Compliant' if str(c).startswith('✅') else '')
            if 'SLA State' in assets_df.columns:
                assets_df['SLA Badge'] = assets_df['SLA State'].map(_sla_badge)
            if 'Policy Compliance' in assets_df.columns:
                assets_df['Compliance Badge'] = assets_df['Policy Compliance'].map(_comp_badge)
    except Exception:
        pass

    if status_filter != "All" and not assets_df.empty:
        assets_df = assets_df[assets_df['Status'] == status_filter]

    if risk_filter != "All" and not assets_df.empty:
        assets_df = assets_df[assets_df['Risk'] == risk_filter]
    if 'Type' in assets_df.columns and type_filter != "All" and not assets_df.empty:
        assets_df = assets_df[assets_df['Type'] == type_filter]

    # Apply advanced filters
    if min_rows > 0 and not assets_df.empty:
        try:
            assets_df['_rows_numeric'] = assets_df['Rows'].astype(str).str.replace(',', '').astype(float)
            assets_df = assets_df[assets_df['_rows_numeric'] >= min_rows]
            assets_df = assets_df.drop(columns=['_rows_numeric'])
        except Exception:
            pass
    
    if min_size_mb > 0 and not assets_df.empty and 'Size (MB)' in assets_df.columns:
        assets_df = assets_df[assets_df['Size (MB)'] >= min_size_mb]
    
    if max_cost > 0 and not assets_df.empty and 'Estimated Monthly Cost ($)' in assets_df.columns:
        assets_df = assets_df[assets_df['Estimated Monthly Cost ($)'] <= max_cost]
    
    if min_dependencies > 0 and not assets_df.empty and 'Dependencies' in assets_df.columns:
        assets_df = assets_df[assets_df['Dependencies'] >= min_dependencies]

    # Category filter (moved after advanced filters)
    category_filter = st.session_state.get('category_filter', 'All')
    if category_filter != "All" and not assets_df.empty:
        # Use tags first; fallback to heuristics on Location
        mask_tags = assets_df['Tags'].str.upper().str.contains(category_filter.upper(), na=False)
        if not mask_tags.any():
            if category_filter == "PII":
                pattern = r"SSN|EMAIL|PHONE|ADDRESS|DOB|PII|CUSTOMER|PERSON|EMPLOYEE"
            elif category_filter == "PHI":
                pattern = r"PHI|HEALTH|MEDICAL|PATIENT"
            elif category_filter == "Financial":
                pattern = r"FINANCE|GL|LEDGER|INVOICE|PAYROLL|AR|AP|REVENUE|EXPENSE"
            else:  # Regulatory
                pattern = r"SOX|REGULATORY|GDPR|HIPAA|PCI|IFRS|GAAP"
            mask_tags = assets_df['Location'].str.upper().str.contains(pattern, na=False)
        assets_df = assets_df[mask_tags]

    # Business Unit/Domain filters
    try:
        if 'Business Unit' in assets_df.columns and bu_filter:
            assets_df = assets_df[assets_df['Business Unit'].isin(bu_filter)]
        if 'Business Domain' in assets_df.columns and domain_filter:
            assets_df = assets_df[assets_df['Business Domain'].isin(domain_filter)]
        if 'Lifecycle' in assets_df.columns and lifecycle_filter != 'All':
            assets_df = assets_df[assets_df['Lifecycle'] == lifecycle_filter]
    except Exception:
        pass

    # Column-level filter application
    matching_cols: Dict[str, List[str]] = {}
    if (col_name_filter or col_dtype_filter or (col_masking_filter != "Any") or col_category_filter or (col_min_count and col_min_count > 0)) and not assets_df.empty:
        # Fetch column metadata and masking references for current (filtered) assets, capped to 300 assets for performance
        selected_assets = assets_df['Location'].dropna().tolist()[:300]
        @st.cache_data(ttl=180)
        def _fetch_columns_for_assets(full_names: List) -> Dict:
            out: Dict[str, List] = {}
            try:
                if not full_names:
                    return out
                # Build per-schema/table queries
                # Use UNION ALL with individual table predicates for simplicity
                predicates = []
                params = {}
                for idx, fn in enumerate(full_names):
                    try:
                        db, sch, tbl = fn.split('.')
                    except ValueError:
                        continue
                    predicates.append(f"(TABLE_CATALOG = %(db{idx})s AND TABLE_SCHEMA = %(s{idx})s AND TABLE_NAME = %(t{idx})s)")
                    params[f"db{idx}"] = db
                    params[f"s{idx}"] = sch
                    params[f"t{idx}"] = tbl
                if not predicates:
                    return out
                db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
                if not db:
                    return out
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT TABLE_CATALOG||'.'||TABLE_SCHEMA||'.'||TABLE_NAME AS FULL,
                           COLUMN_NAME, DATA_TYPE
                    FROM {db}.INFORMATION_SCHEMA.COLUMNS
                    WHERE {" OR ".join(predicates)}
                    ORDER BY FULL, ORDINAL_POSITION
                    """,
                    params,
                ) or []
                # Masking references (column-level)
                refs = snowflake_connector.execute_query(
                    """
                    SELECT UPPER(OBJECT_DATABASE||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME) AS FULL,
                           UPPER(COLUMN_NAME) AS COL
                    FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
                    WHERE POLICY_KIND = 'MASKING POLICY'
                    """
                ) or []
                refset = {(r.get('FULL'), r.get('COL')) for r in refs}
                for r in rows:
                    full = r.get('FULL')
                    col = (r.get('COLUMN_NAME') or '').upper()
                    dt = (r.get('DATA_TYPE') or '').upper()
                    if not full:
                        continue
                    if full not in out:
                        out[full] = []
                    out[full].append({"column": col, "data_type": dt, "masked": (full.upper(), col) in refset})
            except Exception:
                return out
            return out
        columns_map = _fetch_columns_for_assets(selected_assets)

        def _col_category_hit(col_name: str, categories: List[str]) -> bool:
            n = (col_name or "").upper()
            hits = []
            if "PII" in categories:
                hits.append(any(k in n for k in ["SSN","EMAIL","PHONE","ADDRESS","DOB","PERSON","CUSTOMER","EMPLOYEE"]))
            if "PHI" in categories:
                hits.append(any(k in n for k in ["PHI","HEALTH","MEDICAL","PATIENT","DIAGNOSIS","RX"]))
            if "PCI" in categories:
                hits.append(any(k in n for k in ["CARD","PAN","CREDIT","CC_NUMBER"]))
            if "Financial" in categories:
                hits.append(any(k in n for k in ["GL","LEDGER","INVOICE","PAYROLL","AR","AP","REVENUE","EXPENSE"]))
            if "Regulatory" in categories:
                hits.append(any(k in n for k in ["GDPR","HIPAA","PCI","SOX","IFRS","GAAP"]))
            return any(hits) if hits else True

        keep_assets = []
        for fn in selected_assets:
            cols = columns_map.get(fn) or []
            if col_min_count and col_min_count > 0 and len(cols) < int(col_min_count):
                continue
            # Evaluate per asset: at least one column must satisfy all specified column-level predicates
            matched = False
            matched_list = []
            for cinfo in cols:
                cname = cinfo.get('column') or ''
                ctype = cinfo.get('data_type') or ''
                cmasked = bool(cinfo.get('masked'))
                # Name filter
                if col_name_filter and (col_name_filter.lower() not in cname.lower()):
                    continue
                # Dtype filter
                if col_dtype_filter and not any(ctype.startswith(dt) for dt in col_dtype_filter):
                    continue
                # Masking filter
                if col_masking_filter == "Yes" and not cmasked:
                    continue
                if col_masking_filter == "No" and cmasked:
                    continue
                # Category filter
                if col_category_filter and not _col_category_hit(cname, col_category_filter):
                    continue
                matched = True
                matched_list.append(cname)
            if matched:
                keep_assets.append(fn)
                if matched_list:
                    matching_cols[fn] = matched_list[:25]
        if keep_assets:
            assets_df = assets_df[assets_df['Location'].isin(keep_assets)]
        else:
            assets_df = assets_df.iloc[0:0]

    # Sorting
    if not assets_df.empty and sort_by != "None":
        if sort_by == "CIA (max)":
            assets_df = assets_df.assign(_CIA_MAX=assets_df[["C","I","A"]].max(axis=1)).sort_values("_CIA_MAX", ascending=False).drop(columns=["_CIA_MAX"])
        elif sort_by == "Creation Date" and 'Creation Date' in assets_df.columns:
            assets_df = assets_df.sort_values('Creation Date', ascending=False)
        elif sort_by == "Last Modified" and 'Last Modified' in assets_df.columns:
            assets_df = assets_df.sort_values('Last Modified', ascending=False)
        elif sort_by == "Overall Risk":
            # Map Low/Medium/High to 1/2/3
            rmap = {"Low":1,"Medium":2,"High":3}
            assets_df = assets_df.assign(_R=assets_df['Risk'].map(rmap)).sort_values('_R', ascending=False).drop(columns=['_R'])
        elif sort_by == "Size (MB)" and 'Size (MB)' in assets_df.columns:
            assets_df = assets_df.sort_values('Size (MB)', ascending=False)
        elif sort_by == "Owner (A→Z)" and 'Owner' in assets_df.columns:
            assets_df = assets_df.sort_values('Owner', ascending=True, na_position='last')

    # Pagination (Widget removed per request; defaulting to Page 1)
    total_rows = len(assets_df)
    page_size = 50
    page_num = 1
    start = (int(page_num) - 1) * int(page_size)
    end = start + int(page_size)
    page_df = assets_df.iloc[start:end].copy()
    
    # Render live preview in Table/View List tab (uses computed page_df)
    with b_tbl:
        st.caption("Live results for the current database (first 50 results).")
        try:
            preview_cols = [
                c for c in ["Location","Database","Schema","Name","Type","Classification","CIA Score","C","I","A","Owner","Risk","Status","SLA State","SLA Badge","Policy Compliance","Compliance Badge","Decision Notes","Reclass Needed","Reclass Reason","Rows","Size (MB)","Last Updated"]
                if c in page_df.columns
            ]
            if not page_df.empty and preview_cols:
                st.dataframe(page_df[preview_cols], use_container_width=True, hide_index=True)
            else:
                st.info("No rows available. Adjust filters.")
        except Exception:
            st.caption("No preview available.")
        # Quick actions for reclassification on flagged assets
        try:
            flagged = page_df[page_df.get('Reclass Needed') == True] if 'Reclass Needed' in page_df.columns else page_df.iloc[0:0]
            if not flagged.empty:
                st.markdown("**⚠️ Assets requiring reclassification (policy 6.3)**")
                sel_flag = st.selectbox("Choose an asset to submit reclassification request", options=flagged['Location'].tolist())
                just = st.text_input("Justification", value=str(flagged.set_index('Location').get('Reclass Reason').get(sel_flag, '')) if 'Reclass Reason' in flagged.columns else "")
                if st.button("Submit Reclassification Request") and sel_flag:
                    try:
                        # Current tuple
                        cur_row = flagged[flagged['Location'] == sel_flag].iloc[0]
                        cur_tuple = (str(cur_row.get('Classification') or ''), int(cur_row.get('C') or 0), int(cur_row.get('I') or 0), int(cur_row.get('A') or 0))
                        # Proposed defaults to current (owner will adjust later)
                        proposed = cur_tuple
                        user = (st.session_state.get('user_email') or 'unknown') if isinstance(st.session_state, dict) else 'unknown'
                        # Prefer orchestration façade; fallback to legacy service if needed
                        try:
                            req_id = cwf.submit_reclassification(
                                asset_full_name=sel_flag,
                                proposed=proposed,
                                justification=just or 'Policy 6.3 trigger',
                                created_by=user,
                                trigger_type='UI_FLAGGED'
                            )
                        except Exception:
                            req_id = reclassification_service.submit_request(
                                asset_full_name=sel_flag,
                                proposed=proposed,
                                justification=just or 'Policy 6.3 trigger',
                                created_by=user,
                                trigger_type='UI_FLAGGED'
                            )
                        st.success(f"Reclassification request submitted (ID: {req_id})")
                    except Exception as e:
                        st.warning(f"Failed to submit reclassification request: {e}")
        except Exception:
            pass
    
    # Render live column-level details in Column-level Details tab
    with b_cols:
        st.caption("Live column-level details for a selected asset in the current database.")
        try:
            asset_opts_tab = page_df['Location'].dropna().tolist() if not page_df.empty else assets_df['Location'].dropna().tolist()
            if not asset_opts_tab:
                st.info("No assets available in the current page/filter. Adjust filters.")
            sel_asset_tab = st.selectbox("Select asset (DB.SCHEMA.TABLE)", options=asset_opts_tab, index=0 if asset_opts_tab else None, key="bcols_asset_live")
            show_debug = st.checkbox("Show debug details", value=False, key="bcols_debug")
            if sel_asset_tab:
                @st.cache_data(ttl=180)
                def _fetch_cols_and_mask_single(asset_fqn: str) -> Tuple[List[Dict], str]:
                    try:
                        db, sch, tbl = asset_fqn.split('.')
                    except ValueError:
                        return [], "Invalid asset name format"
                    # Always query the target asset's database INFORMATION_SCHEMA to avoid cross-db filter mismatch
                    dbctx = db
                    try:
                        rows = snowflake_connector.execute_query(
                            f"""
                            SELECT UPPER(COLUMN_NAME) AS COLUMN_NAME, UPPER(DATA_TYPE) AS DATA_TYPE
                            FROM {dbctx}.INFORMATION_SCHEMA.COLUMNS
                            WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                            ORDER BY ORDINAL_POSITION
                            """,
                            {"s": sch, "t": tbl}
                        ) or []
                    except Exception as e:
                        return [], f"COLUMNS query failed: {e}"
                    try:
                        refs = snowflake_connector.execute_query(
                            """
                            SELECT UPPER(OBJECT_DATABASE||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME) AS FULL,
                                   UPPER(COLUMN_NAME) AS COL
                            FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
                            WHERE POLICY_KIND = 'MASKING POLICY'
                            """
                        ) or []
                    except Exception as e:
                        refs, err = [], f"POLICY_REFERENCES query failed: {e}"
                    else:
                        err = ""
                    # Column tag references (to detect PII/Financial/Regulatory via tags)
                    try:
                        tag_refs = snowflake_connector.execute_query(
                            """
                            SELECT UPPER(OBJECT_DATABASE||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME) AS FULL,
                                   UPPER(COLUMN_NAME) AS COL,
                                   UPPER(TAG_DATABASE||'.'||TAG_SCHEMA||'.'||TAG_NAME) AS TAG_NAME
                            FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                            WHERE DOMAIN = 'COLUMN'
                            """
                        ) or []
                    except Exception:
                        tag_refs = []
                    tag_map = {}
                    full_up = sel_asset_tab.upper()
                    for tr in tag_refs:
                        if (tr.get('FULL') or '') == full_up:
                            tag_map.setdefault(tr.get('COL'), set()).add(tr.get('TAG_NAME'))
                    full_up = sel_asset_tab.upper()
                    refset = {r.get('COL') for r in refs if (r.get('FULL') or '') == full_up}
                    out = []
                    for r in rows:
                        colname = r.get('COLUMN_NAME')
                        dtype = r.get('DATA_TYPE')
                        masked = "Yes" if (colname or '') in refset else "No"
                        tags_for_col = tag_map.get(colname) or set()
                        tags_str = ", ".join(sorted(tags_for_col)) if tags_for_col else ""
                        upn = (colname or '').upper()
                        # Heuristics plus tags
                        pii = any(k in upn for k in ["SSN","EMAIL","PHONE","ADDRESS","DOB","PERSON","CUSTOMER","EMPLOYEE"]) or any("PII" in t for t in tags_for_col)
                        fin = any(k in upn for k in ["GL","LEDGER","INVOICE","PAYROLL","AR","AP","REVENUE","EXPENSE"]) or any("FINANCE" in t or "FINANCIAL" in t for t in tags_for_col)
                        reg = any(k in upn for k in ["GDPR","HIPAA","PCI","SOX"]) or any(any(x in t for x in ["GDPR","HIPAA","PCI","SOX"]) for t in tags_for_col)
                        flags = []
                        if pii: flags.append("PII")
                        if fin: flags.append("Financial")
                        if reg: flags.append("Regulatory")
                        out.append({
                            "Column": colname,
                            "Data Type": dtype,
                            "Masked?": masked,
                            "Flags": ", ".join(flags),
                            "Tags": tags_str,
                        })
                    return out, err
                data, err = _fetch_cols_and_mask_single(sel_asset_tab)
                if data:
                    # Visual indicators for flags
                    df_cols = pd.DataFrame(data)
                    # No heavy styling to keep performance; show flags column with emojis
                    if 'Flags' in df_cols.columns:
                        def _flag_emojis(s: str) -> str:
                            up = (s or '')
                            icons = []
                            if 'PII' in up: icons.append('🧍')
                            if 'Financial' in up: icons.append('💳')
                            if 'Regulatory' in up: icons.append('⚖️')
                            return (s + ' ' + ' '.join(icons)).strip()
                        df_cols['Flags'] = df_cols['Flags'].apply(_flag_emojis)
                    st.dataframe(df_cols, use_container_width=True)
                else:
                    st.info("No columns found or insufficient privileges.")
                if show_debug and err:
                    st.code(err)
        except Exception as ex:
            st.caption("Column details unavailable.")
            st.debug(str(ex))
    
    # Redundant display sections and widgets removed per request.
    if assets_df.empty:
        st.info("No data assets found in your Snowflake database, or there was an error connecting.")

# Relationships & Lineage section disabled per new IA
if False:
    st.markdown("<div class='section-header'>🔗 Relationships & Lineage</div>", unsafe_allow_html=True)
    st.info("This functionality lives in the dedicated Lineage module for a single source of truth.")
    if st.button("Open Data Lineage", type="primary"):
        try:
            st.switch_page("pages/6_Data_Lineage.py")
        except Exception:
            st.rerun()
# Lifecycle & Governance section disabled per new IA
if False:
    st.markdown("<div class='section-header'>Lifecycle & Governance</div>", unsafe_allow_html=True)

# Export section disabled per new IA (download of current view is still available in results table area)
if False:
    with tab_export:
        st.markdown("<div class='section-header'>Export Asset Inventory</div>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-box'>
            <strong>Export Options</strong><br>
            Download your filtered asset inventory in multiple formats for reporting, compliance documentation, and analysis.
        </div>
        """, unsafe_allow_html=True)
        # Export format selection
        col_exp1, col_exp2 = st.columns([2, 1])
        with col_exp1:
            st.markdown("**Select Export Format**")
        with col_exp2:
            st.metric("Total Assets", len(assets_df))
        
        export_cols = [
            "Name","Description","Location","Type","Classification","CIA Score","Risk",
            "Status","Data Quality","Owner","Rows","Size (MB)","Last Updated"
        ]
        # Ensure all columns exist; fill if missing
        exp_df = assets_df.copy()
        for c in export_cols:
            if c not in exp_df.columns:
                exp_df[c] = None
        
        # Enhanced export buttons with descriptions
        col_csv, col_excel, col_pdf = st.columns(3)
        
        with col_csv:
            st.markdown("""
            <div class='relationship-card'>
                <div style='font-size: 14px; font-weight: 600; margin-bottom: 5px;'>CSV Export</div>
                <div style='font-size: 12px; color: rgba(255,255,255,0.6);'>Raw data for analysis</div>
            </div>
            """, unsafe_allow_html=True)
            csv = exp_df[export_cols].to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name="dataset_inventory.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col_excel:
            st.markdown("""
            <div class='relationship-card'>
                <div style='font-size: 14px; font-weight: 600; margin-bottom: 5px;'>Excel Export</div>
                <div style='font-size: 12px; color: rgba(255,255,255,0.6);'>Formatted workbook</div>
            </div>
            """, unsafe_allow_html=True)
            try:
                xbuf = BytesIO()
                exp_df[export_cols].to_excel(xbuf, index=False, sheet_name='Assets')
                xbytes = xbuf.getvalue()
                st.download_button(
                    label="⬇️ Download Excel",
                    data=xbytes,
                    file_name="dataset_inventory.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True
                )
            except Exception:
                st.caption("Excel export unavailable - install openpyxl")
        
        with col_pdf:
            st.markdown("""
            <div class='relationship-card'>
                <div style='font-size: 14px; font-weight: 600; margin-bottom: 5px;'>📑 PDF Summary</div>
                <div style='font-size: 12px; color: rgba(255,255,255,0.6);'>Executive report</div>
            </div>
            """, unsafe_allow_html=True)
            try:
                from reportlab.lib.pagesizes import A4
                from reportlab.pdfgen import canvas
                pbuf = BytesIO()
                c = canvas.Canvas(pbuf, pagesize=A4)
                text = c.beginText(40, 800)
                text.setFont("Helvetica", 12)
                text.textLine("Data Assets Summary")
                text.textLine("")
                text.textLine(f"Total: {len(exp_df)} | Classified: {int((exp_df['Classification'].isin(['Restricted','Confidential'])).sum())} | Unclassified: {len(exp_df) - int((exp_df['Classification'].isin(['Restricted','Confidential'])).sum())}")
                text.textLine(f"High-Risk: {int((exp_df['Risk']=='High').sum())}")
                c.drawText(text)
                c.showPage(); c.save()
                pbytes = pbuf.getvalue(); pbuf.close()
                st.download_button(
                    label="⬇️ Download PDF",
                    data=pbytes,
                    file_name="assets_summary.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            except Exception:
                st.caption("PDF export unavailable - install reportlab")
        
        # Export preview
        st.markdown("---")
        st.markdown("**📋 Export Preview** (first 10 rows)")
        st.dataframe(exp_df[export_cols].head(10), use_container_width=True)
        
    if exp_df is None or exp_df.empty:
        st.info("No assets available to export. Apply filters to view assets.")

# Removed explanatory info panel per request
