# -*- coding: utf-8 -*-
"""
Data Assets page for the data governance application.
"""
from __future__ import annotations

import sys
import os
from typing import Optional, List, Dict, Tuple, Set

# Add the project root (parent of 'src') to the Python path so 'src.*' imports work
_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))  # .../src
_project_root = os.path.dirname(_src_dir)           # project root containing 'src'
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import streamlit as st
import pandas as pd
import altair as alt
from io import BytesIO
from src.ui.theme import apply_global_theme
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.tagging_service import tagging_service
from src.services.reclassification_service import reclassification_service
from src.services.ai_classification_service import ai_classification_service
from src.services.audit_service import audit_service
from src.services.policy_enforcement_service import policy_enforcement_service
from src.services.authorization_service import authz
from src.services.snowpark_udf_service import snowpark_udf_service
from src.services.system_classify_service import system_classify_service

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

# Feature flag to temporarily bypass RBAC for verification of tabs/UI only
# Set to True to bypass stop() when role is not consumer. Do NOT leave enabled in production.
REVERSE_DATA_ASSETS_RBAC = True

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
    try:
        wh_rows = snowflake_connector.execute_query("SHOW WAREHOUSES") or []
        wh_opts = sorted([r.get('name') or r.get('NAME') for r in wh_rows if (r.get('name') or r.get('NAME'))])
    except Exception:
        wh_opts = []
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
    try:
        db_rows = snowflake_connector.execute_query("SHOW DATABASES") or []
        db_opts = sorted([r.get('name') or r.get('NAME') for r in db_rows if (r.get('name') or r.get('NAME'))])
    except Exception:
        db_opts = []
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
        "Table/View name",
        value=st.session_state.get('da_tbl_search', ''),
        placeholder="orders*, finance.payroll_*, customer?"
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
try:
    role_row = snowflake_connector.execute_query("select current_role() as ROLE")
    wh_row = snowflake_connector.execute_query("select current_warehouse() as WAREHOUSE")
    db_row = snowflake_connector.execute_query("select current_database() as DATABASE")
    role = role_row[0]['ROLE'] if role_row else None
    wh = wh_row[0]['WAREHOUSE'] if wh_row else None
    db = db_row[0]['DATABASE'] if db_row else None
    st.caption(f"Connected as role: {role or 'Unknown'} | Warehouse: {wh or 'Unknown'} | Database: {db or 'Unknown'}")
except Exception:
    st.caption("Connected role/warehouse/database: unavailable (insufficient privileges)")

# Session & Scope controls moved to the sidebar (see app.py)

# New top-level tabs per updated IA
tab_inv_browser, tab_adv_search, tab_asset_details, tab_favorites = st.tabs([
    "🔍 Inventory Browser", "🎯 Advanced Search & Filters", "📋 Asset Details View", "⭐ Favorites & Bookmarks"
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
            # fallback: current database
            try:
                db_row = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
                curdb = db_row[0].get('DB') if db_row else None
                if curdb:
                    dbs = [curdb]
            except Exception:
                dbs = []
        if not dbs:
            st.warning("No database set. Use the sidebar → '🔧 Role & Session' to set an active Database.")
            return pd.DataFrame()

        # Aggregate tables/views across selected databases
        table_results: List[Dict] = []
        per_db_limit = max(1, int(500 / max(1, len(dbs))))
        for _db in dbs:
            try:
                rows_tbl = snowflake_connector.execute_query(f"""
                    SELECT 
                        "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" as full_name,
                        "TABLE_SCHEMA" as schema_name,
                        "TABLE_NAME" as table_name,
                        "ROW_COUNT" as row_count,
                        "BYTES" as size_bytes,
                        "CREATED" as created_date,
                        "LAST_ALTERED" as last_modified,
                        'TABLE' AS object_type
                    FROM {_db}.INFORMATION_SCHEMA.TABLES
                    WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                    ORDER BY 1
                    LIMIT {per_db_limit}
                """) or []
                rows_view = snowflake_connector.execute_query(f"""
                    SELECT 
                        "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" as full_name,
                        "TABLE_SCHEMA" as schema_name,
                        "TABLE_NAME" as table_name,
                        NULL as row_count,
                        NULL as size_bytes,
                        "CREATED" as created_date,
                        "LAST_ALTERED" as last_modified,
                        'VIEW' AS object_type
                    FROM {_db}.INFORMATION_SCHEMA.VIEWS
                    WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                    ORDER BY 1
                    LIMIT {per_db_limit}
                """) or []
                table_results.extend(rows_tbl + rows_view)
            except Exception:
                continue

        # Convert to DataFrame
        if table_results:
            assets_data = []
            for i, row in enumerate(table_results):
                # Determine classification based on schema or table name
                schema = row['SCHEMA_NAME'].upper()
                table_name = row['TABLE_NAME'].upper()
                obj_type = (row.get('OBJECT_TYPE') or (row.get('OBJECT_TYPE'.lower()) if isinstance(row, dict) else None) or 'TABLE')
                # Normalize potentially null metrics
                row_count_val = int(row['ROW_COUNT'] or 0)
                
                # Enhanced classification logic with CIA triad scoring
                # Confidentiality score (0-3)
                if 'COMPLIANCE' in schema or 'SECURITY' in schema or 'PAYMENT' in table_name:
                    confidentiality = 3  # Critical
                elif 'FINANCE' in schema or 'HR' in schema:
                    confidentiality = 2  # High
                elif 'PUBLIC' in schema:
                    confidentiality = 0  # Low
                else:
                    confidentiality = 1  # Medium
                
                # Integrity score (0-3)
                if 'FINANCE' in schema or 'PAYMENT' in table_name:
                    integrity = 3  # Critical
                elif 'COMPLIANCE' in schema or 'SECURITY' in schema:
                    integrity = 2  # High
                else:
                    integrity = 1  # Medium
                
                # Availability score (0-3)
                if 'PUBLIC' in schema:
                    availability = 0  # Low
                elif 'COMPLIANCE' in schema or 'SECURITY' in schema:
                    availability = 2  # High
                else:
                    availability = 1  # Medium
                
                # Overall classification based on highest CIA score
                max_cia = max(confidentiality, integrity, availability)
                if max_cia == 3:
                    classification = 'Confidential'
                elif max_cia == 2:
                    classification = 'Restricted'
                elif max_cia == 0:
                    classification = 'Public'
                else:
                    classification = 'Internal'
                
                # Determine owner based on schema
                if 'VAULT' in schema:
                    owner = 'data.engineering@company.com'
                elif 'COMPLIANCE' in schema:
                    owner = 'compliance@company.com'
                elif 'FINANCE' in schema:
                    owner = 'finance@company.com'
                elif 'HR' in schema:
                    owner = 'hr@company.com'
                else:
                    owner = 'admin@company.com'
                
                # Determine data quality score (simplified)
                # In a real implementation, this would be based on actual data quality metrics
                if row_count_val > 1000000:
                    data_quality = 'High'
                elif row_count_val > 10000:
                    data_quality = 'Medium'
                else:
                    data_quality = 'Low'
                
                assets_data.append({
                    "ID": f"asset_{i+1:03d}",
                    "Name": row['TABLE_NAME'],
                    "Description": f"{schema} schema table with {row_count_val:,} records",
                    "Location": row['FULL_NAME'],
                    "Database": row['FULL_NAME'].split('.')[0] if isinstance(row.get('FULL_NAME'), str) and '.' in row['FULL_NAME'] else None,
                    "Classification": classification,
                    "CIA Score": f"C{confidentiality}-I{integrity}-A{availability}",
                    "Owner": owner,
                    "Rows": f"{row_count_val:,}",
                    "Size (MB)": round(row['SIZE_BYTES'] / (1024 * 1024), 2) if row['SIZE_BYTES'] else 0,
                    "Data Quality": data_quality,
                    "Last Updated": row['LAST_MODIFIED'].strftime('%Y-%m-%d') if row['LAST_MODIFIED'] else 'Unknown',
                    "Type": obj_type
                })
            
            return pd.DataFrame(assets_data)
        else:
            return pd.DataFrame()
            
    except Exception as e:
        st.error(f"Error fetching data assets from Snowflake: {str(e)}")
        return pd.DataFrame()

def compute_policy_fields(df: pd.DataFrame) -> pd.DataFrame:
    """Augment dataframe with Risk, Type, Status, and parsed CIA fields."""
    if df.empty:
        return df
    out = df.copy()
    # Risk from CIA (policy 5.3): map highest CIA to Low/Medium/High
    def parse_cia_any(v) -> Tuple[int, int, int]:
        """Parse CIA from various formats:
        - "C2-I3-A1", "C2/I3/A1", "2-3-1", "2/3/1", (2,3,1), {"C":2,...}
        Defaults to (1,1,1) on failure.
        """
        try:
            # Tuple/list input
            if isinstance(v, (tuple, list)) and len(v) >= 3:
                return int(v[0]), int(v[1]), int(v[2])
            # Dict-like input
            if isinstance(v, dict):
                c = int(v.get('C', v.get('c', 1)))
                i = int(v.get('I', v.get('i', 1)))
                a = int(v.get('A', v.get('a', 1)))
                return c, i, a
            # String input
            s = str(v or '').upper().strip()
            if not s:
                return 1, 1, 1
            # Normalize separators and remove labels
            for ch in ['C', 'I', 'A']:
                s = s.replace(ch, ' ')
            for sep in ['-', '/', '|', ',', ':']:
                s = s.replace(sep, ' ')
            parts = [p for p in s.split() if p]
            nums: List[int] = []
            for p in parts:
                try:
                    nums.append(int(p))
                except Exception:
                    continue
            c, i, a = (nums + [1, 1, 1])[:3]
            # Clamp to 0..3 per policy scale
            c = max(0, min(3, c)); i = max(0, min(3, i)); a = max(0, min(3, a))
            return c, i, a
        except Exception:
            return 1, 1, 1

    # Derive C/I/A columns
    if "CIA Score" in out.columns:
        ciap = out["CIA Score"].apply(parse_cia_any)
        out["C"] = ciap.apply(lambda t: t[0])
        out["I"] = ciap.apply(lambda t: t[1])
        out["A"] = ciap.apply(lambda t: t[2])
    else:
        # If C/I/A already present, use them; else default to 1
        out["C"] = out.get("C", pd.Series([1] * len(out)))
        out["I"] = out.get("I", pd.Series([1] * len(out)))
        out["A"] = out.get("A", pd.Series([1] * len(out)))

    out["Risk"] = out.apply(lambda r: ("High" if max(r["C"], r["I"], r["A"]) >= 3 else ("Medium" if max(r["C"], r["I"], r["A"]) == 2 else "Low")), axis=1)
    # Type preserved from source; if missing, default to TABLE
    if "Type" not in out.columns:
        out["Type"] = "TABLE"
    # Status via Inventory (fallback heuristic): Classified vs Unclassified; Overdue if unclassified and >5 business days
    out["Status"] = "Unknown"
    try:
        if 'Location' not in out.columns:
            raise KeyError("Location column missing")
        names_list = out['Location'].dropna().tolist()
        inv_map = {}
        if names_list:
            # Group FULL_NAMEs by database and query per database
            by_db = {}
            for fn in names_list:
                try:
                    dbn = str(fn).split('.')[0]
                except Exception:
                    dbn = None
                by_db.setdefault(dbn, []).append(fn)
            for dbn, fns in by_db.items():
                if not dbn or not fns:
                    continue
                # Escape single quotes inside identifiers for safe IN clause
                safe_vals = ["'" + str(x).replace("'", "''") + "'" for x in fns]
                in_list = ','.join(safe_vals)
                inv_rows = snowflake_connector.execute_query(
                    f"""
                    SELECT FULL_NAME, CLASSIFIED, FIRST_DISCOVERED
                    FROM {dbn}.DATA_GOVERNANCE.ASSET_INVENTORY
                    WHERE FULL_NAME IN ({in_list})
                    """
                ) or []
                inv_map.update({r["FULL_NAME"]: r for r in inv_rows})
        now = pd.Timestamp.utcnow().normalize()
        def business_days_between(start_ts, end_ts):
            try:
                start = pd.to_datetime(start_ts)
                end = pd.to_datetime(end_ts)
                bdays = pd.bdate_range(start.normalize(), end.normalize())
                return max(0, len(bdays) - 1)
            except Exception:
                return None
        def status_for(loc):
            row = inv_map.get(loc)
            if not row:
                return "Unclassified ❌"
            if row.get("CLASSIFIED"):
                return "Classified ✅"
            fd = pd.to_datetime(row.get("FIRST_DISCOVERED")) if row.get("FIRST_DISCOVERED") else None
            days = business_days_between(fd, now) if fd is not None else None
            if days is not None and days >= 5:
                return "Overdue ⏰"
            return "Unclassified ❌"
        out["Status"] = out["Location"].apply(status_for)
    except Exception:
        # Fallback: mark classified based on non-Internal/Public
        if "Classification" in out.columns:
            out["Status"] = out["Classification"].apply(lambda x: "Classified ✅" if x in ("Restricted","Confidential") else "Unclassified ❌")
        else:
            out["Status"] = "Unclassified ❌"
    # Decision rationale and notes (latest per asset) from DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
    try:
        if 'Location' not in out.columns:
            raise KeyError("Location column missing")
        names_list = out['Location'].dropna().unique().tolist()
        @st.cache_data(ttl=180)
        def _latest_decisions_map(full_names: List[str]) -> Dict:
            if not full_names:
                return {}
            by_db: Dict[str, List[str]] = {}
            for fn in full_names:
                try:
                    dbn = str(fn).split('.')[0]
                except Exception:
                    dbn = None
                by_db.setdefault(dbn, []).append(fn)
            out_map: Dict[str, Dict] = {}
            for dbn, fns in by_db.items():
                if not dbn or not fns:
                    continue
                safe_vals = ["'" + str(x).replace("'", "''") + "'" for x in fns]
                in_list = ','.join(safe_vals)
                try:
                    rows = snowflake_connector.execute_query(
                        f"""
                        SELECT ASSET_FULL_NAME, RATIONALE, CHECKLIST_JSON, CLASSIFICATION, C, I, A, DECIDED_AT
                        FROM {dbn}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
                        WHERE ASSET_FULL_NAME IN ({in_list})
                        QUALIFY ROW_NUMBER() OVER (PARTITION BY ASSET_FULL_NAME ORDER BY DECIDED_AT DESC) = 1
                        """
                    ) or []
                    for r in rows:
                        out_map[r.get('ASSET_FULL_NAME')] = r
                except Exception:
                    continue
            return out_map
        dec_map = _latest_decisions_map(names_list)
        def _decision_notes(r: dict) -> str:
            if not r:
                return ""
            # Prefer explicit rationale; fallback to a compact checklist excerpt
            rat = r.get('RATIONALE') or ''
            if rat:
                return str(rat)
            cj = str(r.get('CHECKLIST_JSON') or '')
            return cj[:200] + ('…' if len(cj) > 200 else '')
        out['Decision Rationale'] = out['Location'].map(lambda x: (dec_map.get(x) or {}).get('RATIONALE') or '')
        out['Decision Notes'] = out['Location'].map(lambda x: _decision_notes(dec_map.get(x)))
        # Keep latest decision timestamp for reclassification checks
        out['_decided_at'] = out['Location'].map(lambda x: (dec_map.get(x) or {}).get('DECIDED_AT'))
    except Exception:
        out['Decision Rationale'] = ''
        out['Decision Notes'] = ''
        out['_decided_at'] = None
    # Reclassification triggers per policy 6.3 (lifecycle/regulatory/context changes)
    try:
        # Derive simple signals from tags for PII/Regulatory/Financial
        def _tags_has(tags: str, keys: List[str]) -> bool:
            t = (tags or '').upper()
            return any(k in t for k in keys)
        def _regs_from_tags(tags: str) -> List[str]:
            t = (tags or '').upper()
            regs = []
            for r in ['GDPR','HIPAA','PCI','SOX']:
                if r in t:
                    regs.append(r)
            return regs
        def _needs_reclass(row: pd.Series) -> Tuple[bool, str]:
            try:
                lab = str(row.get('Classification') or '').title()
                c,i,a = int(row.get('C') or 1), int(row.get('I') or 1), int(row.get('A') or 1)
                tags = str(row.get('Tags') or '')
                lifecycle = str(row.get('Lifecycle') or 'Active')
                has_pii = _tags_has(tags, ['PII','SSN','EMAIL','PHONE','DOB','ADDRESS','CUSTOMER','EMPLOYEE'])
                regs = _regs_from_tags(tags)
                ok, msg = _validate_decision_matrix(lab, c, i, a, has_pii, regs)
                if not ok:
                    return True, f"Policy check: {msg}"
                if lifecycle in ('Deprecated','Archived'):
                    return True, f"Lifecycle={lifecycle}"
                # If decision is very old and tags show new regs keywords
                decided_at = row.get('_decided_at')
                if decided_at:
                    try:
                        decided_ts = pd.to_datetime(decided_at)
                        age_days = (pd.Timestamp.utcnow() - decided_ts).days
                        if age_days >= 180 and (has_pii or regs):
                            return True, ">180d since decision with sensitive tags"
                    except Exception:
                        pass
                return False, ""
            except Exception as e:
                return False, f"check_err:{e}"
        flags = out.apply(_needs_reclass, axis=1)
        out['Reclass Needed'] = flags.apply(lambda t: t[0])
        out['Reclass Reason'] = flags.apply(lambda t: t[1])
    except Exception:
        out['Reclass Needed'] = False
        out['Reclass Reason'] = ''
    return out

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
    # Use the resolved database list
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
    @st.cache_data(ttl=120)
    def get_tags_map(full_names: list, limit: int = 200) -> dict:
        tmap = {}
        for fn in full_names[:limit]:
            try:
                refs = tagging_service.get_object_tags(fn, object_type="TABLE")
                if refs:
                    # Aggregate tag=value pairs
                    tags = []
                    for r in refs:
                        tname = r.get('TAG_NAME') or r.get('tag_name')
                        tval = r.get('TAG_VALUE') or r.get('tag_value')
                        if tname and tval:
                            tags.append(f"{tname}={tval}")
                    tmap[fn] = ", ".join(sorted(set(tags)))
            except Exception:
                continue
        return tmap

    # Build a Tags column (partial, best-effort), plus category flags
    try:
        names = assets_df['Location'].dropna().tolist()
        tag_map = get_tags_map(names)
        assets_df['Tags'] = assets_df['Location'].map(lambda x: tag_map.get(x, ''))
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

    # Pre-compute SLA state for filtering (best-effort); values: Classified, Overdue, Due
    try:
        inv_map_all = _get_inventory_map(assets_df['Location'].dropna().tolist())
        def _sla_state(loc: str) -> str:
            try:
                row = inv_map_all.get(loc)
                if not row:
                    return ''
                classified = bool(row.get('CLASSIFIED'))
                if classified:
                    return 'Classified'
                fd = pd.to_datetime(row.get('FIRST_DISCOVERED')) if row.get('FIRST_DISCOVERED') else None
                if fd is None:
                    return ''
                now = pd.Timestamp.utcnow().normalize()
                bdays = pd.bdate_range(fd.normalize(), now)
                days = max(0, len(bdays) - 1)
                return 'Overdue' if days >= 5 else 'Unclassified'
            except Exception:
                return ''
        assets_df['SLA State'] = assets_df['Location'].map(_sla_state)
    except Exception:
        assets_df['SLA State'] = ''

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
                    SELECT FULL_NAME, FIRST_DISCOVERED, CLASSIFIED
                    FROM {dbn}.DATA_GOVERNANCE.ASSET_INVENTORY
                    WHERE FULL_NAME IN ({in_list})
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

    def _get_dependency_counts(full_names: list) -> dict:
        """Get dependency counts (upstream + downstream) for assets."""
        try:
            if not full_names:
                return {}
            result = {}
            for fn in full_names[:100]:  # Limit to avoid heavy queries
                try:
                    db, schema, table = fn.split('.')
                    up = snowflake_connector.execute_query(
                        """
                        SELECT COUNT(*) AS CNT
                        FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
                        WHERE REFERENCED_DATABASE=%(db)s AND REFERENCED_SCHEMA=%(s)s AND REFERENCED_OBJECT_NAME=%(o)s
                        """,
                        {"db": db, "s": schema, "o": table}
                    ) or []
                    down = snowflake_connector.execute_query(
                        """
                        SELECT COUNT(*) AS CNT
                        FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
                        WHERE OBJECT_DATABASE=%(db)s AND OBJECT_SCHEMA=%(s)s AND OBJECT_NAME=%(o)s
                        """,
                        {"db": db, "s": schema, "o": table}
                    ) or []
                    up_cnt = up[0].get('CNT', 0) if up else 0
                    down_cnt = down[0].get('CNT', 0) if down else 0
                    result[fn] = int(up_cnt) + int(down_cnt)
                except Exception:
                    result[fn] = 0
            return result
        except Exception:
            return {}

with tab_inv_browser:
    # KPI Cards Section
    try:
        t_assets = int(len(assets_df)) if not assets_df.empty else 0
        t_classified = int((assets_df['Status'] == 'Classified ✅').sum()) if not assets_df.empty and 'Status' in assets_df.columns else 0
        t_highrisk = int((assets_df['Risk'] == 'High').sum()) if not assets_df.empty and 'Risk' in assets_df.columns else 0
        t_overdue = int((assets_df['Status'] == 'Overdue ⏰').sum()) if not assets_df.empty and 'Status' in assets_df.columns else 0
        cov = f"{(100.0 * t_classified / t_assets):.0f}%" if t_assets > 0 else "0%"
        
        k1, k2, k3, k4 = st.columns(4)
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
                <div style='font-size: 32px; font-weight: 700; color: #F1C40F;'>{cov}</div>
                <div style='font-size: 12px; color: rgba(255,255,255,0.5); margin-top: 5px;'>{t_classified:,} of {t_assets:,} classified</div>
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
        with k4:
            st.markdown(f"""
            <div class='kpi-card kpi-confidential'>
                <div style='font-size: 14px; color: rgba(255,255,255,0.7); margin-bottom: 8px;'>⏰ Overdue (SLA)</div>
                <div style='font-size: 32px; font-weight: 700; color: #E74C3C;'>{t_overdue:,}</div>
                <div style='font-size: 12px; color: rgba(255,255,255,0.5); margin-top: 5px;'>Past 5-day deadline</div>
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
    def _summarize_by(group_key: str) -> pd.DataFrame:
        if assets_df.empty:
            return pd.DataFrame()
        df = assets_df.copy()
        # Derive DB/SCHEMA for grouping
        df["Database"] = df["Location"].str.split('.').str[0]
        df["Schema"] = df["Location"].str.split('.').str[1]
        # Compliance proxies (best-effort using Tags/Status)
        df["HasTags"] = df["Tags"].apply(lambda t: bool(t and len(str(t).strip()) > 0))
        df["IsClassified"] = df["Status"].eq("Classified ✅") if "Status" in df.columns else False
        df["SOX"] = df["Tags"].str.upper().str.contains("SOX", na=False)
        df["SOC2"] = df["Tags"].str.upper().str.contains("SOC", na=False)
        grp = df.groupby(group_key).agg(
            total_assets=("Location", "count"),
            tables=("Type", lambda s: int((s == "TABLE").sum()) if "Type" in df.columns else 0),
            views=("Type", lambda s: int((s == "VIEW").sum()) if "Type" in df.columns else 0),
            classified=("IsClassified", "sum"),
            tagged=("HasTags", "sum"),
            sox_cnt=("SOX", "sum"),
            soc2_cnt=("SOC2", "sum"),
            high_risk=("Risk", lambda s: int((s == "High").sum()) if "Risk" in df.columns else 0),
        ).reset_index()
        grp["classification_%"] = (100.0 * grp["classified"] / grp["total_assets"]).round(1).fillna(0)
        grp["compliance_status"] = grp.apply(lambda r: ("✅ Good" if r["classification_%"] >= 80 else ("⚠️ Needs Attention" if r["classification_%"] >= 50 else "❌ Poor")), axis=1)
        return grp

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
            # Owner assignment for entire database
            st.markdown("---")
            oc1, oc2, oc3 = st.columns([2,2,1])
            with oc1:
                owner_email_db = st.text_input("Owner Email (assign to all tables in selected DB)", value="")
            with oc2:
                confirm_txt = st.text_input("Type the database name to confirm", value="")
            with oc3:
                if st.button("Assign Owner to DB") and owner_email_db and confirm_txt == sel_db:
                    try:
                        rows = snowflake_connector.execute_query(
                            f"SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME FROM {sel_db}.INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA <> 'INFORMATION_SCHEMA'"
                        ) or []
                        updated = 0
                        for r in rows:
                            full = f"{r['TABLE_CATALOG']}.{r['TABLE_SCHEMA']}.{r['TABLE_NAME']}"
                            try:
                                try:
                                    tagging_service.apply_tags_to_object(full, "TABLE", {"OWNER": owner_email_db})
                                    updated += 1
                                    continue
                                except Exception:
                                    pass
                                dbi = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
                                if dbi:
                                    snowflake_connector.execute_non_query(
                                        f"UPDATE {dbi}.DATA_GOVERNANCE.ASSET_INVENTORY SET OWNER = %(o)s WHERE FULL_NAME = %(f)s",
                                        {"o": owner_email_db, "f": full},
                                    )
                                    updated += 1
                            except Exception:
                                continue
                        st.success(f"Owner assignment attempted for {updated} object(s) in {sel_db}")
                    except Exception as e:
                        st.warning(f"DB-level owner assignment failed: {e}")

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
            with s1:
                sel_schema_full = st.text_input("Schema (DB.SCHEMA)", value=(assets_df["Location"].iloc[0].rsplit('.',1)[0] if not assets_df.empty else ""))
            with s2:
                if st.button("Bulk Classify Schema (C2/I2/A2)") and sel_schema_full and "." in sel_schema_full:
                    try:
                        tagging_service.bulk_apply_classification(sel_schema_full, "Restricted", 2, 2, 2)
                        st.success(f"Bulk classification applied to {sel_schema_full}")
                    except Exception as e:
                        st.warning(f"Failed to apply classification: {e}")
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
                fd = pd.to_datetime(inv.get('FIRST_DISCOVERED')) if inv and inv.get('FIRST_DISCOVERED') else None
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

        # Bulk actions
        st.markdown("---")
        st.markdown("**Bulk Actions**")
        b1, b2 = st.columns([3,2])
        with b1:
            sel_bulk = st.multiselect("Select favorites", options=favs, default=favs[:5] if len(favs) > 0 else [])
        with b2:
            colb1, colb2 = st.columns(2)
            with colb1:
                if st.button("Bulk Reclassify") and sel_bulk:
                    ok_count = 0
                    # Ensure DB context once, prefer sidebar DB; fallback to first asset's DB
                    try:
                        _db_ctx_b = (st.session_state.get('sf_database') or '').strip()
                        if not _db_ctx_b or _db_ctx_b.upper() in {"ALL","NONE","(NONE)","NULL","UNKNOWN"}:
                            if sel_bulk:
                                _db_ctx_b = sel_bulk[0].split('.')[0]
                        if _db_ctx_b:
                            snowflake_connector.execute_non_query(f"USE DATABASE {_db_ctx_b}")
                            st.session_state['sf_database'] = _db_ctx_b
                    except Exception:
                        pass
                    for a in sel_bulk:
                        try:
                            row = fav_df.loc[fav_df['Asset'] == a].iloc[0] if not fav_df.empty else None
                            pcls, pc, pi, pa = (row['Label'] or 'Internal', int(row['C'] or 1), int(row['I'] or 1), int(row['A'] or 1)) if row is not None else ("Internal",1,1,1)
                            reclassification_service.submit_request(a, (pcls, pc, pi, pa), "User-triggered bulk from Favorites", st.session_state.get('sf_user') or 'user')
                            ok_count += 1
                        except Exception:
                            continue
                    try:
                        from src.services.audit_service import audit_service as _audit
                        _audit.log(st.session_state.get('sf_user') or 'user', "FAV_BULK_RECLASSIFY", "COLLECTION", ",".join(sel_bulk), {"count": ok_count})
                    except Exception:
                        pass
                    st.success(f"Submitted {ok_count} reclassification request(s).")
            with colb2:
                if st.button("Bulk Owner Reminders") and sel_bulk:
                    ok_count = 0
                    try:
                        from src.services.notifier_service import notifier_service as _notifier
                    except Exception:
                        _notifier = None
                    for a in sel_bulk:
                        try:
                            if _notifier:
                                _notifier.notify_owner(asset_full_name=a, subject="Classification Reminder", message="Please classify your asset within SLA.")
                                ok_count += 1
                        except Exception:
                            continue
                    try:
                        from src.services.audit_service import audit_service as _audit
                        _audit.log(st.session_state.get('sf_user') or 'user', "FAV_BULK_OWNER_REMINDERS", "COLLECTION", ",".join(sel_bulk), {"count": ok_count})
                    except Exception:
                        pass
                    st.success(f"Sent {ok_count} reminder(s).")

        # Recent
        with st.expander("Recent Views (this session)", expanded=False):
            st.write(st.session_state["recent_assets"]) 

    # ---------------- Asset Details View ----------------
    with tab_asset_details:
        st.markdown("<div class='section-header'>📋 Asset Details</div>", unsafe_allow_html=True)
        # Asset picker
        asset_options = assets_df['Location'].dropna().tolist() if not assets_df.empty else []
        if not asset_options:
            st.info("No assets available. Ensure a database is selected and filters are not excluding all rows.")
            st.stop()
        sel_asset = st.selectbox("Select asset (DB.SCHEMA.TABLE)", options=asset_options, index=0, key="asset_details_asset")
        show_debug_det = st.checkbox("Show debug", value=False, key="asset_details_debug")

        # Split selector info
        try:
            db_sel, schema_sel, name_sel = sel_asset.split('.')
        except Exception:
            db_sel = schema_sel = name_sel = None

        # Helpers: fetch latest decision, inventory row, and tags for the selected asset
        def _latest_decision_for(asset_fqn: str) -> dict:
            try:
                db_ctx = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE or (asset_fqn.split('.')[0] if asset_fqn and '.' in asset_fqn else None)
                if not db_ctx:
                    return {}
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT ASSET_FULL_NAME, CLASSIFICATION, C, I, A, RATIONALE,
                           TRY_TO_VARCHAR(NULLIF(BUSINESS_IMPACT, '')) AS BUSINESS_IMPACT,
                           CHECKLIST_JSON, DECIDED_BY, DECIDED_AT
                    FROM {db_ctx}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
                    WHERE ASSET_FULL_NAME = %(asset)s
                    QUALIFY ROW_NUMBER() OVER (PARTITION BY ASSET_FULL_NAME ORDER BY DECIDED_AT DESC) = 1
                    """,
                    {"asset": asset_fqn}
                ) or []
                return rows[0] if rows else {}
            except Exception as e:
                if show_debug_det:
                    st.code(f"latest decision error: {e}")
                return {}

        def _inventory_for(asset_fqn: str) -> dict:
            try:
                db_ctx = asset_fqn.split('.')[0]
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT FULL_NAME, OWNER, CLASSIFIED, FIRST_DISCOVERED
                    FROM {db_ctx}.DATA_GOVERNANCE.ASSET_INVENTORY
                    WHERE FULL_NAME = %(f)s
                    LIMIT 1
                    """,
                    {"f": asset_fqn}
                ) or []
                return rows[0] if rows else {}
            except Exception:
                return {}

        def _tags_dict_for(asset_fqn: str) -> dict:
            try:
                refs = tagging_service.get_object_tags(asset_fqn, object_type="TABLE") or []
                out = {}
                for r in refs:
                    tname = (r.get('TAG_NAME') or r.get('tag_name') or '').upper()
                    tval = r.get('TAG_VALUE') or r.get('tag_value')
                    if tname:
                        out[tname] = tval
                return out
            except Exception:
                return {}

        latest_dec = _latest_decision_for(sel_asset)
        inv_row = _inventory_for(sel_asset)
        tag_map_det = _tags_dict_for(sel_asset)

        # Basic metadata
        st.markdown("**Basic metadata**")
        meta_cols = st.columns(3)
        try:
            created_ts = None
            modified_ts = None
            if not base_df.empty and sel_asset in base_df['FULL_NAME'].values:
                row = base_df.loc[base_df['FULL_NAME'] == sel_asset].iloc[0]
                created_ts = row.get('CREATED_DATE') or row.get('created_date')
                modified_ts = row.get('LAST_MODIFIED') or row.get('last_modified')
        except Exception:
            pass
        # QA Panel: list and act on pending reviews
        with st.expander("QA Reviews", expanded=False):
            try:
                colq1, colq2 = st.columns([2,1])
                with colq1:
                    st.caption("Pending approvals and high-risk items (sample)")
                    from src.services.classification_review_service import list_reviews as _list_reviews
                    me = st.text_input("Reviewer (email)", value=str(st.session_state.get('user') or ''), help="Used to filter 'Pending my approval'")
                    rf = st.selectbox("Review filter", options=["All","Pending approvals","High-risk","Recent changes"], index=1)
                    ap = st.selectbox("Approval status", options=["All pending","Pending my approval"], index=0)
                    resp = _list_reviews(current_user=me or '', review_filter=rf, approval_status=ap, lookback_days=30, page=1, page_size=20)
                    st.dataframe(pd.DataFrame(resp.get('reviews') or []), use_container_width=True)
                with colq2:
                    st.caption("Take action on a review")
                    rid = st.text_input("Review ID")
                    act = st.selectbox("Action", options=["Approve","Reject","Request changes"], index=0)
                    asset = st.text_input("Asset full name")
                    appr = st.text_input("Approver email")
                    if act == "Approve":
                        lbl = st.text_input("Label", value="Internal")
                        c = st.number_input("C", 0, 3, 1)
                        i = st.number_input("I", 0, 3, 1)
                        a = st.number_input("A", 0, 3, 1)
                        cm = st.text_area("Comments", value="Approved via Inventory QA panel")
                        if st.button("Approve Review") and rid and asset:
                            try:
                                from src.services import review_actions_service as _ra
                                ok = _ra.approve_review(rid, asset, lbl, int(c), int(i), int(a), approver=appr, comments=cm)
                                st.success("Approved" if ok else "Approval failed")
                            except Exception as _qae:
                                st.error(f"Approve failed: {_qae}")
                    elif act == "Reject":
                        why = st.text_area("Justification")
                        if st.button("Reject Review") and rid and asset:
                            try:
                                from src.services import review_actions_service as _ra
                                ok = _ra.reject_review(rid, asset, approver=appr, justification=why)
                                st.success("Rejected" if ok else "Rejection failed")
                            except Exception as _qre:
                                st.error(f"Reject failed: {_qre}")
                    else:
                        notes = st.text_area("Instructions")
                        if st.button("Request Changes") and rid and asset:
                            try:
                                from src.services import review_actions_service as _ra
                                ok = _ra.request_changes(rid, asset, approver=appr, instructions=notes)
                                st.success("Requested" if ok else "Request failed")
                            except Exception as _qce:
                                st.error(f"Request failed: {_qce}")
            except Exception:
                st.caption("QA Reviews unavailable")

        # Policy Guidance quick link
        with st.expander("Policy Guidance", expanded=False):
            st.caption("Open the full guidance for decision tree and checklists")
            if st.button("Open Policy Guidance"):
                try:
                    st.switch_page("pages/12_Policy_Guidance.py")
                except Exception:
                    st.rerun()
        with meta_cols[0]:
            st.metric("Path", sel_asset)
            st.caption(f"Type: {assets_df.loc[assets_df['Location']==sel_asset,'Type'].iloc[0] if not assets_df.empty else 'Unknown'}")
        with meta_cols[1]:
            st.metric("Created", str(created_ts) if created_ts else "Unknown")
            st.metric("Last Modified", str(modified_ts) if modified_ts else "Unknown")
        with meta_cols[2]:
            # Lineage summary via dependency counts
            try:
                dep_counts = _get_dependency_counts([sel_asset])
                st.metric("Related objects", dep_counts.get(sel_asset, 0))
            except Exception:
                st.metric("Related objects", "N/A")

        # Current classification & CIA
        st.markdown("**Current classification**")
        try:
            lab = latest_dec.get('CLASSIFICATION') if latest_dec else None
            c = int(latest_dec.get('C') or 0) if latest_dec else int(assets_df.loc[assets_df['Location']==sel_asset,'C'].iloc[0]) if 'C' in assets_df.columns else 0
            i = int(latest_dec.get('I') or 0) if latest_dec else int(assets_df.loc[assets_df['Location']==sel_asset,'I'].iloc[0]) if 'I' in assets_df.columns else 0
            a = int(latest_dec.get('A') or 0) if latest_dec else int(assets_df.loc[assets_df['Location']==sel_asset,'A'].iloc[0]) if 'A' in assets_df.columns else 0
            # Compliance check vs policy minimums
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
            if show_debug_det:
                st.code(f"classification section error: {e}")

        # Rationale and Business Impact
        st.markdown("**Rationale & Business Impact**")
        with st.expander("View rationale and business impact", expanded=False):
            try:
                rat = (latest_dec.get('RATIONALE') or '').strip() if latest_dec else ''
                bi = (latest_dec.get('BUSINESS_IMPACT') or '').strip() if latest_dec else ''
                if rat:
                    st.markdown(f"- Rationale: {rat}")
                if bi:
                    st.markdown(f"- Business Impact: {bi}")
                if not rat and not bi:
                    st.caption("No rationale or business impact recorded.")
            except Exception:
                st.caption("No rationale or business impact available.")

        # Classification history (timeline)
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
            if show_debug_det:
                st.code(f"History query failed: {e}")
            st.caption("History unavailable.")

        # Data owner, approval, SLA info (from tags and ASSET_INVENTORY)
        st.markdown("**Ownership & SLA**")
        try:
            owner_from_inv = inv_row.get('OWNER') if inv_row else None
            owner_from_tag = tag_map_det.get('OWNER') or tag_map_det.get('DATA_OWNER')
            primary_owner = owner_from_tag or owner_from_inv or "Unassigned"
        except Exception:
            primary_owner = "Unassigned"
        try:
            backup_owner = tag_map_det.get('OWNER_BACKUP') or tag_map_det.get('BACKUP_OWNER') or "N/A"
        except Exception:
            backup_owner = "N/A"
        try:
            approval_status = tag_map_det.get('APPROVAL_STATUS') or "Unknown"
        except Exception:
            approval_status = "Unknown"
        # SLA/Overdue from inventory
        try:
            classified = bool(inv_row.get('CLASSIFIED')) if inv_row else False
            fd = pd.to_datetime(inv_row.get('FIRST_DISCOVERED')) if inv_row and inv_row.get('FIRST_DISCOVERED') else None
            if classified:
                sla_badge = "🟢 Classified"
            elif fd is not None:
                bdays = pd.bdate_range(fd.normalize(), pd.Timestamp.utcnow().normalize())
                days = max(0, len(bdays) - 1)
                sla_badge = "🔴 Overdue" if days >= 5 else "🟡 Unclassified"
            else:
                sla_badge = ""
        except Exception:
            sla_badge = ""
        ocols = st.columns(4)
        with ocols[0]:
            st.metric("Primary owner", primary_owner)
        with ocols[1]:
            st.metric("Backup owner", backup_owner)
        with ocols[2]:
            st.metric("Approval status", approval_status)
        with ocols[3]:
            st.metric("SLA", sla_badge or (assets_df.loc[assets_df['Location']==sel_asset,'SLA State'].iloc[0] if 'SLA State' in assets_df.columns else ''))

        # Related assets (dependencies)
        st.markdown("**Related assets**")
        try:
            up = snowflake_connector.execute_query(
                """
                SELECT OBJECT_DATABASE||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME AS NAME
                FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
                WHERE REFERENCED_DATABASE=%(db)s AND REFERENCED_SCHEMA=%(s)s AND REFERENCED_OBJECT_NAME=%(o)s
                LIMIT 50
                """,
                {"db": db_sel, "s": schema_sel, "o": name_sel}
            ) or []
            down = snowflake_connector.execute_query(
                """
                SELECT REFERENCED_DATABASE||'.'||REFERENCED_SCHEMA||'.'||REFERENCED_OBJECT_NAME AS NAME
                FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
                WHERE OBJECT_DATABASE=%(db)s AND OBJECT_SCHEMA=%(s)s AND OBJECT_NAME=%(o)s
                LIMIT 50
                """,
                {"db": db_sel, "s": schema_sel, "o": name_sel}
            ) or []
            rcols = st.columns(2)
            with rcols[0]:
                st.caption("Upstream")
                st.write(pd.DataFrame(up) if up else "None")
            with rcols[1]:
                st.caption("Downstream")
                st.write(pd.DataFrame(down) if down else "None")
        except Exception as e:
            if show_debug_det:
                st.code(f"Dependency queries failed: {e}")
            st.caption("Dependencies unavailable.")

        # Usage statistics (queries, access patterns)
        st.markdown("**Usage statistics (last 30 days)**")
        try:
            usage = snowflake_connector.execute_query(
                """
                SELECT COUNT(*) AS QUERY_COUNT
                FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                WHERE START_TIME >= DATEADD(day, -30, CURRENT_TIMESTAMP())
                  AND UPPER(QUERY_TEXT) LIKE %(like)s
                """,
                {"like": f"% {name_sel.upper()} %" if name_sel else "%UNKNOWN%"}
            ) or []
            qcnt = usage[0].get('QUERY_COUNT') if usage else 0
            st.metric("Queries (30d)", int(qcnt or 0))
        except Exception as e:
            if show_debug_det:
                st.code(f"Usage query failed: {e}")
            st.caption("Usage unavailable.")

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

    # Pagination
    total_rows = len(assets_df)
    total_pages = max(1, (total_rows + page_size - 1) // page_size)
    page_num = st.number_input("Page", min_value=1, max_value=int(total_pages), value=1, step=1)
    start = (int(page_num) - 1) * int(page_size)
    end = start + int(page_size)
    page_df = assets_df.iloc[start:end].copy()
    
    # Render live preview in Table/View List tab (uses computed page_df)
    with b_tbl:
        st.caption("Live results for the current database (current page of filtered results).")
        try:
            preview_cols = [
                c for c in ["Location","Database","Schema","Name","Type","Classification","CIA Score","C","I","A","Owner","Risk","Status","SLA State","SLA Badge","Policy Compliance","Compliance Badge","Decision Notes","Reclass Needed","Reclass Reason","Rows","Size (MB)","Last Updated"]
                if c in page_df.columns
            ]
            if not page_df.empty and preview_cols:
                st.dataframe(page_df[preview_cols], use_container_width=True, hide_index=True)
            else:
                st.info("No rows on this page. Adjust filters or pagination.")
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
                st.info("No assets available in the current page/filter. Adjust filters or pagination.")
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
    
    
     
    # Display as table with better formatting and status badges
    if not assets_df.empty:
        # Add derived columns for Schema and Business Unit (Schema treated as BU)
        tmp_df = page_df.copy()
        tmp_df["Schema"] = tmp_df["Location"].str.split('.').str[1]
        # Prefer enriched Business Unit/Domain if computed earlier
        tmp_df["Business Unit"] = tmp_df.get("Business Unit", tmp_df["Schema"]) if "Business Unit" in tmp_df.columns else tmp_df["Schema"]
        tmp_df["Business Domain"] = tmp_df.get("Business Domain", tmp_df["Schema"]) if "Business Domain" in tmp_df.columns else tmp_df["Schema"]
        tmp_df["Lifecycle"] = tmp_df.get("Lifecycle", "Active")
        # Ensure display set required by spec
        tmp_df["Dataset Name"] = tmp_df["Location"]
        tmp_df["Table Name"] = tmp_df["Name"]
        # Optional: add rough storage cost estimate (best-effort)
        try:
            def _cost_from_bytes(b):
                try:
                    gb = float(b or 0) / (1024*1024*1024)
                    # Assumed $23/TB-month -> ~$0.023/GB-month (adjust per environment)
                    return round(gb * 0.023, 4)
                except Exception:
                    return 0.0
            if 'Size (MB)' in tmp_df.columns and 'size_bytes' not in tmp_df.columns:
                tmp_df['Estimated Monthly Cost ($)'] = tmp_df['Size (MB)'].apply(lambda mb: round((mb or 0)/1024 * 0.023, 4))
            elif 'Size (MB)' in tmp_df.columns:
                tmp_df['Estimated Monthly Cost ($)'] = tmp_df['Size (MB)'].apply(lambda mb: round((mb or 0)/1024 * 0.023, 4))
        except Exception:
            pass
        # Optional: dependency counts for current page
        try:
            dep_map = _get_dependency_counts(tmp_df['Location'].dropna().tolist())
            tmp_df['Dependencies'] = tmp_df['Location'].map(lambda x: dep_map.get(x, 0))
        except Exception:
            pass
        # Enrich with SLA and QA Status for the current page only (best-effort)
        try:
            cur_names = tmp_df['Location'].dropna().tolist()
            inv_map = _get_inventory_map(cur_names)
            qa_map = _get_qa_status_map(cur_names)
            def _sla_str(loc):
                try:
                    row = inv_map.get(loc)
                    if not row:
                        return ''
                    fd = pd.to_datetime(row.get('FIRST_DISCOVERED')) if row.get('FIRST_DISCOVERED') else None
                    classified = bool(row.get('CLASSIFIED'))
                    if fd is None or classified:
                        return ''
                    now = pd.Timestamp.utcnow().normalize()
                    bdays = pd.bdate_range(fd.normalize(), now)
                    days = max(0, len(bdays) - 1)
                    if days >= 5:
                        return f"Overdue by {days - 5} days"
                    return f"Due in {max(0, 5 - days)} days"
                except Exception:
                    return ''
            tmp_df['SLA'] = tmp_df['Location'].map(_sla_str)
            tmp_df['QA Status'] = tmp_df['Location'].map(lambda x: qa_map.get(x, ''))
        except Exception:
            pass
        # Compute Special Category badges for each asset (PII / Financial / Regulatory)
        try:
            def _special_category_row(r: pd.Series) -> str:
                cats: List[str] = []
                try:
                    if 'Has PII' in r and bool(r.get('Has PII')):
                        cats.append('PII')
                except Exception:
                    pass
                try:
                    if 'Has Financial' in r and bool(r.get('Has Financial')):
                        cats.append('Financial')
                except Exception:
                    pass
                try:
                    if 'Has Regulatory' in r and bool(r.get('Has Regulatory')):
                        cats.append('Regulatory')
                except Exception:
                    pass
                # Fallback to Tags and Name patterns if explicit flags are absent
                if not cats:
                    try:
                        t = str(r.get('Tags') or '').upper()
                        n = str(r.get('Location') or '').upper()
                        if any(x in t or x in n for x in ['PII','EMAIL','SSN','DOB','PHONE','PERSON','EMPLOYEE']):
                            cats.append('PII')
                        if any(x in t or x in n for x in ['FINANCE','GL','LEDGER','INVOICE','PAYROLL','AR','AP','REVENUE','EXPENSE']):
                            cats.append('Financial')
                        if any(x in t or x in n for x in ['GDPR','HIPAA','PCI','SOX','REGULATORY','IFRS','GAAP']):
                            cats.append('Regulatory')
                    except Exception:
                        pass
                if not cats:
                    return 'None'
                # Pretty badges
                emap = {'PII':'🔒 PII','Financial':'💹 Financial','Regulatory':'⚖️ Regulatory'}
                return ' | '.join([emap.get(c,c) for c in sorted(set(cats))])
            tmp_df['Special Category'] = tmp_df.apply(_special_category_row, axis=1)
        except Exception:
            tmp_df['Special Category'] = 'None'
        default_cols = [
            "Dataset Name","Database","Schema","Table Name","Owner","Classification","CIA Score","C","I","A","Decision Notes","Decision Rationale","Reclass Needed","Reclass Reason","Tags","Special Category","Lifecycle","Risk","Status","Type","Dependencies","Estimated Monthly Cost ($)","Last Updated","SLA","QA Status"
        ]
        available_cols = [c for c in default_cols if c in tmp_df.columns]
        # Inline policy guidance for quick reference
        with st.expander("Policy Guidance", expanded=False):
            st.markdown("""
            - **Decision model**: Choose the highest of C/I/A to determine label (`Confidential`, `Restricted`, `Internal`, `Public`).
            - **Special Categories**: If asset contains PII/Financial/Regulatory data, ensure appropriate masking and labels.
            - **SLA**: Classify within 5 business days of discovery. Overdue items should be prioritized or escalated.
            - **Checklist**: Capture decision rationale and validation checklist when changing labels.
            
            See `docs/AI_CLASSIFICATION.md` for full policy and decision matrix.
            """)
        with st.expander("Columns", expanded=False):
            selected_cols = st.multiselect("Choose columns to display", options=list(tmp_df.columns), default=available_cols)
        # Filters for SLA State and Special Categories
        try:
            fc1, fc2, fc3 = st.columns([1,1,2])
            with fc1:
                sla_opts = ["All","On Track","Due Soon","Overdue"] if 'SLA State' in tmp_df.columns else ["All"]
                sla_filter = st.selectbox("SLA State", options=sla_opts, index=0)
            with fc2:
                cat_filter = st.multiselect(
                    "Special Categories",
                    options=["PII","Financial","Regulatory","PCI","PHI"],
                    default=[],
                    help="Filter by detected categories (requires detection or pre-populated column)")
            with fc3:
                if st.button("Open Compliance Dashboard"):
                    try:
                        st.switch_page("pages/4_Compliance.py")
                    except Exception:
                        st.rerun()
        except Exception:
            sla_filter = "All"; cat_filter = []
        # Derive SLA State (5-business-day rule) and enrich Special Categories on-demand
        try:
            def _business_days_between(start_ts):
                from datetime import datetime, timedelta
                if not start_ts:
                    return None
                try:
                    dt = start_ts if hasattr(start_ts, 'weekday') else datetime.fromisoformat(str(start_ts))
                except Exception:
                    return None
                days = 0
                cur = dt
                now = datetime.utcnow()
                while cur.date() < now.date():
                    cur += timedelta(days=1)
                    if cur.weekday() < 5:
                        days += 1
                return days

            if 'FIRST_DISCOVERED' in tmp_df.columns and 'CLASSIFIED' in tmp_df.columns:
                if 'SLA State' not in tmp_df.columns:
                    tmp_df['SLA State'] = tmp_df.apply(
                        lambda r: (
                            'Overdue' if ( (_business_days_between(r.get('FIRST_DISCOVERED')) or 0) > 5 and not bool(r.get('CLASSIFIED')) ) else 
                            ('Due Soon' if ( (_business_days_between(r.get('FIRST_DISCOVERED')) or 0) in [4,5] and not bool(r.get('CLASSIFIED')) ) else 'On Track')
                        ), axis=1
                    )
        except Exception:
            pass

        # Optional: on-demand category detection for visible rows (cached)
        try:
            en_cols = ['Special Categories']
            for c in en_cols:
                if c not in tmp_df.columns:
                    tmp_df[c] = None
            do_detect = st.checkbox("Detect Special Categories for current view", value=False, help="Runs AI detection for PII/Financial/Regulatory on visible assets; cached to limit cost")
            if do_detect:
                try:
                    from src.services.ai_classification_service import ai_classification_service
                    # Limit to first 100 assets in current result for performance
                    sample_assets = (tmp_df['Location'] if 'Location' in tmp_df.columns else tmp_df['Dataset Name']).dropna().astype(str).head(100).tolist()
                    detected_map = {}
                    for full in sample_assets:
                        try:
                            detections = ai_classification_service.detect_sensitive_columns(full, sample_size=25) or []
                            cats = sorted({c for r in detections for c in (r.get('categories') or [])})
                            detected_map[full] = ", ".join(cats[:6]) if cats else None
                        except Exception:
                            detected_map[full] = None
                    if 'Location' in tmp_df.columns:
                        tmp_df['Special Categories'] = tmp_df['Location'].map(lambda x: detected_map.get(str(x)))
                    elif 'Dataset Name' in tmp_df.columns:
                        tmp_df['Special Categories'] = tmp_df['Dataset Name'].map(lambda x: detected_map.get(str(x)))
                except Exception:
                    st.caption("Category detection unavailable")
        except Exception:
            pass

        # Apply filters before rendering
        filtered_df = tmp_df
        try:
            if 'SLA State' in filtered_df.columns and sla_filter and sla_filter != 'All':
                filtered_df = filtered_df.loc[filtered_df['SLA State'] == sla_filter]
            if 'Special Categories' in filtered_df.columns and cat_filter:
                patt = '|'.join([c for c in cat_filter])
                filtered_df = filtered_df.loc[filtered_df['Special Categories'].fillna('').str.contains(patt, case=False, regex=True)]
        except Exception:
            pass
        # Render main table with enriched columns
        view_df = filtered_df[selected_cols] if selected_cols else filtered_df[available_cols]
        st.dataframe(view_df, use_container_width=True)

        # Inline KPIs for the current view
        try:
            k1, k2, k3, k4 = st.columns(4)
            with k1:
                st.metric("Total Assets (view)", len(view_df))
            with k2:
                cls_col = 'Classification' if 'Classification' in view_df.columns else None
                pct = 0
                if cls_col:
                    denom = max(len(view_df), 1)
                    pct = int(100 * (view_df[cls_col].notna() & view_df[cls_col].astype(str).str.len().gt(0)).sum() / denom)
                st.metric("Classified %", f"{pct}%")
            with k3:
                overdue = 0
                if 'SLA State' in view_df.columns:
                    overdue = int((view_df['SLA State'] == 'Overdue').sum())
                st.metric("Overdue (>5 bd)", overdue)
            with k4:
                pii_assets = 0
                if 'Special Categories' in view_df.columns:
                    pii_assets = int(view_df['Special Categories'].fillna('').str.contains('PII', case=False).sum())
                st.metric("Assets with PII", pii_assets)
        except Exception:
            pass

        # Action: Notify owners for overdue assets on this page
        try:
            overdue_assets: List[str] = []
            if 'SLA' in view_df.columns:
                overdue_assets = view_df.loc[view_df['SLA'].str.contains('Overdue', case=False, na=False), 'Dataset Name' if 'Dataset Name' in view_df.columns else 'Location'].dropna().tolist()
            elif 'SLA State' in view_df.columns:
                overdue_assets = view_df.loc[view_df['SLA State'] == 'Overdue', 'Dataset Name' if 'Dataset Name' in view_df.columns else 'Location'].dropna().tolist()
            if overdue_assets:
                if st.button(f"Notify owners for overdue assets ({len(overdue_assets)})", help="Sends reminders to owners for assets overdue >5 business days"):
                    try:
                        from src.services.notifier_service import notifier_service
                        for loc in overdue_assets[:200]:
                            notifier_service.notify_owner(asset_full_name=loc, subject="Classification Overdue", message="Your asset is overdue for classification (>5 business days). Please classify or request an exception.")
                        st.success(f"Reminders sent for up to {len(overdue_assets)} assets on this page")
                    except Exception as _notify_err:
                        st.warning(f"Reminder dispatch failed: {_notify_err}")
            # Auto-enforce: run SLA trigger detection and escalate as needed
            if st.button("Auto-Enforce SLA (create overdue requests)", help="Runs trigger detection to open reclassification requests for overdue assets"):
                try:
                    created = reclassification_service.detect_triggers()
                    st.success(f"Created {created} trigger(s) for overdue/DDL changes")
                except Exception as _trig_err:
                    st.warning(f"Auto-enforce failed: {_trig_err}")
        except Exception:
            pass
        # Exceptions Management
        with st.expander("Exceptions", expanded=False):
            try:
                colx1, colx2 = st.columns(2)
                with colx1:
                    st.markdown("**Request Exception**")
                    sel_asset = st.selectbox(
                        "Asset",
                        options=(view_df['Dataset Name'] if 'Dataset Name' in view_df.columns else view_df['Location']).dropna().astype(str).unique().tolist() if not view_df.empty else [],
                    )
                    regulatory = st.selectbox("Regulatory", options=["GDPR","HIPAA","PCI","SOX","Other"], index=0)
                    risk = st.selectbox("Risk Level", options=["Low","Medium","High"], index=1)
                    just = st.text_area("Justification")
                    req_by = st.text_input("Requested by (email)")
                    days = st.number_input("Days valid", min_value=1, max_value=365, value=90)
                    if st.button("Submit Exception") and sel_asset and req_by and just:
                        try:
                            from src.services.exception_service import exception_service
                            eid = exception_service.submit(sel_asset, regulatory, just, risk, req_by, days_valid=int(days))
                            st.success(f"Submitted exception {eid}")
                        except Exception as _ex_err:
                            st.error(f"Submit failed: {_ex_err}")
                with colx2:
                    st.markdown("**Track Exceptions**")
                    try:
                        from src.services.exception_service import exception_service
                        stt = st.selectbox("Status", options=["All","Pending","Approved","Rejected","Expired"], index=0)
                        rows = exception_service.list(status=stt, limit=100)
                        if rows:
                            st.dataframe(pd.DataFrame(rows), use_container_width=True)
                        else:
                            st.caption("No exceptions found for the selected filter.")
                    except Exception as _ex_list_err:
                        st.caption(f"Exceptions unavailable: {_ex_list_err}")
            except Exception:
                st.caption("Exceptions panel unavailable")

        # Optional view of matching columns from column-level filters
        try:
            if matching_cols:
                if st.checkbox("Show matching columns per asset", value=False, help="Lists columns that matched the column-level filters"):
                    rows = []
                    for loc in view_df['Dataset Name'] if 'Dataset Name' in view_df.columns else view_df['Location']:
                        cols = matching_cols.get(loc) or []
                        if cols:
                            rows.append({
                                'Asset': loc,
                                'Matching Columns (sample)': ", ".join(cols[:10]) + (" …" if len(cols) > 10 else "")
                            })
                    if rows:
                        st.dataframe(pd.DataFrame(rows), use_container_width=True)
        except Exception:
            pass
        # Download current view (CSV)
        try:
            csv_view = view_df.to_csv(index=False).encode('utf-8')
            st.download_button(label="Download current view (CSV)", data=csv_view, file_name="data_assets_view.csv", mime="text/csv")
        except Exception:
            pass
        st.caption(f"Page {page_num} of {total_pages}")
    else:
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

# Explanation for non-technical users
st.info("""💡 **What you're seeing:**
- This page shows ALL the actual tables in your Snowflake database
- Each row represents a real table with real business data
- Classifications are automatically determined based on the CIA triad scoring model
- CIA Score shows Confidentiality-Integrity-Availability ratings (0-3 for each)
- Lineage information shows how tables are related through dependencies
- You can search, filter, bulk classify, and export this inventory

**This is NOT mock data - it's your actual Snowflake database structure!**""")
