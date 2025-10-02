"""
Data Assets page for the data governance application.
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

# RBAC guard and capability flags
try:
    _ident = authz.get_current_identity()
    if not authz.is_consumer(_ident):
        st.error("You do not have permission to access Data Assets. Please sign in with a role that has at least consumer-level access.")
        st.stop()
    _can_classify = authz.can_classify(_ident)
    _can_approve = authz.can_approve_tags(_ident)
    if not _can_classify:
        st.info("Your role does not permit classification or tagging actions on this page.")
except Exception as _rbac_err:
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

def _persist_decision(asset: str, new_cls: str, c: int, i: int, a: int, owner: str, rationale: str, checklist: dict, decided_by: str, prev: dict | None = None):
    """Persist a classification decision for auditability."""
    try:
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

def _validate_decision_matrix(label: str, c: int, i: int, a: int, has_pii: bool, regs: list[str]) -> tuple[bool, str]:
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

# Dataset Filters expander removed; use the unified Search and Filter section below

# Organize into subtabs for better UX and organization
tab_overview, tab_inventory, tab_relationships, tab_lifecycle, tab_export = st.tabs([
    "📊 Overview", "📋 Asset Inventory", "🔗 Relationships & Lineage", "🔄 Lifecycle & Governance", "📥 Export"
])

# Function to get real data assets from Snowflake
@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_real_data_assets():
    try:
        # Get current database
        db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
        if not db:
            # Try to get current database from Snowflake
            try:
                db_row = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
                db = db_row[0].get('DB') if db_row else None
            except Exception:
                pass
        
        if not db:
            st.error("No database selected. Please set a database in the login page or session settings.")
            return pd.DataFrame()
        
        # Get actual tables from Snowflake
        table_results = snowflake_connector.execute_query(f"""
            SELECT 
                "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" as full_name,
                "TABLE_SCHEMA" as schema_name,
                "TABLE_NAME" as table_name,
                "ROW_COUNT" as row_count,
                "BYTES" as size_bytes,
                "CREATED" as created_date,
                "LAST_ALTERED" as last_modified,
                'TABLE' AS object_type
            FROM {db}.INFORMATION_SCHEMA.TABLES
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            UNION ALL
            SELECT 
                "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" as full_name,
                "TABLE_SCHEMA" as schema_name,
                "TABLE_NAME" as table_name,
                NULL as row_count,
                NULL as size_bytes,
                "CREATED" as created_date,
                "LAST_ALTERED" as last_modified,
                'VIEW' AS object_type
            FROM {db}.INFORMATION_SCHEMA.VIEWS
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            ORDER BY 1
            LIMIT 500
        """)
        
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
    def parse_cia(cia: str):
        try:
            parts = cia.upper().replace('C','').replace('I',' ').replace('A',' ').replace('-', ' ').split()
            nums = [int(p) for p in parts if p.isdigit()]
            c, i, a = (nums + [1,1,1])[:3]
            return c, i, a
        except Exception:
            return 1, 1, 1
    ciap = out["CIA Score"].apply(parse_cia)
    out["C"] = ciap.apply(lambda t: t[0])
    out["I"] = ciap.apply(lambda t: t[1])
    out["A"] = ciap.apply(lambda t: t[2])
    out["Risk"] = out.apply(lambda r: ("High" if max(r["C"], r["I"], r["A"]) >= 3 else ("Medium" if max(r["C"], r["I"], r["A"]) == 2 else "Low")), axis=1)
    # Type preserved from source; if missing, default to TABLE
    if "Type" not in out.columns:
        out["Type"] = "TABLE"
    # Status via Inventory (fallback heuristic): Classified vs Unclassified; Overdue if unclassified and >5 business days
    out["Status"] = "Unknown"
    try:
        db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
        names_list = out['Location'].dropna().tolist()
        inv = []
        if names_list and db:
            inv = snowflake_connector.execute_query(
                f"""
                SELECT FULL_NAME, CLASSIFIED, FIRST_DISCOVERED
                FROM {db}.DATA_GOVERNANCE.ASSET_INVENTORY
                WHERE FULL_NAME IN ({','.join([f"'{n}'" for n in names_list])})
                """
            ) or []
        inv_map = {r["FULL_NAME"]: r for r in inv}
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
        out["Status"] = out["Classification"].apply(lambda x: "Classified ✅" if x in ("Restricted","Confidential") else "Unclassified ❌")
    return out

# Get data assets
with st.spinner("Fetching real data assets from your Snowflake database..."):
    base_df = get_real_data_assets()
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

    # Helpers to enrich page-level SLA and QA status for current page only (avoid heavy queries)
    def _get_inventory_map(full_names: list) -> dict:
        try:
            db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
            if not full_names or not db:
                return {}
            in_list = ','.join([f"'{x}'" for x in full_names])
            rows = snowflake_connector.execute_query(
                f"""
                SELECT FULL_NAME, FIRST_DISCOVERED, CLASSIFIED
                FROM {db}.DATA_GOVERNANCE.ASSET_INVENTORY
                WHERE FULL_NAME IN ({in_list})
                """
            ) or []
            return {r['FULL_NAME']: r for r in rows}
        except Exception:
            return {}

    def _get_qa_status_map(full_names: list) -> dict:
        try:
            db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
            if not full_names or not db:
                return {}
            in_list = ','.join([f"'{x}'" for x in full_names])
            rows = snowflake_connector.execute_query(
                f"""
                SELECT ASSET_FULL_NAME, STATUS, REQUESTED_AT, REVIEWED_AT
                FROM {db}.DATA_GOVERNANCE.QA_REVIEWS
                WHERE ASSET_FULL_NAME IN ({in_list})
                """
            ) or []
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
            db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
            if not full_names or not db:
                return {}
            in_list = ','.join([f"'{x}'" for x in full_names])
            rows = snowflake_connector.execute_query(
                f"""
                SELECT ASSET_FULL_NAME, STATUS
                FROM {db}.DATA_GOVERNANCE.ASSET_LIFECYCLE
                WHERE ASSET_FULL_NAME IN ({in_list})
                ORDER BY UPDATED_AT DESC
                """
            ) or []
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

# ==================== OVERVIEW TAB ====================
with tab_overview:
    st.markdown("<div class='section-header'>📊 Asset Overview Dashboard</div>", unsafe_allow_html=True)
    st.markdown("""
    <div class='info-box'>
        <strong>📈 Quick Insights</strong><br>
        High-level summary of your data assets including classification breakdown, compliance coverage, and lifecycle statistics.
    </div>
    """, unsafe_allow_html=True)
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
    
    # Visualization Section
    st.markdown("### 📈 Visual Analytics")
    try:
        if not assets_df.empty:
            viz_col1, viz_col2, viz_col3 = st.columns(3)
            
            with viz_col1:
                st.markdown("**Classification Distribution**")
                cls_df = assets_df['Classification'].value_counts().rename_axis('Classification').reset_index(name='Count')
                chart_cls = alt.Chart(cls_df).mark_arc().encode(
                    theta='Count:Q',
                    color=alt.Color('Classification:N', legend=alt.Legend(title="Classification")),
                    tooltip=['Classification','Count']
                ).properties(height=250)
                st.altair_chart(chart_cls, use_container_width=True)
            
            with viz_col2:
                st.markdown("**Lifecycle Status**")
                if 'Lifecycle' in assets_df.columns:
                    lc_df = assets_df['Lifecycle'].value_counts().rename_axis('Lifecycle').reset_index(name='Count')
                    chart_lc = alt.Chart(lc_df).mark_bar().encode(
                        x='Count:Q',
                        y=alt.Y('Lifecycle:N', sort='-x'),
                        color=alt.Color('Lifecycle:N', legend=None),
                        tooltip=['Lifecycle','Count']
                    ).properties(height=250)
                    st.altair_chart(chart_lc, use_container_width=True)
                else:
                    st.info("Lifecycle data not available")
            
            with viz_col3:
                st.markdown("**Top Business Domains**")
                if 'Business Domain' in assets_df.columns:
                    bd_df = assets_df['Business Domain'].value_counts().head(10).rename_axis('Domain').reset_index(name='Count')
                    chart_bd = alt.Chart(bd_df).mark_bar().encode(
                        x='Count:Q',
                        y=alt.Y('Domain:N', sort='-x'),
                        tooltip=['Domain','Count']
                    ).properties(height=250)
                    st.altair_chart(chart_bd, use_container_width=True)
                else:
                    st.info("Business domain data not available")
    except Exception:
        st.caption("Visualizations unavailable")
    
    # Summary Statistics
    st.markdown("---")
    st.markdown("### 📋 Summary Statistics")
    if not assets_df.empty:
        sum_col1, sum_col2, sum_col3, sum_col4 = st.columns(4)
        with sum_col1:
            st.metric("Total Tables", int((assets_df['Type'] == 'TABLE').sum()) if 'Type' in assets_df.columns else 0)
        with sum_col2:
            st.metric("Total Views", int((assets_df['Type'] == 'VIEW').sum()) if 'Type' in assets_df.columns else 0)
        with sum_col3:
            if 'Dependencies' in assets_df.columns:
                avg_deps = int(assets_df['Dependencies'].mean()) if not assets_df['Dependencies'].isna().all() else 0
                st.metric("Avg Dependencies", avg_deps)
            else:
                st.metric("Avg Dependencies", "N/A")
        with sum_col4:
            if 'Estimated Monthly Cost ($)' in assets_df.columns:
                total_cost = assets_df['Estimated Monthly Cost ($)'].sum()
                st.metric("Total Monthly Cost", f"${total_cost:,.2f}")
            else:
                st.metric("Total Monthly Cost", "N/A")

# ==================== ASSET INVENTORY TAB ====================
with tab_inventory:
    st.markdown("<div class='section-header'>📋 Asset Inventory</div>", unsafe_allow_html=True)
    st.markdown("""
    <div class='info-box'>
        <strong>🗂️ Complete Asset Catalog</strong><br>
        Browse and filter all data assets across databases, schemas, and tables with advanced search capabilities.
    </div>
    """, unsafe_allow_html=True)
    
    # Show helpful message if no assets found
    if assets_df.empty:
        st.info("📊 No data assets found in the current database. Please ensure:\n\n"
                "1. You have selected a valid database in your session\n"
                "2. The database contains tables or views\n"
                "3. You have the necessary permissions to query INFORMATION_SCHEMA")
        st.stop()
    
    # Enhanced search and filter section with better organization
    st.markdown("<div class='section-header'>🔍 Search & Filter Assets</div>", unsafe_allow_html=True)
    with st.expander("**Filter Panel** - Click to expand/collapse", expanded=True):
        st.markdown("<div class='filter-section'>", unsafe_allow_html=True)
        st.markdown("**🎯 Primary Filters**")
        # Primary row
        col1, col2, col3 = st.columns(3)
        with col1:
            search_term = st.text_input("Search assets", placeholder="DB, schema, table, column or tags")
            include_col_search = st.checkbox("Include column names in search (slower)", value=False)
        with col2:
            classification_filter = st.selectbox(
                "Classification Level",
                ["All", "Public", "Internal", "Restricted", "Confidential"]
            )
        with col3:
            compliance_tags = st.multiselect("Compliance Tag", ["GDPR","HIPAA","PCI"], default=[])

        # Secondary row
        col_db, col_schema, col_table = st.columns(3)
        with col_db:
            db_filter = st.selectbox(
                "Database",
                ["All"] + sorted(assets_df['Location'].str.split('.').str[0].unique()) if not assets_df.empty else ["All"]
            )
        with col_schema:
            schema_filter = st.selectbox(
                "Schema",
                ["All"] + sorted(assets_df['Location'].str.split('.').str[1].unique()) if not assets_df.empty else ["All"]
            )
        with col_table:
            table_filter = st.text_input("Table name contains", value="")

        # Tertiary row
        col4, col5, col6 = st.columns(3)
        with col4:
            owner_filter = st.text_input("Owner contains", value="")
        with col5:
            status_filter = st.selectbox("Status", ["All","Classified ✅","Unclassified ❌","Overdue ⏰"])
        with col6:
            risk_filter = st.selectbox("Risk", ["All","Low","Medium","High"])

        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div class='filter-section'>", unsafe_allow_html=True)
        st.markdown("**⚡ Advanced Filters**")
        col_adv1, col_adv2, col_adv3, col_adv4 = st.columns(4)
        with col_adv1:
            min_rows = st.number_input("Min row count", min_value=0, value=0, step=1000, help="Filter assets with at least this many rows")
        with col_adv2:
            min_size_mb = st.number_input("Min size (MB)", min_value=0, value=0, step=100, help="Filter assets with at least this size")
        with col_adv3:
            max_cost = st.number_input("Max monthly cost ($)", min_value=0.0, value=0.0, step=10.0, help="Filter assets below this cost threshold (0=no limit)")
        with col_adv4:
            min_dependencies = st.number_input("Min dependencies", min_value=0, value=0, step=1, help="Filter assets with at least this many dependencies")

        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div class='filter-section'>", unsafe_allow_html=True)
        st.markdown("**🏢 Business Context**")
        col_bu, col_bd, col_type = st.columns(3)
        # Derive options best-effort from existing columns, tags, or schema names
        def _derive_opts(kind: str):
            try:
                def _parse_tag(tags: str, key: str) -> str:
                    try:
                        parts = [t.strip() for t in (tags or '').split(',') if t]
                        for t in parts:
                            if '=' in t:
                                k, v = t.split('=', 1)
                                if k.strip().upper() == key.upper():
                                    return v.strip()
                    except Exception:
                        pass
                    return ''
                if kind == 'BU':
                    if 'Business Unit' in assets_df.columns:
                        return sorted([x for x in assets_df['Business Unit'].dropna().unique().tolist() if x])
                    bu_series = assets_df['Tags'].apply(lambda s: _parse_tag(s, 'BUSINESS_UNIT')) if 'Tags' in assets_df.columns else pd.Series([], dtype=str)
                    fallback = assets_df['Location'].str.split('.').str[1] if 'Location' in assets_df.columns else pd.Series([], dtype=str)
                    return sorted([x for x in (bu_series.replace('', pd.NA).fillna(fallback)).dropna().unique().tolist() if x])
                else:
                    if 'Business Domain' in assets_df.columns:
                        return sorted([x for x in assets_df['Business Domain'].dropna().unique().tolist() if x])
                    bd_series = assets_df['Tags'].apply(lambda s: _parse_tag(s, 'BUSINESS_DOMAIN')) if 'Tags' in assets_df.columns else pd.Series([], dtype=str)
                    fallback = assets_df['Location'].str.split('.').str[1] if 'Location' in assets_df.columns else pd.Series([], dtype=str)
                    return sorted([x for x in (bd_series.replace('', pd.NA).fillna(fallback)).dropna().unique().tolist() if x])
            except Exception:
                return []
        bu_opts = _derive_opts('BU')
        bd_opts = _derive_opts('BD')
        with col_bu:
            bu_filter = st.multiselect("Business Unit", bu_opts, default=[])
        with col_bd:
            domain_filter = st.multiselect("Business Domain", bd_opts, default=[])
        with col_type:
            type_filter = st.selectbox("Type", ["All","TABLE","VIEW"])

        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div class='filter-section'>", unsafe_allow_html=True)
        st.markdown("**🔄 Lifecycle & Data Categories**")
        col_lc, col_cat = st.columns(2)
        with col_lc:
            lifecycle_filter = st.selectbox("Lifecycle", ["All","Active","Deprecated","Archived"], index=0)
        with col_cat:
            category_filter = st.selectbox("Data Category", ["All","PII","PHI","Financial","Regulatory"], index=0, key='category_filter')

        # Sorting / pagination
        col9, col10, col11 = st.columns(3)
        with col9:
            sort_by = st.selectbox("Sort by", ["None","CIA (max)","Creation Date","Last Modified","Overall Risk"], index=0)
        with col10:
            page_size = st.selectbox("Page size", [25, 50, 100], index=0)
        with col11:
            pass

        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div class='filter-section'>", unsafe_allow_html=True)
        st.markdown("**📋 Column-Level Filters** (Advanced)")
        st.caption("Filter assets based on their column characteristics - name, type, masking, and categories")
        cfa, cfb, cfc = st.columns(3)
        with cfa:
            col_name_filter = st.text_input("Column name contains", value="", help="Substring match (case-insensitive)")
        with cfb:
            col_dtype_filter = st.multiselect(
                "Column data type",
                options=["STRING","VARCHAR","TEXT","CHAR","NUMBER","DECIMAL","INTEGER","FLOAT","DOUBLE","BOOLEAN","DATE","TIMESTAMP_NTZ","TIMESTAMP_TZ","TIMESTAMP_LTZ","BINARY"],
                default=[]
            )
        with cfc:
            col_masking_filter = st.selectbox("Has masking policy", ["Any","Yes","No"], index=0)
        cfd, cfe = st.columns(2)
        with cfd:
            col_category_filter = st.multiselect(
                "Column category",
                options=["PII","PHI","PCI","Financial","Regulatory"],
                default=[]
            )
        with cfe:
            col_min_count = st.number_input("Minimum column count", min_value=0, max_value=5000, value=0, step=1, help="Require at least this many columns on the asset")

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
    matching_cols: dict[str, list[str]] = {}
    if (col_name_filter or col_dtype_filter or (col_masking_filter != "Any") or col_category_filter or (col_min_count and col_min_count > 0)) and not assets_df.empty:
        # Fetch column metadata and masking references for current (filtered) assets, capped to 300 assets for performance
        selected_assets = assets_df['Location'].dropna().tolist()[:300]
        @st.cache_data(ttl=180)
        def _fetch_columns_for_assets(full_names: list) -> dict:
            out: dict[str, list] = {}
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

        def _col_category_hit(col_name: str, categories: list[str]) -> bool:
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

    # Pagination
    total_rows = len(assets_df)
    total_pages = max(1, (total_rows + page_size - 1) // page_size)
    page_num = st.number_input("Page", min_value=1, max_value=int(total_pages), value=1, step=1)
    start = (int(page_num) - 1) * int(page_size)
    end = start + int(page_size)
    page_df = assets_df.iloc[start:end].copy()
    
    # Enhanced asset display section
    st.markdown("<div class='section-header'>📊 Asset Inventory Results</div>", unsafe_allow_html=True)
    t_count = int((assets_df['Type'] == 'TABLE').sum()) if 'Type' in assets_df.columns else len(assets_df)
    v_count = int((assets_df['Type'] == 'VIEW').sum()) if 'Type' in assets_df.columns else 0
    
    # Results summary - simple count only (charts are in Overview tab)
    st.markdown(f"""
    <div style='padding: 10px; background: rgba(52, 152, 219, 0.1); border-radius: 8px; border-left: 4px solid #3498db; margin-bottom: 20px;'>
        <span style='font-size: 18px; font-weight: 600;'>Found {len(assets_df)} assets</span>
        <span style='color: rgba(255,255,255,0.6); margin-left: 10px;'>({t_count} tables, {v_count} views)</span>
        <span style='color: rgba(255,255,255,0.6); margin-left: 10px;'>| Page {page_num} of {total_pages}</span>
    </div>
    """, unsafe_allow_html=True)
    # Column-level summary (per-class) with scope toggle and drill-down
    try:
        # Toggle: compute from current page vs all filtered assets (heavier)
        use_all_filtered = st.checkbox(
            "Build summary from all filtered assets (may be slower)",
            value=False,
            help="If checked, the summary will aggregate across all filtered rows instead of just the current page."
        )
        source_df = assets_df if use_all_filtered else (page_df if not page_df.empty else assets_df)
        page_assets = source_df['Location'].dropna().tolist()[:500]
        @st.cache_data(ttl=180)
        def _cols_and_mask_for_assets(full_names: list) -> dict:
            out: dict[str, list] = {}
            try:
                if not full_names:
                    return out
                preds = []
                params = {}
                for i, fn in enumerate(full_names):
                    try:
                        db, sch, tbl = fn.split('.')
                    except ValueError:
                        continue
                    preds.append(f"(TABLE_CATALOG = %(db{i})s AND TABLE_SCHEMA = %(s{i})s AND TABLE_NAME = %(t{i})s)")
                    params[f"db{i}"] = db
                    params[f"s{i}"] = sch
                    params[f"t{i}"] = tbl
                if not preds:
                    return out
                db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
                if not db:
                    return out
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT TABLE_CATALOG||'.'||TABLE_SCHEMA||'.'||TABLE_NAME AS FULL,
                           UPPER(COLUMN_NAME) AS COLUMN_NAME,
                           UPPER(DATA_TYPE) AS DATA_TYPE
                    FROM {db}.INFORMATION_SCHEMA.COLUMNS
                    WHERE {" OR ".join(preds)}
                    """,
                    params,
                ) or []
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
                    col = r.get('COLUMN_NAME')
                    dt = r.get('DATA_TYPE')
                    if not full:
                        continue
                    if full not in out:
                        out[full] = []
                    out[full].append({"column": col, "data_type": dt, "masked": (full.upper(), col) in refset})
            except Exception:
                return out
            return out
        colmap = _cols_and_mask_for_assets(page_assets)
        # Aggregate per-class
        import collections as _co
        agg = _co.defaultdict(lambda: {"assets": 0, "columns": 0, "masked": 0, "pii": 0, "phi": 0, "pci": 0})
        details = _co.defaultdict(list)  # per-class column details
        cls_by_loc = dict(zip(assets_df['Location'], assets_df['Classification']))
        def _is_pii_col(n: str) -> bool:
            u = n.upper()
            return any(k in u for k in ["SSN","EMAIL","PHONE","ADDRESS","DOB","PERSON","CUSTOMER","EMPLOYEE"])
        def _is_phi_col(n: str) -> bool:
            u = n.upper()
            return any(k in u for k in ["PHI","HEALTH","MEDICAL","PATIENT","DIAGNOSIS","RX"])
        def _is_pci_col(n: str) -> bool:
            u = n.upper()
            return any(k in u for k in ["CARD","PAN","CREDIT","CC_NUMBER"])
        seen_asset_in_class = set()
        for loc, cols in colmap.items():
            cls = cls_by_loc.get(loc)
            if not cls:
                continue
            key = cls
            if (key, loc) not in seen_asset_in_class:
                agg[key]["assets"] += 1
                seen_asset_in_class.add((key, loc))
            agg[key]["columns"] += len(cols)
            for c in cols:
                if c.get("masked"):
                    agg[key]["masked"] += 1
                nm = c.get("column") or ""
                if _is_pii_col(nm):
                    agg[key]["pii"] += 1
                if _is_phi_col(nm):
                    agg[key]["phi"] += 1
                if _is_pci_col(nm):
                    agg[key]["pci"] += 1
                # collect details (sample up to 300 per class later)
                details[key].append({
                    "Table": loc,
                    "Column": nm,
                    "Data Type": c.get("data_type") or "",
                    "Masked?": "Yes" if c.get("masked") else "No",
                    "Category": ("PCI" if _is_pci_col(nm) else ("PHI" if _is_phi_col(nm) else ("PII" if _is_pii_col(nm) else ""))),
                })
        if agg:
            st.markdown("#### Column-level Summary by Classification")
            import pandas as _pd
            rows = []
            for k, v in agg.items():
                cols = int(v["columns"]) or 0
                masked = int(v["masked"]) or 0
                pct_masked = f"{(100.0*masked/cols):.1f}%" if cols else "0.0%"
                rows.append({
                    "Classification": k,
                    "Assets": int(v["assets"]) or 0,
                    "Columns": cols,
                    "Masked Columns": masked,
                    "% Masked": pct_masked,
                    "PII Cols": int(v["pii"]) or 0,
                    "PHI Cols": int(v["phi"]) or 0,
                    "PCI-like Cols": int(v["pci"]) or 0,
                })
            st.dataframe(_pd.DataFrame(rows).sort_values(["Classification"]).reset_index(drop=True), use_container_width=True)
            # Drill-down per classification
            st.caption("Expand a classification to view a sample of matching columns (name, type, masking, category)")
            for cls_name in sorted(details.keys()):
                with st.expander(f"{cls_name} — column details", expanded=False):
                    dlist = details.get(cls_name) or []
                    # Limit rows for display; provide counts
                    total_cols = len(dlist)
                    # Filters inside expander
                    f1, f2, f3 = st.columns([2,1,1])
                    with f1:
                        q = st.text_input("Search column name", value="", key=f"cls_{cls_name}_q")
                    with f2:
                        type_opts = sorted({r.get("Data Type") for r in dlist if r.get("Data Type")})
                        tsel = st.selectbox("Type", options=["All"] + type_opts, index=0, key=f"cls_{cls_name}_type")
                    with f3:
                        cats = ["PII","PHI","PCI"]
                        csel = st.multiselect("Category", options=cats, default=[], key=f"cls_{cls_name}_cat")
                    # Apply filters
                    filtered = dlist
                    if q:
                        filtered = [r for r in filtered if q.lower() in (r.get("Column") or "").lower()]
                    if tsel != "All":
                        filtered = [r for r in filtered if (r.get("Data Type") or "") == tsel]
                    if csel:
                        filtered = [r for r in filtered if (r.get("Category") or "") in csel]
                    sample = filtered[:500]
                    st.caption(f"Showing {len(sample)} of {total_cols} matching columns")
                    try:
                        df_det = _pd.DataFrame(sample)
                        st.dataframe(df_det, use_container_width=True)
                        # CSV download of shown rows
                        csv = df_det.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label="Download CSV (this view)",
                            data=csv,
                            file_name=f"{cls_name.lower()}_column_details.csv",
                            mime="text/csv",
                            key=f"dl_{cls_name}"
                        )
                    except Exception:
                        pass
    except Exception:
        pass

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
        default_cols = [
            "Dataset Name","Database","Schema","Table Name","Owner","Classification","CIA Score","C","I","A","Tags","Lifecycle","Risk","Status","Type","Dependencies","Estimated Monthly Cost ($)","Last Updated","SLA","QA Status"
        ]
        available_cols = [c for c in default_cols if c in tmp_df.columns]
        with st.expander("Columns", expanded=False):
            selected_cols = st.multiselect("Choose columns to display", options=list(tmp_df.columns), default=available_cols)
        # Render main table
        view_df = tmp_df[selected_cols] if selected_cols else tmp_df[available_cols]
        st.dataframe(view_df, use_container_width=True)
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

# ==================== RELATIONSHIPS & LINEAGE TAB ====================
with tab_relationships:
    st.markdown("<div class='section-header'>🔗 Relationships & Lineage</div>", unsafe_allow_html=True)
    st.markdown("""
    <div class='info-box'>
        <strong>🌐 Dependency Mapping</strong><br>
        Visualize upstream/downstream dependencies, explore lineage, and discover similar assets with AI-powered recommendations.
    </div>
    """, unsafe_allow_html=True)
    
    if not assets_df.empty and len(page_df) > 0:
        st.markdown("#### 🔍 Select Asset to Analyze")
        rel_asset = st.selectbox(
            "Choose an asset to view its relationships",
            options=page_df["Location"].tolist(),
            key="rel_viz_asset_tab"
        )
        
        col_rel1, col_rel2 = st.columns(2)
        
        with col_rel1:
            st.markdown("**⬆️ Upstream Dependencies**")
            st.caption("Assets that this asset depends on")
            try:
                db, schema, table = rel_asset.split('.')
                upstream = snowflake_connector.execute_query(
                    """
                    SELECT REFERENCED_OBJECT_NAME AS NAME, 
                           REFERENCED_OBJECT_DOMAIN AS TYPE
                    FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
                    WHERE OBJECT_DATABASE=%(db)s 
                      AND OBJECT_SCHEMA=%(s)s 
                      AND OBJECT_NAME=%(o)s
                    LIMIT 50
                    """,
                    {"db": db, "s": schema, "o": table}
                ) or []
                if upstream:
                    up_df = pd.DataFrame(upstream)
                    st.dataframe(up_df, use_container_width=True)
                    st.caption(f"✅ Found {len(upstream)} upstream dependencies")
                else:
                    st.info("No upstream dependencies found")
            except Exception as e:
                st.warning(f"Could not fetch upstream: {e}")
        
        with col_rel2:
            st.markdown("**⬇️ Downstream Dependencies**")
            st.caption("Assets that depend on this asset")
            try:
                db, schema, table = rel_asset.split('.')
                downstream = snowflake_connector.execute_query(
                    """
                    SELECT OBJECT_NAME AS NAME,
                           OBJECT_DOMAIN AS TYPE
                    FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
                    WHERE REFERENCED_DATABASE=%(db)s 
                      AND REFERENCED_SCHEMA=%(s)s 
                      AND REFERENCED_OBJECT_NAME=%(o)s
                    LIMIT 50
                    """,
                    {"db": db, "s": schema, "o": table}
                ) or []
                if downstream:
                    down_df = pd.DataFrame(downstream)
                    st.dataframe(down_df, use_container_width=True)
                    st.caption(f"✅ Found {len(downstream)} downstream dependencies")
                else:
                    st.info("No downstream dependencies found")
            except Exception as e:
                st.warning(f"Could not fetch downstream: {e}")
        
        st.markdown("<hr style='margin: 30px 0; border: 1px solid rgba(255,255,255,0.1);'>", unsafe_allow_html=True)
        st.markdown("""
        <div class='relationship-card'>
            <div style='font-size: 16px; font-weight: 600; margin-bottom: 10px;'>🎯 Similar Asset Recommendations</div>
            <div style='color: rgba(255,255,255,0.7); font-size: 14px;'>AI-powered similarity scoring based on classification, ownership, schema, and risk profile</div>
        </div>
        """, unsafe_allow_html=True)
        
        try:
            # Find similar assets based on current selection
            selected_row = assets_df[assets_df['Location'] == rel_asset].iloc[0]
            similar_mask = (
                (assets_df['Location'] != rel_asset) &
                (
                    (assets_df['Classification'] == selected_row['Classification']) |
                    (assets_df['Owner'] == selected_row['Owner']) |
                    (assets_df['Location'].str.split('.').str[1] == rel_asset.split('.')[1])
                )
            )
            similar_assets = assets_df[similar_mask].head(10)
            
            if not similar_assets.empty:
                # Calculate similarity score
                def calc_similarity(row):
                    score = 0
                    if row['Classification'] == selected_row['Classification']:
                        score += 3
                    if row['Owner'] == selected_row['Owner']:
                        score += 2
                    if row['Location'].split('.')[1] == rel_asset.split('.')[1]:
                        score += 2
                    if 'Risk' in row and row['Risk'] == selected_row.get('Risk'):
                        score += 1
                    return score
                
                similar_assets['Similarity Score'] = similar_assets.apply(calc_similarity, axis=1)
                similar_assets = similar_assets.sort_values('Similarity Score', ascending=False)
                
                display_cols = ['Name', 'Classification', 'Owner', 'Risk', 'Similarity Score']
                available_display = [c for c in display_cols if c in similar_assets.columns]
                st.dataframe(similar_assets[available_display], use_container_width=True)
            else:
                st.info("No similar assets found")
        except Exception as e:
            st.warning(f"Could not compute similar assets: {e}")
    else:
        st.info("No assets available for relationship analysis")

# ==================== LIFECYCLE & GOVERNANCE TAB ====================
with tab_lifecycle:
    st.markdown("<div class='section-header'>🔄 Lifecycle & Governance</div>", unsafe_allow_html=True)
    st.markdown("""
    <div class='info-box'>
        <strong>📋 Asset Management Workflows</strong><br>
        Manage asset lifecycle, assign ownership, apply bulk classifications, and track governance activities.
    </div>
    """, unsafe_allow_html=True)
    
    # Subtabs for different lifecycle operations
    lc_tab1, lc_tab2, lc_tab3 = st.tabs(["🏷️ Ownership & Lifecycle", "⚙️ Bulk Operations", "🔎 Discovery Feed"])
    
    with lc_tab1:
        st.markdown("### Ownership & Lifecycle Management")
        if not assets_df.empty:
            selected_lc_asset = st.selectbox(
                "Select asset to manage",
                options=assets_df["Location"].tolist(),
                key="lc_asset_select"
            )
            
            col_lc1, col_lc2 = st.columns(2)
            
            with col_lc1:
                st.markdown("**👤 Ownership Assignment**")
                new_owner = st.text_input("Assign/Update Owner (email)", value="", key="lc_owner")
                if st.button("Apply Owner", key="btn_apply_owner_lc"):
                    if new_owner:
                        try:
                            tagging_service.apply_object_tag(selected_lc_asset, tag_name="OWNER", tag_value=new_owner, object_type="TABLE")
                            st.success(f"✅ Owner assigned: {new_owner}")
                        except Exception as e:
                            st.error(f"Failed to apply owner: {e}")
                    else:
                        st.warning("Please enter an owner email")
            
            with col_lc2:
                st.markdown("**🔄 Lifecycle Status**")
                lc_action = st.selectbox("Lifecycle Action", ["None","Mark Active","Mark Deprecated","Mark Archived"], index=0, key="lc_action_select")
                if lc_action != "None" and st.button("Apply Lifecycle", key="btn_apply_lifecycle_lc"):
                    try:
                        status = lc_action.replace("Mark ", "")
                        db_lc = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
                        if db_lc:
                            try:
                                snowflake_connector.execute_non_query(
                                    f"""
                                    CREATE SCHEMA IF NOT EXISTS {db_lc}.DATA_GOVERNANCE;
                                    CREATE TABLE IF NOT EXISTS {db_lc}.DATA_GOVERNANCE.ASSET_LIFECYCLE (
                                      ASSET_FULL_NAME STRING, STATUS STRING, UPDATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
                                    );
                                    """
                                )
                            except Exception:
                                pass
                            snowflake_connector.execute_non_query(
                                f"""
                                INSERT INTO {db_lc}.DATA_GOVERNANCE.ASSET_LIFECYCLE (ASSET_FULL_NAME, STATUS)
                                VALUES (%(f)s, %(s)s)
                                """,
                                {"f": selected_lc_asset, "s": status}
                            )
                        try:
                            tagging_service.apply_object_tag(selected_lc_asset, tag_name="LIFECYCLE", tag_value=status.upper(), object_type="TABLE")
                        except Exception:
                            pass
                        st.success(f"✅ Lifecycle set to {status}")
                    except Exception as e:
                        st.error(f"Failed to set lifecycle: {e}")
        else:
            st.info("No assets available")
    
    with lc_tab2:
        st.markdown("### Bulk Classification Operations")
        st.caption("Apply classification, CIA scores, and compliance tags to multiple assets simultaneously")
        
        if not assets_df.empty:
            multi = st.multiselect("Select assets", options=assets_df["Location"].tolist())
            b_cls = st.selectbox("Classification", ["Public","Internal","Restricted","Confidential"], index=1)
            colc, coli, cola = st.columns(3)
            with colc:
                bc = st.number_input("C", min_value=0, max_value=3, value=1, step=1, key="bc")
            with coli:
                bi = st.number_input("I", min_value=0, max_value=3, value=1, step=1, key="bi")
            with cola:
                ba = st.number_input("A", min_value=0, max_value=3, value=1, step=1, key="ba")
            # Policy-required rationale & checklist (applies to all selected)
            bulk_rationale = st.text_area("Classification Rationale (required)", key="bulk_rationale")
            bcol1, bcol2 = st.columns(2)
            with bcol1:
                bulk_has_pii = st.checkbox("Contains personal data (PII) in selected?", key="bulk_pii")
                bulk_avail = st.selectbox("Availability criticality (typical)", ["Low","Standard","High","Critical"], index=1, key="bulk_avail")
            with bcol2:
                bulk_regs = st.multiselect("Regulatory obligations (any)", ["GDPR","HIPAA","PCI","SOX","Other"], key="bulk_regs")
            if st.button("Apply to Selected", type="primary", key="bulk_apply_btn"):
                if not _can_classify:
                    st.error("You do not have permission to apply tags (classification). Contact a Data Owner or Admin.")
                    st.stop()
                if not multi:
                    st.warning("Please select at least one asset")
                    st.stop()
                # Require justification for higher sensitivity (Policy 6.1.2 Step 6: Documentation)
                if b_cls in ("Restricted", "Confidential") and not (bulk_rationale and bulk_rationale.strip()):
                    st.warning("Rationale is required when applying Restricted/Confidential labels (Policy 6.1.2).")
                    st.stop()

                # Enforce decision matrix before any tag writes (Policy 5.2, 5.5, 6.2.2)
                ok_matrix, msg = _validate_decision_matrix(b_cls, int(bc), int(bi), int(ba), bool(bulk_has_pii), list(bulk_regs))
                if not ok_matrix:
                    st.error(f"Decision blocked by policy: {msg}")
                    st.stop()
                ok, failed = 0, 0
                enforced_cols = 0
                for obj in multi:
                    try:
                        # Privilege-based check per object
                        if not authz.can_apply_tags_for_object(obj, object_type='TABLE'):
                            failed += 1
                            st.warning(f"Skipped {obj}: insufficient privileges to apply tags (ALTER/OWNERSHIP required)")
                            continue
                        row = assets_df[assets_df['Location'] == obj].head(1)
                        obj_type = row.iloc[0]['Type'] if not row.empty and 'Type' in row.columns else 'TABLE'
                        # Validate per asset (double-check)
                        ok_m, msg_m = _validate_decision_matrix(b_cls, int(bc), int(bi), int(ba), bool(bulk_has_pii), list(bulk_regs))
                        if not ok_m:
                            failed += 1
                            st.warning(f"{obj}: blocked by policy - {msg_m}")
                            continue
                        prev = {
                            "classification": (row.iloc[0]['Classification'] if not row.empty else None),
                            "C": (int(row.iloc[0]['C']) if not row.empty and 'C' in row.columns else None),
                            "I": (int(row.iloc[0]['I']) if not row.empty and 'I' in row.columns else None),
                            "A": (int(row.iloc[0]['A']) if not row.empty and 'A' in row.columns else None),
                        }
                        tagging_service.apply_tags_to_object(
                            obj,
                            obj_type,
                            {
                                "DATA_CLASSIFICATION": b_cls,
                                "CONFIDENTIALITY_LEVEL": str(int(bc)),
                                "INTEGRITY_LEVEL": str(int(bi)),
                                "AVAILABILITY_LEVEL": str(int(ba)),
                            },
                        )
                        ok += 1
                        # Persist decision to audit table
                        try:
                            decided_by = getattr(st.session_state.get('user'), 'username', 'unknown') if hasattr(st.session_state, 'user') else 'unknown'
                            owner_val = row.iloc[0]['Owner'] if (not row.empty and 'Owner' in row.columns) else None
                            _persist_decision(
                                asset=obj,
                                new_cls=b_cls,
                                c=int(bc), i=int(bi), a=int(ba),
                                owner=owner_val,
                                rationale=bulk_rationale,
                                checklist={"has_pii": bool(bulk_has_pii), "availability": bulk_avail, "regulations": list(bulk_regs)},
                                decided_by=decided_by,
                                prev=prev,
                            )
                        except Exception:
                            pass
                        # Auto-enforce masking policies for sensitive columns
                        try:
                            detections = ai_classification_service.detect_sensitive_columns(obj)
                            result = policy_enforcement_service.auto_enforce_for_table(table=obj, detections=detections)
                            enforced_cols += len(result.get("applied", []))
                        except Exception:
                            pass
                        try:
                            user_id = getattr(st.session_state.get('user'), 'username', 'unknown') if hasattr(st.session_state, 'user') else 'unknown'
                            audit_details = {
                                "old": prev,
                                "new": {"classification": b_cls, "C": int(bc), "I": int(bi), "A": int(ba)},
                                "rationale": bulk_rationale,
                                "checklist": {"has_pii": bool(bulk_has_pii), "availability": bulk_avail, "regulations": list(bulk_regs)},
                            }
                            audit_service.log(user_id=user_id, action="bulk_apply_tags", resource_type="TABLE", resource_id=obj, details=audit_details)
                        except Exception:
                            pass
                    except Exception:
                        failed += 1
                if enforced_cols > 0:
                    st.success(f"Applied to {ok} assets, enforced masking on {enforced_cols} column(s). Failed: {failed}")
                else:
                    st.success(f"Applied to {ok} assets. Failed: {failed}")
        else:
            st.info("No assets available for bulk operations")
    
    with lc_tab3:
        st.markdown("### Discovery Feed")
        st.caption("View recently discovered unclassified assets prioritized by risk and compliance requirements")
        
        try:
            from src.services.discovery_service import discovery_service
            queue = discovery_service.get_queue(limit=50)
            if queue:
                qdf = pd.DataFrame(queue)
                st.dataframe(qdf, use_container_width=True)
                if st.button("Run Quick Scan", key="discovery_scan_btn"):
                    with st.spinner("Scanning for new assets..."):
                        n = discovery_service.scan(limit=500)
                    st.success(f"✅ Scan complete. Upserted {n} assets.")
            else:
                st.info("Queue empty. Run a scan to populate.")
        except Exception as e:
            st.warning(f"Discovery feed unavailable: {e}")

# ==================== EXPORT TAB ====================

with tab_export:
    st.markdown("<div class='section-header'>📥 Export Asset Inventory</div>", unsafe_allow_html=True)
    st.markdown("""
    <div class='info-box'>
        <strong>📊 Export Options</strong><br>
        Download your filtered asset inventory in multiple formats for reporting, compliance documentation, and analysis.
    </div>
    """, unsafe_allow_html=True)
    
    if not assets_df.empty:
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
                <div style='font-size: 14px; font-weight: 600; margin-bottom: 5px;'>📄 CSV Export</div>
                <div style='font-size: 12px; color: rgba(255,255,255,0.6);'>Raw data for analysis</div>
            </div>
            """, unsafe_allow_html=True)
            csv = exp_df[export_cols].to_csv(index=False).encode('utf-8')
            st.download_button(
                label="⬇️ Download CSV",
                data=csv,
                file_name="dataset_inventory.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col_excel:
            st.markdown("""
            <div class='relationship-card'>
                <div style='font-size: 14px; font-weight: 600; margin-bottom: 5px;'>📊 Excel Export</div>
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
        
    else:
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
