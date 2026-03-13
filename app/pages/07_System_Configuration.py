"""
Administration page
- Dashboard view with dynamic status
- User Management (RBAC)
- System Configuration (Governance, I/A Rules, IdP)
- Tag Management (Labels, Snowflake Tags)
"""
import sys
import os
import pathlib

# Add the project root to the Python path
_here = pathlib.Path(str(__file__)).resolve()
_dir = _here.parent
# Traverse up to find directory containing 'src'
for _ in range(3):
    if (_dir / "src").exists():
        if str(_dir) not in sys.path:
            sys.path.insert(0, str(_dir))
        break
    _dir = _dir.parent

import streamlit as st

# Page configuration - MUST be the first Streamlit command
st.set_page_config(
    page_title="System Configuration - Data Governance App",
    page_icon="🛠️",
    layout="wide"
)

import pandas as pd
import time
from datetime import datetime

from src.ui.theme import apply_global_theme
from src.services.tagging_service import tagging_service, ALLOWED_CLASSIFICATIONS
# from src.services.classification_pipeline_service import discovery_service
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.compliance_service import compliance_service
from src.services.authorization_service import authz
# Removed broken system_classify_service import
from src.ui.quick_links import render_quick_links
from src.components.filters import render_global_filters

# Use tagging_service for label registry operations (backward-compatible alias)
label_service = tagging_service

# Apply centralized theme
apply_global_theme()

st.markdown("""
<style>
    /* Standardized Dashboard-style Card System */
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
        font-size: 11px;
        font-weight: 700;
        color: rgba(255, 255, 255, 0.5);
        text-transform: uppercase;
        letter-spacing: 1.2px;
    }

    .pillar-status {
        font-size: 11px;
        font-weight: 600;
        color: #38bdf8;
        margin-top: 10px;
        padding: 4px 10px;
        background: rgba(56, 189, 248, 0.1);
        border-radius: 20px;
        display: inline-block;
    }
</style>
""", unsafe_allow_html=True)

# Resolve database name
db_name = settings.SNOWFLAKE_DATABASE
if not db_name or str(db_name).upper() == 'NONE':
    db_name = "DATA_CLASSIFICATION_DB"

# Initialize Session State for View Navigation
if 'admin_view' not in st.session_state:
    st.session_state.admin_view = 'Dashboard'

def set_view(view_name):
    st.session_state.admin_view = view_name
    st.rerun()

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS FOR DYNAMIC STATUS
# -----------------------------------------------------------------------------

def get_snowflake_status():
    try:
        snowflake_connector.execute_query("SELECT 1")
        return True, "Connected"
    except Exception:
        return False, "Disconnected"

def get_tag_sync_status():
    try:
        # Check if the main DATA_CLASSIFICATION tag exists
        exists = tagging_service._tag_exists(db_name, "DATA_GOVERNANCE", "DATA_CLASSIFICATION")
        if exists:
            return True, "Active"
        else:
            return False, "Inactive (Missing Tags)"
    except Exception:
        return False, "Error Checking Tags"

def get_metadata_status():
    try:
        # Check if ASSETS table exists and has recent data
        res = snowflake_connector.execute_query(
            f"SELECT MAX(LAST_SCANNED) FROM {db_name}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS"
        )
        if res and res[0] and res[0].get('MAX(LAST_SCANNED)'):
            last_scan = res[0]['MAX(LAST_SCANNED)']
            return True, f"Active (Last: {last_scan})"
        elif res:
             return True, "Active (No scans yet)"
        else:
            return False, "Inactive"
    except Exception:
        # Table might not exist yet
        return False, "Inactive (Table missing)"

def get_auto_classification_status():
    try:
        # Check if CLASSIFICATION_HISTORY exists
        snowflake_connector.execute_query(
            f"SELECT 1 FROM {db_name}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_HISTORY LIMIT 1"
        )
        return True, "Running"
    except Exception:
        return False, "Idle / Not Configured"

# RBAC Check
try:
    _ident = authz.get_current_identity()
    # Hardcoded bypass for testing
    can_admin = True
    try:
        if authz._is_bypass():
            can_admin = True
        else:
            can_admin = authz.is_custodian(_ident) or authz.is_admin(_ident)
    except Exception:
        can_admin = True

    if not can_admin:
        st.error("You do not have permission to access Administration. Contact an Admin.")
        st.stop()
    _is_admin = True
    _is_custodian = True
except Exception as _auth_err:
    _is_admin = True
    _is_custodian = True



# -----------------------------------------------------------------------------
# MAIN RENDERER
# -----------------------------------------------------------------------------

st.markdown("""
<div class="page-hero">
    <div style="display: flex; align-items: center; gap: 1.5rem;">
        <div class="hero-icon-box">🛠️</div>
        <div>
            <h1 class="hero-title">Administration</h1>
            <p class="hero-subtitle">System configuration, user management, and tag governance controls.</p>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Global Filters (In Sidebar)
with st.sidebar:
    g_filters = render_global_filters(key_prefix="admin")

# Quick Links usually stay at top
render_quick_links()

# "Back" navigation if not on Dashboard
if st.session_state.admin_view != 'Dashboard':
    if st.button("← Back to Dashboard"):
        set_view('Dashboard')
    st.markdown("---")

    # -----------------------------------------------------------------------------
    # VIEW: DASHBOARD
    # -----------------------------------------------------------------------------
    if st.session_state.admin_view == 'Dashboard':
        st.caption("System health and platform status")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("👥 User Management")
            st.write("Manage roles, permissions, and access controls")
            if st.button("Manage Users", width='stretch'):
                set_view('Users')
        
        with col2:
            st.subheader("⚙️ System Config")
            st.write("Configure classification schema and business rules")
            if st.button("View Settings", width='stretch'):
                set_view('Config')
        
        st.markdown("---")
        
        st.subheader("🔗 Snowflake Integration Status")
        
        # Dynamic Status Checks
        with st.spinner("Checking integration status..."):
            sf_ok, sf_msg = get_snowflake_status()
            meta_ok, meta_msg = get_metadata_status()
            auto_ok, auto_msg = get_auto_classification_status()

        # Display Status using Pillar Cards
        sc1, sc2, sc3 = st.columns(3)
        
        with sc1:
            color = "#10b981" if sf_ok else "#ef4444"
            icon = "🔌"
            st.markdown(f"""
    <div class="pillar-card">
        <div class="pillar-icon">{icon}</div>
        <div class="pillar-label">Snowflake Connection</div>
        <div class="pillar-value" style="font-size: 1.2rem;">{sf_msg}</div>
        <div class="pillar-status" style="color: {color}; background: {color}20;">Status</div>
    </div>
            """, unsafe_allow_html=True)

        with sc2:
            color = "#10b981" if meta_ok else "#f59e0b"
            icon = "📦"
            st.markdown(f"""
    <div class="pillar-card">
        <div class="pillar-icon">{icon}</div>
        <div class="pillar-label">Assets Inventory</div>
        <div class="pillar-value" style="font-size: 1.2rem;">{meta_msg.split('(')[0].strip()}</div>
        <div class="pillar-status" style="color: {color}; background: {color}20;">Inventory</div>
    </div>
            """, unsafe_allow_html=True)
            
        with sc3:
            color = "#10b981" if auto_ok else "#3b82f6"
            icon = "🤖"
            st.markdown(f"""
    <div class="pillar-card">
        <div class="pillar-icon">{icon}</div>
        <div class="pillar-label">Auto-Classification Status</div>
        <div class="pillar-value" style="font-size: 1.2rem;">{auto_msg}</div>
        <div class="pillar-status" style="color: {color}; background: {color}20;">Service</div>
    </div>
            """, unsafe_allow_html=True)



    # -----------------------------------------------------------------------------
    # VIEW: USER MANAGEMENT (Roles & Permissions)
    # -----------------------------------------------------------------------------
    elif st.session_state.admin_view == 'Users':
        st.header("👥 User Management")
        
        # Keep only Role Assignments tab
        st.subheader("Role-based Access Control")
        st.caption("Manage roles and assignments.")
        try:
            # Reusing existing RBAC logic
            snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db_name}.DATA_GOVERNANCE")
            snowflake_connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {db_name}.DATA_GOVERNANCE.ROLES (
                    ROLE_NAME STRING PRIMARY KEY, DESCRIPTION STRING
                )
                """
            )
            snowflake_connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {db_name}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS (
                    USER_EMAIL STRING, ROLE_NAME STRING, ASSIGNED_AT TIMESTAMP_NTZ, PRIMARY KEY (USER_EMAIL, ROLE_NAME)
                )
                """
            )
            # Get current roles for display
            roles = snowflake_connector.execute_query(
                f"SELECT ROLE_NAME, DESCRIPTION FROM {db_name}.DATA_GOVERNANCE.ROLES ORDER BY ROLE_NAME"
            ) or []
            
            # Display roles in a dataframe with a form to add new roles
            col1, col2 = st.columns([2, 1])
            
            with col1:
                if roles:
                    st.dataframe(pd.DataFrame(roles), width='stretch')
                else:
                    st.warning("No roles found. Please add a role using the form.")
            
            with col2:
                with st.form("add_role_form"):
                    st.subheader("Add New Role")
                    new_role = st.text_input("Role Name", 
                                          help="Enter a unique role name (e.g., 'Data Steward')")
                    role_desc = st.text_area("Description",
                                          help="Describe the role's purpose and permissions")
                    
                    if st.form_submit_button("Create Role"):
                        if new_role and role_desc:
                            try:
                                snowflake_connector.execute_non_query(
                                    f"""
                                    INSERT INTO {db_name}.DATA_GOVERNANCE.ROLES (ROLE_NAME, DESCRIPTION)
                                    VALUES (%(role_name)s, %(description)s)
                                    """,
                                    {"role_name": new_role.strip(), "description": role_desc.strip()}
                                )
                                st.success(f"Role '{new_role}' created successfully!")
                                st.rerun()
                            except Exception as e:
                                if "already exists" in str(e):
                                    st.error(f"Error: A role with name '{new_role}' already exists.")
                                else:
                                    st.error(f"Error creating role: {str(e)}")
                        else:
                            st.warning("Please provide both a role name and description.")
            
            st.markdown("---")
            # Assignments
            st.write("Active Assignments:")
            assigns = snowflake_connector.execute_query(
                f"SELECT USER_EMAIL, ROLE_NAME, ASSIGNED_AT FROM {db_name}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS ORDER BY ASSIGNED_AT DESC LIMIT 200"
            ) or []
            st.dataframe(pd.DataFrame(assigns), width='stretch')
            
            # Add Assignment
            cA, cB, cC = st.columns(3)
            with cA: user_email = st.text_input("User Email")
            with cB: role_name = st.selectbox("Role", [r['ROLE_NAME'] for r in roles] if roles else ["Admin","Custodian"])
            with cC:
                def _local_safe(name: str) -> str:
                    name = (name or "").strip()
                    for ch in [';', '\\', '/', '\'', '"', '`']: name = name.replace(ch, '')
                    return f'"{name.upper()}"'

                if st.button("Assign Role", type="primary"):
                    if _is_admin:
                        try:
                            # 1. Update Application Metadata (Audit/Tracking)
                            snowflake_connector.execute_non_query(
                                f"MERGE INTO {db_name}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS t "
                                f"USING (SELECT %(u)s AS U, %(r)s AS R) s ON t.USER_EMAIL=s.U AND t.ROLE_NAME=s.R "
                                f"WHEN MATCHED THEN UPDATE SET ASSIGNED_AT=CURRENT_TIMESTAMP "
                                f"WHEN NOT MATCHED THEN INSERT (USER_EMAIL, ROLE_NAME, ASSIGNED_AT) VALUES (s.U, s.R, CURRENT_TIMESTAMP)",
                                {"u": user_email, "r": role_name}
                            )
                            
                            # 2. Synchronize with Snowflake (Live Grant)
                            snowflake_connector.execute_non_query(
                                f"GRANT ROLE {_local_safe(role_name)} TO USER {_local_safe(user_email)}"
                            )
                            
                            st.success(f"✅ Governance metadata updated and Role '{role_name}' granted to {user_email} in Snowflake.")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Synchronization Error: {e}")
                    else:
                        st.error("Permission Denied: Admin authorization required.")
        except Exception as e:
            st.error(f"Error loading RBAC: {e}")

    # -----------------------------------------------------------------------------
    # VIEW: SYSTEM CONFIG (Governance, I/A Rules)
    # -----------------------------------------------------------------------------
    elif st.session_state.admin_view == 'Config':
        st.markdown(f"""
    <div style="background: linear-gradient(90deg, rgba(59, 130, 246, 0.1), rgba(0, 0, 0, 0)); padding: 20px; border-radius: 12px; border-left: 4px solid #3b82f6; margin-bottom: 25px;">
        <h3 style="margin:0; color:white; font-size:1.4rem;">⚙️ Governance Engine Controls</h3>
        <p style="margin:5px 0 0 0; color:rgba(255,255,255,0.6); font-size:0.9rem;">
            Configure the <b>intelligence logic</b>, business rules, and <b>security frameworks</b> that power your governance platform.<br>
            Define discovery thresholds and automate integrity assessments across your data landscape.
        </p>
    </div>
    """, unsafe_allow_html=True)
        
        tGov, tIA = st.tabs(["🚀 Platform Capabilities", "🧠 Inference Engine"])
        
        with tGov:
            st.subheader("Core Governance Modules")
            st.caption("Enable or disable platform features to match your organizational needs.")
            try:
                snowflake_connector.execute_non_query(f"CREATE TABLE IF NOT EXISTS {db_name}.DATA_GOVERNANCE.APP_SETTINGS (KEY STRING PRIMARY KEY, VALUE STRING)")
                
                def get_setting(k, d):
                    r = snowflake_connector.execute_query(f"SELECT VALUE FROM {db_name}.DATA_GOVERNANCE.APP_SETTINGS WHERE KEY=%(k)s", {"k":k})
                    return r[0]['VALUE'] if r else d

                col_set1, col_set2 = st.columns(2)
                with col_set1:
                    with st.container(border=True):
                        st.markdown("#### 🔍 Data Discovery")
                        st.write("Enables the automated scanning and inventory tracking of Snowflake assets.")
                        en_disc = st.toggle("Activate Discovery Engine", value=(get_setting("enable_discovery","true")=="true"), key="tg_disc")
                
                with col_set2:
                    with st.container(border=True):
                        st.markdown("#### 📝 Classification Workflow")
                        st.write("Powers the manual review, AI suggestion, and approval cycles for labels.")
                        en_flow = st.toggle("Activate Workflow Studio", value=(get_setting("enable_workflow","true")=="true"), key="tg_flow")
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("💾 Persist Configuration Changes", type="primary", width='stretch'):
                    if _is_admin:
                        snowflake_connector.execute_non_query(
                            f"MERGE INTO {db_name}.DATA_GOVERNANCE.APP_SETTINGS t USING (SELECT 'enable_discovery' as K, '{str(en_disc).lower()}' as V) s ON t.KEY=s.K WHEN MATCHED THEN UPDATE SET VALUE=s.V WHEN NOT MATCHED THEN INSERT (KEY, VALUE) VALUES (s.K, s.V)"
                        )
                        st.success("✅ Configuration synchronized successfully.")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Permission Denied: Administrator role required.")
            except Exception as e:
                st.error(f"Intelligence Sync Failure: {e}")

        with tIA:
            st.subheader("Integrity & Availability (I/A) Logic")
            st.caption("Manage automated inference patterns for data importance and reliability.")
            
            try:
                snowflake_connector.execute_non_query(f"CREATE TABLE IF NOT EXISTS {db_name}.DATA_GOVERNANCE.IA_RULES (TYPE STRING, PATTERN STRING, I_LEVEL NUMBER, A_LEVEL NUMBER, PRIORITY NUMBER, UPDATED_AT TIMESTAMP_NTZ)")
                query = f"""
                SELECT 
                    TYPE, PATTERN, I_LEVEL, A_LEVEL, PRIORITY, UPDATED_AT
                FROM {db_name}.DATA_GOVERNANCE.IA_RULES 
                ORDER BY PRIORITY DESC
                """
                rules = snowflake_connector.execute_query(query) or []
                
                if rules:
                    st.dataframe(
                        pd.DataFrame(rules), 
                        width='stretch',
                        column_config={
                            "UPDATED_AT": st.column_config.DatetimeColumn("Last Modified"),
                            "PRIORITY": st.column_config.NumberColumn("Priority Rank", help="Higher numbers execute first")
                        }
                    )
                else:
                    st.info("No inference rules defined. Use the console below to create your first safeguard.")
                
                with st.expander("🛠️ Rule Authoring Console", expanded=False):
                    with st.form("add_rule", clear_on_submit=True):
                        c1, c2 = st.columns([3, 1])
                        with c1: 
                            patt = st.text_input("Object Name Pattern", placeholder="e.g. %_PAYMENT%, /.*_ID$/", help="Supports SQL ILIKE patterns or regex")
                        with c2: 
                            pri = st.number_input("Priority", value=100, step=10)
                        
                        st.markdown("---")
                        st.write("**Inferred Asset Criticality**")
                        ci, ca = st.columns(2)
                        with ci: 
                            il = st.select_slider("Integrity Level (I)", options=[0, 1, 2, 3], value=2, help="0: Low, 3: High")
                        with ca: 
                            al = st.select_slider("Availability Level (A)", options=[0, 1, 2, 3], value=2, help="0: Low, 3: High")
                        
                        if st.form_submit_button("🚀 Deploy New Inference Rule", width='stretch'):
                            if _is_admin:
                                snowflake_connector.execute_non_query(
                                    f"INSERT INTO {db_name}.DATA_GOVERNANCE.IA_RULES (PATTERN, I_LEVEL, A_LEVEL, PRIORITY, UPDATED_AT) VALUES (%(p)s, %(i)s, %(a)s, %(pri)s, CURRENT_TIMESTAMP)",
                                    {"p": patt, "i": il, "a": al, "pri": pri}
                                )
                                st.success(f"Rule for '{patt}' deployed to engine.")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error("Admin permissions required to modify engine logic.")
            except Exception as e:
                st.error(f"Inference Engine Fault: {e}")

    # Tags view removed as per MVP scope
    pass

