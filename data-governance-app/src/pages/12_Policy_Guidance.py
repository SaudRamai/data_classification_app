"""
Policy & Guidance page for the Data Governance Application.
- Decision Tree and Quick Reference checklist derived from policy document.
- Links classification actions to rationale capture and exceptions.
"""
from src.ui.quick_links import render_quick_links
import sys
import os

# Add the project root (parent of 'src') to the Python path
try:
    _file = __file__
except NameError:
    _file = "12_Policy_Guidance.py"
_root = os.path.abspath(_file)
_dir = os.path.dirname(_root)
for _ in range(3):
    if os.path.exists(os.path.join(_dir, "src")):
        if _dir not in sys.path:
            sys.path.insert(0, _dir)
        break
    _dir = os.path.dirname(_dir)

import streamlit as st
import pandas as pd
from src.ui.theme import apply_global_theme

from src.services.compliance_service import compliance_service as _ncs
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

st.set_page_config(page_title="Handling Rules & Policy Guidance", page_icon="📘", layout="wide")

# Apply centralized theme
apply_global_theme()
st.title("Handling Rules & Policy Guidance")
render_quick_links()

# -----------------------------------------------------------------------------
# DATABASE RESOLUTION
# -----------------------------------------------------------------------------
# Resolve database name to handle 'NONE' or missing settings
db_name = settings.SNOWFLAKE_DATABASE
if not db_name or str(db_name).upper() == 'NONE':
    db_name = "DATA_CLASSIFICATION_DB"

# Ensure Schema exists
try:
    snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db_name}.DATA_CLASSIFICATION_GOVERNANCE")
except Exception:
    pass

# -----------------------------------------------------------------------------
# DYNAMIC DATA FETCHING
# -----------------------------------------------------------------------------

def get_role_counts():
    """Fetch user counts per role from DATA_GOVERNANCE.ROLE_ASSIGNMENTS"""
    counts = {
        "Data Owner": 0,
        "Data Custodian": 0,
        "Classification Specialist": 0,
        "Data Consumer": 0
    }
    try:
        # NOTE: Roles are likely in DATA_GOVERNANCE schema based on other pages, 
        # but safe to check both or assume DATA_GOVERNANCE per Administration page.
        # We will use the resolved db_name.
        snowflake_connector.execute_query(f"SELECT 1 FROM {db_name}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS LIMIT 1")
        
        query = f"""
            SELECT ROLE_NAME, COUNT(DISTINCT USER_EMAIL) as CNT
            FROM {db_name}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS
            GROUP BY ROLE_NAME
        """
        rows = snowflake_connector.execute_query(query) or []
        for r in rows:
            r_name = str(r['ROLE_NAME']).upper()
            if "OWNER" in r_name:
                counts["Data Owner"] += r['CNT']
            elif "CUSTODIAN" in r_name:
                counts["Data Custodian"] += r['CNT']
            elif "SPECIALIST" in r_name or "ADMIN" in r_name:
                counts["Classification Specialist"] += r['CNT']
            else:
                counts["Data Consumer"] += r['CNT']
    except Exception:
        pass
    return counts

def get_key_policies():
    """Fetch latest policies, prioritizing SOX, SOC2, PII using new Schema"""
    policies = []
    try:
        # Check if table exists in new schema
        snowflake_connector.execute_query(f"SELECT 1 FROM {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES LIMIT 1")
        
        query = f"""
            SELECT POLICY_ID, POLICY_NAME, POLICY_VERSION, LEFT(POLICY_CONTENT, 100) as DESC
            FROM {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES
            WHERE POLICY_NAME ILIKE '%SOX%' OR POLICY_NAME ILIKE '%SOC2%' OR POLICY_NAME ILIKE '%PII%' OR POLICY_NAME ILIKE '%CLASSIFICATION%'
            ORDER BY CREATED_AT DESC
            LIMIT 4
        """
        rows = snowflake_connector.execute_query(query) or []
        # Normalize keys for UI defaults
        for r in rows:
            policies.append({
                "TITLE": r.get('POLICY_NAME'),
                "VERSION": r.get('POLICY_VERSION'),
                "DESC": r.get('DESC')
            })
    except Exception:
        pass
    
    # Fallback
    if not policies:
        policies = [
            {"TITLE": "Data Classification Policy", "VERSION": "1.0", "DESC": "Standard classification handling procedures."},
            {"TITLE": "SOX Compliance Guidelines", "VERSION": "2.1", "DESC": "Financial reporting controls."},
            {"TITLE": "SOC2 Controls Matrix", "VERSION": "1.0", "DESC": "Security, Availability, and Confidentiality controls."},
            {"TITLE": "PII Handling Procedures", "VERSION": "1.2", "DESC": "Guidelines for personally identifiable information."}
        ]
    return policies

# -----------------------------------------------------------------------------
# UI LAYOUT
# -----------------------------------------------------------------------------

tab_dash, tab_manage = st.tabs([
    "Policy Dashboard", 
    "Upload & Manage"
])

# --- DASHBOARD TAB ---
with tab_dash:
    st.caption("Access policy documents, guidelines, and governance resources")
    
    role_counts = get_role_counts()
    policies = get_key_policies()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📄 Policy Hub")
        for p in policies:
            label = f"{p.get('TITLE', 'Policy')} (v{p.get('VERSION','1.0')})" 
            if st.button(label, key=f"pol_btn_{p.get('TITLE')}", use_container_width=True):
                st.info(f"Summary: {p.get('DESC', 'No preview available.')}")

        if len(policies) < 4:
             st.button("FAQ & Best Practices", use_container_width=True)

    with col2:
        st.subheader("👥 Roles & Responsibilities")
        st.info(f"**Data Owner** - {role_counts['Data Owner']} users")
        st.info(f"**Data Custodian** - {role_counts['Data Custodian']} users")
        st.info(f"**Classification Specialist** - {role_counts['Classification Specialist']} users")
        st.info(f"**Data Consumer** - {role_counts['Data Consumer']} users")
    
    st.markdown("---")
    
    st.subheader("📐 Classification Framework")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.write("**Confidentiality (C)**")
        st.success("C0 - Public")
        st.warning("C1 - Internal")
        st.error("C2 - Restricted")
        st.error("C3 - Confidential")
    
    with col2:
        st.write("**Integrity (I)**")
        st.info("I0 - Low")
        st.info("I1 - Standard")
        st.info("I2 - High")
        st.info("I3 - Critical")
    
    with col3:
        st.write("**Availability (A)**")
        st.info("A0 - Low")
        st.info("A1 - Standard")
        st.info("A2 - High")
        st.info("A3 - Critical")

# --- UPLOAD & MANAGE TAB ---
with tab_manage:
    st.subheader("Upload & Manage Policies")
    st.caption("Upload new policies or update existing ones. Use the AI Parser to auto-extract details.")
    
    # 1. Ensure Table Exists with NEW Schema
    try:
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES (
                POLICY_ID VARCHAR(36) PRIMARY KEY, -- DEFAULT UUID_STRING() not always supported in simple CREATE syntax if implied
                POLICY_NAME VARCHAR(255) NOT NULL,
                POLICY_VERSION VARCHAR(20),
                POLICY_TYPE VARCHAR(100),
                DOCUMENT_CLASSIFICATION VARCHAR(50),
                EFFECTIVE_DATE DATE,
                NEXT_REVIEW_DATE DATE,
                DOCUMENT_OWNER VARCHAR(255),
                APPROVAL_AUTHORITY VARCHAR(255),
                BUSINESS_UNIT VARCHAR(100),
                POLICY_CONTENT TEXT,
                FILE_CONTENT VARIANT,
                FILE_NAME VARCHAR(500),
                FILE_SIZE NUMBER,
                MIME_TYPE VARCHAR(100),
                CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
                UPDATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                UPDATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
                STATUS VARCHAR(50) DEFAULT 'ACTIVE'
            );
            """
        )
    except Exception as e:
        # It might fail if table exists with different schema, we'll try to proceed or user might need to drop it.
        # But IF NOT EXISTS should handle it.
        pass

    # 2. Fetch existing for dropdown
    existing_policies = []
    try:
        existing_policies = snowflake_connector.execute_query(
            f"SELECT POLICY_ID, POLICY_NAME, POLICY_VERSION FROM {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES WHERE POLICY_NAME IS NOT NULL ORDER BY POLICY_NAME"
        ) or []
    except Exception:
        pass

    action = st.radio("Action", ["Create New Policy", "Update Existing Policy"], horizontal=True)

    selected_policy_id = None
    default_title = ""
    default_ver = "1.0"
    default_owner = ""
    
    if action == "Update Existing Policy":
        if not existing_policies:
            st.warning("No existing policies found to update.")
        else:
            # Create a label map
            pol_map = {f"{p['POLICY_NAME']} (v{p['POLICY_VERSION']})": p for p in existing_policies}
            sel_pol_label = st.selectbox("Select Policy to Update", list(pol_map.keys()))
            if sel_pol_label:
                sel_pol = pol_map[sel_pol_label]
                selected_policy_id = sel_pol['POLICY_ID']
                default_title = sel_pol['POLICY_NAME']
                try:
                    v_parts = str(sel_pol['POLICY_VERSION']).split('.')
                    if len(v_parts) == 2:
                        default_ver = f"{v_parts[0]}.{int(v_parts[1])+1}"
                    else:
                         default_ver = f"{sel_pol['POLICY_VERSION']}.1"
                except:
                    default_ver = "1.1"

    st.markdown("#### Policy Details")
    with st.form("policy_form"):
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            p_name = st.text_input("Policy Name", value=default_title, disabled=(action=="Update Existing Policy"))
            p_ver = st.text_input("Version", value=default_ver)
            p_owner = st.text_input("Document Owner")
            p_type = st.selectbox("Policy Type", ["Standard", "Procedure", "Guideline", "Framework"], index=0)
        with col_f2:
            p_eff = st.date_input("Effective Date")
            p_rev = st.date_input("Next Review Date")
            p_class = st.selectbox("Document Classification", ["Internal", "Public", "Confidential", "Restricted"])
        
        st.markdown("#### Document Content")
        uploaded_file = st.file_uploader("Upload Policy Document (PDF/TXT/MD)", type=['pdf','txt','md'])
        
        p_content = st.text_area("Or Paste Content / Edit Parsed Text", height=200)

        submit = st.form_submit_button("Save Policy")
    
    if submit:
        final_content = p_content
        fname = None
        fsize = 0
        fmime = "text/plain"
        
        if uploaded_file:
            fname = uploaded_file.name
            fsize = uploaded_file.size
            fmime = uploaded_file.type
            try:
                raw = uploaded_file.read()
                try:
                    final_content = raw.decode("utf-8", errors="ignore")
                except Exception:
                    final_content = str(raw)
            except Exception as e:
                st.error(f"Error reading file: {e}")
                st.stop()
        
        if not p_name:
            st.error("Policy Name is required.")
        elif not final_content:
            st.error("Content is required.")
        else:
            import uuid
            try:
                if action == "Create New Policy":
                    new_id = str(uuid.uuid4())
                    snowflake_connector.execute_non_query(
                        f"""
                        INSERT INTO {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES
                        (
                            POLICY_ID, POLICY_NAME, POLICY_VERSION, POLICY_TYPE, DOCUMENT_CLASSIFICATION,
                            EFFECTIVE_DATE, NEXT_REVIEW_DATE, DOCUMENT_OWNER, POLICY_CONTENT, 
                            FILE_NAME, FILE_SIZE, MIME_TYPE, CREATED_AT, UPDATED_AT
                        )
                        SELECT 
                            %(id)s, %(name)s, %(ver)s, %(type)s, %(dclass)s,
                            %(eff)s, %(rev)s, %(own)s, %(cont)s,
                            %(fn)s, %(fs)s, %(fmt)s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                        """,
                        {
                            "id": new_id, "name": p_name, "ver": p_ver, "type": p_type, "dclass": p_class,
                            "eff": str(p_eff), "rev": str(p_rev), "own": p_owner, "cont": final_content,
                            "fn": fname, "fs": fsize, "fmt": fmime
                        }
                    )
                    st.success(f"Created new policy: {p_name} v{p_ver}")
                    
                else: # Update  
                    if selected_policy_id:
                        snowflake_connector.execute_non_query(
                            f"""
                            UPDATE {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES
                            SET 
                                POLICY_NAME=%(name)s, POLICY_VERSION=%(ver)s, POLICY_TYPE=%(type)s, 
                                DOCUMENT_CLASSIFICATION=%(dclass)s, EFFECTIVE_DATE=%(eff)s, 
                                NEXT_REVIEW_DATE=%(rev)s, DOCUMENT_OWNER=%(own)s, POLICY_CONTENT=%(cont)s,
                                FILE_NAME=%(fn)s, FILE_SIZE=%(fs)s, MIME_TYPE=%(fmt)s, UPDATED_AT=CURRENT_TIMESTAMP
                            WHERE POLICY_ID=%(id)s
                            """,
                            {
                                "id": selected_policy_id, "name": p_name, "ver": p_ver, "type": p_type,
                                "dclass": p_class, "eff": str(p_eff), "rev": str(p_rev), "own": p_owner, 
                                "cont": final_content, "fn": fname, "fs": fsize, "fmt": fmime
                            }
                        )
                        st.success(f"Updated policy: {p_name}")
                    else:
                        st.error("Policy ID missing for update.")
                        
            except Exception as e:
                st.error(f"Database Error: {e}")


