"""
Policy & Guidance page for the Data Governance Application.
- Decision Tree and Quick Reference checklist derived from policy document.
- Links classification actions to rationale capture and exceptions.
"""
from src.ui.quick_links import render_quick_links
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

# MUST be the first Streamlit command
st.set_page_config(page_title="Handling Rules & Policy Guidance", page_icon="📘", layout="wide")

import pandas as pd
import time
import io
try:
    import pypdf
except ImportError:
    pypdf = None
from src.ui.theme import apply_global_theme
from src.services.compliance_service import compliance_service as _ncs
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.components.filters import render_global_filters

from src.services.authorization_service import authz

# Apply centralized theme
apply_global_theme()

# ============================================================================
# RBAC CHECK
# ============================================================================
try:
    _ident = authz.get_current_identity()
    if not authz.is_consumer(_ident):
        if authz._is_bypass():
            st.warning("RBAC bypass active (testing). UI is visible for verification.")
        else:
            st.error("You do not have permission to access the Policy module.")
            st.stop()
except Exception as _auth_err:
    if not authz._is_bypass():
        st.warning(f"Authorization check failed: {_auth_err}")
        st.stop()

# Global Filters

with st.sidebar:
    g_filters = render_global_filters(key_prefix="policy")

st.markdown("""
<div class="page-hero">
    <div style="display: flex; align-items: center; gap: 1.5rem;">
        <div class="hero-icon-box">📘</div>
        <div>
            <h1 class="hero-title">Handling Rules & Policy Guidance</h1>
            <p class="hero-subtitle">Decision frameworks and handling requirements for sensitive data.</p>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)
render_quick_links()

st.markdown("""
<style>
    /* Premium Dashboard Styles */
    .glass-card {
        background: linear-gradient(145deg, rgba(31, 41, 55, 0.4), rgba(17, 24, 39, 0.6));
        border-radius: 16px;
        padding: 20px;
        border: 1px solid rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(8px);
        margin-bottom: 20px;
    }

    .policy-item {
        background: rgba(59, 130, 246, 0.05);
        border-left: 4px solid #3b82f6;
        padding: 15px;
        border-radius: 0 12px 12px 0;
        margin-bottom: 12px;
        transition: all 0.3s ease;
    }

    .policy-item:hover {
        background: rgba(59, 130, 246, 0.1);
        transform: translateX(5px);
    }

    .role-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 8px;
    }

    .framework-tier {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 8px 12px;
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.03);
        margin-bottom: 6px;
    }

    .tier-circle {
        width: 10px;
        height: 10px;
        border-radius: 50%;
    }

    /* Card System */
    .pillar-card {
        background: linear-gradient(135deg, rgba(26, 32, 44, 0.7), rgba(17, 21, 28, 0.9));
        border-radius: 18px;
        padding: 20px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        text-align: center;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }
    
    .pillar-card:hover {
        transform: translateY(-5px);
        border-color: rgba(59, 130, 246, 0.4);
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
    }

    .pillar-icon { font-size: 24px; margin-bottom: 8px; }
    .pillar-value { font-size: 28px; font-weight: 800; color: #fff; margin-bottom: 2px; }
    .pillar-label { font-size: 10px; font-weight: 700; color: rgba(255,255,255,0.4); text-transform: uppercase; letter-spacing: 1px; }
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# DATABASE RESOLUTION
# -----------------------------------------------------------------------------
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

def get_governance_roles():
    """Fetch Snowflake roles synchronized with application responsibility metadata."""
    try:
        sf_roles_raw = snowflake_connector.execute_query("SHOW ROLES") or []
        sf_role_names = [r['name'].upper() for r in sf_roles_raw]
        
        meta_rows = snowflake_connector.execute_query(
            f"SELECT ROLE_NAME, DESCRIPTION FROM {db_name}.DATA_GOVERNANCE.ROLES"
        ) or []
        meta_dict = {r['ROLE_NAME'].upper(): r['DESCRIPTION'] for r in meta_rows}
        
        sync_roles = []
        for name in sorted(sf_role_names):
            sync_roles.append({
                "ROLE": name,
                "RESPONSIBILITY": meta_dict.get(name, "General functional role; specific governance responsibility not defined.")
            })
        return sync_roles
    except Exception:
        return []

def get_role_counts():
    """Fetch counts per major governance category for the dashboard."""
    counts = {"Owners": 0, "Stewards": 0, "Analysts": 0, "Consumers": 0}
    try:
        query = f"SELECT ROLE_NAME, COUNT(DISTINCT USER_EMAIL) as CNT FROM {db_name}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS GROUP BY 1"
        rows = snowflake_connector.execute_query(query) or []
        for r in rows:
            rn = str(r['ROLE_NAME']).upper()
            if "OWNER" in rn: counts["Owners"] += r['CNT']
            elif "STEWARD" in rn or "CUSTODIAN" in rn: counts["Stewards"] += r['CNT']
            elif "ANALYST" in rn or "SPECIALIST" in rn: counts["Analysts"] += r['CNT']
            else: counts["Consumers"] += r['CNT']
    except Exception:
        pass
    return counts

def get_key_policies():
    """Fetch all policies present in the POLICIES table."""
    policies = []
    try:
        # Check if table exists
        snowflake_connector.execute_query(f"SELECT 1 FROM {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES LIMIT 1")
        
        query = f"""
            SELECT POLICY_ID, POLICY_NAME, POLICY_VERSION, POLICY_CONTENT, FILE_NAME,
                   REGEXP_REPLACE(LEFT(POLICY_CONTENT, 200), '[\r\n\t]+', ' ', 1, 0) as SNIP
            FROM {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES
            ORDER BY CREATED_AT DESC
        """
        rows = snowflake_connector.execute_query(query) or []
        for r in rows:
            policies.append({
                "TITLE": r.get('POLICY_NAME'),
                "VERSION": r.get('POLICY_VERSION'),
                "DESC": r.get('SNIP'),
                "FULL": r.get('POLICY_CONTENT'),
                "FNAME": r.get('FILE_NAME') or f"{r.get('POLICY_NAME')}.txt"
            })
    except Exception:
        pass
    
    return policies

# -----------------------------------------------------------------------------
# UI LAYOUT
# -----------------------------------------------------------------------------

tab_dash, tab_manage = st.tabs(["Policy Dashboard", "Upload & Manage"])

# --- DASHBOARD TAB ---
with tab_dash:
    st.markdown(f"""
    <div style="background: linear-gradient(90deg, rgba(59, 130, 246, 0.08), rgba(0, 0, 0, 0)); padding: 15px; border-radius: 12px; border-left: 3px solid #3b82f6; margin-bottom: 20px;">
        <span style="color:rgba(255,255,255,0.6); font-size:0.85rem; font-weight:600; text-transform:uppercase; letter-spacing:1px;">Governance Command Center</span>
        <h3 style="margin:0; color:white; font-size:1.4rem;">Policy Hub & Accountability Framework</h3>
    </div>
    """, unsafe_allow_html=True)
    
    role_counts = get_role_counts()
    policies = get_key_policies()
    
    col1, col2 = st.columns([1, 1.5], gap="large")
    
    with col1:
        st.markdown('<h4 style="color:#3b82f6; font-size:1rem; margin-bottom:15px;">📄 ACTIVE POLICIES</h4>', unsafe_allow_html=True)
        
        if not policies:
            st.info("No policy documents found in the database. Use the 'Upload & Manage' tab to add governance documentation.")
        
        for p in policies:
            with st.container():
                st.markdown(f"""
                <div class="policy-item">
                    <div style="font-weight:700; color:white; font-size:0.95rem;">{p.get('TITLE')}</div>
                    <div style="font-size:0.75rem; color:rgba(255,255,255,0.5); margin-top:4px;">Version {p.get('VERSION')} • Active</div>
                </div>
                """, unsafe_allow_html=True)
                
                c_btn1, c_btn2 = st.columns(2)
                with c_btn1:
                    if st.button("Read Summary", key=f"rd_{p.get('TITLE')}"):
                        st.info(f"**Preview:** {p.get('DESC')}...")
                with c_btn2:
                    st.download_button(
                        label="📤 Download Text",
                        data=p.get('FULL') or "",
                        file_name=f"EXTRACTED_{p.get('FNAME') if p.get('FNAME').endswith('.txt') else p.get('FNAME') + '.txt'}",
                        mime="text/plain",
                        key=f"dl_{p.get('TITLE')}",
                        use_container_width=True
                    )
        
        st.markdown("<br>", unsafe_allow_html=True)

    with col2:
        st.markdown('<h4 style="color:#10b981; font-size:1rem; margin-bottom:15px;">👥 ROLES & RESPONSIBILITIES</h4>', unsafe_allow_html=True)
        
        gov_roles = get_governance_roles()
        
        # Add Search
        search_role = st.text_input("🔍 Search Roles", placeholder="Filter by role name...", label_visibility="collapsed")
        
        # Filter and Sort: Governed roles first, then by name
        filtered_roles = [r for r in gov_roles if search_role.upper() in r['ROLE'].upper()]
        # Sort key: (is_not_governed, name) -> Governed (is_not_governed=False) comes first
        filtered_roles.sort(key=lambda x: ("responsibility not defined" in x['RESPONSIBILITY'].lower(), x['ROLE']))

        with st.container(height=400, border=False):
            if not filtered_roles:
                st.info("No matching roles found.")
            for r in filtered_roles:
                is_defined = "responsibility not defined" not in r['RESPONSIBILITY'].lower()
                border_color = "rgba(16, 185, 129, 0.4)" if is_defined else "rgba(255, 255, 255, 0.05)"
                bg_color = "rgba(16, 185, 129, 0.03)" if is_defined else "rgba(255, 255, 255, 0.01)"
                
                st.markdown(f"""
                <div style="background: {bg_color}; border: 1px solid {border_color}; border-radius: 12px; padding: 14px; margin-bottom: 12px; transition: all 0.2s ease;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <span style="font-weight:700; color:white; font-size:1rem; letter-spacing:0.5px;">{r['ROLE']}</span>
                        <span class="role-badge" style="margin:0; background:{'rgba(16, 185, 129, 0.15)' if is_defined else 'rgba(255,255,255,0.08)'}; color:{'#10b981' if is_defined else 'rgba(255,255,255,0.4)'}; border: 1px solid {'#10b98140' if is_defined else 'transparent'};">
                            {('Governed' if is_defined else 'Functional')}
                        </span>
                    </div>
                    <div style="font-size:0.85rem; color:{'rgba(255,255,255,0.8)' if is_defined else 'rgba(255,255,255,0.45)'}; line-height:1.5;">{r['RESPONSIBILITY']}</div>
                </div>
                """, unsafe_allow_html=True)
            
        st.markdown("<br>", unsafe_allow_html=True)
        sc1, sc2, sc3 = st.columns(3)
        with sc1:
            st.markdown(f'<div class="pillar-card"><div class="pillar-icon">👑</div><div class="pillar-value">{role_counts["Owners"]}</div><div class="pillar-label">Owners</div></div>', unsafe_allow_html=True)
        with sc2:
            st.markdown(f'<div class="pillar-card"><div class="pillar-icon">🛠️</div><div class="pillar-value">{role_counts["Stewards"]}</div><div class="pillar-label">Stewards</div></div>', unsafe_allow_html=True)
        with sc3:
            st.markdown(f'<div class="pillar-card"><div class="pillar-icon">👥</div><div class="pillar-value">{role_counts["Analysts"]+role_counts["Consumers"]}</div><div class="pillar-label">Users</div></div>', unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown('<h4 style="color:#f59e0b; font-size:1rem; margin-bottom:15px; text-transform:uppercase; letter-spacing:1px;">📐 Classification Framework (C/I/A)</h4>', unsafe_allow_html=True)
    f1, f2, f3 = st.columns(3)
    
    with f1:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.write("**Confidentiality (C)**")
        tiers = [("C0 - Public", "#10b981"), ("C1 - Internal", "#f59e0b"), ("C2 - Restricted", "#f43f5e"), ("C3 - Confidential", "#9f1239")]
        for t, c in tiers:
            st.markdown(f'<div class="framework-tier"><div class="tier-circle" style="background:{c}"></div><span style="font-size:0.85rem;">{t}</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with f2:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.write("**Integrity (I)**")
        tiers = [("I0 - Low", "#64748b"), ("I1 - Standard", "#3b82f6"), ("I2 - High", "#6366f1"), ("I3 - Critical", "#8b5cf6")]
        for t, c in tiers:
            st.markdown(f'<div class="framework-tier"><div class="tier-circle" style="background:{c}"></div><span style="font-size:0.85rem;">{t}</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with f3:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.write("**Availability (A)**")
        tiers = [("A0 - Low", "#64748b"), ("A1 - Standard", "#3b82f6"), ("A2 - High", "#6366f1"), ("A3 - Critical", "#8b5cf6")]
        for t, c in tiers:
            st.markdown(f'<div class="framework-tier"><div class="tier-circle" style="background:{c}"></div><span style="font-size:0.85rem;">{t}</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# --- UPLOAD & MANAGE TAB ---
with tab_manage:
    st.markdown(f"""
    <div style="background: linear-gradient(90deg, rgba(16, 185, 129, 0.08), rgba(0, 0, 0, 0)); padding: 15px; border-radius: 12px; border-left: 3px solid #10b981; margin-bottom: 25px;">
        <h3 style="margin:0; color:white; font-size:1.3rem;">📤 Policy Lifecycle Management</h3>
        <p style="margin:5px 0 0 0; color:rgba(255,255,255,0.6); font-size:0.9rem;">
            Maintain authoritative policy versions and business rules. Use the <b>AI Document Parser</b> for intelligent field extraction.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    try:
        snowflake_connector.execute_non_query(
            f"CREATE TABLE IF NOT EXISTS {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES (POLICY_ID VARCHAR(36) PRIMARY KEY, POLICY_NAME VARCHAR(255) NOT NULL, POLICY_VERSION VARCHAR(20), POLICY_TYPE VARCHAR(100), DOCUMENT_CLASSIFICATION VARCHAR(50), EFFECTIVE_DATE DATE, NEXT_REVIEW_DATE DATE, DOCUMENT_OWNER VARCHAR(255), POLICY_CONTENT TEXT, FILE_NAME VARCHAR(500), FILE_SIZE NUMBER, MIME_TYPE VARCHAR(100), CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(), UPDATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(), STATUS VARCHAR(50) DEFAULT 'ACTIVE');"
        )
    except Exception: pass

    action = st.radio("Management Phase", ["🆕 Create New Policy", "🔄 Update Existing Documentation"], horizontal=True)

    # 2. Fetch existing for dropdown
    existing_policies = []
    try:
        existing_policies = snowflake_connector.execute_query(
            f"SELECT * FROM {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES WHERE POLICY_NAME IS NOT NULL ORDER BY POLICY_NAME"
        ) or []
    except Exception: pass

    selected_policy_id = None
    default_title = ""
    default_ver = "1.0"
    default_owner = ""
    default_type = "Standard"
    default_eff = None
    default_rev = None
    default_class = "Internal"
    default_content = ""
    
    if "Update" in action:
        if not existing_policies:
            st.warning("No existing policies found to update.")
        else:
            pol_map = {f"{p['POLICY_NAME']} (v{p['POLICY_VERSION']})": p for p in existing_policies}
            sel_pol_label = st.selectbox("Select Policy to Update", list(pol_map.keys()))
            if sel_pol_label:
                sel_pol = pol_map[sel_pol_label]
                selected_policy_id = sel_pol['POLICY_ID']
                default_title = sel_pol['POLICY_NAME']
                default_owner = sel_pol.get('DOCUMENT_OWNER', "")
                default_type = sel_pol.get('POLICY_TYPE', "Standard")
                default_eff = sel_pol.get('EFFECTIVE_DATE')
                default_rev = sel_pol.get('NEXT_REVIEW_DATE')
                default_class = sel_pol.get('DOCUMENT_CLASSIFICATION', "Internal")
                default_content = sel_pol.get('POLICY_CONTENT', "")
                
                try:
                    v_parts = str(sel_pol['POLICY_VERSION']).split('.')
                    if len(v_parts) == 2: default_ver = f"{v_parts[0]}.{int(v_parts[1])+1}"
                    else: default_ver = f"{sel_pol['POLICY_VERSION']}.1"
                except: default_ver = "1.1"

    st.markdown("#### Policy Details")
    with st.form("policy_form"):
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            p_name = st.text_input("Policy Name", value=default_title, disabled=("Update" in action))
            p_ver = st.text_input("Version", value=default_ver)
            p_owner = st.text_input("Document Owner", value=default_owner)
            try:
                type_idx = ["Standard", "Procedure", "Guideline", "Framework"].index(default_type)
            except: type_idx = 0
            p_type = st.selectbox("Policy Type", ["Standard", "Procedure", "Guideline", "Framework"], index=type_idx)
        with col_f2:
            p_eff = st.date_input("Effective Date", value=default_eff)
            p_rev = st.date_input("Next Review Date", value=default_rev)
            try:
                class_idx = ["Internal", "Public", "Confidential", "Restricted"].index(default_class)
            except: class_idx = 0
            p_class = st.selectbox("Document Classification", ["Internal", "Public", "Confidential", "Restricted"], index=class_idx)
        uploaded_file = st.file_uploader("Upload Policy Document (PDF/TXT/MD)", type=['pdf','txt','md'])
        p_content = st.text_area("Or Paste Content / Edit Parsed Text", value=default_content, height=250)
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
                raw_bytes = uploaded_file.read()
                # More robust PDF detection
                is_pdf = fmime == "application/pdf" or fname.lower().endswith(".pdf") or raw_bytes.startswith(b"%PDF")
                
                if is_pdf:
                    if pypdf:
                        try:
                            reader = pypdf.PdfReader(io.BytesIO(raw_bytes))
                            text_pages = []
                            for page in reader.pages:
                                extracted = page.extract_text()
                                if extracted: text_pages.append(extracted)
                            
                            final_content = "\n\n".join(text_pages).strip()
                            if not final_content:
                                final_content = "[System: PDF extraction yielded no text. The document may be scanned or image-based.]"
                            else:
                                st.info(f"✅ Extracted {len(text_pages)} pages of text from PDF.")
                        except Exception as pdf_err:
                            final_content = f"[System: PDF Processing Error: {pdf_err}]"
                    else:
                        st.error("⚠️ 'pypdf' library not available in environment. Saving raw file stream (not recommended for PDF).")
                        final_content = raw_bytes.decode("utf-8", errors="ignore")
                else:
                    try:
                        final_content = raw_bytes.decode("utf-8", errors="ignore")
                    except Exception:
                        final_content = "[System: Binary or incompatible text encoding detected.]"
            except Exception as e:
                st.error(f"Error reading file: {e}")
                st.stop()
        
        if not p_name:
            st.error("Policy Name is required.")
        elif not final_content and not p_content:
            st.error("Policy content is required (either via upload or manual entry).")
        else:
            # Use p_content only if no file was uploaded, otherwise prefer extracted file content
            save_content = final_content if uploaded_file else p_content
            import uuid
            try:
                if "🆕" in action:
                    new_id = str(uuid.uuid4())
                    snowflake_connector.execute_non_query(
                        f"INSERT INTO {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES (POLICY_ID, POLICY_NAME, POLICY_VERSION, POLICY_TYPE, DOCUMENT_CLASSIFICATION, EFFECTIVE_DATE, NEXT_REVIEW_DATE, DOCUMENT_OWNER, POLICY_CONTENT, FILE_NAME, FILE_SIZE, MIME_TYPE, CREATED_AT, UPDATED_AT) VALUES (%(id)s, %(name)s, %(ver)s, %(type)s, %(dclass)s, %(eff)s, %(rev)s, %(own)s, %(cont)s, %(fn)s, %(fs)s, %(fmt)s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                        {"id": new_id, "name": p_name, "ver": p_ver, "type": p_type, "dclass": p_class, "eff": str(p_eff), "rev": str(p_rev), "own": p_owner, "cont": save_content, "fn": fname, "fs": fsize, "fmt": fmime}
                    )
                    st.success(f"Created new policy: {p_name} v{p_ver}")
                else: 
                    if selected_policy_id:
                        snowflake_connector.execute_non_query(
                            f"UPDATE {db_name}.DATA_CLASSIFICATION_GOVERNANCE.POLICIES SET POLICY_NAME=%(name)s, POLICY_VERSION=%(ver)s, POLICY_TYPE=%(type)s, DOCUMENT_CLASSIFICATION=%(dclass)s, EFFECTIVE_DATE=%(eff)s, NEXT_REVIEW_DATE=%(rev)s, DOCUMENT_OWNER=%(own)s, POLICY_CONTENT=%(cont)s, FILE_NAME=%(fn)s, FILE_SIZE=%(fs)s, MIME_TYPE=%(fmt)s, UPDATED_AT=CURRENT_TIMESTAMP WHERE POLICY_ID=%(id)s",
                            {"id": selected_policy_id, "name": p_name, "ver": p_ver, "type": p_type, "dclass": p_class, "eff": str(p_eff), "rev": str(p_rev), "own": p_owner, "cont": save_content, "fn": fname, "fs": fsize, "fmt": fmime}
                        )
                        st.success(f"Updated policy: {p_name}")
                    else: st.error("Policy ID missing for update.")
            except Exception as e: st.error(f"Database Error: {e}")
