"""
Policy & Guidance page for the Data Governance Application.
- Decision Tree and Quick Reference checklist derived from policy document.
- Links classification actions to rationale capture and exceptions.
"""
from src.ui.quick_links import render_quick_links
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd
from src.ui.theme import apply_global_theme

from src.services import nlp_compliance_service as _ncs  # provides AI policy parsing utilities
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

st.set_page_config(page_title="Handling Rules & Policy Guidance", page_icon="📘", layout="wide")

# Apply centralized theme (fonts, CSS variables, Plotly template)
apply_global_theme()
st.title("Handling Rules & Policy Guidance")
render_quick_links()

# Top-level tabs for policy operations
tab_lib, tab_ai, tab_gen, tab_rules = st.tabs(["Policy Library", "AI Policy Parser & Diff", "Control/Check Generation", "Handling Rules"])

with tab_lib:
    st.subheader("Policy Library")
    st.caption("Versioned policies with effective dates and next review dates. Stored in DATA_GOVERNANCE.POLICIES.")
    try:
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.POLICIES (
              ID STRING,
              TITLE STRING,
              VERSION STRING,
              EFFECTIVE_DATE DATE,
              NEXT_REVIEW_DATE DATE,
              OWNER STRING,
              CONTENT STRING,
              CREATED_AT TIMESTAMP_NTZ
            );
            """
        )
    except Exception:
        pass
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT ID, TITLE, VERSION, EFFECTIVE_DATE, NEXT_REVIEW_DATE, OWNER, LEFT(CONTENT, 200) AS PREVIEW, CREATED_AT
            FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.POLICIES
            ORDER BY CREATED_AT DESC
            LIMIT 500
            """
        ) or []
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.info("No policies found. Upload a new policy in the AI Parser tab or insert via your ETL.")
    except Exception as e:
        st.warning(f"Unable to read policies: {e}")

with tab_ai:
    st.subheader("AI Policy Parser & Diff")
    st.caption("Upload a policy document to extract requirements and controls, and compare against previous versions.")
    up = st.file_uploader("Upload policy file (txt/markdown/pdf)", type=["txt","md","pdf"], key="policy_upload")
    policy_title = st.text_input("Policy Title")
    policy_version = st.text_input("Version", value="1.0")
    owner = st.text_input("Owner (email)")
    eff = st.date_input("Effective Date")
    next_rev = st.date_input("Next Review Date")
    if st.button("Parse & Save") and up and policy_title:
        try:
            raw = up.read()
            # Basic text extraction; PDFs would need extra parsing in nlp_compliance_service if supported
            try:
                text = raw.decode("utf-8", errors="ignore")
            except Exception:
                text = str(raw)
            parsed = _ncs.parse_policy(text)
            st.success("Parsed policy successfully.")
            st.json({k: parsed.get(k) for k in ["requirements","controls","notes"]})
            # Persist
            import uuid
            pid = str(uuid.uuid4())
            snowflake_connector.execute_non_query(
                f"""
                INSERT INTO {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.POLICIES
                (ID, TITLE, VERSION, EFFECTIVE_DATE, NEXT_REVIEW_DATE, OWNER, CONTENT, CREATED_AT)
                SELECT %(id)s, %(t)s, %(v)s, %(e)s, %(n)s, %(o)s, %(c)s, CURRENT_TIMESTAMP
                """,
                {"id": pid, "t": policy_title, "v": policy_version, "e": str(eff), "n": str(next_rev), "o": owner, "c": text}
            )
            st.success(f"Saved policy '{policy_title}' v{policy_version}.")
        except Exception as e:
            st.error(f"Parsing or saving failed: {e}")

with tab_gen:
    st.subheader("Control/Check Generation")
    st.caption("Generate or update framework requirements, controls, and automated checks from parsed policy content.")
    framework = st.text_input("Framework Name (e.g., SOC2, SOX, ISO 27001)", value="SOC2")
    source_text = st.text_area("Policy Content / Excerpts", height=200, placeholder="Paste relevant sections here or select a policy from the library above.")
    if st.button("Generate Draft Mappings"):
        if not source_text.strip():
            st.warning("Please provide policy content for generation.")
        else:
            try:
                gen = _ncs.generate_controls_and_checks(source_text, framework)
                st.success("Generated draft requirements, controls, and checks.")
                st.json(gen)
                st.caption("Review and approve in Compliance → Frameworks & Controls section.")
                # store in session for publish
                st.session_state['policy_gen_output'] = gen
            except Exception as e:
                st.error(f"Generation failed: {e}")

    st.markdown("---")
    st.subheader("Publish to Compliance")
    st.caption("Persist generated Controls and Checks into the Compliance library.")
    pub_owner = st.text_input("Owner (email) for created records", key="gen_pub_owner")
    if st.button("Publish Draft to Library"):
        gen = st.session_state.get('policy_gen_output')
        if not gen:
            st.warning("Please generate draft mappings first.")
        else:
            try:
                # Ensure tables exist (CONTROLS already ensured in Compliance page; also ensure CHECKS here)
                snowflake_connector.execute_non_query(
                    f"""
                    CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.CHECKS (
                      ID STRING,
                      FRAMEWORK STRING,
                      CODE STRING,
                      DESCRIPTION STRING,
                      RULE STRING,
                      CREATED_AT TIMESTAMP_NTZ
                    )
                    """
                )
                import uuid
                fw = gen.get('framework') or (framework or 'FRAMEWORK').upper()
                # Insert controls
                for c in (gen.get('controls') or [])[:200]:
                    try:
                        snowflake_connector.execute_non_query(
                            f"""
                            INSERT INTO {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.CONTROLS
                            (ID, FRAMEWORK, CONTROL_ID, TITLE, DESCRIPTION, STATUS, OWNER, UPDATED_AT)
                            SELECT %(id)s, %(fw)s, %(cid)s, %(title)s, %(desc)s, 'Draft', %(own)s, CURRENT_TIMESTAMP
                            """,
                            {
                                "id": str(uuid.uuid4()),
                                "fw": fw,
                                "cid": c.get('id') or '',
                                "title": (c.get('text') or '')[:180],
                                "desc": c.get('text') or '',
                                "own": pub_owner or '',
                            }
                        )
                    except Exception:
                        continue
                # Insert checks
                for ck in (gen.get('checks') or [])[:200]:
                    try:
                        snowflake_connector.execute_non_query(
                            f"""
                            INSERT INTO {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.CHECKS
                            (ID, FRAMEWORK, CODE, DESCRIPTION, RULE, CREATED_AT)
                            SELECT %(id)s, %(fw)s, %(code)s, %(desc)s, %(rule)s, CURRENT_TIMESTAMP
                            """,
                            {
                                "id": str(uuid.uuid4()),
                                "fw": fw,
                                "code": ck.get('code') or '',
                                "desc": ck.get('description') or '',
                                "rule": ck.get('rule') or '',
                            }
                        )
                    except Exception:
                        continue
                st.success("Published generated controls and checks to the Compliance library.")
            except Exception as e:
                st.error(f"Publishing failed: {e}")

    st.markdown("---")
    st.subheader("Publish AI Rules to Policies (for Dynamic Compliance)")
    st.caption("Persist AI-extracted rules into DATA_GOVERNANCE.POLICIES (FRAMEWORK, RULE_CODE, CATEGORY, MIN_CONFIDENTIALITY, REQUIRE_MASKING, REQUIRE_ROW_ACCESS). These policies drive dynamic compliance mapping without hardcoding.")
    pub_owner2 = st.text_input("Owner (email) for created policies", key="gen_pub_owner2")
    if st.button("Publish AI Rules to POLICIES"):
        gen = st.session_state.get('policy_gen_output')
        if not gen:
            st.warning("Please generate draft mappings first.")
        else:
            try:
                # Ensure DATA_GOVERNANCE.POLICIES has the expected structure (FRAMEWORK/RULE_CODE/...)
                snowflake_connector.execute_non_query(
                    f"""
                    CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.POLICIES (
                      ID STRING,
                      FRAMEWORK STRING,
                      RULE_CODE STRING,
                      RULE_TEXT STRING,
                      CATEGORY STRING,
                      MIN_CONFIDENTIALITY NUMBER,
                      REQUIRE_MASKING BOOLEAN,
                      REQUIRE_ROW_ACCESS BOOLEAN,
                      CREATED_AT TIMESTAMP_NTZ,
                      SOURCE STRING,
                      DETAILS VARIANT
                    )
                    """
                )
                import uuid, json as _json
                fw = (gen.get('framework') or (framework or 'FRAMEWORK')).upper()
                checks = gen.get('checks') or []
                # Map generated checks to policy rows with inferred category and minimums
                for ck in checks:
                    code = ck.get('code') or ''
                    desc = ck.get('description') or ''
                    rule_expr = ck.get('rule') or ''
                    # Infer category and requirements from code/desc heuristically
                    up = f"{code} {desc} {rule_expr}".upper()
                    category = 'Other'
                    min_c = None
                    req_mask = False
                    req_row = False
                    if 'PII' in up:
                        category = 'PII'
                        min_c = 2
                        req_mask = True
                    if any(k in up for k in ['PHI','HIPAA']):
                        category = 'PHI'
                        min_c = max(2, (min_c or 0))
                        req_mask = True
                    if any(k in up for k in ['FINANCIAL','SOX','PCI']):
                        category = 'Financial'
                        # PCI often needs C3, SOX at least C2; pick higher when ambiguous
                        min_c = max(3 if 'PCI' in up else 2, (min_c or 0))
                        req_mask = True
                        req_row = ('ROW ACCESS' in up or 'ROW_ACCESS' in up or 'ROW' in up)
                    # Insert policy row
                    snowflake_connector.execute_non_query(
                        f"""
                        INSERT INTO {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.POLICIES
                        (ID, FRAMEWORK, RULE_CODE, RULE_TEXT, CATEGORY, MIN_CONFIDENTIALITY, REQUIRE_MASKING, REQUIRE_ROW_ACCESS, CREATED_AT, SOURCE, DETAILS)
                        SELECT %(id)s, %(fw)s, %(code)s, %(text)s, %(cat)s, %(minc)s, %(mask)s, %(row)s, CURRENT_TIMESTAMP, 'AI_NLP', TO_VARIANT(PARSE_JSON(%(det)s))
                        """,
                        {
                            'id': str(uuid.uuid4()),
                            'fw': fw,
                            'code': code,
                            'text': desc or rule_expr,
                            'cat': category,
                            'minc': (min_c if min_c is not None else None),
                            'mask': bool(req_mask),
                            'row': bool(req_row),
                            'det': _json.dumps({'source': 'policy_gen', 'rule': rule_expr}),
                        }
                    )
                st.success("Published AI rules to DATA_GOVERNANCE.POLICIES.")
            except Exception as e:
                st.error(f"Publishing to POLICIES failed: {e}")

st.markdown(
    """
    ### Classification Decision Tree (Quick Guide)
    1. Is the data intended for public release or already public?
       - Yes → Classify as **Public (C0)**
       - No → Continue
    2. Does the data contain personal information, proprietary data, or confidential business information?
       - Yes → Continue
       - No → **Internal (C1)**
    3. Would unauthorized disclosure cause severe business harm or regulatory violations?
       - Yes → **Confidential (C3)**
       - No → **Restricted (C2)**
    4. Assess Integrity and Availability (0–3) based on business criticality.
    """
)

st.markdown("---")

st.subheader("Classification Checklist")
st.markdown(
    """
    - [ ] Understand business purpose and context of the data
    - [ ] Identify stakeholders who use/are impacted by the data
    - [ ] Consider regulatory requirements (PII, Financial/SOX, HIPAA, PCI, GDPR)
    - [ ] Assess business impact for Confidentiality, Integrity, Availability
    - [ ] Review similar data classifications for consistency
    - [ ] Document rationale for the decision
    - [ ] Apply tags in Snowflake (classification and CIA levels)
    - [ ] Schedule review/reclassification and communicate to stakeholders
    """
)

st.markdown("---")

st.subheader("Special Categories (Minimums)")
st.info(
    """
    Minimum classifications enforced by policy:
    - Personal Data (PII): at least **Restricted (C2)**
    - Sensitive Personal Data (e.g., SSN): **Confidential (C3)**
    - Financial data used for reporting/SOX: at least **Restricted (C2)**; SOX-relevant **Confidential (C3)**

    If you need an exception, provide business justification and submit a request. Approved exceptions are time-bound and reviewed periodically.
    """
)

st.markdown("---")

st.subheader("Rationale Templates")
st.code(
    """Business Context: <summary of how the data is used and by whom>\n\nImpact Assessment:\n- Confidentiality: <impact of disclosure>\n- Integrity: <impact of incorrect data>\n- Availability: <impact of downtime>\n\nRegulatory Considerations: <PII/Financial/etc.>\n\nDecision & Justification: <final class + CIA with reasons>\n\nStakeholders Notified: <names/roles>\n\nReview Schedule: <date and owner>""",
    language="markdown",
)

with tab_rules:
    st.subheader("🏷️ Data Classification Handling Rules")
    st.caption("Comprehensive guidance for handling data at each classification level (Policy 4.1.3, 5.4)")
    
    # Classification level selector
    classification = st.selectbox(
        "Select Classification Level",
        ["Public", "Internal", "Restricted", "Confidential"],
        key="classification_selector"
    )
    
    # CIA Level selector
    cia_level = st.selectbox(
        "Select CIA Level (0-3)",
        [0, 1, 2, 3],
        key="cia_selector"
    )
    
    # Display handling rules based on selection
    if classification == "Public":
        st.markdown("### 🌐 Public Data (C0)")
        st.info("**Business Impact:** No impact from disclosure")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**✅ Allowed Actions:**")
            st.markdown("- Share freely within organization")
            st.markdown("- Publish to public websites")
            st.markdown("- Include in public reports")
            st.markdown("- Download without restrictions")
            st.markdown("- Email to external parties")
        
        with col2:
            st.markdown("**❌ Restricted Actions:**")
            st.markdown("- None - fully open")
        
        st.markdown("**💾 Storage & Access:**")
        st.markdown("- Any storage location acceptable")
        st.markdown("- No access controls required")
        st.markdown("- No encryption required")
        
    elif classification == "Internal":
        st.markdown(f"### 🏢 Internal Data (C{cia_level})")
        st.info("**Business Impact:** Limited impact from disclosure")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**✅ Allowed Actions:**")
            st.markdown("- Share within organization")
            st.markdown("- Include in internal reports")
            st.markdown("- Store in internal systems")
            if cia_level >= 1:
                st.markdown("- Email within organization")
            if cia_level >= 2:
                st.markdown("- Limited external sharing with NDA")
        
        with col2:
            st.markdown("**❌ Restricted Actions:**")
            st.markdown("- No public disclosure")
            st.markdown("- No external sharing without approval")
            if cia_level >= 1:
                st.markdown("- No unencrypted external transmission")
        
        st.markdown("**💾 Storage & Access:**")
        if cia_level >= 1:
            st.markdown("- Basic access controls required")
        if cia_level >= 2:
            st.markdown("- Encryption recommended for sensitive data")
        
    elif classification == "Restricted":
        st.markdown(f"### 🔒 Restricted Data (C{cia_level})")
        st.warning("**Business Impact:** Moderate impact from disclosure")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**✅ Allowed Actions:**")
            st.markdown("- Access by authorized personnel only")
            st.markdown("- Share with need-to-know basis")
            st.markdown("- Store in secure systems")
            if cia_level >= 2:
                st.markdown("- Email with encryption")
        
        with col2:
            st.markdown("**❌ Restricted Actions:**")
            st.markdown("- No external sharing without approval")
            st.markdown("- No public disclosure")
            st.markdown("- No unencrypted storage")
            st.markdown("- No download without authorization")
            if cia_level >= 1:
                st.markdown("- No transmission over unsecured networks")
        
        st.markdown("**💾 Storage & Access:**")
        st.markdown("- Strict access controls required")
        st.markdown("- Encryption at rest required")
        st.markdown("- Audit logging required")
        if cia_level >= 2:
            st.markdown("- Multi-factor authentication required")
        
    elif classification == "Confidential":
        st.markdown(f"### 🔐 Confidential Data (C{cia_level})")
        st.error("**Business Impact:** Severe impact from disclosure")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**✅ Allowed Actions:**")
            st.markdown("- Access by authorized personnel only")
            st.markdown("- Store in highly secure systems")
            if cia_level >= 3:
                st.markdown("- Limited sharing with executive approval")
        
        with col2:
            st.markdown("**❌ Restricted Actions:**")
            st.markdown("- No external sharing")
            st.markdown("- No public disclosure")
            st.markdown("- No unencrypted storage")
            st.markdown("- No download without executive approval")
            st.markdown("- No email transmission")
            st.markdown("- No printing")
            if cia_level >= 2:
                st.markdown("- No screen sharing")
        
        st.markdown("**💾 Storage & Access:**")
        st.markdown("- Maximum security controls required")
        st.markdown("- Encryption at rest and in transit")
        st.markdown("- Comprehensive audit logging")
        st.markdown("- Data loss prevention (DLP) required")
        
    st.markdown("---")
    st.subheader("🔄 Download & Export Restrictions")
    
    # Download/Export gating logic
    st.markdown("**Current Selection:** {} (C{})".format(classification, cia_level))
    
    # Role-based permissions
    user_role = st.selectbox(
        "Your Role",
        ["Viewer", "Analyst", "Data Owner", "Compliance Officer", "Executive"],
        key="user_role"
    )
    
    can_download = False
    can_export = False
    restriction_reason = ""
    
    if classification == "Public":
        can_download = True
        can_export = True
    elif classification == "Internal":
        can_download = user_role in ["Analyst", "Data Owner", "Compliance Officer", "Executive"]
        can_export = user_role in ["Data Owner", "Compliance Officer", "Executive"]
        if not can_download:
            restriction_reason = "Internal data requires Analyst+ role for download"
    elif classification == "Restricted":
        can_download = user_role in ["Data Owner", "Compliance Officer", "Executive"]
        can_export = user_role in ["Compliance Officer", "Executive"]
        if not can_download:
            restriction_reason = "Restricted data requires Data Owner+ role for download"
    elif classification == "Confidential":
        can_download = user_role in ["Compliance Officer", "Executive"]
        can_export = user_role == "Executive"
        if not can_download:
            restriction_reason = "Confidential data requires Compliance Officer+ role for download"
    
    # Display permissions
    col1, col2 = st.columns(2)
    with col1:
        if can_download:
            st.success("✅ DOWNLOAD ALLOWED")
        else:
            st.error("❌ DOWNLOAD BLOCKED")
            st.warning(restriction_reason)
    
    with col2:
        if can_export:
            st.success("✅ EXPORT ALLOWED")
        else:
            st.error("❌ EXPORT BLOCKED")
            st.warning(restriction_reason)
    
    st.markdown("---")
    st.subheader("🚨 Visual Indicators for Restricted/Confidential")
    
    st.markdown("**Banners and Watermarks:**")
    if classification in ["Restricted", "Confidential"]:
        if classification == "Restricted":
            st.markdown(
                '''<div style="background-color: #fff3cd; border: 2px solid #ffc107; padding: 10px; border-radius: 5px; margin: 10px 0;">
                <strong>🔒 RESTRICTED DATA</strong><br>
                This data requires special handling. Unauthorized access or disclosure is prohibited.
                </div>''',
                unsafe_allow_html=True
            )
        else:  # Confidential
            st.markdown(
                '''<div style="background-color: #f8d7da; border: 2px solid #dc3545; padding: 10px; border-radius: 5px; margin: 10px 0;">
                <strong>🔐 CONFIDENTIAL DATA</strong><br>
                This data is highly sensitive. Access and handling are strictly controlled.
                </div>''',
                unsafe_allow_html=True
            )
        
        st.markdown("**Watermark Example:**")
        st.code(
            f"""-- {classification.upper()} DATA --
-- Classification: {classification} (C{cia_level}) --
-- Unauthorized access prohibited --
-- Last updated: {pd.Timestamp.now().strftime('%Y-%m-%d')} --""",
            language=None
        )
    else:
        st.info("No special visual indicators required for this classification level.")
    
    st.markdown("---")
    st.subheader("📋 Quick Reference Checklist")
    
    st.markdown("**Before Handling Data:**")
    st.markdown("- [ ] Verify your access permissions")
    st.markdown("- [ ] Check classification level and CIA requirements")
    st.markdown("- [ ] Ensure secure transmission method")
    st.markdown("- [ ] Verify recipient authorization")
    st.markdown("- [ ] Document access justification")
    
    st.markdown("**After Handling Data:**")
    st.markdown("- [ ] Clear temporary files")
    st.markdown("- [ ] Log access in audit system")
    st.markdown("- [ ] Verify no data remnants")
    st.markdown("- [ ] Report any security incidents")

