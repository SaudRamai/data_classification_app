"""
Administration page
- Label registry management
- Tagging initialization and bulk tagging
- Review scheduling and compliance report generation
- Admin-level discovery utilities
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
from src.ui.theme import apply_global_theme

from src.services.label_service import get_label_service
from src.services.tagging_service import tagging_service, ALLOWED_CLASSIFICATIONS
from src.services.discovery_service import discovery_service
from src.services.compliance_service import compliance_service
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.policy_enforcement_service import policy_enforcement_service
from src.services.authorization_service import authz
from src.services.ai_rule_mining_service import ai_rule_mining_service
from src.ui.quick_links import render_quick_links

# Lazy init label service instance
label_service = get_label_service()
from src.services.dynamic_query_service import dynamic_query_service
from src.services.continuous_classifier_service import continuous_classifier_service
from src.services.system_classify_service import system_classify_service
from src.services.dynamic_compliance_report_service import dynamic_compliance_report_service

# Page configuration
st.set_page_config(
    page_title="Administration - Data Governance App",
    page_icon="🛠️",
    layout="wide"
)

# Apply centralized theme (fonts, CSS variables, Plotly template)
apply_global_theme()

st.title("Administration")
render_quick_links()

# Align UI elements with global teal slate theme
# Using centralized theme for card, metric, and table styling
st.markdown("<!-- Admin page uses global theme; removed redundant CSS -->", unsafe_allow_html=True)

# RBAC guard: Admin or Custodian only
try:
    _ident = authz.get_current_identity()
    if not (authz.is_custodian(_ident) or authz.is_admin(_ident)):
        st.error("You do not have permission to access Administration. Contact an Admin.")
        st.stop()
    else:
        st.caption(f"Signed in as: {_ident.user or 'Unknown'} | Current role: {_ident.current_role or 'Unknown'}")
    # Capability flags for fine-grained control
    _is_admin = authz.is_admin(_ident)
    _is_custodian = authz.is_custodian(_ident)
except Exception as _auth_err:
    st.warning(f"Authorization check failed: {_auth_err}")
    st.stop()

# Section: Label Registry Management
st.header("🏷️ Label Registry")
with st.spinner("Loading labels..."):
    labels = label_service.list_labels()

colL1, colL2 = st.columns([2, 1])
with colL1:
    if labels:
        st.dataframe(pd.DataFrame(labels), use_container_width=True)
    else:
        st.info("No labels found. Seeding defaults on save, or add your own below.")

with colL2:
    st.subheader("Add/Update Label")
    lbl_name = st.text_input("Label Name", value="Internal")
    lbl_desc = st.text_area("Description", value="Company-internal data")
    lbl_color = st.color_picker("Color", value="#F1C40F")
    c = st.slider("Default Confidentiality (C)", 0, 3, 1)
    i = st.slider("Default Integrity (I)", 0, 3, 1)
    a = st.slider("Default Availability (A)", 0, 3, 1)
    policy = st.text_area("Enforcement Policy", value="ROW_ACCESS=STANDARD;MASKING=LIGHT")
    if st.button("Save Label"):
        if not (_is_admin or _is_custodian):
            st.error("You do not have permission to save labels.")
            st.stop()
        label_service.upsert_label(lbl_name, lbl_desc, lbl_color, c, i, a, policy)
        st.success(f"Saved label '{lbl_name}'.")
        st.cache_data.clear()
    st.divider()
    st.subheader("Delete Label")
    del_name = st.text_input("Label to delete")
    if st.button("Delete") and del_name:
        if not (_is_admin or _is_custodian):
            st.error("You do not have permission to delete labels.")
            st.stop()
        label_service.delete_label(del_name)
        st.success(f"Deleted label '{del_name}'.")
        st.cache_data.clear()

st.markdown("---")

# Section: Tagging Operations
st.header("🏷️ Snowflake Tagging")
colT1, colT2 = st.columns(2)
with colT1:
    st.subheader("Initialize Tag Schema")
    if st.button("Initialize Tags"):
        if not (_is_admin or _is_custodian):
            st.error("You do not have permission to initialize tags.")
            st.stop()
        tagging_service.initialize_tagging()
        st.success("Ensured standardized tags exist: DATA_CLASSIFICATION, CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL")
    st.subheader("Apply Tags to Object")
    obj_full = st.text_input("Object (DATABASE.SCHEMA.OBJECT)")
    obj_type = st.selectbox("Object Type", ["TABLE", "VIEW", "SCHEMA", "DATABASE"], index=0)
    # Choose label to set classification & CIA defaults
    label_names = [l.get("LABEL_NAME") for l in (labels or [])]
    chosen_label = st.selectbox("Label (optional)", ["None"] + label_names if label_names else ["None"])
    classification = st.selectbox("Classification", ALLOWED_CLASSIFICATIONS, index=1)
    col_c, col_i, col_a = st.columns(3)
    with col_c:
        cia_c = st.number_input("C", min_value=0, max_value=3, value=1, step=1)
    with col_i:
        cia_i = st.number_input("I", min_value=0, max_value=3, value=1, step=1)
    with col_a:
        cia_a = st.number_input("A", min_value=0, max_value=3, value=1, step=1)
    if chosen_label and chosen_label != "None" and labels:
        for l in labels:
            if l.get("LABEL_NAME") == chosen_label:
                classification = l.get("LABEL_NAME") if l.get("LABEL_NAME") in ALLOWED_CLASSIFICATIONS else classification
                cia_c = int(l.get("DEFAULT_C") or cia_c)
                cia_i = int(l.get("DEFAULT_I") or cia_i)
                cia_a = int(l.get("DEFAULT_A") or cia_a)
                break
    if st.button("Apply Tags") and obj_full:
        if not (_is_admin or _is_custodian):
            st.error("You do not have permission to apply tags.")
            st.stop()
        tagging_service.apply_tags_to_object(
            obj_full,
            obj_type,
            {
                "DATA_CLASSIFICATION": classification,
                "CONFIDENTIALITY_LEVEL": str(cia_c),
                "INTEGRITY_LEVEL": str(cia_i),
                "AVAILABILITY_LEVEL": str(cia_a),
            },
        )
        st.success(f"Applied tags to {obj_type} {obj_full}")
with colT2:
    st.subheader("Bulk Tag by Schema")
    schema_full = st.text_input("Schema (DATABASE.SCHEMA)")
    blabel = st.selectbox("Label for bulk tagging", label_names if label_names else ALLOWED_CLASSIFICATIONS)
    # If user picks a custom label not in allowed, classification will fall back to choice
    if label_names and blabel in label_names:
        # Fetch defaults from label
        defaults = None
        for l in labels:
            if l.get("LABEL_NAME") == blabel:
                defaults = l
                break
        default_cls = blabel if blabel in ALLOWED_CLASSIFICATIONS else "Internal"
        default_c = int(defaults.get("DEFAULT_C") if defaults else 1)
        default_i = int(defaults.get("DEFAULT_I") if defaults else 1)
        default_a = int(defaults.get("DEFAULT_A") if defaults else 1)
    else:
        default_cls = blabel
        default_c, default_i, default_a = 1, 1, 1
    if st.button("Run Bulk Tagging") and schema_full:
        if not (_is_admin or _is_custodian):
            st.error("You do not have permission to run bulk tagging.")
            st.stop()
        count = tagging_service.bulk_apply_classification(schema_full, default_cls, default_c, default_i, default_a)
        st.success(f"Tagged {count} objects in {schema_full}")

st.markdown("---")

st.info("Reviews & Reports have moved to the Compliance page to simplify navigation and avoid duplication. Use the Compliance → Reports tab to schedule reviews and generate/view reports.")

st.markdown("---")

# Admin utilities
st.header("🧰 Utilities")
if st.button("Run Discovery Scan (Admin)"):
    if not _is_admin:
        st.error("Only Admins can run discovery scans.")
        st.stop()
    with st.spinner("Scanning Snowflake for assets..."):
        num = discovery_service.scan()
    st.success(f"Discovery scan complete. Upserted {num} assets.")

# Admin AI/Native Runs
st.markdown("---")
st.header("🧪 AI/Native Runs (Admin)")
with st.expander("SYSTEM$CLASSIFY & Dynamic Compliance Reports", expanded=False):
    st.caption("Run Snowflake-native classification across target schemas and generate dynamic framework-aligned compliance reports without hardcoded mappings.")
    colA, colB = st.columns(2)
    with colA:
        low_thr = st.slider("Low-confidence threshold", 0.0, 1.0, 0.5, 0.05, key="adm_thr")
        limit = st.number_input("Max tables to scan", 1, 2000, 200, 50, key="adm_lim")
        btn_sys = st.button("Run SYSTEM$CLASSIFY Scan", key="adm_run_sys")
    with colB:
        btn_rep = st.button("Generate Dynamic Compliance Reports", key="adm_gen_reports")
    if btn_sys:
        if not (_is_admin or _is_custodian):
            st.error("You do not have permission to run SYSTEM$CLASSIFY scans.")
            st.stop()
        with st.spinner("Executing SYSTEM$CLASSIFY across target schemas..."):
            try:
                res = system_classify_service.run(low_conf_threshold=float(low_thr), limit=int(limit))
                st.success(f"Tables: {res.get('tables')} | History: {res.get('history_rows')} | Decisions: {res.get('decisions')} | Queued: {res.get('queued')}")
                st.json(res)
            except Exception as e:
                st.error(f"SYSTEM$CLASSIFY failed: {e}")
    if btn_rep:
        if not (_is_admin or _is_custodian):
            st.error("You do not have permission to generate reports.")
            st.stop()
        with st.spinner("Generating dynamic compliance reports..."):
            try:
                author = getattr(getattr(st.session_state, 'user', None), 'username', None) or 'system'
                out = dynamic_compliance_report_service.generate_reports(author=author)
                st.success(f"Reports: {out.get('reports', 0)} | Violations: {out.get('violations', 0)}")
                st.json(out)
            except Exception as e:
                st.error(f"Report generation failed: {e}")

st.markdown("---")

# Notifications & Alerts
st.header("📣 Notifications & Alerts")
st.caption("Send pending notifications from NOTIFICATIONS_OUTBOX and review recent alerts.")
try:
    from src.services.notifier_service import notifier_service
    # Ensure tables and show recent outbox
    notifier_service._ensure_tables()
    rows = snowflake_connector.execute_query(
        f"""
        SELECT ID, CHANNEL, TARGET, SUBJECT, BODY, CREATED_AT, SENT_AT, SENT_RESULT
        FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.NOTIFICATIONS_OUTBOX
        ORDER BY COALESCE(SENT_AT, CREATED_AT) DESC
        LIMIT 200
        """
    ) or []
    st.dataframe(pd.DataFrame(rows), use_container_width=True)
    colN1, colN2 = st.columns([1,1])
    with colN1:
        if st.button("Send Pending Notifications", key="btn_send_notif"):
            if not (_is_admin or _is_custodian):
                st.error("You do not have permission to send notifications.")
                st.stop()
            sent = notifier_service.run_once(limit=200)
            st.success(f"Processed {sent} notification(s).")
            st.rerun()
    with colN2:
        st.caption("Set SLACK_WEBHOOK_URL or SMTP_* env vars to enable delivery.")
except Exception as e:
    st.warning(f"Notifications unavailable: {e}")

st.markdown("---")

# Roles & Permissions (RBAC) and Governance Settings
st.header("🔐 Admin & Roles")
tab_roles, tab_gov = st.tabs(["Roles & Permissions", "Governance Settings"]) 

with tab_roles:
    st.subheader("Role-based Access Control")
    st.caption("Manage roles and assignments. Placeholder tables created in Snowflake if missing.")
    try:
        # Ensure tables exist
        snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE")
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLES (
                ROLE_NAME STRING PRIMARY KEY,
                DESCRIPTION STRING
            )
            """
        )
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS (
                USER_EMAIL STRING,
                ROLE_NAME STRING,
                ASSIGNED_AT TIMESTAMP_NTZ,
                PRIMARY KEY (USER_EMAIL, ROLE_NAME)
            )
            """
        )
        # Seed common roles if empty
        existing_roles = snowflake_connector.execute_query(
            f"SELECT COUNT(*) AS CNT FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLES"
        )
        if existing_roles and int(existing_roles[0]['CNT']) == 0:
            snowflake_connector.execute_non_query(
                f"""
                INSERT INTO {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLES (ROLE_NAME, DESCRIPTION)
                SELECT 'Admin','Full administrative access' UNION ALL
                SELECT 'Data Owner','Owns assets and approves classification' UNION ALL
                SELECT 'Custodian','Implements technical controls' UNION ALL
                SELECT 'Auditor','Read-only access to logs and reports'
                """
            )
        # List roles
        roles = snowflake_connector.execute_query(
            f"SELECT ROLE_NAME, DESCRIPTION FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLES ORDER BY ROLE_NAME"
        ) or []
        st.write("Defined Roles:")
        st.dataframe(pd.DataFrame(roles), use_container_width=True)
        # Assignments
        st.write("Role Assignments:")
        assigns = snowflake_connector.execute_query(
            f"SELECT USER_EMAIL, ROLE_NAME, ASSIGNED_AT FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS ORDER BY ASSIGNED_AT DESC LIMIT 200"
        ) or []
        st.dataframe(pd.DataFrame(assigns), use_container_width=True)
        colA, colB, colC = st.columns(3)
        with colA:
            user_email = st.text_input("User email")
        with colB:
            role_name = st.selectbox("Role", options=[r['ROLE_NAME'] for r in roles] if roles else ["Admin","Data Owner","Custodian","Auditor"])
        with colC:
            if st.button("Assign Role") and user_email and role_name:
                if not _is_admin:
                    st.error("Only Admins can assign roles.")
                    st.stop()
                snowflake_connector.execute_non_query(
                    f"""
                    MERGE INTO {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS t
                    USING (SELECT %(u)s AS USER_EMAIL, %(r)s AS ROLE_NAME) s
                    ON t.USER_EMAIL = s.USER_EMAIL AND t.ROLE_NAME = s.ROLE_NAME
                    WHEN MATCHED THEN UPDATE SET ASSIGNED_AT = CURRENT_TIMESTAMP
                    WHEN NOT MATCHED THEN INSERT (USER_EMAIL, ROLE_NAME, ASSIGNED_AT) VALUES (s.USER_EMAIL, s.ROLE_NAME, CURRENT_TIMESTAMP)
                    """,
                    {"u": user_email, "r": role_name}
                )
                st.success("Role assigned.")
        # Removal
        colD, colE = st.columns(2)
        with colD:
            rem_user = st.text_input("Remove assignment - user email")
        with colE:
            rem_role = st.selectbox("Remove assignment - role", options=[r['ROLE_NAME'] for r in roles] if roles else ["Admin","Data Owner","Custodian","Auditor"])
        if st.button("Remove Assignment") and rem_user and rem_role:
            if not _is_admin:
                st.error("Only Admins can remove role assignments.")
                st.stop()
            snowflake_connector.execute_non_query(
                f"DELETE FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS WHERE USER_EMAIL = %(u)s AND ROLE_NAME = %(r)s",
                {"u": rem_user, "r": rem_role}
            )
            st.success("Assignment removed.")
    except Exception as e:
        st.warning(f"RBAC management unavailable: {e}")

with tab_gov:
    st.subheader("Governance Settings")
    st.caption("Toggle module availability and actions (placeholders; persists in Snowflake settings table).")
    try:
        # Ensure settings table
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.APP_SETTINGS (
                KEY STRING PRIMARY KEY,
                VALUE STRING
            )
            """
        )
        def get_setting(key: str, default: str) -> str:
            try:
                row = snowflake_connector.execute_query(
                    f"SELECT VALUE FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.APP_SETTINGS WHERE KEY = %(k)s",
                    {"k": key}
                )
                return (row[0]['VALUE'] if row else default)
            except Exception:
                return default
        def set_setting(key: str, value: str) -> None:
            snowflake_connector.execute_non_query(
                f"""
                MERGE INTO {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.APP_SETTINGS t
                USING (SELECT %(k)s AS KEY, %(v)s AS VALUE) s
                ON t.KEY = s.KEY
                WHEN MATCHED THEN UPDATE SET VALUE = s.VALUE
                WHEN NOT MATCHED THEN INSERT (KEY, VALUE) VALUES (s.KEY, s.VALUE)
                """,
                {"k": key, "v": value}
            )
        # Toggles (placeholders)
        enable_discovery = st.checkbox("Enable Data Discovery Module", value=(get_setting("enable_discovery","true").lower() == "true"))
        enable_inventory = st.checkbox("Enable Dataset Inventory & Management", value=(get_setting("enable_inventory","true").lower() == "true"))
        enable_workflow = st.checkbox("Enable Classification Workflow", value=(get_setting("enable_workflow","true").lower() == "true"))
        enable_approvals = st.checkbox("Enable Reclassification & Approvals", value=(get_setting("enable_approvals","true").lower() == "true"))
        enable_compliance = st.checkbox("Enable Compliance & Audit", value=(get_setting("enable_compliance","true").lower() == "true"))
        enable_quality = st.checkbox("Enable Data Quality", value=(get_setting("enable_quality","true").lower() == "true"))
        enable_lineage = st.checkbox("Enable Data Lineage", value=(get_setting("enable_lineage","true").lower() == "true"))
        if st.button("Save Settings"):
            if not _is_admin:
                st.error("Only Admins can change governance settings.")
                st.stop()
            set_setting("enable_discovery", str(enable_discovery).lower())
            set_setting("enable_inventory", str(enable_inventory).lower())
            set_setting("enable_workflow", str(enable_workflow).lower())
            set_setting("enable_approvals", str(enable_approvals).lower())
            set_setting("enable_compliance", str(enable_compliance).lower())
            set_setting("enable_quality", str(enable_quality).lower())
            set_setting("enable_lineage", str(enable_lineage).lower())
            st.success("Settings saved.")
    except Exception as e:
        st.warning(f"Governance settings unavailable: {e}")

st.markdown("---")

# I/A Rules Management (data-driven inference for Integrity and Availability)
st.header("🧩 Integrity/Availability Rules")
st.caption("Manage data-driven rules used by automation to infer Integrity (I) and Availability (A). Patterns support substrings or regex delimited as /.../.")
try:
    # Ensure schema and table
    snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE")
    snowflake_connector.execute_non_query(
        f"""
        CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.IA_RULES (
          TYPE STRING,
          PATTERN STRING,
          I_LEVEL NUMBER(1),
          A_LEVEL NUMBER(1),
          PRIORITY NUMBER(3),
          UPDATED_AT TIMESTAMP_NTZ
        )
        """
    )
    # List existing rules
    rules = snowflake_connector.execute_query(
        f"SELECT TYPE, PATTERN, I_LEVEL, A_LEVEL, PRIORITY, UPDATED_AT FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.IA_RULES ORDER BY PRIORITY DESC, TYPE, PATTERN"
    ) or []
    st.dataframe(pd.DataFrame(rules), use_container_width=True)
    colR1, colR2 = st.columns(2)
    with colR1:
        st.subheader("Add / Update Rule")
        r_type = st.text_input("Type (optional, matches categories like FINANCIAL, PII, AUTH, PHI, PCI)", key="ia_type")
        r_pattern = st.text_input("Pattern (substring or /regex/)", key="ia_pattern")
        r_i = st.number_input("I Level (0-3)", min_value=0, max_value=3, value=2, key="ia_i")
        r_a = st.number_input("A Level (0-3)", min_value=0, max_value=3, value=2, key="ia_a")
        r_pri = st.number_input("Priority (higher first)", min_value=0, max_value=999, value=100, key="ia_pri")
        if st.button("Save Rule", key="btn_save_ia_rule"):
            if not (_is_admin or _is_custodian):
                st.error("You do not have permission to modify rules.")
                st.stop()
            if not r_pattern:
                st.warning("Pattern is required.")
            else:
                snowflake_connector.execute_non_query(
                    f"""
                    MERGE INTO {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.IA_RULES t
                    USING (SELECT %(t)s AS TYPE, %(p)s AS PATTERN) s
                    ON COALESCE(t.TYPE,'') = COALESCE(s.TYPE,'') AND COALESCE(t.PATTERN,'') = COALESCE(s.PATTERN,'')
                    WHEN MATCHED THEN UPDATE SET I_LEVEL = %(i)s, A_LEVEL = %(a)s, PRIORITY = %(pri)s, UPDATED_AT = CURRENT_TIMESTAMP
                    WHEN NOT MATCHED THEN INSERT (TYPE, PATTERN, I_LEVEL, A_LEVEL, PRIORITY, UPDATED_AT)
                    VALUES (%(t)s, %(p)s, %(i)s, %(a)s, %(pri)s, CURRENT_TIMESTAMP)
                    """,
                    {"t": (r_type or None), "p": r_pattern, "i": int(r_i), "a": int(r_a), "pri": int(r_pri)}
                )
                st.success("Rule saved.")
                st.cache_data.clear()
                st.rerun()
    with colR2:
        st.subheader("Delete Rule")
        d_type = st.text_input("Type (optional)", key="ia_del_type")
        d_pattern = st.text_input("Pattern", key="ia_del_pattern")
        if st.button("Delete", key="btn_del_ia_rule") and d_pattern:
            if not (_is_admin or _is_custodian):
                st.error("You do not have permission to delete rules.")
                st.stop()
            snowflake_connector.execute_non_query(
                f"""
                DELETE FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.IA_RULES
                WHERE COALESCE(PATTERN,'') = %(p)s AND COALESCE(TYPE,'') = COALESCE(%(t)s,'')
                """,
                {"p": d_pattern, "t": (d_type or None)}
            )
            st.success("Rule deleted.")
            st.cache_data.clear()
            st.rerun()
except Exception as e:
    st.warning(f"I/A rules management unavailable: {e}")

st.markdown("---")

# IdP Group Mapping and Policy Simulator
st.header("🔗 IdP Group Mapping & 🎯 Policy Simulator")

colM1, colM2 = st.columns(2)
with colM1:
    st.subheader("Map IdP Groups → Snowflake Roles")
    try:
        # Ensure mapping table
        snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE")
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.IDP_GROUP_MAP (
                GROUP_NAME STRING,
                ROLE_NAME STRING,
                UPDATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (GROUP_NAME)
            )
            """
        )
        # List mappings
        maps = snowflake_connector.execute_query(
            f"SELECT GROUP_NAME, ROLE_NAME, UPDATED_AT FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.IDP_GROUP_MAP ORDER BY GROUP_NAME"
        ) or []
        st.dataframe(pd.DataFrame(maps), use_container_width=True)
        # Upsert mapping
        grp = st.text_input("IdP Group (e.g., okta:Finance-Analyst)")
        # Fetch roles from governance table seeded above
        try:
            role_rows = snowflake_connector.execute_query(
                f"SELECT ROLE_NAME FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLES ORDER BY ROLE_NAME"
            ) or []
            role_opts = [r['ROLE_NAME'] for r in role_rows]
        except Exception:
            role_opts = ["Admin","Data Owner","Custodian","Auditor"]
        grp_role = st.selectbox("Snowflake Role", options=role_opts)
        if st.button("Save Mapping") and grp:
            if not _is_admin:
                st.error("Only Admins can save IdP group mappings.")
                st.stop()
            snowflake_connector.execute_non_query(
                f"""
                MERGE INTO {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.IDP_GROUP_MAP t
                USING (SELECT %(g)s AS GROUP_NAME, %(r)s AS ROLE_NAME) s
                ON t.GROUP_NAME = s.GROUP_NAME
                WHEN MATCHED THEN UPDATE SET ROLE_NAME = s.ROLE_NAME, UPDATED_AT = CURRENT_TIMESTAMP
                WHEN NOT MATCHED THEN INSERT (GROUP_NAME, ROLE_NAME) VALUES (s.GROUP_NAME, s.ROLE_NAME)
                """,
                {"g": grp, "r": grp_role}
            )
            st.success("Mapping saved.")
        # Delete mapping
        del_grp = st.text_input("Delete mapping for Group")
        if st.button("Delete Mapping") and del_grp:
            if not _is_admin:
                st.error("Only Admins can delete IdP group mappings.")
                st.stop()
            snowflake_connector.execute_non_query(
                f"DELETE FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.IDP_GROUP_MAP WHERE GROUP_NAME = %(g)s",
                {"g": del_grp}
            )
            st.success("Mapping deleted.")
    except Exception as e:
        st.warning(f"IdP mapping unavailable: {e}")

with colM2:
    st.subheader("Policy Impact Simulator")
    st.caption("Simulates access decisions for Row Access (BU/GEO) and Masking policy visibility.")
    try:
        # Ensure the reusable BU/GEO row access policy exists
        fq = policy_enforcement_service.ensure_bu_geo_row_access_policy()
        st.caption(f"Row Access Policy ensured: {fq}")
    except Exception:
        pass
    # Inputs
    try:
        role_rows = snowflake_connector.execute_query(
            f"SELECT ROLE_NAME FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLES ORDER BY ROLE_NAME"
        ) or []
        role_opts = [r['ROLE_NAME'] for r in role_rows]
    except Exception:
        role_opts = ["Admin","Data Owner","Custodian","Auditor"]
    sim_role = st.selectbox("Assume Role", options=role_opts, index=0)
    sim_bu = st.text_input("Business Unit (BU)", value="FINANCE")
    sim_geo = st.text_input("Geography (GEO)", value="US")
    st.caption("Row access uses ROW_ACCESS_RULES where (ROLE_NAME, ATTRIBUTE, VALUE) must match any of (BU, GEO).")
    if st.button("Simulate Access"):
        # Read rules and compute decision
        try:
            rules = snowflake_connector.execute_query(
                f"SELECT ATTRIBUTE, VALUE FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROW_ACCESS_RULES WHERE ROLE_NAME = %(r)s",
                {"r": sim_role}
            ) or []
            allow = any((r.get('ATTRIBUTE') == 'BU' and r.get('VALUE') == sim_bu) or (r.get('ATTRIBUTE') == 'GEO' and r.get('VALUE') == sim_geo) for r in rules)
            if allow:
                st.success("Row Access: ALLOW (rule match found)")
            else:
                st.error("Row Access: DENY (no BU/GEO rule match)")
        except Exception as e:
            st.warning(f"Simulation failed: {e}")
        # Masking visibility based on base policy expression
        visible_roles = {"SECURITY_ADMIN","SYSADMIN"}
        if sim_role in visible_roles:
            st.success("Masking Visibility: CLEAR (base policy grants unmasked view)")
        else:
            st.info("Masking Visibility: MASKED (role not in base policy allowlist)")

# Moved from Dashboard: Snowflake Users & Roles utilities (admin/custodian)
st.markdown("---")
if _is_admin or _is_custodian:
    with st.expander("🧑‍💼 Admin: Users & Roles", expanded=False):
        st.caption("Create roles/users, grant roles, set defaults, and switch role for this session. Use carefully in non-prod.")

        def _safe_ident(name: str) -> str:
            # Very basic identifier sanitation; wrap in double quotes
            name = (name or "").strip()
            for ch in [';', '\\', '/', '\'', '"', '`']:
                name = name.replace(ch, '')
            return f'"{name.upper()}"'

        tabs = st.tabs(["Roles", "Users", "Grants", "Role Switch"]) 

        # Roles tab
        with tabs[0]:
            rcol1, rcol2 = st.columns(2)
            with rcol1:
                new_role = st.text_input("New role name", placeholder="e.g., ANALYTICS_VIEWER")
                if st.button("Create Role", key="adm_btn_create_role") and new_role:
                    try:
                        sql = f"CREATE ROLE IF NOT EXISTS {_safe_ident(new_role)}"
                        snowflake_connector.execute_non_query(sql)
                        st.success(f"Created/ensured role: {new_role}")
                    except Exception as e:
                        st.error(f"Failed creating role: {e}")
            with rcol2:
                st.write("Current user grants")
                try:
                    rows = snowflake_connector.execute_query("SHOW GRANTS TO USER CURRENT_USER()") or []
                    st.dataframe(rows, use_container_width=True)
                except Exception as e:
                    st.info(f"Unable to fetch grants: {e}")

        # Users tab
        with tabs[1]:
            u1, u2 = st.columns(2)
            with u1:
                uname = st.text_input("Username", key="adm_u_name")
                upwd = st.text_input("Password", type="password", key="adm_u_pwd")
                dflt_role = st.text_input("Default Role (optional)", key="adm_u_def_role")
                if st.button("Create User", key="adm_btn_create_user") and uname and upwd:
                    try:
                        sql = f"CREATE USER IF NOT EXISTS {_safe_ident(uname)} PASSWORD='{upwd}'"
                        if dflt_role:
                            sql += f" DEFAULT_ROLE = {_safe_ident(dflt_role)}"
                        snowflake_connector.execute_non_query(sql)
                        st.success(f"Created/ensured user: {uname}")
                    except Exception as e:
                        st.error(f"Failed creating user: {e}")
            with u2:
                # Set default role after creation
                uname2 = st.text_input("User (set default role)", key="adm_u2_name")
                drole2 = st.text_input("Default Role", key="adm_u2_role")
                if st.button("Set Default Role", key="adm_btn_set_def_role") and uname2 and drole2:
                    try:
                        sql = f"ALTER USER {_safe_ident(uname2)} SET DEFAULT_ROLE = {_safe_ident(drole2)}"
                        snowflake_connector.execute_non_query(sql)
                        st.success("Default role set.")
                    except Exception as e:
                        st.error(f"Failed setting default role: {e}")

        # Grants tab
        with tabs[2]:
            g1, g2 = st.columns(2)
            with g1:
                role_to_grant = st.text_input("Role to grant", key="adm_gr_role")
                user_target = st.text_input("To User", key="adm_gr_user")
                if st.button("Grant Role to User", key="adm_btn_gr_role_user") and role_to_grant and user_target:
                    try:
                        sql = f"GRANT ROLE {_safe_ident(role_to_grant)} TO USER {_safe_ident(user_target)}"
                        snowflake_connector.execute_non_query(sql)
                        st.success("Granted role to user.")
                    except Exception as e:
                        st.error(f"Failed granting role to user: {e}")
            with g2:
                child = st.text_input("Child Role", key="adm_gr_child")
                parent = st.text_input("Parent Role", key="adm_gr_parent")
                if st.button("Grant Role to Role", key="adm_btn_gr_role_role") and child and parent:
                    try:
                        sql = f"GRANT ROLE {_safe_ident(child)} TO ROLE {_safe_ident(parent)}"
                        snowflake_connector.execute_non_query(sql)
                        st.success("Granted role to role.")
                    except Exception as e:
                        st.error(f"Failed granting role to role: {e}")

        # Role Switch tab
        with tabs[3]:
            st.caption("Switch the active role for the current session (affects Snowflake permissions in this app session).")
            try:
                roles = snowflake_connector.execute_query("SHOW ROLES") or []
                role_opts = [r.get('name') or r.get('NAME') for r in roles if (r.get('name') or r.get('NAME'))]
            except Exception:
                role_opts = []
            new_role = st.selectbox("Assume role", options=role_opts or ["No roles available"])
            if st.button("Use Role", key="adm_btn_use_role") and new_role and new_role != "No roles available":
                try:
                    snowflake_connector.execute_non_query(f"use role \"{new_role}\"")
                    st.success(f"Switched role to {new_role}. Some data may change based on new permissions.")
                    st.cache_data.clear()
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to switch role: {e}")
