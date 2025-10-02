"""
Classification page for the data governance application.
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
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.label_service import get_label_service
from src.services.tagging_service import tagging_service, ALLOWED_CLASSIFICATIONS
from src.services.reclassification_service import reclassification_service
from src.services.policy_enforcement_service import policy_enforcement_service
from src.services.ai_classification_service import ai_classification_service
from src.services.authorization_service import authz
from src.services.testing_service import testing_service
from src.services.discovery_service import discovery_service
from src.services.classification_decision_service import classification_decision_service
from src.services.decision_matrix_service import validate as dm_validate
from src.components.filters import render_data_filters, render_compliance_facets
from src.services.ai_rule_mining_service import ai_rule_mining_service
from src.services.snowpark_udf_service import snowpark_udf_service
from src.services.system_classify_service import system_classify_service

# Lazy init: obtain the label service instance on first use
label_service = get_label_service()

# Helper function to get current database
def _get_current_db():
    db = st.session_state.get('sf_database') or _get_current_db()
    if not db:
        try:
            result = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB")
            if result and len(result) > 0:
                db = result[0].get('DB')
        except Exception:
            pass
    return db


# Page configuration
st.set_page_config(
    page_title="Classification - Data Governance App",
    page_icon="🏷️",
    layout="wide"
)

# Apply centralized theme (fonts, CSS variables, Plotly template)
apply_global_theme()

# Page title
st.title("Data Classification")

# --- Policy enforcement helpers (Decision table persistence) ---
def _ensure_decisions_table():
    try:
        db = _get_current_db()
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
        pass

def _persist_decision(asset_full_name: str, label: str, c: int, i: int, a: int, owner: str | None, rationale: str | None, checklist: dict | None, decided_by: str, prev: dict | None = None):
    try:
        _ensure_decisions_table()
        params = {
            "asset": asset_full_name,
            "cls": label,
            "c": int(c),
            "i": int(i),
            "a": int(a),
            "owner": owner or None,
            "rationale": (rationale or "").strip() or None,
            "checklist": str(checklist or {}),
            "by": decided_by or "system",
            "p_cls": (prev or {}).get("classification"),
            "p_c": (prev or {}).get("C"),
            "p_i": (prev or {}).get("I"),
            "p_a": (prev or {}).get("A"),
        }
        db = _get_current_db()
        snowflake_connector.execute_non_query(
            f"""
            INSERT INTO {db}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
            (ASSET_FULL_NAME, CLASSIFICATION, C, I, A, OWNER, RATIONALE, CHECKLIST_JSON, DECIDED_BY, PREV_CLASSIFICATION, PREV_C, PREV_I, PREV_A)
            VALUES (%(asset)s, %(cls)s, %(c)s, %(i)s, %(a)s, %(owner)s, %(rationale)s, %(checklist)s, %(by)s, %(p_cls)s, %(p_c)s, %(p_i)s, %(p_a)s)
            """,
            params,
        )
    except Exception:
        pass

# Authorization guard: allow only Owners, Custodians, Specialists, Admins
try:
    _ident = authz.get_current_identity()
    st.caption(f"Signed in as: {_ident.user or 'Unknown'} | Current role: {_ident.current_role or 'Unknown'}")
    if not authz.can_access_classification(_ident):
        st.error("You do not have permission to access the Classification module. Please contact a Data Owner or Admin.")
        st.stop()
    # Capability flags used to gate actions within this page
    _can_classify = authz.can_classify(_ident)
    _can_approve = authz.can_approve_tags(_ident)
except Exception as _auth_err:
    st.warning(f"Authorization check failed: {_auth_err}")
    st.stop()

# Global filters and facets
with st.expander("🔎 Dataset Filters", expanded=True):
    sel = render_data_filters(key_prefix="classify")
with st.expander("🧭 Compliance Facets", expanded=False):
    facets = render_compliance_facets(key_prefix="classify")

# Tabs for Classification module per requested structure (consolidated)
tab0, tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["Discovery", "Tagging & CIA Labels", "AI Detection", "Risk Analysis", "Reclassification", "History", "Approvals"])

with tab0:
    st.subheader("Discovery")
    st.caption("Recent discoveries, search, full-scan, and quick health checks. Classification SLA (5 business days) is monitored on the Dashboard.")
    # Discovered assets (inventory)
    try:
        db = st.session_state.get('sf_database') or _get_current_db()
        if not db:
            st.warning("No database selected. Please select a database from the Dashboard.")
            st.stop()
        with st.spinner("Reading discovered assets from inventory..."):
            rows = snowflake_connector.execute_query(
                f"""
                SELECT FULL_NAME, OBJECT_DOMAIN, FIRST_DISCOVERED, LAST_SEEN, CLASSIFIED
                FROM {db}.DATA_GOVERNANCE.ASSET_INVENTORY
                ORDER BY COALESCE(LAST_SEEN, FIRST_DISCOVERED) DESC
                LIMIT 200
                """
            ) or []
        if rows:
            idf = pd.DataFrame(rows)
            idf.rename(columns={"FULL_NAME":"Asset","OBJECT_DOMAIN":"Type"}, inplace=True)
            idf["Status"] = idf["CLASSIFIED"].apply(lambda x: "Classified ✅" if x else "Unclassified ❌")
            st.dataframe(idf[["Asset","Type","FIRST_DISCOVERED","LAST_SEEN","Status"]], use_container_width=True)
        else:
            st.info("No assets in inventory yet. Run a scan below.")
    except Exception as e:
        st.warning(f"Unable to read inventory: {e}")
        st.caption("Ensure DATA_GOVERNANCE.ASSET_INVENTORY exists or run a Discovery scan.")

    st.markdown("---")
    # Search panel
    st.subheader("🔍 Search Tables & Columns")
    qcol1, qcol2, qcol3 = st.columns([3, 1, 1])
    with qcol1:
        query = st.text_input("Search by schema/table/column name", placeholder="e.g. users, customer, email", key="disc_query")
    with qcol2:
        limit_tables = st.number_input("Table results", min_value=10, max_value=1000, value=50, step=10, key="disc_tbl_lim")
    with qcol3:
        limit_cols = st.number_input("Column results", min_value=10, max_value=5000, value=200, step=50, key="disc_col_lim")

    @st.cache_data(ttl=1800)
    def search_tables_cached(q: str, limit: int):
        return testing_service.search_tables(q, limit)

    @st.cache_data(ttl=1800)
    def search_columns_cached(q: str, limit: int):
        return testing_service.search_columns(q, limit)

    if query:
        with st.spinner("Searching Snowflake..."):
            trows = search_tables_cached(query, int(limit_tables))
            crows = search_columns_cached(query, int(limit_cols))
        tdf = pd.DataFrame(trows)
        cdf = pd.DataFrame(crows)
        # Apply dataset filters best-effort by string matching on fully qualified names
        try:
            if sel.get("database") and not tdf.empty:
                for col in ["FULL_NAME","full_name","TABLE","Asset","NAME","TABLE_NAME"]:
                    if col in tdf.columns:
                        tdf = tdf[tdf[col].astype(str).str.contains(fr"^{sel['database']}\.", case=False, regex=True)]
                        break
            if sel.get("schema") and not tdf.empty:
                tdf = tdf[tdf.astype(str).apply(lambda r: f".{sel['schema']}." in " ".join(r.values), axis=1)]
            if sel.get("table") and not tdf.empty:
                tdf = tdf[tdf.astype(str).apply(lambda r: r.str.contains(fr"\.{sel['table']}$", case=False, regex=True).any(), axis=1)]
        except Exception:
            pass
        try:
            if sel.get("database") and not cdf.empty:
                cdf = cdf[cdf.astype(str).apply(lambda r: f"{sel['database']}." in " ".join(r.values), axis=1)]
            if sel.get("schema") and not cdf.empty:
                cdf = cdf[cdf.astype(str).apply(lambda r: f".{sel['schema']}." in " ".join(r.values), axis=1)]
            if sel.get("table") and not cdf.empty:
                cdf = cdf[cdf.astype[str].apply(lambda r: r.str.endswith(sel['table']).any(), axis=1)]
            if sel.get("column") and not cdf.empty:
                # Try to filter by column name column if present
                for col in ["COLUMN","COLUMN_NAME","name","Name"]:
                    if col in cdf.columns:
                        cdf = cdf[cdf[col].astype(str).str.contains(sel['column'], case=False, regex=False)]
                        break
        except Exception:
            pass
        st.markdown("**Tables**")
        st.dataframe(tdf, use_container_width=True)
        st.markdown("**Columns**")
        st.dataframe(cdf, use_container_width=True)
    else:
        st.info("Enter a search string above to find tables and columns.")

    st.markdown("---")
    # Full scan & health
    st.subheader("📦 Complete Database Processing & Health")
    colf1, colf2, colf3 = st.columns([2, 1, 1])
    with colf1:
        st.write("Run a full inventory scan to ensure all tables and views are discovered and upserted into the inventory queue.")
    with colf2:
        if st.button("Run Full Scan", key="disc_run_full"):
            with st.spinner("Scanning entire database in batches..."):
                total = discovery_service.full_scan(batch_size=1000)
            st.success(f"Full scan complete. Upserted {total} assets.")
    with colf3:
        if st.button("Connectivity Test", key="disc_conn_test"):
            ok = testing_service.connectivity_test()
            if ok:
                st.success("Connectivity OK: able to query Snowflake.")
            else:
                st.error("Connectivity failed. Check credentials/warehouse/role.")

with tab1:
    st.subheader("Tagging & CIA Labels")
    st.write("Select dataset(s), assign classification and CIA, validate against prior tags, and apply to Snowflake.")

    # Load assets from inventory or fallback to INFORMATION_SCHEMA
    try:
        from src.services.discovery_service import discovery_service
        with st.spinner("Loading assets from inventory..."):
            inv_rows = discovery_service.get_queue(limit=500) or []
            inv_assets = [r.get("FULL_NAME") for r in inv_rows if r.get("FULL_NAME")]
        if not inv_assets:
            tables = snowflake_connector.execute_query(
                f"""
                SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS full_name
                FROM {_get_current_db()}.INFORMATION_SCHEMA.TABLES
                WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                ORDER BY "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"
                LIMIT 200
                """
            )
            inv_assets = [t['FULL_NAME'] for t in (tables or [])]
    except Exception as e:
        st.warning(f"Could not load assets: {e}")
        inv_assets = []

    # Search/filter across datasets (persisted via session state)
    search_q = st.text_input("Search datasets", placeholder="Type to filter by name...", key="manual_search")
    # Apply dataset filters to asset list
    def _match_sel(a: str) -> bool:
        try:
            db, sc, tb = a.split('.')[:3]
            if sel.get("database") and db.upper() != sel['database'].upper():
                return False
            if sel.get("schema") and sc.upper() != sel['schema'].upper():
                return False
            if sel.get("table") and tb.upper() != sel['table'].upper():
                return False
            return True
        except Exception:
            return True
    inv_assets2 = [a for a in inv_assets if _match_sel(a)]
    filtered_assets = [a for a in inv_assets2 if (search_q.lower() in a.lower())] if search_q else inv_assets2
    selected_assets = st.multiselect("Choose one or more assets", options=filtered_assets, default=filtered_assets[:1] if filtered_assets else [])

    # Auto-suggest CIA and Level
    def suggest_levels(name: str):
        up = (name or "").upper()
        # Start from neutral (0) and elevate based on detected cues to reduce bias
        c, i, a = 0, 0, 0
        if any(k in up for k in ["SSN","EMAIL","PHONE","ADDRESS","DOB","PII","CUSTOMER","PERSON","EMPLOYEE"]):
            c = max(c, 2)
        if any(k in up for k in ["FINANCE","GL","LEDGER","INVOICE","PAYROLL","AR","AP","REVENUE","EXPENSE"]):
            c = max(c, 2); i = max(i, 2)
        if any(k in up for k in ["SOX","FINANCIAL_REPORT","GAAP","IFRS","AUDIT"]):
            c = max(c, 3); i = max(i, 3)
        if any(k in up for k in ["REALTIME","ORDERS","OPERATIONS","SUPPORT"]):
            a = max(a, 2)
        if any(k in up for k in ["CRITICAL","ALERT","EMERGENCY"]):
            a = max(a, 3)
        highest = max(c, i, a)
        level = "Confidential" if highest == 3 else ("Restricted" if highest == 2 else ("Public" if highest == 0 else "Internal"))
        return c, i, a, level

    base_c, base_i, base_a, base_cls = (suggest_levels(selected_assets[0]) if selected_assets else (0, 0, 0, "Internal"))
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        c_val = st.number_input("C (0-3)", min_value=0, max_value=3, value=int(base_c))
    with c2:
        i_val = st.number_input("I (0-3)", min_value=0, max_value=3, value=int(base_i))
    with c3:
        a_val = st.number_input("A (0-3)", min_value=0, max_value=3, value=int(base_a))
    with c4:
        cls_val = st.selectbox("Classification", options=ALLOWED_CLASSIFICATIONS, index=ALLOWED_CLASSIFICATIONS.index(base_cls) if base_cls in ALLOWED_CLASSIFICATIONS else 1)

    # Special Categories selection (affects minimum required levels per Policy 5.5)
    st.write("**Special Categories (Policy 5.5)**")
    special_categories = st.multiselect(
        "Select all that apply",
        options=["PII", "PHI/HIPAA", "Financial/SOX", "PCI"],
        help="These selections enforce minimum classification/Confidentiality (C) levels and controls.",
        key="manual_special_categories",
    )

    st.write("**Rationale / Notes (for audit)**")
    justification = st.text_area("Rationale", height=100, placeholder="Explain why this classification is appropriate...")

    # Validation against prior tags + SOX/SOC hints
    st.markdown("---")
    st.write("**Validation & Sensitivity Hints**")
    try:
        from src.services.tagging_service import tagging_service
        for asset in selected_assets[:10]:
            with st.expander(f"Validation: {asset}"):
                try:
                    refs = tagging_service.get_object_tags(asset, "TABLE")
                    prev = {}
                    for r in refs:
                        tname = r.get("TAG_NAME") or r.get("TAG") or r.get("TAG_DATABASE")
                        val = r.get("TAG_VALUE") or r.get("VALUE")
                        if tname:
                            prev[str(tname).split('.')[-1].upper()] = val
                    st.write("Previous tags:")
                    st.json(prev or {"info": "No tags found"})
                    incons = []
                    if prev.get("DATA_CLASSIFICATION") and prev.get("DATA_CLASSIFICATION") != cls_val:
                        incons.append("Classification differs from previous")
                    if prev.get("CONFIDENTIALITY_LEVEL") and int(prev.get("CONFIDENTIALITY_LEVEL", 0)) > c_val:
                        incons.append("C lower than previous")
                    if prev.get("INTEGRITY_LEVEL") and int(prev.get("INTEGRITY_LEVEL", 0)) > i_val:
                        incons.append("I lower than previous")
                    if prev.get("AVAILABILITY_LEVEL") and int(prev.get("AVAILABILITY_LEVEL", 0)) > a_val:
                        incons.append("A lower than previous")
                    if incons:
                        st.error("; ".join(incons))
                except Exception as ve:
                    st.info(f"No prior tags or validation unavailable: {ve}")
    except Exception:
        pass

    hints = []
    for asset in selected_assets:
        up = asset.upper()
        if any(k in up for k in ["SOX","FINANCIAL_REPORT","GAAP","IFRS","AUDIT"]):
            hints.append(f"{asset} may require SOX/SOC controls")
    if hints:
        for h in hints:
            st.warning(h)

    user_email = st.text_input("Your email (for audit)", key="manual_user_email")
    # Special Categories enforcement helper
    def required_minimum_for_asset(asset_name: str, categories: list[str] | None = None):
        """Determine minimum required levels from both heuristics and explicit category selection.
        Returns: (min_c, min_cls, regulatory_label)
        """
        up = (asset_name or "").upper()
        categories = categories or []
        # Defaults
        min_c = 1  # C1 Internal
        min_cls = "Internal"
        regulatory = None
        # Explicit categories take precedence
        if "PII" in categories:
            min_c = max(min_c, 2)
            min_cls = "Restricted" if min_c < 3 else "Confidential"
            regulatory = (regulatory or "PII")
        if "PHI/HIPAA" in categories:
            min_c = max(min_c, 2)
            min_cls = "Restricted" if min_c < 3 else "Confidential"
            regulatory = (regulatory or "HIPAA")
        if "Financial/SOX" in categories:
            min_c = max(min_c, 2)
            # SOX-relevant often drives higher integrity and sometimes C3; keep C2 minimum here and allow heuristics to elevate
            min_cls = "Restricted" if min_c < 3 else "Confidential"
            regulatory = (regulatory or "SOX")
        if "PCI" in categories:
            # PCI cardholder data generally requires C3
            min_c = max(min_c, 3)
            min_cls = "Confidential"
            regulatory = (regulatory or "PCI")
        # Heuristic name signals (fallbacks and elevation)
        if any(k in up for k in ["SSN","EMAIL","PHONE","ADDRESS","DOB","PII","PERSON","EMPLOYEE"]):
            min_c = max(min_c, 2)
            min_cls = "Restricted" if min_c < 3 else "Confidential"
            regulatory = (regulatory or "PII")
        if any(k in up for k in ["SSN","NATIONAL_ID","PASSPORT","PAN","AADHAAR"]):
            min_c = max(min_c, 3)
            min_cls = "Confidential"
            regulatory = (regulatory or "PII")
        if any(k in up for k in ["SOX","FINANCIAL_REPORT","GL","LEDGER","REVENUE","EXPENSE","PAYROLL","AUDIT"]):
            min_c = max(min_c, 2)
            # Some financial contexts may warrant C3; allow separate hints to elevate
            min_cls = "Restricted" if min_c < 3 else "Confidential"
            regulatory = (regulatory or "SOX")
        return min_c, min_cls, regulatory

    # Exception submission choice (only shown if enforcement blocks)
    request_exception = st.checkbox("Request exception if below required minimums", value=False)

    if st.button("Apply Tags to Selected", type="primary"):
        if not _can_classify:
            st.error("You do not have permission to apply classifications or tags. Contact a Data Owner or Admin.")
            st.stop()
        if not selected_assets:
            st.warning("Please select at least one asset")
        elif not user_email:
            st.warning("Please enter your email for audit")
        elif cls_val in ("Restricted", "Confidential") and not (justification and justification.strip()):
            st.warning("Provide a justification for Restricted/Confidential classifications (Policy 6.1.2 Step 6: Documentation).")
        else:
            # Additional guard: require justification if any CIA level increases vs previous tags
            try:
                from src.services.tagging_service import tagging_service as _tsvc
                needs_rationale = False
                for asset in selected_assets:
                    try:
                        refs = _tsvc.get_object_tags(asset, "TABLE")
                        prev_c = prev_i = prev_a = None
                        for r in refs:
                            tname = (r.get("TAG_NAME") or r.get("TAG") or r.get("TAG_DATABASE") or "").upper()
                            val = r.get("TAG_VALUE") or r.get("VALUE")
                            if tname.endswith("CONFIDENTIALITY_LEVEL"):
                                prev_c = int(str(val)) if str(val).isdigit() else None
                            if tname.endswith("INTEGRITY_LEVEL"):
                                prev_i = int(str(val)) if str(val).isdigit() else None
                            if tname.endswith("AVAILABILITY_LEVEL"):
                                prev_a = int(str(val)) if str(val).isdigit() else None
                        if ((prev_c is not None and int(c_val) > prev_c) or (prev_i is not None and int(i_val) > prev_i) or (prev_a is not None and int(a_val) > prev_a)) and not (justification and justification.strip()):
                            needs_rationale = True
                            break
                    except Exception:
                        continue
                if needs_rationale:
                    st.error("Provide a justification when increasing any CIA level compared to previous tags (Policy 6.2.2 Step 4).")
                    st.stop()
            except Exception:
                pass
            # Enforce Policy 5.5 minimums per asset name heuristics; allow exception path
            violations = []
            req_payloads = []
            for asset in selected_assets:
                req_min_c, req_min_cls, regulatory = required_minimum_for_asset(asset, categories=special_categories)
                # If proposed classification is below required minimums
                if (int(c_val) < int(req_min_c)) or (
                    (ALLOWED_CLASSIFICATIONS.index(cls_val) < ALLOWED_CLASSIFICATIONS.index(req_min_cls))
                ):
                    violations.append({
                        "asset": asset,
                        "required_c": req_min_c,
                        "required_cls": req_min_cls,
                        "reg": regulatory or "Policy",
                    })
                    if request_exception:
                        req_payloads.append((asset, regulatory or "Policy"))

            if violations and not request_exception:
                st.error("Classification below policy minimums for some assets (Policy 5.5). Enable 'Request exception' or adjust levels.")
                for v in violations[:10]:
                    st.warning(f"{v['asset']}: requires at least {v['required_cls']} (C≥{v['required_c']}) due to {v['reg']}")
                st.stop()

            # If exceptions requested, submit them first
            if req_payloads:
                try:
                    from src.services.exception_service import exception_service
                except Exception as e:
                    st.error(f"Exception service unavailable: {e}")
                    st.stop()
                created_exc = 0
                for asset, reg in req_payloads:
                    try:
                        eid = exception_service.submit(
                            asset_full_name=asset,
                            regulatory=reg,
                            justification=justification or f"Exception requested for class={cls_val}, C={c_val} below minimum",
                            risk_level="High" if reg in ("PII","SOX") else "Medium",
                            requested_by=user_email,
                            days_valid=90,
                            details={"proposed": {"classification": cls_val, "C": int(c_val), "I": int(i_val), "A": int(a_val)}},
                        )
                        created_exc += 1
                    except Exception as e:
                        st.error(f"Failed to submit exception for {asset}: {e}")
                if created_exc > 0:
                    st.success(f"Submitted {created_exc} exception request(s). Pending approval.")

            # Validate guardrails (label must meet/exceed minimum given CIA)
            ok, reasons = dm_validate(cls_val, int(c_val), int(i_val), int(a_val))
            if not ok:
                for r in reasons:
                    st.error(r)
                st.stop()

            # Gate C3/Confidential behind approval if user lacks approval capability
            requires_approval = (str(cls_val).lower() == "confidential" or int(c_val) == 3) and (not _can_approve)
            if requires_approval:
                try:
                    from src.services.reclassification_service import reclassification_service as _reclass
                    created = 0
                    for asset in selected_assets:
                        rid = _reclass.submit_request(
                            asset_full_name=asset,
                            proposed=(cls_val, int(c_val), int(i_val), int(a_val)),
                            justification=justification or "Manual submission requiring approval (C3/Confidential)",
                            created_by=user_email or "system",
                            trigger_type="MANUAL_HIGH_RISK",
                        )
                        created += 1 if rid else 0
                        # Record submitted decision for audit
                        try:
                            classification_decision_service.record(
                                asset_full_name=asset,
                                decision_by=user_email or "system",
                                source="MANUAL",
                                status="Submitted",
                                label=cls_val,
                                c=int(c_val), i=int(i_val), a=int(a_val),
                                rationale=justification or "",
                                details={"request_id": rid, "reason": "C3/Confidential requires approval"},
                            )
                        except Exception:
                            pass
                    st.success(f"Submitted {created} reclassification request(s) for approval (C3/Confidential).")
                except Exception as e:
                    st.error(f"Failed to submit for approval: {e}")
                st.stop()

            from src.services.audit_service import audit_service
            applied = 0
            enforced_cols = 0
            for asset in selected_assets:
                try:
                    # Privilege-based guard: require ALTER/OWNERSHIP on the object (no hardcoded roles)
                    if not authz.can_apply_tags_for_object(asset, object_type="TABLE"):
                        st.warning(f"Skipped {asset}: insufficient privileges to apply tags (ALTER/OWNERSHIP required)")
                        continue
                    tagging_service.apply_tags_to_object(
                        asset,
                        "TABLE",
                        {
                            "DATA_CLASSIFICATION": cls_val,
                            "CONFIDENTIALITY_LEVEL": str(int(c_val)),
                            "INTEGRITY_LEVEL": str(int(i_val)),
                            "AVAILABILITY_LEVEL": str(int(a_val)),
                        },
                    )
                    from src.services.discovery_service import discovery_service as _disc
                    _disc.mark_classified(asset, cls_val, int(c_val), int(i_val), int(a_val))
                    audit_service.log(user_email, "MANUAL_CLASSIFY_APPLY", "ASSET", asset, {"cls": cls_val, "c": c_val, "i": i_val, "a": a_val, "just": justification})
                    # Record applied decision
                    try:
                        classification_decision_service.record(
                            asset_full_name=asset,
                            decision_by=user_email or "system",
                            source="MANUAL",
                            status="Applied",
                            label=cls_val,
                            c=int(c_val), i=int(i_val), a=int(a_val),
                            rationale=justification or "",
                            details=None,
                        )
                    except Exception:
                        pass
                    # Persist to Snowflake decisions table for durable auditability
                    try:
                        _persist_decision(
                            asset_full_name=asset,
                            label=cls_val,
                            c=int(c_val), i=int(i_val), a=int(a_val),
                            owner=None,
                            rationale=(justification or ""),
                            checklist={},
                            decided_by=(user_email or "system"),
                            prev=None,
                        )
                    except Exception:
                        pass
                    applied += 1

                    # Auto-enforce masking policies for sensitive columns (tag-aware RBAC enforcement)
                    try:
                        detections = ai_classification_service.detect_sensitive_columns(asset)
                        result = policy_enforcement_service.auto_enforce_for_table(table=asset, detections=detections)
                        enforced_cols += len(result.get("applied", []))
                    except Exception:
                        pass
                except Exception as e:
                    st.error(f"Failed tagging {asset}: {e}")
            if enforced_cols > 0:
                st.success(f"Applied tags to {applied} asset(s) and enforced masking on {enforced_cols} column(s).")
            else:
                st.success(f"Applied tags to {applied} asset(s).")

    # CSV-based bulk assignment
    st.markdown("---")
    st.write("**Bulk Assignment via CSV**")
    st.caption("CSV columns required: FULL_NAME, DATA_CLASSIFICATION, C, I, A; optional: JUSTIFICATION")
    bulk_file = st.file_uploader("Upload CSV for bulk tagging", type=["csv"], key="bulk_csv")
    dry_run = st.checkbox("Dry run (validate only)", value=True)
    if bulk_file is not None:
        try:
            df_bulk = pd.read_csv(bulk_file)
            st.dataframe(df_bulk.head(20))
            if st.button("Process Bulk CSV", type="primary"):
                if not _can_classify:
                    st.error("You do not have permission to process bulk classification/tagging.")
                    st.stop()
                required_cols = {"FULL_NAME","DATA_CLASSIFICATION","C","I","A"}
                if not required_cols.issubset(set([c.upper() for c in df_bulk.columns])):
                    st.error(f"CSV must include columns: {', '.join(required_cols)}")
                else:
                    # Normalize columns to upper
                    df_bulk.columns = [c.upper() for c in df_bulk.columns]
                    errors = []
                    processed = 0
                    from src.services.tagging_service import tagging_service as _tsvc2
                    for _, row in df_bulk.iterrows():
                        full = str(row.get("FULL_NAME",""))
                        cls = str(row.get("DATA_CLASSIFICATION",""))
                        try:
                            c_b = int(row.get("C"))
                            i_b = int(row.get("I"))
                            a_b = int(row.get("A"))
                        except Exception:
                            errors.append(f"{full}: C/I/A must be integers 0-3")
                            continue
                        just = str(row.get("JUSTIFICATION")) if "JUSTIFICATION" in df_bulk.columns else ""
                        # Validate
                        if cls not in ALLOWED_CLASSIFICATIONS:
                            errors.append(f"{full}: invalid DATA_CLASSIFICATION '{cls}'")
                            continue
                        if not (0 <= c_b <= 3 and 0 <= i_b <= 3 and 0 <= a_b <= 3):
                            errors.append(f"{full}: C/I/A must be in 0..3")
                            continue
                        # Require justification for Restricted/Confidential or any CIA increase vs previous
                        try:
                            prev_c = prev_i = prev_a = None
                            refs = _tsvc2.get_object_tags(full, "TABLE") if full.count('.') == 2 else _tsvc2.get_object_tags(".".join(full.split('.')[:3]), "TABLE")
                            for r in refs:
                                tname = (r.get("TAG_NAME") or r.get("TAG") or r.get("TAG_DATABASE") or "").upper()
                                val = r.get("TAG_VALUE") or r.get("VALUE")
                                if tname.endswith("CONFIDENTIALITY_LEVEL"):
                                    prev_c = int(str(val)) if str(val).isdigit() else None
                                if tname.endswith("INTEGRITY_LEVEL"):
                                    prev_i = int(str(val)) if str(val).isdigit() else None
                                if tname.endswith("AVAILABILITY_LEVEL"):
                                    prev_a = int(str(val)) if str(val).isdigit() else None
                            if (cls in ("Restricted","Confidential") or (prev_c is not None and c_b > prev_c) or (prev_i is not None and i_b > prev_i) or (prev_a is not None and a_b > prev_a)) and not (just and just.strip()):
                                errors.append(f"{full}: justification required for Restricted/Confidential or CIA increase vs previous")
                                continue
                        except Exception:
                            # If previous tags cannot be read, proceed but still require justification for Restricted/Confidential
                            if cls in ("Restricted","Confidential") and not (just and just.strip()):
                                errors.append(f"{full}: justification required for Restricted/Confidential classification")
                                continue
                        # Enforce policy minimums similar to manual flow (no exception path in bulk)
                        try:
                            req_min_c, req_min_cls, _reg = required_minimum_for_asset(full, categories=[])
                            if (c_b < int(req_min_c)) or (ALLOWED_CLASSIFICATIONS.index(cls) < ALLOWED_CLASSIFICATIONS.index(req_min_cls)):
                                errors.append(f"{full}: below policy minimums (requires at least {req_min_cls}, C≥{req_min_c})")
                                continue
                        except Exception:
                            pass
                        if dry_run:
                            processed += 1
                            continue
                        try:
                            parts = full.split(".")
                            if len(parts) == 4:
                                table_full = ".".join(parts[0:3])
                                column_name = parts[3]
                                # Require privileges on the parent table
                                if not authz.can_apply_tags_for_object(table_full, object_type="TABLE"):
                                    errors.append(f"{full}: insufficient privileges to tag column (ALTER/OWNERSHIP on table required)")
                                    continue
                                tagging_service.apply_tags_to_column(
                                    table_full,
                                    column_name,
                                    {
                                        "DATA_CLASSIFICATION": cls,
                                        "CONFIDENTIALITY_LEVEL": str(c_b),
                                        "INTEGRITY_LEVEL": str(i_b),
                                        "AVAILABILITY_LEVEL": str(a_b),
                                    },
                                )
                                # Column-level tagging doesn't change table inventory classification directly
                                target_id = f"{table_full}.{column_name}"
                            else:
                                if not authz.can_apply_tags_for_object(full, object_type="TABLE"):
                                    errors.append(f"{full}: insufficient privileges to apply tags (ALTER/OWNERSHIP required)")
                                    continue
                                tagging_service.apply_tags_to_object(
                                    full,
                                    "TABLE",
                                    {
                                        "DATA_CLASSIFICATION": cls,
                                        "CONFIDENTIALITY_LEVEL": str(c_b),
                                        "INTEGRITY_LEVEL": str(i_b),
                                        "AVAILABILITY_LEVEL": str(a_b),
                                    },
                                )
                                from src.services.discovery_service import discovery_service as _disc
                                _disc.mark_classified(full, cls, int(c_b), int(i_b), int(a_b))
                                target_id = full
                            from src.services.audit_service import audit_service as _audit
                            _audit.log(user_email or "bulk@system", "BULK_CLASSIFY_APPLY", "ASSET", target_id, {"cls": cls, "c": c_b, "i": i_b, "a": a_b, "just": just})
                            processed += 1
                        except Exception as e:
                            errors.append(f"{full}: {e}")
                    if dry_run:
                        st.info(f"Dry run OK. {processed} row(s) validated successfully. {len(errors)} error(s).")
                    else:
                        st.success(f"Processed {processed} row(s). {len(errors)} error(s).")
                    if errors:
                        st.error("\n".join(errors[:50]))
        except Exception as e:
            st.error(f"Failed to read CSV: {e}")

    # -------------------------------------------------------------
    # Column-level Tagging (Multiplayer)
    # -------------------------------------------------------------
    st.markdown("---")
    with st.expander("Column-level Tagging (Multiplayer)", expanded=True):
        st.caption("Filter down to a table, pick columns, review suggestions, and apply column-level classification tags. URL sync enabled for easy sharing.")

        # URL query param sync to facilitate shared context
        try:
            q = st.experimental_get_query_params() or {}
        except Exception:
            q = {}

        # Cached loaders
        @st.cache_data(ttl=1800)
        def list_databases():
            try:
                rows = snowflake_connector.execute_query(
                    """
                    SELECT DATABASE_NAME AS NAME
                    FROM SNOWFLAKE.ACCOUNT_USAGE.DATABASES
                    WHERE DELETED IS NULL OR DELETED = FALSE
                    ORDER BY NAME
                    LIMIT 200
                    """
                ) or []
                return [r.get("NAME") for r in rows if r.get("NAME")]
            except Exception:
                return []

        @st.cache_data(ttl=1800)
        def list_schemas(db: str):
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT SCHEMA_NAME AS NAME
                    FROM {db}.INFORMATION_SCHEMA.SCHEMATA
                    WHERE SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA')
                    ORDER BY NAME
                    LIMIT 1000
                    """
                ) or []
                return [r.get("NAME") for r in rows if r.get("NAME")]
            except Exception:
                return []

        @st.cache_data(ttl=1800)
        def list_tables(db: str, schema: str):
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT TABLE_NAME AS NAME
                    FROM {db}.INFORMATION_SCHEMA.TABLES
                    WHERE TABLE_SCHEMA = %(sc)s AND TABLE_TYPE IN ('BASE TABLE','VIEW')
                    ORDER BY NAME
                    LIMIT 5000
                    """,
                    {"sc": schema},
                ) or []
                return [r.get("NAME") for r in rows if r.get("NAME")]
            except Exception:
                return []

        @st.cache_data(ttl=1800)
        def list_columns(db: str, schema: str, table: str):
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT COLUMN_NAME, DATA_TYPE, ORDINAL_POSITION
                    FROM {db}.INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = %(sc)s AND TABLE_NAME = %(tb)s
                    ORDER BY ORDINAL_POSITION
                    """,
                    {"sc": schema, "tb": table},
                ) or []
                return rows
            except Exception:
                return []

        # Controls row 1: database, schema, table + url sync
        dbs = list_databases()
        c1, c2, c3, c4 = st.columns([2,2,3,1])
        with c1:
            sel_db = st.selectbox("Database", options=dbs, index=(dbs.index(q.get('db',[sel.get('database') or ''])[0]) if (q.get('db') and q.get('db')[0] in dbs) else (dbs.index(sel.get('database')) if sel.get('database') in dbs else 0)) if dbs else None, key="col_db")
        schemas = list_schemas(sel_db) if sel_db else []
        with c2:
            sel_sc = st.selectbox("Schema", options=schemas, index=(schemas.index(q.get('sc',[sel.get('schema') or ''])[0]) if (q.get('sc') and q.get('sc')[0] in schemas) else (schemas.index(sel.get('schema')) if sel.get('schema') in schemas else 0)) if schemas else None, key="col_sc")
        tables = list_tables(sel_db, sel_sc) if (sel_db and sel_sc) else []
        with c3:
            sel_tb = st.selectbox("Table", options=tables, index=(tables.index(q.get('tb',[sel.get('table') or ''])[0]) if (q.get('tb') and q.get('tb')[0] in tables) else (tables.index(sel.get('table')) if sel.get('table') in tables else 0)) if tables else None, key="col_tb")
        with c4:
            sync = st.checkbox("Sync URL", value=True, help="Include db/schema/table in URL for sharing")
        if sync and sel_db and sel_sc and sel_tb:
            try:
                st.experimental_set_query_params(db=sel_db, sc=sel_sc, tb=sel_tb)
            except Exception:
                pass

        # Controls row 2: column search and multi-select
        cols = list_columns(sel_db, sel_sc, sel_tb) if (sel_db and sel_sc and sel_tb) else []
        table_full = f"{sel_db}.{sel_sc}.{sel_tb}" if (sel_db and sel_sc and sel_tb) else None
        f1, f2 = st.columns([3,2])
        with f1:
            col_search = st.text_input("Filter columns", placeholder="Search by name or data type...", key="col_search")
        col_names = [r.get("COLUMN_NAME") for r in cols]
        if col_search:
            cols_view = [r for r in cols if col_search.lower() in str(r.get("COLUMN_NAME","" )).lower() or col_search.lower() in str(r.get("DATA_TYPE","" )).lower()]
        else:
            cols_view = cols
        with f2:
            selected_columns = st.multiselect("Columns", options=[r.get("COLUMN_NAME") for r in cols_view], default=[r.get("COLUMN_NAME") for r in cols_view[:5]], key="col_pick")

        # Quick select actions (multiplayer-friendly)
        q1, q2, q3 = st.columns([1,1,2])
        with q1:
            if st.button("Select All", key="col_pick_all"):
                st.session_state["col_pick"] = [r.get("COLUMN_NAME") for r in cols_view]
                st.rerun()
        with q2:
            if st.button("Clear", key="col_pick_clear"):
                st.session_state["col_pick"] = []
                st.rerun()
        with q3:
            pii_keys = ["SSN","EMAIL","PHONE","ADDRESS","DOB","PII","PERSON","EMPLOYEE","CUSTOMER","CARD","PAN","AADHAAR","PASSPORT","NATIONAL_ID","NAME"]
            if st.button("Quick-select PII-like", key="col_pick_pii"):
                picks = []
                for r in cols_view:
                    nm = (r.get("COLUMN_NAME") or "").upper()
                    if any(k in nm for k in pii_keys):
                        picks.append(r.get("COLUMN_NAME"))
                st.session_state["col_pick"] = picks or st.session_state.get("col_pick", [])
                st.rerun()

        # Suggested labels via AI detection (best-effort)
        suggestions = {}
        if table_full:
            try:
                det = ai_classification_service.detect_sensitive_columns(table_full)
                # Expecting det like {"columns": {"EMAIL": {"label":"Restricted","c":2,...}}}
                if isinstance(det, dict):
                    colmap = det.get("columns") or det
                    for k, v in colmap.items():
                        if isinstance(v, dict):
                            suggestions[str(k).upper()] = {
                                "label": v.get("label") or v.get("classification") or "Internal",
                                "c": int(v.get("c", 1)),
                                "i": int(v.get("i", 1)),
                                "a": int(v.get("a", 1)),
                                "reason": v.get("reason") or v.get("explanation") or "",
                            }
            except Exception:
                pass

        # Fetch current tags for object/columns (best-effort) to show history/current state
        prev_tags = {}
        if table_full:
            try:
                refs = tagging_service.get_object_tags(table_full, "TABLE")
                # Build a map: COLUMN_NAME -> {TAG_NAME: value}
                for r in refs:
                    col = r.get("COLUMN_NAME") or r.get("COLUMN") or r.get("name")
                    tname = r.get("TAG_NAME") or r.get("TAG") or r.get("TAG_DATABASE")
                    val = r.get("TAG_VALUE") or r.get("VALUE")
                    if not tname:
                        continue
                    tkey = str(tname).split(".")[-1].upper()
                    if col:
                        prev_tags.setdefault(str(col).upper(), {})[tkey] = val
                    else:
                        prev_tags.setdefault("__OBJECT__", {})[tkey] = val
            except Exception:
                prev_tags = {}

        # Build editable grid: columns with type, suggestion, and chosen tagging
        import pandas as _pd  # safe inside block
        grid_rows = []
        for r in cols_view:
            nm = r.get("COLUMN_NAME")
            if nm not in selected_columns:
                continue
            typ = r.get("DATA_TYPE")
            sug = suggestions.get(str(nm).upper(), {})
            sc, si, sa = sug.get("c", 1), sug.get("i", 1), sug.get("a", 1)
            slabel = sug.get("label", "Internal")
            # Merge with previous tags to show current state
            cur = prev_tags.get(str(nm).upper(), {})
            cur_label = cur.get("DATA_CLASSIFICATION") or slabel
            try:
                cur_c = int(cur.get("CONFIDENTIALITY_LEVEL", sc))
                cur_i = int(cur.get("INTEGRITY_LEVEL", si))
                cur_a = int(cur.get("AVAILABILITY_LEVEL", sa))
            except Exception:
                cur_c, cur_i, cur_a = sc, si, sa
            grid_rows.append({
                "Column": nm,
                "Type": typ,
                "Suggested Label": slabel,
                "C": cur_c,
                "I": cur_i,
                "A": cur_a,
                "Label": cur_label if cur_label in ALLOWED_CLASSIFICATIONS else "Internal",
                "Reason": sug.get("reason", ""),
                "Current Tags": ", ".join([f"{k}={v}" for k, v in cur.items()]) if cur else "",
            })
        df_grid = _pd.DataFrame(grid_rows) if grid_rows else _pd.DataFrame(columns=["Column","Type","Suggested Label","C","I","A","Label","Reason","Current Tags"])

        # Bulk defaults for selected rows
        b1, b2, b3, b4, b5 = st.columns([2,1,1,1,1])
        with b1:
            bulk_label = st.selectbox("Set Label for selected", options=ALLOWED_CLASSIFICATIONS, index=1, key="col_bulk_label")
        with b2:
            bulk_c = st.number_input("C", min_value=0, max_value=3, value=1, step=1, key="col_bulk_c")
        with b3:
            bulk_i = st.number_input("I", min_value=0, max_value=3, value=1, step=1, key="col_bulk_i")
        with b4:
            bulk_a = st.number_input("A", min_value=0, max_value=3, value=1, step=1, key="col_bulk_a")
        with b5:
            if st.button("Apply to selected rows", key="col_bulk_apply_btn"):
                st.session_state.setdefault("col_bulk", {})
                st.session_state["col_bulk"].update({"apply": True, "label": bulk_label, "c": int(bulk_c), "i": int(bulk_i), "a": int(bulk_a), "target": set(selected_columns)})
                st.rerun()

        # Interactive editor with constrained choices for Label and CIA
        editor_conf = {
            "Label": st.column_config.SelectboxColumn(options=ALLOWED_CLASSIFICATIONS, help="Classification label"),
            "C": st.column_config.NumberColumn(min_value=0, max_value=3, step=1, help="Confidentiality 0..3"),
            "I": st.column_config.NumberColumn(min_value=0, max_value=3, step=1, help="Integrity 0..3"),
            "A": st.column_config.NumberColumn(min_value=0, max_value=3, step=1, help="Availability 0..3"),
        }
        # If bulk apply flag set, override grid_rows before rendering
        _bulk = st.session_state.get("col_bulk") or {}
        if _bulk.get("apply") and grid_rows:
            tgt = _bulk.get("target") or set()
            for row in grid_rows:
                if row.get("Column") in tgt:
                    row["Label"] = _bulk.get("label")
                    row["C"] = int(_bulk.get("c", row["C"]))
                    row["I"] = int(_bulk.get("i", row["I"]))
                    row["A"] = int(_bulk.get("a", row["A"]))
            # reset flag after applying
            st.session_state["col_bulk"]["apply"] = False
        df_grid = _pd.DataFrame(grid_rows) if grid_rows else _pd.DataFrame(columns=["Column","Type","Suggested Label","C","I","A","Label","Reason","Current Tags"])

        edited_df = st.data_editor(
            df_grid,
            num_rows="dynamic",
            use_container_width=True,
            column_config=editor_conf,
            disabled=["Column","Type","Suggested Label","Current Tags"],
            key="col_editor",
        )

        # Optional: Tag history drawer (last 5 decisions per selected column)
        show_hist = st.checkbox("Show tag history (last 5 / column)", value=False, key="col_hist_toggle")
        if show_hist and table_full and selected_columns:
            try:
                from datetime import datetime as _dt  # localize import
                DB = _get_current_db()
                for colnm in selected_columns[:10]:
                    with st.expander(f"History: {table_full}.{colnm}", expanded=False):
                        try:
                            rows = snowflake_connector.execute_query(
                                f"""
                                SELECT ID, DECISION_AT, DECISION_BY, SOURCE, STATUS, LABEL, C, I, A, RISK_LEVEL, RATIONALE
                                FROM {DB}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
                                WHERE ASSET_FULL_NAME = %(afn)s
                                ORDER BY DECISION_AT DESC
                                LIMIT 5
                                """,
                                {"afn": f"{table_full}.{colnm}"},
                            ) or []
                            st.dataframe(_pd.DataFrame(rows), use_container_width=True)
                        except Exception as e:
                            st.info(f"No history available: {e}")
            except Exception:
                pass

        # Apply actions
        user_email_cols = st.text_input("Your email (for audit)", key="col_user_email")
        col_just = st.text_area(
            "Rationale (required for Restricted/Confidential; stored in audit)",
            key="col_just",
            height=80,
        )
        apply_cols_btn = st.button("Apply Column Tags", type="primary", key="btn_apply_cols")

        if apply_cols_btn:
            if not _can_classify:
                st.error("You do not have permission to apply classifications or tags.")
                st.stop()
            if not table_full or not selected_columns:
                st.warning("Select a database, schema, table and at least one column.")
                st.stop()
            # Privilege check at table level
            if not authz.can_apply_tags_for_object(table_full, object_type="TABLE"):
                st.error("Insufficient privileges to tag columns on this table (ALTER/OWNERSHIP required)")
                st.stop()
            from src.services.audit_service import audit_service as _audit
            applied = 0
            errors = []
            # Iterate over edited grid rows to pick chosen values
            for _, row in edited_df.iterrows():
                colnm = row.get("Column")
                if colnm not in selected_columns:
                    continue
                try:
                    label = str(row.get("Label") or row.get("Suggested Label") or "Internal")
                    c_b = int(row.get("C") or 1); i_b = int(row.get("I") or 1); a_b = int(row.get("A") or 1)
                    if label not in ALLOWED_CLASSIFICATIONS or not (0 <= c_b <= 3 and 0 <= i_b <= 3 and 0 <= a_b <= 3):
                        errors.append(f"{table_full}.{colnm}: invalid Label or CIA levels")
                        continue
                    # Enforce decision matrix (CIA-to-label minimums and special categories)
                    ok_dm, reasons_dm = dm_validate(label, int(c_b), int(i_b), int(a_b))
                    if not ok_dm:
                        for r in (reasons_dm or []):
                            errors.append(f"{table_full}.{colnm}: {r}")
                        continue
                    # Require rationale for higher sensitivity labels
                    if label in ("Restricted", "Confidential") and not (col_just and col_just.strip()):
                        errors.append(f"{table_full}.{colnm}: rationale is required for {label}")
                        continue
                    tagging_service.apply_tags_to_column(
                        table_full,
                        colnm,
                        {
                            "DATA_CLASSIFICATION": label,
                            "CONFIDENTIALITY_LEVEL": str(c_b),
                            "INTEGRITY_LEVEL": str(i_b),
                            "AVAILABILITY_LEVEL": str(a_b),
                        },
                    )
                    # Optional: record decision at column granularity
                    try:
                        classification_decision_service.record(
                            asset_full_name=f"{table_full}.{colnm}",
                            decision_by=user_email_cols or (user_email or "system"),
                            source="MANUAL",
                            status="Applied",
                            label=label,
                            c=c_b, i=i_b, a=a_b,
                            rationale=(col_just or justification or ""),
                            details={"scope": "COLUMN"},
                        )
                    except Exception:
                        pass
                    # Persist to Snowflake decisions table for auditability
                    try:
                        _persist_decision(
                            asset_full_name=f"{table_full}.{colnm}",
                            label=label,
                            c=int(c_b), i=int(i_b), a=int(a_b),
                            owner=None,
                            rationale=(col_just or justification or ""),
                            checklist={},
                            decided_by=(user_email_cols or (user_email or "system")),
                            prev=None,
                        )
                    except Exception:
                        pass
                    _audit.log(user_email_cols or (user_email or "system"), "COLUMN_CLASSIFY_APPLY", "COLUMN", f"{table_full}.{colnm}", {"cls": label, "c": c_b, "i": i_b, "a": a_b, "just": col_just})
                    applied += 1
                except Exception as e:
                    errors.append(f"{table_full}.{colnm}: {e}")
            if applied and not errors:
                st.success(f"Applied tags to {applied} column(s).")
            elif applied and errors:
                st.success(f"Applied tags to {applied} column(s). {len(errors)} error(s).")
                st.error("\n".join(errors[:50]))
            else:
                st.error("No column tags applied.")

with tab2:
    # AI Detection
    st.subheader("AI Detection")
    st.write("Use AI to suggest labels, CIA scores, evidence snippets, and applicable frameworks. Apply or submit for approval.")
    # Quick actions: run in-database Snowpark heuristic or native SYSTEM$CLASSIFY for a selected asset
    try:
        # Load a small asset list for selection
        aset_rows = snowflake_connector.execute_query(
            f"""
            SELECT "TABLE_CATALOG"||'.'||"TABLE_SCHEMA"||'.'||"TABLE_NAME" AS FULL
            FROM {_get_current_db()}.INFORMATION_SCHEMA.TABLES
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            ORDER BY 1 LIMIT 100
            """
        ) or []
        aset_opts = [r.get('FULL') for r in aset_rows if r.get('FULL')]
    except Exception:
        aset_opts = []
    col_ai1, col_ai2 = st.columns([3,1])
    with col_ai1:
        target_asset = st.selectbox("Select asset for AI detection", options=aset_opts, index=0 if aset_opts else None, key="ai_det_asset")
    with col_ai2:
        run_sp = st.button("Snowpark Classify", key="btn_ai_sp")
        run_sys = st.button("SYSTEM$CLASSIFY", key="btn_ai_sys")
    if run_sp and target_asset:
        with st.spinner("Running Snowpark contextual classification..."):
            res = snowpark_udf_service.classify_table(target_asset)
        st.success(f"Label: {res.get('label')} | Confidence: {res.get('confidence')}")
        st.json({k: v for k, v in res.items() if k != 'features'})
    if run_sys and target_asset:
        with st.spinner("Running SYSTEM$CLASSIFY for selected asset..."):
            try:
                out = snowflake_connector.execute_query("SELECT SYSTEM$CLASSIFY('TABLE', %(f)s) AS R", {"f": target_asset}) or []
                st.json(out[0] if out else {})
            except Exception as e:
                st.error(f"SYSTEM$CLASSIFY failed: {e}")
    try:
        from src.services.ai_classification_service import ai_classification_service
        # Asset list
        try:
            with st.spinner("Loading assets from Snowflake..."):
                tables = snowflake_connector.execute_query(
                    f"""
                    SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS full_name
                    FROM {_get_current_db()}.INFORMATION_SCHEMA.TABLES
                    WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                    ORDER BY "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"
                    LIMIT 200
                    """
                )
                asset_options = [t['FULL_NAME'] for t in tables] if tables else []
        except Exception as e:
            st.warning(f"Could not load assets: {e}")
            asset_options = []

        # Search/filter across datasets
        ai_search = st.text_input("Search datasets", placeholder="Type to filter by name...", key="ai_search")
        ai_options = [a for a in asset_options if (ai_search.lower() in a.lower())] if ai_search else asset_options
        selected_asset = st.selectbox("Select an asset", ai_options if ai_options else ["No assets available"]) 

        if st.button("Get AI Suggestion", type="primary") and selected_asset and selected_asset != "No assets available":
            with st.spinner("Analyzing data asset with AI..."):
                try:
                    result = ai_classification_service.classify_table(selected_asset)
                    st.success(f"AI Classification for {selected_asset}")
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Suggested Label", result.get('classification', 'Unknown'))
                    c2.metric("Confidence", f"{result.get('confidence', 0)*100:.1f}%")
                    c3.metric("Frameworks", ", ".join(result.get('compliance_frameworks', [])) or "None")

                    # Evidence snippets (sample rows)
                    try:
                        sample_df = ai_classification_service.get_sample_data(selected_asset, 5)
                        if not sample_df.empty:
                            st.caption("Evidence snippets (first 5 rows)")
                            st.dataframe(sample_df.head(5))
                    except Exception:
                        pass

                    # CIA defaults from label registry
                    suggested_cls = result.get('classification') or 'Internal'
                    try:
                        labels = label_service.list_labels()
                        defaults = next((l for l in (labels or []) if str(l.get('LABEL_NAME')).lower() == suggested_cls.lower()), None)
                        if defaults:
                            def_c = int(defaults.get('DEFAULT_C') or 1)
                            def_i = int(defaults.get('DEFAULT_I') or 1)
                            def_a = int(defaults.get('DEFAULT_A') or 1)
                        else:
                            mapping = {'Public': (0,0,0),'Internal':(1,1,1),'Restricted':(2,2,2),'Confidential':(3,3,3)}
                            def_c, def_i, def_a = mapping.get(suggested_cls, (1,1,1))
                    except Exception:
                        def_c, def_i, def_a = 1, 1, 1

                    st.markdown("---")
                    st.write("Suggested CIA (editable)")
                    cc, ii, aa = st.columns(3)
                    with cc:
                        sug_c = st.number_input("C", 0, 3, int(def_c))
                    with ii:
                        sug_i = st.number_input("I", 0, 3, int(def_i))
                    with aa:
                        sug_a = st.number_input("A", 0, 3, int(def_a))

                    default_just = f"AI suggested '{suggested_cls}' with frameworks: {', '.join(result.get('compliance_frameworks', []))}"
                    justification = st.text_area("Justification", value=default_just)
                    user_email = st.text_input("Your email (for audit)", key="ai_user_email")

                    col_left, col_right = st.columns(2)
                    with col_left:
                        if st.button("Submit for Approval") and user_email:
                            try:
                                rid = reclassification_service.submit_request(
                                    selected_asset,
                                    (suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal', int(sug_c), int(sug_i), int(sug_a)),
                                    justification or default_just,
                                    user_email,
                                    trigger_type="AI_SUGGESTED",
                                )
                                st.success(f"Submitted reclassification request: {rid}")
                            except Exception as e:
                                st.error(f"Failed to submit request: {e}")
                    with col_right:
                        if st.button("Apply Now"):
                            if not _can_classify:
                                st.error("You do not have permission to apply classifications or tags. Contact a Data Owner or Admin.")
                                st.stop()
                            try:
                                # Validate guardrails
                                ok2, reasons2 = dm_validate(suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal', int(sug_c), int(sug_i), int(sug_a))
                                if not ok2:
                                    for r in reasons2:
                                        st.error(r)
                                    st.stop()
                                # Gate C3/Confidential behind approval if user lacks approval capability
                                requires_approval_ai = ((result.get('classification') or '').lower() == 'confidential' or int(sug_c) == 3) and (not _can_approve)
                                if requires_approval_ai:
                                    from src.services.reclassification_service import reclassification_service as _reclass
                                    rid = _reclass.submit_request(
                                        selected_asset,
                                        (suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal', int(sug_c), int(sug_i), int(sug_a)),
                                        justification or default_just or "AI suggested C3/Confidential - approval required",
                                        user_email or "system",
                                        trigger_type="AI_SUGGESTED_HIGH_RISK",
                                    )
                                    # Record submitted decision
                                    try:
                                        classification_decision_service.record(
                                            asset_full_name=selected_asset,
                                            decision_by=user_email or "system",
                                            source="AI_SUGGESTED",
                                            status="Submitted",
                                            label=suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal',
                                            c=int(sug_c), i=int(sug_i), a=int(sug_a),
                                            rationale=justification or default_just or "",
                                            details={"request_id": rid},
                                        )
                                    except Exception:
                                        pass
                                    st.success(f"Submitted reclassification request for approval: {rid}")
                                    st.stop()
                                if not authz.can_apply_tags_for_object(selected_asset, object_type="TABLE"):
                                    st.error("Insufficient privileges to apply tags to this asset (ALTER/OWNERSHIP required).")
                                    st.stop()
                                tagging_service.apply_tags_to_object(
                                    selected_asset,
                                    "TABLE",
                                    {
                                        "DATA_CLASSIFICATION": suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal',
                                        "CONFIDENTIALITY_LEVEL": str(int(sug_c)),
                                        "INTEGRITY_LEVEL": str(int(sug_i)),
                                        "AVAILABILITY_LEVEL": str(int(sug_a)),
                                    },
                                )
                                # Record applied decision from AI suggestion
                                try:
                                    classification_decision_service.record(
                                        asset_full_name=selected_asset,
                                        decision_by=user_email or "system",
                                        source="AI_SUGGESTED",
                                        status="Applied",
                                        label=suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal',
                                        c=int(sug_c), i=int(sug_i), a=int(sug_a),
                                        rationale=justification or default_just or "",
                                        details=None,
                                    )
                                except Exception:
                                    pass
                                st.success("Applied suggested tags.")
                            except Exception as e:
                                st.error(f"Failed to apply tags: {e}")

                    with st.expander("View detailed AI features"):
                        st.json(result.get('features', {}))
                except Exception as e:
                    st.error(f"Error during AI classification: {str(e)}")
    except ImportError as e:
        st.error(f"AI classification service not available: {str(e)}")
        st.info("Please ensure all required dependencies are installed.")

with tab3:
    st.subheader("Risk Analysis")
    st.write("Compute overall risk based on highest CIA score. Highlight high-risk datasets.")
    try:
        only_classified = st.checkbox("Only classified assets", value=True, help="Show only assets with CLASSIFIED = TRUE")
        where_clause = "WHERE CLASSIFIED = TRUE" if only_classified else ""
        rows = snowflake_connector.execute_query(
            f"""
            SELECT FULL_NAME, CLASSIFICATION_LEVEL, CIA_CONF, CIA_INT, CIA_AVAIL
            FROM {_get_current_db()}.DATA_GOVERNANCE.ASSET_INVENTORY
            {where_clause}
            LIMIT 500
            """
        )
        df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["FULL_NAME","CLASSIFICATION_LEVEL","CIA_CONF","CIA_INT","CIA_AVAIL"])
        if not df.empty:
            # Normalize CIA columns to integers; handle NaN/None safely
            for col in ["CIA_CONF", "CIA_INT", "CIA_AVAIL"]:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
            def risk_row(r):
                highest = max(int(r.get('CIA_CONF') or 0), int(r.get('CIA_INT') or 0), int(r.get('CIA_AVAIL') or 0))
                level = 'Low' if highest <= 1 else ('Medium' if highest == 2 else 'High')
                rationale = f"Highest CIA={highest} from C={r.get('CIA_CONF')}, I={r.get('CIA_INT')}, A={r.get('CIA_AVAIL')}"
                # Regulatory chips
                name = str(r.get('FULL_NAME') or '')
                up = name.upper()
                regs = []
                if any(k in up for k in ["SOX","FINANCE","GL","PAYROLL","INVOICE","AUDIT"]):
                    regs.append("SOX/SOC2")
                if any(k in up for k in ["GDPR","EU","DATA_SUBJECT","DSR"]):
                    regs.append("GDPR")
                if any(k in up for k in ["HIPAA","PHI","HEALTH","MEDICAL"]):
                    regs.append("HIPAA")
                # Risk indicator emoji
                emoji = '🟢' if level == 'Low' else ('🟠' if level == 'Medium' else '🔴')
                return pd.Series({"RISK": level, "RISK_IND": emoji, "Regulatory": ", ".join(regs), "RegsList": regs, "Rationale": rationale, "HIGHEST": highest})
            risk = df.apply(risk_row, axis=1)
            out = pd.concat([df, risk], axis=1)
            # Min CIA threshold filter
            min_threshold = st.slider("Min CIA threshold", min_value=0, max_value=3, value=0, help="Show assets with max(C,I,A) >= threshold")
            out = out[out["HIGHEST"] >= int(min_threshold)] if not out.empty else out
            st.markdown("**Legend:** 🔴 High  🟠 Medium  🟢 Low")
            show_cols = ["RISK_IND","FULL_NAME","CLASSIFICATION_LEVEL","CIA_CONF","CIA_INT","CIA_AVAIL","RISK","Regulatory","Rationale"]
            st.dataframe(out[show_cols], use_container_width=True)
            try:
                csv_bytes = out[show_cols].to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="Download Risk Analysis (CSV)",
                    data=csv_bytes,
                    file_name="risk_analysis.csv",
                    mime="text/csv",
                )
            except Exception:
                pass

            # Summary metrics
            high_count = (out['RISK'] == 'High').sum()
            med_count = (out['RISK'] == 'Medium').sum()
            low_count = (out['RISK'] == 'Low').sum()
            c1, c2, c3 = st.columns(3)
            c1.metric("High Risk", int(high_count))
            c2.metric("Medium Risk", int(med_count))
            c3.metric("Low Risk", int(low_count))
            if high_count:
                st.warning(f"{int(high_count)} high-risk datasets detected")
            # Risk distribution chart
            try:
                dist_df = pd.DataFrame({"Risk": ["High","Medium","Low"], "Count": [int(high_count), int(med_count), int(low_count)]})
                st.bar_chart(dist_df.set_index("Risk"))
            except Exception:
                pass

            # Pill-style regulatory chips (card view)
            with st.expander("Show chip-style view"):
                st.markdown(
                    """
                    <style>
                      .chip {display:inline-block;padding:2px 8px;margin:2px;border-radius:12px;font-size:12px;color:white}
                      .chip-sox {background-color:#6c5ce7}
                      .chip-gdpr {background-color:#0984e3}
                      .chip-hipaa {background-color:#00b894}
                      .chip-other {background-color:#636e72}
                      .card {border:1px solid #e0e0e0;border-radius:8px;padding:8px;margin-bottom:8px}
                      .risk-high {border-left:6px solid #e74c3c}
                      .risk-med {border-left:6px solid #e67e22}
                      .risk-low {border-left:6px solid #2ecc71}
                    </style>
                    """,
                    unsafe_allow_html=True,
                )
                # Limit number of cards for performance
                subset = out.head(100)
                for _, row in subset.iterrows():
                    regs = row.get("RegsList") or []
                    chips = []
                    for r in regs:
                        cls = "chip-other"
                        if r.startswith("SOX"): cls = "chip-sox"
                        elif r == "GDPR": cls = "chip-gdpr"
                        elif r == "HIPAA": cls = "chip-hipaa"
                        chips.append(f"<span class=\"chip {cls}\">{r}</span>")
                    chips_html = " ".join(chips) if chips else "<span class='chip chip-other'>None</span>"
                    risk_cls = "risk-high" if row.get("RISK") == "High" else ("risk-med" if row.get("RISK") == "Medium" else "risk-low")
                    risk_ind = row.get('RISK_IND','')
                    full_name = row.get('FULL_NAME','')
                    cls_level = row.get('CLASSIFICATION_LEVEL','-')
                    c_val = row.get('CIA_CONF',0)
                    i_val = row.get('CIA_INT',0)
                    a_val = row.get('CIA_AVAIL',0)
                    rationale = row.get('Rationale','')
                    html = f"""
                    <div class='card {risk_cls}'>
                      <div><b>{risk_ind} {full_name}</b></div>
                      <div>Classification: {cls_level} | C:{c_val} I:{i_val} A:{a_val}</div>
                      <div>Regulatory: {chips_html}</div>
                      <div style='color:#636e72;font-size:12px'>Rationale: {rationale}</div>
                    </div>
                    """
                    st.markdown(html, unsafe_allow_html=True)
        else:
            st.info("No inventory found. Run discovery scan to populate inventory.")
    except Exception as e:
        st.warning(f"Risk analysis unavailable: {e}")

with tab4:
    st.subheader("Reclassification")
    st.write("Track triggers, submit requests with impact assessment, and manage approvals.")

    st.markdown("---")
    st.subheader("Provisional I/A Review")
    st.caption("Review assets where automated I/A assignment is provisional. Finalize Integrity and Availability with business rationale.")
    try:
        db = _get_current_db()
        prov = snowflake_connector.execute_query(
            f"""
            SELECT ID, ASSET_FULL_NAME, REASON, CONFIDENCE, SENSITIVE_CATEGORIES, CREATED_AT, DETAILS
            FROM {db}.DATA_GOVERNANCE.CLASSIFICATION_QUEUE
            WHERE REASON = 'PROVISIONAL_IA'
            ORDER BY CREATED_AT ASC
            LIMIT 500
            """
        ) or []
    except Exception as e:
        prov = []
        st.info(f"Provisional queue unavailable: {e}")

    if prov:
        import pandas as _pd
        pdf = _pd.DataFrame(prov)
        st.dataframe(pdf[[c for c in ["ID","ASSET_FULL_NAME","REASON","CONFIDENCE","SENSITIVE_CATEGORIES","CREATED_AT"] if c in pdf.columns]], use_container_width=True)
        sel_id = st.selectbox("Select provisional item", options=[p.get("ID") for p in prov])
        chosen = next((p for p in prov if p.get("ID") == sel_id), None)
        if chosen:
            st.write(f"Asset: {chosen.get('ASSET_FULL_NAME')}")
            st.json({"detected_categories": chosen.get("SENSITIVE_CATEGORIES"), "details": chosen.get("DETAILS")})
            ccol1, ccol2, ccol3 = st.columns(3)
            with ccol1:
                i_fix = st.number_input("Finalize I (0-3)", min_value=0, max_value=3, value=2, key="prov_fix_i")
            with ccol2:
                a_fix = st.number_input("Finalize A (0-3)", min_value=0, max_value=3, value=2, key="prov_fix_a")
            with ccol3:
                cls_fix = st.selectbox("Classification", options=ALLOWED_CLASSIFICATIONS, index=1, key="prov_fix_cls")
            rat = st.text_area("Rationale (required)", height=80, key="prov_fix_rat")
            approver = st.text_input("Your email (approver)", key="prov_fix_user")
            if st.button("Finalize I/A & Apply", type="primary", key="prov_fix_apply"):
                if not approver:
                    st.warning("Please enter your email.")
                elif not rat or not rat.strip():
                    st.warning("Please provide rationale.")
                else:
                    full = chosen.get("ASSET_FULL_NAME")
                    try:
                        # Apply tags to object with finalized I/A, keep existing C/label from selection
                        tagging_service.apply_tags_to_object(
                            full,
                            "TABLE",
                            {
                                "DATA_CLASSIFICATION": cls_fix,
                                "CONFIDENTIALITY_LEVEL": str(max(int(i_fix), int(a_fix))) if cls_fix == "Internal" else ("2" if cls_fix == "Restricted" else ("3" if cls_fix == "Confidential" else "0")),
                                "INTEGRITY_LEVEL": str(int(i_fix)),
                                "AVAILABILITY_LEVEL": str(int(a_fix)),
                            },
                        )
                        # Persist decision for audit
                        try:
                            classification_decision_service.record(
                                asset_full_name=full,
                                decision_by=approver,
                                source="REVIEW",
                                status="Applied",
                                label=cls_fix,
                                c=int(max(int(i_fix), int(a_fix))),
                                i=int(i_fix),
                                a=int(a_fix),
                                rationale=rat,
                                details={"source": "PROVISIONAL_IA_REVIEW", "queue_id": chosen.get("ID")},
                            )
                        except Exception:
                            pass
                        # Remove from provisional queue
                        try:
                            snowflake_connector.execute_non_query(
                                f"DELETE FROM {db}.DATA_GOVERNANCE.CLASSIFICATION_QUEUE WHERE ID = %(id)s",
                                {"id": chosen.get("ID")},
                            )
                        except Exception:
                            pass
                        st.success("Finalized I/A and applied tags. Queue item cleared.")
                    except Exception as e:
                        st.error(f"Failed to finalize I/A: {e}")
    else:
        st.info("No provisional I/A items pending review.")
    try:
        # Detect triggers
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Detect Triggers (auto)"):
                try:
                    created = reclassification_service.detect_triggers()
                    st.success(f"Created {created} reclassification trigger(s)")
                except Exception as e:
                    st.error(f"Trigger detection failed: {e}")
        with c2:
            st.caption("Auto-triggers: overdue classification, recent DDL changes")

        # Manual submission
        st.markdown("---")
        st.write("Submit a Reclassification Request")
        try:
            tables = snowflake_connector.execute_query(
                f"""
                SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS full_name
                FROM {_get_current_db()}.INFORMATION_SCHEMA.TABLES
                WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                ORDER BY "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"
                LIMIT 200
                """
            )
            asset_options = [t['FULL_NAME'] for t in tables] if tables else []
        except Exception:
            asset_options = []
        asset = st.selectbox("Asset", options=asset_options if asset_options else ["No assets available"], key="reclass_asset")
        colc, coli, cola = st.columns(3)
        with colc:
            pc = st.number_input("Proposed C", 0, 3, 1)
        with coli:
            pi = st.number_input("Proposed I", 0, 3, 1)
        with cola:
            pa = st.number_input("Proposed A", 0, 3, 1)
        pcls = st.selectbox("Proposed Classification", options=ALLOWED_CLASSIFICATIONS)
        impact = st.text_area("Impact Assessment & Stakeholders", placeholder="Describe business impact, stakeholders to notify, approvals required...")
        requester = st.text_input("Your email (requester)", key="reclass_requester")
        if st.button("Submit Request") and requester and asset and asset != "No assets available":
            try:
                rid = reclassification_service.submit_request(
                    asset,
                    (pcls, int(pc), int(pi), int(pa)),
                    impact or "Manual reclassification request",
                    requester,
                    trigger_type="MANUAL",
                )
                st.success(f"Submitted request {rid}")
            except Exception as e:
                st.error(f"Failed to submit request: {e}")

        # Approvals queue
        st.markdown("---")
        st.write("Approvals (Data Owners/Admins)")
        status = st.selectbox("Status filter", ["All", "Pending", "Approved", "Rejected"], index=1, key="reclass_status")
        limit = st.slider("Max rows", 10, 500, 100, 10, key="reclass_limit")
        if status == "All":
            rows = reclassification_service.list_requests(limit=limit)
        else:
            rows = reclassification_service.list_requests(status=status, limit=limit)
        if rows:
            df = pd.DataFrame(rows)
            show_cols = [
                "ID","ASSET_FULL_NAME","TRIGGER_TYPE","CURRENT_CLASSIFICATION","CURRENT_C","CURRENT_I","CURRENT_A",
                "PROPOSED_CLASSIFICATION","PROPOSED_C","PROPOSED_I","PROPOSED_A","STATUS","CREATED_BY","CREATED_AT"
            ]
            for c in show_cols:
                if c not in df.columns:
                    df[c] = None
            # Defensive CIA normalization for display
            for col in ["CURRENT_C","CURRENT_I","CURRENT_A","PROPOSED_C","PROPOSED_I","PROPOSED_A"]:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
            st.dataframe(df[show_cols], use_container_width=True)
            sel = st.selectbox("Select Request", options=[r.get("ID") for r in rows])
            approver = st.text_input("Your email (approver)", key="reclass_approver")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Approve & Apply", type="primary") and sel and approver:
                    try:
                        reclassification_service.approve(sel, approver)
                        st.success("Approved and applied tags.")
                    except Exception as e:
                        st.error(f"Approval failed: {e}")
            with c2:
                justification = st.text_input("Rejection justification", key="reclass_reject_just")
                if st.button("Reject") and sel and approver:
                    try:
                        reclassification_service.reject(sel, approver, justification)
                        st.success("Rejected request.")
                    except Exception as e:
                        st.error(f"Rejection failed: {e}")
        else:
            st.info("No requests found.")
    except Exception as e:
        st.warning(f"Reclassification module unavailable: {e}")

with tab5:
    st.subheader("History")
    st.write("View historical classifications and audit trail for a dataset.")
    # Select dataset
    try:
        tables = snowflake_connector.execute_query(
            f"""
            SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS full_name
            FROM {_get_current_db()}.INFORMATION_SCHEMA.TABLES
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            ORDER BY "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"
            LIMIT 200
            """
        )
        asset_options = [t['FULL_NAME'] for t in tables] if tables else []
    except Exception:
        asset_options = []
    hist_asset = st.selectbox("Select dataset", options=asset_options if asset_options else ["No assets available"], key="hist_asset")

    from src.services.audit_service import audit_service
    if hist_asset and hist_asset != "No assets available":
        # Show reclassification history
        try:
            reqs = reclassification_service.list_requests(limit=500)
            reqs_df = pd.DataFrame([r for r in reqs if r.get("ASSET_FULL_NAME") == hist_asset])
            if not reqs_df.empty:
                st.write("Reclassification Requests:")
                show_cols = [
                    "CREATED_AT","STATUS","TRIGGER_TYPE","CURRENT_CLASSIFICATION","CURRENT_C","CURRENT_I","CURRENT_A",
                    "PROPOSED_CLASSIFICATION","PROPOSED_C","PROPOSED_I","PROPOSED_A","CREATED_BY","APPROVED_BY","JUSTIFICATION"
                ]
                for c in show_cols:
                    if c not in reqs_df.columns:
                        reqs_df[c] = None
                # Defensive CIA normalization for display
                for col in ["CURRENT_C","CURRENT_I","CURRENT_A","PROPOSED_C","PROPOSED_I","PROPOSED_A"]:
                    if col in reqs_df.columns:
                        reqs_df[col] = pd.to_numeric(reqs_df[col], errors="coerce").fillna(0).astype(int)
                st.dataframe(reqs_df[show_cols], use_container_width=True)
                try:
                    req_csv = reqs_df[show_cols].to_csv(index=False).encode("utf-8")
                    st.download_button(
                        label="Download Requests (CSV)",
                        data=req_csv,
                        file_name="classification_history_requests.csv",
                        mime="text/csv",
                    )
                except Exception:
                    pass
            else:
                st.info("No reclassification requests found for this asset.")
        except Exception as e:
            st.warning(f"Failed to load reclassification history: {e}")

        # Show audit trail
        try:
            logs = audit_service.query(limit=500)
            logs_df = pd.DataFrame([l for l in (logs or []) if l.get("RESOURCE_ID") == hist_asset])
            if not logs_df.empty:
                st.write("Audit Trail:")
                log_cols = ["TIMESTAMP","USER_ID","ACTION","DETAILS"]
                for c in log_cols:
                    if c not in logs_df.columns:
                        logs_df[c] = None
                st.dataframe(logs_df[log_cols], use_container_width=True)
                try:
                    logs_csv = logs_df[log_cols].to_csv(index=False).encode("utf-8")
                    st.download_button(
                        label="Download Audit Logs (CSV)",
                        data=logs_csv,
                        file_name="classification_history_audit_logs.csv",
                        mime="text/csv",
                    )
                except Exception:
                    pass
            else:
                st.info("No audit logs for this asset.")
        except Exception as e:
            st.warning(f"Failed to load audit logs: {e}")