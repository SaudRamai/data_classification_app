"""
Classification Center - Centralized, policy-aligned implementation

Implements Avendra Data Classification Policy (AVD-DWH-DCLS-001)
- Section 5.2 CIA Scales (C0–C3, I0–I3, A0–A3)
- Section 5.3 Overall Risk Classification (risk mapping from CIA)
- Section 6.1 Guided Workflow (Steps 1–6)
- Section 6.2.2 Classification Matrix & Controls (validation)
- Section 7 Quality Assurance & Approvals (peer, management, technical)
- Section 8 SLA & Compliance Reporting (5 business days, coverage, overdue)

This module provides a single source of truth for the Classification Center UI and logic.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

import pandas as pd
import streamlit as st

# Ensure project root on path for `src.*` imports when running as a Streamlit page
_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))  # .../src
_project_root = os.path.dirname(_src_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Services (best-effort imports; UI guards against failures)
from src.connectors.snowflake_connector import snowflake_connector
from src.services.authorization_service import authz
from src.services.tagging_service import tagging_service
from src.services.reclassification_service import reclassification_service
from src.services.decision_matrix_service import validate as dm_validate
from src.services.audit_service import audit_service
from src.services.ai_classification_service import ai_classification_service
from src.services.classification_tasks_service import get_my_tasks
from src.services.classification_review_service import list_reviews
from src.services.review_actions_service import approve_review, reject_review, request_changes
from src.components.history_tab import render_history_tab
from src.services.classification_decision_service import classification_decision_service
try:
    from src.services.notifier_service import notifier_service
except Exception:  # optional notifications
    notifier_service = None

# Optional helpers
try:
    from src.services.discovery_service import discovery_service
except Exception:  # pragma: no cover - not critical for all flows
    discovery_service = None


@dataclass
class CIA:
    """Implements Section 5.2 CIA Scales: C0–C3, I0–I3, A0–A3."""
    c: int
    i: int
    a: int

    def normalized(self) -> Tuple[int, int, int]:
        return max(0, min(self.c, 3)), max(0, min(self.i, 3)), max(0, min(self.a, 3))

    def risk_level(self) -> str:
        """Implements Section 5.3 Overall Risk Classification.
        Highest-of-CIA dominates. Combination effects: any 3 => High; any 2s without 3 => Medium; else Low.
        """
        c, i, a = self.normalized()
        highest = max(c, i, a)
        if highest >= 3:
            return "High"
        if highest == 2:
            return "Medium"
        return "Low"


def _get_current_db() -> Optional[str]:
    try:
        db = st.session_state.get("sf_database")
        if not db:
            rows = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
            db = rows[0].get("DB") if rows else None
        return db
    except Exception:
        return None


def _list_tables(limit: int = 300) -> list[str]:
    """Best-effort read of tables for selection."""
    try:
        db = _get_current_db()
        if not db:
            return []
        rows = snowflake_connector.execute_query(
            f"""
            SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS FULL_NAME
            FROM {db}.INFORMATION_SCHEMA.TABLES
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            ORDER BY 1
            LIMIT {int(limit)}
            """
        ) or []
        return [r.get("FULL_NAME") for r in rows if r.get("FULL_NAME")]
    except Exception:
        return []


def _apply_tags(asset_full_name: str, cia: CIA, risk: str, who: str, rationale: str = "") -> None:
    """Apply standardized Snowflake tags (policy requirement) and record audit.
    Implements tagging using both policy-standard lowercase names and legacy uppercase names
    to maintain compatibility until all environments converge.
    """
    c, i, a = cia.normalized()
    tags_lower = {
        "data_classification": risk,  # Low/Medium/High risk per policy
        "confidentiality_level": str(c),
        "integrity_level": str(i),
        "availability_level": str(a),
    }
    tags_upper = {
        "DATA_CLASSIFICATION": risk,
        "CONFIDENTIALITY_LEVEL": str(c),
        "INTEGRITY_LEVEL": str(i),
        "AVAILABILITY_LEVEL": str(a),
    }
    # Privilege guard
    if not authz.can_apply_tags_for_object(asset_full_name, object_type="TABLE"):
        st.error("Insufficient privileges to apply tags (ALTER/OWNERSHIP required).")
        st.stop()
    # Apply both sets for forward/backward compatibility
    tagging_service.apply_tags_to_object(asset_full_name, "TABLE", tags_lower)
    tagging_service.apply_tags_to_object(asset_full_name, "TABLE", tags_upper)
    audit_service.log(who or "system", "CLASSIFY_APPLY", "ASSET", asset_full_name,
                      {"risk": risk, "c": c, "i": i, "a": a, "rationale": rationale})


def _sla_due(created_at: datetime, business_days: int = 5) -> datetime:
    """Compute SLA due date by adding business days (Mon-Fri). Implements Section 8."""
    days = 0
    cur = created_at
    while days < business_days:
        cur += timedelta(days=1)
        if cur.weekday() < 5:  # Mon-Fri
            days += 1
    return cur


def _coverage_and_overdue() -> tuple[pd.DataFrame, Dict[str, int]]:
    """Compliance reporting per Section 8: coverage %, overdue classifications, SLA checks."""
    db = _get_current_db()
    if not db:
        return pd.DataFrame(), {"total": 0, "classified": 0, "overdue": 0}
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT FULL_NAME, FIRST_DISCOVERED, CLASSIFIED, CIA_CONF, CIA_INT, CIA_AVAIL
            FROM {db}.DATA_GOVERNANCE.ASSET_INVENTORY
            ORDER BY COALESCE(FIRST_DISCOVERED, CURRENT_TIMESTAMP()) DESC
            LIMIT 5000
            """
        ) or []
        df = pd.DataFrame(rows)
        if not df.empty:
            df["FIRST_DISCOVERED_DT"] = pd.to_datetime(df.get("FIRST_DISCOVERED"))
            df["DUE_BY"] = df["FIRST_DISCOVERED_DT"].apply(lambda d: _sla_due(d) if pd.notnull(d) else pd.NaT)
            now = datetime.utcnow()
            df["OVERDUE"] = (~df["CLASSIFIED"].fillna(False)) & (pd.to_datetime(df["DUE_BY"]).dt.tz_localize(None) < now)
        total = int(len(df))
        classified = int(df["CLASSIFIED"].fillna(False).sum()) if not df.empty else 0
        overdue = int(df["OVERDUE"].sum()) if not df.empty and "OVERDUE" in df.columns else 0
        return df, {"total": total, "classified": classified, "overdue": overdue}
    except Exception:
        return pd.DataFrame(), {"total": 0, "classified": 0, "overdue": 0}


def _stepper_ui():
    """Renders the Guided Workflow (Steps 1–6). Implements Section 6.1."""
    st.subheader("Core Workflow (Classification Center)")

    # Step 0: Select Asset
    tables = _list_tables(limit=300)
    asset = st.selectbox("Select data asset", options=tables if tables else ["No assets available"], index=0)
    if not asset or asset == "No assets available":
        st.info("Select an asset to continue the workflow.")
        return

    st.markdown("---")
    st.markdown("### Step 1: Business Context Assessment")
    with st.expander("Business Context", expanded=True):
        purpose = st.text_area("Purpose of the data", placeholder="Describe business purpose and usage")
        value = st.text_area("Business value", placeholder="Describe value (e.g., supports reporting, critical ops)")
        stakeholders = st.text_input("Key stakeholders", placeholder="Owners, SMEs, consumers")
    # Policy quick reference & checklist (inline guidance)
    with st.expander("Policy Reference & Checklist", expanded=False):
        st.caption("See DATA_CLASSIFICATION_POLICY.md Sections 5.2, 5.3, 6.1 and Appendix B")
        st.markdown("- Ensure CIA are rated 0–3 based on impact\n- Special categories (PII, Financial, Regulatory) require minimum C-levels\n- Record a clear rationale and apply Snowflake tags")

    st.markdown("---")
    st.markdown("### Step 2: Confidentiality Assessment (C0–C3)")
    with st.expander("Confidentiality", expanded=True):
        c_q1 = st.selectbox("Would unauthorized disclosure cause harm?", ["No/Minimal", "Some", "Material", "Severe"], index=1)
        c_q2 = st.selectbox("Contains PII/financial/proprietary?", ["No", "Possible", "Likely", "Yes"], index=0)
        c_q3 = st.selectbox("Regulatory requirements present?", ["None", "Some", "Multiple", "Strict"], index=0)
        # Base C from questionnaire (0..3)
        c_val = max(["No/Minimal","Some","Material","Severe"].index(c_q1),
                    ["No","Possible","Likely","Yes"].index(c_q2),
                    ["None","Some","Multiple","Strict"].index(c_q3))
        # Enforce policy floors for special categories (Appendix 5.5)
        # Minimums: PII/Financial => at least C2; Regulatory "Strict" => C3; "Multiple" regs => at least C2.
        min_c = 0
        if c_q2 in ("Likely", "Yes"):
            min_c = max(min_c, 2)
        if c_q3 == "Multiple":
            min_c = max(min_c, 2)
        if c_q3 == "Strict":
            min_c = max(min_c, 3)
        if c_val < min_c:
            c_val = min_c
            st.warning("Policy floor applied: special category requires higher Confidentiality level.")
        st.caption(f"Selected Confidentiality level (with policy floor): C{c_val}")

    st.markdown("---")
    st.markdown("### Step 3: Integrity Assessment (I0–I3)")
    with st.expander("Integrity", expanded=True):
        i_q1 = st.selectbox("How critical is accuracy to operations?", ["Low", "Moderate", "High", "Critical"], index=1)
        i_q2 = st.selectbox("Impact if data is corrupted?", ["Minor", "Moderate", "Major", "Severe"], index=1)
        i_val = max(["Low","Moderate","High","Critical"].index(i_q1),
                    ["Minor","Moderate","Major","Severe"].index(i_q2))
        st.caption(f"Selected Integrity level: I{i_val}")

    st.markdown("---")
    st.markdown("### Step 4: Availability Assessment (A0–A3)")
    with st.expander("Availability", expanded=True):
        a_q1 = st.selectbox("How quickly must data be accessible?", ["Days+", "Hours", "< 1 hour", "Near-realtime"], index=1)
        a_q2 = st.selectbox("Impact if unavailable?", ["Minor", "Moderate", "Major", "Severe"], index=1)
        a_val = max(["Days+","Hours","< 1 hour","Near-realtime"].index(a_q1),
                    ["Minor","Moderate","Major","Severe"].index(a_q2))
        st.caption(f"Selected Availability level: A{a_val}")

    # Step 5: Overall Risk Classification
    st.markdown("---")
    st.markdown("### Step 5: Overall Risk Classification (Section 5.3)")
    cia = CIA(c=c_val, i=i_val, a=a_val)
    risk = cia.risk_level()
    # Provide special-category context to centralized validator
    cats = ["PII"] if c_q2 in ("Likely", "Yes") else []
    ok_dm, reasons = dm_validate(risk, cia.c, cia.i, cia.a, categories=cats, regulatory_level=c_q3)
    cols = st.columns(4)
    cols[0].metric("Confidentiality", f"C{cia.c}")
    cols[1].metric("Integrity", f"I{cia.i}")
    cols[2].metric("Availability", f"A{cia.a}")
    cols[3].metric("Risk", risk)
    if not ok_dm and reasons:
        for r in reasons:
            st.error(r)
        st.stop()

    # Step 6: Documentation & Approval
    st.markdown("---")
    st.markdown("### Step 6: Documentation & Approval")
    rationale = st.text_area("Rationale (required)", placeholder="Explain the decision per policy and context")
    user_email = st.text_input("Your email (for audit)")

    # Approval routing for High risk: peer review, management review, technical validation (Section 7)
    requires_approval = (risk == "High")
    col_apply, col_submit = st.columns(2)
    with col_submit:
        if st.button("Submit for Review/Approval", type="primary"):
            if not user_email:
                st.warning("Enter your email.")
                st.stop()
            if not rationale or not rationale.strip():
                st.warning("Rationale is required.")
                st.stop()
            rid = reclassification_service.submit_request(
                asset_full_name=asset,
                proposed=(risk, cia.c, cia.i, cia.a),
                justification=rationale,
                created_by=user_email,
                trigger_type="MANUAL_HIGH_RISK" if requires_approval else "MANUAL",
            )
            audit_service.log(user_email, "CLASSIFY_SUBMIT", "ASSET", asset,
                              {"risk": risk, "c": cia.c, "i": cia.i, "a": cia.a, "rationale": rationale, "request_id": rid})
            st.success(f"Submitted for {'approval' if requires_approval else 'review'}: {rid}")
    with col_apply:
        if st.button("Apply Classification Now"):
            if not user_email:
                st.warning("Enter your email.")
                st.stop()
            if not rationale or not rationale.strip():
                st.warning("Rationale is required.")
                st.stop()
            if requires_approval and not authz.can_approve_tags(authz.get_current_identity()):
                st.warning("High-risk requires approval; submitting request instead.")
                rid = reclassification_service.submit_request(
                    asset_full_name=asset,
                    proposed=(risk, cia.c, cia.i, cia.a),
                    justification=rationale,
                    created_by=user_email,
                    trigger_type="MANUAL_HIGH_RISK",
                )
                st.success(f"Submitted for approval: {rid}")
                st.stop()
            _apply_tags(asset, cia, risk, who=user_email, rationale=rationale)
            # Persist explicit decision record for consistent auditability
            try:
                classification_decision_service.record(
                    asset_full_name=asset,
                    decision_by=user_email,
                    source="GUIDED_WORKFLOW",
                    status="Applied",
                    label=risk,
                    c=int(cia.c), i=int(cia.i), a=int(cia.a),
                    rationale=rationale,
                    details={"source": "GuidedWorkflow"},
                )
            except Exception:
                pass
            st.success("Classification applied and audited.")


def _ai_assistance_panel():
    """AI Classification Assistant
    - Automated sensitive detection (tables/columns)
    - AI-suggested CIA at table/column level
    - Policy validation with badges and SLA indicators
    - Editable suggestions and apply/review with audit trail
    - Bulk actions
    """
    st.subheader("AI Classification Assistant")

    # Context
    db = _get_current_db()
    if not db:
        st.info("Select a database in Filters to begin.")
        return
    else:
        # Ensure Snowflake session context matches selected DB
        try:
            snowflake_connector.execute_non_query(f"USE DATABASE {db}")
        except Exception:
            pass

    # Controls
    col_l, col_r = st.columns([3, 1])
    with col_l:
        tables = _list_tables(limit=500)
        asset = st.selectbox("Dataset", options=tables if tables else ["No assets available"], index=0, key="ai_asset")
    with col_r:
        limit_tbls = st.slider("Scan limit", 10, 500, 100, 10, key="ai_scan_limit")

    st.markdown("---")
    st.markdown("### Sensitive Tables Overview")

    # Build sensitive table list with AI CIA and policy compliance
    # Pull Global Filters from session and apply to overview
    gf = {}
    try:
        gf = st.session_state.get("global_filters") or {}
    except Exception:
        gf = {}
    sel_schema = str(gf.get("schema") or "").strip()
    sel_table = str(gf.get("table") or "").strip()
    sel_schema_up = sel_schema.upper() if sel_schema and sel_schema != "All" else ""
    sel_table_up = sel_table.upper() if sel_table and sel_table != "All" else ""

    def _ci(row: dict, *keys: str):
        for k in keys:
            if k in row and row[k] is not None:
                return row[k]
        # try case-insensitive fallback
        lower_map = {str(k).lower(): v for k, v in row.items()}
        for k in keys:
            v = lower_map.get(str(k).lower())
            if v is not None:
                return v
        return None

    rows = []
    inv = []
    try:
        inv = snowflake_connector.execute_query(
            f"""
            SELECT FULL_NAME, COALESCE(ROW_COUNT,0) AS ROW_COUNT, FIRST_DISCOVERED, CLASSIFIED,
                   COALESCE(CIA_CONF,0) AS CIA_C, COALESCE(CIA_INT,0) AS CIA_I, COALESCE(CIA_AVAIL,0) AS CIA_A
            FROM {db}.DATA_GOVERNANCE.ASSET_INVENTORY
            ORDER BY COALESCE(ROW_COUNT,0) DESC
            LIMIT {int(limit_tbls)}
            """
        ) or []
    except Exception:
        inv = []
    # Show active scope for transparency
    scope_note = f"DB={db}"
    if sel_schema_up:
        scope_note += f", Schema={sel_schema_up}"
    if sel_table_up:
        scope_note += f", Table={sel_table_up}"
    st.caption(f"Active scope: {scope_note}")
    for r in inv:
        full = _ci(r, "FULL_NAME")
        # Detect categories quickly (best-effort)
        try:
            if not full:
                continue
            # Apply schema/table filters against FULL_NAME
            full_up = str(full).upper()
            if sel_schema_up and f".{sel_schema_up}." not in full_up:
                continue
            if sel_table_up and not full_up.endswith(f".{sel_table_up}"):
                continue
            det = ai_classification_service.detect_sensitive_columns(full, sample_size=30) or []
            cats = sorted({c for d in det for c in (d.get('categories') or [])})
        except Exception:
            cats = []
        # Normalize categories for display/policy
        allowed = {"PII", "Financial", "SOX"}
        out = []
        for c in cats:
            if c in allowed:
                out.append("SOC/SOX" if c == "SOX" else c)
        # AI CIA suggestion (table-level): use max of inventory CIA and suggestion by dominant type
        dominant = next((p for p in ["PCI","PHI","PII","Financial","Auth"] if p in cats), None)
        cia_sug = ai_classification_service._suggest_cia_from_type(dominant or "")
        try:
            c0 = int(_ci(r, "CIA_C") or 0)
            i0 = int(_ci(r, "CIA_I") or 0)
            a0 = int(_ci(r, "CIA_A") or 0)
        except Exception:
            c0 = i0 = a0 = 0
        c = max(c0, int(cia_sug.get("C", 0)))
        i = max(i0, int(cia_sug.get("I", 0)))
        a = max(a0, int(cia_sug.get("A", 0)))
        # Map to label via risk
        risk = CIA(c, i, a).risk_level()
        label = "Confidential" if c >= 3 else ("Restricted" if c >= 2 else ("Internal" if c >= 1 else "Public"))
        # SLA due and overdue
        fd = _ci(r, "FIRST_DISCOVERED")
        try:
            due = _sla_due(pd.to_datetime(fd).to_pydatetime()) if fd else None
        except Exception:
            due = None
        overdue = False
        try:
            classified = bool(_ci(r, "CLASSIFIED") or False)
            overdue = (not classified) and (due is not None) and (due < datetime.utcnow())
        except Exception:
            overdue = False
        rows.append({
            "Table Name": full,
            "Detected Types": ", ".join(sorted(out)) if out else "",
            "Row Count": int(_ci(r, "ROW_COUNT") or 0),
            "AI C": c, "AI I": i, "AI A": a,
            "Label": label, "Risk": risk,
            "SLA Due": due.strftime("%Y-%m-%d") if due else "",
            "Overdue": "Yes" if overdue else "No",
            "Classified": bool(_ci(r, "CLASSIFIED") or False),
        })

    if rows:
        df = pd.DataFrame(rows)
        # Allow users to restrict to sensitive-only
        only_sensitive = st.checkbox("Show only sensitive tables", value=True, key="ai_only_sensitive")
        if only_sensitive and not df.empty and "Detected Types" in df.columns:
            df = df[df["Detected Types"].astype(str).str.len() > 0]
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )
        st.caption("Badges: Overdue=Yes indicates violation of 5-business-day SLA if not yet classified.")
    else:
        # Fallback: build from INFORMATION_SCHEMA.TABLES when inventory is empty or filtered out
        try:
            where = []
            if sel_schema_up:
                where.append("TABLE_SCHEMA = %(s)s")
            if sel_table_up:
                where.append("TABLE_NAME = %(t)s")
            w = (" where " + " and ".join(where)) if where else ""
            params = {"s": sel_schema_up, "t": sel_table_up}
            alt = snowflake_connector.execute_query(
                f"""
                select TABLE_CATALOG as DB, TABLE_SCHEMA as SCH, TABLE_NAME as NAME, coalesce(ROW_COUNT,0) as ROW_COUNT
                from {db}.INFORMATION_SCHEMA.TABLES
                {w}
                order by ROW_COUNT desc
                limit {int(limit_tbls)}
                """,
                params if (sel_schema_up or sel_table_up) else None,
            ) or []
        except Exception:
            alt = []
        for r in alt:
            try:
                full = f"{r.get('DB')}.{r.get('SCH')}.{r.get('NAME')}"
                det = ai_classification_service.detect_sensitive_columns(full, sample_size=30) or []
                cats = sorted({c for d in det for c in (d.get('categories') or [])})
                allowed = {"PII", "Financial", "SOX"}
                out = ["SOC/SOX" if c == "SOX" else c for c in cats if c in allowed]
                dominant = next((p for p in ["PCI","PHI","PII","Financial","Auth"] if p in cats), None)
                cia_sug = ai_classification_service._suggest_cia_from_type(dominant or "")
                c = int(cia_sug.get("C", 0)); i = int(cia_sug.get("I", 0)); a = int(cia_sug.get("A", 0))
                risk = CIA(c, i, a).risk_level()
                label = "Confidential" if c >= 3 else ("Restricted" if c >= 2 else ("Internal" if c >= 1 else "Public"))
                rows.append({
                    "Table Name": full,
                    "Detected Types": ", ".join(sorted(out)) if out else "",
                    "Row Count": int(r.get("ROW_COUNT") or 0),
                    "AI C": c, "AI I": i, "AI A": a,
                    "Label": label, "Risk": risk,
                    "SLA Due": "",
                    "Overdue": "No",
                    "Classified": False,
                })
            except Exception:
                continue
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption("Showing INFORMATION_SCHEMA fallback because ASSET_INVENTORY had no rows for this scope.")
        else:
            st.info(f"No sensitive tables found for the selected scope in {db}. Consider widening filters or seeding ASSET_INVENTORY.")

    st.markdown("---")
    st.markdown("### Column-level Suggestions and Edits")
    if not asset or asset == "No assets available":
        return

    # Detect columns and build editable grid
    try:
        detections = ai_classification_service.detect_sensitive_columns(asset, sample_size=60) or []
    except Exception as e:
        detections = []
        st.warning(f"Column detection unavailable: {e}")

    # Prepare initial DF
    initial = []
    for d in detections:
        col = d.get("column")
        cats = d.get("categories") or []
        dominant = next((p for p in ["PCI","PHI","PII","Financial","Auth"] if p in cats), None)
        cia = ai_classification_service._suggest_cia_from_type(dominant or "")
        C, I, A = int(cia.get("C", 0)), int(cia.get("I", 0)), int(cia.get("A", 0))
        label = "Confidential" if C >= 3 else ("Restricted" if C >= 2 else ("Internal" if C >= 1 else "Public"))
        initial.append({
            "Column Name": col,
            "Sensitivity Types": ",".join(sorted(cats)) if cats else "",
            "Label": label,
            "C": C, "I": I, "A": A,
        })
    col_df = pd.DataFrame(initial)

    # Editable grid
    edited = st.data_editor(
        col_df if not col_df.empty else pd.DataFrame(columns=["Column Name","Sensitivity Types","Label","C","I","A"]),
        use_container_width=True,
        hide_index=True,
        num_rows="dynamic",
        column_config={
            "Column Name": st.column_config.TextColumn(disabled=True),
            "Sensitivity Types": st.column_config.TextColumn(disabled=True),
            "Label": st.column_config.SelectboxColumn(options=["Public","Internal","Restricted","Confidential"]),
            "C": st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
            "I": st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
            "A": st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
        },
        key=f"ai_cols_{asset}",
    )

    # Table-level derived suggestion (editable)
    if not edited.empty:
        tC, tI, tA = int(max(edited["C"].max(), 0)), int(max(edited["I"].max(), 0)), int(max(edited["A"].max(), 0))
    else:
        tC = tI = tA = 0
    tLabel = "Confidential" if tC >= 3 else ("Restricted" if tC >= 2 else ("Internal" if tC >= 1 else "Public") )
    st.markdown("**Table-level Classification (editable)**")
    table_init = pd.DataFrame([{ "Table Name": asset, "Label": tLabel, "C": tC, "I": tI, "A": tA }])
    table_edit = st.data_editor(
        table_init,
        use_container_width=True,
        hide_index=True,
        num_rows="fixed",
        column_config={
            "Table Name": st.column_config.TextColumn(disabled=True),
            "Label": st.column_config.SelectboxColumn(options=["Public","Internal","Restricted","Confidential"]),
            "C": st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
            "I": st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
            "A": st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
        },
        key=f"ai_tbl_{asset}"
    )
    try:
        tLabel = str(table_edit.iloc[0]['Label'])
        tC = int(table_edit.iloc[0]['C']); tI = int(table_edit.iloc[0]['I']); tA = int(table_edit.iloc[0]['A'])
    except Exception:
        pass

    # Policy validation badges
    val_issues = []
    try:
        tagging_service.validate_tags({
            'DATA_CLASSIFICATION': tLabel,
            'CONFIDENTIALITY_LEVEL': str(tC),
            'INTEGRITY_LEVEL': str(tI),
            'AVAILABILITY_LEVEL': str(tA),
        })
        tagging_service._enforce_policy_minimums(asset, {
            'DATA_CLASSIFICATION': tLabel,
            'CONFIDENTIALITY_LEVEL': str(tC),
        })
        st.success("Table classification passes policy validation.")
    except Exception as e:
        st.warning(f"Table policy: {e}")

    for _, row in edited.iterrows():
        try:
            tagging_service.validate_tags({
                'DATA_CLASSIFICATION': row['Label'],
                'CONFIDENTIALITY_LEVEL': str(int(row['C'])),
                'INTEGRITY_LEVEL': str(int(row['I'])),
                'AVAILABILITY_LEVEL': str(int(row['A'])),
            })
            tagging_service._enforce_policy_minimums(asset, {
                'DATA_CLASSIFICATION': row['Label'],
                'CONFIDENTIALITY_LEVEL': str(int(row['C'])),
            })
        except Exception as e:
            val_issues.append({ 'column': row['Column Name'], 'error': str(e) })
    if val_issues:
        st.error({'policy_issues': val_issues})
    else:
        st.info("All column suggestions meet minimum policy requirements.")

    # Decision support: rationale & business impact
    rationale = st.text_area("Rationale & Business Impact (for audit)", key=f"ai_rat_{asset}")
    user_id = str(st.session_state.get('user') or 'system')

    col_b1, col_b2, col_b3 = st.columns(3)
    with col_b1:
        if st.button("Apply classification and log", key=f"apply_{asset}"):
            apply_errors = []
            try:
                tagging_service.apply_tags_to_object(asset, "TABLE", {
                    'DATA_CLASSIFICATION': tLabel,
                    'CONFIDENTIALITY_LEVEL': str(tC),
                    'INTEGRITY_LEVEL': str(tI),
                    'AVAILABILITY_LEVEL': str(tA),
                })
                classification_decision_service.record(
                    asset_full_name=asset,
                    decision_by=user_id,
                    source="AI_ASSISTANT",
                    status="Applied",
                    label=tLabel,
                    c=int(tC), i=int(tI), a=int(tA),
                    rationale=rationale or "AI Assistant apply",
                    details={'source': 'AI Assistant'},
                )
                audit_service.log(user_id, "UI_APPLY", "ASSET", asset, { 'label': tLabel, 'C': tC, 'I': tI, 'A': tA })
            except Exception as e:
                apply_errors.append(f"TABLE: {e}")
            # Column tags
            for _, row in edited.iterrows():
                try:
                    tagging_service.apply_tags_to_column(asset, row['Column Name'], {
                        'DATA_CLASSIFICATION': row['Label'],
                        'CONFIDENTIALITY_LEVEL': str(int(row['C'])),
                        'INTEGRITY_LEVEL': str(int(row['I'])),
                        'AVAILABILITY_LEVEL': str(int(row['A'])),
                    })
                    classification_decision_service.record(
                        asset_full_name=f"{asset}.{row['Column Name']}",
                        decision_by=user_id,
                        source="AI_ASSISTANT",
                        status="Applied",
                        label=row['Label'],
                        c=int(row['C']), i=int(row['I']), a=int(row['A']),
                        rationale=rationale or "AI Assistant apply",
                        details={'source': 'AI Assistant'},
                    )
                    audit_service.log(user_id, "UI_APPLY", "COLUMN", f"{asset}.{row['Column Name']}", {
                        'label': row['Label'], 'C': int(row['C']), 'I': int(row['I']), 'A': int(row['A'])
                    })
                except Exception as e:
                    apply_errors.append(f"{row['Column Name']}: {e}")
            if apply_errors:
                st.error({'apply_errors': apply_errors})
            else:
                st.success("Classification applied and logged.")
    with col_b2:
        if st.button("Submit for review", key=f"review_{asset}"):
            try:
                reclassification_service.submit_request(
                    asset_full_name=asset,
                    proposed=(tLabel, int(tC), int(tI), int(tA)),
                    justification=rationale or "AI Assistant submission",
                    created_by=user_id,
                    trigger_type="AI_ASSISTANT",
                )
                audit_service.log(user_id, "CLASSIFY_SUBMIT", "ASSET", asset, { 'label': tLabel, 'C': tC, 'I': tI, 'A': tA })
                st.success("Submitted for review.")
            except Exception as e:
                st.error(f"Submit failed: {e}")
    with col_b3:
        if st.button("Notify (overdue/non-compliant)"):
            try:
                if notifier_service:
                    notifier_service.notify("Classification Alert", f"{asset} requires attention", recipients=None)
                audit_service.log(user_id, "CLASSIFY_NOTIFY", "ASSET", asset, { 'reason': 'overdue/non-compliant' })
                st.success("Notification recorded (audit).")
            except Exception as e:
                st.error(f"Notify failed: {e}")

    st.markdown("---")
    st.markdown("### Bulk Actions")
    multi = st.multiselect("Select assets to apply table-level label/CIA", options=[r["Table Name"] for r in rows] if rows else [], max_selections=50)
    if st.button("Apply to selected (table-level only)") and multi:
        ok = 0; errs = []
        for m in multi:
            try:
                tagging_service.apply_tags_to_object(m, "TABLE", {
                    'DATA_CLASSIFICATION': tLabel,
                    'CONFIDENTIALITY_LEVEL': str(tC),
                    'INTEGRITY_LEVEL': str(tI),
                    'AVAILABILITY_LEVEL': str(tA),
                })
                classification_decision_service.record(
                    asset_full_name=m,
                    decision_by=user_id,
                    source="AI_ASSISTANT_BULK",
                    status="Applied",
                    label=tLabel,
                    c=int(tC), i=int(tI), a=int(tA),
                    rationale=rationale or "AI Assistant bulk apply",
                    details={'source': 'AI Assistant'},
                )
                ok += 1
            except Exception as e:
                errs.append(f"{m}: {e}")
        st.success(f"Applied to {ok} asset(s). {len(errs)} error(s).")
        if errs:
            st.error("\n".join(errs[:50]))


def _bulk_classification_panel():
    """Bulk classification with validation reports and 5-business-day SLA reminder. Implements Section 6 (bulk) and Section 8."""
    st.subheader("Bulk Classification")
    st.caption("Upload CSV with columns: FULL_NAME, C, I, A; optional: RATIONALE")
    f = st.file_uploader("Upload template (CSV)", type=["csv"], key="bulk_csv_center")
    dry_run = st.checkbox("Dry run (validate only)", value=True)
    if not f:
        return
    try:
        df = pd.read_csv(f)
    except Exception as e:
        st.error(f"Failed to read CSV: {e}")
        return
    st.dataframe(df.head(20), use_container_width=True)

    missing = [c for c in ["FULL_NAME","C","I","A"] if c not in [x.upper() for x in df.columns]]
    if missing:
        st.error(f"Missing required columns: {', '.join(missing)}")
        return
    df.columns = [c.upper() for c in df.columns]

    errors = []
    processed = 0
    if st.button("Process Bulk", type="primary"):
        for _, row in df.iterrows():
            full = str(row.get("FULL_NAME",""))
            try:
                c = int(row.get("C")); i = int(row.get("I")); a = int(row.get("A"))
            except Exception:
                errors.append(f"{full}: C/I/A must be integers 0..3")
                continue
            if not (0 <= c <= 3 and 0 <= i <= 3 and 0 <= a <= 3):
                errors.append(f"{full}: C/I/A must be within 0..3")
                continue
            risk = CIA(c, i, a).risk_level()
            ok_dm, reasons = dm_validate(risk, c, i, a)
            if not ok_dm:
                errors.extend([f"{full}: {r}" for r in reasons or []])
                continue
            if dry_run:
                processed += 1
                continue
            # Apply tags using both lower/upper tag sets
            try:
                _apply_tags(full, CIA(c, i, a), risk, who=st.session_state.get("user") or "bulk@system", rationale=str(row.get("RATIONALE") or "Bulk classification"))
                processed += 1
            except Exception as e:
                errors.append(f"{full}: {e}")
        if dry_run:
            st.info(f"Dry run OK. {processed} row(s) validated. {len(errors)} error(s).")
        else:
            st.success(f"Processed {processed} row(s). {len(errors)} error(s).")
        if errors:
            st.error("\n".join(errors[:50]))
        st.caption("Reminder: Review all bulk-classified assets within 5 business days (SLA).")


def _management_panel():
    """Classification Management: tasks, pending reviews, reclassification, history & audit, tag ops."""
    st.subheader("Classification Management")
    tab_a, tab_b, tab_c, tab_d, tab_e = st.tabs([
        "My Tasks",
        "Pending Reviews",
        "History",
        "Reclassification Management",
        "Snowflake Tag Management",
    ]) 

    with tab_a:
        st.caption("My Classification Tasks — personal workbench for assignments")

        # Unified Tasks (Snowflake governance tables)
        with st.container():
            c1, c2, c3, c4, c5 = st.columns([1.4, 1.4, 1.4, 1.0, 1.2])
            with c1:
                f_assignment = st.selectbox(
                    "Assignment",
                    ["All", "Assigned to me", "Unassigned"],
                    index=0,
                    key="tasks2_assignment",
                )
            with c2:
                f_priority = st.selectbox(
                    "Priority",
                    ["All", "High", "Medium", "Low"],
                    index=0,
                    key="tasks2_priority",
                )
            with c3:
                f_type = st.selectbox(
                    "Task Type",
                    ["All", "Classification", "Reclassification", "Review"],
                    index=0,
                    key="tasks2_type",
                )
            with c4:
                f_due = st.selectbox(
                    "Due Date",
                    ["All", "Overdue", "This week", "Next week"],
                    index=0,
                    key="tasks2_due",
                )
            with c5:
                page_size = st.selectbox("Page Size", [25, 50, 100], index=1, key="tasks2_ps")

            # Resolve current user (for assignment logic)
            try:
                ident2 = authz.get_current_identity()
                me_user = (ident2.user or "").strip()
            except Exception:
                me_user = str(st.session_state.get("user") or "")

            page = st.number_input("Page", min_value=1, value=1, step=1, key="tasks2_page")
            with st.spinner("Loading tasks..."):
                data = get_my_tasks(
                    current_user=me_user,
                    assignment=f_assignment,
                    priority=f_priority,
                    task_type=f_type,
                    due_date=f_due,
                    page=int(page),
                    page_size=int(page_size),
                    database=st.session_state.get("sf_database"),
                )
            tasks = (data or {}).get("tasks", [])
            total = int((data or {}).get("total", 0))
            if not tasks:
                st.info("No tasks found for current filters.")
            else:
                import pandas as _pd
                df = _pd.DataFrame(tasks)
                # Map to display columns
                disp = df[[
                    "asset_name", "object_type", "database", "schema", "current_classification",
                    "due_date", "priority", "status", "assigned_to", "pii_detected", "risk_score", "task_type"
                ]].rename(columns={
                    "asset_name": "Asset",
                    "object_type": "Type",
                    "database": "Database",
                    "schema": "Schema",
                    "current_classification": "Classification",
                    "due_date": "Due Date",
                    "priority": "Priority",
                    "status": "Status",
                    "assigned_to": "Assigned To",
                    "pii_detected": "PII",
                    "risk_score": "Risk Score",
                    "task_type": "Task Type",
                })
                st.caption(f"Showing up to {len(disp)} of {total} tasks")
                st.dataframe(disp, use_container_width=True, hide_index=True)

        # Legacy My Tasks (kept under expander during migration)
        with st.expander("Legacy My Tasks (Inventory/Requests)", expanded=False):
            st.caption("Legacy task queue and wizard are available below during migration.")

        # Build task queue: unclassified assets + reclassification requests (legacy)
        def _load_task_queue(limit_assets: int = 500, limit_reqs: int = 300) -> pd.DataFrame:
            items = []
            # Unclassified assets (Initial Classification)
            try:
                db = _get_current_db()
                if db:
                    inv = snowflake_connector.execute_query(
                        f"""
                        SELECT FULL_NAME, OBJECT_DOMAIN, FIRST_DISCOVERED, CLASSIFIED
                        FROM {db}.DATA_GOVERNANCE.ASSET_INVENTORY
                        ORDER BY COALESCE(FIRST_DISCOVERED, CURRENT_TIMESTAMP()) DESC
                        LIMIT {int(limit_assets)}
                        """
                    ) or []
                    for r in inv:
                        full = r.get("FULL_NAME")
                        if not full:
                            continue
                        if bool(r.get("CLASSIFIED")):
                            continue
                        fd = pd.to_datetime(r.get("FIRST_DISCOVERED")) if r.get("FIRST_DISCOVERED") else None
                        due_by = _sla_due(fd.tz_localize(None) if isinstance(fd, pd.Timestamp) else datetime.utcnow()) if fd is not None else _sla_due(datetime.utcnow())
                        days_left = (due_by - datetime.utcnow()).days
                        priority = "High" if days_left < 0 else ("Medium" if days_left <= 2 else "Low")
                        items.append({
                            "Asset Name": full,
                            "Type": r.get("OBJECT_DOMAIN") or "TABLE",
                            "Due Date": due_by.date(),
                            "Priority": priority,
                            "Status": "New",
                            "Source": "Inventory",
                        })
            except Exception:
                pass
            # Reclassification requests
            try:
                reqs = reclassification_service.list_requests(limit=int(limit_reqs)) or []
                for r in reqs:
                    full = r.get("ASSET_FULL_NAME") or r.get("ASSET") or r.get("FULL_NAME")
                    if not full:
                        continue
                    created = pd.to_datetime(r.get("CREATED_AT") or r.get("CREATED"), errors='coerce')
                    due_by = _sla_due(created.to_pydatetime() if isinstance(created, pd.Timestamp) else datetime.utcnow()) if created is not None else _sla_due(datetime.utcnow())
                    days_left = (due_by - datetime.utcnow()).days
                    priority = "High" if days_left < 0 else ("Medium" if days_left <= 2 else "Low")
                    items.append({
                        "Asset Name": full,
                        "Type": r.get("OBJECT_TYPE") or "TABLE",
                        "Due Date": due_by.date(),
                        "Priority": priority,
                        "Status": r.get("STATUS") or r.get("state") or "In Progress",
                        "Source": "Reclassification",
                        "Request ID": r.get("ID"),
                        "CREATED_BY": r.get("CREATED_BY"),
                    })
            except Exception:
                pass
            return pd.DataFrame(items)

        # Filters — moved to sidebar
        with st.sidebar.expander("My Tasks filters", expanded=True):
            task_status = st.selectbox(
                "Task Status",
                options=["All", "New", "In Progress", "Awaiting Review", "Completed"],
                index=0,
                key="mytasks_status",
            )
            due_range = st.date_input(
                "Due Date range",
                value=[],
                key="mytasks_due_range",
                help="Select start and end dates to filter tasks by Due Date.",
            )
            priority_filter = st.multiselect(
                "Priority",
                options=["Critical", "High", "Normal"],
                default=[],
                key="mytasks_priority",
            )
            # Asset Type checkboxes (render from discovered types)
            df_preview = _load_task_queue().head(1)
            types = sorted(df_preview["Type"].unique().tolist()) if not df_preview.empty else ["TABLE"]
            st.caption("Asset Types")
            type_checks = {t: st.checkbox(t, value=True, key=f"mytasks_type_{t}") for t in types}
            # Business Unit filter (from inventory)
            try:
                db__ = _get_current_db()
                bu_rows__ = snowflake_connector.execute_query(
                    f"select distinct coalesce(BUSINESS_UNIT,'Unknown') as BU from {db__}.DATA_GOVERNANCE.ASSET_INVENTORY order by 1 limit 500"
                ) or [] if db__ else []
                bu_opts__ = [r.get("BU") for r in bu_rows__ if r.get("BU")]
            except Exception:
                bu_opts__ = []
            bu_filter = st.selectbox("Business Unit", options=["All"] + bu_opts__, index=0, key="mytasks_bu")
            # Data Owner filter (free text contains)
            owner_filter = st.text_input("Data Owner contains", value="", key="mytasks_owner")

        df = _load_task_queue()
        if not df.empty:
            me = (st.session_state.get("user") or str(authz.get_current_identity().user or "")).lower()
            now = datetime.utcnow()

            # Derivations for display and filtering
            def _priority_map(p):
                return "Critical" if str(p) == "High" else ("High" if str(p) == "Medium" else "Normal")

            def _assignment(row):
                cb = str(row.get("CREATED_BY") or "").lower()
                return "Assigned to me" if cb and me and cb == me else "Unassigned"

            df = df.copy()
            df["Priority2"] = df["Priority"].apply(_priority_map)
            df["Assignment"] = df.apply(_assignment, axis=1)

            # Enrich with Business Unit and Data Owner from inventory for filtering/display
            try:
                db__ = _get_current_db()
                if db__ and "Asset Name" in df.columns and not df["Asset Name"].empty:
                    names = [str(x) for x in df["Asset Name"].dropna().unique().tolist()]
                    if names:
                        # Chunk IN clause to avoid overly long lists
                        bu_map = {}
                        ow_map = {}
                        for i in range(0, len(names), 100):
                            chunk = names[i:i+100]
                            placeholders = ",".join([f"%(n{i+j})s" for j in range(len(chunk))])
                            params = {f"n{i+j}": chunk[j] for j in range(len(chunk))}
                            rows_en = snowflake_connector.execute_query(
                                f"""
                                select FULL_NAME, coalesce(BUSINESS_UNIT,'Unknown') as BU, coalesce(DATA_OWNER, OWNER, '') as OWNER
                                from {db__}.DATA_GOVERNANCE.ASSET_INVENTORY
                                where FULL_NAME in ({placeholders})
                                """,
                                params,
                            ) or []
                            for r in rows_en:
                                fu = r.get("FULL_NAME")
                                if fu:
                                    bu_map[fu] = r.get("BU")
                                    ow_map[fu] = r.get("OWNER")
                        df["Business Unit"] = df["Asset Name"].map(lambda x: bu_map.get(x))
                        df["Data Owner"] = df["Asset Name"].map(lambda x: ow_map.get(x))
            except Exception:
                df["Business Unit"] = None
                df["Data Owner"] = None

            # Apply filters
            if task_status != "All":
                # Normalize 'Awaiting Review' mapping for requests in Pending/Submitted states
                def _status_norm(s: str) -> str:
                    s0 = (s or "").strip().lower()
                    if any(k in s0 for k in ["pending", "await", "submitted", "review"]):
                        return "Awaiting Review"
                    if "complete" in s0 or "approved" in s0:
                        return "Completed"
                    if "progress" in s0:
                        return "In Progress"
                    return "New"
                df["StatusN"] = df["Status"].apply(_status_norm)
                df = df[df["StatusN"] == task_status]

            # Due date range filter
            if isinstance(due_range, (list, tuple)) and len(due_range) == 2:
                start, end = due_range
                try:
                    start_dt = pd.to_datetime(start)
                    end_dt = pd.to_datetime(end)
                    df = df[(pd.to_datetime(df["Due Date"]) >= start_dt) & (pd.to_datetime(df["Due Date"]) <= end_dt)]
                except Exception:
                    pass

            # Priority filter
            if priority_filter:
                df = df[df["Priority2"].isin(priority_filter)]

            # Asset Type checkboxes
            sel_types = [t for t, on in (type_checks or {}).items() if on]
            if sel_types:
                df = df[df["Type"].isin(sel_types)]

            # Business Unit filter
            if bu_filter and bu_filter != "All" and "Business Unit" in df.columns:
                df = df[df["Business Unit"] == bu_filter]

            # Data Owner filter (contains)
            if owner_filter and "Data Owner" in df.columns:
                df = df[df["Data Owner"].fillna("").str.contains(owner_filter, case=False, na=False)]

            # Render table with color-coded priority
            def _style_priority(val):
                v = str(val)
                color = "#ef4444" if v == "Critical" else ("#f59e0b" if v == "High" else "#10b981")
                return f"color: {color}; font-weight: 700;"
            st.dataframe(
                df[["Asset Name","Type","Business Unit","Data Owner","Due Date","Priority2","Status"]]
                  .rename(columns={"Priority2":"Priority"})
                  .style.applymap(_style_priority, subset=["Priority"]).hide(axis="index"),
                use_container_width=True,
            )

            # Quick actions
            sel_asset = st.selectbox("Select a task", options=df["Asset Name"].tolist(), key="mytasks_sel_asset")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Classify", type="primary", key="mytasks_btn_classify") and sel_asset:
                    st.session_state["task_wizard_asset"] = sel_asset
                    try:
                        st.experimental_set_query_params(sub="tasks", action="classify", asset=sel_asset)
                    except Exception:
                        pass
                    st.rerun()
            with c2:
                if st.button("View Details", key="mytasks_btn_view") and sel_asset:
                    st.info(f"Details for {sel_asset} coming soon. Request/Inventory drill-down will appear here.")
        else:
            st.info("No tasks found for the current context.")

        # Classification Wizard "modal" area
        try:
            q = st.experimental_get_query_params() or {}
        except Exception:
            q = {}
        action = (q.get("action") or [None])[0]
        asset_q = (q.get("asset") or [None])[0]
        target_asset = st.session_state.get("task_wizard_asset") or asset_q

        if action == "classify" or target_asset:
            st.markdown("---")
            st.subheader(f"Classification Wizard — {target_asset}")
            with st.form(key="mytasks_wizard_form", clear_on_submit=False):
                # Step 1: Business Context Assessment
                st.markdown("### Step 1: Business Context Assessment")
                st.text_input("Asset Name / ID", value=str(target_asset or ""), key="wiz3_asset_name", disabled=True)
                col_bc1, col_bc2 = st.columns(2)
                with col_bc1:
                    bc_bu = st.text_input("Business Unit or Department", key="wiz3_bu")
                with col_bc2:
                    bc_system = st.text_input("System or Application Name", key="wiz3_system")
                col_bc3, col_bc4 = st.columns(2)
                with col_bc3:
                    bc_owner = st.text_input("Owner / Data Steward", key="wiz3_owner")
                with col_bc4:
                    bc_short = st.text_area("Short description of the asset’s purpose", key="wiz3_short")

                # Fetch asset signals (optional helpers)
                pii_flag = False
                overdue_flag = False
                try:
                    db__ = _get_current_db()
                    if db__ and target_asset:
                        row__ = snowflake_connector.execute_query(
                            f"""
                            select PII_DETECTED, FIRST_DISCOVERED
                            from {db__}.DATA_GOVERNANCE.ASSET_INVENTORY
                            where FULL_NAME = %(f)s
                            limit 1
                            """,
                            {"f": target_asset},
                        ) or []
                        if row__:
                            pii_flag = bool(row__[0].get("PII_DETECTED"))
                            fd = pd.to_datetime(row__[0].get("FIRST_DISCOVERED"), errors='coerce')
                            if pd.notnull(fd):
                                overdue_flag = _sla_due(fd.to_pydatetime()) < datetime.utcnow()
                except Exception:
                    pass
                if overdue_flag:
                    st.warning("SLA: This asset is past the 5-business-day classification window.")

                # Step 2: Confidentiality Assessment (C0–C3)
                st.markdown("### Step 2: Confidentiality Assessment (C0–C3)")
                c_val = st.selectbox("Confidentiality level", options=["C0 Public","C1 Internal Use","C2 Sensitive","C3 Highly Sensitive / Confidential"], index=(2 if pii_flag else 1), key="wiz3_c")
                c_val = int(str(c_val)[1])

                # Step 3: Integrity Assessment (I0–I3)
                st.markdown("### Step 3: Integrity Assessment (I0–I3)")
                i_val = st.selectbox("Integrity requirement", options=["I0 Low","I1 Medium","I2 High","I3 Critical / Mandatory Accuracy"], index=1, key="wiz3_i")
                i_val = int(str(i_val)[1])

                # Step 4: Availability Assessment (A0–A3)
                st.markdown("### Step 4: Availability Assessment (A0–A3)")
                a_val = st.selectbox("Availability requirement", options=["A0 Low (non-critical)","A1 Medium","A2 High","A3 Always Available / Critical"], index=1, key="wiz3_a")
                a_val = int(str(a_val)[1])

                # Step 5: Overall Risk Classification
                st.markdown("### Step 5: Overall Risk Classification")
                cia = CIA(c=c_val, i=i_val, a=a_val)
                auto_risk = cia.risk_level()  # Low/Medium/High
                risk_override = st.selectbox("Overall Risk (auto-calculated; you may override)", options=[auto_risk, "Low", "Medium", "High"], index=0, key="wiz3_risk")
                # Derived label for tagging convenience (max-of-CIA)
                label = ["Public","Internal","Restricted","Confidential"][max(cia.c, cia.i, cia.a)]
                ok_dm, reasons = dm_validate(label, int(cia.c), int(cia.i), int(cia.a))
                cols = st.columns(4)
                cols[0].metric("Confidentiality", f"C{cia.c}")
                cols[1].metric("Integrity", f"I{cia.i}")
                cols[2].metric("Availability", f"A{cia.a}")
                cols[3].metric("Risk", risk_override)
                if not ok_dm and reasons:
                    for r in reasons:
                        st.error(r)
                requires_approval = (cia.c >= 3 or risk_override == "High")
                if requires_approval:
                    st.warning("Policy: High risk or C3 detected — review & approval required.")

                # Step 6: Documentation & Approval
                st.markdown("### Step 6: Documentation & Approval")
                rationale = st.text_area("Justification or rationale (required)", placeholder="Explain the decision per policy and context", key="wiz3_rationale")
                attachments = st.file_uploader("Attachments (optional)", accept_multiple_files=True, key="wiz3_files")
                user_email = st.text_input("Your email (for audit)", value=str(st.session_state.get("user") or ""), key="wiz3_email")
                suggest_users = st.session_state.get("directory_users", ["dcls.specialist@company.com", "data.owner@company.com"]) or []
                mentions = st.multiselect("@Mention specialists (optional)", options=suggest_users, default=[], key="wiz3_mentions")
                request_review = st.checkbox("Submit for approval (recommended for High risk)", value=requires_approval, key="wiz3_review")

                # Comment thread (session + audit)
                st.markdown("#### Comments")
                new_comment = st.text_input("Add a comment", key="wiz2_comment")
                if st.form_submit_button("Post Comment", help="Add to thread and audit") and new_comment:
                    try:
                        audit_service.log(st.session_state.get("user") or "wizard@system", "TASK_COMMENT", "ASSET", target_asset, {"comment": new_comment})
                    except Exception:
                        pass
                    cm = st.session_state.get("task_comments", {})
                    cm.setdefault(target_asset, []).append({"at": datetime.utcnow().isoformat(), "by": str(st.session_state.get("user") or "user"), "text": new_comment})
                    st.session_state["task_comments"] = cm
                # Render comments
                for c in (st.session_state.get("task_comments", {}).get(target_asset, []))[-10:]:
                    st.caption(f"{c.get('at')} — {c.get('by')}: {c.get('text')}")

                b1, b2, b3 = st.columns(3)
                with b1:
                    save_draft = st.form_submit_button("Save as Draft")
                with b2:
                    submit = st.form_submit_button("Submit", type="primary")
                with b3:
                    cancel = st.form_submit_button("Cancel")

            # Handle form actions
            if 'submit' in locals() and submit:
                if not rationale or not rationale.strip():
                    st.warning("Rationale is required.")
                else:
                    try:
                        rid = reclassification_service.submit_request(
                            asset_full_name=target_asset,
                            proposed=(label, int(cia.c), int(cia.i), int(cia.a)),
                            justification=f"{rationale} | Risk={risk_override}",
                            created_by=st.session_state.get("user") or "wizard@system",
                            trigger_type="MANUAL_REVIEW" if (request_review or requires_approval) else "MANUAL",
                        )
                        audit_service.log(st.session_state.get("user") or "wizard@system", "CLASSIFY_SUBMIT", "ASSET", target_asset, {"label": label, "risk": risk_override, "c": cia.c, "i": cia.i, "a": cia.a, "mentions": mentions, "request_review": (request_review or requires_approval), "request_id": rid, "business_unit": bc_bu, "system": bc_system, "owner": bc_owner, "description": bc_short})
                        st.success(f"Submitted classification for {target_asset}: {rid}")
                        st.session_state.pop("task_wizard_asset", None)
                        try:
                            st.experimental_set_query_params(sub="tasks")
                        except Exception:
                            pass
                    except Exception as e:
                        st.error(f"Submission failed: {e}")
            if 'save_draft' in locals() and save_draft:
                drafts = st.session_state.get("task_drafts", {})
                drafts[target_asset] = {
                    "label": label,
                    "risk": risk_override,
                    "c": int(cia.c), "i": int(cia.i), "a": int(cia.a),
                    "rationale": rationale, "mentions": mentions, "request_review": request_review,
                    "business_unit": bc_bu, "system": bc_system, "owner": bc_owner, "description": bc_short,
                    "saved_at": datetime.utcnow().isoformat(),
                }
                st.session_state["task_drafts"] = drafts
                try:
                    audit_service.log(st.session_state.get("user") or "wizard@system", "CLASSIFY_DRAFT_SAVE", "ASSET", target_asset, drafts[target_asset])
                except Exception:
                    pass
                st.success("Draft saved locally for this session.")
            if 'cancel' in locals() and cancel:
                st.session_state.pop("task_wizard_asset", None)
                try:
                    st.experimental_set_query_params(sub="tasks")
                except Exception:
                    pass

    with tab_b:
        st.caption("Pending Reviews: Peer, Management, Technical Validation")
        # Unified Review panel (CLASSIFICATION_HISTORY)
        r1, r2, r3, r4, r5 = st.columns([1.6, 1.6, 1.2, 1.0, 1.0])
        with r1:
            rev_filter = st.selectbox("Review Filter", ["All", "Pending approvals", "High-risk", "Recent changes"], index=0, key="rev2_filter")
        with r2:
            rev_status = st.selectbox("Approval Status", ["All pending", "Pending my approval"], index=0, key="rev2_status")
        with r3:
            lookback = st.number_input("Lookback (days)", min_value=1, value=30, step=1, key="rev2_lb")
        with r4:
            page = st.number_input("Page", min_value=1, value=1, step=1, key="rev2_page")
        with r5:
            page_size = st.selectbox("Page Size", [25, 50, 100], index=1, key="rev2_ps")

        # Additional interactive filters per requirements
        f1, f2, f3 = st.columns([1.6, 1.6, 1.6])
        with f1:
            filter_reviewer = st.text_input("Filter by Reviewer", key="rev2_reviewer")
        with f2:
            filter_level = st.selectbox("Classification Level", ["All", "Public", "Internal", "Restricted", "Confidential"], index=0, key="rev2_level")
        with f3:
            filter_status = st.selectbox("Status", ["All", "Pending", "Approved", "Rejected"], index=1, key="rev2_stat")

        try:
            ident_r = authz.get_current_identity()
            me_r = (ident_r.user or "").strip()
        except Exception:
            me_r = str(st.session_state.get("user") or "")

        with st.spinner("Loading reviews..."):
            res = list_reviews(
                current_user=me_r,
                review_filter=rev_filter,
                approval_status=rev_status,
                lookback_days=int(lookback),
                page=int(page),
                page_size=int(page_size),
                database=st.session_state.get("sf_database"),
            )
        items = (res or {}).get("reviews", [])
        total = int((res or {}).get("total", 0))
        if not items:
            st.info("No reviews found for current filters.")
        else:
            import pandas as _pd
            from datetime import datetime as _dt, timedelta as _td

            def _add_business_days(start: _dt, days: int = 5) -> _dt:
                d = start
                added = 0
                while added < days:
                    d += _td(days=1)
                    if d.weekday() < 5:
                        added += 1
                return d

            df = _pd.DataFrame(items)
            # Normalize/derive required display fields
            if "database" in df.columns and "schema" in df.columns and "asset_name" in df.columns:
                df["dataset"] = df["database"].fillna("") + "." + df["schema"].fillna("") + "." + df["asset_name"].fillna("")
            else:
                df["dataset"] = df.get("asset_name", "")
            df["c"] = _pd.to_numeric(df.get("c_level", 0), errors="coerce").fillna(0).astype(int)
            df["i"] = _pd.to_numeric(df.get("i_level", 0), errors="coerce").fillna(0).astype(int)
            df["a"] = _pd.to_numeric(df.get("a_level", 0), errors="coerce").fillna(0).astype(int)
            df["overall_classification"] = df.get("classification", "")
            # Reviewer: prefer APPROVED_BY, else CREATED_BY (submitter) — placeholder until dedicated reviewer column exists
            df["reviewer"] = df.get("approved_by").fillna("")
            df.loc[df["reviewer"].eq(""), "reviewer"] = df.get("created_by").fillna("")
            # Status mapping
            def _map_status(row):
                if bool(row.get("approval_required", False)) and not row.get("approved_by"):
                    return "Pending"
                if row.get("approved_by"):
                    return "Approved"
                return "Pending"
            df["status"] = df.apply(_map_status, axis=1)
            # Due date as 5 business days after change_timestamp
            try:
                ts = _pd.to_datetime(df.get("change_timestamp"), errors="coerce")
                df["due_date"] = ts.apply(lambda t: _add_business_days(t) if _pd.notnull(t) else _pd.NaT)
            except Exception:
                df["due_date"] = _pd.NaT

            # Client-side filters
            if filter_reviewer:
                df = df[df["reviewer"].str.contains(filter_reviewer, case=False, na=False)]
            if filter_level and filter_level != "All":
                df = df[df["overall_classification"].str.upper() == filter_level.upper()]
            if filter_status and filter_status != "All":
                df = df[df["status"].str.upper() == filter_status.upper()]

            # Display table with required columns
            disp_cols = [
                "dataset", "c", "i", "a", "overall_classification", "reviewer", "status", "due_date"
            ]
            cols_ren = {
                "dataset": "Dataset",
                "c": "C",
                "i": "I",
                "a": "A",
                "overall_classification": "Overall Classification",
                "reviewer": "Reviewer",
                "status": "Status",
                "due_date": "Due Date",
            }
            disp = df.reindex(columns=[c for c in disp_cols if c in df.columns]).rename(columns=cols_ren)
            st.caption(f"Showing {len(disp)} of {total} items")
            st.dataframe(disp, use_container_width=True, hide_index=True)

            # Selection and actions
            try:
                sel_idx = st.selectbox(
                    "Select a review item",
                    options=list(range(len(df))),
                    format_func=lambda i: f"{df.iloc[i]['dataset']} @ {df.iloc[i].get('due_date','')}" if not df.empty else str(i),
                )
            except Exception:
                sel_idx = None
            if sel_idx is not None and not df.empty:
                row = df.iloc[int(sel_idx)]
                asset_full = str(row.get("dataset") or row.get("asset_name") or "").strip()
                label = str(row.get("overall_classification") or row.get("classification") or "").strip()
                c_val = int(row.get("c") or 0)
                i_val = int(row.get("i") or 0)
                a_val = int(row.get("a") or 0)
                review_id = str(row.get("id") or "")

                st.markdown("### Actions")
                ac1, ac2, ac3 = st.columns(3)
                with ac1:
                    appr_by = st.text_input("Your email (approver)", value=me_r or "", key="rev_act_approver")
                    if st.button("Approve", key="rev_act_approve"):
                        ok = approve_review(review_id, asset_full, label, c_val, i_val, a_val, approver=appr_by, comments="Approved in Pending Reviews")
                        if ok:
                            st.success("Approved and recorded. (Snowflake DML placeholders are in review_actions_service.)")
                        else:
                            st.error("Approve action failed. See logs.")
                with ac2:
                    change_note = st.text_input("Change request note", key="rev_act_note")
                    if st.button("Request Changes", key="rev_act_reqchg"):
                        ok = request_changes(review_id, asset_full, approver=me_r, instructions=change_note)
                        if ok:
                            st.success("Change request recorded.")
                        else:
                            st.error("Request Changes failed.")
                with ac3:
                    rej_note = st.text_input("Rejection justification", key="rev_act_rej")
                    if st.button("Reject", key="rev_act_reject"):
                        ok = reject_review(review_id, asset_full, approver=me_r, justification=rej_note)
                        if ok:
                            st.success("Rejected.")
                        else:
                            st.error("Reject action failed.")

                # Comparison viewer
                st.markdown("### Comparison")
                ccur, cprop = st.columns(2)
                with ccur:
                    st.caption("Current (from inventory)")
                    try:
                        db = _get_current_db()
                        cur = snowflake_connector.execute_query(
                            f"""
                            /* TODO Snowflake: replace with your inventory source */
                            select FULL_NAME, CLASSIFIED, CIA_CONF, CIA_INT, CIA_AVAIL
                            from {db}.DATA_GOVERNANCE.ASSET_INVENTORY
                            where FULL_NAME = %(f)s
                            limit 1
                            """,
                            {"f": asset_full},
                        ) or [] if db else []
                        st.json(cur[0] if cur else {"FULL_NAME": asset_full})
                    except Exception as _e:
                        st.info("Current state unavailable.")
                with cprop:
                    st.caption("Proposed")
                    st.json({
                        "classification": label,
                        "c": c_val,
                        "i": i_val,
                        "a": a_val,
                        "reason": row.get("change_reason"),
                        "justification": row.get("business_justification"),
                    })

                # Consistency checker for similar assets (same schema/name pattern)
                st.markdown("### Consistency Checker")
                try:
                    db = _get_current_db()
                    if db and asset_full and asset_full.count(".") == 2:
                        _db, _sch, _tbl = asset_full.split(".")
                        rows_sim = snowflake_connector.execute_query(
                            f"""
                            /* TODO Snowflake: consider enriching this similarity query */
                            select FULL_NAME, CIA_CONF, CIA_INT, CIA_AVAIL
                            from {db}.DATA_GOVERNANCE.ASSET_INVENTORY
                            where TABLE_SCHEMA = %(s)s and lower(TABLE_NAME) like %(p)s
                            order by FULL_NAME
                            limit 50
                            """,
                            {"s": _sch, "p": f"%{_tbl.lower()}%"},
                        ) or []
                    else:
                        rows_sim = []
                    if rows_sim:
                        st.dataframe(_pd.DataFrame(rows_sim), use_container_width=True)
                    else:
                        st.caption("No similar assets found in inventory.")
                except Exception as _e:
                    st.caption("Similarity check unavailable.")

        # Legacy reclassification requests (reference)
        with st.expander("Legacy Pending Reviews (Requests)", expanded=False):
            try:
                rows = reclassification_service.list_requests(status="Pending", limit=200) or []
                df = pd.DataFrame(rows)
                if not df.empty:
                    df.rename(columns={"ASSET":"ASSET_FULL_NAME","FULL_NAME":"ASSET_FULL_NAME","CREATED":"CREATED_AT","CREATEDBY":"CREATED_BY"}, inplace=True)
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("No pending review requests.")
            except Exception as e:
                st.error(f"Failed to load legacy pending reviews: {e}")

    with tab_c:
        st.subheader("History")
        # Delegate to dedicated History sub-tab component for modularity
        # This component queries Snowflake CLASSIFICATION_AUDIT and falls back to mock data if unavailable.
        # Columns: Dataset, Previous CIA Scores, Current CIA Scores, Overall Risk, Approver Comments, Submission/Approval Dates
        # Filters: Date range, dataset name, classification level, owner. Sorting/searching included.
        render_history_tab(key_prefix="mgmt_hist")

    with tab_d:
        st.subheader("Reclassification Management")
        st.caption("Trigger alerts, analyze impact, run bulk operations, notify stakeholders")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### Trigger Reclassification Alert")
            asset = st.text_input("Asset (DATABASE.SCHEMA.OBJECT)", key="recl_asset")
            trig = st.selectbox("Trigger Type", ["REGULATORY","BUSINESS","INCIDENT","MANUAL"], index=0, key="recl_trig")
            just = st.text_area("Justification", key="recl_just")
            if st.button("Create Reclassification Request", key="recl_btn") and asset:
                try:
                    rid = reclassification_service.submit_request(
                        asset_full_name=asset,
                        proposed=("Review", None, None, None),
                        justification=just or f"Trigger: {trig}",
                        created_by=str(st.session_state.get("user") or "ops@system"),
                        trigger_type=trig,
                    )
                    st.success(f"Request submitted: {rid}")
                except Exception as e:
                    st.error(f"Failed to submit: {e}")
        with c2:
            st.markdown("#### Stakeholder Notifications")
            emails = st.text_input("Emails (comma-separated)", key="recl_emails")
            note = st.text_area("Message", key="recl_msg")
            if st.button("Notify Stakeholders", key="recl_notify"):
                try:
                    audit_service.log(str(st.session_state.get("user") or "ops@system"), "STAKEHOLDER_NOTIFY", "CLASSIFICATION", "bulk", {"emails": emails, "note": note})
                    st.success("Notification recorded (audit). Integrate with email/webhook service.")
                except Exception as e:
                    st.error(f"Notify failed: {e}")

        st.markdown("---")
        st.markdown("#### Bulk Reclassification (IDs)")
        f = st.file_uploader("Upload CSV with column ASSET_FULL_NAME", type=["csv"], key="recl_bulk")
        if f is not None:
            try:
                bdf = pd.read_csv(f)
                st.dataframe(bdf.head(20), use_container_width=True)
                if st.button("Submit Bulk Requests", key="recl_bulk_btn"):
                    ok = 0; errs = []
                    for _, r in bdf.iterrows():
                        full = str(r.get("ASSET_FULL_NAME") or "").strip()
                        if not full:
                            continue
                        try:
                            reclassification_service.submit_request(
                                asset_full_name=full,
                                proposed=("Review", None, None, None),
                                justification=str(r.get("JUSTIFICATION") or "Bulk reclassification"),
                                created_by=str(st.session_state.get("user") or "ops@system"),
                                trigger_type=str(r.get("TRIGGER") or "BULK"),
                            )
                            ok += 1
                        except Exception as e:
                            errs.append(f"{full}: {e}")
                    st.success(f"Submitted {ok} request(s). {len(errs)} error(s).")
                    if errs:
                        st.error("\n".join(errs[:50]))
            except Exception as e:
                st.error(f"Bulk file read failed: {e}")

    with tab_e:
        st.subheader("Snowflake Tag Management")
        st.caption("Tag sync status, drift detection, tag operations console")
        db = _get_current_db()
        c1, c2, c3 = st.columns(3)
        # Tag sync status
        try:
            tr = snowflake_connector.execute_query(
                """
                select coalesce(TAG_NAME,'') as TAG_NAME, count(*) as CNT
                from SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                group by 1
                order by CNT desc
                limit 20
                """
            ) or []
            c1.metric("Tracked Tags", f"{len(tr)}")
        except Exception:
            tr = []
            c1.metric("Tracked Tags", "-")
        # Drift detection (mismatches & orphans) — best effort vs inventory
        try:
            inv = snowflake_connector.execute_query(
                f"""
                select count(*) as TOTAL, sum(case when CLASSIFIED then 1 else 0 end) as CLASSIFIED_CNT
                from {db}.DATA_GOVERNANCE.ASSET_INVENTORY
                """
            ) or [] if db else []
            total = int(inv[0].get("TOTAL",0)) if inv else 0
            classified = int(inv[0].get("CLASSIFIED_CNT",0)) if inv else 0
        except Exception:
            total, classified = 0, 0
        try:
            # Count DATA_CLASSIFICATION tag references as proxy for sync
            tag_refs = snowflake_connector.execute_query(
                """
                select count(*) as CNT
                from SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                where upper(TAG_NAME) in ('DATA_CLASSIFICATION','CONFIDENTIALITY_LEVEL','INTEGRITY_LEVEL','AVAILABILITY_LEVEL')
                """
            ) or []
            tag_cnt = int(tag_refs[0].get("CNT",0)) if tag_refs else 0
        except Exception:
            tag_cnt = 0
        c2.metric("Inventory Classified", f"{classified} / {total}")
        c3.metric("Tag Refs (core)", f"{tag_cnt}")

        st.markdown("---")
        st.markdown("#### Tag Operations Console")
        colx, coly, colz = st.columns(3)
        with colx:
            if st.button("Validate Tags"):
                try:
                    audit_service.log(str(st.session_state.get("user") or "tags@system"), "TAGS_VALIDATE", "GLOBAL", "*", {})
                    st.success("Validation recorded (audit).")
                except Exception as e:
                    st.error(f"Validate failed: {e}")
        with coly:
            if st.button("Retry Failed Ops"):
                try:
                    audit_service.log(str(st.session_state.get("user") or "tags@system"), "TAGS_RETRY", "GLOBAL", "*", {})
                    st.success("Retry recorded (audit).")
                except Exception as e:
                    st.error(f"Retry failed: {e}")
        with colz:
            if st.button("Cleanup Orphans"):
                try:
                    audit_service.log(str(st.session_state.get("user") or "tags@system"), "TAGS_CLEANUP", "GLOBAL", "*", {})
                    st.success("Cleanup recorded (audit).")
                except Exception as e:
                    st.error(f"Cleanup failed: {e}")


def _compliance_panel():
    st.subheader("Compliance & QA")
    df, metrics = _coverage_and_overdue()
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Assets", metrics.get("total", 0))
    c2.metric("Classified", metrics.get("classified", 0))
    c3.metric("Overdue (SLA 5d)", metrics.get("overdue", 0))
    if not df.empty:
        st.dataframe(df[[c for c in ["FULL_NAME","FIRST_DISCOVERED","CLASSIFIED","CIA_CONF","CIA_INT","CIA_AVAIL","DUE_BY","OVERDUE"] if c in df.columns]], use_container_width=True)


def render():
    """Entry point called by `3_Classification.py`. Renders a tabbed policy-aligned center."""
    # Authorization guard
    ident = authz.get_current_identity()
    st.caption(f"Signed in as: {ident.user or 'Unknown'} | Role: {ident.current_role or 'Unknown'}")
    if not authz.can_access_classification(ident):
        st.error("You do not have permission to access the Classification Center.")
        st.stop()

    # Global filters (Database, Schema)
    with st.expander("filters", expanded=True):
        cur_db = st.session_state.get("sf_database") or _get_current_db()
        st.caption(f"Current Database: {cur_db or 'None'}")
        # Database selector
        try:
            db_rows = snowflake_connector.execute_query(
                """
                SELECT DATABASE_NAME AS NAME
                FROM SNOWFLAKE.ACCOUNT_USAGE.DATABASES
                WHERE DELETED IS NULL OR DELETED = FALSE
                ORDER BY NAME
                LIMIT 200
                """
            ) or []
            db_options = [r.get("NAME") for r in db_rows if r.get("NAME")]
        except Exception:
            db_options = []
        col_db, col_sc, col_btn = st.columns([2, 2, 1])
        with col_db:
            sel_db = st.selectbox("Database", options=db_options or [], index=(db_options.index(cur_db) if cur_db in db_options else 0 if db_options else None), key="cc_pick_db")
        # Schema selector (depends on database)
        schemas = []
        if sel_db:
            try:
                sch_rows = snowflake_connector.execute_query(
                    f"SELECT SCHEMA_NAME AS NAME FROM {sel_db}.INFORMATION_SCHEMA.SCHEMATA ORDER BY NAME LIMIT 500"
                ) or []
                schemas = [r.get("NAME") for r in sch_rows if r.get("NAME")]
            except Exception:
                schemas = []
        with col_sc:
            sel_schema = st.selectbox("Schema", options=schemas or [], index=0 if schemas else None, key="cc_pick_schema")
        with col_btn:
            if st.button("Set Context", key="cc_ctx_set"):
                if sel_db:
                    st.session_state["sf_database"] = sel_db
                if sel_schema:
                    st.session_state["sf_schema"] = sel_schema
                try:
                    st.experimental_rerun()
                except Exception:
                    st.toast("Context updated. Please reload the page.")

    # Feature flag to disable Bulk Classification (revert to pre-bulk state)
    BULK_CLASSIFICATION_ENABLED = False

    if BULK_CLASSIFICATION_ENABLED:
        tab1, tab2, tab3, tab4 = st.tabs([
            "Guided Workflow",
            "AI Assistance",
            "Bulk Classification",
            "Classification Management",
        ])
    else:
        tab1, tab2, tab4 = st.tabs([
            "Guided Workflow",
            "AI Assistance",
            "Classification Management",
        ])

    with tab1:
        _stepper_ui()
    with tab2:
        _ai_assistance_panel()
    if 'tab3' in locals() and BULK_CLASSIFICATION_ENABLED:
        with tab3:
            _bulk_classification_panel()
    with tab4:
        _management_panel()
        st.markdown("---")
        _compliance_panel()
