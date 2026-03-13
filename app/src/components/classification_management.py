"""
Classification Management - Manual Approval Functions
Provides manual approval interface for classifications based on asset names
"""

import streamlit as st
import pandas as pd
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
import time

from src.services.classification_workflow_service import classification_workflow_service
from src.services.compliance_service import compliance_service
from src.services.tagging_service import tagging_service
from src.connectors.snowflake_connector import snowflake_connector
# from src.services.classification_pipeline_service import discovery_service

def _suggest_min_label(c: int, i: int, a: int) -> str:
    """Determine the minimum classification label based on CIA scores."""
    highest = max(int(c or 0), int(i or 0), int(a or 0))
    if highest >= 3: return "Confidential"
    if highest == 2: return "Restricted"
    if highest == 1: return "Internal"
    return "Public"

def render_unified_task_action_panel(asset_name, c_init, i_init, a_init, status, user, task_id=None, priority=None, completion=None, database=None, key_prefix=""):
    """
    Unified task review and action interface for manual approval and tagging.
    Ensures a consistent experience across My Tasks, Guided Workflow, and Bulk Upload.
    """
    st.markdown("### ⚡ Task Review & Action")
    st.caption("Review details and perform manual approval, adjustments, or tagging trigger.")
    
    # Layout for Review
    rev_left, rev_right = st.columns([3, 2])
    
    # Deterministic key generation using key_prefix instead of timestamp
    # This ensures button state is preserved across re-runs
    idx_key = f"{key_prefix}_{task_id or asset_name}".replace(".", "_")

    with rev_left:
        st.markdown(f"#### Asset: `{asset_name}`")
        st.info(f"**Status:** {status} | **Priority:** {priority or 'Normal'} | **Completion:** {completion or 'N/A'}")
        
        # Manual Override & Tagging Inputs
        st.markdown("**Core Classification Tags**")
        st.caption("Surface classification and compliance tags directly for application.")
        
        # Suggested logic for pre-fill
        try:
            c_val_init = int(str(c_init or "1").replace("C","").replace("c",""))
            i_val_init = int(str(i_init or "1").replace("I","").replace("i",""))
            a_val_init = int(str(a_init or "1").replace("A","").replace("a",""))
        except Exception:
            c_val_init, i_val_init, a_val_init = 1, 1, 1

        suggested_label = _suggest_min_label(c_val_init, i_val_init, a_val_init)
        
        # 1. Classification Level & CIA Grid
        m_lab, m1, m2, m3 = st.columns([2, 1, 1, 1])
        with m_lab:
            labels = ["Public", "Internal", "Restricted", "Confidential"]
            cl_idx = labels.index(suggested_label) if suggested_label in labels else 1
            t_label = st.selectbox("Level", labels, index=cl_idx, key=f"ua_label_{idx_key}")
        with m1:
            c_val = st.number_input("C", 0, 3, c_val_init, key=f"ua_c_{idx_key}")
        with m2:
            i_val = st.number_input("I", 0, 3, i_val_init, key=f"ua_i_{idx_key}")
        with m3:
            a_val = st.number_input("A", 0, 3, a_val_init, key=f"ua_a_{idx_key}")
        
        # 2. Compliance Frameworks
        from src.services.tagging_service import TAG_DEFINITIONS
        try:
            from src.services.classification_pipeline_service import ai_classification_service

            _detected = []
            _compliance_detected = []

            try:
                parts = str(asset_name).split('.')
                if len(parts) == 3:
                    _db, _sc, _tb = parts
                elif len(parts) == 2:
                    _db = database or "DATA_CLASSIFICATION_DB"
                    _sc, _tb = parts
                else:
                    _db = database or "DATA_CLASSIFICATION_DB"
                    _sc = "PUBLIC"
                    _tb = asset_name

                _res = ai_classification_service.get_bulk_suggestions(_db, _sc, _tb)

                for _col in _res.get('column_results', []):
                    _detected.extend(_col.get('categories', []))

                _comp_str = str(_res.get('Compliance') or 'NONE').upper()
                if _comp_str not in ('NONE', 'NORMAL', 'UNKNOWN', 'NAN'):
                    _compliance_detected = [f.strip() for f in _comp_str.split(',') if f.strip()]
            except Exception as _e_pipe:
                logger.warning(f"AI Pipeline suggestion failed for {asset_name}: {_e_pipe}")

            _detected_up = [str(x).upper() for x in _detected]
            _fw_opts = TAG_DEFINITIONS.get("COMPLIANCE_FRAMEWORKS", ["PII", "SOX", "SOC"])

            _def_fw = []
            for _f in _compliance_detected:
                if _f in _fw_opts:
                    _def_fw.append(_f)
                elif _f == 'SOC2' and 'SOC' in _fw_opts:
                    _def_fw.append('SOC')

            if any(k in _detected_up for k in ["PII", "PERSONAL", "PHI", "HIPAA", "PCI",
                                                "EMAIL", "PHONE", "SSN", "PASSPORT", "DOB",
                                                "ADDRESS", "EMPLOYEE", "CUSTOMER", "NATIONAL_ID"]):
                if "PII" in _fw_opts and "PII" not in _def_fw: _def_fw.append("PII")
            if any(k in _detected_up for k in ["SOX", "FINANCIAL", "PAYROLL", "GL",
                                                "LEDGER", "REVENUE", "AUDIT", "INCOME"]):
                if "SOX" in _fw_opts and "SOX" not in _def_fw: _def_fw.append("SOX")
            if any(k in _detected_up for k in ["SOC", "SOC2", "REGULATORY"]):
                if "SOC" in _fw_opts and "SOC" not in _def_fw: _def_fw.append("SOC")

            # Signal 2: asset name heuristics
            _name_up = str(asset_name or "").upper()
            _name_fw_map = {
                "PII": ["PII","SSN","EMAIL","PHONE","ADDRESS","DOB","PERSON",
                        "EMPLOYEE","CUSTOMER","PASSPORT","AADHAAR","PAN",
                        "BIOMETRIC","VOTER_ID","DRIVER","NATIONAL_ID"],
                "SOX": ["SOX","GL","LEDGER","PAYROLL","REVENUE","EXPENSE",
                        "FINANCIAL","GAAP","IFRS","AUDIT","INCOME",
                        "BALANCE_SHEET","EARNINGS"],
                "SOC": ["SOC","SOC2","SOC1","SECURITY_AUDIT","SYSTEM_CONTROL"],
            }
            for _fw, _keys in _name_fw_map.items():
                if _fw in _fw_opts and any(_k in _name_up for _k in _keys):
                    if _fw not in _def_fw:
                        _def_fw.append(_fw)

            _def_fw = sorted(set([f for f in _def_fw if f in _fw_opts]))

            # Dynamic key per asset — resets when a different asset is selected
            _fw_widget_key = f"ua_compliance__{hash(str(asset_name))}"
            # Seed if: first render, OR previously cached as empty but we now have detections
            if _fw_widget_key not in st.session_state or \
                    (not st.session_state[_fw_widget_key] and _def_fw):
                st.session_state[_fw_widget_key] = _def_fw

            # Auto-detected badges
            if _def_fw:
                _badge_html = " ".join(
                    f'<span style="background:#1e3a5f;color:#38bdf8;padding:1px 8px;'
                    f'border-radius:10px;font-size:0.78rem;font-weight:700;'
                    f'margin-right:3px;">🔍 {_fw}</span>'
                    for _fw in _def_fw
                )
                st.markdown(
                    f'<div style="margin-bottom:4px;font-size:0.78rem;'
                    f'color:rgba(255,255,255,0.5);">Auto-detected:&nbsp;{_badge_html}</div>',
                    unsafe_allow_html=True,
                )

            compliance_frameworks = st.multiselect(
                "Compliance Frameworks",
                options=_fw_opts,
                help="Auto-suggested from AI detection & asset name. Adjust freely.",
                key=_fw_widget_key,
            )
        except Exception as _e_ui:
            compliance_frameworks = st.multiselect("Compliance Frameworks", ["PII", "SOX", "SOC"], key=f"ua_compliance_{idx_key}")
            st.error(f"UI Error: {_e_ui}")
        
        mt_comment = st.text_area("Review Comments / Rationale", placeholder="Add rationale for manual approval/tagging...", key=f"ua_comment_{idx_key}")

    with rev_right:
        st.markdown("#### ⚡ Next Actions")
        st.write("")  # Spacer

        # 1. Classify / Approve
        approve_mode_key = f"approve_mode_{idx_key}"

        if st.button("✅ Classify / Approve", type="primary", width='stretch',
                     help="Approve the proposed classification or assign a new level",
                     key=f"ua_btn_approve_main_{idx_key}"):
            st.session_state[approve_mode_key] = True
            st.rerun()

        if st.session_state.get(approve_mode_key, False):
            st.markdown("---")
            st.markdown("**🔍 Classification Preview**")
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Classification Level", t_label)
                st.metric("Confidentiality", f"C{c_val}")
            with col2:
                st.metric("Integrity", f"I{i_val}")
                st.metric("Availability", f"A{a_val}")

            if compliance_frameworks:
                st.markdown("**Compliance Impact**")
                for framework in compliance_frameworks:
                    st.markdown(f"- {framework}")

            st.markdown("---")
            approval_msg = st.text_area("Approval Note", value=mt_comment,
                                        placeholder="Enter any specific approval notes...",
                                        key=f"app_msg_{idx_key}")

            c1, c2 = st.columns([1, 1])
            with c1:
                if st.button("Confirm Approval", type="primary", key=f"confirm_approve_{idx_key}"):
                    try:
                        tags_to_apply = {
                            "DATA_CLASSIFICATION": t_label,
                            "CONFIDENTIALITY_LEVEL": f"C{c_val}",
                            "INTEGRITY_LEVEL": f"I{i_val}",
                            "AVAILABILITY_LEVEL": f"A{a_val}",
                            "LAST_CLASSIFIED_BY": user,
                            "LAST_CLASSIFIED_AT": datetime.now().isoformat(),
                            "COMPLIANCE_FRAMEWORKS": ",".join(compliance_frameworks) if compliance_frameworks else "",
                        }
                        ok = classification_workflow_service.update_or_submit_task(
                            asset_full_name=asset_name,
                            c=c_val, i=i_val, a=a_val,
                            label=t_label,
                            action="submit",
                            comments=approval_msg or "Classified & Approved",
                            user=user,
                            database=database,
                            details={"compliance": compliance_frameworks}
                        )
                        if ok:
                            try:
                                tagging_service.apply_tags_to_object(asset_name, "TABLE", tags_to_apply)
                                
                                # Use the singleton from classification_pipeline_service
                                # The shadowing at the source has been fixed
                                from src.services.classification_pipeline_service import discovery_service
                                if hasattr(discovery_service, "mark_classified"):
                                    discovery_service.mark_classified(
                                        asset_name, t_label, c_val, i_val, a_val,
                                        compliance_frameworks=compliance_frameworks
                                    )
                                else:
                                    logger.warning(f"discovery_service ({type(discovery_service).__name__}) missing mark_classified method. Skipping inventory update.")
                                
                                msg = f"✅ {asset_name} Approved & Classified"
                                icon = "✅"
                                st.toast(msg, icon=icon)
                                st.session_state["flash_toast"] = msg
                                st.session_state["flash_icon"] = icon
                                st.session_state[approve_mode_key] = False
                                st.balloons()
                                time.sleep(1.5)
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error applying tags: {e}")
                                st.toast(f"❌ Error applying tags: {e}", icon="🚨")
                    except Exception as e:
                        st.error(f"Error during approval: {e}")
                        st.toast(f"❌ Error during approval: {e}", icon="🚨")
            with c2:
                if st.button("Cancel", key=f"cancel_approve_{idx_key}"):
                    st.session_state[approve_mode_key] = False
                    st.rerun()

        # 2. Reject / Escalate
        st.markdown("---")
        col_rej, col_esc = st.columns(2)
        with col_rej:
            if st.button("🚫 Reject", width='stretch', key=f"ua_btn_reject_{idx_key}"):
                classification_workflow_service.update_or_submit_task(
                    asset_full_name=asset_name, c=c_val, i=i_val, a=a_val, label=t_label,
                    action="reject", comments=mt_comment or "Rejected", user=user, database=database
                )
                msg = "Task Rejected."
                icon = "🚫"
                st.toast(msg, icon=icon)
                st.session_state["flash_toast"] = msg
                st.session_state["flash_icon"] = icon
                time.sleep(0.5)
                st.rerun()
        with col_esc:
            if st.button("⚠️ Escalate", width='stretch', key=f"ua_btn_escalate_{idx_key}"):
                classification_workflow_service.update_or_submit_task(
                    asset_full_name=asset_name, c=c_val, i=i_val, a=a_val, label=t_label,
                    action="escalate", comments=mt_comment or "Escalated for further review",
                    user=user, database=database
                )
                msg = "Task Escalated."
                icon = "⚠️"
                st.toast(msg, icon=icon)
                st.session_state["flash_toast"] = msg
                st.session_state["flash_icon"] = icon
                time.sleep(0.5)
                st.rerun()















    
    # Color coding based on urgency



