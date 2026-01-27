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
from src.services.classification_pipeline_service import discovery_service

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
        
        # 2. Compliance Frameworks & Comments
        compliance_frameworks = st.multiselect(
            "Compliance Frameworks", 
            ["PII", "SOX", "SOC"],
            key=f"ua_compliance_{idx_key}"
        )
        
        mt_comment = st.text_area("Review Comments / Rationale", placeholder="Add rationale for manual approval/tagging...", key=f"ua_comment_{idx_key}")

    with rev_right:
        st.markdown("#### ⚡ Next Actions")
        st.write("") # Spacer
        
        # 1. Review (Start/Mark In Review)
        if st.button("👀 Review", use_container_width=True, help="Examine details and mark as In Review", key=f"ua_btn_review_{idx_key}"):
             try:
                ok = classification_workflow_service.update_or_submit_task(
                    asset_full_name=asset_name,
                    c=c_val, i=i_val, a=a_val,
                    label=t_label,
                    action="review",
                    comments=mt_comment or "Marked as Review In Progress",
                    user=user,
                    database=database
                )
                if ok:
                    msg = f"✅ Status updated to 'In Review' for {asset_name}"
                    icon = "👀"
                    st.toast(msg, icon=icon)
                    st.session_state["flash_toast"] = msg
                    st.session_state["flash_icon"] = icon
                    time.sleep(0.5)
                    st.rerun()
             except Exception as e:
                st.error(f"Error: {e}")
                st.toast(f"❌ Error: {e}", icon="🚨")

        # 2. Review Details (Examine context)
        with st.expander("🔍 Review Asset Details", expanded=False):
            st.caption("Detailed view of metadata and current tags for deep review.")
            try:
                # Try to fetch current tags or metadata for review
                curr_tags = tagging_service.get_object_tags(asset_name, "TABLE")
                if curr_tags:
                    st.json(curr_tags)
                else:
                    st.info("No current tags found for this asset.")
            except Exception:
                st.info("Additional metadata unavailable for this asset.")

        st.markdown("---")

        # 3. Classify / Approve (Approve Decision)
        # Use session state to manage approval flow visibility
        approve_mode_key = f"approve_mode_{idx_key}"
        
        if st.button("✅ Classify / Approve", type="primary", use_container_width=True, help="Approve the proposed classification or assign a new level", key=f"ua_btn_approve_main_{idx_key}"):
            st.session_state[approve_mode_key] = True
            st.rerun()

        if st.session_state.get(approve_mode_key, False):
            with st.expander("🔍 Classification Preview & Affirmation", expanded=True):
                st.markdown("### Classification Preview")
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
                
                # Dedicated Approval Message Input
                st.markdown("---")
                approval_msg = st.text_area("Approval Note", value=mt_comment, placeholder="Enter any specific approval notes...", key=f"app_msg_{idx_key}")
                
                # Confirmation and options
                c1, c2 = st.columns([1, 1])
                with c1:
                    if st.button("Confirm Approval", type="primary", key=f"confirm_approve_{idx_key}"):
                        try:
                            # Prepare Tags
                            tags_to_apply = {
                                "DATA_CLASSIFICATION": t_label,
                                "CONFIDENTIALITY_LEVEL": f"C{c_val}",
                                "INTEGRITY_LEVEL": f"I{i_val}",
                                "AVAILABILITY_LEVEL": f"A{a_val}",
                                "LAST_CLASSIFIED_BY": user,
                                "LAST_CLASSIFIED_AT": datetime.now().isoformat(),
                                "COMPLIANCE_FRAMEWORKS": ",".join(compliance_frameworks) if compliance_frameworks else ""
                            }
                            
                            # Apply Tags & Submit Task
                            ok = classification_workflow_service.update_or_submit_task(
                                asset_full_name=asset_name,
                                c=c_val, i=i_val, a=a_val,
                                label=t_label,
                                action="submit", # Maps to Approved/Completed
                                comments=approval_msg or "Classified & Approved",
                                user=user,
                                database=database
                            )
                            
                            if ok:
                                try:
                                    tagging_service.apply_tags_to_object(asset_name, "TABLE", tags_to_apply)
                                    discovery_service.mark_classified(asset_name, t_label, c_val, i_val, a_val, compliance_frameworks=compliance_frameworks)
                                    
                                    msg = f"✅ {asset_name} Approved & Classified"
                                    icon = "✅"
                                    st.toast(msg, icon=icon)
                                    st.session_state["flash_toast"] = msg
                                    st.session_state["flash_icon"] = icon
                                    # Clear approval mode
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

        # 4. Reject / Escalate
        with st.expander("🚫 Reject / Escalate"):
            col_rej, col_esc = st.columns(2)
            with col_rej:
                if st.button("Reject", use_container_width=True, key=f"ua_btn_reject_{idx_key}"):
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
                if st.button("Escalate", use_container_width=True, key=f"ua_btn_escalate_{idx_key}"):
                    classification_workflow_service.update_or_submit_task(
                        asset_full_name=asset_name, c=c_val, i=i_val, a=a_val, label=t_label,
                        action="escalate", comments=mt_comment or "Escalated for further review", user=user, database=database
                    )
                    msg = "Task Escalated."
                    icon = "⚠️"
                    st.toast(msg, icon=icon)
                    st.session_state["flash_toast"] = msg
                    st.session_state["flash_icon"] = icon
                    time.sleep(0.5)
                    st.rerun()
        
        # 5. Update Tags Only
        if st.button("🏷️ Update Tags", use_container_width=True, help="Modify sensitivity tags without closing the task", key=f"ua_btn_tag_v2_{idx_key}"):
            try:
                # Update task to indicate tags updated (Draft/In Progress)
                tags_to_apply = {
                    "DATA_CLASSIFICATION": t_label,
                    "CONFIDENTIALITY_LEVEL": f"C{c_val}",
                    "INTEGRITY_LEVEL": f"I{i_val}",
                    "AVAILABILITY_LEVEL": f"A{a_val}"
                }
                tagging_service.apply_tags_to_object(asset_name, "TABLE", tags_to_apply)
                
                classification_workflow_service.update_or_submit_task(
                    asset_full_name=asset_name, c=c_val, i=i_val, a=a_val, label=t_label,
                    action="update_tags", comments=mt_comment or "Tags updated manually", user=user, database=database
                )
                
                msg = "✅ Tags Updated (Task remains In Progress)"
                icon = "🏷️"
                st.toast(msg, icon=icon)
                st.session_state["flash_toast"] = msg
                st.session_state["flash_icon"] = icon
                time.sleep(0.5)
                st.rerun()
                
            except Exception as e:
                st.error(f"Tag update failed: {str(e)}")
                st.toast(f"❌ Tag update failed: {str(e)}", icon="🚨")

        # 6. Complete / Submit (Final Action)
        if st.button("🚀 Complete / Submit", use_container_width=True, help="Mark the task as done after action", key=f"ua_btn_submit_v2_{idx_key}"):
             try:
                ok = classification_workflow_service.update_or_submit_task(
                    asset_full_name=asset_name,
                    c=c_val, i=i_val, a=a_val,
                    label=t_label,
                    action="submit",
                    comments=mt_comment or "Task completed via inbox",
                    user=user,
                    database=database
                )
                if ok:
                    msg = f"✅ Task Completed: {asset_name}"
                    icon = "🚀"
                    st.toast(msg, icon=icon)
                    st.session_state["flash_toast"] = msg
                    st.session_state["flash_icon"] = icon
                    st.balloons()
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Failed to complete task")
                    st.toast("❌ Failed to complete task", icon="🚨")
             except Exception as e:
                st.error(f"Error: {e}")
                st.toast(f"❌ Error: {e}", icon="🚨")



def render_classification_management_ui(
    snowflake_connector,
    classification_workflow_service,
    current_user: str
):
    """
    Render the Classification Management UI with tabs for:
    - My Tasks
    - Pending Reviews  
    - History
    - Reclassification Requests
    
    All tabs support filtering by asset name.
    """
    
    
    # --- Flash Message Handling ---
    if "flash_toast" in st.session_state:
        msg = st.session_state["flash_toast"]
        icon = st.session_state.get("flash_icon")
        st.toast(msg, icon=icon)
        del st.session_state["flash_toast"]
        if "flash_icon" in st.session_state:
            del st.session_state["flash_icon"]

    st.markdown("""
    <div style="background: linear-gradient(90deg, rgba(59, 130, 246, 0.1), rgba(0, 0, 0, 0)); padding: 20px; border-radius: 12px; border-left: 4px solid #3b82f6; margin-bottom: 25px;">
        <h3 style="margin:0; color:white; font-size:1.4rem;">🗂️ Classification Management</h3>
        <p style="margin:5px 0 0 0; color:rgba(255,255,255,0.6); font-size:0.9rem;">
            Review and approve classification requests, manage tasks, and track history
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Create tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "📋 My Tasks",
        "⏳ Pending Reviews",
        "📜 History",
        "🔁 Reclassification Requests"
    ])
    
    # Tab 1: My Tasks
    with tab1:
        render_my_tasks_tab(snowflake_connector, classification_workflow_service, current_user)
    
    # Tab 2: Pending Reviews
    with tab2:
        render_pending_reviews_tab(snowflake_connector, classification_workflow_service, current_user)
    
    # Tab 3: History
    with tab3:
        render_history_tab(snowflake_connector, current_user)
    
    # Tab 4: Reclassification Requests
    with tab4:
        render_reclassification_requests_tab(snowflake_connector, classification_workflow_service, current_user)


def render_my_tasks_tab(snowflake_connector, classification_workflow_service, current_user: str):
    """Render My Tasks tab with unified selection-based action panel"""
    
    st.markdown("### 📋 My Tasks")
    st.caption("Tasks assigned to you that require action")
    
    # Asset name filter
    col1, col2 = st.columns([3, 1])
    with col1:
        asset_filter = st.text_input(
            "🔍 Filter by Asset Name",
            placeholder="Enter asset name",
            key="my_tasks_asset_filter"
        )
    with col2:
        if st.button("🔄 Refresh", key="refresh_my_tasks"):
            st.rerun()
    
    # Fetch tasks
    try:
        # Use the service method
        tasks = classification_workflow_service.fetch_user_tasks_from_assets(current_user=current_user)
        
        if not tasks:
            st.info("✅ No pending tasks. Great job!")
            return
        
        # Convert to DataFrame
        df_tasks = pd.DataFrame(tasks)
        
        # Apply asset name filter
        if asset_filter:
            df_tasks = df_tasks[
                df_tasks['ASSET_NAME'].str.contains(asset_filter, case=False, na=False)
            ]
        
        if df_tasks.empty:
            st.info(f"No tasks found matching '{asset_filter}'")
            return
            
        st.markdown(f"**Found {len(df_tasks)} task(s)**")
        
        # Add selection column
        df_tasks["Selected"] = False
        
        # Configure column display
        edited_df = st.data_editor(
            df_tasks,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Selected": st.column_config.CheckboxColumn("Select", width="small"),
                "ASSET_ID": None, # Hide internal IDs
                "ASSET_NAME": st.column_config.TextColumn("Asset Name", width="large"),
                "TASK_TYPE": st.column_config.TextColumn("Type"),
                "CLASSIFICATION_LABEL": st.column_config.TextColumn("Label"),
                "REVIEW_STATUS": st.column_config.TextColumn("Status"),
                "DAYS_SINCE_CREATION": st.column_config.NumberColumn("Age (Days)"),
            },
            column_order=["Selected", "ASSET_NAME", "TASK_TYPE", "CLASSIFICATION_LABEL", "REVIEW_STATUS", "DAYS_SINCE_CREATION"],
            disabled=[c for c in df_tasks.columns if c != "Selected"],
            key="my_tasks_editor_lib"
        )

        # --- Unified Task Review & Action Panel ---
        st.divider()
        
        selected_tasks = edited_df[edited_df["Selected"] == True]
        
        if not selected_tasks.empty:
            # If multiple selected, show a selectbox to pick which one to action specifically
            s_ids = selected_tasks.index.tolist()
            s_map = dict(zip(s_ids, selected_tasks["ASSET_NAME"]))
            
            if len(s_ids) > 1:
                st.info(f"Multiple tasks selected ({len(s_ids)}). Choose one below to action.")
                sel_idx = st.selectbox("Action Task", options=s_ids, format_func=lambda x: s_map.get(x, x), key="my_task_action_select_lib")
            else:
                sel_idx = s_ids[0]
            
            if sel_idx is not None:
                selected_row = selected_tasks.loc[sel_idx]
                
                # Call the unified panel helper
                render_unified_task_action_panel(
                    asset_name=selected_row["FULLY_QUALIFIED_NAME"] or selected_row["ASSET_NAME"],
                    c_init=1, # Default as ASSETS table might not have CIA directly in this view
                    i_init=1,
                    a_init=1,
                    status=selected_row["REVIEW_STATUS"],
                    user=current_user,
                    task_id=selected_row.get("ASSET_ID"), # Use Asset ID as task ID link
                    priority=None,
                    completion=None,
                    key_prefix="mytask"
                )
        else:
            st.info("Select rows from the table above to perform actions.")
    
    except Exception as e:
        st.error(f"Error loading tasks: {e}")
        logging.error(f"Error in render_my_tasks_tab: {e}")


def render_pending_reviews_tab(snowflake_connector, classification_workflow_service, current_user: str):
    """Render Pending Reviews tab with unified selection-based action panel"""
    
    st.markdown("### ⏳ Pending Reviews")
    st.caption("Classification submissions waiting for approval")
    
    # Filters
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        asset_filter = st.text_input(
            "🔍 Filter by Asset Name",
            placeholder="Enter asset name",
            key="pending_reviews_asset_filter"
        )
    with col2:
        review_type = st.selectbox(
            "Review Type",
            ["All", "Pending Approvals", "High-Risk", "Recent Changes"],
            key="review_type_filter"
        )
    with col3:
        if st.button("🔄 Refresh", key="refresh_reviews"):
            st.rerun()
    
    # Fetch reviews
    try:
        reviews_data = classification_workflow_service.list_reviews(
            current_user=current_user,
            review_filter=review_type,
            approval_status="All pending",
            asset_name_filter=asset_filter,
            lookback_days=30
        )
        
        reviews = reviews_data.get('reviews', [])
        
        if not reviews:
            st.info("✅ No pending reviews")
            return
        
        st.markdown(f"**Found {len(reviews)} review(s)**")
        
        # Convert to DataFrame for easier handling
        df_reviews = pd.DataFrame(reviews)
        df_reviews["Selected"] = False
        
        # Configure column display
        edited_df = st.data_editor(
            df_reviews,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Selected": st.column_config.CheckboxColumn("Select", width="small"),
                "id": st.column_config.TextColumn("Review ID", width="small"),
                "asset_name": st.column_config.TextColumn("Asset Name", width="large"),
                "classification": st.column_config.TextColumn("Classification"),
                "created_by": st.column_config.TextColumn("Submitted By"),
                "created_at": st.column_config.DatetimeColumn("Created At"),
                "status": st.column_config.TextColumn("Status"),
            },
            column_order=["Selected", "id", "asset_name", "classification", "created_by", "created_at", "status"],
            disabled=[c for c in df_reviews.columns if c != "Selected"],
            key="pending_reviews_editor_lib"
        )

        # --- Unified Task Review & Action Panel ---
        st.divider()
        
        selected_reviews = edited_df[edited_df["Selected"] == True]
        
        if not selected_reviews.empty:
            # If multiple selected, show a selectbox to pick which one to action specifically
            s_ids = selected_reviews["id"].tolist()
            s_map = dict(zip(selected_reviews["id"], selected_reviews["asset_name"]))
            
            if len(s_ids) > 1:
                st.info(f"Multiple reviews selected ({len(s_ids)}). Choose one below to action.")
                sel_id = st.selectbox("Action Review", options=s_ids, format_func=lambda x: s_map.get(x, x), key="pending_review_action_select_lib")
            else:
                sel_id = s_ids[0]
            
            if sel_id:
                selected_row = df_reviews[df_reviews["id"] == sel_id].iloc[0]
                
                # Call the unified panel helper
                render_unified_task_action_panel(
                    asset_name=selected_row["asset_name"],
                    c_init=selected_row.get("c_level") or 1,
                    i_init=1,
                    a_init=1,
                    status=selected_row["status"],
                    user=current_user,
                    task_id=selected_row["id"],
                    priority=None,
                    completion=None,
                    key_prefix="review"
                )
        else:
            st.info("Select rows from the table above to perform actions.")
    
    except Exception as e:
        st.error(f"Error loading reviews: {e}")
        logging.error(f"Error in render_pending_reviews_tab: {e}")


def render_history_tab(snowflake_connector, current_user: str):
    """Render History tab with asset name filtering"""
    
    st.markdown("### 📜 Classification History")
    st.caption("Historical classification decisions and changes")
    
    # Filters
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        asset_filter = st.text_input(
            "🔍 Filter by Asset Name",
            placeholder="Enter asset name",
            key="history_asset_filter"
        )
    with col2:
        days_back = st.selectbox("Time Range", [7, 30, 90, 365], index=1, key="history_days")
    with col3:
        if st.button("🔄 Refresh", key="refresh_history"):
            st.rerun()
    
    # Fetch history
    try:
        # Get database from session state
        db = st.session_state.get("sf_database")
        if not db:
            st.warning("No database selected. Please select a database from the sidebar.")
            return
        
        # Build query with proper database reference
        table_path = f"{db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_HISTORY"
        
        query = f"""
        SELECT 
            HISTORY_ID,
            ASSET_FULL_NAME,
            OLD_LABEL,
            NEW_LABEL,
            CHANGED_BY,
            CHANGE_REASON,
            CHANGE_TIMESTAMP,
            STATUS
        FROM {table_path}
        WHERE CHANGE_TIMESTAMP >= DATEADD(day, -{days_back}, CURRENT_TIMESTAMP())
        """
        
        if asset_filter:
            query += f" AND UPPER(ASSET_FULL_NAME) LIKE UPPER('%{asset_filter}%')"
        
        query += " ORDER BY CHANGE_TIMESTAMP DESC LIMIT 100"
        
        history = snowflake_connector.execute_query(query) or []
        
        if not history:
            st.info("No history records found")
            return
        
        df_history = pd.DataFrame(history)
        st.dataframe(
            df_history,
            use_container_width=True,
            hide_index=True,
            column_config={
                "CHANGE_TIMESTAMP": st.column_config.DatetimeColumn("Changed At", format="YYYY-MM-DD HH:mm"),
                "STATUS": st.column_config.TextColumn("Status")
            }
        )
    
    except Exception as e:
        st.error(f"Error loading history: {e}")
        logging.error(f"Error in render_history_tab: {e}")


def render_reclassification_requests_tab(snowflake_connector, classification_workflow_service, current_user: str):
    """Render Reclassification Requests tab with unified selection-based action panel"""
    
    st.markdown("### 🔁 Reclassification Requests")
    st.caption("Requests to change existing classifications")
    
    # Filters
    col1, col2 = st.columns([3, 1])
    with col1:
        asset_filter = st.text_input(
            "🔍 Filter by Asset Name",
            placeholder="Enter asset name",
            key="reclass_asset_filter"
        )
    with col2:
        if st.button("🔄 Refresh", key="refresh_reclass"):
            st.rerun()
    
    # Fetch reclassification requests
    try:
        requests = classification_workflow_service.list_reclassification_requests(
            status="Pending"
        )
        
        if not requests:
            st.info("✅ No pending reclassification requests")
            return
        
        # Filter by asset name
        if asset_filter:
            requests = [r for r in requests if asset_filter.upper() in r.get('asset_full_name', '').upper()]
        
        if not requests:
            st.info(f"No requests found matching '{asset_filter}'")
            return
        
        st.markdown(f"**Found {len(requests)} request(s)**")
        
        # Convert to DataFrame
        df_reclass = pd.DataFrame(requests)
        df_reclass["Selected"] = False
        
        # Configure column display
        edited_df = st.data_editor(
            df_reclass,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Selected": st.column_config.CheckboxColumn("Select", width="small"),
                "request_id": st.column_config.TextColumn("Request ID", width="small"),
                "asset_full_name": st.column_config.TextColumn("Asset Name", width="large"),
                "current_label": st.column_config.TextColumn("Current"),
                "proposed_label": st.column_config.TextColumn("Proposed"),
                "status": st.column_config.TextColumn("Status"),
                "created_at": st.column_config.DatetimeColumn("Submitted At"),
            },
            column_order=["Selected", "request_id", "asset_full_name", "current_label", "proposed_label", "status", "created_at"],
            disabled=[c for c in df_reclass.columns if c != "Selected"],
            key="reclass_requests_editor_lib"
        )

        # --- Unified Task Review & Action Panel ---
        st.divider()
        
        selected_requests = edited_df[edited_df["Selected"] == True]
        
        if not selected_requests.empty:
            # If multiple selected, show a selectbox to pick which one to action specifically
            s_ids = selected_requests["request_id"].tolist()
            s_map = dict(zip(selected_requests["request_id"], selected_requests["asset_full_name"]))
            
            if len(s_ids) > 1:
                st.info(f"Multiple requests selected ({len(s_ids)}). Choose one below to action.")
                sel_id = st.selectbox("Action Request", options=s_ids, format_func=lambda x: s_map.get(x, x), key="reclass_action_select_lib")
            else:
                sel_id = s_ids[0]
            
            if sel_id:
                selected_row = df_reclass[df_reclass["request_id"] == sel_id].iloc[0]
                
                # Call the unified panel helper
                render_unified_task_action_panel(
                    asset_name=selected_row["asset_full_name"],
                    c_init=selected_row.get("proposed_c") or 1,
                    i_init=selected_row.get("proposed_i") or 1,
                    a_init=selected_row.get("proposed_a") or 1,
                    status=selected_row["status"],
                    user=current_user,
                    task_id=selected_row["request_id"],
                    priority=None,
                    completion=None,
                    key_prefix="req"
                )
        else:
            st.info("Select rows from the table above to perform actions.")
    
    except Exception as e:
        st.error(f"Error loading reclassification requests: {e}")
        logging.error(f"Error in render_reclassification_requests_tab: {e}")


def render_task_card(task: Dict[str, Any], classification_workflow_service, current_user: str):
    """Render a single task card with approval actions"""
    
    asset_name = task.get('ASSET_NAME', 'Unknown')
    task_type = task.get('TASK_TYPE', '')
    days_old = task.get('DAYS_SINCE_CREATION', 0)
    
    # Color coding based on urgency

def approve_task(task: Dict, classification_workflow_service, current_user: str):
    """Approve a single task (Legacy fallback)"""
    try:
        # Implementation depends on task type
        st.success(f"Approved task for {task.get('ASSET_NAME')}")
        st.rerun()
    except Exception as e:
        st.error(f"Error approving task: {e}")


def reject_task(task: Dict, classification_workflow_service, current_user: str):
    """Reject a single task (Legacy fallback)"""
    try:
        # Implementation depends on task type
        st.warning(f"Rejected task for {task.get('ASSET_NAME')}")
        st.rerun()
    except Exception as e:
        st.error(f"Error rejecting task: {e}")
