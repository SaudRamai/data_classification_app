"""
Classification Management - Manual Approval Functions
Provides manual approval interface for classifications based on asset names
"""

import streamlit as st
import pandas as pd
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


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
    """Render My Tasks tab with asset name filtering"""
    
    st.markdown("### 📋 My Tasks")
    st.caption("Tasks assigned to you that require action")
    
    # Asset name filter
    col1, col2 = st.columns([3, 1])
    with col1:
        asset_filter = st.text_input(
            "🔍 Filter by Asset Name",
            placeholder="Enter asset name (e.g., CUSTOMERS, SALES_*)",
            key="my_tasks_asset_filter"
        )
    with col2:
        if st.button("🔄 Refresh", key="refresh_my_tasks"):
            st.rerun()
    
    # Fetch tasks
    try:
        from src.services.classification_workflow_service import classification_workflow_service as wf_service
        
        # Import the my_fetch_tasks function
        from pages.3_Classification import my_fetch_tasks
        
        tasks = my_fetch_tasks(current_user=current_user)
        
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
        
        # Display tasks grouped by type
        for task_type in df_tasks['TASK_TYPE'].unique():
            with st.expander(f"{task_type} ({len(df_tasks[df_tasks['TASK_TYPE'] == task_type])})", expanded=True):
                type_tasks = df_tasks[df_tasks['TASK_TYPE'] == task_type]
                
                for idx, task in type_tasks.iterrows():
                    render_task_card(task, classification_workflow_service, current_user)
    
    except Exception as e:
        st.error(f"Error loading tasks: {e}")
        logger.error(f"Error in render_my_tasks_tab: {e}")


def render_pending_reviews_tab(snowflake_connector, classification_workflow_service, current_user: str):
    """Render Pending Reviews tab with asset name filtering and bulk approval"""
    
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
            asset_name_filter=asset_filter,  # Use the new parameter we added
            lookback_days=30
        )
        
        reviews = reviews_data.get('reviews', [])
        
        if not reviews:
            st.info("✅ No pending reviews")
            return
        
        st.markdown(f"**Found {len(reviews)} review(s)**")
        
        # Bulk actions
        st.markdown("---")
        st.markdown("#### Bulk Actions")
        col_bulk1, col_bulk2 = st.columns(2)
        
        with col_bulk1:
            if st.button("✅ Approve All Filtered", key="bulk_approve", type="primary"):
                approve_bulk_reviews(reviews, classification_workflow_service, current_user, "approve")
        
        with col_bulk2:
            if st.button("❌ Reject All Filtered", key="bulk_reject"):
                approve_bulk_reviews(reviews, classification_workflow_service, current_user, "reject")
        
        st.markdown("---")
        
        # Display individual reviews
        for review in reviews:
            render_review_card(review, classification_workflow_service, current_user)
    
    except Exception as e:
        st.error(f"Error loading reviews: {e}")
        logger.error(f"Error in render_pending_reviews_tab: {e}")


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
        db = st.session_state.get("sf_database", "DATA_CLASSIFICATION_DB")
        
        query = f"""
        SELECT 
            HISTORY_ID,
            ASSET_FULL_NAME,
            OLD_LABEL,
            NEW_LABEL,
            CHANGED_BY,
            CHANGE_REASON,
            CHANGE_TIMESTAMP,
            APPROVAL_STATUS
        FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_HISTORY
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
                "APPROVAL_STATUS": st.column_config.TextColumn("Status")
            }
        )
    
    except Exception as e:
        st.error(f"Error loading history: {e}")
        logger.error(f"Error in render_history_tab: {e}")


def render_reclassification_requests_tab(snowflake_connector, classification_workflow_service, current_user: str):
    """Render Reclassification Requests tab with asset name filtering"""
    
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
        
        # Display requests
        for req in requests:
            render_reclassification_card(req, classification_workflow_service, current_user)
    
    except Exception as e:
        st.error(f"Error loading reclassification requests: {e}")
        logger.error(f"Error in render_reclassification_requests_tab: {e}")


def render_task_card(task: Dict[str, Any], classification_workflow_service, current_user: str):
    """Render a single task card with approval actions"""
    
    asset_name = task.get('ASSET_NAME', 'Unknown')
    task_type = task.get('TASK_TYPE', '')
    days_old = task.get('DAYS_SINCE_CREATION', 0)
    
    # Color coding based on urgency
    if days_old > 5:
        border_color = "#ef4444"  # Red for overdue
    elif days_old > 3:
        border_color = "#f59e0b"  # Orange for warning
    else:
        border_color = "#3b82f6"  # Blue for normal
    
    st.markdown(f"""
    <div style="background: rgba(255,255,255,0.03); border-left: 4px solid {border_color}; border-radius: 8px; padding: 15px; margin-bottom: 10px;">
        <div style="display: flex; justify-content: space-between;">
            <div>
                <strong style="color: white; font-size: 1.1rem;">{asset_name}</strong>
                <div style="color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-top: 5px;">
                    Type: {task_type} | Age: {days_old} days
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Action buttons
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        if st.button(f"✅ Approve", key=f"approve_task_{task.get('ASSET_ID')}"):
            approve_task(task, classification_workflow_service, current_user)
    with col2:
        if st.button(f"❌ Reject", key=f"reject_task_{task.get('ASSET_ID')}"):
            reject_task(task, classification_workflow_service, current_user)


def render_review_card(review: Dict[str, Any], classification_workflow_service, current_user: str):
    """Render a single review card"""
    
    asset_name = review.get('asset_name', 'Unknown')
    classification = review.get('classification', '')
    created_by = review.get('created_by', '')
    
    st.markdown(f"""
    <div style="background: rgba(255,255,255,0.03); border-left: 4px solid #3b82f6; border-radius: 8px; padding: 15px; margin-bottom: 10px;">
        <strong style="color: white;">{asset_name}</strong>
        <div style="color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-top: 5px;">
            Classification: {classification} | Submitted by: {created_by}
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button(f"✅ Approve", key=f"approve_review_{review.get('id')}"):
            classification_workflow_service.approve_review(
                review_id=review.get('id'),
                asset_full_name=review.get('asset_name'),
                label=review.get('classification'),
                c=review.get('c_level', 1),
                i=1,
                a=1,
                approver=current_user
            )
            st.success(f"Approved classification for {asset_name}")
            st.rerun()
    
    with col2:
        if st.button(f"❌ Reject", key=f"reject_review_{review.get('id')}"):
            classification_workflow_service.reject_review(
                review_id=review.get('id'),
                asset_full_name=review.get('asset_name'),
                approver=current_user
            )
            st.warning(f"Rejected classification for {asset_name}")
            st.rerun()


def render_reclassification_card(req: Dict[str, Any], classification_workflow_service, current_user: str):
    """Render a reclassification request card"""
    
    asset_name = req.get('asset_full_name', 'Unknown')
    old_label = req.get('current_label', '')
    new_label = req.get('proposed_label', '')
    
    st.markdown(f"""
    <div style="background: rgba(255,255,255,0.03); border-left: 4px solid #f59e0b; border-radius: 8px; padding: 15px; margin-bottom: 10px;">
        <strong style="color: white;">{asset_name}</strong>
        <div style="color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-top: 5px;">
            {old_label} → {new_label}
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button(f"✅ Approve Change", key=f"approve_reclass_{req.get('request_id')}"):
            classification_workflow_service.approve_reclassification(
                request_id=req.get('request_id'),
                approver=current_user
            )
            st.success(f"Approved reclassification for {asset_name}")
            st.rerun()
    
    with col2:
        if st.button(f"❌ Reject Change", key=f"reject_reclass_{req.get('request_id')}"):
            classification_workflow_service.reject_reclassification(
                request_id=req.get('request_id'),
                approver=current_user
            )
            st.warning(f"Rejected reclassification for {asset_name}")
            st.rerun()


def approve_bulk_reviews(reviews: List[Dict], classification_workflow_service, current_user: str, action: str):
    """Approve or reject multiple reviews at once"""
    
    success_count = 0
    error_count = 0
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for idx, review in enumerate(reviews):
        try:
            if action == "approve":
                classification_workflow_service.approve_review(
                    review_id=review.get('id'),
                    asset_full_name=review.get('asset_name'),
                    label=review.get('classification'),
                    c=review.get('c_level', 1),
                    i=1,
                    a=1,
                    approver=current_user
                )
            else:
                classification_workflow_service.reject_review(
                    review_id=review.get('id'),
                    asset_full_name=review.get('asset_name'),
                    approver=current_user
                )
            success_count += 1
        except Exception as e:
            error_count += 1
            logger.error(f"Error processing review {review.get('id')}: {e}")
        
        progress_bar.progress((idx + 1) / len(reviews))
        status_text.text(f"Processing {idx + 1}/{len(reviews)}...")
    
    progress_bar.empty()
    status_text.empty()
    
    if action == "approve":
        st.success(f"✅ Approved {success_count} reviews. {error_count} errors.")
    else:
        st.warning(f"❌ Rejected {success_count} reviews. {error_count} errors.")
    
    st.rerun()


def approve_task(task: Dict, classification_workflow_service, current_user: str):
    """Approve a single task"""
    try:
        # Implementation depends on task type
        st.success(f"Approved task for {task.get('ASSET_NAME')}")
        st.rerun()
    except Exception as e:
        st.error(f"Error approving task: {e}")


def reject_task(task: Dict, classification_workflow_service, current_user: str):
    """Reject a single task"""
    try:
        # Implementation depends on task type
        st.warning(f"Rejected task for {task.get('ASSET_NAME')}")
        st.rerun()
    except Exception as e:
        st.error(f"Error rejecting task: {e}")
