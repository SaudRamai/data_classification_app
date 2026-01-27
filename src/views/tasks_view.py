"""View for displaying and managing classification tasks."""
from typing import List, Dict, Any, Optional, Tuple
import streamlit as st
from datetime import datetime, date
import pandas as pd
import time

from src.connectors.snowflake_connector import snowflake_connector
from src.services.authorization_service import authz

class TasksView:
    """View for displaying and managing classification tasks."""

    def __init__(self):
        """Initialize the tasks view."""
        self.current_user = authz.get_current_identity()
        
    def get_my_tasks(self, status: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch tasks assigned to the current user from Snowflake.
        
        Args:
            status: Optional status filter (e.g., 'Pending', 'In Progress', 'Completed')
            limit: Maximum number of tasks to return
            
        Returns:
            List of task dictionaries
        """
        query = """
        SELECT 
            TASK_ID,
            DATASET_NAME,
            ASSET_FULL_NAME,
            OWNER,
            STATUS,
            CONFIDENTIALITY_LEVEL as CONFIDENTIALITY,
            INTEGRITY_LEVEL as INTEGRITY,
            AVAILABILITY_LEVEL as AVAILABILITY,
            DUE_DATE,
            CREATED_AT,
            UPDATED_AT,
            STATUS_LABEL,
            DETAILS
        FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.VW_MY_CLASSIFICATION_TASKS
        WHERE UPPER(OWNER) = UPPER(%(username)s)
        {status_filter}
        ORDER BY 
            CASE 
                WHEN STATUS LIKE '%Pending%' THEN 1
                WHEN STATUS LIKE '%In Progress%' THEN 2
                WHEN STATUS LIKE '%Completed%' THEN 3
                ELSE 4
            END,
            DUE_DATE ASC
        LIMIT %(limit)s
        """
        
        params = {
            'username': self.current_user,
            'limit': limit
        }
        
        if status:
            query = query.replace('{status_filter}', 'AND STATUS = %(status)s')
            params['status'] = status
        else:
            query = query.replace('{status_filter}', '')
        
        try:
            with snowflake_connector.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                columns = [col[0] for col in cursor.description]
                tasks = [dict(zip(columns, row)) for row in cursor.fetchall()]
                return tasks
        except Exception as e:
            st.error(f"Error fetching tasks: {str(e)}")
            return []
    
    def update_task_status(self, task_id: str, new_status: str) -> bool:
        """
        Update the status of a task.
        
        Args:
            task_id: ID of the task to update
            new_status: New status to set
            
        Returns:
            bool: True if update was successful, False otherwise
        """
        update_query = """
        UPDATE DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_TASKS
        SET 
            STATUS = %(status)s,
            UPDATED_AT = CURRENT_TIMESTAMP()
        WHERE TASK_ID = %(task_id)s
        """
        
        try:
            with snowflake_connector.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(update_query, {
                    'task_id': task_id,
                    'status': new_status
                })
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            st.error(f"Error updating task status: {str(e)}")
            return False
    
    def render_task_card(self, task: Dict[str, Any]) -> None:
        """
        Render a single task as a card in the UI.
        
        Args:
            task: Dictionary containing task details
        """
        with st.expander(f"{task['STATUS_LABEL']} - {task['DATASET_NAME']}"):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.subheader(task['DATASET_NAME'])
                if task.get('ASSET_FULL_NAME'):
                    st.caption(f"Asset: {task['ASSET_FULL_NAME']}")
                
                if task.get('DETAILS'):
                    st.caption("Details:")
                    st.info(task['DETAILS'])
                
                # Show CIA levels if available
                if all(k in task for k in ['CONFIDENTIALITY', 'INTEGRITY', 'AVAILABILITY']):
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.metric("🔒 Confidentiality", task['CONFIDENTIALITY'])
                    with c2:
                        st.metric("🛡️ Integrity", task['INTEGRITY'])
                    with c3:
                        st.metric("⚡ Availability", task['AVAILABILITY'])
            
            with col2:
                # Format dates
                due_date = task.get('DUE_DATE')
                created_date = task.get('CREATED_AT')
                updated_date = task.get('UPDATED_AT')
                
                if due_date:
                    days_left = (due_date - date.today()).days
                    if days_left < 0:
                        status_text = f"🔴 Overdue by {-days_left} days"
                    elif days_left == 0:
                        status_text = "🟡 Due today"
                    elif days_left <= 7:
                        status_text = f"🟠 Due in {days_left} days"
                    else:
                        status_text = f"🟢 Due in {days_left} days"
                    
                    st.caption(status_text)
                    st.caption(f"Due: {due_date.strftime('%b %d, %Y')}")
                
                if created_date:
                    st.caption(f"Created: {created_date.strftime('%b %d, %Y')}")
                
                # Add action buttons based on status
                current_status = task.get('STATUS', '').lower()
                
                if 'pending' in current_status:
                    if st.button("Start Review", key=f"start_{task['TASK_ID']}"):
                        if self.update_task_status(task['TASK_ID'], 'In Progress'):
                            st.success("Task marked as In Progress")
                            time.sleep(1)  # Give time to see the success message
                            st.experimental_rerun()
                
                elif 'in progress' in current_status:
                    if st.button("Mark Complete", key=f"complete_{task['TASK_ID']}"):
                        if self.update_task_status(task['TASK_ID'], 'Completed'):
                            st.success("Task marked as Completed")
                            time.sleep(1)  # Give time to see the success message
                            st.experimental_rerun()
                
                # Add a link to the asset if available
                if task.get('ASSET_FULL_NAME'):
                    asset_parts = task['ASSET_FULL_NAME'].split('.')
                    if len(asset_parts) >= 3:
                        db, schema, table = asset_parts[0], asset_parts[1], asset_parts[2]
                        st.markdown(f"""
                        <a href="#ai-assisted-classification" target="_self">
                            <button>View Asset</button>
                        </a>
                        """, unsafe_allow_html=True)
    
    def render(self) -> None:
        """Render the tasks view with filters and task cards."""
        st.title("📋 My Classification Tasks")
        
        # Add filters
        col1, col2 = st.columns(2)
        with col1:
            status_filter = st.selectbox(
                "Filter by Status",
                ["All", "Pending", "In Progress", "Completed"],
                index=0
            )
        
        with col2:
            sort_by = st.selectbox(
                "Sort By",
                ["Due Date (Ascending)", "Due Date (Descending)", "Status", "Asset Name"],
                index=0
            )
        
        # Fetch tasks based on filters
        status_to_fetch = status_filter.lower() if status_filter != "All" else None
        tasks = self.get_my_tasks(status=status_to_fetch)
        
        # Apply sorting
        if sort_by == "Due Date (Ascending)":
            tasks.sort(key=lambda x: x.get('DUE_DATE') or date.max)
        elif sort_by == "Due Date (Descending)":
            tasks.sort(key=lambda x: x.get('DUE_DATE') or date.min, reverse=True)
        elif sort_by == "Status":
            tasks.sort(key=lambda x: x.get('STATUS', '').lower())
        elif sort_by == "Asset Name":
            tasks.sort(key=lambda x: x.get('DATASET_NAME', '').lower())
        
        # Display task count
        st.caption(f"Showing {len(tasks)} tasks")
        
        # Group tasks by status
        status_groups = {
            "Pending": [],
            "In Progress": [],
            "Completed": []
        }
        
        for task in tasks:
            status = task.get('STATUS', 'Pending').lower()
            if 'complete' in status:
                status_groups["Completed"].append(task)
            elif 'progress' in status:
                status_groups["In Progress"].append(task)
            else:
                status_groups["Pending"].append(task)
        
        # Display tasks in sections by status
        for status, status_tasks in status_groups.items():
            if status_tasks:
                st.subheader(f"{status} ({len(status_tasks)})")
                for task in status_tasks:
                    self.render_task_card(task)
                    st.write("---")
        
        if not tasks:
            st.info("No tasks found matching your criteria.")
            
        # Add a refresh button
        if st.button("🔄 Refresh Tasks"):
            st.experimental_rerun()
