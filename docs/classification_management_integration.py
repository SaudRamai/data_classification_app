# Example: How to add Classification Management to pages/3_Classification.py

"""
Add this code to your Classification page (pages/3_Classification.py) 
to enable the Classification Management UI with manual approval functions.

Place this after your existing imports and before the main page content.
"""

# Import the Classification Management component
from src.components.classification_management import render_classification_management_ui

# Get current user
try:
    current_user_identity = authz.get_current_identity()
    current_user = current_user_identity.user if current_user_identity else "UNKNOWN_USER"
except Exception:
    current_user = st.session_state.get("sf_user", "UNKNOWN_USER")

# Add a section for Classification Management
st.markdown("---")
st.markdown("## 🗂️ Classification Management")

# Render the Classification Management UI
render_classification_management_ui(
    snowflake_connector=snowflake_connector,
    classification_workflow_service=classification_workflow_service,
    current_user=current_user
)

"""
This will create 4 tabs:

1. 📋 My Tasks
   - Shows tasks assigned to the current user
   - Filter by asset name
   - Approve/Reject individual tasks
   - Shows: Needs Classification, Needs Peer Review, Needs Management Approval, Past SLA, Exception Expiring Soon

2. ⏳ Pending Reviews
   - Shows all pending classification reviews
   - Filter by asset name
   - Bulk approve/reject filtered reviews
   - Individual approve/reject for each review

3. 📜 History
   - Shows classification history
   - Filter by asset name and time range
   - View all past classification changes

4. 🔁 Reclassification Requests
   - Shows pending reclassification requests
   - Filter by asset name
   - Approve/Reject reclassification changes
   - Archives old classifications before applying new ones
"""
