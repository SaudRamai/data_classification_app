# Task Review & Action vs Classification Review - Detailed Comparison

## Overview

Your data classification application has two distinct review mechanisms that serve different purposes in the classification workflow. While they share the same underlying action panel (`render_unified_task_action_panel`), they differ in their **data sources**, **purpose**, and **user context**.

---

## 1. ⚡ Task Review & Action (My Tasks Tab)

### Location
- **File**: `src/components/classification_management.py`
- **Function**: `render_my_tasks_tab()`
- **UI Tab**: "My Tasks" sub-tab

### Purpose
**Individual task management** - Allows users to work on classification tasks specifically assigned to them.

### Data Source
```python
tasks = classification_workflow_service.fetch_user_tasks_from_assets(current_user=current_user)
```

**Source Table**: `ASSETS` table
- Filters by: `ASSIGNED_TO = current_user`
- Shows: Tasks assigned to the logged-in user
- Focus: Personal workload and assignments

### Key Characteristics

#### Data Columns Displayed:
- `ASSET_NAME` - The asset requiring classification
- `TASK_TYPE` - Type of classification task
- `CLASSIFICATION_LABEL` - Current/proposed classification
- `REVIEW_STATUS` - Current status of the task
- `DAYS_SINCE_CREATION` - How long the task has been pending

#### Workflow:
1. **User-centric**: Only shows tasks assigned to you
2. **Action-oriented**: Complete your assigned classification work
3. **Status tracking**: Updates task status in `CLASSIFICATION_TASKS` table
4. **Personal accountability**: Tracks individual user progress

#### CIA Values:
```python
# Default CIA values (not directly from ASSETS table in this view)
c_init=1
i_init=1  
a_init=1
```

---

## 2. 📋 Classification Review (Pending Reviews Tab)

### Location
- **File**: `src/components/classification_management.py`
- **Function**: `render_pending_reviews_tab()`
- **UI Tab**: "Pending Reviews" sub-tab (also called "Classification Review")

### Purpose
**Approval workflow** - Reviews and approves classification decisions submitted by others for quality control and governance.

### Data Source
```python
reviews_data = classification_workflow_service.list_reviews(
    current_user=current_user,
    review_filter=review_type,
    approval_status="All pending",
    asset_name_filter=asset_filter,
    lookback_days=30
)
```

**Source Tables**: `CLASSIFICATION_DECISIONS` and `CLASSIFICATION_REVIEW` tables
- Shows: Classification submissions awaiting approval
- Focus: Governance and quality control
- Not limited to specific user assignments

### Key Characteristics

#### Data Columns Displayed:
- `id` - Review ID
- `asset_name` - Asset being reviewed
- `classification` - Proposed classification
- `created_by` - Who submitted the classification
- `created_at` - When it was submitted
- `status` - Current approval status

#### Workflow:
1. **Governance-centric**: Review all pending classification decisions
2. **Approval-focused**: Approve or reject submissions
3. **Quality control**: Validate classification accuracy
4. **Broader oversight**: Not limited to your assignments

#### CIA Values:
```python
# CIA values from the review record
c_init=selected_row.get("c_level") or 1
i_init=1  # Default
a_init=1  # Default
```

#### Additional Filters:
- **Review Type**: All, Pending Approvals, High-Risk, Recent Changes
- **Asset Name Filter**: Search by asset name
- **Lookback Period**: Last 30 days

---

## 3. The Unified Action Panel

Both tabs use the **same action panel** (`render_unified_task_action_panel`), which provides:

### Common Features:
✅ **Classification Level Selection** (Public, Internal, Restricted, Confidential)
✅ **CIA Score Inputs** (Confidentiality, Integrity, Availability: 0-3)
✅ **Compliance Frameworks** (PII, SOX, SOC)
✅ **Review Comments/Rationale** text area
✅ **Approve & Apply Tagging** button

### Action Behavior:
```python
# If task_id exists (My Tasks):
classification_workflow_service.update_or_submit_task(
    asset_full_name=asset_name,
    c=c_val, i=i_val, a=a_val,
    label=t_label,
    action="submit",
    comments=mt_comment,
    user=user
)

# If no task_id (Classification Review):
classification_workflow_service.record_decision(
    asset_full_name=asset_name,
    decision_by=user,
    source="MANUAL_ACTION",
    status="Approved",
    label=t_label,
    c=c_val, i=i_val, a=a_val,
    rationale=mt_comment
)
```

---

## 4. Key Differences Summary

| Aspect | ⚡ Task Review & Action | 📋 Classification Review |
|--------|------------------------|-------------------------|
| **Purpose** | Complete assigned tasks | Approve submitted decisions |
| **Data Source** | `ASSETS` table | `CLASSIFICATION_DECISIONS` + `CLASSIFICATION_REVIEW` |
| **Filter** | `ASSIGNED_TO = current_user` | Pending approvals (all users) |
| **User Context** | Personal workload | Governance oversight |
| **Action Type** | Submit/Complete task | Approve/Reject decision |
| **Status Update** | `CLASSIFICATION_TASKS.STATUS` | `CLASSIFICATION_REVIEW.STATUS` |
| **CIA Source** | Default (1,1,1) | From review record |
| **Workflow** | Task completion | Approval workflow |
| **Role** | Data Classifier | Data Owner/Admin/Approver |

---

## 5. Workflow Integration

### Typical Flow:

1. **Task Assignment** → User receives task in "My Tasks"
2. **Task Completion** → User classifies asset using "Task Review & Action" panel
3. **Submission** → Decision recorded in `CLASSIFICATION_DECISIONS` table
4. **Review Queue** → Appears in "Classification Review" for approvers
5. **Approval** → Approver validates and approves using the same action panel
6. **Enforcement** → Tags applied to Snowflake objects
7. **Completion** → Task status updated to "Completed"

---

## 6. Historical Context (From Conversation History)

Based on conversation `48239cdc-eefc-43d2-960d-b197bb8a7988`, there was work done to:
- **Align both panels** to have identical behavior and capabilities
- **Ensure consistent C/I/A parsing** across both implementations
- **Unify the action interface** using `render_unified_task_action_panel`

This means while the **data sources differ**, the **user experience and actions** are now consistent.

---

## 7. When to Use Each

### Use "⚡ Task Review & Action" when:
- You want to complete tasks assigned to you
- You're a data classifier working on your workload
- You need to see your personal task queue
- You want to track your own progress

### Use "📋 Classification Review" when:
- You're a Data Owner or Admin approving classifications
- You need to review submissions from multiple users
- You want to ensure classification quality
- You're performing governance oversight
- You need to approve high-risk classifications

---

## Conclusion

Both features work together as part of a **complete classification governance workflow**:
- **Task Review & Action** = "Do the work"
- **Classification Review** = "Approve the work"

They share the same action panel for consistency but serve distinct roles in the classification lifecycle.
