"""
Review Actions Service

Encapsulates backend actions for Pending Reviews:
- approve_review
- reject_review
- request_changes

Snowflake logic is isolated here. UI should call these functions and handle messages.

Notes:
- TODO Snowflake: Replace placeholder DML with your governance tables/views.
  Suggested sources: <DB>.DATA_GOVERNANCE.CLASSIFICATION_HISTORY and
  <DB>.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS.
- All functions emit audit logs via audit_service for traceability.
"""
from __future__ import annotations

from typing import Optional, Dict, Any

from src.connectors.snowflake_connector import snowflake_connector
from src.services.audit_service import audit_service
from src.services.classification_decision_service import classification_decision_service

try:
    import streamlit as st  # for session context (e.g., current db)
except Exception:  # pragma: no cover
    st = None


def _current_user() -> str:
    try:
        if st is not None:
            return str(st.session_state.get("user") or st.session_state.get("sf_user") or "user")
    except Exception:
        pass
    return "user"


def approve_review(
    review_id: str,
    asset_full_name: str,
    label: str,
    c: int,
    i: int,
    a: int,
    approver: Optional[str] = None,
    comments: str = "",
) -> bool:
    """
    Approve the selected review.
    Actions:
    - Record an APPROVED decision in CLASSIFICATION_DECISIONS (policy-aligned).
    - Mark the review entry as approved in CLASSIFICATION_HISTORY (placeholder).
    - Emit an audit log.

    TODO Snowflake: Replace the UPDATE/MERGE below with your canonical governance process.
    """
    who = approver or _current_user()
    try:
        # 1) Persist decision
        classification_decision_service.record(
            asset_full_name=asset_full_name,
            decision_by=who,
            source="REVIEW",
            status="Approved",
            label=label,
            c=int(c), i=int(i), a=int(a),
            rationale=comments or "Approved via Pending Reviews",
            details={"review_id": review_id},
        )
        # 2) Mark review as approved (placeholder table/columns)
        try:
            snowflake_connector.execute_non_query(
                """
                /* TODO Snowflake: replace table/columns with actual history structure */
                UPDATE IDENTIFIER(:hist_table)
                SET APPROVED_BY = :who,
                    APPROVAL_TIMESTAMP = CURRENT_TIMESTAMP,
                    APPROVAL_STATUS = 'APPROVED'
                WHERE HISTORY_ID = :rid
                """,
                {
                    "hist_table": (st.session_state.get("sf_database") or "DATA_CLASSIFICATION_DB") + ".DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_HISTORY",
                    "who": who,
                    "rid": review_id,
                },
            )
        except Exception:
            # Best-effort; non-fatal in mock/demo contexts
            pass
        # 3) Audit log
        audit_service.log(who, "REVIEW_APPROVE", "CLASSIFICATION", asset_full_name, {"review_id": review_id, "label": label, "c": int(c), "i": int(i), "a": int(a)})
        return True
    except Exception:
        return False


def reject_review(
    review_id: str,
    asset_full_name: str,
    approver: Optional[str] = None,
    justification: str = "",
) -> bool:
    """
    Reject the selected review.
    Actions:
    - Mark history entry as REJECTED with justification (placeholder).
    - Audit log.

    TODO Snowflake: Replace the UPDATE target with your canonical table.
    """
    who = approver or _current_user()
    try:
        try:
            snowflake_connector.execute_non_query(
                """
                /* TODO Snowflake: replace table/columns with actual history structure */
                UPDATE IDENTIFIER(:hist_table)
                SET APPROVED_BY = :who,
                    APPROVAL_TIMESTAMP = CURRENT_TIMESTAMP,
                    APPROVAL_STATUS = 'REJECTED',
                    REJECTION_REASON = :why
                WHERE HISTORY_ID = :rid
                """,
                {
                    "hist_table": (st.session_state.get("sf_database") or "DATA_CLASSIFICATION_DB") + ".DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_HISTORY",
                    "who": who,
                    "why": justification or "Rejected via Pending Reviews",
                    "rid": review_id,
                },
            )
        except Exception:
            pass
        audit_service.log(who, "REVIEW_REJECT", "CLASSIFICATION", asset_full_name, {"review_id": review_id, "justification": justification})
        return True
    except Exception:
        return False


def request_changes(
    review_id: str,
    asset_full_name: str,
    approver: Optional[str] = None,
    instructions: str = "",
) -> bool:
    """
    Request changes from the submitter/owner.
    Actions:
    - Mark history entry as CHANGES_REQUESTED with notes (placeholder).
    - Audit log.

    TODO Snowflake: Replace the UPDATE target with your canonical table.
    """
    who = approver or _current_user()
    try:
        try:
            snowflake_connector.execute_non_query(
                """
                /* TODO Snowflake: replace table/columns with actual history structure */
                UPDATE IDENTIFIER(:hist_table)
                SET APPROVAL_STATUS = 'CHANGES_REQUESTED',
                    APPROVAL_NOTES = :notes
                WHERE HISTORY_ID = :rid
                """,
                {
                    "hist_table": (st.session_state.get("sf_database") or "DATA_CLASSIFICATION_DB") + ".DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_HISTORY",
                    "notes": instructions or "Please revise classification details",
                    "rid": review_id,
                },
            )
        except Exception:
            pass
        audit_service.log(who, "REVIEW_REQUEST_CHANGES", "CLASSIFICATION", asset_full_name, {"review_id": review_id, "notes": instructions})
        return True
    except Exception:
        return False
