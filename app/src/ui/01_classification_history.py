"""
UI for Classification Management → History sub-tab.

Renders:
- Filters: date range, dataset name, classification level, owner
- Sortable/searchable grid of audit rows
- CSV download

Backend:
- Uses src/services/classification_audit_service.fetch_audit()
- All Snowflake SQL lives in the service. This UI is purely presentation.
"""
from __future__ import annotations

from typing import List, Optional, Dict, Any
from datetime import date, timedelta
import pandas as pd
import streamlit as st

from src.services.classification_audit_service import fetch_audit


CLASSIFICATION_LEVELS = ["Public", "Internal", "Restricted", "Confidential"]


def _to_str(v: Any) -> str:
    return "" if v is None else str(v)


def render_classification_history_tab(key_prefix: str = "cm_hist") -> None:
    """Render the History sub-tab content."""
    st.markdown("#### History")
    st.caption(
        "Complete audit trail of classification events from Snowflake (or mock if unavailable)."
    )

    # Filters row
    c1, c2, c3, c4 = st.columns([1.2, 1.2, 1.2, 1.2])
    with c1:
        # Use a toggle to avoid invalid (None, None) range values
        enable_date_filter = st.checkbox(
            "Filter by date range",
            value=False,
            key=f"{key_prefix}_date_enable",
            help="Enable to filter by submission/approval dates",
        )
        date_range = None
        if enable_date_filter:
            today = date.today()
            default_start = today - timedelta(days=30)
            date_range = st.date_input(
                "Date range",
                value=(default_start, today),
                key=f"{key_prefix}_date",
                help="Filter by submission/approval date range",
            )
    with c2:
        dataset_name = st.text_input(
            "Dataset name contains",
            key=f"{key_prefix}_ds",
            placeholder="e.g., DB.SCHEMA.TABLE or partial",
        )
    with c3:
        levels = st.multiselect(
            "Classification level",
            options=CLASSIFICATION_LEVELS,
            default=[],
            key=f"{key_prefix}_lvl",
        )
    with c4:
        owner = st.text_input(
            "Owner",
            key=f"{key_prefix}_owner",
            placeholder="user@company.com or name",
        )

    # Build service filters
    start_date_str: Optional[str] = None
    end_date_str: Optional[str] = None
    if date_range and isinstance(date_range, (list, tuple)) and len(date_range) == 2:
        sd, ed = date_range
        if sd is not None and ed is not None:
            start_date_str = sd.strftime("%Y-%m-%d")
            end_date_str = ed.strftime("%Y-%m-%d")

    # Fetch data from service (Snowflake or mock fallback)
    rows = fetch_audit(
        start_date=start_date_str,
        end_date=end_date_str,
        dataset_name=(dataset_name or None),
        classification_levels=(levels or None),
        owner=(owner or None),
        limit=2000,
    )

    # Convert to DataFrame and apply client-side search filter
    df = pd.DataFrame(rows or [])

    # Ensure expected columns exist
    expected = [
        "dataset",
        "prev_cia",
        "curr_cia",
        "overall_risk",
        "approver_comments",
        "submitted_at",
        "approved_at",
        "owner",
        "classification_level",
    ]
    for col in expected:
        if col not in df.columns:
            df[col] = None

    # Search across all columns
    st.markdown("---")
    search_q = st.text_input(
        "Search (all columns)",
        key=f"{key_prefix}_q",
        placeholder="Type to filter...",
    )

    view_df = df.copy()
    if search_q:
        q = search_q.lower()
        mask = pd.Series([False] * len(view_df))
        for col in expected:
            mask = mask | view_df[col].astype(str).str.lower().str.contains(q, na=False)
        view_df = view_df[mask]

    # Rename for nicer display
    display_df = view_df.rename(
        columns={
            "dataset": "Dataset",
            "prev_cia": "Previous CIA Scores",
            "curr_cia": "Current CIA Scores",
            "overall_risk": "Overall Risk",
            "approver_comments": "Approver Comments",
            "submitted_at": "Submitted At",
            "approved_at": "Approved At",
            "owner": "Owner",
            "classification_level": "Classification Level",
        }
    )

    st.dataframe(display_df, use_container_width=True)

    # CSV download
    try:
        csv_bytes = display_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download CSV",
            data=csv_bytes,
            file_name="classification_history_audit.csv",
            mime="text/csv",
            key=f"{key_prefix}_dl",
        )
    except Exception:
        pass

    # Developer note: The Snowflake query lives in fetch_audit().
    # To customize for your schema, edit src/services/classification_audit_service.py
