"""
Repository for Classification Audit (Snowflake SQL only)

This module encapsulates the SQL to query the CLASSIFICATION_AUDIT table.
It should NOT contain any Streamlit/UI logic or mock data. Consumers should
handle fallbacks and mapping as needed.

Returned rows are normalized to the UI schema expected by
`src/ui/classification_history_tab.py`:
- dataset
- prev_cia (e.g., "1/1/1")
- curr_cia (e.g., "2/2/2")
- overall_risk
- approver_comments
- submitted_at
- approved_at
- owner
- classification_level

Customize the SELECT mapping to match your Snowflake table columns.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.connectors.snowflake_connector import snowflake_connector


def _like(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = str(value).strip()
    return f"%{v}%" if v else None


def fetch_audit_rows(
    *,
    database: str,
    schema: str = "DATA_GOVERNANCE",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    dataset_name: Optional[str] = None,
    classification_levels: Optional[List[str]] = None,
    owner: Optional[str] = None,
    limit: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Execute the Snowflake query against {database}.{schema}.CLASSIFICATION_AUDIT and
    return normalized rows for the UI.

    Note: This function assumes the table exists. Let callers catch exceptions and
    decide on fallbacks (e.g., mock data).
    """
    where_sql: List[str] = []
    params: Dict[str, Any] = {"limit": int(max(1, min(10000, limit)))}

    if start_date and end_date:
        where_sql.append("a.SUBMITTED_AT BETWEEN %(sd)s AND %(ed)s")
        params["sd"] = start_date
        params["ed"] = end_date
    if dataset_name:
        where_sql.append("upper(a.DATASET_NAME) like upper(%(ds)s)")
        params["ds"] = _like(dataset_name)
    if owner:
        where_sql.append("upper(coalesce(a.OWNER, '')) like upper(%(ow)s)")
        params["ow"] = _like(owner)
    if classification_levels:
        in_list = ",".join(["'" + str(x).replace("'","''").upper() + "'" for x in classification_levels if x]) or "''"
        where_sql.append(f"upper(coalesce(a.CLASSIFICATION_LEVEL,'')) in ({in_list})")

    where_clause = (" where " + " and ".join(where_sql)) if where_sql else ""

    # IMPORTANT: Map to your schema here
    sql = f"""
        SELECT
          /* Dataset full name or provided DATASET_NAME */
          COALESCE(a.DATASET_NAME, a.DATABASE || '.' || a.SCHEMA || '.' || a.OBJECT_NAME) AS DATASET,
          /* Previous CIA string */
          CONCAT(COALESCE(a.PREV_C,0),'/',COALESCE(a.PREV_I,0),'/',COALESCE(a.PREV_A,0)) AS PREV_CIA,
          /* Current CIA string */
          CONCAT(COALESCE(a.NEW_C,0),'/',COALESCE(a.NEW_I,0),'/',COALESCE(a.NEW_A,0))   AS CURR_CIA,
          /* Overall Risk */
          COALESCE(a.RISK, 'Medium') AS OVERALL_RISK,
          /* Approver Comments */
          COALESCE(a.APPROVER_COMMENTS, a.COMMENTS) AS APPROVER_COMMENTS,
          /* Submission/Approval timestamps */
          a.SUBMITTED_AT,
          a.APPROVED_AT,
          /* Owner/submitter */
          COALESCE(a.OWNER, a.SUBMITTED_BY) AS OWNER,
          /* Classification label */
          COALESCE(a.CLASSIFICATION_LEVEL, a.NEW_CLASSIFICATION) AS CLASSIFICATION_LEVEL
        FROM {database}.{schema}.CLASSIFICATION_AUDIT a
        {where_clause}
        ORDER BY COALESCE(a.APPROVED_AT, a.SUBMITTED_AT) DESC
        LIMIT %(limit)s
    """

    rows = snowflake_connector.execute_query(sql, params) or []
    # Rows already normalized by SELECT aliases
    return [
        {
            "dataset": r.get("DATASET"),
            "prev_cia": r.get("PREV_CIA"),
            "curr_cia": r.get("CURR_CIA"),
            "overall_risk": r.get("OVERALL_RISK"),
            "approver_comments": r.get("APPROVER_COMMENTS"),
            "submitted_at": r.get("SUBMITTED_AT"),
            "approved_at": r.get("APPROVED_AT"),
            "owner": r.get("OWNER"),
            "classification_level": r.get("CLASSIFICATION_LEVEL"),
        }
        for r in rows
    ]
