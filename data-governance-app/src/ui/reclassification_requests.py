"""
Reclassification Requests UI Module

- Streamlit UI for submitting and managing reclassification requests
- Clear separation of concerns:
  - SnowflakeOps: encapsulates DB operations (with placeholders and comments)
  - Backend: business logic bridging UI and Snowflake/services
  - render_reclassification_requests(): the Streamlit UI renderer

Requirements addressed:
- Form: Dataset Name, Reason for Reclassification, Proposed CIA, Rationale, Attachments
- Workflow statuses: Pending, Approved, Rejected, Under Review
- Table with filters: status, owner, dataset
- Store requests and workflow logs in Snowflake (uses service/connector with placeholders)
- Comments for Snowflake query points
- Modular and importable from the Classification Management tab
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

import pandas as pd
import streamlit as st

# Ensure project root on path for `src.*` imports when running as a Streamlit page
_here = os.path.abspath(str(__file__))
_src_dir = os.path.dirname(os.path.dirname(_here))  # .../src
_project_root = os.path.dirname(_src_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Services and connectors (best-effort imports)
try:
    from src.connectors.snowflake_connector import snowflake_connector
except Exception:  # type: ignore
    snowflake_connector = None  # type: ignore

from src.services.classification_workflow_service import classification_workflow_service as reclassification_service

try:
    from src.services.classification_audit_service import classification_audit_service as audit_service
except Exception:  # type: ignore
    audit_service = None  # type: ignore

# Orchestration façade (preferred entry point)
from src.services.classification_workflow_service import classification_workflow_service as cwf


GOV_SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
REQ_TABLE = "RECLASSIFICATION_REQUESTS"
LOG_TABLE = "RECLASSIFICATION_WORKFLOW_LOG"

VALID_STATUSES = ["Pending", "Under Review", "Approved", "Rejected"]


@dataclass
class ReclassRequest:
    id: str
    asset_full_name: str
    reason: str
    proposed_c: Optional[int]
    proposed_i: Optional[int]
    proposed_a: Optional[int]
    proposed_label: Optional[str]
    rationale: str
    attachment_name: Optional[str]
    attachment_bytes: Optional[bytes]
    created_by: str
    status: str = "Pending"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class SnowflakeOps:
    """Encapsulates all Snowflake reads/writes. Includes placeholder fallbacks.

    IMPORTANT: All SQL points are annotated with comments for easy replacement.
    """

    def __init__(self):
        self.sf = snowflake_connector

    def _db(self) -> Optional[str]:
        INVALID_DB_VALUES = {"NONE", "NULL", "UNKNOWN", "(NONE)"}
        # Session state first, but ignore placeholders
        try:
            db = st.session_state.get("sf_database")
            if db:
                vv = str(db).strip()
                if vv and vv.upper() not in INVALID_DB_VALUES:
                    return vv
        except Exception:
            pass
        # Current session database from Snowflake
        try:
            if self.sf:
                rows = self.sf.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
                cur = rows[0].get("DB") if rows else None
                if cur and str(cur).strip().upper() not in INVALID_DB_VALUES:
                    return str(cur).strip()
        except Exception:
            return None
        return None

    def ensure_objects(self) -> None:
        """Create schema/tables if not exists. Safe no-op without Snowflake."""
        if not self.sf:
            return
        db = self._db()
        if not db:
            return
        try:
            # Create governance schema if not exists
            self.sf.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db}.{GOV_SCHEMA}")
            # Requests table
            self.sf.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {db}.{GOV_SCHEMA}.{REQ_TABLE} (
                    ID STRING,
                    ASSET_FULL_NAME STRING,
                    TRIGGER_TYPE STRING,
                    CURRENT_CLASSIFICATION STRING,
                    CURRENT_C NUMBER,
                    CURRENT_I NUMBER,
                    CURRENT_A NUMBER,
                    PROPOSED_CLASSIFICATION STRING,
                    PROPOSED_C NUMBER,
                    PROPOSED_I NUMBER,
                    PROPOSED_A NUMBER,
                    STATUS STRING,
                    VERSION NUMBER,
                    JUSTIFICATION STRING,
                    CREATED_BY STRING,
                    APPROVED_BY STRING,
                    CREATED_AT TIMESTAMP_NTZ,
                    UPDATED_AT TIMESTAMP_NTZ
                )
                """
            )
            # Workflow log table
            # NOTE: This table captures status transitions and comments at each step.
            self.sf.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {db}.{GOV_SCHEMA}.{LOG_TABLE} (
                    ID STRING,
                    REQUEST_ID STRING,
                    ACTION STRING,
                    OLD_STATUS STRING,
                    NEW_STATUS STRING,
                    ACTOR STRING,
                    COMMENT STRING,
                    CREATED_AT TIMESTAMP_NTZ
                )
                """
            )
        except Exception:
            # Best-effort; do not fail UI
            pass

    def insert_request(self, req: ReclassRequest) -> str:
        """Insert request to Snowflake or no-op fallback.

        SQL INSERT point:
        INSERT INTO <DB>.DATA_CLASSIFICATION_GOVERNANCE.RECLASSIFICATION_REQUESTS (...columns...)
        VALUES (...)
        """
        # Preferred path: façade orchestrates downstream effects
        if cwf:
            try:
                rid = cwf.submit_reclassification(
                    asset_full_name=req.asset_full_name,
                    proposed=(req.proposed_label or "Review", req.proposed_c or 0, req.proposed_i or 0, req.proposed_a or 0),
                    justification=req.rationale or req.reason,
                    created_by=req.created_by,
                    trigger_type="MANUAL",
                )
                # Attachment handling placeholder: store metadata only
                self.insert_log(
                    request_id=rid,
                    action="SUBMIT",
                    actor=req.created_by,
                    comment=f"Attachment: {req.attachment_name or 'None'} (not persisted)",
                    old_status=None,
                    new_status="Pending",
                )
                return rid
            except Exception:
                pass
        if reclassification_service:
            try:
                rid = reclassification_service.submit_request(
                    asset_full_name=req.asset_full_name,
                    proposed=(req.proposed_label or "Review", req.proposed_c or 0, req.proposed_i or 0, req.proposed_a or 0),
                    justification=req.rationale or req.reason,
                    created_by=req.created_by,
                    trigger_type="MANUAL",
                )
                self.insert_log(
                    request_id=rid,
                    action="SUBMIT",
                    actor=req.created_by,
                    comment=f"Attachment: {req.attachment_name or 'None'} (not persisted)",
                    old_status=None,
                    new_status="Pending",
                )
                return rid
            except Exception:
                pass
        # Fallback direct SQL
        if not self.sf:
            # Last resort: stash in session (demo only)
            st.session_state.setdefault("_reclass_demo_requests", [])
            rid = f"demo-{len(st.session_state['_reclass_demo_requests'])+1}"
            st.session_state["_reclass_demo_requests"].append({
                "ID": rid,
                "ASSET_FULL_NAME": req.asset_full_name,
                "PROPOSED_CLASSIFICATION": req.proposed_label,
                "PROPOSED_C": req.proposed_c,
                "PROPOSED_I": req.proposed_i,
                "PROPOSED_A": req.proposed_a,
                "STATUS": "Pending",
                "JUSTIFICATION": req.rationale or req.reason,
                "CREATED_BY": req.created_by,
                "CREATED_AT": datetime.utcnow().isoformat(),
                "UPDATED_AT": datetime.utcnow().isoformat(),
            })
            return rid
        db = self._db()
        if not db:
            raise RuntimeError("No active database context to insert request.")
        # Direct insert with parameters
        params = {
            "id": st.session_state.get("_req_uuid") or str(datetime.utcnow().timestamp()).replace(".", ""),
            "full": req.asset_full_name,
            "pcls": req.proposed_label,
            "pc": req.proposed_c,
            "pi": req.proposed_i,
            "pa": req.proposed_a,
            "just": req.rationale or req.reason,
            "user": req.created_by,
        }
        self.sf.execute_non_query(
            f"""
            INSERT INTO {db}.{GOV_SCHEMA}.{REQ_TABLE}
            (ID, ASSET_FULL_NAME, TRIGGER_TYPE, CURRENT_CLASSIFICATION, CURRENT_C, CURRENT_I, CURRENT_A,
             PROPOSED_CLASSIFICATION, PROPOSED_C, PROPOSED_I, PROPOSED_A, STATUS, VERSION, JUSTIFICATION, CREATED_BY,
             CREATED_AT, UPDATED_AT)
            SELECT %(id)s, %(full)s, 'MANUAL', NULL, NULL, NULL, NULL,
                   %(pcls)s, %(pc)s, %(pi)s, %(pa)s, 'Pending', 1, %(just)s, %(user)s,
                   CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            """,
            params,
        )
        self.insert_log(params["id"], "SUBMIT", req.created_by, "Submitted", None, "Pending")
        return str(params["id"])

    def insert_log(self, request_id: str, action: str, actor: str, comment: str,
                    old_status: Optional[str], new_status: Optional[str]) -> None:
        """Insert a workflow log entry.

        SQL INSERT point:
        INSERT INTO <DB>.DATA_CLASSIFICATION_GOVERNANCE.RECLASSIFICATION_WORKFLOW_LOG (...)
        VALUES (...)
        """
        if not self.sf:
            # demo fallback
            st.session_state.setdefault("_reclass_demo_logs", [])
            st.session_state["_reclass_demo_logs"].append({
                "REQUEST_ID": request_id,
                "ACTION": action,
                "OLD_STATUS": old_status,
                "NEW_STATUS": new_status,
                "ACTOR": actor,
                "COMMENT": comment,
                "CREATED_AT": datetime.utcnow().isoformat(),
            })
            return
        db = self._db()
        if not db:
            return
        try:
            self.sf.execute_non_query(
                f"""
                INSERT INTO {db}.{GOV_SCHEMA}.{LOG_TABLE}
                (ID, REQUEST_ID, ACTION, OLD_STATUS, NEW_STATUS, ACTOR, COMMENT, CREATED_AT)
                SELECT RANDOM(), %(rid)s, %(ac)s, %(old)s, %(new)s, %(actor)s, %(com)s, CURRENT_TIMESTAMP
                """,
                {"rid": request_id, "ac": action, "old": old_status, "new": new_status, "actor": actor, "com": comment},
            )
        except Exception:
            pass

    def list_requests(self, status: Optional[str] = None, owner: Optional[str] = None,
                      dataset_like: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        """Return requests with optional filters.

        SQL SELECT point:
        SELECT * FROM <DB>.DATA_CLASSIFICATION_GOVERNANCE.RECLASSIFICATION_REQUESTS WHERE ... ORDER BY CREATED_AT DESC LIMIT <N>
        """
        # Service path preferred (maps to same table and ensures compatibility)
        try:
            if cwf and status in (None, "All"):
                rows = cwf.list_reclassification_requests(limit=limit)
            elif cwf and status in VALID_STATUSES:
                rows = cwf.list_reclassification_requests(status=status, limit=limit)
            else:
                rows = None
        except Exception:
            rows = None
        if rows is not None:
            df = pd.DataFrame(rows)
        else:
            # Direct SQL fallback
            if not self.sf:
                df = pd.DataFrame(st.session_state.get("_reclass_demo_requests", []))
            else:
                db = self._db()
                if not db:
                    return []
                where = []
                params: Dict[str, Any] = {}
                if status and status not in ("All",):
                    where.append("STATUS = %(st)s")
                    params["st"] = status
                if owner:
                    where.append("UPPER(CREATED_BY) = UPPER(%(own)s)")
                    params["own"] = owner
                if dataset_like:
                    where.append("UPPER(ASSET_FULL_NAME) LIKE UPPER(%(ds)s)")
                    params["ds"] = f"%{dataset_like}%"
                where_sql = (" WHERE " + " AND ".join(where)) if where else ""
                q = f"SELECT * FROM {db}.{GOV_SCHEMA}.{REQ_TABLE}{where_sql} ORDER BY CREATED_AT DESC LIMIT {int(limit)}"
                df = pd.DataFrame(self.sf.execute_query(q, params))
        if df is None or df.empty:
            return []
        # Apply optional filters client-side if needed
        if owner:
            df = df[df["CREATED_BY"].str.upper() == str(owner).upper()]
        if dataset_like:
            df = df[df["ASSET_FULL_NAME"].str.contains(str(dataset_like), case=False, na=False)]
        # Normalize columns for display
        for col in ["CURRENT_C","CURRENT_I","CURRENT_A","PROPOSED_C","PROPOSED_I","PROPOSED_A"]:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
        return df.to_dict(orient="records")

    def update_status(self, request_id: str, new_status: str, actor: str, comment: str = "") -> None:
        """Update request status and log the transition.

        SQL UPDATE point:
        UPDATE <DB>.DATA_CLASSIFICATION_GOVERNANCE.RECLASSIFICATION_REQUESTS SET STATUS = <>, UPDATED_AT = CURRENT_TIMESTAMP WHERE ID = <>
        """
        old_status = None
        if not self.sf and not reclassification_service:
            # demo
            lst = st.session_state.get("_reclass_demo_requests", [])
            for r in lst:
                if r.get("ID") == request_id:
                    old_status = r.get("STATUS")
                    r["STATUS"] = new_status
                    r["UPDATED_AT"] = datetime.utcnow().isoformat()
                    break
            self.insert_log(request_id, "STATUS_CHANGE", actor, comment or f"{old_status}->{new_status}", old_status, new_status)
            return
        # Prefer service transitions where possible
        try:
            if cwf and new_status == "Approved":
                cwf.approve_reclassification(request_id, actor)
                old_status = "Pending"
                self.insert_log(request_id, "APPROVE", actor, comment or "Approved", old_status, "Approved")
                return
            if cwf and new_status == "Rejected":
                cwf.reject_reclassification(request_id, actor, comment)
                old_status = "Pending"
                self.insert_log(request_id, "REJECT", actor, comment or "Rejected", old_status, "Rejected")
                return
        except Exception:
            # fall through to direct SQL update if service path fails
            pass
        if not self.sf:
            return
        db = self._db()
        if not db:
            return
        # Direct update
        try:
            self.sf.execute_non_query(
                f"UPDATE {db}.{GOV_SCHEMA}.{REQ_TABLE} SET STATUS = %(st)s, UPDATED_AT = CURRENT_TIMESTAMP WHERE ID = %(id)s",
                {"st": new_status, "id": request_id},
            )
            self.insert_log(request_id, "STATUS_CHANGE", actor, comment or f"-> {new_status}", old_status, new_status)
        except Exception:
            pass


class Backend:
    """Business orchestration for requests and workflow."""

    def __init__(self):
        self.sfops = SnowflakeOps()
        self.sfops.ensure_objects()

    def submit(self, req: ReclassRequest) -> str:
        rid = self.sfops.insert_request(req)
        if audit_service:
            try:
                audit_service.log(req.created_by, "RECLASS_REQUEST_SUBMIT_UI", "ASSET", req.asset_full_name, {"request_id": rid})
            except Exception:
                pass
        return rid

    def list(self, status: Optional[str], owner: Optional[str], dataset_like: Optional[str], limit: int = 500):
        return self.sfops.list_requests(status=status, owner=owner, dataset_like=dataset_like, limit=limit)

    def set_status(self, request_id: str, status: str, actor: str, comment: str = "") -> None:
        self.sfops.update_status(request_id, status, actor, comment)


def _list_assets(limit: int = 300) -> List[str]:
    """Best-effort dataset list for autocomplete."""
    try:
        if not snowflake_connector:
            return []
        db_rows = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
        db = db_rows[0].get("DB") if db_rows else None
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


def render_reclassification_requests(key_prefix: str = "reclass") -> None:
    """Render the Reclassification Requests sub-tab UI.

    Import and call this from your Classification Management tab, e.g.:
        from src.ui.reclassification_requests import render_reclassification_requests
        with subtab:
            render_reclassification_requests()
    """
    backend = Backend()

    st.markdown("### Reclassification Requests")

    with st.form(key=f"{key_prefix}_form", clear_on_submit=True):
        # Dataset
        assets = _list_assets(limit=400)
        asset = st.selectbox("Dataset Name (DATABASE.SCHEMA.OBJECT)", options=assets or [""], index=0)
        # Reason & Rationale
        reason = st.text_area("Reason for Reclassification", placeholder="What changed? Regulation, business need, incident, etc.")
        rationale = st.text_area("Rationale / Detailed Context", placeholder="Provide assessment, risk justification, stakeholders, and impact.")
        # Proposed CIA and label
        colc, coli, cola, coll = st.columns([1,1,1,2])
        with colc:
            pc = st.number_input("Proposed C", min_value=0, max_value=3, value=1, step=1)
        with coli:
            pi = st.number_input("Proposed I", min_value=0, max_value=3, value=1, step=1)
        with cola:
            pa = st.number_input("Proposed A", min_value=0, max_value=3, value=1, step=1)
        with coll:
            label = st.selectbox("Proposed CIA-derived Classification", options=["Low","Medium","High","Review"], index=1)
        # Attachments
        file = st.file_uploader("Attachments (optional)", type=["pdf","txt","csv","xls","xlsx","png","jpg","jpeg"], accept_multiple_files=False)
        # Requester
        requester = st.text_input("Requester (email)", value=str(st.session_state.get("user") or ""))

        submitted = st.form_submit_button("Submit Reclassification Request", type="primary")
        if submitted:
            if not asset:
                st.error("Please select a dataset.")
            elif not reason and not rationale:
                st.error("Please provide a reason or rationale.")
            elif not requester:
                st.error("Please provide your email.")
            else:
                try:
                    req = ReclassRequest(
                        id="",  # assigned by backend
                        asset_full_name=asset,
                        reason=reason,
                        proposed_c=int(pc),
                        proposed_i=int(pi),
                        proposed_a=int(pa),
                        proposed_label=label,
                        rationale=rationale,
                        attachment_name=(file.name if file else None),
                        attachment_bytes=(file.getvalue() if file else None),
                        created_by=requester,
                        status="Pending",
                    )
                    rid = backend.submit(req)
                    st.success(f"Submitted request: {rid}")
                except Exception as e:
                    st.error(f"Failed to submit request: {e}")

    st.markdown("---")
    st.markdown("#### Requests Overview")
    # Filters
    colf1, colf2, colf3, colf4 = st.columns([1.2, 1.2, 2, 1])
    with colf1:
        f_status = st.selectbox("Status", options=["All"] + VALID_STATUSES, index=0, key=f"{key_prefix}_f_status")
    with colf2:
        f_owner = st.text_input("Owner (email)", key=f"{key_prefix}_f_owner")
    with colf3:
        f_dataset = st.text_input("Dataset contains", key=f"{key_prefix}_f_ds")
    with colf4:
        f_limit = st.number_input("Limit", min_value=10, max_value=1000, value=200, step=10, key=f"{key_prefix}_f_lim")

    rows = backend.list(status=(None if f_status == "All" else f_status), owner=(f_owner or None), dataset_like=(f_dataset or None), limit=int(f_limit))
    if rows:
        df = pd.DataFrame(rows)
        show_cols = [
            "ID","ASSET_FULL_NAME","PROPOSED_CLASSIFICATION","PROPOSED_C","PROPOSED_I","PROPOSED_A",
            "STATUS","CREATED_BY","CREATED_AT","APPROVED_BY","JUSTIFICATION","TRIGGER_TYPE",
        ]
        for c in show_cols:
            if c not in df.columns:
                df[c] = None
        st.dataframe(df[show_cols], use_container_width=True, hide_index=True)

        st.markdown("#### Take Action")
        colsel, colactor = st.columns([2, 2])
        with colsel:
            sel_id = st.selectbox("Select Request ID", options=list(df["ID"].astype(str).values))
        with colactor:
            actor = st.text_input("Acting as (email)", value=str(st.session_state.get("user") or ""), key=f"{key_prefix}_actor")
        colb1, colb2, colb3 = st.columns(3)
        with colb1:
            if st.button("Mark Under Review", key=f"{key_prefix}_btn_under_review") and sel_id and actor:
                try:
                    backend.set_status(sel_id, "Under Review", actor, "Moving to review queue")
                    st.success("Status updated to Under Review")
                except Exception as e:
                    st.error(f"Failed to update: {e}")
        with colb2:
            if st.button("Approve", type="primary", key=f"{key_prefix}_btn_approve") and sel_id and actor:
                try:
                    backend.set_status(sel_id, "Approved", actor, "Approved and applied")
                    st.success("Approved and applied tags")
                except Exception as e:
                    st.error(f"Approval failed: {e}")
        with colb3:
            reject_comment = st.text_input("Rejection justification", key=f"{key_prefix}_reject_comment")
            if st.button("Reject", key=f"{key_prefix}_btn_reject") and sel_id and actor:
                try:
                    backend.set_status(sel_id, "Rejected", actor, reject_comment)
                    st.success("Rejected request")
                except Exception as e:
                    st.error(f"Rejection failed: {e}")

        # Export
        try:
            csv_bytes = df[show_cols].to_csv(index=False).encode("utf-8")
            st.download_button("Download CSV", data=csv_bytes, file_name="reclassification_requests.csv", mime="text/csv")
        except Exception:
            pass
    else:
        st.info("No reclassification requests found for the selected filters.")
