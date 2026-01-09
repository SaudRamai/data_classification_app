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
import pathlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

import pandas as pd
import streamlit as st

# Ensure project root on path for `src.*` imports when running as a Streamlit page
try:
    _here = pathlib.Path(str(__file__)).resolve()
    _project_root = _here.parent.parent.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))
except Exception:
    # Fallback: if structure is flattened or __file__ fails, rely on CWD being root
    if os.getcwd() not in sys.path:
        sys.path.insert(0, os.getcwd())

# Services and connectors (best-effort imports)
try:
    from src.connectors.snowflake_connector import snowflake_connector
except Exception:  # type: ignore
    snowflake_connector = None  # type: ignore

from src.services.classification_workflow_service import classification_workflow_service as cwf

try:
    from src.services.classification_audit_service import classification_audit_service as audit_service
except Exception:  # type: ignore
    audit_service = None  # type: ignore

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
            # Decisions / Requests table (System of Record)
            self.sf.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS (
                    ID STRING, ASSET_FULL_NAME STRING, DECISION_BY STRING, DECISION_AT TIMESTAMP_NTZ,
                    SOURCE STRING, STATUS STRING, LABEL STRING, C NUMBER, I NUMBER, A NUMBER,
                    RISK_LEVEL STRING, RATIONALE STRING, DETAILS VARIANT,
                    APPROVED_BY STRING, APPROVED_AT TIMESTAMP_NTZ, UPDATED_AT TIMESTAMP_NTZ
                )
                """
            )
            # Schema drift fix: Ensure columns exist if table was created by older version
            try:
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS LABEL STRING")
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS C NUMBER")
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS I NUMBER")
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS A NUMBER")
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS SOURCE STRING")
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS STATUS STRING")
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS RATIONALE STRING")
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS DECISION_BY STRING")
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS DECISION_AT TIMESTAMP_NTZ")
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS APPROVED_BY STRING")
                self.sf.execute_non_query(f"ALTER TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS ADD COLUMN IF NOT EXISTS UPDATED_AT TIMESTAMP_NTZ")
            except Exception:
                pass
        except Exception:
            # Best-effort; do not fail UI
            pass

    def get_asset_current_state(self, asset_full_name: str) -> Dict[str, Any]:
        """Fetch current classification of a dataset from ASSETS or HISTORY."""
        if not self.sf or not asset_full_name:
            return {}
        db = self._db()
        if not db:
            return {}
        try:
            # Try ASSETS table first (Canonical state)
            q = f"""
                SELECT 
                    CLASSIFICATION_LABEL, 
                    CONFIDENTIALITY_LEVEL, 
                    INTEGRITY_LEVEL, 
                    AVAILABILITY_LEVEL
                FROM {db}.{GOV_SCHEMA}.ASSETS
                WHERE UPPER(FULLY_QUALIFIED_NAME) = UPPER(%(fqn)s)
                LIMIT 1
            """
            rows = self.sf.execute_query(q, {"fqn": asset_full_name})
            if rows:
                r = rows[0]
                # Helper to parse "C1" or 1
                def _parse_cia(val):
                    s = str(val or "0").upper().replace("C","").replace("I","").replace("A","")
                    return int(s) if s.isdigit() else 0
                
                return {
                    "label": r.get("CLASSIFICATION_LABEL"),
                    "c": _parse_cia(r.get("CONFIDENTIALITY_LEVEL")),
                    "i": _parse_cia(r.get("INTEGRITY_LEVEL")),
                    "a": _parse_cia(r.get("AVAILABILITY_LEVEL")),
                }
        except Exception:
            pass
        return {}

    def insert_request(self, req: ReclassRequest) -> str:
        """Insert request to Snowflake or no-op fallback."""
        # Preferred path: façade orchestrates downstream effects
        if cwf:
            try:
                # This now internally writes to CLASSIFICATION_DECISIONS
                rid = cwf.submit_reclassification(
                    asset_full_name=req.asset_full_name,
                    proposed=(req.proposed_label or "Review", req.proposed_c or 0, req.proposed_i or 0, req.proposed_a or 0),
                    justification=req.rationale or req.reason,
                    created_by=req.created_by,
                    trigger_type="MANUAL",
                )
                return rid
            except Exception:
                pass
        
        # Fallback direct SQL (Updated to user CLASSIFICATION_DECISIONS)
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
        
        # Direct insert into CLASSIFICATION_DECISIONS
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
            INSERT INTO {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS
            (ID, ASSET_FULL_NAME, DECISION_BY, DECISION_AT, SOURCE, STATUS, LABEL, C, I, A, RATIONALE, UPDATED_AT)
            SELECT %(id)s, %(full)s, %(user)s, CURRENT_TIMESTAMP, 'MANUAL', 'Pending', %(pcls)s, %(pc)s, %(pi)s, %(pa)s, %(just)s, CURRENT_TIMESTAMP
            """,
            params,
        )
        return str(params["id"])

    def list_requests(self, status: Optional[str] = None, owner: Optional[str] = None,
                      dataset_like: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        """Return requests with optional filters."""
        # Service path preferred
        try:
            if cwf:
                # Service now queries CLASSIFICATION_DECISIONS and aliases columns
                rows = cwf.list_reclassification_requests(status=(status if status != "All" else None), limit=limit)
                if rows is not None:
                    # Client-side filtering for owner/dataset since service might simple-filter
                    df = pd.DataFrame(rows)
                    if owner and "CREATED_BY" in df.columns:
                        df = df[df["CREATED_BY"].str.upper() == str(owner).upper()]
                    if dataset_like and "ASSET_FULL_NAME" in df.columns:
                         df = df[df["ASSET_FULL_NAME"].str.contains(str(dataset_like), case=False, na=False)]
                    return df.to_dict(orient="records")
        except Exception:
            pass
            
        # Direct SQL fallback (Updated to CLASSIFICATION_DECISIONS)
        if not self.sf:
            return st.session_state.get("_reclass_demo_requests", [])
            
        db = self._db()
        if not db:
            return []
        
        where = []
        params: Dict[str, Any] = {}
        if status and status not in ("All",):
            where.append("STATUS = %(st)s")
            params["st"] = status
        if owner:
            where.append("UPPER(DECISION_BY) = UPPER(%(own)s)")
            params["own"] = owner
        if dataset_like:
            where.append("UPPER(ASSET_FULL_NAME) LIKE UPPER(%(ds)s)")
            params["ds"] = f"%{dataset_like}%"
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        
        # We assume the UI expects legacy column names, so we alias them here
        select_clauses = [
            "ID",
            "ASSET_FULL_NAME",
            "'MANUAL' AS TRIGGER_TYPE"
        ]
        
        # Check for column existence to avoid compilation errors on legacy schemas
        try:
            cols = [x.get("name") for x in (self.sf.execute_query(f"DESC TABLE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS") or [])]
        except Exception:
            cols = []

        # Helper to safely select column or alias
        def _safe_col(col_name, alias, default_val="'Unknown'", cast=None):
            if col_name in cols:
                return f"{col_name} AS {alias}"
            else:
                return f"{default_val} AS {alias}"

        select_clauses.append(_safe_col("STATUS", "STATUS", "'Pending'"))
        select_clauses.append(_safe_col("RATIONALE", "JUSTIFICATION", "''"))
        select_clauses.append(_safe_col("DECISION_BY", "CREATED_BY", "'System'"))
        select_clauses.append(_safe_col("DECISION_AT", "CREATED_AT", "CURRENT_TIMESTAMP"))
        select_clauses.append(_safe_col("APPROVED_BY", "APPROVED_BY", "NULL"))
        select_clauses.append(_safe_col("UPDATED_AT", "UPDATED_AT", "CURRENT_TIMESTAMP"))

        if "LABEL" in cols: select_clauses.append("LABEL AS PROPOSED_CLASSIFICATION")
        else: select_clauses.append("'Unknown' AS PROPOSED_CLASSIFICATION")

        if "C" in cols: select_clauses.append("C AS PROPOSED_C")
        else: select_clauses.append("0 AS PROPOSED_C")
        
        if "I" in cols: select_clauses.append("I AS PROPOSED_I")
        else: select_clauses.append("0 AS PROPOSED_I")
        
        if "A" in cols: select_clauses.append("A AS PROPOSED_A")
        else: select_clauses.append("0 AS PROPOSED_A")
        
        q = f"""
            SELECT 
                {", ".join(select_clauses)}
            FROM {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS
            {where_sql} 
            ORDER BY DECISION_AT DESC 
            LIMIT {int(limit)}
        """
        return self.sf.execute_query(q, params) or []

    def update_status(self, request_id: str, new_status: str, actor: str, comment: str = "") -> None:
        """Update request status."""
        # Service preferred
        try:
            if cwf:
                if new_status == "Approved":
                    cwf.approve_reclassification(request_id, actor)
                    return
                if new_status == "Rejected":
                    cwf.reject_reclassification(request_id, actor, comment)
                    return
        except Exception:
            pass
            
        if not self.sf:
            return
        db = self._db()
        if not db:
            return
            
        # Direct update to CLASSIFICATION_DECISIONS
        # Note: If Approving, we should really use the service to ensure Tags/Discovery are updated.
        # This fallback is strictly DB-update only.
        try:
            self.sf.execute_non_query(
                f"""
                UPDATE {db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS 
                SET STATUS = %(st)s, 
                    UPDATED_AT = CURRENT_TIMESTAMP,
                    APPROVED_BY = %(ap)s,
                    APPROVED_AT = CURRENT_TIMESTAMP
                WHERE ID = %(id)s
                """,
                {"st": new_status, "id": request_id, "ap": actor},
            )
        except Exception:
            pass


class Backend:
    """Business orchestration for requests and workflow."""

    def __init__(self):
        self.sfops = SnowflakeOps()
        self.sfops.ensure_objects()

    def get_current(self, asset: str) -> Dict[str, Any]:
        return self.sfops.get_asset_current_state(asset)

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
    """Render the Reclassification Requests sub-tab UI."""
    backend = Backend()

    # --- Custom CSS for visual polish ---
    st.markdown("""
    <style>
    /* Hide all horizontal dividers */
    hr, .stHorizontal {
        visibility: hidden;
        height: 0 !important;
        margin: 0.2rem 0 !important;
    }
    
    div[data-testid="column"] {
        background-color: transparent;
        padding: 0.5rem;
    }
    .metric-card {
        background-color: #262730;
        border: 1px solid #41424C;
        padding: 1rem;
        border-radius: 8px;
        color: white;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .metric-title {
        color: #9CA3AF;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-value {
        color: #FFFFFF;
        font-size: 1.5rem;
        font-weight: 700;
    }
    .stSelectbox label {
        color: #E2E8F0 !important;
    }
    </style>
    """, unsafe_allow_html=True)

    st.caption("Manage classification change requests. You can submit new proposals or approve/reject pending requests.")

    tab_new, tab_manage = st.tabs(["➕ New Request", "🔍 Manage Requests"])

    # --- TAB 1: NEW REQUEST ---
    with tab_new:
        with st.container():
            st.markdown("#### Submit Reclassification Request")
            st.info("Propose a change to the classification level of a dataset. Please provide valid business justification and supporting evidence.")
            
            # --- Interactive Asset Selection (Outside Form) ---
            st.markdown("##### 1. Select Asset")
            assets = _list_assets(limit=400)
            sel_asset = st.selectbox("Find Dataset", options=[""] + assets, index=0, key=f"{key_prefix}_sel_asset")
            
            # Comparison Context
            current_state = {}
            if sel_asset:
                current_state = backend.get_current(sel_asset)
                if current_state:
                    st.markdown(f"**Current Classification for `{sel_asset}`**")
                    c1, c2, c3, c4 = st.columns(4)
                    with c1:
                        st.markdown(f"<div class='metric-card'><div class='metric-title'>Label</div><div class='metric-value'>{current_state.get('label','Unset')}</div></div>", unsafe_allow_html=True)
                    with c2:
                        st.markdown(f"<div class='metric-card'><div class='metric-title'>Confidentiality</div><div class='metric-value'>C{current_state.get('c',0)}</div></div>", unsafe_allow_html=True)
                    with c3:
                        st.markdown(f"<div class='metric-card'><div class='metric-title'>Integrity</div><div class='metric-value'>I{current_state.get('i',0)}</div></div>", unsafe_allow_html=True)
                    with c4:
                        st.markdown(f"<div class='metric-card'><div class='metric-title'>Availability</div><div class='metric-value'>A{current_state.get('a',0)}</div></div>", unsafe_allow_html=True)
                else:
                    st.warning(f"No existing classification found for `{sel_asset}`. Defaulting to New.")
            
            st.markdown("---")
            
            # Submission Form
            st.markdown("##### 2. Proposal Details")
            with st.form(key=f"{key_prefix}_real_form", clear_on_submit=True):
                st.markdown("**Proposed Classification**")
                colc, coli, cola, coll = st.columns(4)
                with colc:
                    pc = st.number_input("Confidentiality (C)", min_value=0, max_value=3, value=int(current_state.get("c", 1)), help="0=Public, 3=Restricted")
                with coli:
                    pi = st.number_input("Integrity (I)", min_value=0, max_value=3, value=int(current_state.get("i", 1)), help="0=None, 3=Critical")
                with cola:
                    pa = st.number_input("Availability (A)", min_value=0, max_value=3, value=int(current_state.get("a", 1)), help="0=None, 3=Critical")
                with coll:
                    try:
                        curr_lbl = current_state.get("label", "Internal")
                        # Handle case where curr_lbl might be None or not in list
                        if not curr_lbl or curr_lbl not in ["Public", "Internal", "Confidential", "Restricted"]:
                            curr_lbl = "Internal"
                        idx = ["Public", "Internal", "Confidential", "Restricted"].index(curr_lbl)
                    except ValueError:
                        idx = 1
                    label = st.selectbox("Overall Label", options=["Public", "Internal", "Confidential", "Restricted"], index=idx)

                st.write("") # Spacer
                reason = st.text_input("Summary Reason", placeholder="e.g., 'Data contains PII detected in recent scan'", max_chars=120)
                rationale = st.text_area("Detailed Rationale", placeholder="Provide business context, links to policy, or specific column details...", height=120)
                
                file = st.file_uploader("Evidence (Optional)", type=["pdf","txt","csv","png","jpg"], help="Attach supporting documents.")

                submitted = st.form_submit_button("🚀 Submit Request", type="primary", use_container_width=True)
                
                if submitted:
                    if not sel_asset:
                        st.error("Please select a dataset in step 1.")
                    elif not reason:
                        st.error("Please provide a summary reason.")
                    else:
                        try:
                            req = ReclassRequest(
                                id="",  # assigned by backend
                                asset_full_name=sel_asset,
                                reason=reason,
                                proposed_c=int(pc),
                                proposed_i=int(pi),
                                proposed_a=int(pa),
                                proposed_label=label,
                                rationale=rationale,
                                attachment_name=(file.name if file else None),
                                attachment_bytes=(file.getvalue() if file else None),
                                created_by=str(st.session_state.get("user") or "Unknown"),
                                status="Pending",
                            )
                            rid = backend.submit(req)
                            st.success(f"✅ Request submitted successfully! Reference ID: {rid}")
                        except Exception as e:
                            st.error(f"Failed to submit request: {e}")

    # --- TAB 2: MANAGE REQUESTS ---
    with tab_manage:
        # Filters
        st.markdown("##### 🔍 Filters & Search")
        colf1, colf2, colf3, colf4 = st.columns([1.5, 1.5, 2, 1])
        with colf1:
            f_status = st.multiselect("Status", options=VALID_STATUSES, default=["Pending", "Under Review"], key=f"{key_prefix}_f_status")
        with colf2:
            f_owner = st.text_input("Requester", placeholder="Filter by email...", key=f"{key_prefix}_f_owner")
        with colf3:
            f_dataset = st.text_input("Dataset", placeholder="Search dataset name...", key=f"{key_prefix}_f_ds")
        with colf4:
            f_limit = st.number_input("Max Rows", min_value=10, max_value=500, value=100, step=10, key=f"{key_prefix}_f_lim")
        st.write("")

        # Fetch Data
        status_arg = "All"
        if f_status and len(f_status) < len(VALID_STATUSES):
             status_arg = "All" # Fetch all and filter client-side for multi-select
        elif len(f_status) == 1:
             status_arg = f_status[0]

        rows = backend.list(status=status_arg, owner=(f_owner or None), dataset_like=(f_dataset or None), limit=int(f_limit))
        
        if rows:
            df = pd.DataFrame(rows)
            # Client-side status filter if needed
            if f_status:
                df = df[df["STATUS"].isin(f_status)]

            if df.empty:
                st.info("No requests match your filters.")
            else:
                # Add selection column
                df["Selected"] = False
                
                # Enhanced Column Config
                column_config = {
                    "ID": st.column_config.TextColumn("ID", width="small", help="Reference ID"),
                    "ASSET_FULL_NAME": st.column_config.TextColumn("Dataset", width="medium"),
                    "STATUS": st.column_config.SelectboxColumn(
                        "Status", 
                        options=VALID_STATUSES, 
                        width="small",
                        help="Workflow Status"
                    ),
                    "PROPOSED_CLASSIFICATION": st.column_config.TextColumn("Proposed Label", width="small"),
                    "CREATED_AT": st.column_config.DatetimeColumn("Submitted", format="MMM DD, HH:mm"),
                    "CREATED_BY": st.column_config.TextColumn("Requester", width="medium"),
                    "Selected": st.column_config.CheckboxColumn("Select", width="small"),
                    # Hide detail cols
                    "PROPOSED_C": None, "PROPOSED_I": None, "PROPOSED_A": None, 
                    "CURRENT_C": None, "CURRENT_I": None, "CURRENT_A": None,
                    "TRIGGER_TYPE": None, "VERSION": None, "UPDATED_AT": None,
                    "APPROVED_BY": None, "JUSTIFICATION": None
                }
                
                st.caption(f"Showing {len(df)} requests.")
                
                disp_cols = ["Selected", "STATUS", "ASSET_FULL_NAME", "PROPOSED_CLASSIFICATION", "CREATED_BY", "CREATED_AT", "ID"]
                
                edited_df = st.data_editor(
                    df,
                    column_config=column_config,
                    column_order=disp_cols,
                    hide_index=True,
                    use_container_width=True,
                    disabled=["ID", "STATUS", "ASSET_FULL_NAME", "PROPOSED_CLASSIFICATION", "CREATED_BY", "CREATED_AT"],
                    key=f"{key_prefix}_editor"
                )

                # Action Bar
                st.markdown("#### ⚡ Actions")
                selected_rows = edited_df[edited_df["Selected"] == True]
                
                if not selected_rows.empty:
                    st.write(f"selected {len(selected_rows)} request(s)")
                    
                    col_act1, col_act2, col_act3 = st.columns(3)
                    actor_email = str(st.session_state.get("user") or "unknown_user")
                    
                    with col_act1:
                         if st.button("👀 Mark Under Review", use_container_width=True):
                             for _, row in selected_rows.iterrows():
                                 backend.set_status(str(row["ID"]), "Under Review", actor_email, "Bulk update")
                             st.success("Updated status to Under Review")
                             st.rerun()
                    
                    with col_act2:
                         if st.button("✅ Approve Selected", type="primary", use_container_width=True):
                             for _, row in selected_rows.iterrows():
                                 backend.set_status(str(row["ID"]), "Approved", actor_email, "Bulk Approved")
                             st.success("Approved selected requests")
                             st.rerun()

                    with col_act3:
                         rej_reason = st.text_input("Rejection Reason", placeholder="Reason...", label_visibility="collapsed")
                         if st.button("❌ Reject Selected", type="secondary", use_container_width=True):
                             if not rej_reason:
                                 st.error("Enter a rejection reason first.")
                             else:
                                for _, row in selected_rows.iterrows():
                                    backend.set_status(str(row["ID"]), "Rejected", actor_email, rej_reason)
                                st.success("Rejected selected requests")
                                st.rerun()
                else:
                    st.info("Select rows from the table above to perform actions.")
                    
        else:
             st.info("No requests found.")
