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

from src.components.classification_management import render_unified_task_action_panel

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








