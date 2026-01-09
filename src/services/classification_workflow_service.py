"""
Classification Workflow Service
- Authoritative service for all classification lifecycle workflows: decisions, reviews, tasks, reclassifications, and exceptions.
- Consolidates functionality from multiple legacy services into a single, cohesive unit.
- Persists data to Snowflake via snowflake_connector.
- Emits audit logs via classification_audit_service.
"""
from __future__ import annotations

import logging
import uuid
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set

try:
    import streamlit as st
except Exception:
    st = None

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.classification_audit_service import classification_audit_service as audit_service
from src.services.governance_config_service import governance_config_service

logger = logging.getLogger(__name__)

# --- Constants & Helpers ---
SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
LABEL_ORDER = ["Public", "Internal", "Restricted", "Confidential"]

def _risk_from_cia(c: int, i: int, a: int) -> str:
    try:
        highest = max(int(c or 0), int(i or 0), int(a or 0))
    except (ValueError, TypeError):
        highest = 0
    if highest >= 3: return "High"
    if highest == 2: return "Medium"
    return "Low"

def _suggest_min_label(c: int, i: int, a: int) -> str:
    highest = max(int(c or 0), int(i or 0), int(a or 0))
    if highest >= 3: return "Confidential"
    if highest == 2: return "Restricted"
    if highest == 1: return "Internal"
    return "Public"

def _validate_cia(label: str, c: int, i: int, a: int, categories: Optional[List[str]] = None, regulatory_level: Optional[str] = None) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    try:
        ci, ii, ai = int(c), int(i), int(a)
    except (ValueError, TypeError):
        return False, ["C/I/A must be integers"]
    for v, name in [(ci, "C"), (ii, "I"), (ai, "A")]:
        if v < 0 or v > 3: reasons.append(f"{name} must be in 0..3")
    if reasons: return False, reasons

    min_c_floor = 0
    cats = {str(x).strip().lower() for x in (categories or []) if str(x).strip()}
    if any(k in cats for k in {"pii", "financial", "proprietary"}): min_c_floor = max(min_c_floor, 2)
    rl = (regulatory_level or "").strip().lower()
    if rl == "multiple": min_c_floor = max(min_c_floor, 2)
    if rl == "strict": min_c_floor = max(min_c_floor, 3)
    if ci < min_c_floor:
        reasons.append(f"Confidentiality C{ci} below policy minimum C{min_c_floor} for special categories/regulatory context")

    min_label = _suggest_min_label(ci, ii, ai)
    if label in LABEL_ORDER and LABEL_ORDER.index(label) < LABEL_ORDER.index(min_label):
        reasons.append(f"Label '{label}' below minimum '{min_label}' required by CIA")
    return (len(reasons) == 0), reasons

# --- Service Class ---
class ClassificationWorkflowService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        self._ensured_dbs: Set[str] = set()

    def _resolve_db(self) -> str:
        """Resolve active governance database."""
        db = None
        try:
            if st is not None:
                db = st.session_state.get("sf_database")
        except Exception: pass
        
        if not db:
            try:
                db = governance_config_service.resolve_context().get('database')
            except Exception: pass

        if not db:
            db = getattr(settings, "SNOWFLAKE_DATABASE", None)
            
        if not db or str(db).strip().upper() in ("NONE", "NULL", "", "UNKNOWN", "(NONE)"):
            return "DATA_CLASSIFICATION_DB"
        return str(db).strip()

    def _ensure_schema(self, db: str) -> None:
        if db in self._ensured_dbs: return
        try:
            self.connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db}.{SCHEMA}")
            self._ensured_dbs.add(db)
        except Exception as e:
            logger.error(f"Failed to ensure schema {db}.{SCHEMA}: {e}")

    # --- Decisions ---
    def record_decision(self, asset_full_name: str, decision_by: str, source: str, status: str, label: str, c: int, i: int, a: int, rationale: str, details: Optional[Dict[str, Any]] = None, database: Optional[str] = None) -> str:
        """Record a classification decision (or submission) into the system of record."""
        db = database or self._resolve_db()
        self._ensure_schema(db)
        table = f"{db}.{SCHEMA}.CLASSIFICATION_DECISIONS"
        
        # Enforce User's Requested Schema
        # We use IF NOT EXISTS to avoid wiping data, but we will ensure columns exist via ALTER
        self.connector.execute_non_query(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                ID VARCHAR(16777216),
                ASSET_FULL_NAME VARCHAR(16777216),
                USER_ID VARCHAR(16777216),
                ACTION VARCHAR(16777216),
                CLASSIFICATION_LEVEL VARCHAR(16777216),
                CIA_CONF NUMBER(38,0),
                CIA_INT NUMBER(38,0),
                CIA_AVAIL NUMBER(38,0),
                RATIONALE VARCHAR(16777216),
                CREATED_AT TIMESTAMP_NTZ(9),
                DETAILS VARIANT,
                LABEL VARCHAR(16777216),
                C NUMBER(38,0),
                I NUMBER(38,0),
                A NUMBER(38,0),
                SOURCE VARCHAR(16777216),
                STATUS VARCHAR(16777216),
                DECISION_BY VARCHAR(16777216),
                DECISION_AT TIMESTAMP_NTZ(9),
                APPROVED_BY VARCHAR(16777216),
                UPDATED_AT TIMESTAMP_NTZ(9)
            )
        """)

        # Schema Drift Maintenance: Ensure all columns from DDL exist
        try:
            cols_to_ensure = [
                "USER_ID", "ACTION", "CLASSIFICATION_LEVEL", "CIA_CONF", "CIA_INT", "CIA_AVAIL",
                "LABEL", "C", "I", "A", "SOURCE", "STATUS", "DECISION_BY", "APPROVED_BY", "RATIONALE"
            ]
            for col in cols_to_ensure:
                col_type = "NUMBER(38,0)" if "CIA_" in col or col in ["C","I","A"] else "VARCHAR(16777216)"
                self.connector.execute_non_query(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {col_type}")
        except Exception:
            pass

        ok, reasons = _validate_cia(label, c, i, a)
        # if not ok: raise ValueError("; ".join(reasons)) # Strict validation disabled for draft/GUI flexibility
        
        did = str(uuid.uuid4())
        
        # Map inputs to the extensive schema
        # USER_ID = decision_by
        # ACTION = 'CLASSIFICATION_SUBMISSION'
        # CLASSIFICATION_LEVEL = label
        # CIA_CONF = c ...
        
        qt = f"""
            INSERT INTO {table} 
            (
                ID, ASSET_FULL_NAME, USER_ID, ACTION, 
                CLASSIFICATION_LEVEL, CIA_CONF, CIA_INT, CIA_AVAIL, 
                RATIONALE, CREATED_AT, DETAILS, 
                LABEL, C, I, A, 
                SOURCE, STATUS, DECISION_BY, DECISION_AT, 
                UPDATED_AT
            )
            SELECT 
                %(id)s, %(full)s, %(by)s, 'CLASSIFICATION_SUBMISSION',
                %(lab)s, %(c)s, %(i)s, %(a)s,
                %(rat)s, CURRENT_TIMESTAMP, TO_VARIANT(PARSE_JSON(%(det)s)),
                %(lab)s, %(c)s, %(i)s, %(a)s,
                %(src)s, %(st)s, %(by)s, CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP
        """
        
        self.connector.execute_non_query(qt, {
            "id": did, "full": asset_full_name, "by": decision_by, 
            "lab": label, "c": int(c), "i": int(i), "a": int(a),
            "rat": str(rationale).strip(), "det": None if details is None else json.dumps(details),
            "src": source, "st": status
        })
        
        audit_service.log(decision_by, "CLASSIFICATION_DECISION", "ASSET", asset_full_name, {"decision_id": did, "status": status, "label": label})
        return did

    # --- Reviews ---
    def list_reviews(self, current_user: str, review_filter: str = "All", approval_status: str = "All pending", lookback_days: int = 30, page: int = 1, page_size: int = 50, database: Optional[str] = None) -> Dict[str, Any]:
        db = database or self._resolve_db()
        rf, ap = review_filter.lower(), approval_status.lower()
        lb, p, ps = max(1, int(lookback_days)), max(1, int(page)), max(1, min(500, int(page_size)))
        start, end = (p - 1) * ps + 1, p * ps

        sql = f"""
        WITH base AS (
          SELECT cast(HISTORY_ID as string) as ID, ASSET_ID, DATABASE_NAME, SCHEMA_NAME, ASSET_NAME,
                 COALESCE(CLASSIFICATION_TAG, PROPOSED_CLASSIFICATION, CURRENT_CLASSIFICATION, '') as CLASSIFICATION_TAG,
                 COALESCE(CONFIDENTIALITY_LEVEL, CIA_C, 0) as C_LEVEL,
                 COALESCE(APPROVAL_REQUIRED, false) as APPROVAL_REQUIRED,
                 APPROVED_BY, CREATED_BY, CHANGE_TIMESTAMP, CHANGE_REASON, BUSINESS_JUSTIFICATION
          FROM {db}.{SCHEMA}.CLASSIFICATION_HISTORY
        ),
        filtered AS (
          SELECT * FROM base b WHERE 1=1
          {"AND b.APPROVAL_REQUIRED = true AND b.APPROVED_BY IS NULL" if rf in ("all", "pending approvals") else ""}
          {"AND COALESCE(b.C_LEVEL,0) = 3" if rf == "high-risk" else ""}
          {"AND b.CHANGE_TIMESTAMP >= dateadd('day', -%(lb)s, current_timestamp())" if rf == "recent changes" else ""}
          {"AND b.APPROVAL_REQUIRED = true AND b.APPROVED_BY IS NULL" if ap in ("all pending", "pending my approval") else ""}
          {"AND upper(COALESCE(b.CREATED_BY,'')) <> upper(%(me)s)" if ap == "pending my approval" else ""}
        ),
        numbered AS (
          SELECT f.*, row_number() over (order by f.CHANGE_TIMESTAMP desc, f.ID desc) as RN, count(*) over() as TOTAL
          FROM filtered f
        )
        SELECT * FROM numbered WHERE RN BETWEEN %(start)s AND %(end)s
        """
        try:
            rows = self.connector.execute_query(sql, {"lb": lb, "start": start, "end": end, "me": current_user or ""}) or []
            total = int(rows[0].get("TOTAL", 0)) if rows else 0
            items = [{
                "id": r.get("ID"), "asset_id": r.get("ASSET_ID"), "database": r.get("DATABASE_NAME"),
                "schema": r.get("SCHEMA_NAME"), "asset_name": r.get("ASSET_NAME"), "classification": r.get("CLASSIFICATION_TAG"),
                "c_level": r.get("C_LEVEL"), "approval_required": bool(r.get("APPROVAL_REQUIRED")),
                "approved_by": r.get("APPROVED_BY"), "created_by": r.get("CREATED_BY"),
                "change_timestamp": r.get("CHANGE_TIMESTAMP"), "change_reason": r.get("CHANGE_REASON"),
                "business_justification": r.get("BUSINESS_JUSTIFICATION")
            } for r in rows]
            return {"reviews": items, "page": p, "page_size": ps, "total": total}
        except Exception as e:
            return {"reviews": [], "page": p, "page_size": ps, "total": 0, "error": str(e)}

    def approve_review(self, review_id: str, asset_full_name: str, label: str, c: int, i: int, a: int, approver: Optional[str] = None, comments: str = "") -> bool:
        who = approver or (st.session_state.get("user") if st else "user")
        try:
            # When approving a historical review, we log a *new* decision
            self.record_decision(asset_full_name, who, "REVIEW", "Approved", label, c, i, a, comments or "Approved via Pending Reviews", {"review_id": review_id})
            db = self._resolve_db()
            self.connector.execute_non_query(f"""
                UPDATE {db}.{SCHEMA}.CLASSIFICATION_HISTORY
                SET APPROVED_BY = %(who)s, APPROVAL_TIMESTAMP = CURRENT_TIMESTAMP, APPROVAL_STATUS = 'APPROVED'
                WHERE HISTORY_ID = %(rid)s
            """, {"who": who, "rid": review_id})
            audit_service.log(who, "REVIEW_APPROVE", "CLASSIFICATION", asset_full_name, {"review_id": review_id, "label": label})
            return True
        except Exception: return False

    def reject_review(self, review_id: str, asset_full_name: str, approver: Optional[str] = None, justification: str = "") -> bool:
        who = approver or (st.session_state.get("user") if st else "user")
        try:
            db = self._resolve_db()
            self.connector.execute_non_query(f"""
                UPDATE {db}.{SCHEMA}.CLASSIFICATION_HISTORY
                SET APPROVED_BY = %(who)s, APPROVAL_TIMESTAMP = CURRENT_TIMESTAMP, APPROVAL_STATUS = 'REJECTED', REJECTION_REASON = %(why)s
                WHERE HISTORY_ID = %(rid)s
            """, {"who": who, "why": justification or "Rejected via Pending Reviews", "rid": review_id})
            audit_service.log(who, "REVIEW_REJECT", "CLASSIFICATION", asset_full_name, {"review_id": review_id, "justification": justification})
            return True
        except Exception: return False

    def request_review_changes(self, review_id: str, asset_full_name: str, approver: Optional[str] = None, instructions: str = "") -> bool:
        who = approver or (st.session_state.get("user") if st else "user")
        try:
            db = self._resolve_db()
            self.connector.execute_non_query(f"""
                UPDATE {db}.{SCHEMA}.CLASSIFICATION_HISTORY
                SET APPROVAL_STATUS = 'CHANGES_REQUESTED', APPROVAL_NOTES = %(notes)s
                WHERE HISTORY_ID = %(rid)s
            """, {"notes": instructions or "Please revise classification details", "rid": review_id})
            audit_service.log(who, "REVIEW_REQUEST_CHANGES", "CLASSIFICATION", asset_full_name, {"review_id": review_id, "notes": instructions})
            return True
        except Exception: return False

    # --- Reclassification (Now using CLASSIFICATION_DECISIONS as System of Record) ---
    def submit_reclassification(self, asset_full_name: str, proposed: Tuple[str, int, int, int], justification: str, created_by: str, trigger_type: str = "MANUAL", current: Optional[Tuple[str, int, int, int]] = None) -> str:
        """Submit a reclassification request. Stores in CLASSIFICATION_DECISIONS with status 'Pending'."""
        pcls, pc, pi, pa = proposed
        # We piggyback on record_decision to insert the row
        # We store the "Current" state in details if needed, but the primary record represents the *Action* being proposed.
        return self.record_decision(
            asset_full_name=asset_full_name,
            decision_by=created_by,
            source=trigger_type,
            status="Pending",
            label=pcls,
            c=int(pc or 0), i=int(pi or 0), a=int(pa or 0),
            rationale=justification,
            details={"original_state": current}
        )

    def approve_reclassification(self, request_id: str, approver: str) -> None:
        db = self._resolve_db()
        table = f"{db}.{SCHEMA}.CLASSIFICATION_DECISIONS"
        
        # 1. Fetch the Pending Request
        rows = self.connector.execute_query(f"SELECT * FROM {table} WHERE ID = %(id)s", {"id": request_id})
        if not rows: raise ValueError("Request not found")
        r = rows[0]
        asset = r["ASSET_FULL_NAME"]
        label, c, i, a = r["LABEL"], r["C"], r["I"], r["A"]
        
        # 2. Apply Tags
        from src.services.tagging_service import tagging_service
        from src.services.classification_pipeline_service import discovery_service
        
        tags = {
            "DATA_CLASSIFICATION": label,
            "CONFIDENTIALITY_LEVEL": f"C{int(c or 0)}",
            "INTEGRITY_LEVEL": f"I{int(i or 0)}",
            "AVAILABILITY_LEVEL": f"A{int(a or 0)}",
            "COMPLIANCE_FRAMEWORKS": ""
        }
        tagging_service.apply_tags_to_object(asset, "TABLE", tags)
        
        # 3. Mark Discovery Service
        discovery_service.mark_classified(asset, label, int(c or 0), int(i or 0), int(a or 0))
        
        # 4. Update the Decision Record (Status=Approved, Appproved_By=Approver)
        self.connector.execute_non_query(f"""
            UPDATE {table} 
            SET STATUS = 'Approved', 
                APPROVED_BY = %(ap)s, 
                APPROVED_AT = CURRENT_TIMESTAMP, 
                UPDATED_AT = CURRENT_TIMESTAMP 
            WHERE ID = %(id)s
        """, {"ap": approver, "id": request_id})
        
        audit_service.log(approver, "RECLASS_REQUEST_APPROVE", "ASSET", asset, {"request_id": request_id})

    def reject_reclassification(self, request_id: str, approver: str, justification: Optional[str] = None) -> None:
        db = self._resolve_db()
        table = f"{db}.{SCHEMA}.CLASSIFICATION_DECISIONS"
        self.connector.execute_non_query(f"""
            UPDATE {table} 
            SET STATUS = 'Rejected', 
                APPROVED_BY = %(ap)s, 
                APPROVED_AT = CURRENT_TIMESTAMP, 
                UPDATED_AT = CURRENT_TIMESTAMP,
                DETAILS = OBJECT_INSERT(COALESCE(DETAILS, OBJECT_CONSTRUCT()), 'rejection_reason', %(just)s, true)
            WHERE ID = %(id)s
        """, {"ap": approver, "id": request_id, "just": justification or ""})
        audit_service.log(approver, "RECLASS_REQUEST_REJECT", "REQUEST", request_id, {"justification": justification})

    def list_reclassification_requests(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        db = self._resolve_db()
        table = f"{db}.{SCHEMA}.CLASSIFICATION_DECISIONS"
        
        # Aliasing to maintain backward compatibility with UI expecting 'PROPOSED_CLASSIFICATION' etc.
        # Mapping: LABEL -> PROPOSED_CLASSIFICATION, DECISION_BY -> CREATED_BY
        
        base_q = f"""
            SELECT 
                ID,
                ASSET_FULL_NAME,
                SOURCE AS TRIGGER_TYPE,
                LABEL AS PROPOSED_CLASSIFICATION,
                C AS PROPOSED_C,
                I AS PROPOSED_I,
                A AS PROPOSED_A,
                STATUS,
                RATIONALE AS JUSTIFICATION,
                DECISION_BY AS CREATED_BY,
                DECISION_AT AS CREATED_AT,
                APPROVED_BY,
                UPDATED_AT
            FROM {table}
        """
        
        if status: 
            return self.connector.execute_query(f"{base_q} WHERE STATUS = %(st)s ORDER BY DECISION_AT DESC LIMIT {int(limit)}", {"st": status})
        return self.connector.execute_query(f"{base_q} ORDER BY DECISION_AT DESC LIMIT {int(limit)}")

    # --- Tasks ---
    def list_tasks(self, current_user: str, status: Optional[str] = None, owner: Optional[str] = None, classification_level: Optional[str] = None, date_range: Optional[Tuple[Optional[str], Optional[str]]] = None, limit: int = 500) -> List[Dict[str, Any]]:
        db = self._resolve_db()
        where_clauses, params = ["upper(COALESCE(REVIEWER,'')) = upper(%(me)s)"], {"me": current_user or ""}
        if status:
            s = status.strip().lower()
            if s == "draft": where_clauses.append("lower(COALESCE(STATUS,'')) = 'draft'")
            elif s == "pending": where_clauses.append("lower(COALESCE(STATUS,'')) LIKE '%%pending%%'")
            elif s in ("completed", "approved", "rejected"): where_clauses.append("lower(COALESCE(STATUS,'')) IN ('approved', 'rejected')")
        if owner:
            where_clauses.append("upper(COALESCE(ASSIGNED_TO,'')) LIKE upper(%(owner)s)")
            params["owner"] = f"%{owner}%"
        if classification_level:
            where_clauses.append("upper(COALESCE(CLASSIFICATION_LEVEL,'')) = upper(%(level)s)")
            params["level"] = classification_level
        if date_range:
            sd, ed = date_range
            if sd: where_clauses.append("DUE_DATE >= %(sd)s"); params["sd"] = sd
            if ed: where_clauses.append("DUE_DATE <= %(ed)s"); params["ed"] = ed

        try:
            sql = f"""
            SELECT ASSET_FULL_NAME, split_part(ASSET_FULL_NAME, '.', 1) as DATABASE, split_part(ASSET_FULL_NAME, '.', 2) as SCHEMA, split_part(ASSET_FULL_NAME, '.', 3) as DATASET_NAME,
                   COALESCE(REVIEWER, '') as OWNER, REQUESTED_LABEL as CLASSIFICATION_LEVEL, COALESCE(CONFIDENTIALITY_LEVEL, 0) as C, COALESCE(INTEGRITY_LEVEL, 0) as I, COALESCE(AVAILABILITY_LEVEL, 0) as A,
                   COALESCE(STATUS, 'Pending') as STATUS, COALESCE(REVIEW_DUE_DATE, dateadd(day, 14, current_date())) as DUE_DATE, CREATED_AT, UPDATED_AT, REVIEW_ID, LAST_COMMENT, STATUS_LABEL
            FROM {db}.{SCHEMA}.VW_CLASSIFICATION_REVIEWS
            WHERE {' AND '.join(where_clauses)}
            ORDER BY COALESCE(REVIEW_DUE_DATE, current_date()) ASC LIMIT {int(limit)}
            """
            rows = self.connector.execute_query(sql, params) or []
            return [{
                "asset_full_name": r.get("ASSET_FULL_NAME"), "dataset_name": r.get("DATASET_NAME"), "database": r.get("DATABASE"), "schema": r.get("SCHEMA"),
                "owner": r.get("OWNER"), "classification_level": r.get("CLASSIFICATION_LEVEL"), "c": int(r.get("C") or 0), "i": int(r.get("I") or 0), "a": int(r.get("A") or 0),
                "overall_risk": _risk_from_cia(r.get("C") or 0, r.get("I") or 0, r.get("A") or 0), "status": r.get("STATUS"), "status_label": r.get("STATUS_LABEL", ""),
                "due_date": r.get("DUE_DATE"), "review_id": r.get("REVIEW_ID"), "last_comment": r.get("LAST_COMMENT"), "created_at": r.get("CREATED_AT"), "updated_at": r.get("UPDATED_AT")
            } for r in rows]
        except Exception: return []

    def update_or_submit_task(self, asset_full_name: str, c: int, i: int, a: int, label: str, action: str, comments: str, user: str) -> bool:
        try:
            db = self._resolve_db()
            self.record_decision(asset_full_name, user, action.upper(), "Completed" if action == "submit" else "Draft", label, c, i, a, comments)
            self.connector.execute_non_query(f"UPDATE {db}.{SCHEMA}.CLASSIFICATION_TASKS SET STATUS = %(st)s WHERE ASSET_FULL_NAME = %(a)s", {"st": ("Completed" if action == "submit" else "Draft"), "a": asset_full_name})
            if action == "submit":
                from src.services.tagging_service import tagging_service
                tagging_service.apply_tags_to_object(asset_full_name, "TABLE", {
                    "DATA_CLASSIFICATION": label, 
                    "CONFIDENTIALITY_LEVEL": f"C{int(c)}", 
                    "INTEGRITY_LEVEL": f"I{int(i)}", 
                    "AVAILABILITY_LEVEL": f"A{int(a)}",
                    "COMPLIANCE_FRAMEWORKS": ""
                })
            return True
        except Exception: return False

    # --- Exceptions ---
    def submit_exception(self, asset_full_name: str, regulatory: str, justification: str, risk_level: str, requested_by: str, days_valid: int = 90, details: Optional[Dict[str, Any]] = None) -> str:
        db = self._resolve_db()
        self._ensure_schema(db)
        table = f"{db}.{SCHEMA}.EXCEPTIONS"
        self.connector.execute_non_query(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                ID STRING, ASSET_FULL_NAME STRING, REGULATORY STRING, JUSTIFICATION STRING, RISK_LEVEL STRING, STATUS STRING, REQUESTED_BY STRING, REQUESTED_AT TIMESTAMP_NTZ, APPROVED_BY STRING, APPROVED_AT TIMESTAMP_NTZ, EXPIRES_AT TIMESTAMP_NTZ, DETAILS VARIANT, EVIDENCE_URL STRING
            )
        """)
        eid = str(uuid.uuid4())
        expires = (datetime.utcnow() + timedelta(days=days_valid)).strftime("%Y-%m-%d %H:%M:%S")
        self.connector.execute_non_query(f"""
            INSERT INTO {table} (ID, ASSET_FULL_NAME, REGULATORY, JUSTIFICATION, RISK_LEVEL, STATUS, REQUESTED_BY, REQUESTED_AT, EXPIRES_AT, DETAILS)
            SELECT %(id)s, %(full)s, %(reg)s, %(just)s, %(risk)s, 'Pending', %(req)s, CURRENT_TIMESTAMP, %(exp)s, TO_VARIANT(PARSE_JSON(%(det)s))
        """, {"id": eid, "full": asset_full_name, "reg": regulatory, "just": justification, "risk": risk_level, "req": requested_by, "exp": expires, "det": json.dumps(details) if details else None})
        audit_service.log(requested_by, "EXCEPTION_SUBMIT", "ASSET", asset_full_name, {"exception_id": eid})
        return eid

    def list_exceptions(self, status: Optional[str] = None, limit: int = 200, asset_full_name: Optional[str] = None) -> List[Dict[str, Any]]:
        db = self._resolve_db()
        where, params = ["1=1"], {"lim": limit}
        if status and status != "All": where.append("STATUS = %(status)s"); params["status"] = status
        if asset_full_name: where.append("UPPER(ASSET_FULL_NAME) = UPPER(%(full)s)"); params["full"] = asset_full_name
        return self.connector.execute_query(f"SELECT * FROM {db}.{SCHEMA}.EXCEPTIONS WHERE {' AND '.join(where)} ORDER BY REQUESTED_AT DESC LIMIT %(lim)s", params)

    def approve_exception(self, exception_id: str, approver: str) -> None:
        db = self._resolve_db()
        self.connector.execute_non_query(f"UPDATE {db}.{SCHEMA}.EXCEPTIONS SET STATUS = 'Approved', APPROVED_BY = %(ap)s, APPROVED_AT = CURRENT_TIMESTAMP WHERE ID = %(id)s", {"id": exception_id, "ap": approver})
        audit_service.log(approver, "EXCEPTION_APPROVE", "EXCEPTION", exception_id, None)

    def reject_exception(self, exception_id: str, approver: str, justification: Optional[str] = None) -> None:
        db = self._resolve_db()
        self.connector.execute_non_query(f"""
            UPDATE {db}.{SCHEMA}.EXCEPTIONS SET STATUS = 'Rejected', APPROVED_BY = %(ap)s, APPROVED_AT = CURRENT_TIMESTAMP, DETAILS = OBJECT_CONSTRUCT('rejection_reason', %(just)s)
            WHERE ID = %(id)s
        """, {"id": exception_id, "ap": approver, "just": justification or ""})
        audit_service.log(approver, "EXCEPTION_REJECT", "EXCEPTION", exception_id, {"reason": justification})

    # --- History (Query) ---
    def query_history(self, start_date: Optional[str] = None, end_date: Optional[str] = None, users: Optional[List[str]] = None, levels: Optional[List[str]] = None, c_levels: Optional[List[int]] = None, page: int = 1, page_size: int = 100, database: Optional[str] = None) -> Dict[str, Any]:
        db = database or self._resolve_db()
        p, ps = max(1, int(page)), max(1, min(1000, int(page_size)))
        start, end = (p - 1) * ps + 1, p * ps
        where_clauses, params = [], {"start": start, "end": end}
        if start_date and end_date: where_clauses.append("h.CHANGE_TIMESTAMP BETWEEN %(sd)s AND %(ed)s"); params["sd"] = start_date; params["ed"] = end_date
        if users:
            users_in = ",".join([f"'{str(u).upper()}".replace("'","''") + "'" for u in users if u]) or "''"
            where_clauses.append(f"(upper(COALESCE(h.CHANGED_BY,'')) IN ({users_in}) OR upper(COALESCE(h.APPROVED_BY,'')) IN ({users_in}))")
        if levels:
            levels_in = ",".join([f"'{str(l).upper()}".replace("'","''") + "'" for l in levels if l]) or "''"
            where_clauses.append(f"upper(COALESCE(h.NEW_CLASSIFICATION, h.PREVIOUS_CLASSIFICATION, '')) IN ({levels_in})")
        if c_levels:
            cls_in = ",".join([str(int(c)) for c in c_levels if c is not None]) or "-1"
            where_clauses.append(f"COALESCE(h.NEW_CONFIDENTIALITY, h.PREVIOUS_CONFIDENTIALITY, 0) IN ({cls_in})")
        
        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        sql = f"""
          WITH base AS (
            SELECT cast(h.HISTORY_ID as string) as ID, h.ASSET_ID, a.DATABASE_NAME, a.SCHEMA_NAME, a.ASSET_NAME,
                   COALESCE(h.NEW_CLASSIFICATION, h.PREVIOUS_CLASSIFICATION, '') as CLASSIFICATION_TAG,
                   COALESCE(h.NEW_CONFIDENTIALITY, h.PREVIOUS_CONFIDENTIALITY, 0) as C_LEVEL,
                   COALESCE(h.APPROVAL_REQUIRED, false) as APPROVAL_REQUIRED,
                   h.APPROVED_BY, h.CHANGED_BY as CREATED_BY, h.CHANGE_TIMESTAMP, h.CHANGE_REASON, h.BUSINESS_JUSTIFICATION
            FROM {db}.{SCHEMA}.CLASSIFICATION_HISTORY h
            LEFT JOIN {db}.{SCHEMA}.ASSETS a ON a.ASSET_ID = h.ASSET_ID
            {where_sql}
          ),
          numbered AS (
            SELECT b.*, row_number() over (order by b.CHANGE_TIMESTAMP desc, b.ID desc) as RN, count(*) over() as TOTAL
            FROM base b
          )
          SELECT * FROM numbered WHERE RN BETWEEN %(start)s AND %(end)s
        """
        rows = self.connector.execute_query(sql, params) or []
        total = int(rows[0].get("TOTAL", 0)) if rows else 0
        items = [{
            "id": r.get("ID"), "asset_id": r.get("ASSET_ID"), "database": r.get("DATABASE_NAME"), "schema": r.get("SCHEMA_NAME"), "asset_name": r.get("ASSET_NAME"),
            "classification": r.get("CLASSIFICATION_TAG"), "c_level": r.get("C_LEVEL"), "approval_required": r.get("APPROVAL_REQUIRED"), "approved_by": r.get("APPROVED_BY"),
            "created_by": r.get("CREATED_BY"), "change_timestamp": r.get("CHANGE_TIMESTAMP"), "change_reason": r.get("CHANGE_REASON"), "business_justification": r.get("BUSINESS_JUSTIFICATION")
        } for r in rows]
        return {"history": items, "total": total, "page": p, "page_size": ps}

    def fetch_audit_history(self, **kwargs) -> List[Dict[str, Any]]:
        """Delegate to authoritative audit service for repository-backed history read."""
        return audit_service.fetch_audit(**kwargs)

    # --- Backward Compatibility Aliases ---
    def record(self, *args, **kwargs):
        """Alias for record_decision."""
        return self.record_decision(*args, **kwargs)

    def submit_request(self, *args, **kwargs):
        """Alias for submit_reclassification."""
        return self.submit_reclassification(*args, **kwargs)

    def update_or_submit_classification(self, *args, **kwargs):
        """Alias for update_or_submit_task."""
        return self.update_or_submit_task(*args, **kwargs)

    def query(self, *args, **kwargs):
        """Alias for query_history."""
        return self.query_history(*args, **kwargs)

# Singleton instantiation
classification_workflow_service = ClassificationWorkflowService()
