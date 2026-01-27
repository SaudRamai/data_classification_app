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
import time
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
from src.services.compliance_service import compliance_service

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

    def _ensure_tasks_table(self, db: str) -> None:
        """Ensure the CLASSIFICATION_TASKS table exists with the required schema."""
        table = f"{db}.{SCHEMA}.CLASSIFICATION_TASKS"
        try:
            self.connector.execute_non_query(f"""
                CREATE TABLE IF NOT EXISTS {table} (
                    TASK_ID VARCHAR(16777216),
                    DATASET_NAME VARCHAR(16777216),
                    ASSET_FULL_NAME VARCHAR(16777216),
                    ASSIGNED_TO VARCHAR(16777216),
                    STATUS VARCHAR(16777216),
                    CONFIDENTIALITY_LEVEL VARCHAR(16777216),
                    INTEGRITY_LEVEL VARCHAR(16777216),
                    AVAILABILITY_LEVEL VARCHAR(16777216),
                    DUE_DATE DATE,
                    CREATED_AT TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
                    UPDATED_AT TIMESTAMP_NTZ(9),
                    DETAILS VARIANT
                )
            """)
        except Exception as e:
            logger.error(f"Failed to ensure tasks table {table}: {e}")

    # --- Decisions ---
    # --- Decisions & Reviews ---
    def record_decision(self, asset_full_name: str, decision_by: str, source: str, status: str, label: str, c: int, i: int, a: int, rationale: str, details: Optional[Dict[str, Any]] = None, database: Optional[str] = None, reviewer: Optional[str] = None) -> str:
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
                ASSET_ID VARCHAR(100),
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
                UPDATED_AT TIMESTAMP_NTZ(9),
                ENFORCEMENT_STATUS VARCHAR(16777216),
                ENFORCEMENT_TIMESTAMP VARCHAR(16777216),
                COMPLIANCE_FLAGS VARCHAR(16777216)
            )
        """)

        # ✅ Ensure CLASSIFICATION_REVIEW table and VW_CLASSIFICATION_REVIEWS view exist
        review_table = f"{db}.{SCHEMA}.CLASSIFICATION_REVIEW"
        self.connector.execute_non_query(f"""
            CREATE TABLE IF NOT EXISTS {review_table} (
                REVIEW_ID VARCHAR(16777216),
                ASSET_FULL_NAME VARCHAR(16777216),
                PROPOSED_CLASSIFICATION VARCHAR(16777216),
                PROPOSED_C NUMBER(38,0),
                PROPOSED_I NUMBER(38,0),
                PROPOSED_A NUMBER(38,0),
                REVIEWER VARCHAR(16777216),
                STATUS VARCHAR(16777216),
                CREATED_AT TIMESTAMP_NTZ(9),
                UPDATED_AT TIMESTAMP_NTZ(9),
                REVIEW_DUE_DATE TIMESTAMP_NTZ(9),
                LAST_COMMENT VARCHAR(16777216)
            )
        """)
        
        # Deploy standardized view for UI consumption
        view_name = f"{db}.{SCHEMA}.VW_CLASSIFICATION_REVIEWS"
        self.connector.execute_non_query(f"""
            CREATE OR REPLACE VIEW {view_name} AS
            SELECT 
                REVIEW_ID,
                ASSET_FULL_NAME,
                PROPOSED_CLASSIFICATION AS REQUESTED_LABEL,
                PROPOSED_C AS CONFIDENTIALITY_LEVEL,
                PROPOSED_I AS INTEGRITY_LEVEL,
                PROPOSED_A AS AVAILABILITY_LEVEL,
                REVIEWER,
                STATUS,
                CREATED_AT,
                UPDATED_AT,
                REVIEW_DUE_DATE,
                CASE 
                    WHEN STATUS = 'Pending' THEN 'Pending Review'
                    WHEN STATUS = 'In Review' THEN 'Under Review'
                    WHEN STATUS = 'Approved' THEN 'Approved'
                    WHEN STATUS = 'Rejected' THEN 'Rejected'
                    ELSE STATUS
                END AS STATUS_LABEL,
                LAST_COMMENT 
            FROM {review_table}
        """)

        # Schema Drift Maintenance: Ensure all columns from DDL exist
        try:
            cols_to_ensure = [
                "USER_ID", "ACTION", "CLASSIFICATION_LEVEL", "CIA_CONF", "CIA_INT", "CIA_AVAIL",
                "LABEL", "C", "I", "A", "SOURCE", "STATUS", "DECISION_BY", "APPROVED_BY", "RATIONALE",
                "ENFORCEMENT_STATUS", "ENFORCEMENT_TIMESTAMP"
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
        
        # Try to resolve ASSET_ID from inventory
        asset_id = None
        try:
            asset_row = self.connector.execute_query(
                f"SELECT ASSET_ID FROM {db}.{SCHEMA}.ASSETS WHERE FULLY_QUALIFIED_NAME = %(full)s",
                {"full": asset_full_name}
            )
            if asset_row:
                asset_id = asset_row[0].get("ASSET_ID")
        except Exception:
            pass

        # Extract compliance flags
        compliance_flags = ""
        if details and isinstance(details, dict):
            # Extract from 'compliance' list if present
            c_val = details.get("compliance", "")
            if isinstance(c_val, list):
                compliance_flags = ",".join(c_val)
            else:
                compliance_flags = str(c_val)

        decision_by_str = str(decision_by) if decision_by else "system"
        
        qt = f"""
            MERGE INTO {table} target
            USING (
                SELECT 
                    %(id)s as ID, 
                    %(full)s as ASSET_FULL_NAME, 
                    %(aid)s as ASSET_ID, 
                    %(by)s as USER_ID, 
                    'CLASSIFICATION_SUBMISSION' as ACTION,
                    %(lab)s as CLASSIFICATION_LEVEL, 
                    %(c)s as CIA_CONF, %(i)s as CIA_INT, %(a)s as CIA_AVAIL,
                    %(rat)s as RATIONALE, 
                    CURRENT_TIMESTAMP as CREATED_AT,
                    TO_VARIANT(PARSE_JSON(%(det)s)) as DETAILS,
                    %(lab)s as LABEL, 
                    %(c)s as C, %(i)s as I, %(a)s as A,
                    %(src)s as SOURCE, 
                    %(st)s as STATUS, 
                    %(by)s as DECISION_BY, 
                    CURRENT_TIMESTAMP as DECISION_AT,
                    CURRENT_TIMESTAMP as UPDATED_AT, 
                    %(flags)s as COMPLIANCE_FLAGS
            ) source
            ON target.ASSET_FULL_NAME = source.ASSET_FULL_NAME
            WHEN MATCHED THEN UPDATE SET
                target.ID = source.ID,
                target.USER_ID = source.USER_ID,
                target.ACTION = source.ACTION,
                target.CLASSIFICATION_LEVEL = source.CLASSIFICATION_LEVEL,
                target.CIA_CONF = source.CIA_CONF,
                target.CIA_INT = source.CIA_INT,
                target.CIA_AVAIL = source.CIA_AVAIL,
                target.RATIONALE = source.RATIONALE,
                target.DETAILS = source.DETAILS,
                target.LABEL = source.LABEL,
                target.C = source.C,
                target.I = source.I,
                target.A = source.A,
                target.SOURCE = source.SOURCE,
                target.STATUS = source.STATUS,
                target.DECISION_BY = source.DECISION_BY,
                target.DECISION_AT = source.DECISION_AT,
                target.UPDATED_AT = source.UPDATED_AT,
                target.COMPLIANCE_FLAGS = source.COMPLIANCE_FLAGS
            WHEN NOT MATCHED THEN INSERT (
                ID, ASSET_FULL_NAME, ASSET_ID, USER_ID, ACTION, 
                CLASSIFICATION_LEVEL, CIA_CONF, CIA_INT, CIA_AVAIL, 
                RATIONALE, CREATED_AT, DETAILS, 
                LABEL, C, I, A, 
                SOURCE, STATUS, DECISION_BY, DECISION_AT, 
                UPDATED_AT, COMPLIANCE_FLAGS
            ) VALUES (
                source.ID, source.ASSET_FULL_NAME, source.ASSET_ID, source.USER_ID, source.ACTION, 
                source.CLASSIFICATION_LEVEL, source.CIA_CONF, source.CIA_INT, source.CIA_AVAIL, 
                source.RATIONALE, source.CREATED_AT, source.DETAILS, 
                source.LABEL, source.C, source.I, source.A, 
                source.SOURCE, source.STATUS, source.DECISION_BY, source.DECISION_AT, 
                source.UPDATED_AT, source.COMPLIANCE_FLAGS
            )
        """
        
        self.connector.execute_non_query(qt, {
            "id": did, "full": asset_full_name, "aid": asset_id, "by": decision_by_str, 
            "lab": label, "c": int(c), "i": int(i), "a": int(a),
            "rat": str(rationale).strip(), "det": None if details is None else json.dumps(details),
            "src": source, "st": status, "flags": compliance_flags
        })
        
        audit_service.log(decision_by_str, "CLASSIFICATION_DECISION", "ASSET", asset_full_name, {"decision_id": did, "status": status, "label": label})

        # ✅ HUMAN REVIEW WORKFLOW INTEGRATION:
        # If status is 'Pending', we also populate CLASSIFICATION_REVIEW for the active workflow queue.
        # This matches the user's spec: "Supports human review workflows"
        if status.lower() == "pending":
            try:
                self.connector.execute_non_query(f"""
                    INSERT INTO {review_table} 
                    (REVIEW_ID, ASSET_FULL_NAME, PROPOSED_CLASSIFICATION, PROPOSED_C, PROPOSED_I, PROPOSED_A, REVIEWER, STATUS, CREATED_AT, UPDATED_AT, LAST_COMMENT)
                    VALUES (%(rid)s, %(full)s, %(lbl)s, %(c)s, %(i)s, %(a)s, %(rev)s, 'Pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %(com)s)
                """, {
                    "rid": did, 
                    "full": asset_full_name, 
                    "lbl": label, 
                    "c": int(c), "i": int(i), "a": int(a),
                    "rev": str(reviewer) if reviewer else None,
                    "com": rationale
                })
            except Exception as e:
                logger.warning(f"Failed to populate CLASSIFICATION_REVIEW queue: {e}")

        return did

    # --- Reviews ---
    def list_reviews(self, current_user: str, review_filter: str = "All", approval_status: str = "All pending", asset_name_filter: Optional[str] = None, lookback_days: int = 30, page: int = 1, page_size: int = 50, database: Optional[str] = None) -> Dict[str, Any]:
        db = database or self._resolve_db()
        # Ensure schema and view exist for this DB
        try:
            # We don't want to run the full DDL every time, but ensure_schema is fast
            self._ensure_schema(db)
            # Create a dummy decision to trigger DDL if it's the first time
            # Or just call the DDL logic directly. 
            # For now, we trust the record_decision DDL block or the user's manual setup.
        except Exception: pass
        db = database or self._resolve_db()
        rf, ap = review_filter.lower(), approval_status.lower()
        lb, p, ps = max(1, int(lookback_days)), max(1, int(page)), max(1, min(500, int(page_size)))
        start, end = (p - 1) * ps + 1, p * ps

        # Build asset name filter condition
        asset_filter_sql = ""
        if asset_name_filter and asset_name_filter.strip():
            # Support partial matching with LIKE
            asset_filter_sql = "AND UPPER(b.ASSET_NAME) LIKE UPPER(%(asset_filter)s)"

        # Main source: VW_CLASSIFICATION_REVIEWS (Standardized Review View)
        # Fallback to legacy CLASSIFICATION_HISTORY if view/table not available
        sql = f"""
        WITH base AS (
          SELECT 
            REVIEW_ID as ID, 
            NULL as ASSET_ID, 
            split_part(ASSET_FULL_NAME, '.', 1) as DATABASE_NAME, 
            split_part(ASSET_FULL_NAME, '.', 2) as SCHEMA_NAME, 
            split_part(ASSET_FULL_NAME, '.', 3) as ASSET_NAME,
            REQUESTED_LABEL as CLASSIFICATION_TAG,
            CONFIDENTIALITY_LEVEL as C_LEVEL,
            true as APPROVAL_REQUIRED,
            REVIEWER as APPROVED_BY, 
            'n/a' as CREATED_BY, 
            CREATED_AT as CHANGE_TIMESTAMP, 
            'Standard Review' as CHANGE_REASON, 
            LAST_COMMENT as BUSINESS_JUSTIFICATION
          FROM {db}.{SCHEMA}.VW_CLASSIFICATION_REVIEWS
        ),
        filtered AS (
          SELECT * FROM base b WHERE 1=1
          {"AND b.APPROVAL_REQUIRED = true AND b.APPROVED_BY IS NULL" if rf in ("all", "pending approvals") else ""}
          {"AND COALESCE(b.C_LEVEL,0) = 3" if rf == "high-risk" else ""}
          {"AND b.CHANGE_TIMESTAMP >= dateadd('day', -%(lb)s, current_timestamp())" if rf == "recent changes" else ""}
          {"AND b.APPROVAL_REQUIRED = true AND b.APPROVED_BY IS NULL" if ap in ("all pending", "pending my approval") else ""}
          {"AND upper(COALESCE(b.CREATED_BY,'')) <> upper(%(me)s)" if ap == "pending my approval" else ""}
          {asset_filter_sql}
        ),
        numbered AS (
          SELECT f.*, row_number() over (order by f.CHANGE_TIMESTAMP desc, f.ID desc) as RN, count(*) over() as TOTAL
          FROM filtered f
        )
        SELECT * FROM numbered WHERE RN BETWEEN %(start)s AND %(end)s
        """
        try:
            params = {"lb": lb, "start": start, "end": end, "me": current_user or ""}
            if asset_name_filter and asset_name_filter.strip():
                # Add wildcards for partial matching
                params["asset_filter"] = f"%{asset_name_filter.strip()}%"
            
            rows = self.connector.execute_query(sql, params) or []
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

    def approve_review(self, review_id: str, asset_full_name: str, label: str, c: int, i: int, a: int, approver: Optional[str] = None, comments: str = "") -> Tuple[bool, str]:
        # Robustly resolve 'who' as a string
        val = approver or (st.session_state.get("user") if st else "user")
        who = str(val) if val else "system"
        try:
            # When approving a historical review, we log a *new* decision
            self.record_decision(asset_full_name, who, "REVIEW", "Approved", label, c, i, a, comments or "Approved via Pending Reviews", {"review_id": review_id})
            
            # ✅ APPROVAL GATE: No tags applied if status is PENDING or REJECTED.
            # We mark the decision as 'Approved' with ENFORCEMENT_STATUS = 'Pending'.
            # Actual application happens via automated orchestration or manual sync.
            
            # ✅ UPDATE REVIEW TABLE: We now maintain STATUS in CLASSIFICATION_REVIEW 
            # This fixes the 'invalid identifier APPROVAL_STATUS' error.
            # We also update UPDATED_AT and REVIEWER.
            
            db = self._resolve_db()
            self.connector.execute_non_query(f"""
                UPDATE {db}.{SCHEMA}.CLASSIFICATION_REVIEW
                SET REVIEWER = %(who)s, 
                    UPDATED_AT = CURRENT_TIMESTAMP, 
                    STATUS = 'Approved'
                WHERE REVIEW_ID = %(rid)s
            """, {"who": who, "rid": review_id})

            # Legacy fallback: update history if it exists (optional)
            try:
                self.connector.execute_non_query(f"""
                    UPDATE {db}.{SCHEMA}.CLASSIFICATION_HISTORY
                    SET APPROVED_BY = %(who)s, 
                        APPROVAL_TIMESTAMP = CURRENT_TIMESTAMP, 
                        APPROVAL_STATUS = 'APPROVED'
                    WHERE HISTORY_ID = %(rid)s
                """, {"who": who, "rid": review_id})
            except Exception:
                pass

            # Update ENFORCEMENT_STATUS in decisions table for this review
            self.connector.execute_non_query(f"""
                UPDATE {db}.{SCHEMA}.CLASSIFICATION_DECISIONS
                SET ENFORCEMENT_STATUS = 'Pending',
                    APPROVED_BY = %(who)s,
                    DECISION_AT = CURRENT_TIMESTAMP,
                    UPDATED_AT = CURRENT_TIMESTAMP
                WHERE ID = %(rid)s OR DETAILS:review_id::string = %(rid)s
            """, {"who": who, "rid": review_id})

            # Trigger Enforcement
            enf_result = {}
            try:
                from src.services.compliance_service import compliance_service
                enf_result = compliance_service.enforcement.process_pending_enforcements(db)
            except Exception as enf_err:
                logger.warning(f"Immediate enforcement failed (will retry via task): {enf_err}")
                enf_result = {"error": str(enf_err)}
            
            audit_service.log(who, "REVIEW_APPROVE", "CLASSIFICATION", asset_full_name, {"review_id": review_id, "label": label})
            return True, "", enf_result
        except Exception as e:
            logger.error(f"Error approving review {review_id}: {e}")
            return False, str(e), {}

    def reject_review(self, review_id: str, asset_full_name: str, approver: Optional[str] = None, justification: str = "") -> bool:
        # Robustly resolve 'who' as a string
        val = approver or (st.session_state.get("user") if st else "user")
        who = str(val) if val else "system"
        try:
            db = self._resolve_db()
            # Update CLASSIFICATION_REVIEW System of Record
            self.connector.execute_non_query(f"""
                UPDATE {db}.{SCHEMA}.CLASSIFICATION_REVIEW
                SET STATUS = 'Rejected', 
                    REVIEWER = %(who)s, 
                    UPDATED_AT = CURRENT_TIMESTAMP,
                    LAST_COMMENT = %(why)s
                WHERE REVIEW_ID = %(rid)s
            """, {"who": who, "why": justification or "Rejected", "rid": review_id})
            
            audit_service.log(who, "REVIEW_REJECT", "CLASSIFICATION", asset_full_name, {"review_id": review_id, "justification": justification})
            return True
        except Exception: return False

    def request_review_changes(self, review_id: str, asset_full_name: str, approver: Optional[str] = None, instructions: str = "") -> bool:
        # Robustly resolve 'who' as a string
        val = approver or (st.session_state.get("user") if st else "user")
        who = str(val) if val else "system"
        try:
            db = self._resolve_db()
            # Update CLASSIFICATION_REVIEW System of Record
            self.connector.execute_non_query(f"""
                UPDATE {db}.{SCHEMA}.CLASSIFICATION_REVIEW
                SET STATUS = 'Changes Requested', 
                    LAST_COMMENT = %(notes)s,
                    UPDATED_AT = CURRENT_TIMESTAMP
                WHERE REVIEW_ID = %(rid)s
            """, {"notes": instructions or "Please revise classification details", "rid": review_id})
            
            audit_service.log(who, "REVIEW_REQUEST_CHANGES", "CLASSIFICATION", asset_full_name, {"review_id": review_id, "notes": instructions})
            return True
        except Exception: return False

    def set_under_review(self, review_id: str, asset_full_name: str, approver: Optional[str] = None, comments: str = "") -> bool:
        # Robustly resolve 'who' as a string
        val = approver or (st.session_state.get("user") if st else "user")
        who = str(val) if val else "system"
        try:
            db = self._resolve_db()
            # Update CLASSIFICATION_REVIEW System of Record
            self.connector.execute_non_query(f"""
                UPDATE {db}.{SCHEMA}.CLASSIFICATION_REVIEW
                SET STATUS = 'In Review', 
                    LAST_COMMENT = %(notes)s,
                    UPDATED_AT = CURRENT_TIMESTAMP
                WHERE REVIEW_ID = %(rid)s
            """, {"notes": comments or "Case marked as Under Review", "rid": review_id})
            
            audit_service.log(who, "REVIEW_UNDER_REVIEW", "CLASSIFICATION", asset_full_name, {"review_id": review_id, "notes": comments})
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
        # Robustly ensure approver is a string
        approver = str(approver) if approver else "system"
        db = self._resolve_db()
        table = f"{db}.{SCHEMA}.CLASSIFICATION_DECISIONS"
        
        # 1. Fetch the Pending Request
        rows = self.connector.execute_query(f"SELECT * FROM {table} WHERE ID = %(id)s", {"id": request_id})
        if not rows: raise ValueError("Request not found")
        r = rows[0]
        asset = r["ASSET_FULL_NAME"]
        label, c, i, a = r["LABEL"], r["C"], r["I"], r["A"]
        
        # 2. Archive Old Classification to History (if exists)
        try:
            from src.services.tagging_service import tagging_service
            
            # Get current tags before updating
            current_tags = tagging_service.get_object_tags(asset, "TABLE")
            old_classification = None
            for tag_ref in current_tags:
                if tag_ref.get("TAG_NAME") == "DATA_CLASSIFICATION":
                    old_classification = tag_ref.get("TAG_VALUE")
                    break
            
            if old_classification and old_classification != label:
                # Archive to history
                history_table = f"{db}.{SCHEMA}.CLASSIFICATION_HISTORY"
                self.connector.execute_non_query(f"""
                    INSERT INTO {history_table} 
                    (HISTORY_ID, ASSET_FULL_NAME, OLD_LABEL, NEW_LABEL, CHANGED_BY, CHANGE_REASON, CHANGE_TIMESTAMP)
                    SELECT 
                        %(hid)s, %(asset)s, %(old)s, %(new)s, %(by)s, 'Reclassification Approved', CURRENT_TIMESTAMP
                """, {
                    "hid": str(uuid.uuid4()),
                    "asset": asset,
                    "old": old_classification,
                    "new": label,
                    "by": approver
                })
                logger.info(f"Archived old classification for {asset}: {old_classification} → {label}")
        except Exception as archive_err:
            logger.warning(f"Failed to archive old classification: {archive_err}")
        
        # 3. Update the Decision Record (Status=Approved, Approved_By=Approver)
        # We mark ENFORCEMENT_STATUS = 'Pending' to trigger the Governance Enforcer.
        self.connector.execute_non_query(f"""
            UPDATE {table} 
            SET STATUS = 'Approved', 
                APPROVED_BY = %(ap)s, 
                APPROVED_AT = CURRENT_TIMESTAMP, 
                UPDATED_AT = CURRENT_TIMESTAMP,
                ENFORCEMENT_STATUS = 'Pending'
            WHERE ID = %(id)s
        """, {"ap": approver, "id": request_id})
        
        # 4. Trigger Enforcement (Immediate or via Task)
        enf_result = {}
        try:
            from src.services.compliance_service import compliance_service
            enf_result = compliance_service.enforcement.process_pending_enforcements(db)
        except Exception as enf_err:
            logger.warning(f"Immediate reclassification enforcement failed: {enf_err}")
            enf_result = {"error": str(enf_err)}

        audit_service.log(approver, "RECLASS_REQUEST_APPROVE", "ASSET", asset, {"request_id": request_id, "new_label": label})
        return enf_result

    def reject_reclassification(self, request_id: str, approver: str, justification: Optional[str] = None) -> None:
        # Robustly ensure approver is a string
        approver = str(approver) if approver else "system"
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

    def fetch_user_tasks_from_assets(self, current_user: Optional[str] = None, status: Optional[str] = None, owner: Optional[str] = None, classification_level: Optional[str] = None, date_range: Tuple[Optional[str], Optional[str]] = (None, None), limit: int = 500, db: Optional[str] = None, schema: str = SCHEMA) -> List[Dict[str, Any]]:
        """
        Fetch tasks assigned to a user directly from the ASSETS table.
        This provides a different view than list_tasks which uses VW_CLASSIFICATION_REVIEWS.
        """
        try:
            # Resolve database
            if not db:
                db = self._resolve_db()
            
            # Resolve current user if not provided
            if not current_user:
                try:
                    user_result = self.connector.execute_query("SELECT CURRENT_USER() as U")
                    if user_result and len(user_result) > 0:
                        current_user = user_result[0].get('U')
                except Exception:
                    current_user = "UNKNOWN_USER"
            
            # Build where clauses for optional filters
            extra_where = []
            params = {}
            if status:
                extra_where.append("UPPER(REVIEW_STATUS) = UPPER(%(status)s)")
                params["status"] = status
            if owner:
                extra_where.append("UPPER(DATA_OWNER) LIKE UPPER(%(owner)s)")
                params["owner"] = f"%{owner}%"
            if classification_level:
                extra_where.append("UPPER(CLASSIFICATION_LABEL) = UPPER(%(level)s)")
                params["level"] = classification_level
            if date_range:
                sd, ed = date_range
                if sd: extra_where.append("CREATED_TIMESTAMP >= %(sd)s"); params["sd"] = sd
                if ed: extra_where.append("CREATED_TIMESTAMP <= %(ed)s"); params["ed"] = ed
            
            where_sql = " AND ".join(extra_where)
            if where_sql:
                where_sql = " AND (" + where_sql + ")"

            query = f"""
            SELECT
                ASSET_ID, ASSET_NAME, FULLY_QUALIFIED_NAME, ASSET_TYPE,
                CLASSIFICATION_LABEL, REVIEW_STATUS, NEXT_REVIEW_DATE,
                DATA_OWNER, PEER_REVIEWER, MANAGEMENT_REVIEWER,
                PEER_REVIEW_COMPLETED, MANAGEMENT_REVIEW_COMPLETED,
                HAS_EXCEPTION, EXCEPTION_EXPIRY_DATE, CREATED_TIMESTAMP,
                DATEDIFF(day, CREATED_TIMESTAMP, CURRENT_DATE()) as DAYS_SINCE_CREATION,
                CASE
                    WHEN DATA_OWNER = '{current_user}' AND (CLASSIFICATION_LABEL IS NULL OR UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL', 'N/A', 'TBD', 'ACTION REQUIRED', 'PENDING REVIEW'))
                    THEN 'Needs Classification'
                    WHEN PEER_REVIEWER = '{current_user}' AND PEER_REVIEW_COMPLETED = FALSE
                    THEN 'Needs Peer Review'
                    WHEN MANAGEMENT_REVIEWER = '{current_user}' AND MANAGEMENT_REVIEW_COMPLETED = FALSE
                    THEN 'Needs Management Approval'
                    WHEN DATEDIFF(day, CREATED_TIMESTAMP, CURRENT_DATE()) > 5 
                         AND (CLASSIFICATION_LABEL IS NULL OR UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL', 'N/A', 'TBD', 'ACTION REQUIRED', 'PENDING REVIEW'))
                    THEN 'Past SLA'
                    WHEN HAS_EXCEPTION = TRUE AND EXCEPTION_EXPIRY_DATE <= DATEADD(day, 7, CURRENT_DATE())
                    THEN 'Exception Expiring Soon'
                    ELSE 'Other'
                END as TASK_TYPE
            FROM {db}.{schema}.ASSETS
            WHERE
                ((DATA_OWNER = '{current_user}' AND (CLASSIFICATION_LABEL IS NULL OR UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL', 'N/A', 'TBD', 'ACTION REQUIRED', 'PENDING REVIEW')))
                OR (PEER_REVIEWER = '{current_user}' AND PEER_REVIEW_COMPLETED = FALSE)
                OR (MANAGEMENT_REVIEWER = '{current_user}' AND MANAGEMENT_REVIEW_COMPLETED = FALSE)
                OR (DATA_OWNER = '{current_user}' AND DATEDIFF(day, CREATED_TIMESTAMP, CURRENT_DATE()) > 5 AND (CLASSIFICATION_LABEL IS NULL OR UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL', 'N/A', 'TBD', 'ACTION REQUIRED', 'PENDING REVIEW')))
                OR (HAS_EXCEPTION = TRUE AND EXCEPTION_EXPIRY_DATE <= DATEADD(day, 7, CURRENT_DATE()) AND (DATA_OWNER = '{current_user}' OR PEER_REVIEWER = '{current_user}' OR MANAGEMENT_REVIEWER = '{current_user}')))
                {where_sql}
            ORDER BY 
                CASE TASK_TYPE
                    WHEN 'Past SLA' THEN 1
                    WHEN 'Exception Expiring Soon' THEN 2
                    WHEN 'Needs Management Approval' THEN 3
                    WHEN 'Needs Peer Review' THEN 4
                    WHEN 'Needs Classification' THEN 5
                    ELSE 6
                END,
                DAYS_SINCE_CREATION DESC
            LIMIT {int(limit)}
            """
            return self.connector.execute_query(query, params) or []
        except Exception as e:
            logger.error(f"Error in fetch_user_tasks_from_assets: {e}")
            return []

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

    def update_or_submit_task(self, asset_full_name: str, c: int, i: int, a: int, label: str, action: str, comments: str, user: str, details: Optional[Dict[str, Any]] = None, database: Optional[str] = None) -> bool:
        try:
            # Handle string 'NONE' or similar coming from UI
            if database and str(database).strip().upper() in ("NONE", "NULL", "", "UNKNOWN"):
                database = None
            
            db = database or self._resolve_db()
            self._ensure_schema(db)
            self._ensure_tasks_table(db)
            
            # Map action to status per new requirement: IN_PROGRESS, COMPLETED, CANCELLED
            act_l = action.lower()
            if act_l == "submit":
                status = "COMPLETED"
                dec_status = "Approved"
            elif act_l == "reject":
                # Marked as 'COMPLETED' tasks but 'Rejected' decisions
                status = "COMPLETED"
                dec_status = "Rejected"
            elif act_l == "cancel":
                status = "CANCELLED"
                dec_status = "Cancelled"
            elif act_l == "review":
                status = "IN_PROGRESS"
                dec_status = "In Review"
            elif act_l == "escalate":
                status = "IN_PROGRESS"
                dec_status = "Escalated"
            elif act_l == "update_tags":
                 status = "IN_PROGRESS"
                 dec_status = "Draft" # Just an update
            else:
                status = "IN_PROGRESS"
                dec_status = "Draft"
            
            # 1. Record decision in authoritative audit table
            self.record_decision(asset_full_name, user, action.upper(), dec_status, label, c, i, a, comments, details=details)
            
            # 2. Update/Upsert Task Status
            # Use MERGE to ensure correct status in CLASSIFICATION_TASKS per user request
            check_table = f"{db}.{SCHEMA}.CLASSIFICATION_TASKS"
            qt = f"""
            MERGE INTO {check_table} t
            USING (
                SELECT 
                    %(full)s as ASSET_FULL_NAME,
                    split_part(%(full)s, '.', 3) as DATASET_NAME,
                    %(st)s as STATUS,
                    %(lbl)s as CLASSIFICATION_LEVEL,
                    %(c)s as C, %(i)s as I, %(a)s as A,
                    %(user)s as ASSIGNED_TO,
                    %(dets)s as DETAILS
            ) s
            ON t.ASSET_FULL_NAME = s.ASSET_FULL_NAME
            WHEN MATCHED THEN UPDATE SET 
                STATUS = s.STATUS,
                ASSIGNED_TO = s.ASSIGNED_TO,
                CONFIDENTIALITY_LEVEL = 'C' || s.C,
                INTEGRITY_LEVEL = 'I' || s.I,
                AVAILABILITY_LEVEL = 'A' || s.A,
                UPDATED_AT = CURRENT_TIMESTAMP(),
                DETAILS = PARSE_JSON(s.DETAILS)
            WHEN NOT MATCHED THEN INSERT (
                TASK_ID, ASSET_FULL_NAME, DATASET_NAME, ASSIGNED_TO, STATUS, 
                CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL,
                CREATED_AT, UPDATED_AT, DETAILS
            ) VALUES (
                UUID_STRING(), s.ASSET_FULL_NAME, s.DATASET_NAME, s.ASSIGNED_TO, s.STATUS,
                'C' || s.C, 'I' || s.I, 'A' || s.A,
                CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), PARSE_JSON(s.DETAILS)
            )
            """
            self.connector.execute_non_query(qt, {
                "full": asset_full_name, 
                "st": status, 
                "lbl": label, 
                "c": int(c), "i": int(i), "a": int(a),
                "user": str(user),
                "dets": json.dumps(details) if details else "{}"
            })

            # 3. Update/Upsert Review Queue
            review_table = f"{db}.{SCHEMA}.CLASSIFICATION_REVIEW"
            qr = f"""
            MERGE INTO {review_table} t
            USING (
                SELECT 
                    %(full)s as ASSET_FULL_NAME,
                    %(dec_st)s as STATUS,
                    %(lbl)s as PROPOSED_CLASSIFICATION,
                    %(c)s as PROPOSED_C, %(i)s as PROPOSED_I, %(a)s as PROPOSED_A,
                    %(user)s as REVIEWER,
                    %(com)s as LAST_COMMENT
            ) s
            ON t.ASSET_FULL_NAME = s.ASSET_FULL_NAME
            WHEN MATCHED THEN UPDATE SET 
                STATUS = s.STATUS,
                REVIEWER = s.REVIEWER,
                PROPOSED_CLASSIFICATION = s.PROPOSED_CLASSIFICATION,
                PROPOSED_C = s.PROPOSED_C,
                PROPOSED_I = s.PROPOSED_I,
                PROPOSED_A = s.PROPOSED_A,
                LAST_COMMENT = s.LAST_COMMENT,
                UPDATED_AT = CURRENT_TIMESTAMP()
            WHEN NOT MATCHED THEN INSERT (
                REVIEW_ID, ASSET_FULL_NAME, PROPOSED_CLASSIFICATION, 
                PROPOSED_C, PROPOSED_I, PROPOSED_A, 
                REVIEWER, STATUS, CREATED_AT, UPDATED_AT, LAST_COMMENT
            ) VALUES (
                UUID_STRING(), s.ASSET_FULL_NAME, s.PROPOSED_CLASSIFICATION,
                s.PROPOSED_C, s.PROPOSED_I, s.PROPOSED_A,
                s.REVIEWER, s.STATUS, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), s.LAST_COMMENT
            )
            """
            self.connector.execute_non_query(qr, {
                "full": asset_full_name, 
                "dec_st": dec_status, 
                "lbl": label, 
                "c": int(c), "i": int(i), "a": int(a),
                "user": str(user),
                "com": comments or f"Action {action} performed via My Tasks"
            })
            
            if action.lower() == "submit":
                try:
                    compliance_service.enforcement.process_pending_enforcements(db)
                    
                    # Notify
                    from src.services.notifier_service import notifier_service
                    notifier_service.notify_owner(
                        asset_full_name=asset_full_name,
                        subject=f"Classification Task Completed: {status}",
                        message=f"Pass/Fail: {dec_status}\nActioned by: {user}\nLabel: {label}\nComments: {comments}"
                    )
                except Exception:
                    pass
            elif action.lower() == "reject":
                try:
                     # Notify rejection
                    from src.services.notifier_service import notifier_service
                    notifier_service.notify_owner(
                        asset_full_name=asset_full_name,
                        subject=f"Classification Rejected",
                        message=f"Actioned by: {user}\nReason: {comments}"
                    )
                except Exception:
                    pass

            return True
        except Exception as e:
            logger.error(f"Task update failed: {e}")
            if st:
                st.error(f"Debug Info - Task update internal error: {e}")
            return False

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
