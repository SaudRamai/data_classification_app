"""
Compliance Automation Service (Consolidated)

This is the SINGLE AUTHORITATIVE ORCHESTRATOR for all compliance and policy evaluations.
It consolidates functionality from:
- compliance_service (core)
- dynamic_compliance_report_service (strategic reporting)
- policy_enforcement_service (masking/row-access policies)
- nlp_compliance_service (NLP-based detection)
- metrics_service (KPIs and analytics)

Usage:
    from src.services.compliance_service import compliance_service
    
    # Core compliance logic
    compliance_service.detect_violations()
    
    # Metrics
    coverage = compliance_service.metrics.classification_coverage()
    
    # Enforcement
    compliance_service.enforcement.apply_masking_policy(...)
    
    # NLP
    results = compliance_service.nlp.analyze_text("Sensitive data...")
"""
from __future__ import annotations
from typing import List, Dict, Any, Optional, Set, Tuple
import logging
import uuid
import re
import json
from datetime import datetime, date, timedelta
from concurrent.futures import ThreadPoolExecutor

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

# Attempt to use the unified classification_audit_service first, fallback to no-op
try:
    from src.services.classification_audit_service import classification_audit_service as audit_service
except Exception:
    class _NoopAudit:
        def log(self, *args, **kwargs): return None
        def query(self, *args, **kwargs): return []
        def log_workflow_event(self, *args, **kwargs): return None
    audit_service = _NoopAudit()

try:
    import spacy
except ImportError:
    spacy = None

logger = logging.getLogger(__name__)

# Constants (shared across sub-services)
GOV_SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
TABLE_SCHEDULES = "REVIEW_SCHEDULES"
TABLE_REPORTS = "COMPLIANCE_REPORTS"
TABLE_VIOLATIONS = "VIOLATIONS"
TABLE_REMEDIATION = "REMEDIATION_TASKS"
TABLE_CHECKS = "CHECKS"
TABLE_CHECK_RESULTS = "CHECK_RESULTS"
TABLE_EVIDENCE = "EVIDENCE"
TABLE_ASSETS = "ASSETS"
TABLE_DECISIONS = "CLASSIFICATION_DECISIONS"

# =============================================================================
# SUB-SERVICES (Internalized Logic)
# =============================================================================

class MetricsSubservice:
    """Centralizes all KPI and metrics calculations."""
    def __init__(self, parent: ComplianceService):
        self.parent = parent
        self.connector = snowflake_connector





class EnforcementSubservice:
    """Manages Snowflake masking and row-access policies."""
    def __init__(self, parent: ComplianceService):
        self.parent = parent
        self.connector = snowflake_connector

    def ensure_masking_policy(self, fully_qualified_policy: str, return_type: str = 'STRING', mask_expr_sql: Optional[str] = None) -> None:
        if not mask_expr_sql:
            mask_expr_sql = (
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') "
                "OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL ELSE '***' END"
            )
        sql = f"CREATE MASKING POLICY IF NOT EXISTS {fully_qualified_policy} AS (VAL {return_type}) RETURNS {return_type} -> {mask_expr_sql}"
        self.connector.execute_non_query(sql)

    def apply_masking_policy(self, table: str, column: str, fully_qualified_policy: str) -> None:
        self.connector.execute_non_query(f"ALTER TABLE {table} MODIFY COLUMN {column} SET MASKING POLICY {fully_qualified_policy}")









    def process_pending_enforcements(self, database: Optional[str] = None) -> Dict[str, Any]:
        """Orchestrate post-approval actions: tagging, masking, and RBAC."""
        db = database or self.parent._active_db()
        decisions_table = f"{db}.{GOV_SCHEMA}.CLASSIFICATION_DECISIONS"
        
        # 1. Fetch Approved but not yet Enforced decisions
        query = f"""
            SELECT ID, ASSET_FULL_NAME, LABEL, C, I, A, APPROVED_BY
            FROM {decisions_table}
            WHERE STATUS = 'Approved' AND (ENFORCEMENT_STATUS IS NULL OR ENFORCEMENT_STATUS = 'Pending')
            LIMIT 50
        """
        pending = self.connector.execute_query(query) or []
        results = {"processed": 0, "errors": []}
        
        if not pending:
            return results

        from src.services.tagging_service import tagging_service
        
        for p in pending:
            did, asset, lbl, c, i, a = p["ID"], p["ASSET_FULL_NAME"], p["LABEL"], p["C"], p["I"], p["A"]
            try:
                # A. Apply Classification Tags
                tags = {
                    "DATA_CLASSIFICATION": lbl,
                    "CONFIDENTIALITY_LEVEL": f"C{int(c or 0)}",
                    "INTEGRITY_LEVEL": f"I{int(i or 0)}",
                    "AVAILABILITY_LEVEL": f"A{int(a or 0)}"
                }
                tagging_service.apply_tags_to_object(asset, "TABLE", tags)
                
                # B. Apply Masking Policies for sensitive data (C >= 2)
                if int(c or 0) >= 2:
                    # Simple automated masking based on standard redaction policy
                    # In a real scenario, this would look at column categories
                    # Here we ensure a base policy exists for the asset
                    discovery_query = f"SELECT COLUMN_NAME, DATA_TYPE FROM {asset.split('.')[0]}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%(s)s AND TABLE_NAME=%(t)s"
                    parts = asset.split('.')
                    if len(parts) == 3:
                        cols = self.connector.execute_query(discovery_query, {"s": parts[1], "t": parts[2]}) or []
                        for col_info in cols:
                            col_name = col_info["COLUMN_NAME"]
                            # Only mask if it looks like PII or if explicitly requested in future logic
                            if any(k in col_name.upper() for k in ["EMAIL", "NAME", "PHONE", "SSN", "SECRET"]):
                                policy_fqn = f"{db}.{GOV_SCHEMA}.MASK_REDACT_STRING"
                                self.ensure_masking_policy(policy_fqn, return_type='STRING')
                                self.apply_masking_policy(asset, col_name, policy_fqn)

                # C. Enforce RBAC (Placeholder for dynamic grant management)
                # Logic: If Confidential (C3), only certain roles can access. 
                # This would typically involve REVOKE ALL and then selective GRANT.
                
                # D. Finalize status
                self.connector.execute_non_query(f"""
                    UPDATE {decisions_table}
                    SET ENFORCEMENT_STATUS = 'Success',
                        ENFORCEMENT_TIMESTAMP = CURRENT_TIMESTAMP
                    WHERE ID = %(id)s
                """, {"id": did})
                
                audit_service.log(p["APPROVED_BY"], "ENFORCEMENT_COMPLETE", "ASSET", asset, {"decision_id": did, "actions": ["TAGGING", "MASKING"]})
                results["processed"] += 1
                
            except Exception as e:
                logger.error(f"Enforcement failed for {did} ({asset}): {e}")
                self.connector.execute_non_query(f"UPDATE {decisions_table} SET ENFORCEMENT_STATUS = 'Failed' WHERE ID = %(id)s", {"id": did})
                results["errors"].append({"id": did, "asset": asset, "error": str(e)})

        return results

class NLPSubservice:
    """Internalized NLP-based compliance evaluation."""
    def __init__(self, parent: ComplianceService):
        self.parent = parent
        self._nlp = None
        if spacy:
            try: self._nlp = spacy.load('en_core_web_sm')
            except Exception: pass
        self._patterns = {
            'EMAIL': re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I),
            'PHONE': re.compile(r"\+?[0-9\-()\s]{7,}", re.I),
            'SSN_US': re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b"),
        }




# =============================================================================
# MAIN SERVICE
# =============================================================================

class ComplianceService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        # Initialize sub-services for modular access
        self.metrics = MetricsSubservice(self)
        self.enforcement = EnforcementSubservice(self)
        self.nlp = NLPSubservice(self)
        self._healthy_last_error: Optional[str] = None

    def _active_db(self) -> str:
        db = getattr(settings, "SNOWFLAKE_DATABASE", None)
        if not db or str(db).strip().upper() in {"", "NONE", "(NONE)", "NULL"}:
            return "DATA_CLASSIFICATION_DB"
        return str(db)

    def _ensure_tables(self) -> None:
        db = self._active_db()
        self.connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db}.{GOV_SCHEMA}")
        # Standard compliance tables
        tables = {
            TABLE_SCHEDULES: "ID STRING, ASSET_FULL_NAME STRING, FREQUENCY STRING, NEXT_RUN TIMESTAMP_NTZ, LAST_RUN TIMESTAMP_NTZ, OWNER STRING, ACTIVE BOOLEAN",
            TABLE_REPORTS: "ID STRING, FRAMEWORK STRING, GENERATED_AT TIMESTAMP_NTZ, GENERATED_BY STRING, METRICS VARIANT, LOCATION STRING",
            TABLE_VIOLATIONS: "ID STRING, RULE_CODE STRING, SEVERITY STRING, DESCRIPTION STRING, ASSET_FULL_NAME STRING, DETECTED_AT TIMESTAMP_NTZ, STATUS STRING, DETAILS VARIANT",
            TABLE_CHECKS: "ID STRING, FRAMEWORK STRING, CODE STRING, DESCRIPTION STRING, RULE STRING, CREATED_AT TIMESTAMP_NTZ",
            TABLE_CHECK_RESULTS: "ID STRING, CHECK_CODE STRING, FRAMEWORK STRING, ASSET_FULL_NAME STRING, PASSED BOOLEAN, DETAILS VARIANT, RUN_AT TIMESTAMP_NTZ",
            TABLE_EVIDENCE: "ID STRING, CATEGORY STRING, REF_ID STRING, DESCRIPTION STRING, DATA VARIANT, CREATED_AT TIMESTAMP_NTZ, CREATED_BY STRING",
            "POLICIES": "FRAMEWORK STRING, RULE_CODE STRING, CATEGORY STRING, MIN_CONFIDENTIALITY NUMBER, REQUIRE_MASKING BOOLEAN, REQUIRE_ROW_ACCESS BOOLEAN",
            "FRAMEWORKS": "NAME STRING, OWNER STRING, CREATED_AT TIMESTAMP_NTZ"
        }
        for t, defs in tables.items():
            self.connector.execute_non_query(f"CREATE TABLE IF NOT EXISTS {db}.{GOV_SCHEMA}.{t} ({defs})")


    # --- Core Operational Logic ---




    # --- Strategic Reporting (Dynamic) ---


    # --- Standard Reporting ---


    # --- Shared Helpers ---


# Singleton instance
compliance_service = ComplianceService()
