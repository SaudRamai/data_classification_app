"""
Compliance Automation Service
- Automated review scheduling, compliance report generation, violation detection, remediation workflow
- Persists artifacts in <DB>.DATA_GOVERNANCE (DB from settings)
"""
from typing import List, Dict, Any, Optional
import logging
import uuid
from datetime import datetime

from src.connectors.snowflake_connector import snowflake_connector
try:
    from src.services.audit_service import audit_service
except Exception:
    # Fallback no-op audit to prevent import-time crashes
    class _NoopAudit:
        def log(self, *args, **kwargs):
            return None
        def query(self, *args, **kwargs):
            return []
    audit_service = _NoopAudit()
from src.config.settings import settings

logger = logging.getLogger(__name__)

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"

TABLE_SCHEDULES = "REVIEW_SCHEDULES"
TABLE_REPORTS = "COMPLIANCE_REPORTS"
TABLE_VIOLATIONS = "VIOLATIONS"
TABLE_REMEDIATION = "REMEDIATION_TASKS"
TABLE_CHECKS = "CHECKS"
TABLE_CHECK_RESULTS = "CHECK_RESULTS"
TABLE_EVIDENCE = "EVIDENCE"


class ComplianceService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        # Do not perform side-effecting operations (like creating tables) at import/init time.
        # Pages should call health_check() explicitly, and operational methods will raise
        # clear errors if required tables are missing.
        self._healthy_last_error: Optional[str] = None

    def _ensure_tables(self) -> None:
        try:
            self.connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}")
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE_SCHEDULES} (
                    ID STRING,
                    ASSET_FULL_NAME STRING,
                    FREQUENCY STRING,
                    NEXT_RUN TIMESTAMP_NTZ,
                    LAST_RUN TIMESTAMP_NTZ,
                    OWNER STRING,
                    ACTIVE BOOLEAN
                )
                """
            )
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE_REPORTS} (
                    ID STRING,
                    FRAMEWORK STRING,
                    GENERATED_AT TIMESTAMP_NTZ,
                    GENERATED_BY STRING,
                    METRICS VARIANT,
                    LOCATION STRING
                )
                """
            )
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE_VIOLATIONS} (
                    ID STRING,
                    RULE_CODE STRING,
                    SEVERITY STRING,
                    DESCRIPTION STRING,
                    ASSET_FULL_NAME STRING,
                    DETECTED_AT TIMESTAMP_NTZ,
                    STATUS STRING,
                    DETAILS VARIANT
                )
                """
            )
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE_REMEDIATION} (
                    ID STRING,
                    VIOLATION_ID STRING,
                    ASSIGNEE STRING,
                    DUE_DATE DATE,
                    STATUS STRING,
                    CREATED_AT TIMESTAMP_NTZ,
                    UPDATED_AT TIMESTAMP_NTZ
                )
                """
            )
            # Checks registry (generated from Policy)
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE_CHECKS} (
                    ID STRING,
                    FRAMEWORK STRING,
                    CODE STRING,
                    DESCRIPTION STRING,
                    RULE STRING,
                    CREATED_AT TIMESTAMP_NTZ
                )
                """
            )
            # Check results
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE_CHECK_RESULTS} (
                    ID STRING,
                    CHECK_CODE STRING,
                    FRAMEWORK STRING,
                    ASSET_FULL_NAME STRING,
                    PASSED BOOLEAN,
                    DETAILS VARIANT,
                    RUN_AT TIMESTAMP_NTZ
                )
                """
            )
            # Evidence store for reports/checks/violations
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE_EVIDENCE} (
                    ID STRING,
                    CATEGORY STRING,          -- REPORT, CHECK, VIOLATION, CONTROL
                    REF_ID STRING,            -- ID of the related item (e.g., report ID, violation ID)
                    DESCRIPTION STRING,
                    DATA VARIANT,             -- JSON snapshot
                    CREATED_AT TIMESTAMP_NTZ,
                    CREATED_BY STRING
                )
                """
            )
            # Optional rules table for data-driven I/A inference
            try:
                self.connector.execute_non_query(
                    f"""
                    CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.IA_RULES (
                      TYPE STRING,
                      PATTERN STRING,
                      I_LEVEL NUMBER(1),
                      A_LEVEL NUMBER(1),
                      PRIORITY NUMBER(3),
                      UPDATED_AT TIMESTAMP_NTZ
                    )
                    """
                )
            except Exception:
                pass
            # Classification queue (used by automated and manual workflows)
            try:
                self.connector.execute_non_query(
                    f"""
                    CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.CLASSIFICATION_QUEUE (
                      ID STRING,
                      ASSET_FULL_NAME STRING,
                      COLUMN_NAME STRING,
                      REASON STRING,
                      SUGGESTED_LABEL STRING,
                      CONFIDENCE FLOAT,
                      SENSITIVE_CATEGORIES VARIANT,
                      CREATED_AT TIMESTAMP_NTZ,
                      DETAILS VARIANT
                    )
                    """
                )
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Failed to ensure compliance tables: {e}")
            # Propagate to caller so health_check can report it if invoked with ensure=True
            raise

    def health_check(self, ensure: bool = False) -> Dict[str, Any]:
        """Lightweight service health check.
        - ensure=False: verify connector basic query works (no side-effects)
        - ensure=True: additionally attempt to create required tables
        Returns: {"ok": bool, "error": Optional[str]}
        """
        try:
            _ = self.connector.execute_query("SELECT 1 AS OK") or []
            if ensure:
                # Attempt to create required tables/schemas
                self._ensure_tables()
            self._healthy_last_error = None
            return {"ok": True, "error": None}
        except Exception as e:
            msg = str(e)
            self._healthy_last_error = msg
            return {"ok": False, "error": msg}

    def schedule_review(self, asset_full_name: str, frequency: str, owner: str) -> str:
        sid = str(uuid.uuid4())
        try:
            self.connector.execute_non_query(
                f"""
                INSERT INTO {DB}.{SCHEMA}.{TABLE_SCHEDULES}
                (ID, ASSET_FULL_NAME, FREQUENCY, NEXT_RUN, OWNER, ACTIVE)
                SELECT %(id)s, %(full)s, %(freq)s, DATEADD(day, 30, CURRENT_TIMESTAMP), %(own)s, TRUE
                """,
                {"id": sid, "full": asset_full_name, "freq": frequency, "own": owner},
            )
            audit_service.log(owner, "SCHEDULE_REVIEW", "ASSET", asset_full_name, {"id": sid, "frequency": frequency})
            return sid
        except Exception as e:
            logger.error(f"Failed to schedule review: {e}")
            raise

    def detect_violations(self) -> int:
        """Run a set of rules and persist violations. Returns count created."""
        created = 0
        rules = [
            ("UNTAGGED_TABLE", "High", "Classified assets must have tags", self._rule_untagged_tables),
            ("OVERDUE_REVIEW", "Medium", "Assets overdue for review", self._rule_overdue_reviews),
            ("SLA_5_DAY_OVERDUE", "High", "Assets not classified within 5 business days of discovery", self._rule_sla_overdue),
            ("GDPR_MISSING_TAG", "High", "GDPR-relevant datasets missing GDPR regulatory tag", self._rule_gdpr_missing_tag),
            ("HIPAA_MISSING_CONTROLS", "High", "HIPAA/PHI datasets missing HIPAA tag or masking controls", self._rule_hipaa_missing_controls),
        ]
        for code, severity, desc, fn in rules:
            try:
                rows = fn()
                for r in rows:
                    vid = str(uuid.uuid4())
                    self.connector.execute_non_query(
                        f"""
                        INSERT INTO {DB}.{SCHEMA}.{TABLE_VIOLATIONS}
                        (ID, RULE_CODE, SEVERITY, DESCRIPTION, ASSET_FULL_NAME, DETECTED_AT, STATUS, DETAILS)
                        SELECT %(id)s, %(code)s, %(sev)s, %(desc)s, %(full)s, CURRENT_TIMESTAMP, 'Open', TO_VARIANT(PARSE_JSON(%(details)s))
                        """,
                        {
                            "id": vid,
                            "code": code,
                            "sev": severity,
                            "desc": desc,
                            "full": r.get("FULL_NAME", ""),
                            "details": __import__("json").dumps(r),
                        },
                    )
                    created += 1
            except Exception as e:
                logger.error(f"Violation rule {code} failed: {e}")
        return created

    def _rule_untagged_tables(self) -> List[Dict[str, Any]]:
        sql = f"""
        WITH inv AS (
          SELECT FULLY_QUALIFIED_NAME FROM {DB}.{SCHEMA}.ASSETS
        )
        SELECT inv.FULLY_QUALIFIED_NAME AS FULL_NAME
        FROM inv
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tr
          ON UPPER(inv.FULL_NAME) = UPPER(tr.OBJECT_DATABASE||'.'||tr.OBJECT_SCHEMA||'.'||tr.OBJECT_NAME)
          AND tr.TAG_NAME IN ('DATA_CLASSIFICATION','CONFIDENTIALITY_LEVEL','INTEGRITY_LEVEL','AVAILABILITY_LEVEL')
        GROUP BY inv.FULL_NAME
        HAVING COUNT(tr.TAG_NAME) < 1
        LIMIT 200
        """
        rows = self.connector.execute_query(sql)
        return rows

    def _rule_overdue_reviews(self) -> List[Dict[str, Any]]:
        sql = f"""
        SELECT ASSET_FULL_NAME as FULL_NAME
        FROM {DB}.{SCHEMA}.{TABLE_SCHEDULES}
        WHERE ACTIVE AND COALESCE(NEXT_RUN, CURRENT_TIMESTAMP) < CURRENT_TIMESTAMP
        """
        return self.connector.execute_query(sql)

    # --- Violation & Remediation helpers (for dashboard UI) ---
    def list_violations(self, status: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        """Return violations, optionally filtered by status (e.g., 'Open', 'Resolved')."""
        try:
            if status:
                return self.connector.execute_query(
                    f"SELECT * FROM {DB}.{SCHEMA}.{TABLE_VIOLATIONS} WHERE STATUS = %(st)s ORDER BY DETECTED_AT DESC LIMIT %(lim)s",
                    {"st": status, "lim": int(limit)},
                ) or []
            return self.connector.execute_query(
                f"SELECT * FROM {DB}.{SCHEMA}.{TABLE_VIOLATIONS} ORDER BY DETECTED_AT DESC LIMIT %(lim)s",
                {"lim": int(limit)},
            ) or []
        except Exception:
            return []

    def update_violation_status(self, violation_id: str, status: str, user_id: str = "system") -> None:
        """Update the STATUS of a violation and write an audit log."""
        try:
            self.connector.execute_non_query(
                f"UPDATE {DB}.{SCHEMA}.{TABLE_VIOLATIONS} SET STATUS = %(st)s WHERE ID = %(id)s",
                {"st": status, "id": violation_id},
            )
            try:
                audit_service.log(user_id, "UPDATE_VIOLATION_STATUS", "VIOLATION", violation_id, {"status": status})
            except Exception:
                pass
        except Exception:
            pass

    def list_remediation_tasks(self, violation_id: Optional[str] = None, status: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        """Return remediation tasks, optionally filtered by violation and/or status."""
        try:
            where = []
            params: Dict[str, Any] = {"lim": int(limit)}
            if violation_id:
                where.append("VIOLATION_ID = %(vid)s")
                params["vid"] = violation_id
            if status:
                where.append("STATUS = %(st)s")
                params["st"] = status
            predicate = (" WHERE " + " AND ".join(where)) if where else ""
            return self.connector.execute_query(
                f"SELECT * FROM {DB}.{SCHEMA}.{TABLE_REMEDIATION}{predicate} ORDER BY UPDATED_AT DESC LIMIT %(lim)s",
                params,
            ) or []
        except Exception:
            return []

    def update_remediation_status(self, task_id: str, status: str, user_id: str = "system") -> None:
        try:
            self.connector.execute_non_query(
                f"UPDATE {DB}.{SCHEMA}.{TABLE_REMEDIATION} SET STATUS = %(st)s, UPDATED_AT = CURRENT_TIMESTAMP WHERE ID = %(id)s",
                {"st": status, "id": task_id},
            )
            try:
                audit_service.log(user_id, "UPDATE_REMEDIATION_STATUS", "REMEDIATION", task_id, {"status": status})
            except Exception:
                pass
        except Exception:
            pass

    def _rule_sla_overdue(self) -> List[Dict[str, Any]]:
        """Assets discovered more than 5 business days ago and not yet classified."""
        # Using a simple >=5 day difference; if a BUSINESS_DAY calendar exists, replace with a proper business day calc
        sql = f"""
        SELECT FULLY_QUALIFIED_NAME AS FULL_NAME
        FROM {DB}.{SCHEMA}.ASSETS
        WHERE COALESCE(CLASSIFICATION_LABEL, '') = ''
          AND CREATED_TIMESTAMP < DATEADD(day, -5, CURRENT_TIMESTAMP)
        LIMIT 500
        """
        try:
            return self.connector.execute_query(sql) or []
        except Exception:
            return []

    def generate_report(self, framework: str, user_id: str) -> str:
        rid = str(uuid.uuid4())
        # Basic metrics based on inventory & tags
        metrics = {
            "total_assets": 0,
            "tagged_assets": 0,
            "open_violations": 0,
            "coverage_rate": 0.0,
            "risk_counts": {"High": 0, "Medium": 0, "Low": 0},
        }
        try:
            total_assets = self.connector.execute_query(
                f"SELECT COUNT(*) AS C FROM {DB}.{SCHEMA}.ASSETS"
            )[0]["C"]
            tagged_assets = self.connector.execute_query(
                f"""
                WITH inv AS (
                  SELECT FULLY_QUALIFIED_NAME FROM {DB}.{SCHEMA}.ASSETS
                )
                SELECT COUNT(DISTINCT inv.FULLY_QUALIFIED_NAME) AS C
                FROM inv
                JOIN SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tr
                  ON UPPER(inv.FULL_NAME) = UPPER(tr.OBJECT_DATABASE||'.'||tr.OBJECT_SCHEMA||'.'||tr.OBJECT_NAME)
                """
            )[0]["C"]
            open_violations = self.connector.execute_query(
                f"SELECT COUNT(*) AS C FROM {DB}.{SCHEMA}.{TABLE_VIOLATIONS} WHERE STATUS = 'Open'"
            )[0]["C"]
            # Risk distribution using CIA max
            risk_rows = self.connector.execute_query(
                f"""
                WITH r AS (
                  SELECT COALESCE(GREATEST(CAST(COALESCE(CONFIDENTIALITY_LEVEL,'0') AS INT), CAST(COALESCE(INTEGRITY_LEVEL,'0') AS INT), CAST(COALESCE(AVAILABILITY_LEVEL,'0') AS INT)),0) AS R
                  FROM {DB}.{SCHEMA}.ASSETS
                )
                SELECT 
                  SUM(CASE WHEN R >= 3 THEN 1 ELSE 0 END) AS HIGH,
                  SUM(CASE WHEN R = 2 THEN 1 ELSE 0 END) AS MED,
                  SUM(CASE WHEN R <= 1 THEN 1 ELSE 0 END) AS LOW
                FROM r
                """
            ) or [{"HIGH": 0, "MED": 0, "LOW": 0}]
            risk_counts = {
                "High": int(risk_rows[0].get("HIGH", 0)),
                "Medium": int(risk_rows[0].get("MED", 0)),
                "Low": int(risk_rows[0].get("LOW", 0)),
            }
            metrics.update(
                {
                    "total_assets": total_assets,
                    "tagged_assets": tagged_assets,
                    "open_violations": open_violations,
                    "coverage_rate": (float(tagged_assets) / float(total_assets) if total_assets else 0.0),
                    "risk_counts": risk_counts,
                }
            )
            self.connector.execute_non_query(
                f"""
                INSERT INTO {DB}.{SCHEMA}.{TABLE_REPORTS}
                (ID, FRAMEWORK, GENERATED_AT, GENERATED_BY, METRICS, LOCATION)
                SELECT %(id)s, %(fw)s, CURRENT_TIMESTAMP, %(user)s, TO_VARIANT(PARSE_JSON(%(met)s)), NULL
                """,
                {"id": rid, "fw": framework, "user": user_id, "met": __import__("json").dumps(metrics)},
            )
            audit_service.log(user_id, "GENERATE_REPORT", "REPORT", rid, {"framework": framework})
            return rid
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            raise

    def list_open_violations(self, limit: int = 200) -> List[Dict[str, Any]]:
        return self.connector.execute_query(
            f"SELECT * FROM {DB}.{SCHEMA}.{TABLE_VIOLATIONS} WHERE STATUS = 'Open' ORDER BY DETECTED_AT DESC LIMIT %(lim)s",
            {"lim": limit},
        )

    # --- Checks Runner ---
    def _fetch_asset_features(self) -> List[Dict[str, Any]]:
        """Return per-asset features used for rule evaluation: C, has tags, has masking, has row access.
        Best-effort and optimized for readability over performance.
        """
        sql = f"""
            WITH inv AS (
              SELECT FULLY_QUALIFIED_NAME AS FULL_NAME,
                     CAST(COALESCE(CONFIDENTIALITY_LEVEL,'0') AS INT) AS C
              FROM {DB}.{SCHEMA}.ASSETS
            ),
            tr AS (
              SELECT UPPER(OBJECT_DATABASE||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME) AS FULL,
                     COUNT(*) AS TAGS
              FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
              GROUP BY 1
            ),
            mp AS (
              SELECT DISTINCT UPPER(REF_DATABASE_NAME||'.'||REF_SCHEMA_NAME||'.'||REF_ENTITY_NAME) AS FULL
              FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
              WHERE POLICY_KIND = 'MASKING POLICY'
            ),
            rap AS (
              SELECT DISTINCT UPPER(REF_DATABASE_NAME||'.'||REF_SCHEMA_NAME||'.'||REF_ENTITY_NAME) AS FULL
              FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
              WHERE POLICY_KIND = 'ROW ACCESS POLICY'
            )
            SELECT inv.FULL_NAME,
                   inv.C,
                   (tr.TAGS IS NOT NULL AND tr.TAGS > 0) AS HAS_TAGS,
                   (mp.FULL IS NOT NULL) AS HAS_MASKING,
                   (rap.FULL IS NOT NULL) AS HAS_ROW_ACCESS
            FROM inv
            LEFT JOIN tr  ON UPPER(inv.FULL_NAME) = tr.FULL
            LEFT JOIN mp  ON UPPER(inv.FULL_NAME) = mp.FULL
            LEFT JOIN rap ON UPPER(inv.FULL_NAME) = rap.FULL
        """
        try:
            return self.connector.execute_query(sql) or []
        except Exception:
            return []

    def run_checks(self, framework: Optional[str] = None) -> int:
        """Evaluate checks from CHECKS table against inventory and persist results.
        Supports known codes: TAG_COVERAGE, PII_MINIMUMS, SOX_MINIMUMS.
        Returns count of results written.
        """
        try:
            where = ""
            params: Dict[str, Any] = {}
            if framework:
                where = "WHERE FRAMEWORK = %(fw)s"
                params["fw"] = framework
            checks = self.connector.execute_query(
                f"SELECT FRAMEWORK, CODE, DESCRIPTION, RULE FROM {DB}.{SCHEMA}.{TABLE_CHECKS} {where}",
                params,
            ) or []
        except Exception:
            checks = []
        if not checks:
            return 0
        assets = self._fetch_asset_features()
        # Preload assets with provisional I/A pending review (older than 7 days)
        provisional_set: set[str] = set()
        try:
            q = self.connector.execute_query(
                f"""
                SELECT DISTINCT ASSET_FULL_NAME AS FULL
                FROM {DB}.DATA_GOVERNANCE.CLASSIFICATION_QUEUE
                WHERE REASON = 'PROVISIONAL_IA'
                  AND COALESCE(CREATED_AT, CURRENT_TIMESTAMP) < DATEADD(day, -%(days)s, CURRENT_TIMESTAMP)
                LIMIT 5000
                """,
                {"days": int(getattr(settings, 'SLA_PROVISIONAL_IA_DAYS', 7))}
            ) or []
            provisional_set = {str(r.get('FULL')).upper() for r in q if r.get('FULL')}
        except Exception:
            provisional_set = set()
        if not assets:
            return 0
        written = 0
        import uuid as _uuid
        from json import dumps as _dumps

        # Helper evaluators
        def eval_tag_coverage(a: Dict[str, Any]) -> bool:
            return bool(a.get("HAS_TAGS"))

        def eval_pii_minimums(a: Dict[str, Any]) -> bool:
            # We approximate PII presence by C >= 2 (post-classification) or expect masking
            # For enforcement, require (C >= 2) AND HAS_MASKING = TRUE
            c = int(a.get("C") or 0)
            return (c >= 2) and bool(a.get("HAS_MASKING"))

        def eval_sox_minimums(a: Dict[str, Any]) -> bool:
            # Approximate SOX sensitivity by C >= 2; require masking or row access
            c = int(a.get("C") or 0)
            return (c >= 2) and (bool(a.get("HAS_MASKING")) or bool(a.get("HAS_ROW_ACCESS")))

        def eval_ia_provisional_review(a: Dict[str, Any]) -> bool:
            # Pass when asset is NOT pending provisional IA review beyond the grace period
            full = str(a.get("FULL_NAME") or "").upper()
            return full not in provisional_set

        code_to_fn = {
            "TAG_COVERAGE": eval_tag_coverage,
            "PII_MINIMUMS": eval_pii_minimums,
            "SOX_MINIMUMS": eval_sox_minimums,
            "IA_PROVISIONAL_REVIEW": eval_ia_provisional_review,
        }

        for chk in checks:
            code = (chk.get("CODE") or "").upper()
            fw = chk.get("FRAMEWORK") or ""
            fn = code_to_fn.get(code)
            if not fn:
                continue
            for a in assets:
                try:
                    passed = bool(fn(a))
                    rid = str(_uuid.uuid4())
                    self.connector.execute_non_query(
                        f"""
                        INSERT INTO {DB}.{SCHEMA}.{TABLE_CHECK_RESULTS}
                        (ID, CHECK_CODE, FRAMEWORK, ASSET_FULL_NAME, PASSED, DETAILS, RUN_AT)
                        SELECT %(id)s, %(code)s, %(fw)s, %(full)s, %(ok)s, TO_VARIANT(PARSE_JSON(%(det)s)), CURRENT_TIMESTAMP
                        """,
                        {
                            "id": rid,
                            "code": code,
                            "fw": fw,
                            "full": a.get("FULL_NAME",""),
                            "ok": passed,
                            "det": _dumps({
                                "C": int(a.get("C") or 0),
                                "HAS_TAGS": bool(a.get("HAS_TAGS")),
                                "HAS_MASKING": bool(a.get("HAS_MASKING")),
                                "HAS_ROW_ACCESS": bool(a.get("HAS_ROW_ACCESS")),
                                "rule": chk.get("RULE"),
                            }),
                        },
                    )
                    # Evidence snapshot for check result
                    try:
                        self.add_evidence(
                            category="CHECK",
                            ref_id=rid,
                            description=f"Check {code} on {a.get('FULL_NAME','')} ({'PASSED' if passed else 'FAILED'})",
                            data={
                                "framework": fw,
                                "asset": a.get("FULL_NAME",""),
                                "passed": passed,
                                "features": {
                                    "C": int(a.get("C") or 0),
                                    "HAS_TAGS": bool(a.get("HAS_TAGS")),
                                    "HAS_MASKING": bool(a.get("HAS_MASKING")),
                                    "HAS_ROW_ACCESS": bool(a.get("HAS_ROW_ACCESS")),
                                },
                                "rule": chk.get("RULE"),
                            },
                            created_by="system",
                        )
                    except Exception:
                        pass
                    written += 1
                except Exception:
                    continue
        return written

    def list_check_results(self, framework: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        try:
            if framework:
                return self.connector.execute_query(
                    f"SELECT * FROM {DB}.{SCHEMA}.{TABLE_CHECK_RESULTS} WHERE FRAMEWORK = %(fw)s ORDER BY RUN_AT DESC LIMIT %(lim)s",
                    {"fw": framework, "lim": limit},
                ) or []
            return self.connector.execute_query(
                f"SELECT * FROM {DB}.{SCHEMA}.{TABLE_CHECK_RESULTS} ORDER BY RUN_AT DESC LIMIT %(lim)s",
                {"lim": limit},
            ) or []
        except Exception:
            return []

    # --- Seed minimal controls and checks (starter library) ---
    def seed_controls_and_checks(self, framework: str) -> int:
        """Seed a minimal set of controls and checks for the given framework (e.g., 'SOC 2', 'SOX').
        Returns number of rows inserted across CONTROLS and CHECKS.
        """
        fw = (framework or '').strip()
        if not fw:
            return 0
        inserted = 0
        # Ensure auxiliary tables used by UI (defined in Compliance page) also exist here for safety
        try:
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.FRAMEWORKS (
                  ID STRING,
                  NAME STRING,
                  VERSION STRING,
                  EFFECTIVE_DATE DATE,
                  NEXT_REVIEW_DATE DATE,
                  OWNER STRING,
                  CREATED_AT TIMESTAMP_NTZ
                )
                """
            )
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.CONTROLS (
                  ID STRING,
                  FRAMEWORK STRING,
                  CONTROL_ID STRING,
                  TITLE STRING,
                  DESCRIPTION STRING,
                  STATUS STRING,
                  OWNER STRING,
                  UPDATED_AT TIMESTAMP_NTZ
                )
                """
            )
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.CHECKS (
                  ID STRING,
                  FRAMEWORK STRING,
                  CODE STRING,
                  DESCRIPTION STRING,
                  RULE STRING,
                  CREATED_AT TIMESTAMP_NTZ
                )
                """
            )
        except Exception:
            pass

        import uuid as _uuid
        from datetime import datetime as _dt

        # Define starter controls and checks
        if fw.upper().replace(' ', '') == 'SOC2':
            controls = [
                ("CC6.1", "Logical Access Controls", "Logical access is restricted to authorized users and roles."),
                ("CC7.2", "Change Management", "Changes are authorized, tested, approved, and documented."),
                ("CC8.1", "Data Classification Governance", "Classification procedures are defined, documented, and followed."),
            ]
            checks = [
                ("TAG_COVERAGE", "All inventoried assets have baseline classification tags", "TAG_COVERAGE"),
                ("PII_MINIMUMS", "PII/Financial/Auth assets have masking policies", "PII_MINIMUMS"),
                ("SLA_5_DAY_OVERDUE", "No asset is overdue for initial classification beyond 5 days", "SLA_5_DAY_OVERDUE"),
                ("IA_PROVISIONAL_REVIEW", "Provisional I/A items reviewed within SLA window", "IA_PROVISIONAL_REVIEW"),
            ]
        elif fw.upper() == 'SOX':
            controls = [
                ("ITGC-Access", "Access to Financial Data", "Access to financial reporting data is restricted and monitored."),
                ("ITGC-Change", "Change Management", "Changes to financial reporting systems are controlled."),
                ("ITAC-Classification", "Financial Data Classification", "Financial reporting data is classified and protected according to policy."),
            ]
            checks = [
                ("SOX_MINIMUMS", "SOX-relevant datasets have masking or row access policies", "SOX_MINIMUMS"),
                ("SLA_5_DAY_OVERDUE", "No asset is overdue for initial classification beyond 5 days", "SLA_5_DAY_OVERDUE"),
                ("IA_PROVISIONAL_REVIEW", "Provisional I/A items reviewed within SLA window", "IA_PROVISIONAL_REVIEW"),
            ]
        else:
            controls, checks = [], []

        # Upsert-like inserts (skip if exists)
        for cid, title, desc in controls:
            try:
                exists = self.connector.execute_query(
                    f"SELECT 1 FROM {DB}.{SCHEMA}.CONTROLS WHERE FRAMEWORK = %(fw)s AND CONTROL_ID = %(cid)s LIMIT 1",
                    {"fw": fw, "cid": cid},
                )
                if not exists:
                    self.connector.execute_non_query(
                        f"""
                        INSERT INTO {DB}.{SCHEMA}.CONTROLS
                        (ID, FRAMEWORK, CONTROL_ID, TITLE, DESCRIPTION, STATUS, OWNER, UPDATED_AT)
                        SELECT %(id)s, %(fw)s, %(cid)s, %(t)s, %(d)s, 'Planned', 'governance@system', CURRENT_TIMESTAMP
                        """,
                        {"id": str(_uuid.uuid4()), "fw": fw, "cid": cid, "t": title, "d": desc},
                    )
                    inserted += 1
            except Exception:
                continue

        for code, desc, rule in checks:
            try:
                exists = self.connector.execute_query(
                    f"SELECT 1 FROM {DB}.{SCHEMA}.CHECKS WHERE FRAMEWORK = %(fw)s AND CODE = %(c)s LIMIT 1",
                    {"fw": fw, "c": code},
                )
                if not exists:
                    self.connector.execute_non_query(
                        f"""
                        INSERT INTO {DB}.{SCHEMA}.CHECKS
                        (ID, FRAMEWORK, CODE, DESCRIPTION, RULE, CREATED_AT)
                        SELECT %(id)s, %(fw)s, %(code)s, %(desc)s, %(rule)s, CURRENT_TIMESTAMP
                        """,
                        {"id": str(_uuid.uuid4()), "fw": fw, "code": code, "desc": desc, "rule": rule},
                    )
                    inserted += 1
            except Exception:
                continue

        return inserted

    # --- Evidence helper ---
    def add_evidence(self, category: str, ref_id: str, description: str, data: dict, created_by: str = "system") -> str:
        evid = str(uuid.uuid4())
        try:
            self.connector.execute_non_query(
                f"""
                INSERT INTO {DB}.{SCHEMA}.{TABLE_EVIDENCE}
                (ID, CATEGORY, REF_ID, DESCRIPTION, DATA, CREATED_AT, CREATED_BY)
                SELECT %(id)s, %(cat)s, %(ref)s, %(desc)s, TO_VARIANT(PARSE_JSON(%(dat)s)), CURRENT_TIMESTAMP, %(by)s
                """,
                {"id": evid, "cat": category, "ref": ref_id, "desc": description, "dat": __import__("json").dumps(data or {}), "by": created_by},
            )
            return evid
        except Exception:
            return ""

    def create_remediation_task(self, violation_id: str, assignee: str, due_date: str) -> str:
        tid = str(uuid.uuid4())
        self.connector.execute_non_query(
            f"""
            INSERT INTO {DB}.{SCHEMA}.{TABLE_REMEDIATION}
            (ID, VIOLATION_ID, ASSIGNEE, DUE_DATE, STATUS, CREATED_AT, UPDATED_AT)
            SELECT %(id)s, %(vid)s, %(asg)s, %(due)s, 'Open', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            """,
            {"id": tid, "vid": violation_id, "asg": assignee, "due": due_date},
        )
        audit_service.log(assignee, "CREATE_REMEDIATION", "VIOLATION", violation_id, {"task_id": tid, "due": due_date})
        return tid

    def _rule_gdpr_missing_tag(self) -> List[Dict[str, Any]]:
        """Flag assets likely containing EU personal data without GDPR regulatory tag."""
        sql = f"""
        WITH inv AS (
          SELECT FULLY_QUALIFIED_NAME AS FULL_NAME, COALESCE(CLASSIFICATION_LABEL,'') AS CLASSIFICATION_LEVEL,
                 CAST(COALESCE(CONFIDENTIALITY_LEVEL,'0') AS INT) AS C
          FROM {DB}.{SCHEMA}.ASSETS
        ),
        tags AS (
          SELECT UPPER(OBJECT_DATABASE||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME) AS FULL,
                 LISTAGG(UPPER(TAG_NAME)||':'||UPPER(COALESCE(TAG_VALUE,'')), ',') WITHIN GROUP (ORDER BY TAG_NAME) AS TAGS
          FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
          GROUP BY 1
        )
        SELECT inv.FULL_NAME
        FROM inv
        LEFT JOIN tags ON UPPER(inv.FULL_NAME) = tags.FULL
        WHERE (
          UPPER(inv.FULL_NAME) REGEXP 'SSN|EMAIL|PHONE|ADDRESS|DOB|PII|CUSTOMER|PERSON|EMPLOYEE|EU|GDPR'
          OR UPPER(inv.CLASSIFICATION_LEVEL) IN ('RESTRICTED','CONFIDENTIAL')
          OR inv.C >= 2
        )
        AND (
          tags.TAGS IS NULL OR tags.TAGS NOT LIKE '%GDPR%'
        )
        LIMIT 200
        """
        return self.connector.execute_query(sql)

    def _rule_hipaa_missing_controls(self) -> List[Dict[str, Any]]:
        """Flag assets likely containing PHI without HIPAA tag or masking policy references."""
        sql = f"""
        WITH inv AS (
          SELECT FULLY_QUALIFIED_NAME AS FULL_NAME, COALESCE(CLASSIFICATION_LABEL,'') AS CLASSIFICATION_LEVEL,
                 CAST(COALESCE(CONFIDENTIALITY_LEVEL,'0') AS INT) AS C
          FROM {DB}.{SCHEMA}.ASSETS
        ),
        tags AS (
          SELECT UPPER(OBJECT_DATABASE||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME) AS FULL,
                 LISTAGG(UPPER(TAG_NAME)||':'||UPPER(COALESCE(TAG_VALUE,'')), ',') WITHIN GROUP (ORDER BY TAG_NAME) AS TAGS
          FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
          GROUP BY 1
        ),
        policy_refs AS (
          SELECT DISTINCT UPPER(REF_DATABASE_NAME||'.'||REF_SCHEMA_NAME||'.'||REF_ENTITY_NAME) AS FULL
          FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
          WHERE POLICY_KIND = 'MASKING POLICY'
        )
        SELECT inv.FULL_NAME
        FROM inv
        LEFT JOIN tags ON UPPER(inv.FULL_NAME) = tags.FULL
        LEFT JOIN policy_refs pr ON UPPER(inv.FULL_NAME) = pr.FULL
        WHERE (
          UPPER(inv.FULL_NAME) REGEXP 'PHI|PATIENT|MEDICAL|HEALTH|DIAGNOSIS|CLAIM|RX|HIPAA'
          OR UPPER(inv.CLASSIFICATION_LEVEL) IN ('RESTRICTED','CONFIDENTIAL')
          OR inv.C >= 2
        )
        AND (
          (tags.TAGS IS NULL OR tags.TAGS NOT LIKE '%HIPAA%')
          OR pr.FULL IS NULL
        )
        LIMIT 200
        """
        return self.connector.execute_query(sql)


compliance_service = ComplianceService()
