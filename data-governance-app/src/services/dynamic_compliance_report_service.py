"""
Dynamic Compliance Report Service

Generates compliance coverage dynamically by joining:
- Sensitive categories from CLASSIFICATION_HISTORY.CLASSIFICATION_HISTORY
- CIA/tag levels from ACCOUNT_USAGE.TAG_REFERENCES
- Protection flags from ACCOUNT_USAGE.POLICY_REFERENCES
- AI/NLP extracted rules from DATA_GOVERNANCE.POLICIES and framework registry DATA_GOVERNANCE.FRAMEWORKS

Writes roll-up metrics to DATA_GOVERNANCE.COMPLIANCE_REPORTS and violations to DATA_GOVERNANCE.VIOLATIONS.
"""
from __future__ import annotations

from typing import Optional, Dict, Any, List
import uuid
import json
import logging

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.audit_service import audit_service

logger = logging.getLogger(__name__)


class DynamicComplianceReportService:
    def __init__(self) -> None:
        self.connector = snowflake_connector

    def _asset_policy_view_sql(self, database: Optional[str] = None) -> str:
        db = (database or settings.SNOWFLAKE_DATABASE).upper()
        return f"""
        WITH tags AS (
          SELECT 
            UPPER(OBJECT_DATABASE)||'.'||UPPER(OBJECT_SCHEMA)||'.'||UPPER(OBJECT_NAME) AS FULL_NAME,
            MAX(CASE WHEN TAG_NAME = 'DATA_CLASSIFICATION' THEN TAG_VALUE END) AS LABEL,
            TRY_TO_NUMBER(MAX(CASE WHEN TAG_NAME = 'CONFIDENTIALITY_LEVEL' THEN TAG_VALUE END)) AS C,
            TRY_TO_NUMBER(MAX(CASE WHEN TAG_NAME = 'INTEGRITY_LEVEL' THEN TAG_VALUE END)) AS I,
            TRY_TO_NUMBER(MAX(CASE WHEN TAG_NAME = 'AVAILABILITY_LEVEL' THEN TAG_VALUE END)) AS A
          FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
          WHERE OBJECT_DATABASE = '{db}'
          GROUP BY 1
        ), pol AS (
          SELECT 
            UPPER(OBJECT_DATABASE)||'.'||UPPER(OBJECT_SCHEMA)||'.'||UPPER(OBJECT_NAME) AS FULL_NAME,
            MAX(CASE WHEN POLICY_KIND='MASKING POLICY' THEN 1 ELSE 0 END) AS HAS_MASKING_POLICY,
            MAX(CASE WHEN POLICY_KIND='ROW ACCESS POLICY' THEN 1 ELSE 0 END) AS HAS_ROW_ACCESS_POLICY
          FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
          WHERE OBJECT_DATABASE = '{db}'
          GROUP BY 1
        ), cats AS (
          SELECT 
            UPPER(ASSET_FULL_NAME) AS FULL_NAME,
            ARRAY_AGG_DISTINCT(UPPER(value)::STRING) WITHIN GROUP (ORDER BY value) AS CATEGORIES
          FROM (
            SELECT ASSET_FULL_NAME, SENSITIVE_CATEGORIES AS ARR
            FROM {db}.CLASSIFICATION_HISTORY.CLASSIFICATION_HISTORY
            WHERE SENSITIVE_CATEGORIES IS NOT NULL
          ), LATERAL FLATTEN(input => ARR)
          GROUP BY 1
        )
        SELECT 
          COALESCE(tags.FULL_NAME, pol.FULL_NAME, cats.FULL_NAME) AS FULL_NAME,
          NVL(tags.LABEL,'Internal') AS LABEL,
          NVL(tags.C,0) AS C,
          NVL(tags.I,0) AS I,
          NVL(tags.A,0) AS A,
          NVL(pol.HAS_MASKING_POLICY,0) AS HAS_MASKING_POLICY,
          NVL(pol.HAS_ROW_ACCESS_POLICY,0) AS HAS_ROW_ACCESS_POLICY,
          NVL(cats.CATEGORIES, ARRAY_CONSTRUCT()) AS CATEGORIES
        FROM tags
        FULL OUTER JOIN pol USING(FULL_NAME)
        FULL OUTER JOIN cats USING(FULL_NAME)
        """

    def generate_reports(self, database: Optional[str] = None, author: str = "system") -> Dict[str, Any]:
        db = (database or settings.SNOWFLAKE_DATABASE).upper()
        # Build temp asset-policy view
        apv_sql = self._asset_policy_view_sql(db)
        try:
            self.connector.execute_non_query("CREATE OR REPLACE TEMP TABLE APV AS " + apv_sql)
        except Exception as e:
            return {"ok": False, "error": f"Failed to build APV: {e}"}
        # Load frameworks and policies
        fws = self.connector.execute_query(f"SELECT NAME FROM {db}.DATA_GOVERNANCE.FRAMEWORKS") or []
        reports = 0
        violations = 0
        for r in fws:
            fw = r.get('NAME')
            if not fw:
                continue
            policies = self.connector.execute_query(
                f"""
                SELECT RULE_CODE, CATEGORY, COALESCE(MIN_CONFIDENTIALITY,0) AS MIN_C, 
                       COALESCE(REQUIRE_MASKING,false) AS REQ_MASK, COALESCE(REQUIRE_ROW_ACCESS,false) AS REQ_ROW
                FROM {db}.DATA_GOVERNANCE.POLICIES
                WHERE UPPER(FRAMEWORK) = UPPER(%(fw)s)
                """,
                {"fw": fw},
            ) or []
            rows = self.connector.execute_query("SELECT * FROM APV") or []
            total = len(rows)
            compliant = 0
            non_compliant_assets: List[Dict[str, Any]] = []
            for a in rows:
                cats = set([str(x).upper() for x in (a.get('CATEGORIES') or [])])
                C = int(a.get('C') or 0)
                has_mask = int(a.get('HAS_MASKING_POLICY') or 0) == 1
                has_row = int(a.get('HAS_ROW_ACCESS_POLICY') or 0) == 1
                applicable = [p for p in policies if str(p.get('CATEGORY') or '').upper() in cats] if cats else []
                asset_ok = True
                failed_reasons: List[str] = []
                for p in applicable:
                    min_c = int(p.get('MIN_C') or 0)
                    if C < min_c:
                        asset_ok = False
                        failed_reasons.append(f"C<{min_c}")
                    if bool(p.get('REQ_MASK')) and not has_mask:
                        asset_ok = False
                        failed_reasons.append("masking")
                    if bool(p.get('REQ_ROW')) and not has_row:
                        asset_ok = False
                        failed_reasons.append("row_access")
                if asset_ok:
                    compliant += 1
                else:
                    non_compliant_assets.append({
                        "FULL_NAME": a.get('FULL_NAME'),
                        "C": C,
                        "CATEGORIES": sorted(list(cats)),
                        "failed": failed_reasons,
                    })
            # Write report summary
            try:
                rid = str(uuid.uuid4())
                metrics = {
                    "framework": fw,
                    "total_assets": total,
                    "compliant_assets": compliant,
                    "non_compliant_assets": len(non_compliant_assets),
                }
                self.connector.execute_non_query(
                    f"""
                    INSERT INTO {db}.DATA_GOVERNANCE.COMPLIANCE_REPORTS
                    (ID, FRAMEWORK, GENERATED_AT, GENERATED_BY, METRICS, LOCATION)
                    SELECT %(id)s, %(fw)s, CURRENT_TIMESTAMP, %(by)s, TO_VARIANT(PARSE_JSON(%(m)s)), NULL
                    """,
                    {"id": rid, "fw": fw, "by": author, "m": json.dumps(metrics)},
                )
                reports += 1
            except Exception as e:
                logger.warning(f"Report insert failed for {fw}: {e}")
            # Violations for non-compliant assets
            for item in non_compliant_assets[:1000]:
                try:
                    vid = str(uuid.uuid4())
                    self.connector.execute_non_query(
                        f"""
                        INSERT INTO {db}.DATA_GOVERNANCE.VIOLATIONS
                        (ID, RULE_CODE, SEVERITY, DESCRIPTION, ASSET_FULL_NAME, DETECTED_AT, STATUS, DETAILS)
                        SELECT %(id)s, %(rule)s, 'High', %(desc)s, %(full)s, CURRENT_TIMESTAMP, 'Open', TO_VARIANT(PARSE_JSON(%(det)s))
                        """,
                        {
                            "id": vid,
                            "rule": f"FW:{fw}",
                            "desc": f"Non-compliant with {fw}: {', '.join(item.get('failed') or [])}",
                            "full": item.get('FULL_NAME'),
                            "det": json.dumps(item),
                        },
                    )
                    violations += 1
                except Exception as e:
                    logger.warning(f"Violation insert failed for {fw}: {e}")
        try:
            audit_service.log(author, "GENERATE_COMPLIANCE_REPORTS", "FRAMEWORKS", db, {"reports": reports, "violations": violations})
        except Exception:
            pass
        return {"reports": reports, "violations": violations}


dynamic_compliance_report_service = DynamicComplianceReportService()
