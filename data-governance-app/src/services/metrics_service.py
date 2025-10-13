"""
Metrics Service (Source of Truth)
- Uses Snowflake ACCOUNT_USAGE.TAG_REFERENCES (tags) and {DB}.DATA_GOVERNANCE tables (governance)
- Provides coverage, SOX/SOC2 counts, schema/database breakdowns, and historical trends
"""
from __future__ import annotations
from typing import Dict, Any, List, Optional
import logging

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_GOVERNANCE"  # inventory/history
COMPLIANCE_SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"  # canonical compliance mapping


class MetricsService:
    def __init__(self) -> None:
        self.connector = snowflake_connector

    def _has_table(self, fqn: str) -> bool:
        try:
            db, sch, tbl = fqn.split(".")
            rows = self.connector.execute_query(
                """
                select 1
                from IDENTIFIER(%(db)s).INFORMATION_SCHEMA.TABLES
                where TABLE_SCHEMA = %(s)s and TABLE_NAME = %(t)s
                limit 1
                """,
                {"db": db, "s": sch, "t": tbl},
            )
            return bool(rows)
        except Exception:
            return False

    def classification_coverage(self, database: Optional[str] = None, schema: Optional[str] = None) -> Dict[str, Any]:
        """
        Coverage based on inventory vs classification tags applied.
        - Inventory source: {DB}.DATA_GOVERNANCE.ASSET_INVENTORY (FULL_NAME)
        - Tag source: ACCOUNT_USAGE.TAG_REFERENCES for DATA_CLASSIFICATION/CONFIDENTIALITY_LEVEL
        - Optional filter by database name prefix.
        """
        db = database or DB
        inv_schema = schema or SCHEMA
        inv_fqn = f"{db}.{inv_schema}.ASSET_INVENTORY"
        result = {"total_assets": 0, "tagged_assets": 0, "coverage_pct": 0.0}
        try:
            if not self._has_table(inv_fqn):
                return result
            where = ""
            params: Dict[str, Any] = {}
            if database:
                where = " where upper(split_part(FULL_NAME,'.',1)) = %(dbu)s"
                params["dbu"] = database.upper()
            total_rows = self.connector.execute_query(
                f"select count(*) as C from {inv_fqn}{where}", params
            ) or [{"C": 0}]
            total = int(total_rows[0].get("C", 0))
            tagged_rows = self.connector.execute_query(
                f"""
                with inv as (
                  select upper(FULL_NAME) as FULL from {inv_fqn}{where}
                )
                select count(distinct inv.FULL) as C
                from inv
                join SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tr
                  on inv.FULL = upper(tr.OBJECT_DATABASE||'.'||tr.OBJECT_SCHEMA||'.'||tr.OBJECT_NAME)
                 and tr.TAG_NAME in ('DATA_CLASSIFICATION','CONFIDENTIALITY_LEVEL','INTEGRITY_LEVEL','AVAILABILITY_LEVEL')
                """,
                params,
            ) or [{"C": 0}]
            tagged = int(tagged_rows[0].get("C", 0))
            cov = (float(tagged) / float(total) * 100.0) if total else 0.0
            result.update({"total_assets": total, "tagged_assets": tagged, "coverage_pct": round(cov, 2)})
            return result
        except Exception as e:
            logger.error(f"coverage failed: {e}")
            return result

    def framework_counts(self, database: Optional[str] = None, schema: Optional[str] = None) -> Dict[str, int]:
        """
        Framework counts using canonical COMPLIANCE_MAPPING if available, else fallback to COMPLIANCE_CATEGORY tag.
        Returns counts for keys: SOX, SOC, GDPR, HIPAA, PCI.
        """
        counts = {"SOX": 0, "SOC": 0, "GDPR": 0, "HIPAA": 0, "PCI": 0}
        try:
            db = database or DB
            comp_schema = schema or COMPLIANCE_SCHEMA
            cmap_fqn = f"{db}.{comp_schema}.COMPLIANCE_MAPPING"
            if self._has_table(cmap_fqn):
                rows = self.connector.execute_query(
                    f"""
                    select upper(FRAMEWORK_NAME) as FW, count(distinct ASSET_ID) as CNT
                    from {cmap_fqn}
                    group by 1
                    """
                ) or []
                for r in rows:
                    fw = (r.get("FW") or "").upper()
                    cnt = int(r.get("CNT") or 0)
                    if "SOX" in fw:
                        counts["SOX"] += cnt
                    if "SOC" in fw:
                        counts["SOC"] += cnt
                    if "GDPR" in fw:
                        counts["GDPR"] += cnt
                    if "HIPAA" in fw:
                        counts["HIPAA"] += cnt
                    if "PCI" in fw:
                        counts["PCI"] += cnt
                return counts
            # Fallback: COMPLIANCE_CATEGORY tag on objects
            where_obj = ""
            params: Dict[str, Any] = {}
            if database:
                where_obj = " where upper(OBJECT_DATABASE) = %(dbu)s"
                params["dbu"] = database.upper()
            rows = self.connector.execute_query(
                f"""
                select upper(TAG_VALUE) as TV, count(*) as CNT
                from SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                where upper(TAG_NAME) = 'COMPLIANCE_CATEGORY'
                {where_obj}
                group by 1
                """,
                params,
            ) or []
            for r in rows:
                tv = (r.get("TV") or "").upper()
                cnt = int(r.get("CNT") or 0)
                if "SOX" in tv:
                    counts["SOX"] += cnt
                if "SOC" in tv:
                    counts["SOC"] += cnt
                if "GDPR" in tv:
                    counts["GDPR"] += cnt
                if "HIPAA" in tv:
                    counts["HIPAA"] += cnt
                if "PCI" in tv:
                    counts["PCI"] += cnt
            return counts
        except Exception as e:
            logger.error(f"framework_counts failed: {e}")
            return counts

    def historical_classifications(self, database: Optional[str] = None, days: int = 30) -> List[Dict[str, Any]]:
        """
        Time series of classification decisions for last N days from CLASSIFICATION_DECISIONS.
        """
        db = database or DB
        fqn = f"{db}.{SCHEMA}.CLASSIFICATION_DECISIONS"
        try:
            if not self._has_table(fqn):
                return []
            rows = self.connector.execute_query(
                f"""
                select to_date(DECIDED_AT) as DAY,
                       count(*) as DECISIONS
                from {fqn}
                where DECIDED_AT >= dateadd(day, -%(d)s, current_timestamp())
                group by 1
                order by 1
                """,
                {"d": int(days)},
            ) or []
            return rows
        except Exception as e:
            logger.error(f"historical_classifications failed: {e}")
            return []

    def overdue_unclassified(self, database: Optional[str] = None) -> int:
        """
        Count assets overdue for initial classification (>5 days) from ASSET_INVENTORY.
        """
        db = database or DB
        inv = f"{db}.{SCHEMA}.ASSET_INVENTORY"
        try:
            if not self._has_table(inv):
                return 0
            rows = self.connector.execute_query(
                f"""
                select count(*) as C
                from {inv}
                where coalesce(CLASSIFIED, false) = false
                  and coalesce(FIRST_DISCOVERED, current_timestamp()) < dateadd(day, -5, current_timestamp())
                """
            ) or [{"C": 0}]
            return int(rows[0].get("C", 0))
        except Exception as e:
            logger.error(f"overdue_unclassified failed: {e}")
            return 0


metrics_service = MetricsService()
