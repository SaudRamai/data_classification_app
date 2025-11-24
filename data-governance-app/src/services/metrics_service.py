"""
Metrics Service for Data Governance Dashboard

This service provides various metrics and analytics for the dashboard,
including classification coverage, framework counts, and historical data.
"""
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)


GOV_SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"


def _active_db() -> Optional[str]:
    db = getattr(settings, "SNOWFLAKE_DATABASE", None)
    if not db or str(db).strip().upper() in {"", "NONE", "(NONE)", "NULL", "UNKNOWN"}:
        return None
    return str(db)


def _fqn(db: str, obj: str) -> str:
    return f"{db}.{GOV_SCHEMA}.{obj}"


class MetricsService:
    def __init__(self):
        self.connector = snowflake_connector

    def classification_coverage(self, database: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculate classification coverage metrics based on ASSETS table
        in <DB>.DATA_CLASSIFICATION_GOVERNANCE.
        """
        try:
            db = database or _active_db()
            if not db:
                return {
                    'total_assets': 0,
                    'tagged_assets': 0,
                    'coverage_pct': 0.0,
                    'error': 'No active database context'
                }
            assets_fqn = _fqn(db, 'ASSETS')
            query = f"""
                SELECT
                    COUNT(*) AS TOTAL_ASSETS,
                    COUNT(CASE WHEN COALESCE(CLASSIFICATION_LABEL,'') <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED' THEN 1 END) AS TAGGED_ASSETS,
                    ROUND(
                        100.0 * COUNT(CASE WHEN COALESCE(CLASSIFICATION_LABEL,'') <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED' THEN 1 END)
                        / NULLIF(COUNT(*), 0), 2
                    ) AS COVERAGE_PCT
                FROM {assets_fqn}
            """
            rows = self.connector.execute_query(query) or []
            if rows:
                total = int(rows[0].get('TOTAL_ASSETS', 0) or 0)
                tagged = int(rows[0].get('TAGGED_ASSETS', 0) or 0)
                pct = float(rows[0].get('COVERAGE_PCT', 0.0) or 0.0)
                return {'total_assets': total, 'tagged_assets': tagged, 'coverage_pct': pct}
            return {'total_assets': 0, 'tagged_assets': 0, 'coverage_pct': 0.0}
        except Exception as e:
            logger.error(f"Error calculating classification coverage: {e}")
            return {'total_assets': 0, 'tagged_assets': 0, 'coverage_pct': 0.0, 'error': str(e)}

    def framework_counts(self, database: Optional[str] = None) -> Dict[str, int]:
        """
        Approximate framework counts. Without a canonical summary view, use ASSETS.COMPLIANCE_STATUS
        if present; otherwise return empty.
        """
        try:
            db = database or _active_db()
            if not db:
                return {}
            assets_fqn = _fqn(db, 'ASSETS')
            # Best-effort: use COMPLIANCE_STATUS if exists; otherwise fallback to DATA_CLASSIFICATION buckets
            query = f"""
                SELECT
                  COALESCE(COMPLIANCE_STATUS, 'UNKNOWN') AS FRAMEWORK,
                  COUNT(*) AS COUNT
                FROM {assets_fqn}
                GROUP BY 1
                ORDER BY 2 DESC
            """
            rows = self.connector.execute_query(query) or []
            out: Dict[str, int] = {}
            for r in rows:
                fw = str(r.get('FRAMEWORK') or 'UNKNOWN')
                cnt = int(r.get('COUNT') or 0)
                out[fw] = cnt
            return out
        except Exception as e:
            logger.error(f"Error getting framework counts: {e}")
            return {}

    def historical_classifications(self, days: int = 30, database: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Return daily counts from CLASSIFICATION_DECISIONS if available.
        """
        try:
            db = database or _active_db()
            if not db:
                return []
            decisions_fqn = _fqn(db, 'CLASSIFICATION_DECISIONS')
            query = f"""
                SELECT
                  DATE(COALESCE(CREATED_AT, CURRENT_DATE())) AS DAY,
                  COALESCE(ACTION, 'UNKNOWN') AS CLASSIFICATION_STATUS,
                  COUNT(*) AS DECISIONS
                FROM {decisions_fqn}
                WHERE COALESCE(CREATED_AT, CURRENT_DATE()) >= DATEADD(day, -%(d)s, CURRENT_DATE())
                GROUP BY 1,2
                ORDER BY 1,2
            """
            rows = self.connector.execute_query(query, {"d": int(days)}) or []
            return [
                {
                    'DAY': r.get('DAY'),
                    'classification_status': r.get('CLASSIFICATION_STATUS'),
                    'DECISIONS': int(r.get('DECISIONS') or 0),
                }
                for r in rows
            ]
        except Exception as e:
            logger.error(f"Error getting historical classifications: {e}")
            return []

    def overdue_unclassified(self, database: Optional[str] = None) -> Dict[str, int]:
        """
        Count overdue unclassified assets (no classification label and older than 7 days by timestamps).
        Group by OVERALL_RISK_CLASSIFICATION when available; otherwise return total.
        """
        try:
            db = database or _active_db()
            if not db:
                return {}
            assets_fqn = _fqn(db, 'ASSETS')
            query = f"""
                SELECT
                  COALESCE(OVERALL_RISK_CLASSIFICATION, 'UNKNOWN') AS RISK_LEVEL,
                  COUNT(*) AS COUNT
                FROM {assets_fqn}
                WHERE (CLASSIFICATION_LABEL IS NULL OR CLASSIFICATION_LABEL = '')
                  AND COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP, CURRENT_TIMESTAMP()) < DATEADD(day, -7, CURRENT_TIMESTAMP())
                GROUP BY 1
            """
            rows = self.connector.execute_query(query) or []
            out: Dict[str, int] = {}
            for r in rows:
                rk = str(r.get('RISK_LEVEL') or 'UNKNOWN')
                out[rk] = int(r.get('COUNT') or 0)
            return out
        except Exception as e:
            logger.error(f"Error getting overdue unclassified assets: {e}")
            return {}


# Singleton instance
metrics_service = MetricsService()
