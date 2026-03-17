from typing import List, Optional, Dict, Any, Tuple
import json
from datetime import datetime
import math
import re
import logging
import pandas as pd
try:
    import numpy as _np  # optional
except Exception:
    _np = None  # type: ignore

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

# --- Constants ---
T_ASSETS = "ASSETS"
T_AI_RESULTS = "CLASSIFICATION_AI_RESULTS"
UNCLASSIFIED_VALS = "('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL', 'N/A', 'TBD', 'ACTION REQUIRED', 'PENDING REVIEW')"

class MetadataCatalogService:




    def __init__(self):
        self.sf = snowflake_connector

    def _q(self, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return self.sf.execute_query(sql, params)

    def _x(self, sql: str, params: Optional[Dict[str, Any]] = None) -> int:
        return self.sf.execute_non_query(sql, params)

    def run_asset_merge(self, database: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes the stored procedure to merge newly discovered Snowflake assets
        into the ASSETS table.
        """
        db = database or settings.SNOWFLAKE_DATABASE or "DATA_CLASSIFICATION_DB"
        logger.info(f"Running asset merge for {db}")
        try:
            # Call the SP and capture return message
            # The query returns a single column with the result message
            res = self._q(f"CALL {db}.DATA_CLASSIFICATION_GOVERNANCE.SP_MERGE_ASSETS()")
            msg = res[0].get('SP_MERGE_ASSETS', '') if res else ''
            
            # Optional: Parse counts from message if format matches 'MERGE_COMPLETE — X inserted, Y updated'
            inserted = 0
            updated = 0
            if "MERGE_COMPLETE" in msg:
                try:
                    parts = msg.split('—')[1].split(',')
                    s_ins = re.search(r'(\d+)', parts[0])
                    s_upd = re.search(r'(\d+)', parts[1])
                    inserted = int(s_ins.group(1)) if s_ins else 0
                    updated = int(s_upd.group(1)) if s_upd else 0
                except Exception:
                    # Fallback to current timestamp based counts if parsing fails
                    stats = self._q(f"SELECT COUNT(*) AS CNT FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS WHERE CREATED_TIMESTAMP >= DATEADD(minute, -5, CURRENT_TIMESTAMP()) AND RECORD_VERSION = 1")
                    inserted = stats[0]['CNT'] if stats else 0
                    upd_stats = self._q(f"SELECT COUNT(*) AS CNT FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS WHERE LAST_MODIFIED_TIMESTAMP >= DATEADD(minute, -5, CURRENT_TIMESTAMP()) AND RECORD_VERSION > 1")
                    updated = upd_stats[0]['CNT'] if upd_stats else 0
            
            return {"inserted": inserted, "updated": updated, "message": msg}
        except Exception as e:
            logger.error(f"Asset merge failed: {e}")
            return {"error": str(e)}

    def get_asset_counts(self, database: str, schema: str) -> Dict[str, Any]:
        """Calculate asset coverage and counts solely from the ASSETS table."""
        try:
            fqn = f"{database}.{schema}.{T_ASSETS}"
            query = f"""
                SELECT
                    COUNT(*) AS TOTAL,
                    COUNT(CASE 
                        WHEN CLASSIFICATION_LABEL IS NOT NULL 
                        AND UPPER(TRIM(CLASSIFICATION_LABEL)) NOT IN {UNCLASSIFIED_VALS} 
                        THEN 1 END) AS TAGGED
                FROM {fqn}
                WHERE UPPER(ASSET_TYPE) IN ('TABLE', 'VIEW', 'BASE TABLE', 'STORED_PROCEDURE', 'FUNCTION', 'STAGE', 'DATABASE')
            """
            rows = self._q(query) or [{}]
            r = rows[0]
            total = int(r.get('TOTAL', 0))
            tagged = int(r.get('TAGGED', 0))
            
            return {
                'total_assets': total,
                'classified_count': tagged,
                'unclassified_count': total - tagged,
                'coverage_pct': round(100.0 * tagged / max(total, 1), 2)
            }
        except Exception as e:
            logger.error(f"Error in get_asset_counts: {e}")
            return {'total_assets': 0, 'classified_count': 0, 'unclassified_count': 0, 'coverage_pct': 0.0}

    def get_health_score_metrics(self, db: str, schema: str) -> Dict[str, Any]:
        """Calculate Classification Health Program metrics using the standard view."""
        try:
            db_val = db or settings.SNOWFLAKE_DATABASE or "DATA_CLASSIFICATION_DB"
            view_fqn = f"{db_val}.DATA_CLASSIFICATION_GOVERNANCE.VW_ASSET_INVENTORY_ALL_LEVELS"
            query = f"""
                SELECT
                    "Total_Assets"               AS total,
                    "Classified"                 AS classified,
                    "Has_Classification_Date"    AS has_date,
                    "SLA_Breach_Assets"          AS sla_breach,
                    "New_Pending_Assets"         AS new_pending,
                    "Accuracy_Percent"           AS accuracy_str,
                    "Timeliness_Percent"         AS timeliness_str,
                    "Owner_Coverage"             AS owner_cov_str,
                    "Avg_Days_To_Classify"       AS avg_days,
                    "Classification_Coverage"    AS coverage_str
                FROM {view_fqn}
                WHERE LEVEL = 'DATABASE'
                  AND UPPER("Database") = UPPER('{db}')
                LIMIT 1
            """
            rows = self._q(query)
            if not rows:
                # Try a broader query if specific database not found
                query = f"""
                    SELECT
                        SUM("Total_Assets")            AS total,
                        SUM("Classified")              AS classified,
                        SUM("Has_Classification_Date") AS has_date,
                        SUM("SLA_Breach_Assets")       AS sla_breach,
                        SUM("New_Pending_Assets")      AS new_pending,
                        AVG("Avg_Days_To_Classify")    AS avg_days
                    FROM {view_fqn}
                    WHERE LEVEL = 'DATABASE'
                """
                rows = self._q(query)
            
            r = rows[0] if rows else {}

            def _parse_pct(val):
                try:
                    s = str(val or '0').strip().split('%')[0].strip()
                    return float(s)
                except Exception: return 0.0

            total = int(r.get('TOTAL') or 0)
            classified = int(r.get('CLASSIFIED') or 0)
            cov_pct = _parse_pct(r.get('COVERAGE_STR')) if r.get('COVERAGE_STR') else (round(100.0 * classified / total, 1) if total > 0 else 0.0)
            acc_pct = _parse_pct(r.get('ACCURACY_STR'))
            tim_pct = _parse_pct(r.get('TIMELINESS_STR'))
            gov_pct = _parse_pct(r.get('OWNER_COV_STR'))

            overall_score = (cov_pct + acc_pct + tim_pct + gov_pct) / 4.0

            return {
                'overall_score': round(overall_score, 1),
                'total_assets': total,
                'classified_count': classified,
                'coverage_pct': cov_pct,
                'approval_pct': acc_pct,
                'sla_pct': tim_pct,
                'reviews_pct': gov_pct,
                'sla_breach': int(r.get('SLA_BREACH') or 0),
                'new_pending': int(r.get('NEW_PENDING') or 0),
                'avg_days': float(r.get('AVG_DAYS') or 0),
                'health_status': "Healthy" if overall_score > 80 else "Monitor" if overall_score > 60 else "Action Required",
                'last_updated': datetime.now().strftime("%Y-%m-%d %H:%M")
            }
        except Exception as e:
            logger.error(f"Error in get_health_score_metrics: {e}")
            return {'overall_score': 0, 'health_status': "Error"}

    def get_dashboard_sensitivity_overview(self, db: str, schema: str, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Fetch sensitivity distribution using the standardized inventory view."""
        try:
            db_val = db or settings.SNOWFLAKE_DATABASE or "DATA_CLASSIFICATION_DB"
            view_fqn = f"{db_val}.DATA_CLASSIFICATION_GOVERNANCE.VW_ASSET_INVENTORY_ALL_LEVELS"
            
            where_conds = ["LEVEL = 'ASSET'"]
            if filters:
                f_db = filters.get("db")
                if f_db and str(f_db) != "All": where_conds.append(f"\"Database\" = '{f_db}'")
                elif db and db.upper() not in ("ALL", ""): where_conds.append(f"\"Database\" = '{db}'")
                
                if filters.get("schema") and filters["schema"] != "All":
                    where_conds.append(f"\"Schema\" = '{filters['schema']}'")
                if filters.get("table") and filters["table"] != "All":
                    where_conds.append(f"\"Asset_Name\" = '{filters['table']}'")
                if filters.get("bu") and filters["bu"] != "All":
                    where_conds.append(f"\"Business_Unit\" = '{filters['bu']}'")
                if filters.get("atype") and filters["atype"] != "All":
                    where_conds.append(f"\"Asset_Type\" = '{filters['atype']}'")

            where_sql = " AND ".join(where_conds)
            
            # Fetch aggregated counts from the view
            query = f"""
                SELECT 
                    COUNT(*) as TOTAL,
                    SUM("Classified") as LABELED,
                    -- Parsing Sensitive_Columns string (e.g., '1 PII, 0 SOX, 0 SOC2')
                    SUM(REGEXP_SUBSTR("Sensitive_Columns", '(\\\\d+) PII', 1, 1, 'e')::INT) as PII,
                    SUM(REGEXP_SUBSTR("Sensitive_Columns", '(\\\\d+) SOX', 1, 1, 'e')::INT) as SOX,
                    SUM(REGEXP_SUBSTR("Sensitive_Columns", '(\\\\d+) SOC2', 1, 1, 'e')::INT) as SOC2
                FROM {view_fqn}
                WHERE {where_sql}
            """
            rows = self._q(query)
            r = rows[0] if rows else {}
            total = int(r.get('TOTAL') or 0)
            pii = int(r.get('PII') or 0)
            
            # Fetch label distribution
            # Note: The view doesn't explicitly store the raw CLASSIFICATION_LABEL in all versions, 
            # but we can infer distribution or join back if needed. For now, let's use the ASSETS table 
            # for the distribution to maintain granularity, but filter based on the same logic.
            assets_fqn = f"{db_val}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS"
            dist_query = f"""
                SELECT 
                    COALESCE(CLASSIFICATION_LABEL, 'Unclassified') as LABEL,
                    COUNT(*) as C
                FROM {assets_fqn}
                WHERE DATABASE_NAME = '{db}'
                GROUP BY 1
            """
            lbl_rows = self._q(dist_query)
            labels = {str(x.get("LABEL")): int(x.get("C") or 0) for x in lbl_rows}

            return {
                'total_assets': total, 
                'labels': labels, 
                'pii_count': pii,
                'non_pii_count': max(0, total - pii),
                'regulated': {
                    'PII': pii, 
                    'SOX': int(r.get("SOX") or 0), 
                    'SOC2': int(r.get("SOC2") or 0),
                    'OTHER_REG': int(r.get("PII") or 0) + int(r.get("SOX") or 0) + int(r.get("SOC2") or 0)
                }
            }
        except Exception as e:
            logger.error(f"Error in get_dashboard_sensitivity_overview: {e}")
            return {'total_assets': 0, 'labels': {}}

    def get_unclassified_assets_summary(self, db: str, schema: str) -> Dict[str, Any]:
        """Return summary of unclassified assets, partially reusing health metrics."""
        try:
            health = self.get_health_score_metrics(db, schema)
            
            assets = self._q(f"""
                SELECT ASSET_NAME, DATABASE_NAME || '.' || SCHEMA_NAME as SCOPE, COALESCE(DATA_OWNER, 'Unknown') as OWNER,
                       DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) as DAYS_UNCLASSIFIED
                FROM {db}.{schema}.{T_ASSETS}
                WHERE (CLASSIFICATION_LABEL IS NULL OR UPPER(TRIM(CLASSIFICATION_LABEL)) IN {UNCLASSIFIED_VALS})
                ORDER BY CREATED_TIMESTAMP ASC LIMIT 10
            """) or []
            
            return {
                'total_unclassified': health.get('total_assets', 0) - health.get('classified_count', 0),
                'sla_breached': health.get('sla_breach', 0),
                'new_pending': health.get('new_pending', 0),
                'assets': assets
            }
        except Exception as e:
            logger.error(f"Error in get_unclassified_assets_summary: {e}")
            return {'total_unclassified': 0, 'assets': []}

    def get_review_due_summary(self, db: str, schema: str) -> Dict[str, Any]:
        """Return counts of reviews due."""
        try:
            fqn = f"{db}.{schema}.{T_ASSETS}"
            r = (self._q(f"SELECT COUNT(CASE WHEN NEXT_REVIEW_DATE < CURRENT_DATE() THEN 1 END) as O, COUNT(CASE WHEN NEXT_REVIEW_DATE BETWEEN CURRENT_DATE() AND DATEADD(day, 30, CURRENT_DATE()) THEN 1 END) as U FROM {fqn} WHERE DATABASE_NAME IS NOT NULL") or [{}])[0]
            
            assets = self._q(f"SELECT ASSET_NAME, COALESCE(DATA_OWNER, 'Unknown') as OWNER, NEXT_REVIEW_DATE, DATEDIFF('day', CURRENT_DATE(), NEXT_REVIEW_DATE) as DAYS_REMAINING FROM {fqn} WHERE DATABASE_NAME IS NOT NULL AND NEXT_REVIEW_DATE <= DATEADD(day, 30, CURRENT_DATE()) ORDER BY NEXT_REVIEW_DATE LIMIT 10") or []
            return {'overdue_count': int(r.get('O', 0)), 'upcoming_count': int(r.get('U', 0)), 'assets': assets}
        except Exception: return {'overdue_count': 0, 'upcoming_count': 0, 'assets': []}

    def get_non_compliant_assets_detail(self, db: str, schema: str) -> pd.DataFrame:
        """Return detailed list of non-compliant assets."""
        try:
            rows = self._q(f"SELECT CASE WHEN OVERALL_RISK_CLASSIFICATION = 'High' THEN 'URGENT' ELSE 'NORMAL' END as PRIORITY, ASSET_NAME, COALESCE(NON_COMPLIANCE_REASON, 'Policy Violation Detected') as REASON, COALESCE(DATA_OWNER, 'N/A') as OWNER, DATABASE_NAME || '.' || SCHEMA_NAME as SCOPE FROM {db}.{schema}.{T_ASSETS} WHERE COMPLIANCE_STATUS <> 'COMPLIANT' LIMIT 20")
            return pd.DataFrame(rows) if rows else pd.DataFrame()
        except Exception: return pd.DataFrame()

metadata_catalog_service = MetadataCatalogService()
asset_catalog_service = metadata_catalog_service

# --- Global Aliases for Backward Compatibility ---
def run_asset_merge(*args, **kwargs): return asset_catalog_service.run_asset_merge(*args, **kwargs)
def get_asset_counts(*args, **kwargs): return asset_catalog_service.get_asset_counts(*args, **kwargs)
def get_health_score_metrics(*args, **kwargs): return asset_catalog_service.get_health_score_metrics(*args, **kwargs)
def get_sensitivity_overview(*args, **kwargs): return asset_catalog_service.get_sensitivity_overview(*args, **kwargs)
def get_dashboard_sensitivity_overview(*args, **kwargs): return asset_catalog_service.get_dashboard_sensitivity_overview(*args, **kwargs)
def get_unclassified_assets_summary(*args, **kwargs): return asset_catalog_service.get_unclassified_assets_summary(*args, **kwargs)
def get_review_due_summary(*args, **kwargs): return asset_catalog_service.get_review_due_summary(*args, **kwargs)
def get_non_compliant_assets_detail(*args, **kwargs): return asset_catalog_service.get_non_compliant_assets_detail(*args, **kwargs)
