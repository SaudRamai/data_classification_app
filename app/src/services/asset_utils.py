"""
Asset Utilities Service
Consolidated into the services layer. Provides metrics functionality solely based on 
ASSETS and CLASSIFICATION_AI_RESULTS tables as the authoritative data sources.
"""
from typing import Dict, List, Any, Optional
import pandas as pd
from datetime import datetime
import logging

from src.connectors.snowflake_connector import snowflake_connector

logger = logging.getLogger(__name__)

# Table Names centrally managed for consistency
T_ASSETS = "ASSETS"
T_AI_RESULTS = "CLASSIFICATION_AI_RESULTS"

# Sentinel values for unclassified status
UNCLASSIFIED_VALS = "('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL', 'N/A', 'TBD', 'ACTION REQUIRED', 'PENDING REVIEW')"

def get_asset_counts(database: str, schema: str) -> Dict[str, Any]:
    """Calculate asset coverage and counts solely from the ASSETS table."""
    try:
        fqn = f"{database}.{schema}.{T_ASSETS}"
        # Robust filter for "classified" assets
        query = f"""
            SELECT
                COUNT(*) AS TOTAL,
                COUNT(CASE 
                    WHEN CLASSIFICATION_LABEL IS NOT NULL 
                    AND UPPER(TRIM(CLASSIFICATION_LABEL)) NOT IN {UNCLASSIFIED_VALS} 
                    THEN 1 END) AS TAGGED
            FROM {fqn}
            WHERE UPPER(ASSET_TYPE) IN ('TABLE', 'VIEW', 'BASE TABLE')
        """
        rows = snowflake_connector.execute_query(query) or [{}]
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

def get_health_score_metrics(db: str, schema: str, connector=None) -> Dict[str, Any]:
    """Calculate Classification Health Program metrics.
    Queries VW_ASSET_INVENTORY_ALL_LEVELS directly at DATABASE level
    so all numbers match the view exactly.
    """
    try:
        # Always query from DATA_CLASSIFICATION_DB (authoritative source)
        view_fqn = "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.VW_ASSET_INVENTORY_ALL_LEVELS"
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
                "Avg_Days_To_Classify"       AS avg_days
            FROM {view_fqn}
            WHERE LEVEL = 'DATABASE'
              AND UPPER("Database") = UPPER('{db}')
            LIMIT 1
        """
        rows = snowflake_connector.execute_query(query) or [{}]
        r = rows[0] if rows else {}

        def _parse_pct(val):
            """Convert '30%' or '30% ✅' style string to float."""
            try:
                s = str(val or '0').strip()
                s = s.split('%')[0].strip()
                return float(s)
            except Exception:
                return 0.0

        total = int(r.get('TOTAL') or 0)
        classified = int(r.get('CLASSIFIED') or 0)

        cov_pct = round(100.0 * classified / total, 1) if total > 0 else 0.0
        acc_pct = _parse_pct(r.get('ACCURACY_STR'))
        tim_pct = _parse_pct(r.get('TIMELINESS_STR'))
        gov_pct = _parse_pct(r.get('OWNER_COV_STR'))   # Owner coverage as governance proxy

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
        return {
            'overall_score': 0, 'total_assets': 0, 'classified_count': 0,
            'coverage_pct': 0, 'approval_pct': 0, 'sla_pct': 0, 'reviews_pct': 0,
            'sla_breach': 0, 'new_pending': 0, 'avg_days': 0,
            'health_status': "Error"
        }

def get_sensitivity_overview(db: str, schema: str, connector=None) -> Dict[str, Any]:
    """Return asset counts grouped by sensitivity/risk level from the ASSETS table.
    
    This is the primary data source for the Dashboard's Sensitivity Overview.
    """
    try:
        conn = connector or snowflake_connector
        fqn = f"{db}.{schema}.{T_ASSETS}"
        
        # 1. Sensitivity Distribution (Pie Chart) - Based on CLASSIFICATION_LABEL
        label_rows = conn.execute_query(
            f"""
            SELECT
                CASE
                    WHEN CLASSIFICATION_LABEL IS NULL OR TRIM(CLASSIFICATION_LABEL) = '' THEN 'UNCLASSIFIED'
                    WHEN UPPER(TRIM(CLASSIFICATION_LABEL)) IN {UNCLASSIFIED_VALS} THEN 'UNCLASSIFIED'
                    WHEN UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('RESTRICTED', 'HIGH', 'H') THEN 'Restricted'
                    WHEN UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('CONFIDENTIAL', 'MEDIUM', 'M') THEN 'Confidential'
                    WHEN UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('INTERNAL', 'LOW', 'L') THEN 'Internal'
                    ELSE CLASSIFICATION_LABEL
                END AS CLASSIFICATION_LABEL,
                COUNT(*) as COUNT
            FROM {fqn}
            WHERE UPPER(COALESCE(ASSET_TYPE, '')) IN ('TABLE', 'VIEW', 'BASE TABLE')
            GROUP BY 1
            """
        ) or []
        labels = {str(r.get('CLASSIFICATION_LABEL')): int(r.get('COUNT', 0)) for r in label_rows}
        
        # 2. PII vs Non-PII (Bar Chart) - Based on PII_RELEVANT flag
        # We perform a robust query to get the PII count and total assets
        pii_metrics_q = f"""
            SELECT 
                COUNT(*) as TOTAL,
                COUNT(CASE WHEN PII_RELEVANT = TRUE THEN 1 END) as PII_COUNT,
                COUNT(CASE WHEN SOX_RELEVANT = TRUE THEN 1 END) as SOX_COUNT,
                COUNT(CASE WHEN SOC2_RELEVANT = TRUE THEN 1 END) as SOC2_COUNT
            FROM {fqn}
            WHERE UPPER(COALESCE(ASSET_TYPE, '')) IN ('TABLE', 'VIEW', 'BASE TABLE')
        """
        metrics_rows = conn.execute_query(pii_metrics_q) or [{}]
        r_met = metrics_rows[0]
        
        total_assets = int(r_met.get('TOTAL', 0))
        pii_count = int(r_met.get('PII_COUNT', 0))
        sox_count = int(r_met.get('SOX_COUNT', 0))
        soc2_count = int(r_met.get('SOC2_COUNT', 0))

        # 2.5 Broad Regulatory Coverage - ASSETS table doesn't have REGULATORY column
        reg_count = 0
        
        # Optional native discovery metric disabled for Marketplace portability
        native_pii_count = 0
            
        return {
            'total_assets': total_assets,
            'labels': labels,
            'pii_count': pii_count,
            'non_pii_count': max(0, total_assets - pii_count),
            'regulated': {
                'PII': pii_count,
                'SOX': sox_count,
                'SOC2': soc2_count,
                'OTHER_REG': 0,
                'NATIVE_DISCOVERY': native_pii_count
            }
        }
    except Exception as e:
        logger.error(f"Error in get_sensitivity_overview: {e}")
        return {
            'labels': {}, 
            'pii_count': 0, 
            'non_pii_count': 0, 
            'regulated': {'PII': 0, 'SOX': 0, 'SOC2': 0, 'NATIVE_DISCOVERY': 0}
        }

def get_dashboard_sensitivity_overview(db: str, schema: str, connector=None, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        conn = connector or snowflake_connector
        # The authoritative governance table is in DATA_CLASSIFICATION_DB
        global_db = "DATA_CLASSIFICATION_DB"
        fqn = f"{global_db}.{schema}.{T_ASSETS}"
        
        where_conds = ["1=1"] # or UPPER(COALESCE(ASSET_TYPE, '')) IN ('TABLE', 'VIEW', 'BASE TABLE')
        if filters:
            sc = filters.get("schema") or filters.get("SCHEMA")
            tb = filters.get("table") or filters.get("TABLE")
            
            # The database selected in the UI filter
            f_db = filters.get("db") 
            if f_db and str(f_db) != "All":
                where_conds.append(f"DATABASE_NAME = '{f_db}'")
            elif db and str(db).strip().upper() not in ("NONE", "NULL", "(NONE)", "UNKNOWN", "ALL", "") and db != global_db:
                where_conds.append(f"DATABASE_NAME = '{db}'")
                
            if sc and str(sc) != "All":
                where_conds.append(f"SCHEMA_NAME = '{sc}'")
            if tb and str(tb) != "All":
                where_conds.append(f"ASSET_NAME = '{tb}'")
                
            bu = filters.get("bu")
            if bu and bu != "All":
                where_conds.append(f"BUSINESS_UNIT = '{bu}'")
                
            atype = filters.get("atype")
            if atype and atype != "All":
                where_conds.append(f"ASSET_TYPE = '{atype}'")
                
            risk = filters.get("risk")
            if risk and risk != "All":
                where_conds.append(f"OVERALL_RISK_CLASSIFICATION = '{risk}'")
            
        where_sql = " AND ".join(where_conds)

        q = f"""
            WITH asset_metrics AS (
                SELECT 
                    COALESCE(DATABASE_NAME, 'DATA_CLASSIFICATION_DB') as DATABASE_NAME,
                    SCHEMA_NAME,
                    ASSET_NAME,
                    ASSET_TYPE,
                    CLASSIFICATION_LABEL,
                    PII_RELEVANT as IS_PII,
                    SOX_RELEVANT as IS_SOX,
                    SOC2_RELEVANT as IS_SOC2,
                    CASE 
                        WHEN CLASSIFICATION_LABEL IS NOT NULL 
                             AND UPPER(TRIM(CLASSIFICATION_LABEL)) NOT IN (
                                 '', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 
                                 'NULL', 'N/A', 'TBD', 'ACTION REQUIRED', 'PENDING REVIEW'
                             )
                        THEN 1 
                        ELSE 0 
                    END as IS_CLASSIFIED
                FROM {fqn}
                WHERE {where_sql} AND DATABASE_NAME IS NOT NULL
            )
            SELECT
                COUNT(*) AS TOTAL,
                COALESCE(SUM(CAST(IS_PII AS INT)), 0) AS PII,
                COALESCE(SUM(CAST(IS_SOX AS INT)), 0) AS SOX,
                COALESCE(SUM(CAST(IS_SOC2 AS INT)), 0) AS SOC2,
                COALESCE(SUM(CAST(IS_CLASSIFIED AS INT)), 0) AS LABELED
            FROM asset_metrics
        """

        rows = conn.execute_query(q) or [{}]
        r = rows[0] or {}
        total_assets = int(r.get("TOTAL") or 0)
        pii_count = int(r.get("PII") or 0)
        sox_count = int(r.get("SOX") or 0)
        soc2_count = int(r.get("SOC2") or 0)

        # Label distribution from ASSETS using the same CTE base
        q_lbl = f"""
            WITH asset_metrics AS (
                SELECT 
                    CLASSIFICATION_LABEL
                FROM {fqn}
                WHERE {where_sql} AND DATABASE_NAME IS NOT NULL
            )
            SELECT
                CASE
                    WHEN CLASSIFICATION_LABEL IS NULL OR TRIM(CLASSIFICATION_LABEL) = '' THEN 'UNCLASSIFIED'
                    WHEN UPPER(TRIM(CLASSIFICATION_LABEL)) IN {UNCLASSIFIED_VALS} THEN 'UNCLASSIFIED'
                    WHEN UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('RESTRICTED', 'HIGH', 'H') THEN 'Restricted'
                    WHEN UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('CONFIDENTIAL', 'MEDIUM', 'M') THEN 'Confidential'
                    WHEN UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('INTERNAL', 'LOW', 'L') THEN 'Internal'
                    ELSE CLASSIFICATION_LABEL
                END AS LABEL,
                COUNT(*) AS C
            FROM asset_metrics
            GROUP BY 1
        """
        lbl_rows = conn.execute_query(q_lbl) or []
        labels = {str(x.get("LABEL")): int(x.get("C") or 0) for x in lbl_rows if x.get("LABEL")}
        
        # Regulatory count - ASSETS table doesn't have REGULATORY column directly in this view
        reg_count = 0

        return {
            'total_assets': total_assets,
            'labels': labels,
            'pii_count': pii_count,
            'non_pii_count': max(0, total_assets - pii_count),
            'regulated': {
                'PII': pii_count,
                'SOX': sox_count,
                'SOC2': soc2_count,
                'OTHER_REG': 0,
                'NATIVE_DISCOVERY': 0,
            },
        }
    except Exception as e:
        return {
            'total_assets': 0,
            'labels': { 'Error': 1, str(e): 1 },
            'pii_count': 0,
            'non_pii_count': 0,
            'regulated': {
                'PII': 0,
                'SOX': 0,
                'SOC2': 0,
                'OTHER_REG': 0,
                'NATIVE_DISCOVERY': 0,
            },
        }

def get_unclassified_assets_summary(db: str, schema: str, connector=None) -> Dict[str, Any]:
    """Return summary of unclassified assets and SLA status from the ASSETS table."""
    try:
        conn = connector or snowflake_connector
        fqn = f"{db}.{schema}.{T_ASSETS}"
        # Optimized counts for unclassified assets
        view_fqn = "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.VW_ASSET_INVENTORY_ALL_LEVELS"

        # Pull summary counts directly from the view (DATABASE level)
        view_query = f"""
            SELECT
                "Total_Assets"       AS total,
                "Classified"         AS classified,
                "SLA_Breach_Assets"  AS sla_breach,
                "New_Pending_Assets" AS new_pending
            FROM {view_fqn}
            WHERE LEVEL = 'DATABASE'
              AND UPPER("Database") = UPPER('{db}')
            LIMIT 1
        """
        vrows = conn.execute_query(view_query) or [{}]
        vr = vrows[0] if vrows else {}

        total_assets   = int(vr.get('TOTAL') or 0)
        classified     = int(vr.get('CLASSIFIED') or 0)
        sla_breached   = int(vr.get('SLA_BREACH') or 0)
        new_pending    = int(vr.get('NEW_PENDING') or 0)
        total_unclassified = total_assets - classified

        # Detail list: top 10 oldest unclassified assets from ASSETS table
        assets_query = f"""
            SELECT 
                ASSET_NAME,
                DATABASE_NAME || '.' || SCHEMA_NAME as SCOPE,
                COALESCE(DATA_OWNER, 'Unknown') as OWNER,
                DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) as DAYS_UNCLASSIFIED,
                CASE WHEN DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) >= 5 
                     THEN '⚠️ High Risk' ELSE 'Normal' END as RISK_STATUS
            FROM {fqn}
            WHERE (CLASSIFICATION_LABEL IS NULL 
               OR UPPER(TRIM(CLASSIFICATION_LABEL)) IN {UNCLASSIFIED_VALS})
              AND DATABASE_NAME IS NOT NULL
            ORDER BY CREATED_TIMESTAMP ASC NULLS LAST
            LIMIT 10
        """
        assets = conn.execute_query(assets_query) or []

        return {
            'total_unclassified': total_unclassified,
            'sla_breached': sla_breached,
            'new_pending': new_pending,
            'assets': assets
        }
    except Exception as e:
        logger.error(f"Error in get_unclassified_assets_summary: {e}")
        return {'total_unclassified': 0, 'sla_breached': 0, 'new_pending': 0, 'assets': []}


def get_review_due_summary(db: str, schema: str, connector=None) -> Dict[str, Any]:
    """Return counts of reviews due from the ASSETS table.
    Uses the same CTE-based IS_CLASSIFIED logic as VW_ASSET_INVENTORY_ALL_LEVELS
    for consistent classification status detection.
    """
    try:
        conn = connector or snowflake_connector
        fqn = f"{db}.{schema}.{T_ASSETS}"

        # Use same CTE IS_CLASSIFIED logic as the view for consistent classification check
        counts_query = f"""
            WITH asset_metrics AS (
                SELECT
                    ASSET_NAME,
                    DATA_OWNER,
                    ASSET_TYPE,
                    NEXT_REVIEW_DATE,
                    REVIEW_FREQUENCY_DAYS,
                    LAST_REVIEW_DATE,
                    REVIEW_STATUS,
                    -- IS_CLASSIFIED matching view logic
                    CASE 
                        WHEN CLASSIFICATION_LABEL IS NOT NULL 
                             AND UPPER(TRIM(CLASSIFICATION_LABEL)) NOT IN (
                                 '', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 
                                 'NULL', 'N/A', 'TBD', 'ACTION REQUIRED', 'PENDING REVIEW'
                             )
                        THEN 1 
                        ELSE 0 
                    END as IS_CLASSIFIED,
                    -- Review status matching view logic
                    CASE 
                        WHEN UPPER(TRIM(COMPLIANCE_STATUS)) = 'COMPLIANT' THEN 'Compliant'
                        WHEN REVIEW_STATUS IN ('Approved', 'Validated') THEN 'Reviewed'
                        WHEN LAST_REVIEW_DATE IS NOT NULL 
                             AND DATEDIFF(day, LAST_REVIEW_DATE, CURRENT_DATE()) <= REVIEW_FREQUENCY_DAYS 
                        THEN 'Compliant'
                        WHEN NEXT_REVIEW_DATE < CURRENT_DATE() THEN 'Overdue'
                        ELSE 'Pending'
                    END as COMPUTED_REVIEW_STATUS
                FROM {fqn}
                WHERE DATABASE_NAME IS NOT NULL
                  AND UPPER(COALESCE(ASSET_TYPE, '')) IN ('TABLE', 'VIEW', 'BASE TABLE')
            )
            SELECT 
                COUNT(CASE WHEN NEXT_REVIEW_DATE < CURRENT_DATE() AND IS_CLASSIFIED = 1 THEN 1 END) as OVERDUE_COUNT,
                COUNT(CASE WHEN NEXT_REVIEW_DATE BETWEEN CURRENT_DATE() AND DATEADD(day, 30, CURRENT_DATE()) AND IS_CLASSIFIED = 1 THEN 1 END) as UPCOMING_COUNT
            FROM asset_metrics
        """
        counts = conn.execute_query(counts_query) or [{}]
        r = counts[0]

        overdue = int(r.get('OVERDUE_COUNT', 0))
        upcoming = int(r.get('UPCOMING_COUNT', 0))

        # Asset list using same CTE classification filter
        assets_query = f"""
            WITH asset_metrics AS (
                SELECT
                    ASSET_NAME,
                    COALESCE(DATA_OWNER, 'Unknown') as OWNER,
                    NEXT_REVIEW_DATE,
                    CASE 
                        WHEN CLASSIFICATION_LABEL IS NOT NULL 
                             AND UPPER(TRIM(CLASSIFICATION_LABEL)) NOT IN (
                                 '', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 
                                 'NULL', 'N/A', 'TBD', 'ACTION REQUIRED', 'PENDING REVIEW'
                             )
                        THEN 1 
                        ELSE 0 
                    END as IS_CLASSIFIED
                FROM {fqn}
                WHERE DATABASE_NAME IS NOT NULL
                  AND UPPER(COALESCE(ASSET_TYPE, '')) IN ('TABLE', 'VIEW', 'BASE TABLE')
            )
            SELECT
                ASSET_NAME,
                OWNER,
                NEXT_REVIEW_DATE,
                DATEDIFF('day', CURRENT_DATE(), NEXT_REVIEW_DATE) as DAYS_REMAINING,
                CASE WHEN NEXT_REVIEW_DATE < CURRENT_DATE() THEN '🔴 Overdue' ELSE '🟡 Upcoming' END as STATUS
            FROM asset_metrics
            WHERE IS_CLASSIFIED = 1
              AND (NEXT_REVIEW_DATE IS NULL OR NEXT_REVIEW_DATE <= DATEADD(day, 30, CURRENT_DATE()))
            ORDER BY NEXT_REVIEW_DATE ASC NULLS LAST
            LIMIT 10
        """
        assets = conn.execute_query(assets_query) or []

        return {
            'overdue_count': overdue,
            'upcoming_count': upcoming,
            'total_backlog': overdue + upcoming,
            'assets': assets
        }
    except Exception as e:
        logger.error(f"Error in get_review_due_summary: {e}")
        return {'overdue_count': 0, 'upcoming_count': 0, 'total_backlog': 0, 'assets': []}

def get_non_compliant_assets_detail(db: str, schema: str, connector=None) -> pd.DataFrame:
    """Return detailed list of non-compliant assets from the ASSETS table."""
    try:
        fqn = f"{db}.{schema}.{T_ASSETS}"
        query = f"""
            SELECT 
                CASE WHEN OVERALL_RISK_CLASSIFICATION = 'High' THEN 'URGENT' ELSE 'NORMAL' END as PRIORITY,
                ASSET_NAME,
                COALESCE(NON_COMPLIANCE_REASON, 'Policy Violation Detected') as REASON,
                COALESCE(DATA_OWNER, 'N/A') as OWNER,
                DATABASE_NAME || '.' || SCHEMA_NAME as SCOPE
            FROM {fqn}
            WHERE (COMPLIANCE_STATUS <> 'COMPLIANT' 
               OR (HAS_EXCEPTION = TRUE AND EXCEPTION_EXPIRY_DATE < CURRENT_DATE()))
               AND UPPER(ASSET_TYPE) IN ('TABLE', 'VIEW', 'BASE TABLE')
            LIMIT 20
        """
        rows = snowflake_connector.execute_query(query)
        if rows:
            return pd.DataFrame(rows)
    except Exception as e:
        logger.error(f"Error in get_non_compliant_assets_detail: {e}")
    return pd.DataFrame(columns=["PRIORITY", "ASSET_NAME", "REASON", "OWNER", "SCOPE"])

def get_compliance_coverage_metrics(db: str, schema: str, connector=None) -> Dict[str, Any]:
    """Return compliance coverage KPIs and trends derived from the governance tables."""
    try:
        conn = connector or snowflake_connector
        fqn_assets = f"{db}.{schema}.{T_ASSETS}"
        fqn_decisions = f"{db}.{schema}.{T_AI_RESULTS}" # Using AI results or decisions for trends
        
        # 1. Broad Coverage Metrics (Categorical Counts)
        pii_query = f"""
            SELECT
                COALESCE(ROUND(100.0 * COUNT(CASE 
                    WHEN PII_RELEVANT = TRUE 
                    AND CLASSIFICATION_LABEL IS NOT NULL 
                    AND UPPER(TRIM(CLASSIFICATION_LABEL)) NOT IN {UNCLASSIFIED_VALS} 
                    THEN 1 END) 
                    / NULLIF(COUNT(CASE WHEN PII_RELEVANT = TRUE THEN 1 END), 0), 1), 0.0) as PII_PCT,
                COUNT(CASE WHEN PII_RELEVANT = TRUE THEN 1 END) as PII_ASSETS,
                COUNT(CASE WHEN SOX_RELEVANT = TRUE THEN 1 END) as SOX_ASSETS,
                COUNT(CASE WHEN SOC2_RELEVANT = TRUE THEN 1 END) as SOC2_ASSETS,
                COUNT(CASE WHEN HAS_EXCEPTION = TRUE THEN 1 END) as EX_COUNT,
                COUNT(CASE WHEN SOX_RELEVANT = TRUE OR SOC2_RELEVANT = TRUE THEN 1 END) as REG_TOTAL
            FROM {fqn_assets}
            WHERE UPPER(COALESCE(ASSET_TYPE, '')) IN ('TABLE', 'VIEW', 'BASE TABLE')
        """
        rows = conn.execute_query(pii_query) or [{}]
        r = rows[0]
        
        # 2. Dynamic Trends (Classification Velocity)
        # We query the last 3 months to build the velocity trend
        trend_q = f"""
            SELECT 
                TO_CHAR(LAST_MODIFIED_TIMESTAMP, 'Mon') as MONTH,
                COUNT(*) as CLASSIFIED_COUNT,
                COUNT(CASE WHEN COMPLIANCE_STATUS != 'COMPLIANT' THEN 1 END) as NON_COMPLIANT_COUNT,
                AVG(CONFIDENTIALITY_LEVEL) as RISK_WEIGHT
            FROM {fqn_assets}
            WHERE CLASSIFICATION_LABEL IS NOT NULL 
              AND UPPER(TRIM(CLASSIFICATION_LABEL)) NOT IN {UNCLASSIFIED_VALS}
              AND LAST_MODIFIED_TIMESTAMP >= DATEADD(month, -3, CURRENT_DATE())
            GROUP BY 1, LAST_MODIFIED_TIMESTAMP
            ORDER BY LAST_MODIFIED_TIMESTAMP ASC
        """
        trend_rows = conn.execute_query(trend_q) or []
        
        # Format trends for the UI (grouped by month)
        trends_list = []
        if trend_rows:
            # Simple aggregation by month for the chart
            month_map = {}
            for row in trend_rows:
                m = row['MONTH']
                if m not in month_map:
                    month_map[m] = {'MONTH': m, 'CLASSIFIED_COUNT': 0, 'NON_COMPLIANT_COUNT': 0, 'RISK_WEIGHT': 0.0, 'CT': 0}
                month_map[m]['CLASSIFIED_COUNT'] += row['CLASSIFIED_COUNT']
                month_map[m]['NON_COMPLIANT_COUNT'] += row['NON_COMPLIANT_COUNT']
                month_map[m]['RISK_WEIGHT'] += float(row['RISK_WEIGHT'] or 0)
                month_map[m]['CT'] += 1
            
            for m in month_map:
                month_map[m]['RISK_WEIGHT'] = round(month_map[m]['RISK_WEIGHT'] / max(1, month_map[m]['CT']), 2)
                del month_map[m]['CT']
                trends_list.append(month_map[m])
        else:
            # Fallback to empty list or minimal mock for visualization
            trends_list = [
                {'MONTH': 'Jan', 'CLASSIFIED_COUNT': 0, 'NON_COMPLIANT_COUNT': 0, 'RISK_WEIGHT': 0.0},
                {'MONTH': 'Feb', 'CLASSIFIED_COUNT': 0, 'NON_COMPLIANT_COUNT': 0, 'RISK_WEIGHT': 0.0},
                {'MONTH': 'Mar', 'CLASSIFIED_COUNT': 0, 'NON_COMPLIANT_COUNT': 0, 'RISK_WEIGHT': 0.0}
            ]

        # 3. Native PII Detected (from system views)
        native_count = 0
        try:
             res = snowflake_connector.execute_query(f"SELECT COUNT(DISTINCT (OBJECT_DATABASE || '.' || OBJECT_SCHEMA || '.' || OBJECT_NAME)) as C FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES WHERE TAG_NAME='SEMANTIC_CATEGORY' AND OBJECT_DATABASE='{db}' AND DOMAIN='TABLE'")
             if res:
                 native_count = int(res[0].get('C', 0))
        except Exception:
            pass

        # 3.5 Specific Regulatory Breakdown (Special Categories)
        reg_breakdown = {}
        try:
            reg_bq = f"SELECT REGULATORY, COUNT(*) as C FROM {fqn_assets} WHERE REGULATORY IS NOT NULL AND REGULATORY != '' AND UPPER(ASSET_TYPE) IN ('TABLE', 'VIEW', 'BASE TABLE') GROUP BY 1"
            reg_rows = snowflake_connector.execute_query(reg_bq) or []
            reg_breakdown = {str(r['REGULATORY']): int(r['C']) for r in reg_rows}
        except Exception:
            pass

        # 4. Audit Readiness Score calculation
        # Simplified logic: (Classified PII Assets + Compliant Assets - Exceptions) / Total
        readiness_score = "HIGH"
        if total_assets > 0:
            # Real logic for readiness
            ready_ratio = (float(r.get('PII_PCT', 0)) / 100.0) * 0.7 + (1.0 - (int(r.get('EX_COUNT', 0)) / max(1, total_assets))) * 0.3
            if ready_ratio < 0.3: readiness_score = "CRITICAL"
            elif ready_ratio < 0.6: readiness_score = "MEDIUM"
            else: readiness_score = "HIGH"

        return {
            'pii_coverage_pct': float(r.get('PII_PCT') if r.get('PII_PCT') is not None else 0.0),
            'regulated_total': int(r.get('REG_TOTAL', 0)),
            'exception_count': int(r.get('EX_COUNT', 0)),
            'pii_assets': int(r.get('PII_ASSETS', 0)),
            'sox_assets': int(r.get('SOX_ASSETS', 0)),
            'soc2_assets': int(r.get('SOC2_ASSETS', 0)),
            'native_pii_detected': native_count,
            'audit_readiness': readiness_score,
            'regulatory_breakdown': reg_breakdown,
            'trends': {
                'classification': trends_list
            }
        }
    except Exception as e:
        logger.error(f"Error in get_compliance_coverage_metrics: {e}")
        return {
            'pii_coverage_pct': 0, 
            'regulated_total': 0, 
            'exception_count': 0, 
            'pii_assets': 0, 
            'sox_assets': 0, 
            'soc2_assets': 0, 
            'trends': {'classification': []}
        }

def seed_sample_assets(database: Optional[str] = None, schema: str = "DATA_CLASSIFICATION_GOVERNANCE", connector=None) -> Dict[str, Any]:
    """Maintain logic to initialize the authoritative tables."""
    from src.services.governance_config_service import governance_config_service
    try:
        return governance_config_service.refresh(database=database)
    except Exception:
        return {"ok": False}
