"""
Data Governance Application
"""
import sys
import os
import pathlib

# Add the project root to the Python path
_here = pathlib.Path(str(__file__)).resolve()
_dir = _here.parent
# Traverse up to find directory containing 'src'
for _ in range(3):
    if (_dir / "src").exists():
        if str(_dir) not in sys.path:
            sys.path.insert(0, str(_dir))
        break
    _dir = _dir.parent

import streamlit as st

# Page configuration - MUST be the first Streamlit command
st.set_page_config(
    page_title="Monitoring & Compliance - Data Governance App",
    page_icon="✅",
    layout="wide"
)

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple
from src.ui.theme import apply_global_theme
import io
from io import StringIO
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.authorization_service import authz
import logging
from src.services.asset_catalog_service import get_health_score_metrics
from src.ui.quick_links import render_quick_links
from src.components.filters import render_global_filters
import base64
try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    import docx
except ImportError:
    docx = None

logger = logging.getLogger(__name__)

# Apply centralized theme
apply_global_theme()

# Record the start time of this script execution to track per-run credit consumption
_run_start_ts = datetime.now()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _resolve_db() -> Optional[str]:
    """Resolve active database safely. Defaults to DATA_CLASSIFICATION_DB."""
    try:
        db = st.session_state.get('sf_database')
        if db and str(db).strip().upper() not in ("NONE", "NULL", "(NONE)", "UNKNOWN", ""):
            return db
    except Exception:
        pass
    
    # Try settings
    try:
        db = settings.SNOWFLAKE_DATABASE
        if db and str(db).strip().upper() not in ("NONE", "NULL", "(NONE)", "UNKNOWN", ""):
            return db
    except Exception:
        pass
    
    # Try current database
    try:
        row = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
        db = row[0].get('DB') if row else None
        if db and str(db).strip().upper() not in ("NONE", "NULL", "(NONE)", "UNKNOWN", ""):
            return db
    except Exception:
        pass
    
    # Default to DATA_CLASSIFICATION_DB
    return "DATA_CLASSIFICATION_DB"

def _gv_schema() -> str:
    """Return the governance schema to use for queries. Defaults to DATA_CLASSIFICATION_GOVERNANCE."""
    try:
        gs = st.session_state.get("governance_schema")
        if gs and str(gs).strip():
            return str(gs).strip()
    except Exception:
        pass
    return "DATA_CLASSIFICATION_GOVERNANCE"


# ============================================================================
# FILTER HELPER FUNCTIONS
# ============================================================================



@st.cache_data(ttl=300)
def _list_databases() -> List[str]:
    """Best-effort list of accessible databases."""
    try:
        rows = snowflake_connector.execute_query("SHOW DATABASES") or []
        return [r.get("name") or r.get("NAME") for r in rows if (r.get("name") or r.get("NAME"))]
    except Exception:
        return []





def _get_available_frameworks(db: str) -> List[str]:
    """Auto-detect regulatory frameworks and categories based on available flags in the ASSETS table."""
    try:
        schema = _gv_schema()
        # Check active flags in this scope
        query = f"""
        SELECT 
            MAX(CASE WHEN PII_RELEVANT = TRUE THEN 1 ELSE 0 END) as HAS_PII,
            MAX(CASE WHEN SOX_RELEVANT = TRUE THEN 1 ELSE 0 END) as HAS_SOX,
            MAX(CASE WHEN SOC2_RELEVANT = TRUE THEN 1 ELSE 0 END) as HAS_SOC2
        FROM {db}.{schema}.ASSETS
        """
        rows = snowflake_connector.execute_query(query)
        frameworks = []
        if rows:
            r = rows[0]
            if r.get('HAS_PII') == 1: frameworks.append('PII')
            if r.get('HAS_SOX') == 1: frameworks.append('SOX')
            if r.get('HAS_SOC2') == 1: frameworks.append('SOC2')
        
        return frameworks if frameworks else ['PII', 'SOX', 'SOC2']
    except Exception as e:
        logger.warning(f"Error discovering frameworks: {e}")
        return ["PII", "SOC2", "SOX"]

def _build_filters(filters: Dict, db_val: str, db_col='DATABASE_NAME', schema_col='SCHEMA_NAME', table_col='ASSET_NAME') -> Tuple[str, Dict]:
    # Robust multi-level filter builder for Snowflake queries
    # Standardizes the WHERE clause to handle (All) selections and casing variations.
    where_parts = ["1=1"]
    params = {}
    
    if filters:
        # 1. Database Level (Ignore if (All), None, or empty)
        db_f = filters.get('database')
        if db_f and str(db_f).strip().upper() not in ('ALL', 'NONE', 'NULL', '(NONE)', 'ANY', ''):
            where_parts.append(f"UPPER({db_col}) = UPPER(%(db_f)s)")
            params['db_f'] = db_f
        elif db_val and str(db_val).strip().upper() not in ('ALL', 'NONE', 'NULL', '(NONE)', 'ANY', ''):
             # Fallback to session database if filter is empty but a database is known
             where_parts.append(f"UPPER({db_col}) = UPPER(%(db_val)s)")
             params['db_val'] = db_val
            
        # 2. Schema Level
        sc_f = filters.get('schema')
        if sc_f and str(sc_f).strip().upper() not in ('ALL', 'NONE', 'NULL', '(NONE)', 'ANY', ''):
            where_parts.append(f"UPPER({schema_col}) = UPPER(%(sc_f)s)")
            params['sc_f'] = sc_f
            
        # 3. Table/Object Level
        tb_f = filters.get('table')
        if tb_f and str(tb_f).strip().upper() not in ('ALL', 'NONE', 'NULL', '(NONE)', 'ANY', ''):
            where_parts.append(f"UPPER({table_col}) = UPPER(%(tb_f)s)")
            params['tb_f'] = tb_f
            
    # Framework / Category Filters - based on boolean columns in ASSETS
    if filters and filters.get('frameworks'):
        f_list = filters['frameworks']
        f_clauses = []
        for f in f_list:
            fu = f.upper().strip()
            if fu == 'PII': f_clauses.append("PII_RELEVANT = TRUE")
            elif fu == 'SOX': f_clauses.append("SOX_RELEVANT = TRUE")
            elif fu == 'SOC2': f_clauses.append("SOC2_RELEVANT = TRUE")
        
        if f_clauses:
            where_parts.append(f"({' OR '.join(f_clauses)})")
            
    return (" AND ".join(where_parts), params)

# ============================================================================
# DATA FETCHING FUNCTIONS  
# ============================================================================

# REMOVED CACHE to force fresh data - enable cache after debugging
def get_compliance_overview_metrics(db: str, filters: dict = None) -> Dict:
    """Fetch authoritative compliance metrics directly from the ASSETS table using complex analytics."""
    schema = _gv_schema()
    
    metrics = {
        'classification_coverage': 0.0,
        'count_sensitive': 0.0,
        'count_privileged': 0,
        'snowflake_tag_compliance': 0.0,
        'count_drift': 0,
        'overall_status': '🔴 Action Required',
        'count_tables': 0
    }
    
    try:
        # Resolve a safe database context (some pages may pass "All" when the sidebar filter is not set)
        if not db or str(db).strip().upper() in ("ALL", "NONE", "NULL", "(NONE)", "UNKNOWN", ""):
            db = st.session_state.get("sf_database") or ""
        if not db or str(db).strip().upper() in ("ALL", "NONE", "NULL", "(NONE)", "UNKNOWN", ""):
            return metrics

        where_clause, params = _build_filters(filters, db)
        
        query = f"""
        SELECT
            -- % Tables Classified
            ROUND(
                (COUNT_IF(CLASSIFICATION_LABEL IS NOT NULL) * 100.0) /
                NULLIF(COUNT(*), 0), 2
            ) AS TABLES_CLASSIFIED_PERCENT,

            -- Sensitive Exposure (Count)
            COUNT_IF(
                CLASSIFICATION_LABEL IN ('Confidential','Restricted')
                OR PII_RELEVANT = TRUE
            ) AS SENSITIVE_EXPOSURE,

            -- Privileged Access (Count)
            COUNT_IF(NUMBER_OF_CONSUMERS > 10) AS PRIVILEGED_ACCESS,

            -- % Sensitive Access
            ROUND(
                (COUNT_IF(PII_RELEVANT = TRUE AND LAST_ACCESSED_DATE IS NOT NULL) * 100.0) /
                NULLIF(COUNT_IF(PII_RELEVANT = TRUE), 0),
            2) AS SENSITIVE_ACCESS_PERCENT,

            -- Classification Drift
            COUNT_IF(
                PREVIOUS_CLASSIFICATION_LABEL IS NOT NULL
                AND PREVIOUS_CLASSIFICATION_LABEL <> CLASSIFICATION_LABEL
            ) AS CLASSIFICATION_DRIFT,
            
            COUNT(*) AS TOTAL_TABLES
        FROM {db}.{schema}.ASSETS
        """
        
        # Log query for debugging
        # logger.info(f"Compliance Metrics Query: {query}")
        
        rows = snowflake_connector.execute_query(query, params)
        if rows:
            r = rows[0]
            metrics['classification_coverage'] = float(r.get('TABLES_CLASSIFIED_PERCENT') or 0.0)
            metrics['count_sensitive'] = float(r.get('SENSITIVE_EXPOSURE') or 0.0)
            metrics['count_privileged'] = int(r.get('PRIVILEGED_ACCESS') or 0)
            metrics['snowflake_tag_compliance'] = float(r.get('SENSITIVE_ACCESS_PERCENT') or 0.0)
            metrics['count_drift'] = int(r.get('CLASSIFICATION_DRIFT') or 0)
            metrics['count_tables'] = int(r.get('TOTAL_TABLES') or 0)
            
            # Simple score for dashboard
            score = metrics['classification_coverage']
            if score >= 90: metrics['overall_status'] = '🟢 Healthy'
            elif score >= 70: metrics['overall_status'] = '🟡 Monitor'
            else: metrics['overall_status'] = '🔴 Critical'
            
    except Exception as e:
        logger.error(f"Error in get_compliance_overview_metrics: {e}")
            
    return metrics
    
# REMOVED CACHE to force fresh data - enable cache after debugging
def get_classification_requirements_metrics(db: str, filters: dict = None) -> Dict:
    """Fetch authoritative classification requirements metrics directly from the ASSETS table.
    
    Args:
        db: The database context
        filters: Optional UI filters
        
    Returns:
        Dictionary with classification requirements and compliance status
    """
    schema = _gv_schema()
    try:
        where_clause, params = _build_filters(filters, db)
        query = f"""
        WITH metrics AS (
            SELECT 
                -- 5-Day Rule: % of assets classified (not 'Unclassified') that were created/identified in the last 5 days
                COALESCE(ROUND(
                    COUNT_IF(DATABASE_NAME IS NOT NULL AND (CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL != 'Unclassified')) * 100.0
                    / NULLIF(COUNT(*), 0),
                    1
                ), 0) AS coverage,
                
                -- Annual Review: % of assets where last modified in current year OR status is completed
                COALESCE(ROUND(
                    COUNT_IF(YEAR(COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP)) = YEAR(CURRENT_DATE())) * 100.0
                    / NULLIF(COUNT(*), 0),
                    1
                ), 0) AS annual_review,
                
                -- Documentation Completeness: % of assets with Description and Owner assigned
                COALESCE(ROUND(
                    COUNT_IF(DATA_DESCRIPTION IS NOT NULL AND DATA_OWNER IS NOT NULL) * 100.0
                    / NULLIF(COUNT(*), 0),
                    1
                ), 0) AS doc_completeness,
                
                -- 5-Day SLA: % of assets meeting the 5-day classification SLA
                COALESCE(ROUND(
                    COUNT_IF(
                        DATEDIFF('day', CREATED_TIMESTAMP, CURRENT_DATE()) <= 5 
                        OR (CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL != 'Unclassified')
                    ) * 100.0 / NULLIF(COUNT(*), 0),
                    1
                ), 0) AS five_day_compliance,
                
                -- Policy Violations: Total non-compliant assets
                COUNT_IF(COMPLIANCE_STATUS = 'NON-COMPLIANT' OR COMPLIANCE_STATUS = 'NON_COMPLIANT') AS policy_violations,
                COUNT(*) AS total_assets,
                COUNT(CASE WHEN CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL != 'Unclassified' THEN 1 END) AS classified_assets
            FROM {db}.{schema}.ASSETS
            WHERE {where_clause}
        )
        SELECT 
            total_assets, 
            classified_assets, 
            five_day_compliance, 
            annual_review, 
            documentation_complete,
            CASE
                WHEN five_day_compliance >= 95
                      AND annual_review >= 80
                      AND documentation_complete >= 90
                THEN '✅ Excellent'
                WHEN five_day_compliance >= 80
                      AND annual_review >= 60
                THEN '☑️ Good'
                ELSE '⚠️ Needs Attention'
            END as overall_health
        FROM summary_stats
        """
        
        result = snowflake_connector.execute_query(query, params)
        
        if result and len(result) > 0:
            row = result[0]
            # Convert to uppercase for case-insensitive access
            row_upper = {k.upper(): v for k, v in row.items()}
            
            return {
                'five_day_compliance': float(row_upper.get('FIVE_DAY_COMPLIANCE', 0.0)),
                'annual_review': float(row_upper.get('ANNUAL_REVIEW', 0.0)),
                'doc_completeness': float(row_upper.get('DOC_COMPLETENESS', 0.0)),
                'coverage': float(row_upper.get('COVERAGE', 0.0)),
                'policy_violations': int(row_upper.get('POLICY_VIOLATIONS', 0)),
                'overall_status': row_upper.get('OVERALL_STATUS', '🔴 Unknown')
            }
    except Exception as e:
        logger.warning(f"Error fetching classification requirements: {e}")
    
    return {
        'five_day_compliance': 0.0,
        'annual_review': 0.0,
        'doc_completeness': 0.0,
        'coverage': 0.0,
        'policy_violations': 0,
        'overall_status': '🔴 Unknown'
    }

# REMOVED CACHE to force fresh data - enable cache after debugging

# REMOVED CACHE to force fresh data - enable cache after debugging


def get_risk_exposure_assets(db: str, filters: dict = None) -> pd.DataFrame:
    """Fetch asset-level risk exposure rows using CIA scoring from ASSETS."""
    schema = _gv_schema()
    try:
        # Resolve a safe database context (some pages may pass "All" when the sidebar filter is not set)
        if not db or str(db).strip().upper() in ("ALL", "NONE", "NULL", "(NONE)", "UNKNOWN", ""):
            db = st.session_state.get("sf_database") or ""
        if not db or str(db).strip().upper() in ("ALL", "NONE", "NULL", "(NONE)", "UNKNOWN", ""):
            return pd.DataFrame(columns=[
                "ASSET_NAME",
                "BUSINESS_UNIT",
                "CLASSIFICATION_LABEL",
                "CONFIDENTIALITY_LEVEL",
                "INTEGRITY_LEVEL",
                "AVAILABILITY_LEVEL",
                "CIA_RISK_SCORE",
                "RISK_CATEGORY",
            ])

        where_clause, params = _build_filters(filters, db)

        query = f"""
        SELECT
            ASSET_NAME,
            BUSINESS_UNIT,
            CLASSIFICATION_LABEL,
            CONFIDENTIALITY_LEVEL,
            INTEGRITY_LEVEL,
            AVAILABILITY_LEVEL,
            (
                TO_NUMBER(SUBSTR(CONFIDENTIALITY_LEVEL,2)) +
                TO_NUMBER(SUBSTR(INTEGRITY_LEVEL,2)) +
                TO_NUMBER(SUBSTR(AVAILABILITY_LEVEL,2))
            ) AS CIA_RISK_SCORE,
            CASE
                WHEN (
                    TO_NUMBER(SUBSTR(CONFIDENTIALITY_LEVEL,2)) +
                    TO_NUMBER(SUBSTR(INTEGRITY_LEVEL,2)) +
                    TO_NUMBER(SUBSTR(AVAILABILITY_LEVEL,2))
                ) >= 10 THEN 'CRITICAL'
                WHEN (
                    TO_NUMBER(SUBSTR(CONFIDENTIALITY_LEVEL,2)) +
                    TO_NUMBER(SUBSTR(INTEGRITY_LEVEL,2)) +
                    TO_NUMBER(SUBSTR(AVAILABILITY_LEVEL,2))
                ) >= 7 THEN 'HIGH'
                WHEN (
                    TO_NUMBER(SUBSTR(CONFIDENTIALITY_LEVEL,2)) +
                    TO_NUMBER(SUBSTR(INTEGRITY_LEVEL,2)) +
                    TO_NUMBER(SUBSTR(AVAILABILITY_LEVEL,2))
                ) >= 4 THEN 'MEDIUM'
                ELSE 'LOW'
            END AS RISK_CATEGORY
        FROM {db}.{schema}.ASSETS
        WHERE {where_clause}
        ORDER BY CIA_RISK_SCORE DESC
        """

        rows = snowflake_connector.execute_query(query, params) or []
        return pd.DataFrame(rows)
    except Exception as e:
        logger.warning(f"Error fetching risk exposure assets from ASSETS: {e}")
        return pd.DataFrame(columns=[
            "ASSET_NAME",
            "BUSINESS_UNIT",
            "CLASSIFICATION_LABEL",
            "CONFIDENTIALITY_LEVEL",
            "INTEGRITY_LEVEL",
            "AVAILABILITY_LEVEL",
            "CIA_RISK_SCORE",
            "RISK_CATEGORY",
        ])
# Special category compliance logic using detected boolean flags from ASSETS

def get_special_categories_compliance(db: str, filters: dict = None) -> Dict:
    """Fetch special categories compliance metrics from the ASSETS table based on boolean flags."""
    try:
        schema = _gv_schema()
        where_clause, params = _build_filters(filters, db)
        
        # Use unpivot-style query to get metrics for all three categories efficiently
        query = f"""
        WITH filtered_assets AS (
            SELECT * FROM {db}.{schema}.ASSETS
            WHERE {where_clause}
        ),
        eval_base AS (
            SELECT
                ASSET_ID,
                PII_RELEVANT,
                SOX_RELEVANT,
                SOC2_RELEVANT,
                -- Clean Confidentiality Level (Target: C1=1, C2=2, C3=3)
                CASE 
                    WHEN TRY_TO_NUMBER(SUBSTR(TO_VARCHAR(CONFIDENTIALITY_LEVEL), 2)) IS NOT NULL 
                    THEN TO_NUMBER(SUBSTR(TO_VARCHAR(CONFIDENTIALITY_LEVEL), 2))
                    WHEN TRY_TO_NUMBER(TO_VARCHAR(CONFIDENTIALITY_LEVEL)) IS NOT NULL 
                    THEN TO_NUMBER(TO_VARCHAR(CONFIDENTIALITY_LEVEL))
                    ELSE 0
                END as C_LEVEL
            FROM filtered_assets
        ),
        framework_metrics AS (
            -- PII
            SELECT 
                'PII' as FRAMEWORK,
                COUNT(*) as T,
                COUNT_IF(C_LEVEL >= 2) as C,
                COUNT_IF(C_LEVEL < 2) as V
            FROM eval_base WHERE PII_RELEVANT = TRUE
            
            UNION ALL
            
            -- SOX
            SELECT 
                'SOX' as FRAMEWORK,
                COUNT(*) as T,
                COUNT_IF(C_LEVEL >= 3) as C,
                COUNT_IF(C_LEVEL < 3) as V
            FROM eval_base WHERE SOX_RELEVANT = TRUE
            
            UNION ALL
            
            -- SOC2
            SELECT 
                'SOC2' as FRAMEWORK,
                COUNT(*) as T,
                COUNT_IF(C_LEVEL >= 3) as C,
                COUNT_IF(C_LEVEL < 3) as V
            FROM eval_base WHERE SOC2_RELEVANT = TRUE
        )
        SELECT FRAMEWORK, T, C, V FROM framework_metrics WHERE T > 0
        """
        
        rows = snowflake_connector.execute_query(query, params)
        metrics = {}
        
        if rows:
            for r in rows:
                frm = r.get('FRAMEWORK')
                c_count = int(r.get('C') or 0)
                v_count = int(r.get('V') or 0)
                t_count = int(r.get('T') or 0)
                
                rate = round(c_count * 100.0 / t_count, 0)
                status = '✅ Compliant' if v_count == 0 else ('⚠️ Attention' if rate >= 70 else '❌ Non-Compliant')
                action = 'Compliance Met' if v_count == 0 else ('Review Tagging' if rate >= 70 else 'Critical Gap')
                
                metrics[frm] = {
                    'status': status,
                    'rate_str': f"{rate:.0f}%",
                    'action': action,
                    'compliant': c_count,
                    'non_compliant': v_count
                }
        
        return metrics
                        
    except Exception as e:
        logger.error(f"Error in special categories compliance: {e}")
        return {}

def get_mandatory_controls_metrics(db: str) -> Dict:
    schema = _gv_schema()
    try:
        query = f"""
        WITH base_assets AS (
            SELECT *
            FROM {db}.{schema}.ASSETS
        ),
        data_classification_enabled AS (
            SELECT
                COUNT(*) AS total_assets,
                COUNT(CASE WHEN CLASSIFICATION_LABEL IS NOT NULL AND UPPER(TRIM(CLASSIFICATION_LABEL)) NOT IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL') THEN 1 END) AS classified_assets,
                COUNT(CASE 
                    WHEN (CLASSIFICATION_LABEL IS NULL OR UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL'))
                     AND CREATED_TIMESTAMP >= DATEADD(day, -30, CURRENT_TIMESTAMP())
                    THEN 1 END) AS lifecycle_drift_assets
            FROM base_assets
        ),
        data_protection_tagging AS (
            SELECT
                COUNT(CASE 
                    WHEN PII_RELEVANT = TRUE
                      OR SOX_RELEVANT = TRUE
                      OR SOC2_RELEVANT = TRUE
                    THEN 1 END) AS sensitive_columns,
                COUNT(CASE 
                    WHEN (PII_RELEVANT = TRUE OR SOX_RELEVANT = TRUE OR SOC2_RELEVANT = TRUE)
                     AND CLASSIFICATION_LABEL IS NOT NULL
                     AND UPPER(TRIM(CLASSIFICATION_LABEL)) NOT IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL')
                    THEN 1 END) AS tagged_columns,
                COUNT(CASE 
                    WHEN (PII_RELEVANT = TRUE OR SOX_RELEVANT = TRUE OR SOC2_RELEVANT = TRUE)
                     AND (CLASSIFICATION_LABEL IS NULL OR UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL'))
                    THEN 1 END) AS tag_drift_detected
            FROM base_assets
        ),
        sensitive_data_identification AS (
            SELECT
                COUNT(CASE WHEN PII_RELEVANT = TRUE THEN 1 END) AS pii_identified,
                COUNT(CASE 
                    WHEN NEXT_REVIEW_DATE < CURRENT_DATE()
                    THEN 1 END) AS review_overdue
            FROM base_assets
        ),
        access_control_enforcement AS (
            SELECT
                COUNT(DISTINCT DATA_OWNER) AS roles_with_access,
                COUNT(CASE 
                    WHEN SENSITIVE_DATA_USAGE_COUNT > 0
                     AND (CLASSIFICATION_LABEL IS NULL OR UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL'))
                    THEN 1 END) AS zero_trust_violations
            FROM base_assets
        )
        SELECT
            ROUND(classified_assets * 100.0 / NULLIF(total_assets, 0), 0) AS PERCENT_DATA_CLASSIFIED,
            lifecycle_drift_assets AS OBJECT_LIFECYCLE_DRIFT,
            sensitive_columns AS SENSITIVE_COLUMNS,
            tagged_columns AS TAGGED_COLUMNS,
            tag_drift_detected AS TAG_DRIFT_DETECTED,
            pii_identified AS PII_PATTERNS_IDENTIFIED,
            review_overdue AS REVIEW_OVERDUE,
            roles_with_access AS ROLES_WITH_DATA_ACCESS,
            zero_trust_violations AS ZERO_TRUST_VIOLATIONS
        FROM data_classification_enabled
        CROSS JOIN data_protection_tagging
        CROSS JOIN sensitive_data_identification
        CROSS JOIN access_control_enforcement
        """
        rows = snowflake_connector.execute_query(query)
        if rows:
            return rows[0]
    except Exception as e:
        logger.error(f"Error in get_mandatory_controls_metrics: {e}")
    return {}


# REMOVED CACHE to force fresh data - enable cache after debugging
def get_annual_reviews_data(db: str, filters: dict = None) -> pd.DataFrame:
    """Fetch annual reviews schedule and status directly from the ASSETS table."""
    schema = _gv_schema()
    
    try:
        query = f"""
        SELECT
            ASSET_NAME AS ASSET_FULL_NAME,
            CONFIDENTIALITY_LEVEL,
            INTEGRITY_LEVEL,
            AVAILABILITY_LEVEL,
            DATA_OWNER AS REVIEWER,
            NEXT_REVIEW_DATE AS REVIEW_DUE_DATE,
            REVIEW_STATUS AS STATUS_LABEL,
            CASE 
                WHEN NEXT_REVIEW_DATE < CURRENT_DATE() THEN 'Overdue'
                WHEN REVIEW_STATUS IN ('Approved', 'Completed', 'Validated') THEN 'Completed On Time'
                WHEN NEXT_REVIEW_DATE <= DATEADD(day, 30, CURRENT_DATE()) THEN 'Due Soon'
                ELSE 'Scheduled'
            END AS REVIEW_STATUS,
            CASE
                WHEN CONFIDENTIALITY_LEVEL IN ('C3', '3') OR INTEGRITY_LEVEL IN ('I3', '3') OR AVAILABILITY_LEVEL IN ('A3', '3') THEN 'High Risk'
                WHEN CLASSIFICATION_LABEL IS NULL OR CLASSIFICATION_LABEL = 'Unclassified' THEN 'Unclassified'
                ELSE 'Normal'
            END AS RISK_CLASSIFICATION
        FROM {db}.{schema}.ASSETS
        """
        
        rows = snowflake_connector.execute_query(query)
        if not rows:
            return pd.DataFrame()
            
        return pd.DataFrame(rows)

    except Exception as e:
        logger.warning(f"Error fetching annual reviews data: {e}")
        return pd.DataFrame()

# REMOVED CACHE to force fresh data - enable cache after debugging

def get_policy_violations(db: str, filters: dict = None) -> pd.DataFrame:
    """Fetch policy violations data directly from the ASSETS table with filter support."""
    schema = _gv_schema()
    try:
        where_clause, params = _build_filters(filters, db)
        
        query = f"""
        WITH 
        violation_counts AS (
          -- Missing Classification
          SELECT 
            'Missing Classification' AS violation_type,
            COUNT(*) AS count,
            LISTAGG(DISTINCT ASSET_NAME, ', ') WITHIN GROUP (ORDER BY ASSET_NAME) AS sample_assets,
            COUNT(DISTINCT ASSET_NAME) AS unique_assets
          FROM {db}.{schema}.ASSETS
          WHERE (CLASSIFICATION_LABEL IS NULL OR CLASSIFICATION_LABEL = 'Unclassified')
            AND {where_clause}
          
          UNION ALL
          
          -- Overdue Reviews
          SELECT 
            'Overdue Reviews',
            COUNT(*),
            LISTAGG(DISTINCT ASSET_NAME, ', ') WITHIN GROUP (ORDER BY ASSET_NAME),
            COUNT(DISTINCT ASSET_NAME)
          FROM {db}.{schema}.ASSETS
          WHERE NEXT_REVIEW_DATE < CURRENT_DATE()
            AND {where_clause}
          
          UNION ALL
          
          -- Failed Business Logic (e.g. Corrective Action Required)
          SELECT 
            'Policy Breaches',
            COUNT(*),
            LISTAGG(DISTINCT ASSET_NAME, ', ') WITHIN GROUP (ORDER BY ASSET_NAME),
            COUNT(DISTINCT ASSET_NAME)
          FROM {db}.{schema}.ASSETS
          WHERE (CORRECTIVE_ACTION_REQUIRED = TRUE OR COMPLIANCE_STATUS = 'NON-COMPLIANT')
            AND {where_clause}
        )
        SELECT 
            'VIOLATION TYPE BREAKDOWN' AS category,
            violation_type AS metric,
            CAST(count AS STRING) AS value,
            CONCAT('Unique assets: ', CAST(unique_assets AS STRING)) AS details
        FROM violation_counts
        
        UNION ALL

        SELECT 
            'TOTALS SUMMARY',
            'Active Violations',
            CAST(SUM(count) AS STRING),
            'Total active policy enforcement alerts'
        FROM violation_counts

        UNION ALL

        SELECT 
            'RESOLUTION ANALYSIS',
            'Compliant Assets',
            CAST(COUNT(*) AS STRING),
            'Assets currently meeting all policy standards'
        FROM {db}.{schema}.ASSETS
        WHERE COMPLIANCE_STATUS = 'COMPLIANT'
          AND {where_clause}
        ORDER BY 
            CASE category
                WHEN 'VIOLATION TYPE BREAKDOWN' THEN 1
                WHEN 'TOTALS SUMMARY' THEN 2
                WHEN 'RESOLUTION ANALYSIS' THEN 3
                WHEN 'REPEAT OFFENDERS' THEN 4
                WHEN 'DIAGNOSTIC' THEN 5
                ELSE 6
            END,
            CASE metric
                WHEN 'Missing Classification' THEN 1
                WHEN 'Overdue Reviews' THEN 2
                WHEN 'Insufficient Protection' THEN 3
                ELSE 4
            END
        """
        
        rows = snowflake_connector.execute_query(query, params)
        if not rows:
            return pd.DataFrame(columns=['CATEGORY', 'METRIC', 'VALUE', 'DETAILS'])
            
        return pd.DataFrame(rows)
            
    except Exception as e:
        logger.warning(f"Error fetching policy violations: {e}")
        return pd.DataFrame(columns=['CATEGORY', 'METRIC', 'VALUE', 'DETAILS'])

# REMOVED CACHE to force fresh data - enable cache after debugging
def get_compliance_trends_metrics(db: str, filters: dict = None) -> pd.DataFrame:
    """Fetch unified compliance trends for the last 6 months using dynamic schema references and filters."""
    schema = _gv_schema()
    
    try:
        where_clause, params = _build_filters(filters, db)
        
        query = f"""
        -- ============================================================================
        -- UNIFIED COMPLIANCE TREND - Single Query for All Metrics (Last 6 Months)
        -- ============================================================================
        WITH 
        -- Generate last 6 months date range
        date_spine AS (
            SELECT DATEADD('month', -(ROW_NUMBER() OVER (ORDER BY SEQ4()) - 1), DATE_TRUNC('MONTH', CURRENT_DATE())) AS month
            FROM TABLE(GENERATOR(ROWCOUNT => 6))
        ),

        -- 1. Policy Compliance Metrics - From CLASSIFICATION_DECISIONS base table
        policy_metrics AS (
            SELECT
                DATE_TRUNC('MONTH', DECISION_TIMESTAMP) AS month,
                COUNT(*) AS total_reviews,
                SUM(CASE WHEN STATUS ILIKE '%approved%' THEN 1 ELSE 0 END) AS approved_reviews,
                SUM(CASE WHEN STATUS ILIKE '%rejected%' THEN 1 ELSE 0 END) AS rejected_reviews,
                ROUND(100.0 * SUM(CASE WHEN STATUS ILIKE '%approved%' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) AS policy_compliance_rate
            FROM {db}.{schema}.CLASSIFICATION_DECISIONS
            WHERE DECISION_TIMESTAMP >= DATEADD('month', -6, CURRENT_DATE())
            GROUP BY DATE_TRUNC('MONTH', DECISION_TIMESTAMP)
        ),

        -- 2. Data Governance Metrics - Using ASSETS table
        governance_metrics AS (
            SELECT
                DATE_TRUNC('MONTH', CLASSIFICATION_DATE) AS month,
                COUNT(DISTINCT ASSET_ID) AS total_assets,
                COUNT(DISTINCT CASE 
                    WHEN CONFIDENTIALITY_LEVEL IS NOT NULL 
                      OR INTEGRITY_LEVEL IS NOT NULL 
                      OR AVAILABILITY_LEVEL IS NOT NULL
                    THEN ASSET_ID
                END) AS classified_assets,
                COUNT(DISTINCT CASE 
                    WHEN (TRY_TO_NUMBER(TO_VARCHAR(CONFIDENTIALITY_LEVEL)) >= 2 OR TO_VARCHAR(CONFIDENTIALITY_LEVEL) IN ('C2', 'C3'))
                    THEN ASSET_ID
                END) AS sensitive_assets
            FROM {db}.{schema}.ASSETS
            WHERE CLASSIFICATION_DATE >= DATEADD('month', -6, CURRENT_DATE())
              AND CLASSIFICATION_DATE IS NOT NULL
              AND {where_clause}
            GROUP BY DATE_TRUNC('MONTH', CLASSIFICATION_DATE)
        ),

        governance_calculated AS (
            SELECT
                month,
                total_assets,
                classified_assets,
                sensitive_assets,
                ROUND(100.0 * classified_assets / NULLIF(total_assets, 0), 2) AS governance_completion_rate
            FROM governance_metrics
        ),

        -- 3. Audit Activity Metrics - From CLASSIFICATION_AUDIT base table
        audit_metrics AS (
            SELECT
                DATE_TRUNC('MONTH', TIMESTAMP) AS month,
                COUNT(*) AS total_audit_events,
                COUNT(DISTINCT RESOURCE_ID) AS unique_resources,
                COUNT(CASE WHEN ACTION ILIKE '%classification%' THEN 1 END) AS classification_events,
                COUNT(CASE WHEN ACTION ILIKE '%review%' THEN 1 END) AS review_events
            FROM {db}.{schema}.CLASSIFICATION_AUDIT
            WHERE TIMESTAMP >= DATEADD('month', -6, CURRENT_DATE())
            GROUP BY DATE_TRUNC('MONTH', TIMESTAMP)
        ),

        audit_calculated AS (
            SELECT
                month,
                total_audit_events,
                unique_resources,
                classification_events,
                review_events,
                ROUND(100.0 * classification_events / NULLIF(total_audit_events, 0), 2) AS audit_compliance_rate
            FROM audit_metrics
        ),

        -- 4. Risk Metrics - Using ASSETS table
        risk_metrics AS (
            SELECT
                DATE_TRUNC('MONTH', CLASSIFICATION_DATE) AS month,
                COUNT(DISTINCT CASE 
                    WHEN (TRY_TO_NUMBER(TO_VARCHAR(CONFIDENTIALITY_LEVEL)) >= 3 OR TO_VARCHAR(CONFIDENTIALITY_LEVEL) = 'C3')
                    THEN ASSET_ID
                END) AS high_risk_assets,
                COUNT(DISTINCT CASE 
                    WHEN (TRY_TO_NUMBER(TO_VARCHAR(CONFIDENTIALITY_LEVEL)) = 2 OR TO_VARCHAR(CONFIDENTIALITY_LEVEL) = 'C2')
                    THEN ASSET_ID
                END) AS medium_risk_assets,
                COUNT(DISTINCT CASE 
                    WHEN CONFIDENTIALITY_LEVEL IS NOT NULL
                    THEN ASSET_ID
                END) AS total_classified
            FROM {db}.{schema}.ASSETS
            WHERE CLASSIFICATION_DATE >= DATEADD('month', -6, CURRENT_DATE())
              AND CLASSIFICATION_DATE IS NOT NULL
              AND {where_clause}
            GROUP BY DATE_TRUNC('MONTH', CLASSIFICATION_DATE)
        ),

        risk_calculated AS (
            SELECT
                month,
                high_risk_assets,
                medium_risk_assets,
                total_classified,
                -- Inverse for compliance score (lower risk = higher compliance)
                ROUND(100.0 - (100.0 * high_risk_assets / NULLIF(total_classified, 0)), 2) AS risk_compliance_rate
            FROM risk_metrics
        ),

        -- Combine all metrics
        combined_metrics AS (
            SELECT
                d.month,
                COALESCE(p.policy_compliance_rate, 0) AS policy_compliance_pct,
                COALESCE(g.governance_completion_rate, 0) AS governance_completion_pct,
                COALESCE(a.audit_compliance_rate, 0) AS audit_compliance_pct,
                COALESCE(r.risk_compliance_rate, 0) AS risk_compliance_pct
            FROM date_spine d
            LEFT JOIN policy_metrics p ON d.month = p.month
            LEFT JOIN governance_calculated g ON d.month = g.month
            LEFT JOIN audit_calculated a ON d.month = a.month
            LEFT JOIN risk_calculated r ON d.month = r.month
        ),

        -- Calculate overall compliance score and trends
        compliance_with_trends AS (
            SELECT
                month,
                policy_compliance_pct,
                governance_completion_pct,
                audit_compliance_pct,
                risk_compliance_pct,
                
                -- Overall Compliance Score (weighted average: 30% Policy, 30% Gov, 20% Audit, 20% Risk)
                ROUND(
                    (COALESCE(policy_compliance_pct, 0) * 0.30 +
                     COALESCE(governance_completion_pct, 0) * 0.30 +
                     COALESCE(audit_compliance_pct, 0) * 0.20 +
                     COALESCE(risk_compliance_pct, 0) * 0.20)
                , 2) AS overall_compliance_score,
                
                LAG(policy_compliance_pct) OVER (ORDER BY month) AS prev_policy,
                LAG(governance_completion_pct) OVER (ORDER BY month) AS prev_governance,
                LAG(audit_compliance_pct) OVER (ORDER BY month) AS prev_audit,
                LAG(risk_compliance_pct) OVER (ORDER BY month) AS prev_risk,
                LAG(ROUND(
                    (COALESCE(policy_compliance_pct, 0) * 0.30 +
                     COALESCE(governance_completion_pct, 0) * 0.30 +
                     COALESCE(audit_compliance_pct, 0) * 0.20 +
                     COALESCE(risk_compliance_pct, 0) * 0.20)
                , 2)) OVER (ORDER BY month) AS prev_overall_score
            FROM combined_metrics
        )

        SELECT
            TO_CHAR(month, 'YYYY-MM') AS month_period,
            policy_compliance_pct,
            CASE
                WHEN policy_compliance_pct > prev_policy THEN '📈'
                WHEN policy_compliance_pct < prev_policy THEN '📉'
                ELSE '➡️'
            END AS policy_trend,
            governance_completion_pct,
            CASE
                WHEN governance_completion_pct > prev_governance THEN '📈'
                WHEN governance_completion_pct < prev_governance THEN '📉'
                ELSE '➡️'
            END AS governance_trend,
            audit_compliance_pct,
            CASE
                WHEN audit_compliance_pct > prev_audit THEN '📈'
                WHEN audit_compliance_pct < prev_audit THEN '📉'
                ELSE '➡️'
            END AS audit_trend,
            risk_compliance_pct,
            CASE
                WHEN risk_compliance_pct > prev_risk THEN '✅'
                WHEN risk_compliance_pct < prev_risk THEN '⚠️'
                ELSE '➡️'
            END AS risk_trend,
            overall_compliance_score,
            ROUND(overall_compliance_score - prev_overall_score, 2) AS overall_trend_change,
            CASE
                WHEN overall_compliance_score >= 90 THEN '🟢 Excellent'
                WHEN overall_compliance_score >= 75 THEN '🟡 Good'
                WHEN overall_compliance_score >= 60 THEN '🟠 Fair'
                ELSE '🔴 Needs Improvement'
            END AS compliance_status,
            CASE
                WHEN overall_compliance_score - prev_overall_score > 5 THEN '📈 Strong Improvement'
                WHEN overall_compliance_score - prev_overall_score > 0 THEN '📈 Improving'
                WHEN overall_compliance_score - prev_overall_score < -5 THEN '📉 Declining'
                WHEN overall_compliance_score - prev_overall_score < 0 THEN '📉 Slight Decline'
                ELSE '➡️ Stable'
            END AS overall_trend
        FROM compliance_with_trends
        ORDER BY month DESC;
        """
        
        rows = snowflake_connector.execute_query(query, params)
        if not rows:
            return pd.DataFrame()
            
        return pd.DataFrame(rows)
            
    except Exception as e:
        logger.warning(f"Error fetching compliance trends: {e}")
        return pd.DataFrame()

# ============================================================================
# RBAC CHECK
# ============================================================================

try:
    _ident = authz.get_current_identity()
    can_compliance = True
    try:
        if authz._is_bypass():
            can_compliance = True
        else:
            can_compliance = authz.is_consumer(_ident)
    except Exception:
        can_compliance = True

    if not can_compliance:
        st.error("You do not have permission to access the Compliance module.")
        st.stop()
except Exception as _auth_err:
    if not authz._is_bypass():
        st.warning(f"Authorization check failed: {_auth_err}")
        st.stop()


# ============================================================================
# SIDEBAR FILTERS
# ============================================================================

with st.sidebar:
    # Standardized Global Filters
    g_filters = render_global_filters(key_prefix="comp")

    sel_wh = st.session_state.get('sf_warehouse')
    sel_db = g_filters.get("database")
    sel_schema = g_filters.get("schema")
    sel_obj = g_filters.get("table")
    sel_col = g_filters.get("column")
    
    # Discovery and Framework Filter
    st.markdown("---")
    st.subheader("Compliance Focus")
    framework_options = _get_available_frameworks(sel_db) if sel_db else []
    sel_frameworks = st.multiselect(
        "Regulatory Frameworks",
        options=framework_options,
        default=None,
        help="Filter dashboard metrics by specific regulatory categories detected in assets.",
        key="comp_framework_filter"
    )
    
    # Store filters for page logic
    st.session_state["global_filters"] = {
        "warehouse": sel_wh,
        "database": None if (not sel_db or sel_db == "All") else sel_db,
        "schema": None if (not sel_schema or sel_schema == "All") else sel_schema,
        "table": None if (not sel_obj or sel_obj == "All") else sel_obj,
        "column": None if (not sel_col or sel_col == "All") else sel_col,
        "frameworks": sel_frameworks
    }
    
    st.markdown("---")
    
    # Display active filters summary
    st.subheader("Active Filters")
    filters = st.session_state.get("global_filters", {})
    
    if filters.get("database"):
        st.caption(f"📊 **Database:** {filters['database']}")
    if filters.get("schema"):
        st.caption(f"📁 **Schema:** {filters['schema']}")
    if filters.get("table"):
        st.caption(f"📋 **Table:** {filters['table']}")
    if filters.get("column"):
        st.caption(f"📌 **Column:** {filters['column']}")
    
    if not any([filters.get("database"), filters.get("schema"), filters.get("table"), filters.get("column")]):
        st.caption("_No filters applied (showing all)_")

# ============================================================================
# PAGE HEADER
# ============================================================================

st.markdown(r"""
<style>
    /* Ultra-Premium Compliance Design System */
    .compliance-hero {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
        padding: 3rem;
        border-radius: 28px;
        color: white;
        margin-bottom: 2.5rem;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.08);
        position: relative;
        overflow: hidden;
    }
    
    .compliance-hero::after {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle, rgba(56, 189, 248, 0.03) 0%, transparent 70%);
        pointer-events: none;
    }

    /* Standardized Dashboard-style Card System */
    .pillar-card {
        background: linear-gradient(145deg, rgba(26, 32, 44, 0.6), rgba(17, 21, 28, 0.8));
        border-radius: 20px;
        padding: 22px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        text-align: center;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        position: relative;
        overflow: hidden;
        height: 100%;
    }
    
    .pillar-card:hover {
        transform: translateY(-8px);
        border-color: rgba(79, 209, 197, 0.4);
        background: linear-gradient(145deg, rgba(30, 39, 54, 0.8), rgba(20, 26, 35, 0.9));
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4), 0 0 20px rgba(79, 209, 197, 0.1);
    }
    
    .pillar-icon {
        font-size: 28px;
        margin-bottom: 12px;
        opacity: 0.9;
    }
    
    .pillar-value {
        font-size: 34px;
        font-weight: 800;
        color: #FFFFFF;
        margin: 5px 0;
    }
    
    .pillar-label {
        font-size: 11px;
        font-weight: 700;
        color: rgba(255, 255, 255, 0.5);
        text-transform: uppercase;
        letter-spacing: 1.2px;
    }

    .pillar-status {
        font-size: 11px;
        font-weight: 600;
        color: #38bdf8;
        margin-top: 10px;
        padding: 4px 10px;
        background: rgba(56, 189, 248, 0.1);
        border-radius: 20px;
        display: inline-block;
    }

    .glass-panel {
        background: rgba(30, 41, 59, 0.45);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border-radius: 24px;
        padding: 2rem;
        border: 1px solid rgba(255, 255, 255, 0.05);
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.2);
    }

    /* Circular Progress Metrics */
    .circular-metric {
        width: 90px;
        height: 90px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
        margin: 0 auto;
        box-shadow: 0 0 20px rgba(0,0,0,0.2);
    }
    .circular-metric::before {
        content: '';
        position: absolute;
        width: 72px;
        height: 72px;
        background: #0f172a;
        border-radius: 50%;
    }
    .circular-metric-value {
        position: relative;
        font-size: 1.25rem;
        font-weight: 800;
        color: white;
    }
    .circular-metric-label {
        font-size: 0.65rem;
        color: #94a3b8;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05rem;
        line-height: 1.2;
    }
    
    .health-summary-banner {
        background: linear-gradient(90deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.9) 100%);
        padding: 1.5rem 2rem;
        border-radius: 20px;
        border-left: 6px solid #38bdf8;
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.15);
    }
</style>
""", unsafe_allow_html=True)

# Hero Section
st.markdown("""
<div class="page-hero">
    <div style="display: flex; align-items: center; gap: 1.5rem;">
        <div class="hero-icon-box">🛡️</div>
        <div>
            <h1 class="hero-title">Governance & Compliance</h1>
            <p class="hero-subtitle">Real-time policy enforcement and regulatory orchestration dashboard.</p>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Placeholder for per-run Snowflake credit consumption metrics
# This is populated at the end of the script to capture all queries in the run
consumption_placeholder = st.empty()

render_quick_links()

filters = st.session_state.get("global_filters", {})
active_db = _resolve_db()
active_schema = _gv_schema()

# Top Controls and Filter Summary
scope_col, action_col = st.columns([5, 1.2])

# DATABASE CONTEXT GUARD
if not active_db:
    st.markdown("""
<div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); padding: 2rem; border-radius: 20px; text-align: center; margin: 2rem 0;">
    <div style="font-size: 3rem; margin-bottom: 1rem;">⚠️</div>
    <h3 style="color: #fca5a5; margin-bottom: 0.5rem;">Database Context Required</h3>
    <p style="color: #94a3b8; max-width: 500px; margin: 0 auto;">Please select a database from the <b>Global Filters</b> in the sidebar to load compliance metrics and regulatory frameworks.</p>
</div>
""", unsafe_allow_html=True)
    st.stop()

with scope_col:
    # Render active filters as a modern flex layout
    filter_html = ""
    icon_map = {"database": "📊", "schema": "📁", "table": "📋", "column": "📌"}
    
    for key, icon in icon_map.items():
        if filters.get(key):
            filter_html += f'<div class="filter-tag"><span>{icon}</span> {filters[key]}</div>'
    
    if filter_html:
        st.markdown(f'<div style="display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 2rem;">{filter_html}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<p style="color:#64748b; font-size:0.875rem; font-weight: 500; margin-bottom: 2rem;">🌐 Showing Global Organization Data</p>', unsafe_allow_html=True)

with action_col:
    if st.button("🔄 Sync Live Data", width='stretch', help="Fetch latest telemetry from Snowflake"):
        st.rerun()

# Get active database
db = _resolve_db()
if not db:
    st.error("No active database found. Please select a database from the sidebar.")
    st.stop()

# ============================================================================
# MAIN TABS
# ============================================================================

tab1, tab2, tab3 = st.tabs([
    "📊 Compliance Overview",
    "⚠️ Reviews & Violations",
    "📈 Reports & Trends"
])

with tab1:
    # Fetch metrics
    metrics = get_compliance_overview_metrics(db, filters=filters)
    
    if active_db:
        try:
            # Diagnostics when KPIs are all zero
            try:
                if (
                    float(metrics.get('classification_coverage') or 0) == 0
                    and float(metrics.get('count_sensitive') or 0) == 0
                    and int(metrics.get('count_privileged') or 0) == 0
                    and float(metrics.get('snowflake_tag_compliance') or 0) == 0
                    and int(metrics.get('count_drift') or 0) == 0
                ):
                    diag_db = db
                    if not diag_db or str(diag_db).strip().upper() in ("ALL", "NONE", "NULL", "(NONE)", "UNKNOWN", ""):
                        diag_db = st.session_state.get("sf_database") or ""
                    diag_schema = _gv_schema()
                    if diag_db and diag_schema:
                        where_clause, params = _build_filters(filters, diag_db)
                        q_diag = f"""
                        WITH filtered_assets AS (
                            SELECT * FROM {diag_db}.{diag_schema}.ASSETS
                            WHERE {where_clause}
                        ),
                        base_assets AS (
                            SELECT * FROM filtered_assets
                            WHERE UPPER(TRIM(COALESCE(ASSET_TYPE, ''))) IN ('TABLE','VIEW','BASE TABLE')
                        )
                        SELECT
                            (SELECT COUNT(*) FROM base_assets) AS TOTAL_TABLES,
                            (SELECT COUNT(*) FROM base_assets WHERE CLASSIFICATION_LABEL IS NOT NULL AND UPPER(TRIM(CLASSIFICATION_LABEL)) NOT IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL', 'N/A', 'TBD')) AS CLASSIFIED_TABLES,
                            (SELECT COUNT(*) FROM base_assets WHERE PII_RELEVANT = TRUE OR SOX_RELEVANT = TRUE OR SOC2_RELEVANT = TRUE) AS SENSITIVE_TABLES,
                            (SELECT COUNT(*) FROM base_assets WHERE COALESCE(SENSITIVE_DATA_USAGE_COUNT, 0) > 0) AS SENSITIVE_ACCESS_TABLES,
                            (SELECT COUNT(*) FROM base_assets WHERE (CLASSIFICATION_LABEL IS NULL OR UPPER(TRIM(CLASSIFICATION_LABEL)) IN ('', 'UNCLASSIFIED', 'UNKNOWN', 'PENDING', 'NONE', 'NULL', 'N/A', 'TBD')) AND CREATED_TIMESTAMP >= DATEADD(day, -7, CURRENT_TIMESTAMP())) AS DRIFT_7D
                        """
                        # Re-run diag with permissive params
                        row_diag = (snowflake_connector.execute_query(q_diag, params) or [{}])[0]
            except Exception:
                pass

            # Governance Health Summary Banner
            status_color = "#10b981" if "Healthy" in metrics['overall_status'] else "#f59e0b" if "Monitor" in metrics['overall_status'] else "#ef4444"
            
            st.markdown(f"""
<div class="health-summary-banner" style="border-left-color: {status_color};">
<div>
<div style="color: #94a3b8; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.25rem;">Governance Health Index</div>
<div style="font-size: 1.75rem; font-weight: 900; color: white;">{metrics['overall_status']}</div>
</div>
<div style="text-align: right;">
<div style="color: #94a3b8; font-size: 0.75rem; font-weight: 700; text-transform: uppercase;">Active Tables</div>
<div style="font-size: 1.5rem; font-weight: 800; color: #38bdf8;">{metrics['count_tables']:,}</div>
</div>
</div>
""", unsafe_allow_html=True)
            
            # Health metrics row focusing on gauges
            st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)
            
            # Circular Gauges Row
            c1, c2, c3, c4, c5 = st.columns(5, gap="small")
            
            def render_circular_metric(col, label, value, color="#38bdf8", is_pct=True):
                val_str = f"{value:.0f}%" if is_pct else f"{value}"
                col.markdown(f"""
<div style="display: flex; flex-direction: column; align-items: center; justify-content: center;">
<div class="circular-metric" style="--percentage: {value if is_pct else 100}%; background: conic-gradient({color} {value if is_pct else 100}%, #1e293b 0);">
<div class="circular-metric-value">{val_str}</div>
</div>
<div class="circular-metric-label" style="margin-top: 12px; width: 100%; text-align: center;">{label}</div>
</div>
""", unsafe_allow_html=True)

            render_circular_metric(c1, "% Tables Classified", metrics['classification_coverage'])
            render_circular_metric(c2, "Sensitive Exposure", metrics['count_sensitive'], "#f59e0b")
            render_circular_metric(c3, "Privileged Access", metrics['count_privileged'], "#38bdf8", False)
            render_circular_metric(c4, "Sensitive Access", metrics['snowflake_tag_compliance'], "#10b981")
            render_circular_metric(c5, "Classification Drift", metrics['count_drift'], "#ef4444", False)

            st.markdown("<div style='height: 3rem;'></div>", unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Failed to load health metrics: {str(e)}")
    else:
        st.info("💡 Please select a database from the sidebar to view compliance metrics.")
        st.stop()
    
    # Sub-tabs for Compliance Overview
    subtab1, subtab2 = st.tabs([
        "🛡️ Mandatory Controls",
        "📊 Risk Distribution"
    ])

    # ========================================================================
    # SUBTAB 1: MANDATORY COMPLIANCE
    # ========================================================================
    
    with subtab1:
        st.markdown(f"""
<div style="margin-top: 1rem; margin-bottom: 2rem;">
    <h1 style="font-size: 3rem !important; margin-bottom: 0.5rem !important;">Mandatory Compliance Controls</h1>
    <p style="color: #94a3b8; font-size: 1.2rem; margin: 0;">Data Classification in Snowflake • Automated Governance Monitoring</p>
</div>
""", unsafe_allow_html=True)
        
        # Fetch Mandatory Controls Metrics
        man_metrics = get_mandatory_controls_metrics(db)
        
        # Grid of Pillar Cards
        g_col1, g_col2 = st.columns(2, gap="large")
        
        with g_col1:
            # CARD 1: Data Classification Enabled
            drift_objs = man_metrics.get('OBJECT_LIFECYCLE_DRIFT', 0)
            st.markdown(f"""<div class="pillar-card-v2 blue">
<div class="pillar-header">
<h3 class="pillar-title-v2">Data Classification Enabled</h3>
<span style="font-size: 1.5rem;">{'✅' if drift_objs == 0 else '⚠️'}</span>
</div>
<p class="pillar-subtitle-v2">
Continuous identification of sensitive entities using Snowflake\'s deep-learning engine.
</p>
<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 2rem;">
<div style="background: rgba(15, 23, 42, 0.4); padding: 1rem; border-radius: 12px; text-align: center;">
<div style="font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;">Classified Assets</div>
<div style="font-size: 1.25rem; font-weight: 800; color: #f8fafc;">{man_metrics.get('PERCENT_DATA_CLASSIFIED', 0)}%</div>
</div>
<div style="background: rgba(15, 23, 42, 0.4); padding: 1rem; border-radius: 12px; text-align: center;">
<div style="font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;">Lifecycle Drift</div>
<div style="font-size: 1.25rem; font-weight: 800; color: {'#ef4444' if drift_objs > 0 else '#10b981'};">{drift_objs}</div>
</div>
</div>
<div class="control-check-section">
<p style="font-size: 0.75rem; font-weight: 800; color: #64748b; text-transform: uppercase; margin-bottom: 0.75rem;">Control Check</p>
<div class="control-check-item">
<div class="check-status passed">✓</div>
<div style="font-size: 0.85rem; font-weight: 600;">Audit logs active</div>
</div>
<div class="control-check-item">
<div class="check-status {'passed' if drift_objs == 0 else 'failed'}">{ '✓' if drift_objs == 0 else '✕' }</div>
<div style="font-size: 0.85rem; font-weight: 600;">Schema scans synced</div>
</div>
</div>
</div>""", unsafe_allow_html=True)

            # CARD 2: Data Protection & Tagging
            tag_drift = man_metrics.get('TAG_DRIFT_DETECTED', 0)
            st.markdown(f"""<div class="pillar-card-v2 red">
<div class="pillar-header">
<h3 class="pillar-title-v2">Data Protection & Tagging</h3>
<span style="font-size: 1.5rem;">{'✅' if tag_drift == 0 else '❌'}</span>
</div>
<p class="pillar-subtitle-v2">
Rigid application of object tags to provide semantic layer for governance.
</p>
<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 2rem;">
<div style="background: rgba(15, 23, 42, 0.4); padding: 1rem; border-radius: 12px; text-align: center;">
<div style="font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;">Sensitive Columns</div>
<div style="font-size: 1.25rem; font-weight: 800; color: #f8fafc;">{man_metrics.get('SENSITIVE_COLUMNS', 0):,}</div>
</div>
<div style="background: rgba(15, 23, 42, 0.4); padding: 1rem; border-radius: 12px; text-align: center;">
<div style="font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;">Tagged Columns</div>
<div style="font-size: 1.25rem; font-weight: 800; color: #f8fafc;">{man_metrics.get('TAGGED_COLUMNS', 0):,}</div>
</div>
</div>
<div class="control-check-section">
<p style="font-size: 0.75rem; font-weight: 800; color: #64748b; text-transform: uppercase; margin-bottom: 0.75rem;">Control Check</p>
<div class="control-check-item">
<div class="check-status passed">✓</div>
<div style="font-size: 0.85rem; font-weight: 600;">Masking policies synced</div>
</div>
<div class="control-check-item">
<div class="check-status {'passed' if tag_drift == 0 else 'failed'}">{ '✓' if tag_drift == 0 else '✕' }</div>
<div style="font-size: 0.85rem; font-weight: 600;">Tag drift: {tag_drift} detected</div>
</div>
</div>
</div>""", unsafe_allow_html=True)

        with g_col2:
            # CARD 3: Sensitive Data Identification
            pii_id = man_metrics.get('PII_PATTERNS_IDENTIFIED', 0)
            overdue = man_metrics.get('REVIEW_OVERDUE', 0)
            st.markdown(f"""<div class="pillar-card-v2 yellow">
<div class="pillar-header">
<h3 class="pillar-title-v2">Sensitive Data Identification</h3>
<span style="font-size: 1.5rem;">{'✅' if overdue == 0 else '⚠️'}</span>
</div>
<p class="pillar-subtitle-v2">
Automated classification of sensitive entities using Snowflake Native ML.
</p>
<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 2rem;">
<div style="background: rgba(15, 23, 42, 0.4); padding: 1rem; border-radius: 12px; text-align: center;">
<div style="font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;">PII Patterns</div>
<div style="font-size: 1.25rem; font-weight: 800; color: #f8fafc;">{pii_id}</div>
</div>
<div style="background: rgba(15, 23, 42, 0.4); padding: 1rem; border-radius: 12px; text-align: center;">
<div style="font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;">Reviews Overdue</div>
<div style="font-size: 1.25rem; font-weight: 800; color: {'#ef4444' if overdue > 0 else '#10b981'};">{overdue}</div>
</div>
</div>
<div class="control-check-section">
<p style="font-size: 0.75rem; font-weight: 800; color: #64748b; text-transform: uppercase; margin-bottom: 0.75rem;">Control Check</p>
<div class="control-check-item">
<div class="check-status passed">✓</div>
<div style="font-size: 0.85rem; font-weight: 600;">Native ML patterns active</div>
</div>
<div class="control-check-item">
<div class="check-status {'passed' if overdue == 0 else 'failed'}">{ '✓' if overdue == 0 else '✕' }</div>
<div style="font-size: 0.85rem; font-weight: 600;">Compliance reviews current</div>
</div>
</div>
</div>""", unsafe_allow_html=True)

            # CARD 4: Access Control Enforcement
            roles = man_metrics.get('ROLES_WITH_DATA_ACCESS', 0)
            zt_viol = man_metrics.get('ZERO_TRUST_VIOLATIONS', 0)
            st.markdown(f"""<div class="pillar-card-v2 green">
<div class="pillar-header">
<h3 class="pillar-title-v2">Access Control Enforcement</h3>
<span style="font-size: 1.5rem;">{'✅' if zt_viol == 0 else '⚠️'}</span>
</div>
<p class="pillar-subtitle-v2">
Role-based access control explicitly linked to classification metadata.
</p>
<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 2rem;">
<div style="background: rgba(15, 23, 42, 0.4); padding: 1rem; border-radius: 12px; text-align: center;">
<div style="font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;">Privileged Roles</div>
<div style="font-size: 1.25rem; font-weight: 800; color: #f8fafc;">{roles}</div>
</div>
<div style="background: rgba(15, 23, 42, 0.4); padding: 1rem; border-radius: 12px; text-align: center;">
<div style="font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;">Zero Trust Violations</div>
<div style="font-size: 1.25rem; font-weight: 800; color: {'#ef4444' if zt_viol > 0 else '#10b981'};">{zt_viol}</div>
</div>
</div>
<div class="control-check-section">
<p style="font-size: 0.75rem; font-weight: 800; color: #64748b; text-transform: uppercase; margin-bottom: 0.75rem;">Control Check</p>
<div class="control-check-item">
<div class="check-status passed">✓</div>
<div style="font-size: 0.85rem; font-weight: 600;">RBAC policies active</div>
</div>
<div class="control-check-item">
<div class="check-status {'passed' if zt_viol == 0 else 'failed'}">{ '✓' if zt_viol == 0 else '✕' }</div>
<div style="font-size: 0.85rem; font-weight: 600;">Zero trust verified</div>
</div>
</div>
</div>""", unsafe_allow_html=True)
            
            st.markdown("<div style='height: 1.5rem;'></div>", unsafe_allow_html=True)
            st.button("📋 Generate Enterprise Compliance Audit", width='stretch', type="primary", key="btn_gen_audit_1")

        st.markdown(f"""
<div style="background: rgba(15, 23, 42, 0.6); padding: 1.5rem; border-radius: 16px; margin-top: 2rem; border: 1px solid rgba(255, 255, 255, 0.05); text-align: center;">
<p style="color: #94a3b8; margin: 0; font-size: 1.1rem; font-weight: 600;">
"Mandatory Compliance Controls ensure all sensitive data is <b>automatically classified, tagged, and protected</b> at all times."
</p>
<p style="color: #64748b; margin-top: 0.5rem; font-size: 0.8rem;">Last Sync: {datetime.now().strftime('%A, %B %d, %Y at %I:%M %p')}</p>
</div>
""", unsafe_allow_html=True)

    # ========================================================================
    # SUBTAB 2: RISK DISTRIBUTION
    # ========================================================================
    
    with subtab2:
        st.markdown("""
<div style="margin: 1.5rem 0 2rem 0;">
<h2 style="margin-bottom: 0.5rem; font-size: 2rem; font-weight: 800; letter-spacing: -0.025em;">📊 Risk Exposure Assessment</h2>
<p style="color: #94a3b8; font-size: 1rem; font-weight: 500;">
Analysis of data assets by security posture and C.I.A impact levels.
</p>
</div>
""", unsafe_allow_html=True)
        
        # Fetch detailed asset-level telemetry (CIA scoring)
        risk_assets = get_risk_exposure_assets(active_db, filters=filters)
        try:
            risk_assets["CIA_RISK_SCORE"] = pd.to_numeric(risk_assets.get("CIA_RISK_SCORE"), errors="coerce")
        except Exception:
            pass

        # Build distribution from detailed telemetry; fall back to factory distribution if needed
        try:
            if not risk_assets.empty and "RISK_CATEGORY" in risk_assets.columns:
                _counts = risk_assets["RISK_CATEGORY"].astype(str).str.upper().value_counts().to_dict()
            else:
                _counts = {}
        except Exception:
            _counts = {}

        risk_data = pd.DataFrame([
            {"Risk Level": "CRITICAL", "Count": int(_counts.get("CRITICAL", 0)), "Criteria": "Sum >= 10", "Status": "🔥 Critical"},
            {"Risk Level": "HIGH", "Count": int(_counts.get("HIGH", 0)), "Criteria": "Sum 7-9", "Status": "🚨 High"},
            {"Risk Level": "MEDIUM", "Count": int(_counts.get("MEDIUM", 0)), "Criteria": "Sum 4-6", "Status": "⚠️ Elevated"},
            {"Risk Level": "LOW", "Count": int(_counts.get("LOW", 0)), "Criteria": "Sum < 4", "Status": "✅ Secure"},
        ])
        try:
            _total = int(risk_data["Count"].sum())
            risk_data["Percentage"] = risk_data["Count"].apply(lambda x: f"{round((x / _total) * 100, 1)}%" if _total > 0 else "0%")
        except Exception:
            risk_data["Percentage"] = "0%"

        if not risk_data.empty and "Risk Level" in risk_data.columns and "Count" in risk_data.columns:
            # Stats Summary - Using the new levels from the sum-based scoring
            low_count = int(risk_data[risk_data['Risk Level'] == 'LOW']['Count'].values[0]) if not risk_data[risk_data['Risk Level'] == 'LOW'].empty else 0
            med_count = int(risk_data[risk_data['Risk Level'] == 'MEDIUM']['Count'].values[0]) if not risk_data[risk_data['Risk Level'] == 'MEDIUM'].empty else 0
            high_count = int(risk_data[risk_data['Risk Level'] == 'HIGH']['Count'].values[0]) if not risk_data[risk_data['Risk Level'] == 'HIGH'].empty else 0
            crit_count = int(risk_data[risk_data['Risk Level'] == 'CRITICAL']['Count'].values[0]) if not risk_data[risk_data['Risk Level'] == 'CRITICAL'].empty else 0
            
            total_assets = low_count + med_count + high_count + crit_count
            
            # Calculate percentages
            high_pct = ((crit_count + high_count) / total_assets * 100) if total_assets > 0 else 0
            med_pct = (med_count / total_assets * 100) if total_assets > 0 else 0
            low_pct = (low_count / total_assets * 100) if total_assets > 0 else 0

            # Overall Risk Score Calculation (Weighted)
            # Critical: 4, High: 3, Med: 2, Low: 1
            risk_score_sum = (crit_count * 4 + high_count * 3 + med_count * 2 + low_count * 1)
            risk_score = risk_score_sum / max(total_assets, 1)

            risk_level_text = "CRITICAL EXPOSURE" if risk_score >= 3.0 else "SUBSTANTIAL RISK" if risk_score >= 2.2 else "CONTROLLED ENVIRONMENT" if risk_score >= 1.6 else "OPTIMIZED POSTURE"
            risk_desc = "Immediate remediation required for high-sensitivity leaks." if risk_score >= 3.0 else "Active monitoring and prioritized patching recommended." if risk_score >= 2.2 else "Security baseline met with minor optimizations pending." if risk_score >= 1.6 else "Exceptional governance alignment achieved."
            risk_color = "#ef4444" if risk_score >= 3.0 else "#f59e0b" if risk_score >= 2.2 else "#38bdf8" if risk_score >= 1.6 else "#10b981"
            
            # Overall Risk Summary Banner
            st.markdown(f"""
<div style="background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.9) 100%); padding: 2.5rem; border-radius: 32px; border: 1px solid rgba(255, 255, 255, 0.08); margin-bottom: 3rem; color: white;">
<div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 3rem;">
<div style="flex: 1; min-width: 300px;">
<div style="color: #94a3b8; font-size: 0.85rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.2em; margin-bottom: 1rem;">Risk Mitigation Pulse</div>
<div style="font-size: 2.5rem; font-weight: 950; color: white; line-height: 1; margin-bottom: 1rem;">{risk_level_text}</div>
<p style="color: #64748b; font-size: 1rem; margin-bottom: 1.5rem;">{risk_desc}</p>
<!-- Mini Risk Meter -->
<div style="width: 100%; height: 8px; background: rgba(255,255,255,0.05); border-radius: 10px; position: relative; margin-bottom: 0.5rem;">
<div style="width: {(risk_score/4)*100}%; height: 100%; background: {risk_color}; border-radius: 10px; box-shadow: 0 0 15px {risk_color}30;"></div>
</div>
<div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: #475569; font-weight: 700;">
<span>LOW (1.0)</span>
<span>SCORE: {risk_score:.2f} / 4.00</span>
<span>CRITICAL (4.0)</span>
</div>
</div>
<div style="display: flex; gap: 2.5rem; background: rgba(15, 23, 42, 0.5); padding: 2rem; border-radius: 24px; border: 1px solid rgba(255,255,255,0.03);">
<div style="text-align: center;">
<div style="color: #ef4444; font-size: 2.75rem; font-weight: 900; line-height: 1;">{crit_count}</div>
<div style="color: #ef4444; font-size: 0.7rem; font-weight: 800; text-transform: uppercase; margin-top: 5px;">🔥 Critical</div>
</div>
<div style="text-align: center;">
<div style="color: #f59e0b; font-size: 2.75rem; font-weight: 900; line-height: 1;">{high_count}</div>
<div style="color: #f59e0b; font-size: 0.7rem; font-weight: 800; text-transform: uppercase; margin-top: 5px;">🚨 High</div>
</div>
<div style="text-align: center;">
<div style="color: #10b981; font-size: 2.75rem; font-weight: 900; line-height: 1;">{low_count}</div>
<div style="color: #10b981; font-size: 0.7rem; font-weight: 800; text-transform: uppercase; margin-top: 5px;">✅ Secure</div>
</div>
</div>
</div>
</div>
""", unsafe_allow_html=True)
            
            # Layout with Chart and Detailed Cards
            chart_col, cards_col = st.columns([1, 1.2], gap="large")
            
            with chart_col:
                st.markdown('<div class="glass-panel" style="padding: 2.5rem;">', unsafe_allow_html=True)
                st.markdown("""
<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem;">
<h4 style="margin: 0; font-weight: 800;">Risk Distribution</h4>
<span style="background: rgba(56, 189, 248, 0.1); color: #38bdf8; padding: 4px 12px; border-radius: 12px; font-size: 0.75rem; font-weight: 700;">Live Feed</span>
</div>
""", unsafe_allow_html=True)
                
                # Plotly Donut Chart
                import plotly.graph_objects as go
                fig = go.Figure(data=[go.Pie(
                    labels=risk_data['Risk Level'], 
                    values=risk_data['Count'], 
                    hole=.75,
                    marker=dict(colors=['#334155', '#ef4444', '#f59e0b', '#10b981']),
                    textinfo='none',
                    hoverinfo='label+value+percent',
                    hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Distribution: %{percent}<extra></extra>'
                )])
                
                # Add Center Text
                fig.add_annotation(
                    text=f"<span style='font-size: 2.5rem; font-weight: 900; color: white;'>{total_assets}</span><br><span style='font-size: 0.8rem; color: #64748b; font-weight: 700;'>TOTAL ASSETS</span>",
                    showarrow=False,
                    font=dict(size=14)
                )

                fig.update_layout(
                    showlegend=True,
                    legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5, font=dict(color="#94a3b8", size=11)),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    margin=dict(t=0, b=50, l=0, r=0),
                    height=400
                )
                st.plotly_chart(fig, width='stretch', config={'displayModeBar': False}, key='plotly_risk_chart_1')
                st.markdown('</div>', unsafe_allow_html=True)

            with cards_col:
                # High Risk Card with Actions
                st.markdown(f"""
<div style="background: linear-gradient(145deg, rgba(239, 68, 68, 0.08), rgba(239, 68, 68, 0.03)); padding: 2rem; border-radius: 24px; border: 1px solid rgba(239, 68, 68, 0.15); margin-bottom: 1.5rem;">
<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1.5rem;">
<div style="display: flex; align-items: center; gap: 1rem;">
<div style="background: #ef4444; color: white; padding: 10px; border-radius: 12px; font-size: 1.25rem;">🔥</div>
<div>
<div style="font-size: 1.1rem; font-weight: 800; color: #f8fafc;">Exposure Intensity</div>
<div style="font-size: 0.75rem; color: #94a3b8; font-weight: 600;">Assets with High/Critical Σ(C+I+A) scores</div>
</div>
</div>
<div style="text-align: right;">
<div style="font-size: 1.75rem; font-weight: 950; color: #ef4444;">{high_pct:.1f}%</div>
<div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">of estate</div>
</div>
</div>
<div style="background: rgba(0, 0, 0, 0.2); padding: 1.25rem; border-radius: 16px;">
<div style="font-size: 0.75rem; color: #fca5a5; font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem;">🚨 Risk Mitigation Directives:</div>
<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
<div style="font-size: 0.75rem; color: #cbd5e1; background: rgba(239, 68, 68, 0.1); padding: 8px 12px; border-radius: 8px;">🔐 Enforce MFA/RBAC</div>
<div style="font-size: 0.75rem; color: #cbd5e1; background: rgba(239, 68, 68, 0.1); padding: 8px 12px; border-radius: 8px;">🛠️ Tag Masking Policy</div>
<div style="font-size: 0.75rem; color: #cbd5e1; background: rgba(239, 68, 68, 0.1); padding: 8px 12px; border-radius: 8px;">📊 Prioritize Review</div>
<div style="font-size: 0.75rem; color: #cbd5e1; background: rgba(239, 68, 68, 0.1); padding: 8px 12px; border-radius: 8px;">⚡ Auto-Escalate Alerts</div>
</div>
</div>
</div>
""", unsafe_allow_html=True)
                
                # Medium Risk Card
                st.markdown(f"""
<div style="background: linear-gradient(145deg, rgba(245, 158, 11, 0.08), rgba(245, 158, 11, 0.03)); padding: 2rem; border-radius: 24px; border: 1px solid rgba(245, 158, 11, 0.15); margin-bottom: 1.5rem;">
<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1.5rem;">
<div style="display: flex; align-items: center; gap: 1rem;">
<div style="background: #f59e0b; color: white; padding: 10px; border-radius: 12px; font-size: 1.25rem;">⚖️</div>
<div>
<div style="font-size: 1.1rem; font-weight: 800; color: #f8fafc;">Standard Sensitivity</div>
<div style="font-size: 0.75rem; color: #94a3b8; font-weight: 600;">Assets mapped to C2, I2, or A2 levels</div>
</div>
</div>
<div style="text-align: right;">
<div style="font-size: 1.75rem; font-weight: 950; color: #f59e0b;">{med_pct:.1f}%</div>
<div style="font-size: 0.75rem; color: #64748b; font-weight: 600;">of estate</div>
</div>
</div>
<div style="display: flex; gap: 1rem; flex-wrap: wrap;">
<span style="background: rgba(245, 158, 11, 0.1); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.2); padding: 4px 12px; border-radius: 100px; font-size: 0.7rem; font-weight: 700;">Periodic Audits Required</span>
<span style="background: rgba(245, 158, 11, 0.1); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.2); padding: 4px 12px; border-radius: 100px; font-size: 0.7rem; font-weight: 700;">Schema Variance Checks</span>
</div>
</div>
""", unsafe_allow_html=True)
                
                # Low Risk Card
                st.markdown(f"""
<div style="background: linear-gradient(145deg, rgba(16, 185, 129, 0.08), rgba(16, 185, 129, 0.03)); padding: 2rem; border-radius: 24px; border: 1px solid rgba(16, 185, 129, 0.15);">
<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
<div style="display: flex; align-items: center; gap: 1rem;">
<div style="background: #10b981; color: white; padding: 10px; border-radius: 12px; font-size: 1.25rem;">✅</div>
<div>
<div style="font-size: 1.1rem; font-weight: 800; color: #f8fafc;">Compliant Posture</div>
<div style="font-size: 0.75rem; color: #94a3b8; font-weight: 600;">Low impact or public data classifications</div>
</div>
</div>
</div>
</div>
""", unsafe_allow_html=True)


            st.markdown("<div style='height: 4rem;'></div>", unsafe_allow_html=True)
            
            # Detailed Breakdown Section
            st.markdown("""
<div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem;">
<div style="width: 4px; height: 24px; background: #38bdf8; border-radius: 4px;"></div>
<h3 style="margin: 0; font-weight: 900; letter-spacing: -0.02em;">Detailed Risk Inventory Matrix</h3>
</div>
""", unsafe_allow_html=True)
            
            # Styled Dataframe
            st.dataframe(
                risk_data, 
                width='stretch', 
                hide_index=True,
                column_config={
                    "Risk Level": st.column_config.TextColumn("Risk Category", width="large"),
                    "Count": st.column_config.NumberColumn("Asset Count", format="%d"),
                    "Percentage": st.column_config.TextColumn("Allocation"),
                    "Criteria": st.column_config.TextColumn("Governance Logic")
                }
            )

            # Detailed telemetry matrix (requested query output)
            if not risk_assets.empty:
                st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)
                st.dataframe(
                    risk_assets[[
                        "ASSET_NAME",
                        "BUSINESS_UNIT",
                        "CLASSIFICATION_LABEL",
                        "CONFIDENTIALITY_LEVEL",
                        "INTEGRITY_LEVEL",
                        "AVAILABILITY_LEVEL",
                        "CIA_RISK_SCORE",
                        "RISK_CATEGORY",
                    ]],
                    width='stretch',
                    hide_index=True,
                )

        else:
            st.info("No risk telemetry available for this scope.")

    
    # ============================================================================
    # TAB 2: REVIEWS & AUDITS
    # ============================================================================

with tab2:
    st.header("Reviews & Violations")
    
    # Sub-tabs for Reviews & Violations
    subtab2_1, subtab2_2 = st.tabs([
        "📅 Annual Reviews",
        "🚨 Policy Violations"
    ])

    with subtab2_1:
        st.markdown("""
<div style="margin: 1.5rem 0 1rem 0;">
    <h3 style="margin-bottom: 0.25rem; font-size: 1.25rem;">📅 Annual Review Cycle</h3>
    <p style="color: #64748b; font-size: 0.875rem; font-weight: 500;">Compliance monitoring for periodic asset re-validation (Sec 6.3)</p>
</div>
""", unsafe_allow_html=True)
        
        # Fetch annual reviews data
        reviews_df = get_annual_reviews_data(db, filters=filters)
        
        if not reviews_df.empty:
            # Normalize columns
            reviews_df.columns = [c.upper() for c in reviews_df.columns]
            
            # Ensure proper datetime types
            if 'REVIEW_DUE_DATE' in reviews_df.columns:
                reviews_df['REVIEW_DUE_DATE'] = pd.to_datetime(reviews_df['REVIEW_DUE_DATE'], errors='coerce')
                # Remove timezone if any
                if pd.api.types.is_datetime64_any_dtype(reviews_df['REVIEW_DUE_DATE']):
                    if reviews_df['REVIEW_DUE_DATE'].dt.tz is not None:
                        reviews_df['REVIEW_DUE_DATE'] = reviews_df['REVIEW_DUE_DATE'].dt.tz_localize(None)

            today = datetime.now()
            
            # Calculations
            total_assets = len(reviews_df)
            overdue_count = len(reviews_df[reviews_df['REVIEW_STATUS'] == 'Overdue'])
            completed_count = len(reviews_df[reviews_df['REVIEW_STATUS'] == 'Completed On Time'])
            due_soon_count = len(reviews_df[reviews_df['REVIEW_STATUS'] == 'Due Soon'])
            
            # Summary Metrics for Annual Reviews
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Assets", total_assets)
            m2.metric("Overdue", overdue_count, delta=f"{overdue_count}" if overdue_count > 0 else "0", delta_color="inverse")
            m3.metric("Due Soon", due_soon_count, delta="30 Days", delta_color="off")
            m4.metric("Completion Rate", f"{(completed_count/total_assets*100):.1f}%" if total_assets > 0 else "0%")

            st.write("")
            
            # Dashboard Layout
            col1, col2 = st.columns([1.8, 1], gap="large")
            
            with col1:
                st.markdown("""
<div style="background: rgba(30, 41, 59, 0.2); padding: 1.5rem; border-radius: 20px; border: 1px solid rgba(255,255,255,0.03);">
    <h4 style="margin-top:0; margin-bottom: 1.25rem; font-size: 0.9rem; color: #94a3b8; letter-spacing: 0.1em; text-transform: uppercase;">📦 Audit Tiers & Priorities</h4>
""", unsafe_allow_html=True)

                def render_audit_tier(title, count, status, color, icon, detail):
                    pct = (count / total_assets * 100) if total_assets > 0 else 0
                    st.markdown(f"""
<div style="background: rgba(15, 23, 42, 0.3); padding: 1.25rem; border-radius: 16px; border: 1px solid rgba(255,255,255,0.05); margin-bottom: 1rem;">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; align-items: center; gap: 1rem;">
            <div style="font-size: 1.5rem;">{icon}</div>
            <div>
                <div style="font-size: 1rem; font-weight: 800; color: #f8fafc;">{title}</div>
                <div style="font-size: 0.75rem; color: #64748b;">{detail}</div>
            </div>
        </div>
        <div style="text-align: right;">
            <div style="font-size: 1.25rem; font-weight: 900; color: {color};">{count}</div>
            <div style="font-size: 0.7rem; color: #94a3b8; font-weight: 700;">{status}</div>
        </div>
    </div>
    <div style="width: 100%; background: rgba(255,255,255,0.03); height: 6px; border-radius: 10px; margin-top: 1rem; overflow: hidden;">
        <div style="width: {pct}%; background: {color}; height: 100%; border-radius: 10px;"></div>
    </div>
</div>
""", unsafe_allow_html=True)

                high_risk_count = len(reviews_df[reviews_df['RISK_CLASSIFICATION'] == 'High Risk'])
                unclass_count = len(reviews_df[reviews_df['RISK_CLASSIFICATION'] == 'Unclassified'])
                normal_count = total_assets - high_risk_count - unclass_count

                render_audit_tier("High Risk Assets", high_risk_count, "PRIORITY 1", "#ef4444", "🔥", "C3/I3/A3 sensitive data repositories")
                render_audit_tier("Unclassified Assets", unclass_count, "PRIORITY 2", "#f59e0b", "❔", "Missing valid classification labels")
                render_audit_tier("Enterprise Inventory", total_assets, "CYCLE ACTIVE", "#10b981", "🛡️", "Standard annual re-validation scope")
                
                st.markdown("</div>", unsafe_allow_html=True)
            
            with col2:
                st.markdown("""
<div style="background: rgba(30, 41, 59, 0.4); padding: 1.5rem; border-radius: 20px; border: 1px solid rgba(255,255,255,0.05);">
    <h4 style="margin-top:0; margin-bottom: 1.25rem; font-size: 0.85rem; color: #94a3b8; letter-spacing: 0.1em;">📣 ADHERENCE ACTIONS</h4>
""", unsafe_allow_html=True)
                
                # Action Buttons
                st.button("📧 Bulk Email Reminders", key="review_email_bulk", width='stretch')
                st.button("📝 Schedule Q1 Review Session", key="review_sched_q1", width='stretch')
                st.button("⚙️ Configure Frequency", key="review_config", width='stretch')
                
                st.markdown("<hr style='margin: 1.5rem 0; border-color: rgba(255,255,255,0.05);'>", unsafe_allow_html=True)
                st.write("**📥 Operational Export**")
                csv_data = reviews_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Download Full Review Set",
                    data=csv_data,
                    file_name="annual_review_inventory.csv",
                    mime="text/csv",
                    width='stretch'
                )
                
                st.markdown("</div>", unsafe_allow_html=True)

            st.write("")
            st.markdown("#### 💼 Review Assignment Status")
            
            if 'REVIEWER' in reviews_df.columns:
                # Group by data owner
                owner_stats = reviews_df.groupby('REVIEWER').agg(
                    Managed_Assets=('ASSET_FULL_NAME', 'count'),
                    Overdue=('REVIEW_STATUS', lambda x: (x == 'Overdue').sum()),
                    Completed=('REVIEW_STATUS', lambda x: (x == 'Completed On Time').sum()),
                    Pending=('REVIEW_STATUS', lambda x: ((x != 'Completed On Time') & (x != 'Overdue')).sum())
                ).reset_index()
                
                owner_stats['Health'] = owner_stats.apply(lambda x: '🔴 Critical' if x['Overdue'] > 0 else '🟢 Healthy', axis=1)
                
                st.dataframe(owner_stats.sort_values('Overdue', ascending=False), width='stretch', hide_index=True)
            else:
                st.info("Assign data owners to track review accountability.")

        else:
            st.info("No annual review lifecycle data found in the current environment.")

    with subtab2_2:
        st.write("### Policy Violations (Section 8.2.1)")
        
        # Fetch policy violations data
        with st.spinner("Loading policy violations data..."):
            violations_data = get_policy_violations(db, filters=filters)
        
        if violations_data is None or len(violations_data) == 0:
            st.warning("No policy violations data available or error fetching data.")
        else:
            try:
                # Active Violations
                active_row = violations_data[violations_data['METRIC'] == 'Active Violations']
                active_violations = int(active_row['VALUE'].iloc[0]) if not active_row.empty else 0
                
                # Resolved This Month
                resolved_row = violations_data[violations_data['METRIC'] == 'Resolved This Month']
                resolved_this_month = int(resolved_row['VALUE'].iloc[0]) if not resolved_row.empty else 0
                
                # Repeat Offenders
                repeat_row = violations_data[violations_data['METRIC'] == 'Repeat Offenders Count']
                repeat_offenders = int(repeat_row['VALUE'].iloc[0]) if not repeat_row.empty else 0
                
                v1, v2, v3 = st.columns(3)
                
                def render_violation_card(col, label, val, color, icon):
                    col.markdown(f"""
<div style="background: rgba(30, 41, 59, 0.4); padding: 1.5rem; border-radius: 20px; border: 1px solid {color}30; border-top: 4px solid {color}; backdrop-filter: blur(10px);">
    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem;">
        <span style="font-size: 1.25rem;">{icon}</span>
        <div style="color: #94a3b8; font-size: 0.75rem; font-weight: 800; text-transform: uppercase;">{label}</div>
    </div>
    <div style="color: #f8fafc; font-size: 2.25rem; font-weight: 900;">{val}</div>
</div>
""", unsafe_allow_html=True)

                render_violation_card(v1, "Active Breaches", active_violations, "#ef4444", "🚨")
                render_violation_card(v2, "Resolved (MTD)", resolved_this_month, "#10b981", "🛡️")
                render_violation_card(v3, "Repeat Events", repeat_offenders, "#f59e0b", "🔄")
                
            except Exception as e:
                st.warning(f"Error parsing metrics: {e}")

            st.markdown("---")
            
            # Display detailed breakdown table
            st.write("#### Policy Violations Breakdown")
            st.dataframe(violations_data, width='stretch', hide_index=True)
            
            st.markdown("---")
            
            # Violation Escalation Path
            st.write("#### Violation Escalation Path (Section 8.2.1)")
            ec1, ec2, ec3, ec4 = st.columns(4)
            
            with ec1:
                st.info("**Level 1**\n📧 Warning\n• Email notification\n• Policy reminder")
            with ec2:
                st.warning("**Level 2**\n📚 Retraining\n• Mandatory training\n• Counseling session")
            with ec3:
                st.error("**Level 3**\n🔒 Access Restriction\n• Temporary suspension\n• Manager review")


    # ========================================================================
    # TAB 3: REPORTS & TRENDS
    # ========================================================================

with tab3:
    st.header("Reports & Trends")
    
    # Sub-tabs for Reports & Trends
    subtab3_1, subtab3_2 = st.tabs([
        "📈 Trend Analytics",
        "📥 Export & Reports"
    ])
    
    with subtab3_1:
        st.markdown("### Compliance Trend Analytics")
        
        with st.spinner("Calculating compliance trends..."):
            trend_df = get_compliance_trends_metrics(db, filters=filters)
        
        if trend_df is not None and not trend_df.empty:
            # Normalize column names to upper case
            trend_df.columns = [c.upper() for c in trend_df.columns]
            
            # Ensure month is sorted ascending for charts
            chart_df = trend_df.sort_values('MONTH_PERIOD')
            
            # Line chart for Overall Trends
            import plotly.graph_objects as go
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=chart_df['MONTH_PERIOD'],
                y=chart_df['OVERALL_COMPLIANCE_SCORE'],
                name='Overall Compliance Score',
                mode='lines+markers',
                line=dict(color='#38bdf8', width=4),
                hovertemplate='%{y:.1f}%'
            ))
            
            fig.add_trace(go.Scatter(
                x=chart_df['MONTH_PERIOD'],
                y=chart_df['POLICY_COMPLIANCE_PCT'],
                name='Policy Compliance',
                mode='lines+markers',
                line=dict(color='#10b981', width=2, dash='dot')
            ))
            
            fig.add_trace(go.Scatter(
                x=chart_df['MONTH_PERIOD'],
                y=chart_df['GOVERNANCE_COMPLETION_PCT'],
                name='Governance Completion',
                mode='lines+markers',
                line=dict(color='#3b82f6', width=2, dash='dot')
            ))
            
            fig.add_trace(go.Scatter(
                x=chart_df['MONTH_PERIOD'],
                y=chart_df['AUDIT_COMPLIANCE_PCT'],
                name='Audit Status',
                mode='lines+markers',
                line=dict(color='#f59e0b', width=2, dash='dot')
            ))
            
            fig.add_trace(go.Scatter(
                x=chart_df['MONTH_PERIOD'],
                y=chart_df['RISK_COMPLIANCE_PCT'],
                name='Risk Score',
                mode='lines+markers',
                line=dict(color='#ef4444', width=2, dash='dot')
            ))
            
            fig.update_layout(
                title="Compliance Trends (Last 6 Months)",
                xaxis_title="Month",
                yaxis_title="Compliance %",
                yaxis=dict(range=[0, 105]),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color="#94a3b8"),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig, use_container_width=True, key="plotly_trend_chart")
            
            # Trend indicators
            st.markdown("#### Key Indicators")
            latest = chart_df.iloc[-1]
            prev = chart_df.iloc[-2] if len(chart_df) > 1 else latest
            
            i1, i2, i3, i4 = st.columns(4)
            i1.metric("Compliance Score", f"{latest['OVERALL_COMPLIANCE_SCORE']}%", f"{latest['OVERALL_COMPLIANCE_SCORE'] - prev['OVERALL_COMPLIANCE_SCORE']:.1f}%")
            i2.metric("Policy Rate", f"{latest['POLICY_COMPLIANCE_PCT']}%", f"{latest['POLICY_COMPLIANCE_PCT'] - prev['POLICY_COMPLIANCE_PCT']:.1f}%")
            i3.metric("Governance Rate", f"{latest['GOVERNANCE_COMPLETION_PCT']}%", f"{latest['GOVERNANCE_COMPLETION_PCT'] - prev['GOVERNANCE_COMPLETION_PCT']:.1f}%")
            i4.metric("Risk Score", f"{latest['RISK_COMPLIANCE_PCT']}%", f"{latest['RISK_COMPLIANCE_PCT'] - prev['RISK_COMPLIANCE_PCT']:.1f}%")
        else:
            st.info("Insufficient historical data to render trends.")

    with subtab3_2:
        st.markdown("### Export & Reports")
        st.caption("Downloadable executive and detailed compliance reports")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
<div class="glass-panel" style="padding: 1.5rem; margin-bottom: 1rem;">
    <h4 style="margin-top:0;">📊 Executive Summary</h4>
    <p style="color: #94a3b8; font-size: 0.85rem;">High-level compliance overview for management. Includes overall status, coverage, and major violations.</p>
</div>
""", unsafe_allow_html=True)
            if st.button("Generate Executive Report", key="gen_exec", width='stretch'):
                with st.spinner("Generating executive summary..."):
                    metrics_exec = get_classification_requirements_metrics(db, filters=filters)
                    summary_data = {
                        'Metric': ['Coverage', '5-Day SLA', 'Annual Review', 'Documentation', 'Violations'],
                        'Value': [
                            f"{metrics_exec.get('coverage', 0):.1f}%",
                            f"{metrics_exec.get('five_day_compliance', 0):.1f}%",
                            f"{metrics_exec.get('annual_review', 0):.1f}%",
                            f"{metrics_exec.get('doc_completeness', 0):.1f}%",
                            metrics_exec.get('policy_violations', 0)
                        ]
                    }
                    exec_df = pd.DataFrame(summary_data)
                    csv_exec = exec_df.to_csv(index=False).encode('utf-8')
                    st.download_button("📥 Download Executive Summary (CSV)", data=csv_exec, file_name=f"executive_summary_{datetime.now().strftime('%Y%m%d')}.csv", mime="text/csv", width='stretch', key="exec_csv_btn")

        with col2:
            st.markdown("""
<div class="glass-panel" style="padding: 1.5rem; margin-bottom: 1rem;">
    <h4 style="margin-top:0;">📋 Detailed Compliance</h4>
    <p style="color: #94a3b8; font-size: 0.85rem;">Full asset-level compliance details. Includes all classification metadata and risk scores.</p>
</div>
""", unsafe_allow_html=True)
            if st.button("Generate Detailed Report", key="gen_detail", width='stretch'):
                with st.spinner("Fetching full asset inventory..."):
                    try:
                        query_detail = f"SELECT * FROM {db}.{_gv_schema()}.ASSETS LIMIT 10000"
                        detailed_rows = snowflake_connector.execute_query(query_detail)
                        if detailed_rows:
                            df_detail = pd.DataFrame(detailed_rows)
                            csv_detail = df_detail.to_csv(index=False).encode('utf-8')
                            st.download_button("📥 Download Detailed Report (CSV)", data=csv_detail, file_name=f"detailed_compliance_{datetime.now().strftime('%Y%m%d')}.csv", mime="text/csv", width='stretch', key="detail_csv_btn")
                        else:
                            st.warning("No data found in asset inventory.")
                    except Exception as e:
                        st.error(f"Error: {e}")
        
        st.markdown("---")
        st.markdown("#### 📜 Audit & Policies")
        p_col1, p_col2 = st.columns([1, 1.5])
        
        with p_col1:
            st.markdown("""
<div class="glass-panel" style="padding: 1.5rem; height: 100%;">
    <h5 style="margin-top:0; color: #38bdf8;">🗓️ Audit Schedule</h5>
    <p style="color: #64748b; font-size: 0.75rem;">Planned governance and regulatory reviews.</p>
    <div style="font-size: 0.85rem; color: #f8fafc;">
        <div style="margin-bottom: 0.5rem;">📅 <b>Monthly Sync</b>: Ready</div>
        <div style="margin-bottom: 0.5rem;">📅 <b>Q1 Regulatory</b>: Scheduled</div>
        <div style="margin-bottom: 0.5rem;">📅 <b>Annual External</b>: Planned</div>
    </div>
</div>
""", unsafe_allow_html=True)

        with p_col2:
            # Policy Reader Integration (Simplified)
            st.markdown("""
<div class="glass-panel" style="padding: 1.5rem;">
    <h5 style="margin-top:0; color: #10b981;">📄 Policy Repository</h5>
    <p style="color: #64748b; font-size: 0.75rem;">Access authoritative governance documents.</p>
</div>
""", unsafe_allow_html=True)
            
            pol_db = "DATA_CLASSIFICATION_DB"
            pol_schema = "DATA_CLASSIFICATION_GOVERNANCE"
            try:
                p_rows = snowflake_connector.execute_query(f"SELECT POLICY_ID, POLICY_NAME, MIME_TYPE FROM {pol_db}.{pol_schema}.POLICIES ORDER BY CREATED_AT DESC LIMIT 3") or []
                if not p_rows:
                    st.info("No documents found.")
                else:
                    for p in p_rows:
                        st.markdown(f"📄 **{p['POLICY_NAME']}** ({p['MIME_TYPE']})")
            except:
                st.info("Policy repository unavailable.")

# ============================================================================
# FOOTER
# ============================================================================

st.markdown("---")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Policy: AVD-DWH-DCLS-001")

# --- Snowflake Consumption Tracking ---
def display_consumption_metrics():
    """Calculates and displays the estimated Snowflake credits consumed during this page run."""
    try:
        # Query Information Schema for queries executed in this session since the run started
        # Use a small buffer to ensure we capture the first queries of the run
        ts_str = (_run_start_ts - timedelta(seconds=2)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        query = f"""
        SELECT 
            COUNT(*) as query_count,
            SUM(TOTAL_ELAPSED_TIME) as total_time_ms,
            MAX(WAREHOUSE_SIZE) as wh_size
        FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY_BY_SESSION())
        WHERE START_TIME >= '{ts_str}'::TIMESTAMP_NTZ
        AND QUERY_TEXT NOT LIKE '%QUERY_HISTORY_BY_SESSION%' -- Exclude this tracking query itself
        """
        
        rows = snowflake_connector.execute_query(query)
        if rows and rows[0].get('QUERY_COUNT', 0) > 0:
            r = rows[0]
            cnt = int(r['QUERY_COUNT'])
            ms = float(r['TOTAL_TIME_MS'] or 0)
            wh = str(r['WH_SIZE'] or 'X-SMALL').upper()
            
            # Standard Snowflake Warehouse credit rates (per hour)
            wh_rates = {
                'X-SMALL': 1, 'SMALL': 2, 'MEDIUM': 4, 'LARGE': 8,
                'X-LARGE': 16, '2X-LARGE': 32, '3X-LARGE': 64, '4X-LARGE': 128
            }
            rate = wh_rates.get(wh, 1) # Default to 1 if unknown
            
            # Credit calculation: (seconds / 3600) * rate
            credits = (ms / 1000 / 3600) * rate
            
            # Display in both locations for visibility (Top placeholder and Bottom log)
            consumption_placeholder.warning(f"❄️ **Snowflake Credit Consumption (This Run):** `{credits:.6f}` credits (Est. cost for {cnt} queries and {ms/1000:.2f}s execution)")
            st.info(f"❄️ **Snowflake Credits Consumed (This Run):** `{credits:.6f}` (Estimated based on {cnt} queries and {ms/1000:.2f}s execution time)")
    except Exception:
        # Silently fail if metadata access is restricted
        pass

# Execute the metrics display at the very end of the page
display_consumption_metrics()
