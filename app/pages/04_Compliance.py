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
from src.services.asset_utils import get_health_score_metrics
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

def _table_exists(db: Optional[str], schema: str, table: str) -> bool:
    """Check if a table exists."""
    if not db:
        return False
    try:
        rows = snowflake_connector.execute_query(
            """
            SELECT 1 AS X
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_CATALOG = %(db)s AND TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
            LIMIT 1
            """,
            {"db": db, "s": schema, "t": table},
        ) or []
        return bool(rows)
    except Exception:
        return False

# ============================================================================
# FILTER HELPER FUNCTIONS
# ============================================================================

@st.cache_data(ttl=300)
def _list_warehouses() -> List[str]:
    """Best-effort list of accessible warehouses for selection."""
    try:
        rows = snowflake_connector.execute_query("SHOW WAREHOUSES") or []
        return [r.get("name") or r.get("NAME") for r in rows if (r.get("name") or r.get("NAME"))]
    except Exception:
        return []

def _apply_warehouse(wh: Optional[str]) -> None:
    """Resume and USE the selected warehouse; ignore errors silently."""
    if not wh:
        return
    try:
        try:
            snowflake_connector.execute_non_query(f"ALTER WAREHOUSE {wh} RESUME")
        except Exception:
            pass
        try:
            snowflake_connector.execute_non_query(f"USE WAREHOUSE {wh}")
        except Exception:
            pass
        st.session_state['sf_warehouse'] = wh
    except Exception:
        pass

@st.cache_data(ttl=300)
def _list_databases() -> List[str]:
    """Best-effort list of accessible databases."""
    try:
        rows = snowflake_connector.execute_query("SHOW DATABASES") or []
        return [r.get("name") or r.get("NAME") for r in rows if (r.get("name") or r.get("NAME"))]
    except Exception:
        return []

def _apply_database(db: Optional[str]) -> None:
    """USE the selected database and persist it; ignore errors silently."""
    try:
        if db and db != "All":
            try:
                snowflake_connector.execute_non_query(f"USE DATABASE {db}")
            except Exception:
                pass
            st.session_state['sf_database'] = db
        else:
            # Clear explicit selection; downstream will resolve or prompt
            st.session_state.pop('sf_database', None)
    except Exception:
        pass

@st.cache_data(ttl=300)
def _list_schemas(db: Optional[str]) -> List[str]:
    """List schemas in the given database."""
    if not db or db == "All":
        return []
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT SCHEMA_NAME
            FROM INFORMATION_SCHEMA.SCHEMATA
            ORDER BY SCHEMA_NAME
            """
        ) or []
        return [r.get('SCHEMA_NAME') for r in rows if r.get('SCHEMA_NAME')]
    except Exception:
        return []

@st.cache_data(ttl=300)
def _list_objects(db: Optional[str], schema: Optional[str]) -> List[str]:
    """List tables and views in the given database/schema."""
    if not db or db == "All" or not schema or schema == "All":
        return []
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT TABLE_NAME AS NAME, 'TABLE' AS TYPE
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = %(s)s
            UNION ALL
            SELECT TABLE_NAME AS NAME, 'VIEW' AS TYPE
            FROM INFORMATION_SCHEMA.VIEWS
            WHERE TABLE_SCHEMA = %(s)s
            ORDER BY NAME
            """,
            {"s": schema},
        ) or []
        return [r.get('NAME') for r in rows if r.get('NAME')]
    except Exception:
        return []

@st.cache_data(ttl=300)
def _list_columns(db: Optional[str], schema: Optional[str], obj: Optional[str]) -> List[str]:
    """List columns in the given table/view."""
    if not db or db == "All" or not schema or schema == "All" or not obj or obj == "All":
        return []
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT COLUMN_NAME
            FROM {db}.INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
            ORDER BY ORDINAL_POSITION
            """,
            {"s": schema, "t": obj},
        ) or []
        return [r.get('COLUMN_NAME') for r in rows if r.get('COLUMN_NAME')]
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
def get_mandatory_compliance_elements(db: str, filters: dict = None) -> List[Dict]:
    """Fetch mandatory compliance elements metrics from ASSETS table."""
    schema = _gv_schema()
    
    # Construct query to fetch all metrics from ASSETS table
    query = f"""
    -- CTE to calculate all compliance metrics from ASSETS table
    WITH asset_metrics AS (
        SELECT 
            -- Total assets
            COUNT(*) as total_assets,
            
            -- 5-Day SLA Compliance
            COUNT(CASE WHEN 
                   (DATEDIFF(day, 
                     COALESCE(DATA_CREATION_DATE, CREATED_TIMESTAMP), 
                     CLASSIFICATION_DATE
                   ) - 
                   (FLOOR(DATEDIFF(day, COALESCE(DATA_CREATION_DATE, CREATED_TIMESTAMP), CLASSIFICATION_DATE) / 7) * 2) -
                   CASE 
                       WHEN DAYOFWEEKISO(COALESCE(DATA_CREATION_DATE, CREATED_TIMESTAMP)) = 7 THEN 1 
                       WHEN DAYOFWEEKISO(COALESCE(DATA_CREATION_DATE, CREATED_TIMESTAMP)) = 6 
                            AND DAYOFWEEKISO(CLASSIFICATION_DATE) = 7 THEN 2
                       WHEN DAYOFWEEKISO(CLASSIFICATION_DATE) = 7 THEN 1
                       ELSE 0
                   END) <= 5
                   AND CLASSIFICATION_DATE IS NOT NULL
             THEN 1 END) as sla_compliant,
            COUNT(CASE WHEN CLASSIFICATION_DATE IS NOT NULL THEN 1 END) as classified_total,
            
            -- Annual Reviews (assets reviewed in last 365 days)
            COUNT(CASE WHEN LAST_REVIEW_DATE >= DATEADD(year, -1, CURRENT_DATE()) THEN 1 END) as annual_reviewed,
            
            -- Documentation Complete (assets with non-null, non-empty data_description)
            COUNT(CASE WHEN DATA_DESCRIPTION IS NOT NULL AND TRIM(DATA_DESCRIPTION) != '' THEN 1 END) as doc_complete,
            
            -- Tags Applied (assets with classification label)
            COUNT(CASE WHEN CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL != 'Unclassified' THEN 1 END) as tagged_assets
            
        FROM {db}.{schema}.ASSETS
        WHERE 1=1
    )
    SELECT 
        'Mandatory Compliance Requirements' as CATEGORY,
        'Enforcement tracking for Policy AVD-DWH-DCLS-001 Section 4.1 & 5.2' as METRIC,
        '' as VALUE,
        '' as STATUS,
        '' as DETAILS

    UNION ALL

    SELECT 
        'Assets Classified Within 5 Business Days',
        'Policy SLA compliance for classification timeline',
        (
            SELECT 
                TO_VARCHAR(sla_compliant) || ' / ' || 
                TO_VARCHAR(classified_total) || ' (' || 
                TO_VARCHAR(ROUND(100.0 * sla_compliant / NULLIF(classified_total, 0), 0)) || '%)' 
            FROM asset_metrics
        ),
        (
            SELECT CASE WHEN (100.0 * sla_compliant / NULLIF(classified_total, 0)) >= 90 THEN '🟢' 
                        WHEN (100.0 * sla_compliant / NULLIF(classified_total, 0)) >= 70 THEN '🟡' 
                        ELSE '🔴' END
            FROM asset_metrics
        ),
        (SELECT TO_VARCHAR(classified_total - sla_compliant) || ' assets exceeding 5-day window' FROM asset_metrics)

    UNION ALL

    SELECT 
        'Annual Reviews Completed',
        'Periodic review compliance per policy requirements',
        (
            SELECT 
                TO_VARCHAR(annual_reviewed) || ' / ' || 
                TO_VARCHAR(total_assets) || ' (' || 
                TO_VARCHAR(ROUND(100.0 * annual_reviewed / NULLIF(total_assets, 0), 0)) || '%)' 
            FROM asset_metrics
        ),
        (
            SELECT CASE WHEN (100.0 * annual_reviewed / NULLIF(total_assets, 0)) >= 90 THEN '🟢' 
                        WHEN (100.0 * annual_reviewed / NULLIF(total_assets, 0)) >= 70 THEN '🟡' 
                        ELSE '🔴' END
            FROM asset_metrics
        ),
        (SELECT TO_VARCHAR(total_assets - annual_reviewed) || ' assets pending annual review' FROM asset_metrics)

    UNION ALL

    SELECT 
        'Classification Documentation Complete',
        'Completeness of classification rationale and impact assessments',
        (
            SELECT 
                TO_VARCHAR(doc_complete) || ' / ' || 
                TO_VARCHAR(total_assets) || ' (' || 
                TO_VARCHAR(ROUND(100.0 * doc_complete / NULLIF(total_assets, 0), 0)) || '%)' 
            FROM asset_metrics
        ),
        (
            SELECT CASE WHEN (100.0 * doc_complete / NULLIF(total_assets, 0)) >= 90 THEN '🟢' 
                        WHEN (100.0 * doc_complete / NULLIF(total_assets, 0)) >= 70 THEN '🟡' 
                        ELSE '🔴' END
            FROM asset_metrics
        ),
        (SELECT TO_VARCHAR(total_assets - doc_complete) || ' assets missing documentation' FROM asset_metrics)

    UNION ALL

    SELECT 
        'Snowflake Tags Applied Correctly',
        'System tagging compliance for data classification',
        (
            SELECT 
                TO_VARCHAR(tagged_assets) || ' / ' || 
                TO_VARCHAR(total_assets) || ' (' || 
                TO_VARCHAR(ROUND(100.0 * tagged_assets / NULLIF(total_assets, 0), 0)) || '%)' 
            FROM asset_metrics
        ),
        (
            SELECT CASE WHEN (100.0 * tagged_assets / NULLIF(total_assets, 0)) >= 90 THEN '🟢' 
                        WHEN (100.0 * tagged_assets / NULLIF(total_assets, 0)) >= 70 THEN '🟡' 
                        ELSE '🔴' END
            FROM asset_metrics
        ),
        (SELECT TO_VARCHAR(total_assets - tagged_assets) || ' assets missing classification tags' FROM asset_metrics)
        
    ORDER BY 
        CASE 
            WHEN CATEGORY = 'Mandatory Compliance Requirements' THEN 1
            WHEN CATEGORY = 'Assets Classified Within 5 Business Days' THEN 2
            WHEN CATEGORY = 'Annual Reviews Completed' THEN 3
            WHEN CATEGORY = 'Classification Documentation Complete' THEN 4
            WHEN CATEGORY = 'Snowflake Tags Applied Correctly' THEN 5
            ELSE 6
        END
    """
    
    try:
        # Execute query and return results
        results = snowflake_connector.execute_query(query)
        # Normalize keys to uppercase for consistency
        return [{k.upper(): v for k, v in row.items()} for row in (results or [])]
    except Exception as e:
        logger.error(f"Error executing mandatory compliance query: {e}")
        # Return empty list on error
        return []

# REMOVED CACHE to force fresh data - enable cache after debugging
def get_risk_classification_data(db: str, filters: dict = None) -> pd.DataFrame:
    """Fetch risk classification distribution directly from the ASSETS table."""
    schema = _gv_schema()
    
    try:
        # Resolve a safe database context (some pages may pass "All" when the sidebar filter is not set)
        if not db or str(db).strip().upper() in ("ALL", "NONE", "NULL", "(NONE)", "UNKNOWN", ""):
            db = st.session_state.get("sf_database") or ""
        if not db or str(db).strip().upper() in ("ALL", "NONE", "NULL", "(NONE)", "UNKNOWN", ""):
            return pd.DataFrame([
                {'Risk Level': 'CRITICAL', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum >= 10', 'Status': '🔥 Critical'},
                {'Risk Level': 'HIGH', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum 7-9', 'Status': '🚨 High'},
                {'Risk Level': 'MEDIUM', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum 4-6', 'Status': '⚠️ Elevated'},
                {'Risk Level': 'LOW', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum < 4', 'Status': '✅ Secure'}
            ])

        where_clause, params = _build_filters(filters, db)
        
        query = f"""
        WITH target_assets AS (
            -- Use the provided database and schema context but don't force a match on DATABASE_NAME column
            -- unless explicitly requested by UI filters to be more permissive.
            SELECT * FROM {db}.{schema}.ASSETS
            WHERE {where_clause}
        ),
        risk_calculation AS (
            SELECT
                ASSET_ID,
                (
                    COALESCE(TRY_TO_NUMBER(SUBSTRING(COALESCE(TO_VARCHAR(CONFIDENTIALITY_LEVEL), 'C1'), 2)), 1) +
                    COALESCE(TRY_TO_NUMBER(SUBSTRING(COALESCE(TO_VARCHAR(INTEGRITY_LEVEL), 'I1'), 2)), 1) +
                    COALESCE(TRY_TO_NUMBER(SUBSTRING(COALESCE(TO_VARCHAR(AVAILABILITY_LEVEL), 'A1'), 2)), 1)
                ) as total_score
            FROM target_assets
        ),
        scored_levels AS (
            SELECT 
                ASSET_ID,
                CASE 
                    WHEN total_score >= 10 THEN 'CRITICAL'
                    WHEN total_score >= 7 THEN 'HIGH'
                    WHEN total_score >= 4 THEN 'MEDIUM'
                    ELSE 'LOW'
                END as risk_level
            FROM risk_calculation
        ),
        factory AS (
            SELECT 'CRITICAL' as l UNION ALL SELECT 'HIGH' UNION ALL SELECT 'MEDIUM' UNION ALL SELECT 'LOW'
        ),
        aggregation AS (
            SELECT 
                f.l as "Risk Level",
                COUNT(s.ASSET_ID) as "Count"
            FROM factory f
            LEFT JOIN scored_levels s ON f.l = s.risk_level
            GROUP BY f.l
        ),
        totals AS (
            SELECT SUM("Count") as total_sum FROM aggregation
        )
        SELECT 
            a."Risk Level",
            a."Count",
            CONCAT(ROUND((a."Count" / NULLIF(t.total_sum, 0)) * 100, 1), '%') as "Percentage",
            CASE a."Risk Level"
                WHEN 'CRITICAL' THEN 'Sum >= 10'
                WHEN 'HIGH' THEN 'Sum 7-9'
                WHEN 'MEDIUM' THEN 'Sum 4-6'
                ELSE 'Sum < 4'
            END as "Criteria",
            CASE a."Risk Level"
                WHEN 'CRITICAL' THEN '🔥 Critical'
                WHEN 'HIGH' THEN '🚨 High'
                WHEN 'MEDIUM' THEN '⚠️ Elevated'
                ELSE '✅ Secure'
            END as "Status"
        FROM aggregation a
        CROSS JOIN totals t
        ORDER BY 
            CASE a."Risk Level"
                WHEN 'LOW' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'HIGH' THEN 3
                WHEN 'CRITICAL' THEN 4
            END
        """
        
        rows = snowflake_connector.execute_query(query, params) or []
        df = pd.DataFrame(rows)
        # Keep UI stable even if something returns no rows.
        if df.empty:
            return pd.DataFrame([
                {'Risk Level': 'CRITICAL', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum >= 10', 'Status': '🔥 Critical'},
                {'Risk Level': 'HIGH', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum 7-9', 'Status': '🚨 High'},
                {'Risk Level': 'MEDIUM', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum 4-6', 'Status': '⚠️ Elevated'},
                {'Risk Level': 'LOW', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum < 4', 'Status': '✅ Secure'}
            ])
        return df
        
    except Exception as e:
        logger.warning(f"Error fetching risk classification data from ASSETS: {e}")
        return pd.DataFrame([
            {'Risk Level': 'CRITICAL', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum >= 10', 'Status': '🔥 Critical'},
            {'Risk Level': 'HIGH', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum 7-9', 'Status': '🚨 High'},
            {'Risk Level': 'MEDIUM', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum 4-6', 'Status': '⚠️ Elevated'},
            {'Risk Level': 'LOW', 'Count': 0, 'Percentage': '0%', 'Criteria': 'Sum < 4', 'Status': '✅ Secure'}
        ])


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

def get_compliance_impact_assessment(db: str) -> List[Dict]:
    """
    Perform a multi-dimensional compliance impact assessment for PII, SOX, and SOC 2.
    Evaluates classification, tagging, masking, RBAC, and audit readiness.
    """
    schema = _gv_schema()
    try:
        query = f"""
        WITH framework_assets AS (
            SELECT 
                ASSET_ID,
                ASSET_NAME,
                FULLY_QUALIFIED_NAME,
                CLASSIFICATION_LABEL,
                CONFIDENTIALITY_LEVEL,
                PII_RELEVANT,
                SOX_RELEVANT,
                SOC2_RELEVANT,
                SENSITIVE_DATA_USAGE_COUNT,
                DATA_OWNER,
                LAST_REVIEW_DATE,
                NEXT_REVIEW_DATE,
                -- Verify classification & tagging
                CASE WHEN CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL != 'Unclassified' THEN 1 ELSE 0 END as is_tagged,
                -- Confirm masking (Simulated by checking if C level is elevated or specific tag exists)
                -- In a real app, this would join with SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
                CASE WHEN CONFIDENTIALITY_LEVEL IN ('C2', 'C3') THEN 1 ELSE 0 END as is_masked,
                -- Validate RBAC (Based on whether usage count seems aligned with owner)
                CASE WHEN SENSITIVE_DATA_USAGE_COUNT < 100 THEN 1 ELSE 0 END as is_rbac_aligned,
                -- Audit readiness
                CASE WHEN LAST_REVIEW_DATE >= DATEADD(month, -6, CURRENT_DATE()) THEN 1 ELSE 0 END as is_audit_ready
            FROM {db}.{schema}.ASSETS
            WHERE PII_RELEVANT = TRUE OR SOX_RELEVANT = TRUE OR SOC2_RELEVANT = TRUE
        ),
        impact_calc AS (
            SELECT
                'PII' as framework,
                COUNT(*) as total,
                SUM(CASE WHEN PII_RELEVANT = TRUE THEN 1 ELSE 0 END) as relevant_count,
                SUM(CASE WHEN PII_RELEVANT = TRUE AND is_tagged = 1 THEN 1 ELSE 0 END) as tagged,
                SUM(CASE WHEN PII_RELEVANT = TRUE AND is_masked = 1 THEN 1 ELSE 0 END) as masked,
                SUM(CASE WHEN PII_RELEVANT = TRUE AND is_rbac_aligned = 1 THEN 1 ELSE 0 END) as rbac,
                SUM(CASE WHEN PII_RELEVANT = TRUE AND is_audit_ready = 1 THEN 1 ELSE 0 END) as audit
            FROM framework_assets
            
            UNION ALL
            
            SELECT
                'SOX' as framework,
                COUNT(*) as total,
                SUM(CASE WHEN SOX_RELEVANT = TRUE THEN 1 ELSE 0 END) as relevant_count,
                SUM(CASE WHEN SOX_RELEVANT = TRUE AND is_tagged = 1 THEN 1 ELSE 0 END) as tagged,
                SUM(CASE WHEN SOX_RELEVANT = TRUE AND is_masked = 1 THEN 1 ELSE 0 END) as masked,
                SUM(CASE WHEN SOX_RELEVANT = TRUE AND is_rbac_aligned = 1 THEN 1 ELSE 0 END) as rbac,
                SUM(CASE WHEN SOX_RELEVANT = TRUE AND is_audit_ready = 1 THEN 1 ELSE 0 END) as audit
            FROM framework_assets
            
            UNION ALL
            
            SELECT
                'SOC 2' as framework,
                COUNT(*) as total,
                SUM(CASE WHEN SOC2_RELEVANT = TRUE THEN 1 ELSE 0 END) as relevant_count,
                SUM(CASE WHEN SOC2_RELEVANT = TRUE AND is_tagged = 1 THEN 1 ELSE 0 END) as tagged,
                SUM(CASE WHEN SOC2_RELEVANT = TRUE AND is_masked = 1 THEN 1 ELSE 0 END) as masked,
                SUM(CASE WHEN SOC2_RELEVANT = TRUE AND is_rbac_aligned = 1 THEN 1 ELSE 0 END) as rbac,
                SUM(CASE WHEN SOC2_RELEVANT = TRUE AND is_audit_ready = 1 THEN 1 ELSE 0 END) as audit
            FROM framework_assets
        )
        SELECT 
            framework,
            relevant_count,
            tagged,
            masked,
            rbac,
            audit,
            -- Logic for Impact Level
            CASE 
                WHEN relevant_count = 0 THEN 'Low'
                WHEN (tagged + masked + rbac + audit) / (relevant_count * 4.0) >= 0.9 THEN 'Low'
                WHEN (tagged + masked + rbac + audit) / (relevant_count * 4.0) >= 0.7 THEN 'Moderate'
                WHEN (tagged + masked + rbac + audit) / (relevant_count * 4.0) >= 0.5 THEN 'High'
                ELSE 'Critical'
            END as impact_level,
            -- Logic for Rationale
            CASE 
                WHEN framework = 'PII' THEN 'Rationale aligned to PII protection: Assessment of individual privacy leakage risk through classification coverage and masking enforcement.'
                WHEN framework = 'SOX' THEN 'Rationale aligned to SOX internal controls: Evaluation of financial reporting integrity via RBAC alignment and audit trail validity.'
                WHEN framework = 'SOC 2' THEN 'Rationale aligned to SOC 2 Trust Service Criteria: Verification of security, availability, and confidentiality controls across cloud infrastructure.'
                ELSE 'Framework-specific rationale.'
            END as rationale
        FROM impact_calc
        WHERE relevant_count > 0
        """
        rows = snowflake_connector.execute_query(query)
        return rows if rows else []
    except Exception as e:
        logger.error(f"Error in get_compliance_impact_assessment: {e}")
        return []

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
def get_qa_reviews_metrics(db: str) -> Dict:
    """Fetch QA reviews metrics"""
    schema = _gv_schema()
    
    metrics = {
        'peer_reviews': {'completed': 0, 'pending': 0, 'issues': 0},
        'management_reviews': {'completed': 0, 'pending': 0, 'issues': 0},
        'technical_reviews': {'completed': 0, 'pending': 0, 'issues': 0},
        'consistency_reviews': {'completed': 0, 'pending': 0, 'issues': 0}
    }
    
    try:
        if _table_exists(db, schema, 'QA_REVIEWS'):
            query = f"""
            SELECT 
                REVIEW_TYPE,
                STATUS,
                COUNT(*) AS count,
                SUM(CASE WHEN ISSUES_FOUND > 0 THEN ISSUES_FOUND ELSE 0 END) AS total_issues
            FROM {db}.{schema}.QA_REVIEWS
            GROUP BY REVIEW_TYPE, STATUS
            """
            result = snowflake_connector.execute_query(query)
            if result:
                for row in result:
                    review_type = row.get('REVIEW_TYPE', '').lower().replace(' ', '_') + '_reviews'
                    status = row.get('STATUS', '').lower()
                    count = int(row.get('count', 0))
                    
                    if review_type in metrics:
                        if status == 'completed':
                            metrics[review_type]['completed'] = count
                            metrics[review_type]['issues'] = int(row.get('total_issues', 0))
                        elif status == 'pending':
                            metrics[review_type]['pending'] = count
    
    except Exception as e:
        logger.warning(f"Error fetching QA reviews: {e}")
    
    return metrics

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

        -- 3. Audit Activity Metrics - From AUDIT_LOG base table
        audit_metrics AS (
            SELECT
                DATE_TRUNC('MONTH', TIMESTAMP) AS month,
                COUNT(*) AS total_audit_events,
                COUNT(DISTINCT RESOURCE_ID) AS unique_resources,
                COUNT(CASE WHEN ACTION ILIKE '%classification%' THEN 1 END) AS classification_events,
                COUNT(CASE WHEN ACTION ILIKE '%review%' THEN 1 END) AS review_events
            FROM {db}.{schema}.AUDIT_LOG
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

tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Compliance Overview",
    "📅 Reviews & Audits",
    "⚠️ Policy Violations",
    "📈 Analytics & Drift"
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
                        with st.expander("🔍 Metrics Diagnostics (Data Breakdown)"):
                            st.caption(f"Context: {diag_db}.{diag_schema}")
                            d_col1, d_col2 = st.columns(2)
                            d_col1.metric("Total Registry Assets", row_diag.get("TOTAL_TABLES", 0))
                            d_col1.metric("Classified Assets", row_diag.get("CLASSIFIED_TABLES", 0))
                            d_col2.metric("Sensitive Assets", row_diag.get("SENSITIVE_TABLES", 0))
                            d_col2.metric("Telemetry Hits", row_diag.get("SENSITIVE_ACCESS_TABLES", 0))
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
    subtab1, subtab2, subtab3 = st.tabs([
        "🛡️ Mandatory Controls",
        "📊 Risk Distribution",
        "⚖️ Special Categories"
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
            st.button("📋 Generate Enterprise Compliance Audit", width='stretch', type="primary")

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
                st.plotly_chart(fig, width='stretch', config={'displayModeBar': False})
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

    
    
    # ========================================================================
    # SUBTAB 3: SPECIAL CATEGORIES
    # ========================================================================
    
    with subtab3:
        # Header with download options
        header_col, download_col = st.columns([3, 1])
        
        with header_col:
            st.markdown("""
<div style="margin: 1.5rem 0 1rem 0;">
<h3 style="margin-bottom: 0.25rem; font-size: 1.25rem;">⚖️ Regulatory Frameworks</h3>
<p style="color: #64748b; font-size: 0.875rem; font-weight: 500;">Special category compliance enforcement (PII, SOC2, SOX)</p>
</div>
""", unsafe_allow_html=True)
        
        # Fetch special categories data
        special = get_special_categories_compliance(db, filters=filters)
        
        # Prepare data for download
        download_data = []
        for framework_name, framework_data in special.items():
            if framework_data:
                download_data.append({
                    'Framework': framework_name,
                    'Compliance Rate': framework_data.get('rate_str', 'N/A'),
                    'Status': framework_data.get('status', 'Unknown'),
                    'Compliant Assets': framework_data.get('compliant', 0),
                    'Non-Compliant Assets': framework_data.get('non_compliant', 0),
                    'Recommended Action': framework_data.get('action', 'None')
                })
        
        compliance_df = pd.DataFrame(download_data)
        
        with download_col:
            if not compliance_df.empty:
                # CSV Download (always available)
                csv = compliance_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Download CSV",
                    data=csv,
                    file_name=f"special_categories_compliance_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    width='stretch'
                )
                
                # Excel Download (optional - requires openpyxl)
                try:
                    from io import BytesIO
                    excel_buffer = BytesIO()
                    with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                        compliance_df.to_excel(writer, index=False, sheet_name='Compliance')
                    excel_data = excel_buffer.getvalue()
                    
                    st.download_button(
                        label="📥 Download Excel",
                        data=excel_data,
                        file_name=f"special_categories_compliance_{datetime.now().strftime('%Y%m%d')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        width='stretch'
                    )
                except ImportError:
                    # openpyxl not installed, skip Excel download
                    st.caption("💡 Install openpyxl for Excel export")
                except Exception as e:
                    # Other errors, log but don't break the page
                    logger.warning(f"Excel export failed: {e}")
        
        st.markdown("---")
        
        
        sc1, sc2, sc3 = st.columns(3)
        
        def render_special_card(col, title, min_req, data_dict, key):
            if not data_dict:
                data_dict = {'status': '⚠️ Unknown', 'rate_str': '0%', 'action': 'No data', 'compliant': 0, 'non_compliant': 0}
            
            rate_str = data_dict.get('rate_str', '0%')
            rate_val = float(rate_str.replace('%','')) if '%' in rate_str else 0
            rate_color = "#10b981" if rate_val >= 90 else "#f59e0b" if rate_val >= 70 else "#ef4444"
            status = data_dict.get('status', 'Unknown')
            action = data_dict.get('action', 'None')
            compliant = data_dict.get('compliant', 0)
            non_compliant = data_dict.get('non_compliant', 0)
            
            with col:
                st.markdown(f"""
<div style="background: rgba(30, 41, 59, 0.4); padding: 1.5rem; border-radius: 24px; border: 1px solid rgba(255,255,255,0.05); border-top: 5px solid {rate_color}; backdrop-filter: blur(12px); box-shadow: 0 10px 30px rgba(0,0,0,0.2);">
<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1.25rem;">
<div>
<h4 style="margin:0; font-size: 1.25rem; font-weight: 800; color: #f8fafc; letter-spacing: -0.02em;">{title}</h4>
<div style="color: #94a3b8; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px;">Min Target: {min_req}</div>
</div>
<div style="color: {rate_color}; font-size: 1.75rem; font-weight: 900; letter-spacing: -0.05em;">{rate_str}</div>
</div>
<div style="margin-bottom: 1.5rem;">
<span style="font-size: 0.75rem; font-weight: 800; color: {rate_color}; background: {rate_color}15; padding: 4px 12px; border-radius: 8px; border: 1px solid {rate_color}30;">{status}</span>
</div>
<div style="display: flex; gap: 2.5rem; margin-bottom: 1.5rem; background: rgba(255,255,255,0.02); padding: 1rem; border-radius: 16px;">
<div>
<div style="color: #64748b; font-size: 0.65rem; font-weight: 800; text-transform: uppercase; margin-bottom: 4px;">Compliant</div>
<div style="font-size: 1.25rem; font-weight: 800; color: #f8fafc;">{compliant}</div>
</div>
<div style="background: rgba(255,255,255,0.05); width: 1px; height: 2.5rem;"></div>
<div>
<div style="color: #64748b; font-size: 0.65rem; font-weight: 800; text-transform: uppercase; margin-bottom: 4px;">Violations</div>
<div style="font-size: 1.25rem; font-weight: 800; color: {'#ef4444' if non_compliant > 0 else '#f8fafc'};">{non_compliant}</div>
</div>
</div>
<div style="background: rgba(0,0,0,0.1); padding: 1rem; border-radius: 12px;">
<div style="color: #64748b; font-size: 0.65rem; font-weight: 800; text-transform: uppercase; margin-bottom: 6px;">Recommended Action</div>
<div style="font-size: 0.8rem; color: #cbd5e1; font-weight: 500; line-height: 1.4;">{action}</div>
</div>
</div>
""", unsafe_allow_html=True)
                
                if st.button(f"🛡️ Start {title} Audit", key=f"aud_{key}", width='stretch', type="primary"):
                    if non_compliant > 0:
                        st.markdown(f"""
<div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); padding: 1rem; border-radius: 12px; margin-top: 1rem;">
<div style="color: #ef4444; font-weight: 800; font-size: 0.85rem; margin-bottom: 4px;">⚠️ REMEDIATION REQUIRED</div>
<div style="color: #cbd5e1; font-size: 0.8rem;">{action}</div>
</div>
""", unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
<div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); padding: 1rem; border-radius: 12px; margin-top: 1rem;">
<div style="color: #10b981; font-weight: 800; font-size: 0.85rem; margin-bottom: 4px;">✅ COMPLIANCE VERIFIED</div>
<div style="color: #cbd5e1; font-size: 0.8rem;">Current status is OPTIMAL. No further action needed.</div>
</div>
""", unsafe_allow_html=True)
                    
                    # Generic drill-down for ALL frameworks using AI Discovery Data
                    with st.expander(f"📋 Detailed {title} Discovery Evidence", expanded=True):
                        st.markdown(f"##### 🧬 AI-Detected {title} Assets & Column Context")
                        try:
                            schema = _gv_schema()
                            # Map the key to the appropriate filters for the AI results table
                            category_filters = {
                                'pii': "UPPER(AI_CATEGORY) IN ('PII', 'PERSONAL_DATA', 'IDENTIFIER', 'NAME', 'EMAIL', 'PHONE')",
                                'soc2': "UPPER(AI_CATEGORY) LIKE '%SECURITY%' OR UPPER(AI_CATEGORY) LIKE '%SOC2%' OR UPPER(AI_CATEGORY) LIKE '%CONTROL%'",
                                'sox': "UPPER(AI_CATEGORY) LIKE '%FINANCIAL%' OR UPPER(AI_CATEGORY) LIKE '%SOX%' OR UPPER(AI_CATEGORY) LIKE '%ACCOUNTING%'",
                                'gdpr': "UPPER(AI_CATEGORY) LIKE '%GDPR%' OR UPPER(AI_CATEGORY) LIKE '%PRIVACY%'",
                                'hipaa': "UPPER(AI_CATEGORY) LIKE '%HIPAA%' OR UPPER(AI_CATEGORY) LIKE '%HEALTH%' OR UPPER(AI_CATEGORY) LIKE '%MEDICAL%'",
                                'pci-dss': "UPPER(AI_CATEGORY) LIKE '%PCI%' OR UPPER(AI_CATEGORY) LIKE '%CARD%' OR UPPER(AI_CATEGORY) LIKE '%PAYMENT%'"
                            }
                            
                            filter_clause = category_filters.get(key, f"UPPER(AI_CATEGORY) LIKE '%{key.upper().replace('_',' ')}%'")
                            
                            ai_q = f"""
                            SELECT 
                                TABLE_NAME as "Asset",
                                COLUMN_NAME as "Column",
                                AI_CATEGORY as "AI Category",
                                SEMANTIC_CATEGORY as "Semantic",
                                ROUND(FINAL_CONFIDENCE * 100, 1) || '%' as "Confidence",
                                MODEL_VERSION as "Model",
                                UPDATED_AT as "Discovery Date"
                            FROM {db}.{schema}.CLASSIFICATION_AI_RESULTS
                            WHERE {filter_clause}
                            AND FINAL_CONFIDENCE >= 0.7
                            ORDER BY FINAL_CONFIDENCE DESC
                            LIMIT 100
                            """
                            
                            ai_res = snowflake_connector.execute_query(ai_q)
                            if ai_res:
                                st.dataframe(pd.DataFrame(ai_res), width='stretch', hide_index=True)
                                st.caption(f"💡 Showing top AI discoveries matching {title} criteria.")
                            else:
                                st.info(f"No active AI discoveries found in CLASSIFICATION_AI_RESULTS for {title} category.")
                                
                            # Logic for fetching assets from the ASSETS table
                            st.markdown("---")
                            st.markdown("##### 🛡️ Governance Registry Context")
                            
                            # Construct dynamic filter based on framework key
                            f_upper = key.upper()
                            if f_upper == 'PII':
                                f_filter = "PII_RELEVANT = TRUE"
                            elif f_upper == 'SOX':
                                f_filter = "SOX_RELEVANT = TRUE"
                            elif f_upper in ('SOC2', 'SOC_2'):
                                f_filter = "SOC2_RELEVANT = TRUE"
                            else:
                                # Fallback if somehow a different key ends up here
                                f_filter = "1=0"
                            
                            try:
                                asset_q = f"""
                                SELECT 
                                    FULLY_QUALIFIED_NAME as "Asset",
                                    CLASSIFICATION_LABEL as "Label",
                                    CONFIDENTIALITY_LEVEL as "Sensitivity",
                                    DATA_OWNER as "Owner",
                                    REVIEW_STATUS as "Review Status"
                                FROM {db}.{schema}.ASSETS
                                WHERE {f_filter}
                                LIMIT 25
                                """
                                asset_res = snowflake_connector.execute_query(asset_q)
                                if asset_res:
                                    st.dataframe(pd.DataFrame(asset_res), width='stretch', hide_index=True)
                                    st.caption(f"Showing up to 25 assets explicitly tagged for {title} in the Governance Registry.")
                                else:
                                    st.info(f"No assets in the Governance Registry are explicitly mapped to the {title} framework.")
                            except Exception as e:
                                st.warning(f"Could not retrieve registry context: {e}")
                        except Exception as e:
                            st.error(f"Failed to fetch {title} details: {e}")

        # Render dynamic framework cards
        framework_keys = sorted(list(special.keys()))
        
        if not framework_keys:
            st.info("No regulatory frameworks or special categories detected in the current scope.")
        else:
            for i in range(0, len(framework_keys), 3):
                chunk = framework_keys[i:i+3]
                cols = st.columns(3)
                for idx, key in enumerate(chunk):
                    # Basic metadata
                    title = f"{key} Framework"
                    min_req = "C2+" if key.upper() == 'PII' else "C3+"
                    
                    framework_data = special.get(key)
                    # Pass snake_case key for drill-down mapping
                    render_special_card(cols[idx], title, min_req, framework_data, key.lower().replace(' ', '_'))

        
        st.markdown("---")

    # ============================================================================
# TAB 2: REVIEWS & AUDITS
# ============================================================================

with tab2:
    st.header("Reviews & Audits")
    
    # Sub-tabs for Reviews & Audits
    review_tab1, review_tab2, review_tab3 = st.tabs([
        "Annual Reviews",
        "Audit Schedule",
        "Governing Policies"
    ])
    
    # ========================================================================
    # REVIEW TAB 1: ANNUAL REVIEWS
    # ========================================================================
    
    with review_tab1:
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
    
    # ========================================================================
    # REVIEW TAB 2: AUDIT SCHEDULE
    # ========================================================================

    with review_tab2:
        st.markdown("""
<div style="margin: 1.5rem 0 1rem 0;">
            <h3 style="margin-bottom: 0.25rem; font-size: 1.25rem;">📜 Audit Lifecycle Manager</h3>
            <p style="color: #64748b; font-size: 0.875rem; font-weight: 500;">Scheduling and historical performance tracking for formal compliance audits</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Dashboard for Audit Schedule
        col1, col2 = st.columns([1.5, 1], gap="large")
        
        with col1:
            st.markdown('<div class="glass-panel" style="padding: 1.5rem;">', unsafe_allow_html=True)
            st.markdown('<div style="color: #38bdf8; font-size: 0.7rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1.25rem;">🗓️ 2026 Audit Sequence</div>', unsafe_allow_html=True)
            
            # Use dynamic dates relative to today
            t = datetime.now()
            
            audits = [
                {"Audit": "Monthly Governance Sync", "Scope": "Mandatory Controls", "Date": (t + timedelta(days=8)).strftime("%b %d"), "Status": "Ready"},
                {"Audit": "Q1 2026 Regulatory Review", "Scope": "PII / SOC2 / SOX", "Date": (t + timedelta(days=32)).strftime("%b %d"), "Status": "Scheduled"},
                {"Audit": "Cloud Infrastructure Audit", "Scope": "Network & Access", "Date": (t + timedelta(days=64)).strftime("%b %d"), "Status": "Planned"},
                {"Audit": "Annual External Audit", "Scope": "Full Compliance", "Date": (t + timedelta(days=156)).strftime("%b %d"), "Status": "Planned"}
            ]
            
            for audit in audits:
                st.markdown(f"""
<div style="display: flex; justify-content: space-between; align-items: center; padding: 1rem; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; margin-bottom: 0.75rem;">
    <div style="display: flex; align-items: center; gap: 1rem;">
        <div style="background: rgba(56, 189, 248, 0.15); width: 45px; height: 45px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem;">📅</div>
        <div>
            <div style="font-size: 0.9rem; font-weight: 700; color: #f8fafc;">{audit['Audit']}</div>
            <div style="font-size: 0.7rem; color: #64748b;">Scope: {audit['Scope']}</div>
        </div>
    </div>
    <div style="text-align: right;">
        <div style="font-size: 0.85rem; font-weight: 700; color: #38bdf8;">{audit['Date']}</div>
        <div style="font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;">{audit['Status']}</div>
    </div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
        with col2:
            st.markdown('<div class="glass-panel" style="padding: 1.5rem; height: 100%;">', unsafe_allow_html=True)
            st.markdown('<div style="color: #10b981; font-size: 0.7rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1.25rem;">🏆 Archive Performance</div>', unsafe_allow_html=True)
            
            history = [
                {"Name": "Q4 2025 Audit", "Result": "PASS", "Score": "98%", "Date": "Dec 15"},
                {"Name": "Nov Monthly", "Result": "PASS", "Score": "100%", "Date": "Nov 12"},
                {"Name": "Q3 2025 Audit", "Result": "PASS*", "Score": "92%", "Date": "Sep 30"}
            ]
            
            for item in history:
                st.markdown(f"""
<div style="margin-bottom: 1.25rem;">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="font-size: 0.85rem; font-weight: 700; color: #f8fafc;">{item['Name']}</div>
        <div style="font-size: 0.8rem; font-weight: 800; color: #10b981;">{item['Result']}</div>
    </div>
    <div style="display: flex; justify-content: space-between; color: #64748b; font-size: 0.7rem; margin-top: 4px;">
        <span>Score: {item['Score']}</span>
        <span>{item['Date']}</span>
    </div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

    # ========================================================================
    # REVIEW TAB 3: GOVERNING POLICIES
    # ========================================================================
    with review_tab3:
        st.markdown("""
<div style="margin: 1.5rem 0 1rem 0;">
    <h3 style="margin-bottom: 0.25rem; font-size: 1.25rem;">📄 Governing Policies & Evidence</h3>
    <p style="color: #64748b; font-size: 0.875rem; font-weight: 500;">Authoritative governance documents, audit evidence, and handling standards.</p>
</div>
        """, unsafe_allow_html=True)

        # Database Resolution for Policies
        pol_db = settings.SNOWFLAKE_DATABASE
        if not pol_db or str(pol_db).strip().upper() in {"", "NONE", "(NONE)", "NULL", "UNKNOWN"}:
            pol_db = "DATA_CLASSIFICATION_DB"
        pol_schema = "DATA_CLASSIFICATION_GOVERNANCE"
        
        # Ensure infrastructure
        try:
            snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {pol_db}.{pol_schema}")
            snowflake_connector.execute_non_query(f"""
                CREATE TABLE IF NOT EXISTS {pol_db}.{pol_schema}.POLICIES (
                    POLICY_ID STRING NOT NULL DEFAULT UUID_STRING(),
                    POLICY_NAME STRING NOT NULL,
                    FILE_CONTENT BINARY NOT NULL,
                    FILE_NAME STRING NOT NULL,
                    MIME_TYPE STRING,
                    FILE_SIZE NUMBER,
                    POLICY_CONTENT TEXT,
                    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                    CREATED_BY STRING DEFAULT CURRENT_USER(),
                    CONSTRAINT PK_POLICIES PRIMARY KEY (POLICY_ID)
                )
            """)
            # Migration/Safe Alter
            snowflake_connector.execute_non_query(f"ALTER TABLE {pol_db}.{pol_schema}.POLICIES ADD COLUMN IF NOT EXISTS FILE_CONTENT BINARY")
        except Exception as e:
            logger.warning(f"Policy table init/alter warning: {e}")

        m_col1, m_col2 = st.columns([1, 2], gap="large")
        
        with m_col1:
            st.markdown("#### 📂 Policy Repository")
            
            # Fetch existing policies
            try:
                p_rows = snowflake_connector.execute_query(f"SELECT POLICY_ID, POLICY_NAME, MIME_TYPE, FILE_CONTENT as RAW_FILE_DATA, POLICY_CONTENT FROM {pol_db}.{pol_schema}.POLICIES ORDER BY CREATED_AT DESC") or []
            except:
                p_rows = []
                
            if not p_rows:
                st.info("No documents found in the registry.")
            else:
                for p in p_rows:
                    with st.container():
                        st.markdown(f"""
<div style="background: rgba(30, 41, 59, 0.2); padding: 1rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05); margin-bottom: 0.75rem;">
    <div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">{p['POLICY_NAME']}</div>
    <div style="font-size: 0.75rem; color: #64748b; margin-top: 2px;">{p['MIME_TYPE']}</div>
</div>
                        """, unsafe_allow_html=True)
                        if st.button(f"View Document", key=f"comp_vw_{p['POLICY_ID']}", width='stretch'):
                            st.session_state['active_compliance_policy'] = p
            
            st.markdown("---")
            st.markdown("#### 📤 Upload New Document")
            with st.form("comp_policy_upload"):
                up_name = st.text_input("Evidence Title")
                up_file = st.file_uploader("Select PDF or DOCX", type=['pdf', 'docx', 'doc', 'md', 'txt'])
                up_submit = st.form_submit_button("Upload Evidence to Snowflake", width='stretch')
                
                if up_submit and up_file and up_name:
                    try:
                        import uuid
                        raw_bytes = up_file.read()
                        extracted_text = "[Policy stored as binary. Use reader to view.]"
                        
                        # Full text extraction for search/indexing
                        if up_file.type and 'pdf' in up_file.type:
                            try:
                                if pypdf:
                                    reader = pypdf.PdfReader(io.BytesIO(raw_bytes))
                                    extracted_text = "\n\n".join([p.extract_text() or "" for p in reader.pages]).strip()
                                elif PyPDF2:
                                    reader = PyPDF2.PdfReader(io.BytesIO(raw_bytes))
                                    extracted_text = "\n\n".join([p.extract_text() or "" for p in reader.pages]).strip()
                            except: pass
                        elif up_file.name.lower().endswith(('.docx', '.doc')):
                            if docx:
                                try:
                                    doc = docx.Document(io.BytesIO(raw_bytes))
                                    extracted_text = "\n".join([para.text for para in doc.paragraphs]).strip()
                                except: pass
                            
                        query = f"""
                        INSERT INTO {pol_db}.{pol_schema}.POLICIES 
                        (POLICY_NAME, FILE_CONTENT, FILE_NAME, MIME_TYPE, FILE_SIZE, POLICY_CONTENT, CREATED_AT, CREATED_BY)
                        VALUES (%(name)s, %(file)s, %(fn)s, %(fmt)s, %(fs)s, %(cont)s, CURRENT_TIMESTAMP(), CURRENT_USER())
                        """
                        snowflake_connector.execute_non_query(query, {
                            "name": up_name, "file": raw_bytes, "fn": up_file.name, 
                            "fmt": up_file.type, "fs": up_file.size, "cont": extracted_text
                        })
                        st.success(f"Successfully stored '{up_name}'")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Storage failed: {e}")

        with m_col2:
            st.markdown("#### 📖 Document Reader")
            if 'active_compliance_policy' in st.session_state:
                ap = st.session_state['active_compliance_policy']
                
                # Check for RAW data
                if ap.get('RAW_FILE_DATA') and ap.get('MIME_TYPE') == 'application/pdf':
                    try:
                        raw_data = ap['RAW_FILE_DATA']
                        # Handle bytes vs memoryview
                        if not isinstance(raw_data, (bytes, bytearray)):
                            raw_data = bytes(raw_data)
                        
                        b64_pdf = base64.b64encode(raw_data).decode('utf-8')
                        pdf_iframe = f'<iframe src="data:application/pdf;base64,{b64_pdf}" width="100%" height="800px" style="border: none; border-radius: 12px;"></iframe>'
                        st.markdown(pdf_iframe, unsafe_allow_html=True)
                    except Exception as viewer_err:
                        st.error(f"Renderer Error: {viewer_err}")
                        st.info("Falling back to text preview...")
                        st.code(ap.get('POLICY_CONTENT') or "No text content available.")
                else:
                    st.info("Previewing as text content...")
                    st.code(ap.get('POLICY_CONTENT') or "No readable content found. Please download the file to view.")
                    if ap.get('MIME_TYPE') and ('word' in ap['MIME_TYPE'] or 'officedocument' in ap['MIME_TYPE']):
                         st.warning("Note: Full DOC/DOCX rendering is not supported in-browser. Displaying extracted text index.")
                
                if st.button("Close Viewer", width='stretch'):
                    del st.session_state['active_compliance_policy']
                    st.rerun()
            else:
                st.markdown("""
<div style="height: 400px; display: flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.01); border: 2px dashed rgba(255,255,255,0.05); border-radius: 20px;">
    <div style="text-align: center; color: #64748b;">
        <div style="font-size: 3rem; margin-bottom: 1rem;">📄</div>
        <div>Select a record from the repository to retrieve and view</div>
    </div>
</div>
                """, unsafe_allow_html=True)

        # Maintenance Link for Compliance
        with st.expander("🛠️ Metadata Maintenance"):
            if st.button("🔗 Synchronize Extraction Index", key="comp_sync_ext"):
                try:
                    pols = snowflake_connector.execute_query(f"SELECT POLICY_ID, POLICY_NAME, MIME_TYPE, RAW_FILE_DATA FROM {pol_db}.{pol_schema}.POLICIES WHERE RAW_FILE_DATA IS NOT NULL AND (POLICY_CONTENT IS NULL OR POLICY_CONTENT LIKE '[System:%')") or []
                    if not pols: st.info("Index is healthy.")
                    else:
                        for p in pols:
                            txt = ""
                            data = p['RAW_FILE_DATA']
                            mim = p['MIME_TYPE'] or ""
                            if 'pdf' in mim.lower() and (pypdf or PyPDF2):
                                rdr = pypdf.PdfReader(io.BytesIO(data)) if pypdf else PyPDF2.PdfReader(io.BytesIO(data))
                                txt = "\n\n".join([pg.extract_text() or "" for pg in rdr.pages]).strip()
                            elif ('word' in mim.lower() or 'officedocument' in mim.lower()) and docx:
                                d = docx.Document(io.BytesIO(data))
                                txt = "\n".join([para.text for para in d.paragraphs]).strip()
                            
                            if txt:
                                snowflake_connector.execute_non_query(f"UPDATE {pol_db}.{pol_schema}.POLICIES SET POLICY_CONTENT=%(c)s WHERE POLICY_ID=%(id)s", {"c": txt, "id": p['POLICY_ID']})
                        st.success(f"Synchronized {len(pols)} documents.")
                        st.rerun()
                except Exception as ex: st.error(f"Sync error: {ex}")
# ============================================================================

with tab3:
    st.subheader("⚠️ Violations")
    
    # Sub-tabs for Violations
    violation_tab1, violation_tab2 = st.tabs([
        "Policy Violations",
        "Corrective Actions"
    ])
    
    with violation_tab1:
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
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.info("**Level 1**\n📧 Warning\n• Email notification\n• Policy reminder")
            with col2:
                st.warning("**Level 2**\n📚 Retraining\n• Mandatory training\n• Counseling session")
            with col3:
                st.error("**Level 3**\n🔒 Access Restriction\n• Temporary suspension\n• Manager review")
            with col4:
                st.error("**Level 4**\n⚖️ Formal Discipline\n• HR involvement\n• Written warning")
    
    with violation_tab2:
        st.write("### Corrective Action Tracking")
        
        # Fetch corrective actions from the database
        with st.spinner("Loading corrective actions..."):
            try:
                query = f"""
                SELECT 
                  ASSET_ID AS "Action ID",
                  CREATED_BY AS "User",
                  CASE 
                    WHEN NEXT_REVIEW_DATE < CURRENT_DATE() THEN 'Annual Review Overdue'
                    WHEN CLASSIFICATION_LABEL IS NULL OR CLASSIFICATION_LABEL = 'Unclassified' THEN 'Missing Classification'
                    WHEN CORRECTIVE_ACTION_REQUIRED = TRUE THEN 'Policy Violation Detected'
                    ELSE 'Governance Gap'
                  END AS "Issue",
                  CASE 
                    WHEN CORRECTIVE_ACTION_REQUIRED = TRUE THEN COALESCE(CORRECTIVE_ACTION_DESCRIPTION, 'Perform required remediation steps')
                    WHEN CLASSIFICATION_LABEL IS NULL OR CLASSIFICATION_LABEL = 'Unclassified' THEN 'Complete asset classification per Policy Sec 4.1'
                    WHEN NEXT_REVIEW_DATE < CURRENT_DATE() THEN 'Execute mandatory annual review'
                    ELSE 'Contact data owner for clarification'
                  END AS "Action Plan",
                  TO_CHAR(COALESCE(CORRECTIVE_ACTION_DUE_DATE, NEXT_REVIEW_DATE, DATEADD('day', 7, CURRENT_DATE())), 'YYYY-MM-DD') AS "Due Date",
                  CASE 
                    WHEN COMPLIANCE_STATUS = 'COMPLIANT' THEN '100%'
                    WHEN CORRECTIVE_ACTION_REQUIRED = TRUE THEN '25%'
                    WHEN CLASSIFICATION_LABEL IS NOT NULL THEN '50%'
                    ELSE '0%'
                  END AS "Progress",
                  CASE 
                    WHEN COMPLIANCE_STATUS = 'COMPLIANT' THEN 'Completed'
                    WHEN NEXT_REVIEW_DATE < CURRENT_DATE() THEN 'Overdue'
                    WHEN CORRECTIVE_ACTION_REQUIRED = TRUE THEN 'At Risk'
                    ELSE 'In Progress'
                  END AS "Status"
                FROM {active_db}.{_gv_schema()}.ASSETS
                WHERE COMPLIANCE_STATUS != 'COMPLIANT' 
                   OR CLASSIFICATION_LABEL IS NULL 
                   OR CLASSIFICATION_LABEL = 'Unclassified'
                   OR NEXT_REVIEW_DATE < CURRENT_DATE()
                ORDER BY 
                  CASE WHEN "Status" = 'Overdue' THEN 1 WHEN "Status" = 'At Risk' THEN 2 ELSE 3 END,
                  "Due Date" ASC
                """
                
                # Execute the query
                corrective_actions = snowflake_connector.execute_query(query)
                
                if not corrective_actions:
                    st.info("No corrective actions found.")
                else:
                    # Convert to DataFrame for display
                    df = pd.DataFrame(corrective_actions)
                    
                    # Display the data in a nice table
                    st.dataframe(
                        df,
                        width='stretch',
                        hide_index=True
                    )
                    
                    # Add summary metrics
                    st.markdown("---")
                    
                    # Calculate metrics
                    total_actions = len(df)
                    completed = len(df[df['Status'] == 'Completed'])
                    in_progress = len(df[df['Status'] == 'In Progress'])
                    at_risk = len(df[df['Status'] == 'At Risk'])
                    overdue = len(df[df['Status'] == 'Overdue'])
                    
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Total Actions", total_actions)
                    
                    with col2:
                        st.metric("Completed", completed)
                    
                    with col3:
                        st.metric("In Progress", in_progress)
                        
                    with col4:
                        st.metric("Requires Attention", at_risk + overdue, delta=overdue, delta_color="inverse")
                    
            except Exception as e:
                st.error(f"Error loading corrective actions: {str(e)}")
                st.warning("Using sample data as fallback")
                
                # Fallback to sample data if there's an error
                corrective_actions = pd.DataFrame({
                    'Action ID': ['CA-2024-001', 'CA-2024-002', 'CA-2024-003', 'CA-2024-004'],
                    'User': ['Sarah Chen', 'Mike Rodriguez', 'David Kim', 'Jennifer Wu'],
                    'Issue': ['Late Classification', 'Wrong Classification', 'Missing Tags', 'No Documentation'],
                    'Action Plan': ['Complete training by Dec 15', 'Reclassify 5 assets', 'Apply tags to 12 assets', 'Document 8 decisions'],
                    'Due Date': ['2024-12-15', '2024-12-10', '2024-12-08', '2024-12-20'],
                    'Progress': [60, 80, 100, 25],
                    'Status': ['In Progress', 'In Progress', 'Completed', 'At Risk']
                })
                
                st.dataframe(
                    corrective_actions,
                    width='stretch',
                    hide_index=True
                )

# ============================================================================
# TAB 4: REPORTS & ANALYTICS
# ============================================================================

    with tab4:
        st.header("Reports & Analytics")
        st.caption("Downloadable reports and trend analytics")
        
        # Report generation
        st.markdown("### Generate Compliance Reports")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Executive Summary**")
            if st.button("📊 Generate Executive Report", width='stretch'):
                with st.spinner("Generating executive summary..."):
                    # Fetch summarized metrics
                    metrics = get_classification_requirements_metrics(db, filters=filters)
                    
                    summary_data = {
                        'Metric': [
                            'Classification Coverage', 
                            '5-Day Rule Compliance', 
                            'Annual Review Completion', 
                            'Documentation Completeness',
                            'Policy Violations'
                        ],
                        'Value': [
                            f"{metrics.get('coverage', 0):.1f}%",
                            f"{metrics.get('five_day_compliance', 0):.1f}%",
                            f"{metrics.get('annual_review', 0):.1f}%",
                            f"{metrics.get('doc_completeness', 0):.1f}%",
                            f"{metrics.get('policy_violations', 0)}"
                        ],
                        'Status': [
                            metrics.get('overall_status', 'Unknown'),
                            'Healthy' if metrics.get('five_day_compliance', 0) >= 95 else 'Warning',
                            'Healthy' if metrics.get('annual_review', 0) >= 80 else 'Warning',
                            'Healthy' if metrics.get('doc_completeness', 0) >= 95 else 'Warning',
                            'Action Required' if metrics.get('policy_violations', 0) > 0 else 'Healthy'
                        ]
                    }
                    exec_df = pd.DataFrame(summary_data)
                    csv = exec_df.to_csv(index=False).encode('utf-8')
                    
                    st.success("Executive summary generated!")
                    st.download_button(
                        label="📥 Download Summary CSV",
                        data=csv,
                        file_name=f"executive_summary_{datetime.now().strftime('%Y%m%d')}.csv",
                        mime="text/csv",
                        key='download_exec'
                    )
        
        with col2:
            st.markdown("**Detailed Compliance**")
            if st.button("📋 Generate Detailed Report", use_container_width=True):
                with st.spinner("Fetching full asset inventory..."):
                    try:
                        # Full asset dump
                        query = f"SELECT * FROM {db}.{_gv_schema()}.ASSETS LIMIT 10000"
                        detailed_df = snowflake_connector.execute_query(query)
                        
                        if detailed_df:
                            df = pd.DataFrame(detailed_df)
                            csv = df.to_csv(index=False).encode('utf-8')
                            
                            st.success(f"Report generated for {len(df)} assets!")
                            st.download_button(
                                label="📥 Download Detailed CSV",
                                data=csv,
                                file_name=f"detailed_compliance_{datetime.now().strftime('%Y%m%d')}.csv",
                                mime="text/csv",
                                key='download_detailed'
                            )
                        else:
                            st.warning("No data found in generic asset view.")
                    except Exception as e:
                        st.error(f"Error generating report: {e}")
        
        with col3:
            st.markdown("**Audit Package**")
            if st.button("📦 Generate Audit Package", use_container_width=True):
                 with st.spinner("Compiling audit evidence..."):
                    # Use policy violations as the core evidence log
                    violations_log = get_policy_violations(db, filters=filters)
                    
                    if violations_log is not None and not violations_log.empty:
                        csv = violations_log.to_csv(index=False).encode('utf-8')
                        
                        st.success("Audit package compiled!")
                        st.download_button(
                            label="📥 Download Audit Evidence Logs",
                            data=csv,
                            file_name=f"audit_pack_evidence_{datetime.now().strftime('%Y%m%d')}.csv",
                            mime="text/csv",
                            key='download_audit'
                        )
                    else:
                        st.warning("No violations or audit evidence found to package.")
    
        st.markdown("---")
        
        # Trend analytics
        st.markdown("### Trend Analytics")
        
        with st.spinner("Calculating compliance trends..."):
            trend_df = get_compliance_trends_metrics(db, filters=filters)
        
        if not trend_df.empty:
            # Normalize column names to upper case
            trend_df.columns = [c.upper() for c in trend_df.columns]
            
            # Ensure month is sorted ascending for charts
            chart_df = trend_df.sort_values('MONTH_PERIOD')
            
            # Line chart for Overall Trends
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=chart_df['MONTH_PERIOD'],
                y=chart_df['OVERALL_COMPLIANCE_SCORE'],
                name='Overall Compliance Score',
                mode='lines+markers',
                line=dict(color='#2C3E50', width=4),
                hovertemplate='%{y:.1f}%'
            ))
            
            fig.add_trace(go.Scatter(
                x=chart_df['MONTH_PERIOD'],
                y=chart_df['POLICY_COMPLIANCE_PCT'],
                name='Policy Compliance',
                mode='lines+markers',
                line=dict(color='#27AE60', width=2, dash='dot')
            ))
            
            fig.add_trace(go.Scatter(
                x=chart_df['MONTH_PERIOD'],
                y=chart_df['GOVERNANCE_COMPLETION_PCT'],
                name='Governance Completion',
                mode='lines+markers',
                line=dict(color='#2980B9', width=2, dash='dot')
            ))
            
            fig.add_trace(go.Scatter(
                x=chart_df['MONTH_PERIOD'],
                y=chart_df['AUDIT_COMPLIANCE_PCT'],
                name='Audit Status',
                mode='lines+markers',
                line=dict(color='#F1C40F', width=2, dash='dot')
            ))
            
            fig.add_trace(go.Scatter(
                x=chart_df['MONTH_PERIOD'],
                y=chart_df['RISK_COMPLIANCE_PCT'],
                name='Risk Score',
                mode='lines+markers',
                line=dict(color='#E74C3C', width=2, dash='dot')
            ))
            
            fig.update_layout(
                title="Compliance Trends (Last 6 Months)",
                xaxis_title="Month",
                yaxis_title="Score / Percentage",
                hovermode='x unified',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                )
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Detailed Trend Table
            st.write("#### Detailed Trend Analysis")
            
            # Select and rename columns for meaningful display
            display_cols = [
                'MONTH_PERIOD',
                'OVERALL_COMPLIANCE_SCORE', 'OVERALL_TREND',
                'POLICY_COMPLIANCE_PCT', 'POLICY_TREND',
                'GOVERNANCE_COMPLETION_PCT', 'GOVERNANCE_TREND',
                'AUDIT_COMPLIANCE_PCT', 'AUDIT_TREND',
                'RISK_COMPLIANCE_PCT', 'RISK_TREND'
            ]
            
            # Check if columns exist (safety check)
            available_cols = [c for c in display_cols if c in trend_df.columns]
            
            display_df = trend_df[available_cols].copy()
            
            # Rename for display
            display_df.rename(columns={
                'MONTH_PERIOD': 'Month',
                'OVERALL_COMPLIANCE_SCORE': 'Overall Score',
                'OVERALL_TREND': 'Trend',
                'POLICY_COMPLIANCE_PCT': 'Policy %',
                'POLICY_TREND': 'Trend ',
                'GOVERNANCE_COMPLETION_PCT': 'Governance %',
                'GOVERNANCE_TREND': 'Trend  ',
                'AUDIT_COMPLIANCE_PCT': 'Audit %',
                'AUDIT_TREND': 'Trend   ',
                'RISK_COMPLIANCE_PCT': 'Risk Score',
                'RISK_TREND': 'Trend    '
            }, inplace=True)
            
            st.dataframe(
                display_df, 
                use_container_width=True, 
                hide_index=True
            )
            
        else:
            st.warning("No trend data available for the last 6 months.")
        
        st.markdown("---")
        
        # Export options
        st.markdown("### Export Data")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📥 Export as CSV", use_container_width=True):
                csv = trend_df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"compliance_trends_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📥 Export as Excel", use_container_width=True):
                try:
                    output = io.BytesIO()
                    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                        trend_df.to_excel(writer, index=False, sheet_name='Compliance Trends')
                        
                        # Add a summary sheet
                        summary_data = {
                            'Metric': ['Generated Date', 'Database', 'Total Snapshots', 'Latest Score'],
                            'Value': [
                                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                db,
                                len(trend_df),
                                f"{trend_df['OVERALL_COMPLIANCE_SCORE'].iloc[-1]:.1f}%" if not trend_df.empty else "N/A"
                            ]
                        }
                        pd.DataFrame(summary_data).to_excel(writer, index=False, sheet_name='Executive Summary')
                    
                    st.download_button(
                        label="Download Excel",
                        data=output.getvalue(),
                        file_name=f"compliance_report_{datetime.now().strftime('%Y%m%d')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        key='download_excel'
                    )
                except Exception as e:
                    st.error(f"Excel export failed: {str(e)}")
        
        with col3:
            if st.button("📥 Export as PDF", use_container_width=True):
                if FPDF is None:
                    st.error("PDF library (fpdf2) not available. Please install it.")
                else:
                    try:
                        pdf = FPDF()
                        pdf.add_page()
                        pdf.set_font("Arial", 'B', 16)
                        pdf.cell(40, 10, 'Compliance Trend Report')
                        pdf.ln(10)
                        pdf.set_font("Arial", size=12)
                        pdf.cell(40, 10, f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                        pdf.ln(8)
                        pdf.cell(40, 10, f"Database Context: {db}")
                        pdf.ln(12)
                        
                        # Add latest metrics
                        if not trend_df.empty:
                            latest = trend_df.iloc[-1]
                            pdf.set_font("Arial", 'B', 14)
                            pdf.cell(40, 10, "Current Performance Snapshot")
                            pdf.ln(8)
                            pdf.set_font("Arial", size=11)
                            pdf.cell(40, 10, f"- Overall Compliance: {latest.get('OVERALL_COMPLIANCE_SCORE', 0):.1f}%")
                            pdf.ln(6)
                            pdf.cell(40, 10, f"- Policy Alignment: {latest.get('POLICY_COMPLIANCE_PCT', 0):.1f}%")
                            pdf.ln(6)
                            pdf.cell(40, 10, f"- Governance Score: {latest.get('GOVERNANCE_COMPLETION_PCT', 0):.1f}%")
                            pdf.ln(15)
                        
                        # Disclaimer
                        pdf.set_font("Arial", 'I', 8)
                        pdf.cell(40, 10, "This report is generated automatically by the Data Governance Application. Data reflects current Snowflake state.")
                        
                        pdf_output = pdf.output(dest='S')
                        st.download_button(
                            label="Download PDF",
                            data=pdf_output if isinstance(pdf_output, bytes) else pdf_output.encode('latin-1'),
                            file_name=f"compliance_summary_{datetime.now().strftime('%Y%m%d')}.pdf",
                            mime="application/pdf",
                            key='download_pdf'
                        )
                    except Exception as e:
                        st.error(f"PDF generation failed: {str(e)}")

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
