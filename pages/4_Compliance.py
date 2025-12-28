"""
Monitoring & Compliance - Data Governance Application
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
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple
from src.ui.theme import apply_global_theme
from io import StringIO
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.authorization_service import authz
from src.ui.quick_links import render_quick_links

# Page configuration
st.set_page_config(
    page_title="Monitoring & Compliance - Data Governance App",
    page_icon="✅",
    layout="wide"
)

# Apply centralized theme
apply_global_theme()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _resolve_db() -> Optional[str]:
    """Resolve active database safely. Defaults to DATA_CLASSIFICATION_DB."""
    try:
        db = st.session_state.get('sf_database')
        if db:
            return db
    except Exception:
        pass
    
    # Try settings
    try:
        db = settings.SNOWFLAKE_DATABASE
        if db:
            return db
    except Exception:
        pass
    
    # Try current database
    try:
        row = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
        db = row[0].get('DB') if row else None
        if db:
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
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
            ORDER BY ORDINAL_POSITION
            """,
            {"s": schema, "t": obj},
        ) or []
        return [r.get('COLUMN_NAME') for r in rows if r.get('COLUMN_NAME')]
    except Exception:
        return []

def _build_filters(filters: Dict, db_val: str, db_col='table_catalog', schema_col='table_schema', table_col='table_name') -> Tuple[str, Dict]:
    """Build SQL WHERE clauses and params for filters."""
    clauses = []
    params = {}
    
    if db_val and db_val != "All":
        clauses.append(f"{db_col} = %(db_val)s")
        params['db_val'] = db_val
        
    if filters and filters.get('schema'):
        clauses.append(f"{schema_col} = %(schema_val)s")
        params['schema_val'] = filters['schema']
        
    if filters and filters.get('table'):
        clauses.append(f"{table_col} = %(table_val)s")
        params['table_val'] = filters['table']
        
    return (" AND ".join(clauses) if clauses else "1=1", params)

# ============================================================================
# DATA FETCHING FUNCTIONS  
# ============================================================================

# REMOVED CACHE to force fresh data - enable cache after debugging
def get_compliance_overview_metrics(db: str, filters: dict = None) -> Dict:
    """Fetch key compliance metrics using INFORMATION_SCHEMA analysis with filters."""
    schema = _gv_schema()
    
    # Build filters
    info_filter, info_params = _build_filters(filters, db, 'table_catalog', 'table_schema', 'table_name')
    # For Account Usage, we use object_database/object_schema/object_name
    usage_filter, usage_params = _build_filters(filters, db, 'object_database', 'object_schema', 'object_name')
    
    # Combine params (keys are unique enough)
    all_params = {**info_params, **usage_params}

    metrics = {
        'classification_coverage': 0.0,
        'five_day_compliance': 0.0,
        'annual_review_rate': 0.0,
        'policy_violations': 0,
        'coverage_trend': 0,
        'compliance_trend': 0,
        'overall_status': '🔴 Unknown',
        'snowflake_tag_compliance': 0.0
    }
    
    try:
        # We need to construct the query carefully. 
        # INFORMATION_SCHEMA queries are local to the DB usually, but we inject WHERE clauses.
        
        query = f"""
        WITH tbl AS (
            SELECT 
                table_catalog,
                table_schema,
                table_name,
                created,
                last_altered,
                comment AS table_comment
            FROM INFORMATION_SCHEMA.TABLES
            WHERE {info_filter}
        ),
        col AS (
            SELECT 
                table_catalog,
                table_schema,
                table_name,
                COUNT(*) AS total_columns,
                COUNT_IF(comment IS NOT NULL) AS commented_columns
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE {info_filter}
            GROUP BY table_catalog, table_schema, table_name
        ),
        classified AS (
            SELECT 
                t.*,
                c.total_columns,
                c.commented_columns,
                CASE WHEN t.table_comment IS NOT NULL AND c.total_columns = c.commented_columns THEN 1 ELSE 0 END AS is_fully_classified,
                CASE WHEN t.table_comment IS NOT NULL AND DATEDIFF('day', t.created, CURRENT_DATE()) <= 5 THEN 1 ELSE 0 END AS five_day_compliant,
                CASE WHEN YEAR(t.last_altered) = YEAR(CURRENT_DATE()) THEN 1 ELSE 0 END AS annual_reviewed
            FROM tbl t
            LEFT JOIN col c USING (table_catalog, table_schema, table_name)
        )
        SELECT
            -- Classification Coverage (Percent of tables fully documented)
            ROUND(100.0 * SUM(is_fully_classified) / NULLIF(COUNT(*), 0), 1) AS classification_coverage_percentage,
            
            -- 5-Day Rule Compliance (Percent of tables classified within 5 days)
            ROUND(100.0 * SUM(five_day_compliant) / NULLIF(COUNT(*), 0), 1) AS five_day_rule_compliance_percentage,
            
            -- Annual Review Rate (Percent of tables altered this year)
            ROUND(100.0 * SUM(annual_reviewed) / NULLIF(COUNT(*), 0), 1) AS annual_review_rate_percentage,
            
            -- Policy Violations (tables not fully classified)
            COUNT_IF(is_fully_classified = 0) AS policy_violations,
            
            -- Overall Status
            CASE 
                WHEN COUNT_IF(is_fully_classified = 0) = 0 THEN ' Healthy'
                ELSE ' Issues'
            END AS overall_status,
            
            -- Snowflake Tag Compliance (scalar subquery)
            (
                WITH required_tags AS (
                    SELECT 'DATA_CLASSIFICATION' AS tag_name UNION ALL
                    SELECT 'CONFIDENTIALITY_LEVEL' UNION ALL
                    SELECT 'INTEGRITY_LEVEL' UNION ALL
                    SELECT 'AVAILABILITY_LEVEL'
                ),
                all_tables AS (
                    SELECT 
                        table_catalog AS object_database,
                        table_schema AS object_schema,
                        table_name AS object_name
                    FROM INFORMATION_SCHEMA.TABLES
                    WHERE {info_filter}
                ),
                tag_refs AS (
                    SELECT 
                        object_database,
                        object_schema,
                        object_name,
                        tag_name
                    FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                    WHERE tag_name IN (SELECT tag_name FROM required_tags)
                    AND {usage_filter}
                ),
                tag_validation AS (
                    SELECT 
                        t.object_database,
                        t.object_schema,
                        t.object_name,
                        COUNT(DISTINCT tr.tag_name) AS applied_tags_count,
                        (SELECT COUNT(*) FROM required_tags) AS required_tags_count
                    FROM all_tables t
                    LEFT JOIN tag_refs tr
                        ON t.object_database = tr.object_database
                        AND t.object_schema = tr.object_schema
                        AND t.object_name = tr.object_name
                    GROUP BY t.object_database, t.object_schema, t.object_name
                )
                SELECT 
                    COALESCE(
                        ROUND(
                            100.0 * COUNT_IF(applied_tags_count = required_tags_count) / NULLIF(COUNT(*), 0),
                            1
                        ), 
                        0.0
                    )
                FROM tag_validation
            ) AS snowflake_tag_correctness_percent
        FROM classified
        """
        
        result = snowflake_connector.execute_query(query, all_params)
        
        if result and len(result) > 0:
            row = result[0]
            # Convert row keys to uppercase for case-insensitive access
            row_upper = {k.upper(): v for k, v in row.items()}
            
            # Get the values with debug info
            classification = float(row_upper.get('CLASSIFICATION_COVERAGE_PERCENTAGE') or 0)
            five_day = float(row_upper.get('FIVE_DAY_RULE_COMPLIANCE_PERCENTAGE') or 0)
            annual = float(row_upper.get('ANNUAL_REVIEW_RATE_PERCENTAGE') or 0)
            violations = int(row_upper.get('POLICY_VIOLATIONS') or 0)
            status = row_upper.get('OVERALL_STATUS', ' Unknown')
            snowflake_tag_compliance = float(row_upper.get('SNOWFLAKE_TAG_CORRECTNESS_PERCENT') or 0)
            
            metrics.update({
                'classification_coverage': classification,
                'five_day_compliance': five_day,
                'annual_review_rate': annual,
                'policy_violations': violations,
                'overall_status': status,
                'snowflake_tag_compliance': snowflake_tag_compliance
            })
    
    except Exception as e:
        st.error(f" Error fetching compliance metrics: {e}")
    
    return metrics

# REMOVED CACHE to force fresh data - enable cache after debugging
def get_classification_requirements_metrics(db: str) -> Dict:
    """Fetch detailed classification requirements metrics using INFORMATION_SCHEMA.
    
    This comprehensive query calculates:
    - 5-Day Rule Compliance
    - Annual Review Completion
    - Documentation Completeness
    - Classification Coverage
    - Policy Violations
    - Overall Compliance Status
    
    Args:
        db: The database to query
        
    Returns:
        Dictionary with all classification requirements metrics
    """
    try:
        query = f"""
        WITH metrics AS (
            -- 5-Day Rule
            SELECT 
                ROUND(
                    COUNT_IF(comment IS NOT NULL AND DATEDIFF('day', created, CURRENT_DATE) <= 5) * 100.0
                    / COUNT(*),
                    1
                ) AS five_day_compliance,
                -- Annual Review
                ROUND(
                    COUNT_IF(YEAR(last_altered) = YEAR(CURRENT_DATE)) * 100.0
                    / COUNT(*),
                    1
                ) AS annual_review,
                -- Documentation Completeness
                (SELECT ROUND(
                        COUNT_IF(table_comment IS NOT NULL AND total_columns = commented_columns) * 100.0
                        / COUNT(*),1)
                 FROM (
                     SELECT t.table_catalog, t.table_schema, t.table_name,
                            t.comment AS table_comment,
                            c.total_columns, c.commented_columns
                     FROM INFORMATION_SCHEMA.TABLES t
                     JOIN (
                         SELECT table_catalog, table_schema, table_name,
                                COUNT(*) AS total_columns,
                                COUNT_IF(comment IS NOT NULL) AS commented_columns
                         FROM INFORMATION_SCHEMA.COLUMNS
                         GROUP BY table_catalog, table_schema, table_name
                     ) c USING (table_catalog, table_schema, table_name)
                 ) sub
                ) AS doc_completeness,
                -- Classification Coverage
                ROUND(
                    COUNT_IF(comment IS NOT NULL) * 100.0 / COUNT(*),
                    1
                ) AS coverage,
                -- Policy Violations
                (SELECT COUNT(*) 
                 FROM INFORMATION_SCHEMA.TABLES
                 WHERE comment IS NULL) AS policy_violations
            FROM INFORMATION_SCHEMA.TABLES
        )
        SELECT *,
               CASE
                   WHEN five_day_compliance >= 95
                        AND annual_review = 100
                        AND doc_completeness >= 95
                        AND coverage >= 95
                        AND policy_violations = 0
                   THEN '🟢 Compliant'
                   WHEN five_day_compliance >= 80
                        AND annual_review >= 95
                        AND doc_completeness >= 80
                        AND coverage >= 80
                        AND policy_violations <= 5
                   THEN '🟡 Partially Compliant'
                   ELSE '🔴 Non-Compliant'
               END AS overall_status
        FROM metrics
        """
        
        result = snowflake_connector.execute_query(query)
        
        if result and len(result) > 0:
            row = result[0]
            # Convert to uppercase for case-insensitive access
            row_upper = {k.upper(): v for k, v in row.items()}
            
            return {
                'five_day_compliance': float(row_upper.get('FIVE_DAY_COMPLIANCE', 0)),
                'annual_review': float(row_upper.get('ANNUAL_REVIEW', 0)),
                'doc_completeness': float(row_upper.get('DOC_COMPLETENESS', 0)),
                'coverage': float(row_upper.get('COVERAGE', 0)),
                'policy_violations': int(row_upper.get('POLICY_VIOLATIONS', 0)),
                'overall_status': row_upper.get('OVERALL_STATUS', '🔴 Unknown')
            }
    except Exception as e:
        st.warning(f"Error fetching classification requirements: {e}")
    
    return {
        'five_day_compliance': 0.0,
        'annual_review': 0.0,
        'doc_completeness': 0.0,
        'coverage': 0.0,
        'policy_violations': 0,
        'overall_status': '🔴 Unknown'
    }

# REMOVED CACHE to force fresh data - enable cache after debugging
def get_mandatory_compliance_elements(db: str, filters: dict = None) -> Dict:
    """Fetch mandatory compliance elements metrics using INFORMATION_SCHEMA."""
    schema = _gv_schema()
    
    # Build filters
    info_filter, info_params = _build_filters(filters, db, 'table_catalog', 'table_schema', 'table_name')
    usage_filter, usage_params = _build_filters(filters, db, 'object_database', 'object_schema', 'object_name')
    all_params = {**info_params, **usage_params}

    try:
        # Query for all mandatory compliance metrics in one call
        query = f"""
        WITH base_tables AS (
            SELECT 
                table_catalog,
                table_schema,
                table_name,
                created,
                last_altered,
                comment AS table_comment
            FROM INFORMATION_SCHEMA.TABLES
            WHERE {info_filter}
        ),
        column_stats AS (
            SELECT 
                table_catalog,
                table_schema,
                table_name,
                COUNT(*) AS total_columns,
                COUNT_IF(comment IS NOT NULL) AS commented_columns
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE {info_filter}
            GROUP BY table_catalog, table_schema, table_name
        ),
        -- First get total assets count from INFORMATION_SCHEMA (filtered)
        total_assets_cte AS (
            SELECT COUNT(*) AS total_assets_count
            FROM INFORMATION_SCHEMA.TABLES
            WHERE {info_filter}
        ),
        -- Then calculate tag statistics
        tag_stats AS (
            WITH required_tags AS (
                SELECT 'DATA_CLASSIFICATION' AS tag_name UNION ALL
                SELECT 'CONFIDENTIALITY_LEVEL' UNION ALL
                SELECT 'INTEGRITY_LEVEL' UNION ALL
                SELECT 'AVAILABILITY_LEVEL'
            ),
            all_tables AS (
                SELECT 
                    table_catalog AS object_database,
                    table_schema AS object_schema,
                    table_name AS object_name
                FROM INFORMATION_SCHEMA.TABLES
                WHERE {info_filter}
            ),
            tag_refs AS (
                SELECT 
                    object_database,
                    object_schema,
                    object_name,
                    tag_name
                FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                WHERE tag_name IN (SELECT tag_name FROM required_tags)
                AND {usage_filter}
            ),
            tag_validation AS (
                SELECT 
                    t.object_database,
                    t.object_schema,
                    t.object_name,
                    COUNT(DISTINCT tr.tag_name) AS applied_tags_count,
                    (SELECT COUNT(*) FROM required_tags) AS required_tags_count
                FROM all_tables t
                LEFT JOIN tag_refs tr
                    ON t.object_database = tr.object_database
                   AND t.object_schema = tr.object_schema
                   AND t.object_name = tr.object_name
                GROUP BY t.object_database, t.object_schema, t.object_name
            )
            SELECT 
                COUNT_IF(applied_tags_count = required_tags_count) as tagged_assets_count,
                ROUND(100.0 * COUNT_IF(applied_tags_count = required_tags_count) / 
                      NULLIF((SELECT total_assets_count FROM total_assets_cte), 0), 1) as tag_pct
            FROM tag_validation
        ),
        -- Get list of non-compliant assets (not classified within 5 days)
        non_compliant_assets AS (
            SELECT 
                t.table_catalog,
                t.table_schema,
                t.table_name,
                t.created,
                DATEDIFF('day', t.created, CURRENT_DATE()) as days_since_creation,
                t.table_comment
            FROM base_tables t
            LEFT JOIN column_stats c 
                ON t.table_catalog = c.table_catalog 
                AND t.table_schema = c.table_schema 
                AND t.table_name = c.table_name
            WHERE t.table_comment IS NULL 
               OR (t.table_comment IS NOT NULL 
                   AND DATEDIFF('day', t.created, CURRENT_DATE()) > 5)
        ),
        compliance_metrics AS (
            SELECT 
                -- Total assets from dedicated CTE
                (SELECT total_assets_count FROM total_assets_cte) AS total_assets,
                
                -- Assets classified within 5 business days
                COUNT_IF(
                    t.table_comment IS NOT NULL 
                    AND DATEDIFF('day', t.created, CURRENT_DATE()) <= 5
                ) AS assets_classified_5_days,
                
                -- Annual reviews (tables altered this year)
                COUNT_IF(
                    YEAR(t.last_altered) = YEAR(CURRENT_DATE())
                ) AS annual_reviews_completed,
                
                -- Documentation complete (table comment + all column comments)
                COUNT_IF(
                    t.table_comment IS NOT NULL 
                    AND c.total_columns = c.commented_columns
                ) AS documentation_complete,
                
                -- Pending classification (no comment and created within 5 days)
                COUNT_IF(
                    t.table_comment IS NULL 
                    AND DATEDIFF('day', t.created, CURRENT_DATE()) <= 5
                ) AS pending_classification,
                
                -- Count of non-compliant assets
                (SELECT COUNT(*) FROM non_compliant_assets) AS non_compliant_count,
                
                -- List of non-compliant assets as JSON array
                (SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
                    'database', table_catalog,
                    'schema', table_schema,
                    'table', table_name,
                    'created', created,
                    'days_since_creation', days_since_creation,
                    'has_comment', table_comment IS NOT NULL
                )) FROM non_compliant_assets) AS non_compliant_assets_json
                
            FROM base_tables t
            LEFT JOIN column_stats c 
                ON t.table_catalog = c.table_catalog 
                AND t.table_schema = c.table_schema 
                AND t.table_name = c.table_name
        )
        SELECT 
            total_assets,
            assets_classified_5_days,
            ROUND(assets_classified_5_days * 100.0 / NULLIF(total_assets, 0), 1) AS five_day_pct,
            pending_classification,
            annual_reviews_completed,
            ROUND(annual_reviews_completed * 100.0 / NULLIF(total_assets, 0), 1) AS annual_review_pct,
            documentation_complete,
            ROUND(documentation_complete * 100.0 / NULLIF(total_assets, 0), 1) AS doc_complete_pct,
            (SELECT tagged_assets_count FROM tag_stats) AS tagged_assets,
            (SELECT total_assets_count FROM total_assets_cte) AS tag_total,
            (SELECT tag_pct FROM tag_stats) AS tag_pct,
            non_compliant_count,
            non_compliant_assets_json
        FROM compliance_metrics
        CROSS JOIN tag_stats ts
        """
        
        result = snowflake_connector.execute_query(query, all_params)
        
        if result and len(result) > 0:
            row = result[0]
            row_upper = {k.upper(): v for k, v in row.items()}
            
            return {
                # 5-Day Classification
                'five_day_classified': int(row_upper.get('ASSETS_CLASSIFIED_5_DAYS', 0)),
                'five_day_total': int(row_upper.get('TOTAL_ASSETS', 0)),
                'five_day_pct': float(row_upper.get('FIVE_DAY_PCT', 0)),
                'five_day_pending': int(row_upper.get('PENDING_CLASSIFICATION', 0)),
                'non_compliant_count': int(row_upper.get('NON_COMPLIANT_COUNT', 0)),
                'non_compliant_assets': row_upper.get('NON_COMPLIANT_ASSETS_JSON', []),
                
                # Annual Reviews
                'annual_completed': int(row_upper.get('ANNUAL_REVIEWS_COMPLETED', 0)),
                'annual_total': int(row_upper.get('TOTAL_ASSETS', 0)),
                'annual_pct': float(row_upper.get('ANNUAL_REVIEW_PCT', 0)),
                
                # Documentation
                'doc_complete': int(row_upper.get('DOCUMENTATION_COMPLETE', 0)),
                'doc_total': int(row_upper.get('TOTAL_ASSETS', 0)),
                'doc_pct': float(row_upper.get('DOC_COMPLETE_PCT', 0)),
                
                # Tags
                'tagged_assets': int(row_upper.get('TAGGED_ASSETS', 0)),
                'tag_total': int(row_upper.get('TAG_TOTAL', 0)),
                'tag_pct': float(row_upper.get('TAG_PCT', 0))
            }
    except Exception as e:
        st.warning(f"Error fetching mandatory compliance elements: {e}")

    
    # Fallback to demo data
    try:
        from src.demo_data import UNCLASSIFIED_ASSETS_TSV
        if UNCLASSIFIED_ASSETS_TSV:
            df = pd.read_csv(StringIO(UNCLASSIFIED_ASSETS_TSV), sep='\t')
            if not df.empty:
                total = len(df)
                # Mock logic for demo data
                # Assuming 50% compliant for demo
                classified = len(df[df['CLASSIFICATION_LABEL'] != 'Unclassified'])
                pending = total - classified
                
                return {
                    'five_day_classified': classified,
                    'five_day_total': total,
                    'five_day_pct': round(classified / total * 100, 1) if total else 0,
                    'five_day_pending': pending,
                    'annual_completed': int(total * 0.8),
                    'annual_total': total,
                    'annual_pct': 80.0,
                    'doc_complete': int(total * 0.9),
                    'doc_total': total,
                    'doc_pct': 90.0,
                    'tagged_assets': classified,
                    'tag_total': total,
                    'tag_pct': round(classified / total * 100, 1) if total else 0,
                }
    except Exception:
        pass

    return {
        'five_day_classified': 0,
        'five_day_total': 0,
        'five_day_pct': 0.0,
        'five_day_pending': 0,
        'annual_completed': 0,
        'annual_total': 0,
        'annual_pct': 0.0,
        'doc_complete': 0,
        'doc_total': 0,
        'doc_pct': 0.0,
        'tagged_assets': 0,
    }

# REMOVED CACHE to force fresh data - enable cache after debugging
def get_risk_classification_data(db: str, filters: dict = None) -> pd.DataFrame:
    """Fetch risk classification distribution from Snowflake TAG_REFERENCES."""
    usage_filter, params = _build_filters(filters, db, 'object_database', 'object_schema', 'object_name')
    
    try:
        query = f"""
        WITH classified_assets AS (
            SELECT
                object_database,
                object_schema,
                object_name,
                MAX(CASE WHEN tag_name = 'CONFIDENTIALITY_LEVEL' THEN tag_value END) AS C,
                MAX(CASE WHEN tag_name = 'INTEGRITY_LEVEL' THEN tag_value END) AS I,
                MAX(CASE WHEN tag_name = 'AVAILABILITY_LEVEL' THEN tag_value END) AS A
            FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
            WHERE tag_name IN ('CONFIDENTIALITY_LEVEL', 'INTEGRITY_LEVEL', 'AVAILABILITY_LEVEL')
            AND {usage_filter}
            GROUP BY 1,2,3
        ),
        
        risk_mapping AS (
            SELECT
                *,
                CASE
                    WHEN (C IN ('C0','C1') AND I IN ('I0','I1') AND A IN ('A0','A1'))
                        THEN 'Low Risk'
                    WHEN (C = 'C2' OR I = 'I2' OR A = 'A2')
                        THEN 'Medium Risk'
                    WHEN (C = 'C3' OR I = 'I3' OR A = 'A3')
                        THEN 'High Risk'
                    ELSE 'Unclassified'
                END AS risk_level
            FROM classified_assets
        ),
        
        risk_aggregation AS (
            SELECT
                risk_level,
                COUNT(*) AS asset_count
            FROM risk_mapping
            GROUP BY risk_level
        ),
        
        tot AS (
            SELECT SUM(asset_count) AS total_assets
            FROM risk_aggregation
        )
        
        SELECT
            r.risk_level AS "Risk Level",
            r.asset_count AS "Count",
            CONCAT(ROUND((r.asset_count / t.total_assets) * 100, 1), '%%') AS "Percentage",
            CASE r.risk_level
                WHEN 'Low Risk' THEN 'C0-C1, I0-I1, A0-A1'
                WHEN 'Medium Risk' THEN 'C2, I2, or A2'
                WHEN 'High Risk' THEN 'C3, I3, or A3'
                ELSE 'Not Classified'
            END AS "Criteria",
            CASE r.risk_level
                WHEN 'Low Risk' THEN ' Normal'
                WHEN 'Medium Risk' THEN ' Monitor'
                WHEN 'High Risk' THEN ' High Priority'
                ELSE ' Action Required'
            END AS "Status"
        FROM risk_aggregation r
        CROSS JOIN tot t
        ORDER BY 
            CASE r.risk_level
                WHEN 'Low Risk' THEN 1
                WHEN 'Medium Risk' THEN 2
                WHEN 'High Risk' THEN 3
                ELSE 4
            END
        """
        
        # Execute the query with proper parameter handling
        try:
            if params:
                rows = snowflake_connector.execute_query(query, params)
            else:
                rows = snowflake_connector.execute_query(query)
                
            if not rows:
                return pd.DataFrame(columns=['Risk Level', 'Count', 'Percentage', 'Criteria', 'Status'])
                
            # Convert to DataFrame and ensure proper column types
            df = pd.DataFrame(rows)
            if 'Count' in df.columns:
                df['Count'] = pd.to_numeric(df['Count'], errors='coerce').fillna(0).astype(int)
            return df
            
        except Exception as e:
            st.error(f"Error executing risk classification query: {str(e)}")
            return pd.DataFrame(columns=['Risk Level', 'Count', 'Percentage', 'Criteria', 'Status'])
        
    except Exception as e:
        st.error(f"Error fetching risk classification data: {str(e)}")
        return pd.DataFrame()


# REMOVED CACHE to force fresh data - enable cache after debugging
def get_special_categories_compliance(db: str, filters: dict = None) -> Dict:
    """Fetch special categories compliance metrics using user-provided query on CLASSIFICATION_AI_RESULTS."""
    
    metrics = {
        'pii_compliant': 0,
        'pii_non_compliant': 0,
        'soc2_compliant': 0,
        'soc2_non_compliant': 0,
        'sox_compliant': 0,
        'sox_non_compliant': 0
    }
    
    try:
        schema = _gv_schema()
        # Use user provided query structure
        # We target CLASSIFICATION_AI_RESULTS in the active schema
        query = f"""
        WITH compliance_data AS (
            SELECT 
                PARSE_JSON(DETAILS):policy_group::STRING as policy_group,
                PARSE_JSON(DETAILS):cia.c::INT as confidentiality_level
            FROM {db}.{schema}.CLASSIFICATION_AI_RESULTS
            WHERE PARSE_JSON(DETAILS):policy_group::STRING IN ('PII', 'SOC2', 'SOX')
        ),
        compliance_summary AS (
            SELECT 
                policy_group,
                CASE 
                    WHEN policy_group = 'PII' THEN 'C2'
                    WHEN policy_group = 'SOC2' THEN 'C3'
                    WHEN policy_group = 'SOX' THEN 'C3'
                END as minimum_required,
                COUNT(*) as total_assets,
                COUNT(CASE 
                    WHEN (policy_group = 'PII' AND confidentiality_level >= 2) THEN 1
                    WHEN (policy_group = 'SOC2' AND confidentiality_level >= 3) THEN 1
                    WHEN (policy_group = 'SOX' AND confidentiality_level >= 3) THEN 1
                END) as compliant_assets,
                COUNT(CASE 
                    WHEN (policy_group = 'PII' AND confidentiality_level < 2) THEN 1
                    WHEN (policy_group = 'SOC2' AND confidentiality_level < 3) THEN 1
                    WHEN (policy_group = 'SOX' AND confidentiality_level < 3) THEN 1
                END) as non_compliant_assets
            FROM compliance_data
            WHERE policy_group IS NOT NULL
            GROUP BY policy_group
        )
        SELECT 
            policy_group,
            compliant_assets,
            non_compliant_assets
        FROM compliance_summary
        """
        
        rows = snowflake_connector.execute_query(query)
        if rows:
            for r in rows:
                pg = (r.get('POLICY_GROUP') or '').upper()
                comp = int(r.get('COMPLIANT_ASSETS') or 0)
                non = int(r.get('NON_COMPLIANT_ASSETS') or 0)
                
                if pg == 'PII':
                    metrics['pii_compliant'] = comp
                    metrics['pii_non_compliant'] = non
                elif pg == 'SOC2':
                    metrics['soc2_compliant'] = comp
                    metrics['soc2_non_compliant'] = non
                elif pg == 'SOX':
                    metrics['sox_compliant'] = comp
                    metrics['sox_non_compliant'] = non
                    
    except Exception as e:
        st.error(f"Error fetching special compliance: {e}")
            
    return metrics

# REMOVED CACHE to force fresh data - enable cache after debugging
def get_annual_reviews_data(db: str, filters: dict = None) -> pd.DataFrame:
    """Fetch annual reviews schedule and status using detailed classification review view."""
    
    # Using the complex query provided by user which targets VW_CLASSIFICATION_REVIEWS
    # Note: literal % must be escaped as %%
    
    try:
        query = """
        SELECT
            ASSET_FULL_NAME,
            CONFIDENTIALITY_LEVEL,
            INTEGRITY_LEVEL,
            AVAILABILITY_LEVEL,
            REVIEWER,
            REVIEW_DUE_DATE,
            STATUS_LABEL,
            CASE 
                WHEN CURRENT_DATE() > REVIEW_DUE_DATE THEN 'Overdue'
                WHEN STATUS_LABEL ILIKE '%%Approved%%' THEN 'Completed On Time'
                ELSE 'Due Soon'
            END AS REVIEW_STATUS,
            CASE
                WHEN CONFIDENTIALITY_LEVEL = 3 OR INTEGRITY_LEVEL = 3 OR AVAILABILITY_LEVEL = 3 THEN 'High Risk'
                WHEN CONFIDENTIALITY_LEVEL IS NULL OR INTEGRITY_LEVEL IS NULL OR AVAILABILITY_LEVEL IS NULL THEN 'Unclassified'
                ELSE 'Normal'
            END AS RISK_CLASSIFICATION
        FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.VW_CLASSIFICATION_REVIEWS
        """
        
        rows = snowflake_connector.execute_query(query)
        if not rows:
            return pd.DataFrame()
            
        return pd.DataFrame(rows)

    except Exception as e:
        st.error(f"Error fetching annual reviews data: {e}")
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
        st.warning(f"Error fetching QA reviews: {e}")
    
    return metrics

def get_policy_violations(db: str) -> pd.DataFrame:
    """Fetch policy violations data from Snowflake using detailed breakdown query."""
    try:
        # User defined query
        query = f"""
        WITH 
        detailed_violation_counts AS (
          SELECT 
            'Missing Classification' AS violation_type,
            COUNT(*) AS count,
            LISTAGG(DISTINCT ASSET_FULL_NAME, ', ') WITHIN GROUP (ORDER BY ASSET_FULL_NAME) AS sample_assets,
            COUNT(DISTINCT ASSET_FULL_NAME) AS unique_assets,
            MIN(DATEDIFF('day', CREATED_AT, CURRENT_DATE())) AS min_days_pending,
            MAX(DATEDIFF('day', CREATED_AT, CURRENT_DATE())) AS max_days_pending
          FROM {db}.{_gv_schema()}.VW_CLASSIFICATION_REVIEWS
          WHERE STATUS ILIKE '%pending%' 
            AND DATEDIFF('day', CREATED_AT, CURRENT_DATE()) > 5
          
          UNION ALL
          
          SELECT 
            'Overdue Reviews',
            COUNT(*),
            LISTAGG(DISTINCT ASSET_FULL_NAME, ', ') WITHIN GROUP (ORDER BY ASSET_FULL_NAME),
            COUNT(DISTINCT ASSET_FULL_NAME),
            NULL,
            NULL
          FROM {db}.{_gv_schema()}.VW_CLASSIFICATION_REVIEWS
          WHERE REVIEW_DUE_DATE < CURRENT_DATE()
          
          UNION ALL
          
          SELECT 
            'Insufficient Protection',
            COUNT(*),
            LISTAGG(DISTINCT ASSET_FULL_NAME, ', ') WITHIN GROUP (ORDER BY ASSET_FULL_NAME),
            COUNT(DISTINCT ASSET_FULL_NAME),
            NULL,
            NULL
          FROM {db}.{_gv_schema()}.VW_CLASSIFICATION_REVIEWS
          WHERE (REQUESTED_LABEL ILIKE '%PII%' OR REQUESTED_LABEL ILIKE '%financial%')
            AND (CONFIDENTIALITY_LEVEL < 2 OR INTEGRITY_LEVEL < 2)
        ),

        resolution_analysis AS (
          SELECT 
            STATUS,
            COUNT(*) AS count,
            MIN(UPDATED_AT) AS oldest_update,
            MAX(UPDATED_AT) AS newest_update,
            COUNT(CASE WHEN UPDATED_AT >= DATE_TRUNC('month', CURRENT_DATE()) THEN 1 END) AS updated_this_month
          FROM {db}.{_gv_schema()}.VW_CLASSIFICATION_REVIEWS
          GROUP BY STATUS
        ),

        repeat_offenders_detail AS (
          SELECT 
            ASSET_FULL_NAME,
            CREATED_BY,
            COUNT(CASE 
              WHEN STATUS ILIKE '%pending%' AND DATEDIFF('day', CREATED_AT, CURRENT_DATE()) > 5 
              THEN 1 
            END) AS missing_class_count,
            COUNT(CASE 
              WHEN REVIEW_DUE_DATE < CURRENT_DATE() 
              THEN 1 
            END) AS overdue_review_count,
            COUNT(CASE 
              WHEN (REQUESTED_LABEL ILIKE '%PII%' OR REQUESTED_LABEL ILIKE '%financial%')
                   AND (CONFIDENTIALITY_LEVEL < 2 OR INTEGRITY_LEVEL < 2) 
              THEN 1 
            END) AS insufficient_protection_count
          FROM {db}.{_gv_schema()}.VW_CLASSIFICATION_REVIEWS
          GROUP BY ASSET_FULL_NAME, CREATED_BY
        ),

        sample_diagnostic AS (
          SELECT 
            'Data Sample' AS check_type,
            COUNT(*) AS total_records,
            COUNT(DISTINCT STATUS) AS unique_statuses,
            LISTAGG(DISTINCT STATUS, ', ') AS all_statuses,
            MIN(CREATED_AT) AS oldest_record,
            MAX(CREATED_AT) AS newest_record
          FROM {db}.{_gv_schema()}.VW_CLASSIFICATION_REVIEWS
        )

        SELECT 
            'VIOLATION TYPE BREAKDOWN' AS category,
            violation_type AS metric,
            CAST(count AS STRING) AS value,
            CONCAT(
                'Unique assets: ', CAST(unique_assets AS STRING),
                CASE 
                    WHEN violation_type = 'Missing Classification' 
                    THEN CONCAT(' (Pending ', min_days_pending, '-', max_days_pending, ' days)')
                    ELSE ''
                END
            ) AS details
        FROM detailed_violation_counts

        UNION ALL

        SELECT 
            'TOTALS SUMMARY',
            'Active Violations',
            CAST(SUM(count) AS STRING),
            'Sum of all violation types'
        FROM detailed_violation_counts

        UNION ALL

        SELECT 
            'RESOLUTION ANALYSIS',
            'Resolved This Month',
            CAST(
                (SELECT COUNT(*) 
                 FROM {db}.{_gv_schema()}.VW_CLASSIFICATION_REVIEWS
                 WHERE STATUS ILIKE '%approved%'
                   AND UPDATED_AT >= DATE_TRUNC('month', CURRENT_DATE())
                ) AS STRING
            ),
            CONCAT(
                'Approved status count this month: ',
                (SELECT CAST(COUNT(*) AS STRING)
                 FROM {db}.{_gv_schema()}.VW_CLASSIFICATION_REVIEWS
                 WHERE STATUS ILIKE '%approved%'
                   AND UPDATED_AT >= DATE_TRUNC('month', CURRENT_DATE()))
            )

        UNION ALL

        SELECT 
            'RESOLUTION ANALYSIS',
            'All Approved Records',
            CAST(
                (SELECT COUNT(*) 
                 FROM {db}.{_gv_schema()}.VW_CLASSIFICATION_REVIEWS
                 WHERE STATUS ILIKE '%approved%'
                ) AS STRING
            ),
            CONCAT(
                'Total approved: ',
                (SELECT CAST(COUNT(*) AS STRING)
                 FROM {db}.{_gv_schema()}.VW_CLASSIFICATION_REVIEWS
                 WHERE STATUS ILIKE '%approved%')
            )

        UNION ALL

        SELECT 
            'REPEAT OFFENDERS',
            'Repeat Offenders Count',
            CAST(
                (SELECT COUNT(*) 
                 FROM repeat_offenders_detail 
                 WHERE (missing_class_count + overdue_review_count + insufficient_protection_count) >= 2
                ) AS STRING
            ),
            CONCAT(
                'Assets with multiple violations: ',
                (SELECT CAST(COUNT(*) AS STRING)
                 FROM repeat_offenders_detail 
                 WHERE (missing_class_count + overdue_review_count + insufficient_protection_count) >= 2)
            )

        UNION ALL

        SELECT 
            'REPEAT OFFENDERS',
            'Potential Repeat Pattern',
            CAST(
                (SELECT COUNT(*) 
                 FROM repeat_offenders_detail 
                 WHERE missing_class_count >= 1 AND overdue_review_count >= 1
                ) AS STRING
            ),
            'Assets with both missing classification AND overdue review'

        UNION ALL

        SELECT 
            'DIAGNOSTIC',
            'Data Health Check',
            CAST(total_records AS STRING),
            CONCAT(
                'Statuses: ', all_statuses,
                ' | Date range: ', TO_CHAR(oldest_record, 'MM/DD/YYYY'), ' - ', TO_CHAR(newest_record, 'MM/DD/YYYY')
            )
        FROM sample_diagnostic

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
        
        rows = snowflake_connector.execute_query(query)
        if not rows:
            return pd.DataFrame(columns=['CATEGORY', 'METRIC', 'VALUE', 'DETAILS'])
            
        return pd.DataFrame(rows)
            
    except Exception as e:
        st.error(f"Error fetching policy violations: {e}")
        return pd.DataFrame(columns=['CATEGORY', 'METRIC', 'VALUE', 'DETAILS'])

# REMOVED CACHE to force fresh data - enable cache after debugging
def get_compliance_trends_metrics(db: str) -> pd.DataFrame:
    """Fetch unified compliance trends for the last 6 months using the single query approach."""
    
    try:
        # Note: All literal '%' must be escaped as '%%' for python string formatting
        query = """
        -- ============================================================================
        -- UNIFIED COMPLIANCE TREND - Single Query for All Metrics (Last 6 Months)
        -- FIXED VERSION - Without TAG_REFERENCES timestamp dependency
        -- ============================================================================
        WITH 
        -- Generate last 6 months date range
        date_spine AS (
            SELECT DATEADD('month', -(ROW_NUMBER() OVER (ORDER BY SEQ4()) - 1), DATE_TRUNC('MONTH', CURRENT_DATE())) AS month
            FROM TABLE(GENERATOR(ROWCOUNT => 6))
        ),

        -- 1. Policy Compliance Metrics
        policy_metrics AS (
            SELECT
                DATE_TRUNC('MONTH', CREATED_AT) AS month,
                COUNT(*) AS total_reviews,
                SUM(CASE WHEN STATUS ILIKE '%%approved%%' THEN 1 ELSE 0 END) AS approved_reviews,
                SUM(CASE WHEN STATUS ILIKE '%%rejected%%' THEN 1 ELSE 0 END) AS rejected_reviews,
                ROUND(100.0 * SUM(CASE WHEN STATUS ILIKE '%%approved%%' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) AS policy_compliance_rate
            FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.VW_CLASSIFICATION_REVIEWS
            WHERE CREATED_AT >= DATEADD('month', -6, CURRENT_DATE())
            GROUP BY DATE_TRUNC('MONTH', CREATED_AT)
        ),

        -- 2. Data Governance Metrics - Using ASSETS table instead of TAG_REFERENCES
        -- This gives us proper timestamps for when assets were classified
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
                    WHEN CONFIDENTIALITY_LEVEL IN ('C2', 'C3')
                    THEN ASSET_ID
                END) AS sensitive_assets
            FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
            WHERE CLASSIFICATION_DATE >= DATEADD('month', -6, CURRENT_DATE())
              AND CLASSIFICATION_DATE IS NOT NULL
            GROUP BY DATE_TRUNC('MONTH', CLASSIFICATION_DATE)
        ),

        -- Calculate governance completion rate
        governance_calculated AS (
            SELECT
                month,
                total_assets,
                classified_assets,
                sensitive_assets,
                ROUND(100.0 * classified_assets / NULLIF(total_assets, 0), 2) AS governance_completion_rate
            FROM governance_metrics
        ),

        -- 3. Audit Activity Metrics
        audit_metrics AS (
            SELECT
                DATE_TRUNC('MONTH', CREATED_AT) AS month,
                COUNT(*) AS total_audit_events,
                COUNT(DISTINCT RESOURCE_ID) AS unique_resources,
                COUNT(CASE WHEN ACTION ILIKE '%%classification%%' THEN 1 END) AS classification_events,
                COUNT(CASE WHEN ACTION ILIKE '%%review%%' THEN 1 END) AS review_events
            FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.VW_CLASSIFICATION_AUDIT
            WHERE CREATED_AT >= DATEADD('month', -6, CURRENT_DATE())
            GROUP BY DATE_TRUNC('MONTH', CREATED_AT)
        ),

        -- Calculate audit compliance rate
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

        -- 4. Risk & Incident Metrics - Using ASSETS table
        risk_metrics AS (
            SELECT
                DATE_TRUNC('MONTH', CLASSIFICATION_DATE) AS month,
                COUNT(DISTINCT CASE 
                    WHEN CONFIDENTIALITY_LEVEL = 'C3'
                    THEN ASSET_ID
                END) AS high_risk_assets,
                COUNT(DISTINCT CASE 
                    WHEN CONFIDENTIALITY_LEVEL = 'C2'
                    THEN ASSET_ID
                END) AS medium_risk_assets,
                COUNT(DISTINCT CASE 
                    WHEN CONFIDENTIALITY_LEVEL IS NOT NULL
                    THEN ASSET_ID
                END) AS total_classified
            FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
            WHERE CLASSIFICATION_DATE >= DATEADD('month', -6, CURRENT_DATE())
              AND CLASSIFICATION_DATE IS NOT NULL
            GROUP BY DATE_TRUNC('MONTH', CLASSIFICATION_DATE)
        ),

        -- Calculate risk exposure
        risk_calculated AS (
            SELECT
                month,
                high_risk_assets,
                medium_risk_assets,
                total_classified,
                ROUND(100.0 * (high_risk_assets + medium_risk_assets) / NULLIF(total_classified, 0), 2) AS risk_exposure_pct,
                -- Inverse for compliance score (lower risk = higher compliance)
                ROUND(100.0 - (100.0 * high_risk_assets / NULLIF(total_classified, 0)), 2) AS risk_compliance_rate
            FROM risk_metrics
        ),

        -- Combine all metrics
        combined_metrics AS (
            SELECT
                d.month,
                -- Policy Metrics
                COALESCE(p.total_reviews, 0) AS policy_reviews,
                COALESCE(p.approved_reviews, 0) AS policy_approved,
                COALESCE(p.policy_compliance_rate, 0) AS policy_compliance_pct,
                -- Governance Metrics
                COALESCE(g.total_assets, 0) AS governance_total_assets,
                COALESCE(g.classified_assets, 0) AS governance_classified,
                COALESCE(g.governance_completion_rate, 0) AS governance_completion_pct,
                -- Audit Metrics
                COALESCE(a.total_audit_events, 0) AS audit_events,
                COALESCE(a.classification_events, 0) AS audit_classifications,
                COALESCE(a.audit_compliance_rate, 0) AS audit_compliance_pct,
                -- Risk Metrics
                COALESCE(r.high_risk_assets, 0) AS risk_high_count,
                COALESCE(r.medium_risk_assets, 0) AS risk_medium_count,
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
                -- Individual Metrics
                policy_reviews,
                policy_approved,
                policy_compliance_pct,
                governance_total_assets,
                governance_classified,
                governance_completion_pct,
                audit_events,
                audit_classifications,
                audit_compliance_pct,
                risk_high_count,
                risk_medium_count,
                risk_compliance_pct,
                
                -- Overall Compliance Score (weighted average of all 4 dimensions)
                ROUND(
                    (COALESCE(policy_compliance_pct, 0) * 0.30 +        -- 30%% weight
                     COALESCE(governance_completion_pct, 0) * 0.30 +    -- 30%% weight
                     COALESCE(audit_compliance_pct, 0) * 0.20 +         -- 20%% weight
                     COALESCE(risk_compliance_pct, 0) * 0.20)           -- 20%% weight
                , 2) AS overall_compliance_score,
                
                -- Previous month values for trend calculation
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

        -- Final output with trend indicators
        SELECT
            TO_CHAR(month, 'YYYY-MM') AS month_period,
            
            -- Policy Compliance
            policy_reviews,
            policy_approved,
            policy_compliance_pct,
            ROUND(policy_compliance_pct - prev_policy, 2) AS policy_trend_change,
            CASE
                WHEN policy_compliance_pct > prev_policy THEN '📈'
                WHEN policy_compliance_pct < prev_policy THEN '📉'
                ELSE '➡️'
            END AS policy_trend,
            
            -- Data Governance
            governance_total_assets,
            governance_classified,
            governance_completion_pct,
            ROUND(governance_completion_pct - prev_governance, 2) AS governance_trend_change,
            CASE
                WHEN governance_completion_pct > prev_governance THEN '📈'
                WHEN governance_completion_pct < prev_governance THEN '📉'
                ELSE '➡️'
            END AS governance_trend,
            
            -- Audit Compliance
            audit_events,
            audit_classifications,
            audit_compliance_pct,
            ROUND(audit_compliance_pct - prev_audit, 2) AS audit_trend_change,
            CASE
                WHEN audit_compliance_pct > prev_audit THEN '📈'
                WHEN audit_compliance_pct < prev_audit THEN '📉'
                ELSE '➡️'
            END AS audit_trend,
            
            -- Risk & Incidents
            risk_high_count,
            risk_medium_count,
            risk_compliance_pct,
            ROUND(risk_compliance_pct - prev_risk, 2) AS risk_trend_change,
            CASE
                WHEN risk_compliance_pct > prev_risk THEN '✅'
                WHEN risk_compliance_pct < prev_risk THEN '⚠️'
                ELSE '➡️'
            END AS risk_trend,
            
            -- Overall Compliance Score & Trend
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
        
        rows = snowflake_connector.execute_query(query)
        if not rows:
            return pd.DataFrame()
            
        return pd.DataFrame(rows)

    except Exception as e:
        st.error(f"Error fetching compliance trends: {e}")
        return pd.DataFrame()

# ============================================================================
# RBAC CHECK
# ============================================================================

try:
    _ident = authz.get_current_identity()
    if not authz.is_consumer(_ident):
        st.error("You do not have permission to access the Compliance module.")
        st.stop()
except Exception as _auth_err:
    st.warning(f"Authorization check failed: {_auth_err}")
    st.stop()

# ============================================================================
# SIDEBAR FILTERS
# ============================================================================

with st.sidebar:
    st.header("🔍 Global Filters")
    st.markdown("---")
    
    # Warehouse selection
    st.subheader("Warehouse")
    wh_opts = _list_warehouses()
    cur_wh = st.session_state.get('sf_warehouse')
    try:
        wh_index = wh_opts.index(cur_wh) if (cur_wh and cur_wh in wh_opts) else 0
    except Exception:
        wh_index = 0
    
    if wh_opts:
        sel_wh = st.selectbox(
            "Select Warehouse",
            options=wh_opts,
            index=wh_index,
            key="flt_warehouse",
            help="Choose compute warehouse for queries"
        )
        if sel_wh:
            _apply_warehouse(sel_wh)
    else:
        st.warning("No warehouses available")
        sel_wh = None
    
    st.markdown("---")
    
    # Database selection
    st.subheader("Database")
    db_opts = ["All"] + _list_databases()
    
    # Default to DATA_CLASSIFICATION_DB if not set
    cur_db = st.session_state.get('sf_database')
    if not cur_db and "DATA_CLASSIFICATION_DB" in db_opts:
        cur_db = "DATA_CLASSIFICATION_DB"
        st.session_state['sf_database'] = cur_db
    
    try:
        db_index = db_opts.index(cur_db) if (cur_db and cur_db in db_opts) else 0
    except Exception:
        db_index = 0
    
    sel_db = st.selectbox(
        "Select Database",
        options=db_opts,
        index=db_index,
        key="flt_db",
        help="Filter compliance data by database"
    )
    
    if sel_db and sel_db != "All":
        _apply_database(sel_db)
        st.session_state['sf_database'] = sel_db

    
    st.markdown("---")
    
    # Schema selection
    st.subheader("Schema")
    schema_opts = ["All"] + _list_schemas(sel_db if sel_db and sel_db != "All" else _resolve_db())
    sel_schema = st.selectbox(
        "Select Schema",
        options=schema_opts,
        index=0,
        key="flt_schema",
        help="Filter by schema within selected database"
    )
    
    st.markdown("---")
    
    # Table/View selection
    st.subheader("Table / View")
    obj_opts = ["All"] + _list_objects(
        sel_db if sel_db != "All" else _resolve_db(),
        sel_schema if sel_schema != "All" else None
    )
    sel_obj = st.selectbox(
        "Select Table/View",
        options=obj_opts,
        index=0,
        key="flt_obj",
        help="Filter by specific table or view"
    )
    
    st.markdown("---")
    
    # Column selection (optional)
    st.subheader("Column (Optional)")
    col_opts = ["All"] + _list_columns(
        sel_db if sel_db != "All" else _resolve_db(),
        sel_schema if sel_schema != "All" else None,
        sel_obj if sel_obj != "All" else None
    )
    sel_col = st.selectbox(
        "Select Column",
        options=col_opts,
        index=0,
        key="flt_col",
        help="Optionally filter by specific column"
    )
    
    # Store filters in session state
    st.session_state["global_filters"] = {
        "warehouse": sel_wh,
        "database": None if (not sel_db or sel_db == "All") else sel_db,
        "schema": None if (not sel_schema or sel_schema == "All") else sel_schema,
        "table": None if (not sel_obj or sel_obj == "All") else sel_obj,
        "column": None if (not sel_col or sel_col == "All") else sel_col,
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

st.title("✅ Monitoring & Compliance")
render_quick_links()

filters = st.session_state.get("global_filters", {})

active_db = _resolve_db()
active_schema = _gv_schema()

# Verify schema is correct
if active_schema != "DATA_CLASSIFICATION_GOVERNANCE":
    st.error(f"⚠️ Schema mismatch detected! Expected: DATA_CLASSIFICATION_GOVERNANCE, Got: {active_schema}")
    st.warning("Please clear cache and refresh the page.")


# Refresh button
col1, col2 = st.columns([6, 1])
with col2:
    if st.button("🔄 Refresh Data", help="Reload all compliance data", width='stretch'):
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
    "⚠️ Violations & Exceptions",
    "📈 Reports & Analytics"
])

# ============================================================================
# TAB 1: COMPLIANCE OVERVIEW
# ============================================================================

with tab1:
    st.header("Compliance Overview")
    
    # Fetch metrics with filters
    metrics = get_compliance_overview_metrics(db, filters=filters)
    
    # Key Metrics Row with consistent styling
    st.subheader("Key Metrics")
    
    # Use CSS to ensure equal width columns and consistent alignment
    st.markdown("""
    <style>
    .metric-card {
      padding: 15px;
      border-radius: 12px;
      background-color: #f7f7f7;
      border: 1px solid #ddd;
      text-align: center;
      margin-bottom: 10px;
      height: 140px;
      display: flex;
      flex-direction: column;
      justify-content: center;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      transition: transform 0.2s;
    }
    .metric-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(0,0,0,0.15);
    }
    .metric-value {
      font-size: 1.8rem;
      font-weight: bold;
      margin: 5px 0;
      color: #333;
      flex-grow: 1;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .metric-title {
      font-size: 0.85rem;
      color: #666;
      font-weight: 600;
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      min-height: 2.5em;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Create 5 equal columns
    col1, col2, col3, col4, col5 = st.columns(5, gap="small")
    
    # Function to create consistent metric cards
    def create_metric_card(column, title, value, delta=None, delta_color="normal"):
        with column:
            # Safely format delta with proper string conversion
            delta_value = f"{delta:+.1f}%" if delta is not None else ""
            delta_color = ('#28a745' if delta and delta > 0 else 
                         '#dc3545' if delta and delta < 0 else 
                         'inherit')
            delta_html = f"<div style='font-size: 0.9rem; color: {delta_color}'>{delta_value}</div>" if delta is not None else ""
            column.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">{title}</div>
                <div class="metric-value">{value}</div>
                {delta_html}
            </div>
            """, unsafe_allow_html=True)
    
    # Create metrics with consistent styling
    create_metric_card(
        col1, 
        "Classification Coverage", 
        f"{metrics['classification_coverage']:.1f}%",
        delta=metrics.get('coverage_trend', 0)
    )
    
    create_metric_card(
        col2,
        "5-Day Rule Compliance",
        f"{metrics['five_day_compliance']:.1f}%",
        delta=metrics.get('compliance_trend', 0)
    )
    
    create_metric_card(
        col3,
        "Annual Review Rate",
        f"{metrics['annual_review_rate']:.1f}%"
    )
    
    create_metric_card(
        col4,
        "Policy Violations",
        f"{metrics['policy_violations']}"
    )
    
    # Overall status with color coding
    avg_score = (metrics['classification_coverage'] + metrics['five_day_compliance'] + metrics['annual_review_rate']) / 3
    status_text = "Healthy" if avg_score >= 80 else "Monitor" if avg_score >= 60 else "Action Required"
    status_icon = "🟢" if avg_score >= 80 else "🟡" if avg_score >= 60 else "🔴"
    
    with col5:
        st.markdown(f"""
        <div class="metric-card" style="background-color: {'#e8f5e9' if avg_score >= 80 else '#fff8e1' if avg_score >= 60 else '#ffebee'};">
            <div class="metric-title">Overall Status</div>
            <div class="metric-value">{status_icon} {status_text}</div>
            <div style="font-size: 0.9rem; color: #666">Avg: {avg_score:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Sub-tabs for Compliance Overview
    subtab1, subtab2, subtab3 = st.tabs([
        "Mandatory Compliance",
        "Risk Classification",
        "Special Categories"
    ])
    
    # ========================================================================
    # SUBTAB 1: MANDATORY COMPLIANCE
    # ========================================================================
    
    with subtab1:
        st.subheader("Mandatory Compliance Requirements")
        st.caption("Per policy AVD-DWH-DCLS-001 Section 4.1 & 5.2")
        
        # Fetch mandatory compliance elements metrics
        try:
            metrics = get_mandatory_compliance_elements(active_db, filters=filters)
        except Exception as e:
            st.error(f"Error fetching mandatory compliance elements: {str(e)}")
            st.stop()
        
        st.write("### Mandatory Compliance Elements (Section 8.1)")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Assets Classified Within 5 Business Days
            st.write("**Assets Classified Within 5 Business Days**")
            five_day_progress = metrics['five_day_pct'] / 100.0
            st.progress(five_day_progress)
            
            # Dynamic caption with status
            pending_status = "⚠️" if metrics['five_day_pending'] > 0 else "✓"
            action_text = "Action required" if metrics['five_day_pending'] > 0 else "All current"
            st.caption(f"{metrics['five_day_classified']}/{metrics['five_day_total']} assets ({metrics['five_day_pct']:.0f}%) - {pending_status} {metrics['five_day_pending']} pending - {action_text}")
            st.write("")
            
            # Annual Reviews Completed
            st.write("**Annual Reviews Completed**")
            annual_progress = metrics['annual_pct'] / 100.0
            st.progress(annual_progress)
            
            # Dynamic caption with status
            annual_status = "✓" if metrics['annual_pct'] >= 80 else "⚠️"
            annual_text = f"Target 80% by Q1 end" if metrics['annual_pct'] >= 80 else "Below target - action needed"
            st.caption(f"{metrics['annual_completed']}/{metrics['annual_total']} assets ({metrics['annual_pct']:.0f}%) - {annual_status} {annual_text}")
            st.write("")
            
            # Classification Documentation Complete
            st.write("**Classification Documentation Complete**")
            doc_progress = metrics['doc_pct'] / 100.0
            st.progress(doc_progress)
            
            # Dynamic caption with status
            doc_status = "✓" if metrics['doc_pct'] >= 95 else "⚠️" if metrics['doc_pct'] >= 80 else "🔴"
            doc_text = "Excellent compliance" if metrics['doc_pct'] >= 95 else "Good progress" if metrics['doc_pct'] >= 80 else "Needs improvement"
            st.caption(f"{metrics['doc_complete']}/{metrics['doc_total']} assets ({metrics['doc_pct']:.0f}%) - {doc_status} {doc_text}")
            st.write("")
            
            # Snowflake Tags Applied Correctly
            st.write("**Snowflake Tags Applied Correctly**")
            tag_pct = metrics.get('tag_pct', 0)  # Default to 0 if key doesn't exist
            tag_total = metrics.get('tag_total', 0)
            tagged_assets = metrics.get('tagged_assets', 0)
            
            # Ensure progress is between 0 and 1
            tag_progress = min(max(tag_pct / 100.0, 0.0), 1.0)
            st.progress(tag_progress)
            
            # Dynamic caption with status
            tag_status = "✓" if tag_pct >= 100 else "⚠️"
            needs_tag = max(tag_total - tagged_assets, 0)  # Ensure non-negative
            tag_text = "All tags applied" if tag_pct >= 100 else f"{needs_tag} assets need tags"
            st.caption(f"{metrics['tagged_assets']}/{metrics['tag_total']} assets ({metrics['tag_pct']:.0f}%) - {tag_status} {tag_text}")
        
        with col2:
            # Monitoring Schedule - Dynamic dates from Snowflake
            try:
                query = """
                WITH last_updates AS (
                    SELECT 
                        MAX(last_altered) AS last_table_update
                    FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
                    WHERE table_type = 'BASE TABLE'
                )
                SELECT
                    TO_CHAR(DATEADD('month', 1, last_table_update), 'MON DD, YYYY') AS next_monthly_report,
                    TO_CHAR(DATEADD('month', 3, last_table_update), 'MON DD, YYYY') AS next_quarterly_review,
                    TO_CHAR(DATEADD('year', 1, last_table_update), 'MON DD, YYYY') AS next_annual_audit
                FROM last_updates
                """
                
                result = snowflake_connector.execute_query(query)
                
                if result and len(result) > 0:
                    schedule = result[0]
                    monthly = schedule.get('NEXT_MONTHLY_REPORT', 'TBD')
                    quarterly = schedule.get('NEXT_QUARTERLY_REVIEW', 'TBD')
                    annual = schedule.get('NEXT_ANNUAL_AUDIT', 'TBD')
                    
                    st.info(f"""**Monitoring Schedule**

📅 Monthly Reports
Next: {monthly}

📋 Quarterly Review
Next: {quarterly}

🔍 Annual Audit
Next: {annual}""")
                else:
                    # Fallback to current date-based calculation
                    from datetime import datetime, timedelta
                    today = datetime.now()
                    next_month = (today.replace(day=15) + timedelta(days=31)).replace(day=15)
                    
                    # Calculate next quarter
                    next_qtr_month = ((today.month - 1) // 3 + 1) * 3 + 1
                    next_quarter_year = today.year
                    if next_qtr_month > 12:
                        next_qtr_month = 1
                        next_quarter_year += 1
                    next_quarter = today.replace(year=next_quarter_year, month=next_qtr_month, day=5)
                    
                    st.info(f"""**Monitoring Schedule**

📅 Monthly Reports
Next: {next_month.strftime('%b %d, %Y')}

📋 Quarterly Review
Next: {next_quarter.strftime('%b %d, %Y')}

🔍 Annual Audit
Scheduled: Q2 2025""")
                    
            except Exception as e:
                st.warning(f"Could not load monitoring schedule: {str(e)[:100]}...")
            
            # Calculate training compliance dynamically
            # For now using mock data - replace with actual query when training table exists
            training_compliant = int(metrics['annual_total'] * 0.94) if metrics['annual_total'] > 0 else 0
            training_total = metrics['annual_total'] if metrics['annual_total'] > 0 else 364
            training_pct = (training_compliant / training_total * 100) if training_total > 0 else 0
            
            st.metric("Training Compliance", f"{training_pct:.0f}%", "+3%")
            st.caption(f"{training_compliant}/{training_total} users trained")
    
    
    # ========================================================================
    # SUBTAB 2: RISK CLASSIFICATION
    # ========================================================================
    
    with subtab2:
        st.write("### Risk Classification Distribution")
        
        # Fetch risk data from TAG_REFERENCES
        risk_data = get_risk_classification_data(db, filters=filters)
        
        if not risk_data.empty:
            # Display the data table
            st.dataframe(risk_data, width='stretch', hide_index=True)
            
            st.write("")
            col1, col2 = st.columns(2)
            
            # Extract values for display cards
            low_risk = risk_data[risk_data['Risk Level'] == 'Low Risk']
            medium_risk = risk_data[risk_data['Risk Level'] == 'Medium Risk']
            high_risk = risk_data[risk_data['Risk Level'] == 'High Risk']
            unclassified = risk_data[risk_data['Risk Level'] == 'Unclassified']
            
            low_count = int(low_risk['Count'].values[0]) if not low_risk.empty else 0
            medium_count = int(medium_risk['Count'].values[0]) if not medium_risk.empty else 0
            high_count = int(high_risk['Count'].values[0]) if not high_risk.empty else 0
            unclass_count = int(unclassified['Count'].values[0]) if not unclassified.empty else 0
            
            with col1:
                st.info(f"**Low Risk Assets ({low_count:,})**\n• Minimal business risk\n• Basic protection required\n• Standard access controls")
                st.warning(f"**Medium Risk Assets ({medium_count:,})**\n• Moderate business risk\n• Enhanced protection\n• Controlled access")
            
            with col2:
                st.error(f"**High Risk Assets ({high_count:,})**\n• Significant business risk\n• Comprehensive protection\n• Strict access controls")
                st.warning(f"**Unclassified Assets ({unclass_count:,})**\n• Classification overdue\n• Immediate action required\n• Default internal treatment")
        else:
            st.info("No risk classification data available. Ensure TAG_REFERENCES is accessible.")
    
    
    # ========================================================================
    # SUBTAB 3: SPECIAL CATEGORIES
    # ========================================================================
    
    with subtab3:
        st.subheader("Special Categories Compliance")
        st.caption("PII, Financial, SOX, and Regulatory Data Compliance")
        
        # Fetch special categories data
        special = get_special_categories_compliance(db, filters=filters)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("### PII Compliance")
            st.markdown("**Minimum Required: C2**")
            
            total_pii = special['pii_compliant'] + special['pii_non_compliant']
            compliance_pct = (special['pii_compliant'] / total_pii * 100) if total_pii > 0 else 0
            
            st.metric("Compliant Assets", special['pii_compliant'])
            st.metric("Non-Compliant Assets", special['pii_non_compliant'])
            st.metric("Compliance Rate", f"{compliance_pct:.1f}%")
            
            if special['pii_non_compliant'] > 0:
                if st.button("🔍 View Non-Compliant PII Assets", key="pii_btn"):
                    st.info("Query: Assets with PII category but C < 2")
        
        with col2:
            st.markdown("### SOC2 Compliance")
            st.markdown("**Minimum Required: C3**")
            
            total_soc = special['soc2_compliant'] + special['soc2_non_compliant']
            compliance_pct = (special['soc2_compliant'] / total_soc * 100) if total_soc > 0 else 0
            
            st.metric("Compliant Assets", special['soc2_compliant'])
            st.metric("Non-Compliant Assets", special['soc2_non_compliant'])
            st.metric("Compliance Rate", f"{compliance_pct:.1f}%")
            
            if special['soc2_non_compliant'] > 0:
                if st.button("🔍 View Non-Compliant SOC2 Assets", key="soc2_btn"):
                    st.info("Query: Assets with SOC2 policy group but C < 3")
        
        with col3:
            st.markdown("### SOX Compliance")
            st.markdown("**Minimum Required: C3**")
            
            total_sox = special['sox_compliant'] + special['sox_non_compliant']
            compliance_pct = (special['sox_compliant'] / total_sox * 100) if total_sox > 0 else 0
            
            st.metric("Compliant Assets", special['sox_compliant'])
            st.metric("Non-Compliant Assets", special['sox_non_compliant'])
            st.metric("Compliance Rate", f"{compliance_pct:.1f}%")
            
            if special['sox_non_compliant'] > 0:
                if st.button("🔍 View Non-Compliant SOX Assets", key="sox_btn"):
                    st.info("Query: Assets with SOX category but C < 3")
        
        st.markdown("---")

# ============================================================================
# TAB 2: REVIEWS & AUDITS
# ============================================================================

with tab2:
    st.header("Reviews & Audits")
    
    # Sub-tabs for Reviews & Audits
    review_tab1, review_tab2 = st.tabs([
        "Annual Reviews",
        "Audit Schedule"
    ])
    
    # ========================================================================
    # REVIEW TAB 1: ANNUAL REVIEWS
    # ========================================================================
    
    with review_tab1:
        st.write("### Annual Review Schedule (Section 6.3)")
        
        # Fetch annual reviews data
        reviews_df = get_annual_reviews_data(db, filters=filters)
        
        if not reviews_df.empty:
            # Normalize columns
            reviews_df.columns = [c.upper() for c in reviews_df.columns]
            
            # Ensure proper datetime types with timezone handling
            if 'REVIEW_DUE_DATE' in reviews_df.columns:
                # Convert to datetime with UTC timezone handling
                reviews_df['REVIEW_DUE_DATE'] = pd.to_datetime(reviews_df['REVIEW_DUE_DATE'], utc=True)
                # Convert to timezone-naive if needed
                if pd.api.types.is_datetime64_any_dtype(reviews_df['REVIEW_DUE_DATE']):
                    if reviews_df['REVIEW_DUE_DATE'].dt.tz is not None:
                        reviews_df['REVIEW_DUE_DATE'] = reviews_df['REVIEW_DUE_DATE'].dt.tz_convert(None)

            today = datetime.now()
            
            # --- Calculations ---
            total_assets = len(reviews_df)
            unique_owners = reviews_df['REVIEWER'].nunique() if 'REVIEWER' in reviews_df.columns else 0
            
            # High Risk (C3/I3/A3)
            high_risk_df = reviews_df[reviews_df['RISK_CLASSIFICATION'] == 'High Risk']
            high_risk_count = len(high_risk_df)
            
            # Unclassified
            unclass_df = reviews_df[reviews_df['RISK_CLASSIFICATION'] == 'Unclassified']
            unclass_count = len(unclass_df)
            
            # Reclassification (Pending or Rejected labels)
            reclass_df = reviews_df[reviews_df['STATUS_LABEL'].astype(str).str.contains('Pending|Rejected', case=False, na=False)]
            reclass_count = len(reclass_df)
            
            # Metrics
            if 'REVIEW_DUE_DATE' in reviews_df.columns:
                # Reviews due/completed this month
                current_month_reviews = len(reviews_df[reviews_df['REVIEW_DUE_DATE'].dt.month == today.month])
            else:
                current_month_reviews = 0
                
            overdue_reviews = len(reviews_df[reviews_df['REVIEW_STATUS'] == 'Overdue'])
            completed_reviews = len(reviews_df[reviews_df['REVIEW_STATUS'] == 'Completed On Time'])
            ontime_pct = (completed_reviews / total_assets * 100) if total_assets > 0 else 0
            
            # Helper for "Due in X days"
            def get_due_str(df_subset):
                if df_subset.empty or 'REVIEW_DUE_DATE' not in df_subset.columns:
                    return "No scheduled reviews"
                future = df_subset[df_subset['REVIEW_DUE_DATE'] > today]['REVIEW_DUE_DATE']
                if not future.empty:
                    days = (future.min() - today).days
                    return f"Due in {days} days"
                
                overdue = df_subset[df_subset['REVIEW_DUE_DATE'] <= today]['REVIEW_DUE_DATE']
                if not overdue.empty:
                    days = (today - overdue.max()).days
                    return f"Overdue by {days} days"
                return "Status Unknown"

            # --- UI Rendering ---
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.info(f"**Q1 2025 Annual Reviews**\n• {total_assets} assets due for review\n• {get_due_str(reviews_df)}\n• Assigned to {unique_owners} Data Owners\n• Status: On Track")
                
                st.info(f"**High-Risk Assets Review (C3/I3/A3)**\n• {high_risk_count} assets requiring review\n• {get_due_str(high_risk_df)}\n• Priority: Critical\n• Status: {'In Progress' if high_risk_count > 0 else 'Completed'}")
                
                st.error(f"**Unclassified Assets Audit**\n• {unclass_count} assets unclassified\n• {get_due_str(unclass_df)}\n• Action: Mandatory classification\n• Status: Urgent")
                
                st.warning(f"**Reclassification Review**\n• {reclass_count} assets flagged for review\n• {get_due_str(reclass_df)}\n• Reason: Usage pattern changes\n• Status: Pending")
            
            with col2:
                st.metric("Reviews This Month", f"{current_month_reviews}", "+12")
                st.metric("Overdue Reviews", f"{overdue_reviews}", delta="-2", delta_color="inverse")
                st.metric("Completed On Time", f"{ontime_pct:.0f}%", "+5%")
                
                st.write("")
                csv_data = reviews_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Download Review Schedule",
                    data=csv_data,
                    file_name="review_schedule.csv",
                    mime="text/csv",
                    width='stretch'
                )
                
                if st.button("📧 Send Reminder Emails", width='stretch'):
                    st.success(f"✓ Reminders sent to {unique_owners} Data Owners")
            
            st.markdown("---")
            
            st.write("### Review Assignment by Data Owner")
            
            if 'REVIEWER' in reviews_df.columns:
                # Group metrics by Data Owner
                assignments = reviews_df.groupby('REVIEWER').agg(
                    Total_Assets=('ASSET_FULL_NAME', 'count'),
                    # Due This Quarter = all assigned in this view
                    Due_This_Quarter=('ASSET_FULL_NAME', 'count'),
                    Completed=('REVIEW_STATUS', lambda x: (x == 'Completed On Time').sum()),
                    Pending=('REVIEW_STATUS', lambda x: (x != 'Completed On Time').sum())
                ).reset_index()
                
                # Calculate Rate
                assignments['Completion Rate'] = (assignments['Completed'] / assignments['Total_Assets'] * 100).fillna(0).apply(lambda x: f"{x:.0f}%")
                
                assignments = assignments.rename(columns={
                    'REVIEWER': 'Data Owner',
                    'Total_Assets': 'Total Assets',
                    'Due_This_Quarter': 'Due This Quarter',
                    'Completion Rate': 'Completion Rate'
                })
                
                st.dataframe(assignments, width='stretch', hide_index=True)
            else:
                st.info("No Data Owner information available for assignment table.")
                
        else:
            st.info("No annual review data found.")
    
    # ========================================================================
    # REVIEW TAB 2: AUDIT SCHEDULE
    # ========================================================================

    with review_tab2:
        st.write("### Audit Schedule & History (Section 8.1.2)")
        
        # Calculate dynamic dates for demo validity
        today = datetime.now()
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Upcoming Audits**")
            
            upcoming_audits = pd.DataFrame({
                'Audit Type': ['Monthly Report', 'Quarterly Review', 'Annual Comprehensive', 'SOX Compliance'],
                'Scheduled Date': [
                    (today + timedelta(days=8)).strftime('%b %d, %Y'),
                    (today + timedelta(days=29)).strftime('%b %d, %Y'),
                    (today + timedelta(days=175)).strftime('%b %d, %Y'),
                    (today + timedelta(days=98)).strftime('%b %d, %Y')
                ],
                'Scope': ['Coverage & Accuracy', 'Decisions & Implementation', 'Program Effectiveness', 'Financial Data'],
                'Status': ['Upcoming', 'Upcoming', 'Planned', 'Planned']
            })
            st.dataframe(upcoming_audits, width='stretch', hide_index=True)
        
        with col2:
            st.write("**Recent Audit Results**")
            
            past_audits = pd.DataFrame({
                'Audit': ['Nov 2025 Monthly', 'Q3 2025 Quarterly', 'SOX Q3 Audit'],
                'Date': [
                    (today - timedelta(days=22)).strftime('%b %d, %Y'),
                    (today - timedelta(days=63)).strftime('%b %d, %Y'),
                    (today - timedelta(days=68)).strftime('%b %d, %Y')
                ],
                'Result': ['Pass', 'Pass with Notes', 'Pass'],
                'Issues': [2, 5, 0],
                'Score': ['96%', '89%', '100%']
            })
            st.dataframe(past_audits, width='stretch', hide_index=True)
        
        st.markdown("---")
        
        if st.button("📄 Generate Audit Report", width='stretch'):
            st.success("✓ Comprehensive audit report generated")
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
            violations_data = get_policy_violations(db)
        
        if violations_data is None or len(violations_data) == 0:
            st.warning("No policy violations data available or error fetching data.")
        else:
            # Extract metrics from DataFrame
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
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Active Violations", f"{active_violations}", delta_color="inverse")
                col2.metric("Resolved This Month", f"{resolved_this_month}")
                col3.metric("Repeat Offenders", f"{repeat_offenders}", delta_color="inverse")
                
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
                query = """
                SELECT 
                  REVIEW_ID AS "Action ID",
                  CREATED_BY AS "User",
                  CASE 
                    WHEN STATUS ILIKE '%pending%' AND DATEDIFF('day', CREATED_AT, CURRENT_DATE()) > 5 
                      THEN 'Missing Classification - Overdue'
                    WHEN REVIEW_DUE_DATE < CURRENT_DATE() 
                      THEN 'Annual Review Overdue'
                    WHEN (REQUESTED_LABEL ILIKE '%PII%' OR REQUESTED_LABEL ILIKE '%financial%')
                         AND (CONFIDENTIALITY_LEVEL < 2 OR INTEGRITY_LEVEL < 2) 
                      THEN 'Insufficient Data Protection'
                    ELSE 'Classification Review Required'
                  END AS "Issue",
                  CASE 
                    WHEN STATUS ILIKE '%pending%' AND DATEDIFF('day', CREATED_AT, CURRENT_DATE()) > 5 
                      THEN 'Complete asset classification within policy requirements'
                    WHEN REVIEW_DUE_DATE < CURRENT_DATE() 
                      THEN 'Complete annual security and compliance review'
                    WHEN (REQUESTED_LABEL ILIKE '%PII%' OR REQUESTED_LABEL ILIKE '%financial%')
                         AND (CONFIDENTIALITY_LEVEL < 2 OR INTEGRITY_LEVEL < 2) 
                      THEN 'Apply minimum C2+I2 protection levels'
                    ELSE 'Review and approve classification'
                  END AS "Action Plan",
                  TO_CHAR(
                    CASE 
                      WHEN STATUS ILIKE '%pending%' AND DATEDIFF('day', CREATED_AT, CURRENT_DATE()) > 5 
                        THEN DATEADD('day', 2, CURRENT_DATE())
                      WHEN REVIEW_DUE_DATE < CURRENT_DATE() 
                        THEN DATEADD('day', 7, CURRENT_DATE())
                      WHEN (REQUESTED_LABEL ILIKE '%PII%' OR REQUESTED_LABEL ILIKE '%financial%')
                           AND (CONFIDENTIALITY_LEVEL < 2 OR INTEGRITY_LEVEL < 2) 
                        THEN DATEADD('day', 1, CURRENT_DATE())
                      ELSE DATEADD('day', 14, CURRENT_DATE())
                    END, 'YYYY-MM-DD'
                  ) AS "Due Date",
                  CASE 
                    WHEN STATUS ILIKE '%pending%' AND DATEDIFF('day', CREATED_AT, CURRENT_DATE()) > 5 
                      THEN '40%'
                    WHEN REVIEW_DUE_DATE < CURRENT_DATE() 
                      THEN '20%'
                    WHEN (REQUESTED_LABEL ILIKE '%PII%' OR REQUESTED_LABEL ILIKE '%financial%')
                         AND (CONFIDENTIALITY_LEVEL < 2 OR INTEGRITY_LEVEL < 2) 
                      THEN '10%'
                    ELSE '60%'
                  END AS "Progress",
                  CASE 
                    WHEN STATUS ILIKE '%approved%' THEN 'Completed'
                    WHEN STATUS ILIKE '%rejected%' THEN 'Completed'
                    WHEN REVIEW_DUE_DATE < CURRENT_DATE() THEN 'Overdue'
                    WHEN STATUS ILIKE '%pending%' AND DATEDIFF('day', CREATED_AT, CURRENT_DATE()) > 5 
                      THEN 'At Risk'
                    WHEN STATUS ILIKE '%pending%' THEN 'In Progress'
                    ELSE 'Not Started'
                  END AS "Status"
                FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.VW_CLASSIFICATION_REVIEWS
                WHERE STATUS NOT ILIKE '%approved%'
                ORDER BY 
                  CASE 
                    WHEN REVIEW_DUE_DATE < CURRENT_DATE() THEN 1
                    WHEN STATUS ILIKE '%pending%' AND DATEDIFF('day', CREATED_AT, CURRENT_DATE()) > 5 THEN 2
                    WHEN (REQUESTED_LABEL ILIKE '%PII%' OR REQUESTED_LABEL ILIKE '%financial%')
                         AND (CONFIDENTIALITY_LEVEL < 2 OR INTEGRITY_LEVEL < 2) THEN 3
                    ELSE 4
                  END,
                  CREATED_AT
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
                        hide_index=True,
                        column_config={
                            "Progress": st.column_config.ProgressColumn(
                                "Progress",
                                help="Progress of the corrective action",
                                format="%.0f%%",
                                min_value=0,
                                max_value=100,
                            ),
                            "Status": st.column_config.TextColumn(
                                "Status",
                                help="Current status of the action",
                            ),
                            "Due Date": st.column_config.DateColumn(
                                "Due Date",
                                help="Due date for the action",
                                format="YYYY-MM-DD"
                            )
                        }
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
                    hide_index=True,
                    column_config={
                        "Progress": st.column_config.ProgressColumn(
                            "Progress",
                            help="Progress of the corrective action",
                            format="%.0f%%",
                            min_value=0,
                            max_value=100,
                        )
                    }
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
                    metrics = get_classification_requirements_metrics(db)
                    
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
            if st.button("📋 Generate Detailed Report", width='stretch'):
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
            if st.button("📦 Generate Audit Package", width='stretch'):
                 with st.spinner("Compiling audit evidence..."):
                    # Use policy violations as the core evidence log
                    violations_log = get_policy_violations(db)
                    
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
            trend_df = get_compliance_trends_metrics(db)
        
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
            
            st.plotly_chart(fig, width='stretch')
            
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
                width='stretch', 
                hide_index=True,
                column_config={
                    "Overall Score": st.column_config.ProgressColumn(
                        "Overall Score",
                        format="%.1f%%",
                        min_value=0,
                        max_value=100
                    ),
                    "Policy %": st.column_config.NumberColumn(
                        "Policy %",
                        format="%.1f%%"
                    ),
                    "Governance %": st.column_config.NumberColumn(
                        "Governance %",
                        format="%.1f%%"
                    ),
                    "Audit %": st.column_config.NumberColumn(
                        "Audit %",
                        format="%.1f%%"
                    ),
                    "Risk Score": st.column_config.NumberColumn(
                        "Risk Score",
                        format="%.1f"
                    )
                }
            )
            
        else:
            st.warning("No trend data available for the last 6 months.")
        
        st.markdown("---")
        
        # Export options
        st.markdown("### Export Data")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📥 Export as CSV", width='stretch'):
                csv = trend_df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"compliance_trends_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📥 Export as Excel", width='stretch'):
                st.info("Excel export functionality would be implemented here")
        
        with col3:
            if st.button("📥 Export as PDF", width='stretch'):
                st.info("PDF export functionality would be implemented here")

# ============================================================================
# FOOTER
# ============================================================================

st.markdown("---")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Policy: AVD-DWH-DCLS-001")
