"""
Asset Utilities for consistent asset counting and management across the application.
"""
from typing import Dict, Any, Optional, Tuple
import pandas as pd
import io

def get_asset_count_query(assets_table: str, where_clause: str = "", params: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
    """
    Generate a consistent SQL query for counting assets with optional filtering.
    
    Args:
        assets_table: The fully qualified name of the assets table
        where_clause: Optional WHERE clause (without the WHERE keyword)
        params: Optional parameters for the WHERE clause
        
    Returns:
        Tuple of (sql_query, params_dict)
    """
    params = params or {}
    
    sql = f"""
    SELECT 
        COUNT(*) as TOTAL_ASSETS,
        SUM(CASE 
            WHEN CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND CLASSIFICATION_LABEL != 'Unclassified' 
            THEN 1 ELSE 0 
        END) as CLASSIFIED_COUNT,
        SUM(CASE 
            WHEN CLASSIFICATION_LABEL IS NULL OR CLASSIFICATION_LABEL = '' OR CLASSIFICATION_LABEL = 'Unclassified' 
            THEN 1 ELSE 0 
        END) as UNCLASSIFIED_COUNT,
        IFF(COUNT(*)=0, 0, 
            ROUND(100.0 * 
                SUM(CASE 
                    WHEN CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND CLASSIFICATION_LABEL != 'Unclassified' 
                    THEN 1 ELSE 0 
                END) / 
                COUNT(*), 2)) as COVERAGE_PCT
    FROM {assets_table}
    {where_clause}
    """
    
    return sql, params

def get_asset_counts(assets_table: str, where_clause: str = "", params: Optional[Dict[str, Any]] = None, 
                   snowflake_connector=None) -> Dict[str, Any]:
    """
    Get asset counts with optional filtering.
    
    Args:
        assets_table: The fully qualified name of the assets table
        where_clause: Optional WHERE clause (without the WHERE keyword)
        params: Optional parameters for the WHERE clause
        snowflake_connector: Optional Snowflake connector instance
        
    Returns:
        Dictionary with asset counts and coverage percentage
    """
    if snowflake_connector is None:
        from src.connectors.snowflake_connector import get_snowflake_connection
        snowflake_connector = get_snowflake_connection()
    
    sql, params = get_asset_count_query(assets_table, where_clause, params)
    
    try:
        result = snowflake_connector.execute_query(sql, params)
        if result and len(result) > 0 and result[0].get('TOTAL_ASSETS', 0) > 0:
            return {
                'total_assets': result[0].get('TOTAL_ASSETS', 0),
                'classified_count': result[0].get('CLASSIFIED_COUNT', 0),
                'unclassified_count': result[0].get('UNCLASSIFIED_COUNT', 0),
                'coverage_pct': float(result[0].get('COVERAGE_PCT', 0) or 0)
            }
    except Exception as e:
        print(f"Error getting asset counts: {str(e)}")

    # Fallback to demo data if query failed or returned 0
    try:
        from src.demo_data import UNCLASSIFIED_ASSETS_TSV
        if UNCLASSIFIED_ASSETS_TSV:
            df = pd.read_csv(io.StringIO(UNCLASSIFIED_ASSETS_TSV), sep='\t')
            if not df.empty:
                total = len(df)
                unclassified = len(df[df['CLASSIFICATION_LABEL'] == 'Unclassified'])
                classified = total - unclassified
                coverage = round((classified / total * 100), 2) if total > 0 else 0
                return {
                    'total_assets': total,
                    'classified_count': classified,
                    'unclassified_count': unclassified,
                    'coverage_pct': float(coverage)
                }
    except Exception:
        pass
    
    # Return default values if all else fails
    return {
        'total_assets': 0,
        'classified_count': 0,
        'unclassified_count': 0,
        'coverage_pct': 0.0
    }
