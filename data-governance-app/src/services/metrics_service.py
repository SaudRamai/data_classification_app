"""
Metrics Service for Data Governance Dashboard

This service provides various metrics and analytics for the dashboard,
including classification coverage, framework counts, and historical data.
"""
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime, timedelta
from src.connectors.snowflake_connector import snowflake_connector

logger = logging.getLogger(__name__)

class MetricsService:
    def __init__(self):
        self.connector = snowflake_connector

    def classification_coverage(self, database: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculate classification coverage metrics.
        
        Args:
            database: Optional database name to filter results
            
        Returns:
            Dictionary containing coverage metrics
        """
        try:
            # Base query for coverage metrics
            query = """
                SELECT
                    COUNT(*) AS total_assets,
                    COUNT(CASE WHEN classification_label IS NOT NULL AND classification_label != 'UNCLASSIFIED' 
                             THEN 1 END) AS tagged_assets,
                    ROUND(
                        100.0 * COUNT(CASE WHEN classification_label IS NOT NULL AND classification_label != 'UNCLASSIFIED' THEN 1 END) 
                        / NULLIF(COUNT(*), 0), 2
                    ) AS coverage_percent
                FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                WHERE 1=1
            """
            
            # Add database filter if provided
            if database:
                query += f" AND database_name = '{database}'"
            
            # Execute the query
            result = self.connector.execute_query(query)
            
            if result and result[0]:
                total_assets = result[0].get('TOTAL_ASSETS', 0) or 0
                classified_count = result[0].get('TAGGED_ASSETS', 0) or 0
                coverage_pct = result[0].get('COVERAGE_PERCENT', 0) or 0
                unclassified_count = total_assets - classified_count
                
                return {
                    'total_assets': int(total_assets),
                    'classified_count': int(classified_count),
                    'coverage_percentage': float(coverage_pct)
                }
                
            return {
                'total_assets': 0,
                'classified_count': 0,
                'coverage_percentage': 0.0
            }
            
        except Exception as e:
            logger.error(f"Error calculating classification coverage: {str(e)}")
            return {
                'total_assets': 0,
                'classified_count': 0,
                'coverage_percentage': 0.0,
                'error': str(e)
            }

    def framework_counts(self, database: Optional[str] = None) -> Dict[str, int]:
        """
        Get counts by framework.
        
        Args:
            database: Optional database name to filter results
            
        Returns:
            Dictionary with framework counts
        """
        try:
            query = """
                SELECT 
                    COALESCE(framework, 'UNKNOWN') as framework,
                    COUNT(*) as count
                FROM governance.classification_summary
            """
            
            if database:
                query += f" WHERE database_name = '{database}'"
                
            query += " GROUP BY framework ORDER BY count DESC"
            
            results = self.connector.execute_query(query)
            return {row['FRAMEWORK']: row['COUNT'] for row in results if row['FRAMEWORK']}
            
        except Exception as e:
            logger.error(f"Error getting framework counts: {str(e)}")
            return {}

    def historical_classifications(self, days: int = 30, database: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get historical classification data.
        
        Args:
            days: Number of days of history to retrieve
            database: Optional database name to filter results
            
        Returns:
            List of daily classification metrics
        """
        try:
            query = """
                SELECT 
                    DATE(classification_date) as day,
                    classification_status,
                    COUNT(*) as count
                FROM governance.classification_events
                WHERE classification_date >= DATEADD(day, -%s, CURRENT_DATE())
            """
            
            params = [days]
            
            if database:
                query += " AND database_name = %s"
                params.append(database)
                
            query += """
                GROUP BY day, classification_status
                ORDER BY day, classification_status
            """
            
            results = self.connector.execute_query(query, tuple(params))
            return [dict(row) for row in results]
            
        except Exception as e:
            logger.error(f"Error getting historical classifications: {str(e)}")
            return []

    def overdue_unclassified(self, database: Optional[str] = None) -> Dict[str, int]:
        """
        Get count of overdue unclassified assets.
        
        Args:
            database: Optional database name to filter results
            
        Returns:
            Dictionary with overdue counts by risk level
        """
        try:
            query = """
                SELECT 
                    COALESCE(risk_level, 'UNKNOWN') as risk_level,
                    COUNT(*) as count
                FROM governance.unclassified_assets
                WHERE last_scan_date < DATEADD(day, -7, CURRENT_DATE())
            """
            
            if database:
                query += f" AND database_name = '{database}'"
                
            query += " GROUP BY risk_level"
            
            results = self.connector.execute_query(query)
            return {row['RISK_LEVEL']: row['COUNT'] for row in results}
            
        except Exception as e:
            logger.error(f"Error getting overdue unclassified assets: {str(e)}")
            {}

# Singleton instance
metrics_service = MetricsService()
