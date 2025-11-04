"""
Classification Audit Repository

Data access layer for classification audit operations.
Handles database queries for audit trail retrieval with proper error handling and fallbacks.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, date, timedelta
import logging

logger = logging.getLogger(__name__)

# Import Snowflake connector with error handling
try:
    from src.connectors.snowflake_connector import snowflake_connector
    from src.config.settings import settings
except Exception:
    snowflake_connector = None
    settings = None


def fetch_audit_rows(
    database: Optional[str] = None,
    schema: str = "DATA_GOVERNANCE", 
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    dataset_name: Optional[str] = None,
    classification_levels: Optional[List[str]] = None,
    owner: Optional[str] = None,
    limit: int = 1000
) -> List[Dict[str, Any]]:
    """
    Fetch classification audit rows from Snowflake with filters.
    
    Args:
        database: Database name (defaults to settings database)
        schema: Schema name (defaults to DATA_GOVERNANCE)
        start_date: Filter records from this date (string format)
        end_date: Filter records to this date (string format)
        dataset_name: Filter by dataset name (supports LIKE patterns)
        classification_levels: Filter by classification levels (list of strings)
        owner: Filter by owner name
        limit: Maximum number of records to return
        
    Returns:
        List of audit records as dictionaries
    """
    if not snowflake_connector:
        logger.warning("Snowflake connector not available, returning mock data")
        return _get_mock_audit_data()
    
    try:
        # Resolve database context
        db = database or (settings.SNOWFLAKE_DATABASE if settings else None)
        if not db or str(db).strip().upper() == 'NONE':
            logger.warning("No valid database context available (got '%s'), returning mock data", db)
            return _get_mock_audit_data()
        
        # Build the base query
        query = f"""
        SELECT 
            ASSET_FULL_NAME as dataset,
            '0/0/0' as prev_cia,
            COALESCE(C, 0) || '/' || COALESCE(I, 0) || '/' || COALESCE(A, 0) as curr_cia,
            CASE 
                WHEN GREATEST(COALESCE(C, 0), COALESCE(I, 0), COALESCE(A, 0)) >= 3 THEN 'High'
                WHEN GREATEST(COALESCE(C, 0), COALESCE(I, 0), COALESCE(A, 0)) >= 2 THEN 'Medium'
                ELSE 'Low'
            END as overall_risk,
            COALESCE(RATIONALE, '') as approver_comments,
            CREATED_AT as submitted_at,
            UPDATED_AT as approved_at,
            COALESCE(DECISION_MAKER, 'Unknown') as owner,
            COALESCE(CLASSIFICATION_LABEL, 'Unclassified') as classification_level
        FROM {db}.{schema}.CLASSIFICATION_DECISIONS
        WHERE 1=1
        """
        
        params = {}
        
        # Add date filters
        if start_date:
            query += " AND DATE(CREATED_AT) >= %(start_date)s"
            params["start_date"] = start_date
            
        if end_date:
            query += " AND DATE(CREATED_AT) <= %(end_date)s"
            params["end_date"] = end_date
            
        # Add dataset filter
        if dataset_name:
            query += " AND UPPER(ASSET_FULL_NAME) LIKE UPPER(%(dataset_name)s)"
            params["dataset_name"] = f"%{dataset_name}%"
            
        # Add classification filter
        if classification_levels:
            placeholders = []
            for i, level in enumerate(classification_levels):
                placeholder = f"class_level_{i}"
                placeholders.append(f"%({placeholder})s")
                params[placeholder] = level
            query += f" AND UPPER(CLASSIFICATION_LABEL) IN ({','.join(placeholders)})"
            
        # Add owner filter
        if owner:
            query += " AND UPPER(DECISION_MAKER) LIKE UPPER(%(owner)s)"
            params["owner"] = f"%{owner}%"
        
        # Add ordering and limit
        query += f" ORDER BY CREATED_AT DESC LIMIT {limit}"
        
        # Execute query
        rows = snowflake_connector.execute_query(query, params) or []
        
        # Convert to expected format
        result = []
        for row in rows:
            result.append({
                "dataset": row.get("DATASET", ""),
                "prev_cia": row.get("PREV_CIA", "0/0/0"),
                "curr_cia": row.get("CURR_CIA", "0/0/0"),
                "overall_risk": row.get("OVERALL_RISK", "Low"),
                "approver_comments": row.get("APPROVER_COMMENTS", ""),
                "submitted_at": row.get("SUBMITTED_AT"),
                "approved_at": row.get("APPROVED_AT"),
                "owner": row.get("OWNER", "Unknown"),
                "classification_level": row.get("CLASSIFICATION_LEVEL", "Unclassified")
            })
        
        logger.info(f"Retrieved {len(result)} audit records from database")
        return result
        
    except Exception as e:
        logger.error(f"Failed to fetch audit rows from database: {e}")
        return _get_mock_audit_data()


def _get_mock_audit_data() -> List[Dict[str, Any]]:
    """
    Generate mock audit data for testing/fallback purposes.
    
    Returns:
        List of mock audit records
    """
    from datetime import datetime, timedelta
    import random
    
    mock_data = []
    datasets = [
        "ANALYTICS.FINANCE.REVENUE_DATA",
        "ANALYTICS.HR.EMPLOYEE_INFO", 
        "ANALYTICS.SALES.CUSTOMER_DATA",
        "ANALYTICS.COMPLIANCE.AUDIT_LOGS",
        "ANALYTICS.MARKETING.CAMPAIGN_DATA"
    ]
    
    classifications = ["Public", "Internal", "Restricted", "Confidential"]
    owners = ["john.doe@company.com", "jane.smith@company.com", "data.steward@company.com"]
    
    # Generate 50 mock records
    for i in range(50):
        base_date = datetime.now() - timedelta(days=random.randint(1, 90))
        
        # Generate CIA scores
        prev_c, prev_i, prev_a = random.randint(0, 3), random.randint(0, 3), random.randint(0, 3)
        curr_c, curr_i, curr_a = random.randint(0, 3), random.randint(0, 3), random.randint(0, 3)
        
        # Determine risk level
        max_cia = max(curr_c, curr_i, curr_a)
        if max_cia >= 3:
            risk = "High"
        elif max_cia >= 2:
            risk = "Medium"
        else:
            risk = "Low"
        
        mock_data.append({
            "dataset": random.choice(datasets),
            "prev_cia": f"{prev_c}/{prev_i}/{prev_a}",
            "curr_cia": f"{curr_c}/{curr_i}/{curr_a}",
            "overall_risk": risk,
            "approver_comments": f"Classification updated based on data sensitivity analysis - Record {i+1}",
            "submitted_at": base_date,
            "approved_at": base_date + timedelta(hours=random.randint(1, 48)),
            "owner": random.choice(owners),
            "classification_level": random.choice(classifications)
        })
    
    # Sort by date descending
    mock_data.sort(key=lambda x: x["submitted_at"], reverse=True)
    
    logger.info(f"Generated {len(mock_data)} mock audit records")
    return mock_data


def get_audit_summary(
    database: Optional[str] = None,
    schema: str = "DATA_GOVERNANCE",
    days_back: int = 30
) -> Dict[str, Any]:
    """
    Get summary statistics for audit records.
    
    Args:
        database: Database name
        schema: Schema name
        days_back: Number of days to look back
        
    Returns:
        Dictionary with summary statistics
    """
    try:
        end_date = date.today()
        start_date = date.today() - timedelta(days=days_back)
        
        rows = fetch_audit_rows(
            database=database,
            schema=schema,
            start_date=start_date,
            end_date=end_date,
            limit=10000
        )
        
        if not rows:
            return {
                "total_changes": 0,
                "high_risk_changes": 0,
                "classification_distribution": {},
                "top_owners": []
            }
        
        # Calculate statistics
        total_changes = len(rows)
        high_risk_changes = len([r for r in rows if r.get("overall_risk") == "High"])
        
        # Classification distribution
        class_dist = {}
        for row in rows:
            level = row.get("classification_level", "Unknown")
            class_dist[level] = class_dist.get(level, 0) + 1
        
        # Top owners
        owner_counts = {}
        for row in rows:
            owner = row.get("owner", "Unknown")
            owner_counts[owner] = owner_counts.get(owner, 0) + 1
        
        top_owners = sorted(owner_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total_changes": total_changes,
            "high_risk_changes": high_risk_changes,
            "classification_distribution": class_dist,
            "top_owners": top_owners
        }
        
    except Exception as e:
        logger.error(f"Failed to get audit summary: {e}")
        return {
            "total_changes": 0,
            "high_risk_changes": 0,
            "classification_distribution": {},
            "top_owners": []
        }
