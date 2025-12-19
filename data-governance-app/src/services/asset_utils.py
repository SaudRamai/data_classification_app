
from typing import Dict, Any, Optional, List
import pandas as pd
from datetime import datetime, timedelta

def get_asset_counts(assets_table: str, where_clause: str, params: Dict[str, Any], snowflake_connector) -> Dict[str, Any]:
    """
    Get asset counts and coverage percentage.
    """
    try:
        # Basic counts
        sql = f"""
        SELECT 
            COUNT(*) AS total_assets,
            COUNT(CASE WHEN CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED' THEN 1 END) AS classified_count
        FROM {assets_table}
        {where_clause}
        """
        rows = snowflake_connector.execute_query(sql, params) or []
        if not rows:
            return {
                'total_assets': 0,
                'classified_count': 0,
                'unclassified_count': 0,
                'coverage_pct': 0
            }
        
        total = int(rows[0].get('TOTAL_ASSETS') or 0)
        classified = int(rows[0].get('CLASSIFIED_COUNT') or 0)
        unclassified = total - classified
        coverage = round((classified / total) * 100, 1) if total > 0 else 0
        
        return {
            'total_assets': total,
            'classified_count': classified,
            'unclassified_count': unclassified,
            'coverage_pct': coverage
        }
    except Exception as e:
        return {
            'total_assets': 0,
            'classified_count': 0,
            'unclassified_count': 0,
            'coverage_pct': 0,
            'error': str(e)
        }

def get_health_score_metrics(database: str, schema: str, snowflake_connector) -> Dict[str, Any]:
    """
    Get detailed classification health score metrics using the official schema.
    """
    T_ASSETS = f"{database}.{schema}.ASSETS"
    T_HISTORY = f"{database}.{schema}.CLASSIFICATION_HISTORY"
    
    metrics = {
        'coverage_pct': 0,
        'approval_pct': 0,
        'sla_pct': 0,
        'reviews_pct': 0,
        'total_assets': 0,
        'classified_count': 0,
        'approved_count': 0,
        'within_sla_count': 0,
        'on_time_reviews_count': 0,
        'overall_score': 0
    }
    
    try:
        # 1. Total & Classified (Excluding deprecated/archived via REVIEW_STATUS if lifecycle not present)
        # Based on new DDL, we have REVIEW_STATUS. 
        res = snowflake_connector.execute_query(f"""
            SELECT 
                COUNT(*) as TOTAL,
                COUNT(CASE WHEN CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED' THEN 1 END) as CLASSIFIED
            FROM {T_ASSETS}
            WHERE COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
        """)
        if res:
            metrics['total_assets'] = int(res[0].get('TOTAL') or 0)
            metrics['classified_count'] = int(res[0].get('CLASSIFIED') or 0)
            if metrics['total_assets'] > 0:
                metrics['coverage_pct'] = round((metrics['classified_count'] / metrics['total_assets']) * 100, 1)

        # 2. Approved Classifications (Using PEER_REVIEW_COMPLETED and MANAGEMENT_REVIEW_COMPLETED)
        res = snowflake_connector.execute_query(f"""
            SELECT 
                COUNT(*) as TOTAL,
                COUNT(CASE WHEN PEER_REVIEW_COMPLETED = TRUE AND MANAGEMENT_REVIEW_COMPLETED = TRUE THEN 1 END) as APPROVED
            FROM {T_ASSETS}
            WHERE CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED'
        """)
        if res:
            classified_total = int(res[0].get('TOTAL') or 0)
            metrics['approved_count'] = int(res[0].get('APPROVED') or 0)
            if classified_total > 0:
                metrics['approval_pct'] = round((metrics['approved_count'] / classified_total) * 100, 1)
            else:
                metrics['approval_pct'] = 0

        # 3. Within SLA (5 business days for discovery)
        res = snowflake_connector.execute_query(f"""
            SELECT 
                COUNT(*) as TOTAL,
                COUNT(CASE 
                    WHEN CLASSIFICATION_DATE IS NOT NULL THEN 1 
                    WHEN DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) <= 5 THEN 1 
                    ELSE 0 
                END) as WITHIN_SLA
            FROM {T_ASSETS}
            WHERE COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
        """)
        if res:
            metrics['within_sla_count'] = int(res[0].get('WITHIN_SLA') or 0)
            if metrics['total_assets'] > 0:
                metrics['sla_pct'] = round((metrics['within_sla_count'] / metrics['total_assets']) * 100, 1)

        # 4. Review Completion (On Time)
        res = snowflake_connector.execute_query(f"""
            SELECT 
                COUNT(*) as TOTAL,
                COUNT(CASE WHEN NEXT_REVIEW_DATE >= CURRENT_DATE OR NEXT_REVIEW_DATE IS NULL THEN 1 END) as ON_TIME
            FROM {T_ASSETS}
            WHERE (CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED')
              AND COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
        """)
        if res:
            total_reviews = int(res[0].get('TOTAL') or 0)
            metrics['on_time_reviews_count'] = int(res[0].get('ON_TIME') or 0)
            if total_reviews > 0:
                metrics['reviews_pct'] = round((metrics['on_time_reviews_count'] / total_reviews) * 100, 1)
            else:
                metrics['reviews_pct'] = 100.0
        
        # Overall Score
        metrics['overall_score'] = round(
            (metrics['coverage_pct'] + metrics['approval_pct'] + metrics['sla_pct'] + metrics['reviews_pct']) / 4, 1
        )
        
    except Exception:
        pass # Best effort
        
    return metrics

def get_unclassified_assets_summary(database: str, schema: str, snowflake_connector, limit: int = 10) -> Dict[str, Any]:
    """
    Get summary and list of top unclassified assets.
    """
    T_ASSETS = f"{database}.{schema}.ASSETS"
    
    out = {
        'total_unclassified': 0,
        'new_pending': 0,
        'sla_breached': 0,
        'assets': []
    }
    
    try:
        # 1. Summary Counts
        res = snowflake_connector.execute_query(f"""
            SELECT 
                COUNT(*) as TOTAL,
                COUNT(CASE WHEN DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) <= 2 THEN 1 END) as NEW_PENDING,
                COUNT(CASE WHEN DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) > 5 THEN 1 END) as SLA_BREACHED
            FROM {T_ASSETS}
            WHERE (CLASSIFICATION_LABEL IS NULL OR CLASSIFICATION_LABEL = '' OR UPPER(CLASSIFICATION_LABEL) = 'UNCLASSIFIED')
              AND COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
        """)
        if res:
            out['total_unclassified'] = int(res[0].get('TOTAL') or 0)
            out['new_pending'] = int(res[0].get('NEW_PENDING') or 0)
            out['sla_breached'] = int(res[0].get('SLA_BREACHED') or 0)

        # 2. Detailed List
        assets = snowflake_connector.execute_query(f"""
            SELECT 
                ASSET_NAME,
                DATABASE_NAME || '.' || SCHEMA_NAME as SCOPE,
                COALESCE(DATA_OWNER, 'Unassigned') as OWNER,
                DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) as DAYS_UNCLASSIFIED,
                CASE 
                    WHEN DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) > 5 THEN '🔴 BREACH'
                    WHEN DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) > 2 THEN '🟡 WARNING'
                    ELSE '🟢 NEW'
                END as RISK_STATUS
            FROM {T_ASSETS}
            WHERE (CLASSIFICATION_LABEL IS NULL OR CLASSIFICATION_LABEL = '' OR UPPER(CLASSIFICATION_LABEL) = 'UNCLASSIFIED')
              AND COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
            ORDER BY DAYS_UNCLASSIFIED DESC
            LIMIT {limit}
        """)
        out['assets'] = assets or []
        
    except Exception:
        pass
        
    return out

def get_risk_compliance_summary(database: str, schema: str, snowflake_connector) -> Dict[str, Any]:
    """
    Get summary of risk and compliance metrics.
    """
    T_ASSETS = f"{database}.{schema}.ASSETS"
    
    out = {
        'compliant_count': 0,
        'non_compliant_count': 0,
        'high_risk_count': 0,
        'cia_breakdown': {'C': {}, 'I': {}, 'A': {}}
    }
    
    try:
        # 1. Compliance Counts
        res = snowflake_connector.execute_query(f"""
            SELECT 
                COUNT(CASE WHEN COMPLIANCE_STATUS = 'COMPLIANT' THEN 1 END) as COMPLIANT,
                COUNT(CASE WHEN COMPLIANCE_STATUS = 'NON_COMPLIANT' THEN 1 END) as NON_COMPLIANT,
                COUNT(CASE WHEN OVERALL_RISK_CLASSIFICATION = 'High' THEN 1 END) as HIGH_RISK
            FROM {T_ASSETS}
            WHERE COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
        """)
        if res:
            out['compliant_count'] = int(res[0].get('COMPLIANT') or 0)
            out['non_compliant_count'] = int(res[0].get('NON_COMPLIANT') or 0)
            out['high_risk_count'] = int(res[0].get('HIGH_RISK') or 0)

        # 2. CIA Level Breakdown
        # We assume levels are C1..C3, I1..I3, A1..A3
        for pillar in ['CONFIDENTIALITY', 'INTEGRITY', 'AVAILABILITY']:
            key = pillar[0] # C, I, A
            res = snowflake_connector.execute_query(f"""
                SELECT {pillar}_LEVEL as LEVEL, COUNT(*) as COUNT
                FROM {T_ASSETS}
                WHERE {pillar}_LEVEL IS NOT NULL
                GROUP BY 1
            """)
            if res:
                out['cia_breakdown'][key] = {r['LEVEL']: int(r['COUNT']) for r in res}
                
    except Exception:
        pass
        
    return out

def seed_sample_assets(database: str, schema: str, snowflake_connector) -> Dict[str, Any]:
    """
    Seed the ASSETS table with sample data for the new schema.
    Also ensures the table exists.
    """
    T_ASSETS = f"{database}.{schema}.ASSETS"
    
    # 1. Ensure Table Exists
    create_sql = f"""
    CREATE TABLE IF NOT EXISTS {T_ASSETS} (
        ASSET_ID VARCHAR(100) NOT NULL,
        ASSET_NAME VARCHAR(500) NOT NULL,
        ASSET_TYPE VARCHAR(50) NOT NULL,
        DATABASE_NAME VARCHAR(255),
        SCHEMA_NAME VARCHAR(255),
        OBJECT_NAME VARCHAR(255),
        FULLY_QUALIFIED_NAME VARCHAR(1000),
        BUSINESS_UNIT VARCHAR(100),
        DATA_OWNER VARCHAR(100) NOT NULL,
        DATA_OWNER_EMAIL VARCHAR(255),
        DATA_CUSTODIAN VARCHAR(100),
        DATA_CUSTODIAN_EMAIL VARCHAR(255),
        BUSINESS_PURPOSE VARCHAR(2000),
        DATA_DESCRIPTION VARCHAR(4000),
        CLASSIFICATION_LABEL VARCHAR(20),
        CLASSIFICATION_LABEL_COLOR VARCHAR(20),
        CONFIDENTIALITY_LEVEL VARCHAR(2),
        INTEGRITY_LEVEL VARCHAR(2),
        AVAILABILITY_LEVEL VARCHAR(2),
        OVERALL_RISK_CLASSIFICATION VARCHAR(20),
        PII_RELEVANT BOOLEAN DEFAULT FALSE,
        SOX_RELEVANT BOOLEAN DEFAULT FALSE,
        SOC2_RELEVANT BOOLEAN DEFAULT FALSE,
        CLASSIFICATION_RATIONALE VARCHAR(4000),
        CONFIDENTIALITY_IMPACT_ASSESSMENT VARCHAR(2000),
        INTEGRITY_IMPACT_ASSESSMENT VARCHAR(2000),
        AVAILABILITY_IMPACT_ASSESSMENT VARCHAR(2000),
        CLASSIFICATION_DATE TIMESTAMP_NTZ(9),
        CLASSIFIED_BY VARCHAR(100),
        CLASSIFICATION_METHOD VARCHAR(50),
        LAST_RECLASSIFICATION_DATE TIMESTAMP_NTZ(9),
        RECLASSIFICATION_TRIGGER VARCHAR(500),
        RECLASSIFICATION_COUNT NUMBER(10,0) DEFAULT 0,
        PREVIOUS_CLASSIFICATION_LABEL VARCHAR(20),
        LAST_REVIEW_DATE TIMESTAMP_NTZ(9),
        NEXT_REVIEW_DATE TIMESTAMP_NTZ(9),
        REVIEW_FREQUENCY_DAYS NUMBER(10,0) DEFAULT 365,
        REVIEW_STATUS VARCHAR(50),
        PEER_REVIEW_COMPLETED BOOLEAN DEFAULT FALSE,
        PEER_REVIEWER VARCHAR(100),
        MANAGEMENT_REVIEW_COMPLETED BOOLEAN DEFAULT FALSE,
        MANAGEMENT_REVIEWER VARCHAR(100),
        CONSISTENCY_CHECK_DATE TIMESTAMP_NTZ(9),
        CONSISTENCY_CHECK_STATUS VARCHAR(20),
        DATA_CREATION_DATE TIMESTAMP_NTZ(9),
        DATA_SOURCE_SYSTEM VARCHAR(255),
        DATA_RETENTION_PERIOD_DAYS NUMBER(10,0),
        SENSITIVE_DATA_USAGE_COUNT NUMBER(10,0) DEFAULT 0,
        LAST_ACCESSED_DATE TIMESTAMP_NTZ(9),
        ACCESS_FREQUENCY VARCHAR(20),
        NUMBER_OF_CONSUMERS NUMBER(10,0),
        HAS_EXCEPTION BOOLEAN DEFAULT FALSE,
        EXCEPTION_TYPE VARCHAR(100),
        EXCEPTION_JUSTIFICATION VARCHAR(2000),
        EXCEPTION_APPROVED_BY VARCHAR(100),
        EXCEPTION_APPROVAL_DATE TIMESTAMP_NTZ(9),
        EXCEPTION_EXPIRY_DATE TIMESTAMP_NTZ(9),
        EXCEPTION_MITIGATION_MEASURES VARCHAR(2000),
        COMPLIANCE_STATUS VARCHAR(20),
        NON_COMPLIANCE_REASON VARCHAR(1000),
        CORRECTIVE_ACTION_REQUIRED BOOLEAN DEFAULT FALSE,
        CORRECTIVE_ACTION_DESCRIPTION VARCHAR(2000),
        CORRECTIVE_ACTION_DUE_DATE TIMESTAMP_NTZ(9),
        CREATED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
        CREATED_BY VARCHAR(100),
        LAST_MODIFIED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
        LAST_MODIFIED_BY VARCHAR(100),
        RECORD_VERSION NUMBER(10,0) DEFAULT 1,
        ADDITIONAL_NOTES VARCHAR(4000),
        primary key (ASSET_ID)
    )
    """
    
    # Sample data statements
    statements = [
        create_sql,
        f"DELETE FROM {T_ASSETS}", # Clear old demo data
        f"""
        INSERT INTO {T_ASSETS} (
            ASSET_ID, ASSET_NAME, ASSET_TYPE, DATABASE_NAME, SCHEMA_NAME, DATA_OWNER, 
            CLASSIFICATION_LABEL, CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL, 
            OVERALL_RISK_CLASSIFICATION, COMPLIANCE_STATUS, REVIEW_STATUS,
            CREATED_TIMESTAMP, CLASSIFICATION_DATE, PEER_REVIEW_COMPLETED, MANAGEMENT_REVIEW_COMPLETED
        ) VALUES 
        ('1', 'FIN_JOURNAL_V2', 'TABLE', 'FINANCE', 'ERP', 'Alice Finance', 'Confidential', 'C3', 'I3', 'A1', 'High', 'COMPLIANT', 'Active', DATEADD('day', -10, CURRENT_TIMESTAMP()), DATEADD('day', -8, CURRENT_TIMESTAMP()), TRUE, TRUE),
        ('2', 'HR_EMPLOYEE_LIST', 'TABLE', 'HR', 'PEOPLE', 'Bob HR', 'Unclassified', NULL, NULL, NULL, 'Low', 'NON_COMPLIANT', 'Active', DATEADD('day', -7, CURRENT_TIMESTAMP()), NULL, FALSE, FALSE),
        ('3', 'PUBLIC_WEBSITE_LOGS', 'TABLE', 'MARKETING', 'WEB', 'Charlie Mark', 'Public', 'C1', 'I1', 'A1', 'Low', 'COMPLIANT', 'Active', DATEADD('day', -30, CURRENT_TIMESTAMP()), DATEADD('day', -29, CURRENT_TIMESTAMP()), TRUE, TRUE),
        ('4', 'CUSTOMER_PCI_DATA', 'TABLE', 'SALES', 'STRIPE', 'Dana Sales', 'Restricted', 'C3', 'I2', 'A2', 'High', 'NON_COMPLIANT', 'Active', DATEADD('day', -3, CURRENT_TIMESTAMP()), DATEADD('day', -2, CURRENT_TIMESTAMP()), FALSE, FALSE),
        ('5', 'NEW_CAMPAIGN_2025', 'VIEW', 'MARKETING', 'GROWTH', 'Charlie Mark', 'Unclassified', NULL, NULL, NULL, 'Low', 'COMPLIANT', 'Active', CURRENT_TIMESTAMP(), NULL, FALSE, FALSE)
        """
    ]
    
    results = []
    for s in statements:
        try:
            snowflake_connector.execute_non_query(s)
            results.append("Success")
        except Exception as e:
            results.append(f"Error: {str(e)}")
            
    return {"results": results}

def get_non_compliant_assets_detail(database: str, schema: str, snowflake_connector, limit: int = 15) -> List[Dict[str, Any]]:
    """
    Get detailed list of assets violating governance policies.
    """
    T_ASSETS = f"{database}.{schema}.ASSETS"
    
    sql = f"""
    WITH violations AS (
        SELECT 
            ASSET_NAME,
            DATABASE_NAME || '.' || SCHEMA_NAME as SCOPE,
            COALESCE(DATA_OWNER, 'Unassigned') as OWNER,
            CASE 
                -- Unclassified beyond SLA
                WHEN (CLASSIFICATION_LABEL IS NULL OR CLASSIFICATION_LABEL = '' OR UPPER(CLASSIFICATION_LABEL) = 'UNCLASSIFIED') 
                     AND DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) > 5 
                     THEN 'Unclassified beyond 5-day SLA'
                -- PII without strong CIA levels (C3/I3)
                WHEN PII_RELEVANT = TRUE AND (CONFIDENTIALITY_LEVEL <> 'C3' OR INTEGRITY_LEVEL <> 'I3')
                     THEN 'PII detected with insufficient CIA levels'
                -- Review overdue
                WHEN NEXT_REVIEW_DATE < CURRENT_DATE 
                     THEN 'Classification review is overdue'
                -- Approval missing
                WHEN (CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED')
                     AND (PEER_REVIEW_COMPLETED = FALSE OR MANAGEMENT_REVIEW_COMPLETED = FALSE)
                     THEN 'Classification pending formal approval'
                -- Expired exceptions
                WHEN HAS_EXCEPTION = TRUE AND EXCEPTION_EXPIRY_DATE < CURRENT_DATE
                     THEN 'Governance exception has expired'
                ELSE NULL
            END as REASON,
            CASE 
                WHEN PII_RELEVANT = TRUE AND (CONFIDENTIALITY_LEVEL <> 'C3' OR INTEGRITY_LEVEL <> 'I3') THEN 'Critical'
                WHEN HAS_EXCEPTION = TRUE AND EXCEPTION_EXPIRY_DATE < CURRENT_DATE THEN 'Critical'
                WHEN (CLASSIFICATION_LABEL IS NULL OR CLASSIFICATION_LABEL = '' OR UPPER(CLASSIFICATION_LABEL) = 'UNCLASSIFIED') 
                     AND DATEDIFF('day', COALESCE(CREATED_TIMESTAMP, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) > 5 THEN 'High'
                WHEN NEXT_REVIEW_DATE < CURRENT_DATE THEN 'Medium'
                ELSE 'Low'
            END as PRIORITY
        FROM {T_ASSETS}
        WHERE COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
    )
    SELECT * FROM violations 
    WHERE REASON IS NOT NULL
    ORDER BY 
        CASE PRIORITY WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
        ASSET_NAME
    LIMIT {limit}
    """
    try:
        return snowflake_connector.execute_query(sql) or []
    except Exception:
        return []

def get_sensitivity_overview(database: str, schema: str, snowflake_connector) -> Dict[str, Any]:
    """
    Get multi-dimensional sensitivity metrics for distribution charts.
    """
    T_ASSETS = f"{database}.{schema}.ASSETS"
    
    out = {
        'labels': {},           # Restricted, Confidential, etc.
        'pii_count': 0,
        'non_pii_count': 0,
        'regulated': {          # PII, SOX, SOC2
            'PII': 0,
            'SOX': 0,
            'SOC2': 0
        },
        'risk_levels': {}       # High, Medium, Low
    }
    
    try:
        # 1. Label Distribution
        res = snowflake_connector.execute_query(f"""
            SELECT CLASSIFICATION_LABEL, COUNT(*) as COUNT
            FROM {T_ASSETS}
            WHERE CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED'
              AND COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
            GROUP BY 1
        """)
        if res:
            out['labels'] = {r['CLASSIFICATION_LABEL']: int(r['COUNT']) for r in res}

        # 2. PII vs Non-PII
        res = snowflake_connector.execute_query(f"""
            SELECT 
                COUNT(CASE WHEN PII_RELEVANT = TRUE THEN 1 END) as PII,
                COUNT(CASE WHEN PII_RELEVANT = FALSE OR PII_RELEVANT IS NULL THEN 1 END) as NON_PII
            FROM {T_ASSETS}
            WHERE CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED'
              AND COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
        """)
        if res:
            out['pii_count'] = int(res[0].get('PII') or 0)
            out['non_pii_count'] = int(res[0].get('NON_PII') or 0)

        # 3. Regulated Clusters
        res = snowflake_connector.execute_query(f"""
            SELECT 
                COUNT(CASE WHEN PII_RELEVANT = TRUE THEN 1 END) as PII,
                COUNT(CASE WHEN SOX_RELEVANT = TRUE THEN 1 END) as SOX,
                COUNT(CASE WHEN SOC2_RELEVANT = TRUE THEN 1 END) as SOC2
            FROM {T_ASSETS}
            WHERE CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED'
              AND COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
        """)
        if res:
            out['regulated'] = {
                'PII': int(res[0].get('PII') or 0),
                'SOX': int(res[0].get('SOX') or 0),
                'SOC2': int(res[0].get('SOC2') or 0)
            }

        # 4. Risk Levels
        res = snowflake_connector.execute_query(f"""
            SELECT OVERALL_RISK_CLASSIFICATION as RISK, COUNT(*) as COUNT
            FROM {T_ASSETS}
            WHERE CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED'
              AND COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
            GROUP BY 1
        """)
        if res:
            out['risk_levels'] = {r['RISK']: int(r['COUNT']) for r in res}
                
    except Exception:
        pass
        
    return out

def get_review_due_summary(database: str, schema: str, snowflake_connector, threshold_days: int = 30) -> Dict[str, Any]:
    """
    Get summary and list of assets due for review.
    """
    T_ASSETS = f"{database}.{schema}.ASSETS"
    
    out = {
        'overdue_count': 0,
        'upcoming_count': 0,
        'total_backlog': 0,
        'assets': []
    }
    
    try:
        # 1. Summary Counts
        res = snowflake_connector.execute_query(f"""
            SELECT 
                COUNT(CASE WHEN NEXT_REVIEW_DATE < CURRENT_DATE THEN 1 END) as OVERDUE,
                COUNT(CASE WHEN NEXT_REVIEW_DATE >= CURRENT_DATE AND NEXT_REVIEW_DATE <= DATEADD('day', {threshold_days}, CURRENT_DATE) THEN 1 END) as UPCOMING
            FROM {T_ASSETS}
            WHERE CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED'
              AND COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
        """)
        if res:
            out['overdue_count'] = int(res[0].get('OVERDUE') or 0)
            out['upcoming_count'] = int(res[0].get('UPCOMING') or 0)
            out['total_backlog'] = out['overdue_count'] + out['upcoming_count']

        # 2. Detailed List
        assets = snowflake_connector.execute_query(f"""
            SELECT 
                ASSET_NAME,
                COALESCE(DATA_OWNER, 'Unassigned') as OWNER,
                NEXT_REVIEW_DATE,
                DATEDIFF('day', CURRENT_DATE, NEXT_REVIEW_DATE) as DAYS_REMAINING,
                CASE 
                    WHEN NEXT_REVIEW_DATE < CURRENT_DATE THEN '🔴 OVERDUE'
                    ELSE '🟡 UPCOMING'
                END as STATUS
            FROM {T_ASSETS}
            WHERE NEXT_REVIEW_DATE <= DATEADD('day', {threshold_days}, CURRENT_DATE)
              AND CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED'
              AND COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
            ORDER BY NEXT_REVIEW_DATE ASC
            LIMIT 10
        """)
        out['assets'] = assets or []
        
    except Exception:
        pass
        
    return out

def get_compliance_coverage_metrics(database: str, schema: str, snowflake_connector) -> Dict[str, Any]:
    """
    Get metrics for regulatory focus and trend summaries.
    """
    T_ASSETS = f"{database}.{schema}.ASSETS"
    
    out = {
        'pii_coverage_pct': 0,
        'sox_count': 0,
        'soc2_count': 0,
        'exception_count': 0,
        'regulated_total': 0,
        'trends': {
            'classification': [], # list of {date: ..., count: ...}
            'risk_reduction': []
        }
    }
    
    try:
        # 1. Direct Counts
        res = snowflake_connector.execute_query(f"""
            SELECT 
                COUNT(*) as TOTAL,
                COUNT(CASE WHEN PII_RELEVANT = TRUE THEN 1 END) as PII_TOTAL,
                COUNT(CASE WHEN PII_RELEVANT = TRUE AND CLASSIFICATION_LABEL IS NOT NULL AND CLASSIFICATION_LABEL <> '' AND UPPER(CLASSIFICATION_LABEL) <> 'UNCLASSIFIED' THEN 1 END) as PII_CLASSIFIED,
                COUNT(CASE WHEN SOX_RELEVANT = TRUE THEN 1 END) as SOX,
                COUNT(CASE WHEN SOC2_RELEVANT = TRUE THEN 1 END) as SOC2,
                COUNT(CASE WHEN HAS_EXCEPTION = TRUE THEN 1 END) as EXCEPTIONS
            FROM {T_ASSETS}
            WHERE COALESCE(REVIEW_STATUS, 'Active') NOT IN ('Deprecated', 'Archived', 'Deleted')
        """)
        if res:
            total_pii = int(res[0].get('PII_TOTAL') or 0)
            classified_pii = int(res[0].get('PII_CLASSIFIED') or 0)
            out['pii_coverage_pct'] = round((classified_pii / max(1, total_pii)) * 100, 1)
            out['sox_count'] = int(res[0].get('SOX') or 0)
            out['soc2_count'] = int(res[0].get('SOC2') or 0)
            out['exception_count'] = int(res[0].get('EXCEPTIONS') or 0)
            out['regulated_total'] = out['sox_count'] + out['soc2_count']

        # 2. Rich Trends (Classification, Non-Compliance, and Risk)
        # We simulate a 6-month historical window for visual impact
        trend_sql = f"""
            SELECT 
                DATE_TRUNC('month', COALESCE(CLASSIFICATION_DATE, CURRENT_TIMESTAMP())) as MONTH,
                COUNT(*) as CLASSIFIED_COUNT,
                COUNT(CASE WHEN COMPLIANCE_STATUS <> 'COMPLIANT' THEN 1 END) as NON_COMPLIANT_COUNT,
                SUM(CASE WHEN OVERALL_RISK_CLASSIFICATION = 'High' THEN 3 WHEN OVERALL_RISK_CLASSIFICATION = 'Medium' THEN 2 ELSE 1 END) as RISK_WEIGHT
            FROM {T_ASSETS}
            GROUP BY 1 ORDER BY 1 ASC
        """
        res_trend = snowflake_connector.execute_query(trend_sql)
        out['trends']['classification'] = res_trend or []

    except Exception:
        pass
        
    return out
