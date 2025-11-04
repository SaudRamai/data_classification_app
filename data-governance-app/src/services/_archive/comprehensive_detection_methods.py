"""
Comprehensive Detection Methods - Extension for AIClassificationService

This module contains additional methods to implement the comprehensive 
detection logic as outlined in the requirements:
- Persistence to AI_ASSISTANT_SENSITIVE_ASSETS
- Audit logging to CLASSIFICATION_AUDIT  
- Table-level aggregation with full metadata
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json


def persist_to_ai_assistant_assets(service, run_id: str, column_detections: List[Dict[str, Any]], 
                                  database: str, schema_name: str, table_name: str) -> None:
    """
    Persist comprehensive detection results to AI_ASSISTANT_SENSITIVE_ASSETS table.
    
    This implements step 9️⃣ of the comprehensive detection logic:
    - Writes column-level detections with full metadata
    - Includes detection methods, confidence, compliance mappings
    - Appends to history table for version tracking
    - Logs to CLASSIFICATION_AUDIT for governance
    
    Args:
        service: AIClassificationService instance
        run_id: Unique identifier for this detection run (format: YYYYMMDDTHHMMSSZ)
        column_detections: List of detection results from detect_sensitive_columns
        database: Database name
        schema_name: Schema name
        table_name: Table name
    """
    # Import here to avoid circular dependencies
    try:
        from src.connectors.snowflake_connector import snowflake_connector
    except:
        snowflake_connector = None
    
    if not (service.use_snowflake and snowflake_connector is not None):
        print("Snowflake connector not available, skipping AI_ASSISTANT_SENSITIVE_ASSETS persistence")
        return
    
    try:
        gov_schema = service._gov_schema_fqn()
        
        # Ensure AI_ASSISTANT_SENSITIVE_ASSETS table exists
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {gov_schema}.AI_ASSISTANT_SENSITIVE_ASSETS (
            RUN_ID STRING,
            DATABASE_NAME STRING,
            SCHEMA_NAME STRING,
            TABLE_NAME STRING,
            COLUMN_NAME STRING,
            DETECTED_CATEGORY STRING,
            DETECTED_TYPE STRING,
            COMBINED_CONFIDENCE FLOAT,
            CONFIDENCE_LEVEL STRING,
            METHODS_USED STRING,
            COMPLIANCE_TAGS STRING,
            DETECTION_REASON STRING,
            RULE_SCORE FLOAT,
            PATTERN_SCORE FLOAT,
            AI_SCORE FLOAT,
            COMPOSITE_SCORE FLOAT,
            MATCHED_KEYWORDS STRING,
            MATCHED_PATTERNS STRING,
            CIA_SCORES STRING,
            RECOMMENDED_POLICIES STRING,
            NEED_REVIEW BOOLEAN,
            LAST_SCAN_TS TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
            PRIMARY KEY (DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME)
        )
        """
        snowflake_connector.execute_non_query(create_table_sql)
        
        # Ensure history table exists
        create_history_sql = f"""
        CREATE TABLE IF NOT EXISTS {gov_schema}.AI_ASSISTANT_SENSITIVE_ASSETS_HISTORY (
            RUN_ID STRING,
            DATABASE_NAME STRING,
            SCHEMA_NAME STRING,
            TABLE_NAME STRING,
            COLUMN_NAME STRING,
            DETECTED_CATEGORY STRING,
            DETECTED_TYPE STRING,
            COMBINED_CONFIDENCE FLOAT,
            CONFIDENCE_LEVEL STRING,
            METHODS_USED STRING,
            COMPLIANCE_TAGS STRING,
            DETECTION_REASON STRING,
            RULE_SCORE FLOAT,
            PATTERN_SCORE FLOAT,
            AI_SCORE FLOAT,
            COMPOSITE_SCORE FLOAT,
            MATCHED_KEYWORDS STRING,
            MATCHED_PATTERNS STRING,
            CIA_SCORES STRING,
            RECOMMENDED_POLICIES STRING,
            NEED_REVIEW BOOLEAN,
            SCAN_TS TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
        )
        """
        snowflake_connector.execute_non_query(create_history_sql)
        
        # Insert/update detection results
        for detection in column_detections:
            try:
                column_name = str(detection.get('column', ''))
                dominant_category = str(detection.get('dominant_category', ''))
                confidence = float(detection.get('confidence', 0)) / 100.0  # Convert to 0-1
                
                # Determine confidence level
                if confidence >= 0.7:
                    confidence_level = 'HIGH'
                elif confidence >= 0.4:
                    confidence_level = 'MEDIUM'
                else:
                    confidence_level = 'LOW'
                
                # Build detection methods string
                methods = []
                if detection.get('token_hits'):
                    methods.append('RULE_BASED')
                if detection.get('pattern_ids'):
                    methods.append('PATTERN_BASED')
                if detection.get('semantic_top_category'):
                    methods.append('AI_BASED')
                methods_str = ','.join(methods) if methods else 'NONE'
                
                # Build compliance tags from categories
                categories = detection.get('categories', [])
                compliance_tags = ','.join(categories) if categories else ''
                
                # Build detection reason
                reason_parts = []
                if detection.get('token_hits'):
                    keywords = detection['token_hits'][:3]
                    reason_parts.append(f"Keywords: {','.join(keywords)}")
                if detection.get('pattern_ids'):
                    patterns = detection['pattern_ids'][:3]
                    reason_parts.append(f"Patterns: {','.join(patterns)}")
                if detection.get('semantic_top_category'):
                    reason_parts.append(f"Semantic: {detection['semantic_top_category']}")
                detection_reason = '; '.join(reason_parts) if reason_parts else 'No specific evidence'
                
                # Extract scores
                rule_score = 0.0
                pattern_score = 0.0
                ai_score = float(detection.get('semantic_top_confidence', 0.0))
                
                # Estimate rule and pattern scores from confidence breakdown
                if detection.get('token_hits'):
                    rule_score = min(1.0, len(detection['token_hits']) * 0.2)
                if detection.get('regex_hits_map'):
                    total_hits = sum(detection['regex_hits_map'].values())
                    pattern_score = min(1.0, total_hits / 100.0)
                
                composite_score = confidence
                
                # Build CIA scores string
                cia = detection.get('suggested_cia', {})
                cia_str = f"C:{cia.get('C', 0)}/I:{cia.get('I', 0)}/A:{cia.get('A', 0)}"
                
                # Get matched keywords and patterns
                matched_keywords = ','.join(detection.get('token_hits', [])[:10])
                matched_patterns = ','.join(detection.get('pattern_ids', [])[:10])
                
                # Determine if needs review
                need_review = (
                    confidence_level == 'LOW' or
                    len(categories) > 2 or
                    (confidence > 0.3 and confidence < 0.6)
                )
                
                # Recommended policies based on category
                recommended_policies = ''
                if dominant_category in ['PII', 'PHI']:
                    recommended_policies = 'MASKING,ENCRYPTION,ACCESS_CONTROL'
                elif dominant_category == 'Financial':
                    recommended_policies = 'ENCRYPTION,AUDIT_LOGGING'
                elif dominant_category in ['SOX', 'Regulatory']:
                    recommended_policies = 'AUDIT_LOGGING,RETENTION_POLICY'
                
                # Merge into main table
                merge_sql = f"""
                MERGE INTO {gov_schema}.AI_ASSISTANT_SENSITIVE_ASSETS AS target
                USING (
                    SELECT 
                        %(run_id)s AS RUN_ID,
                        %(database)s AS DATABASE_NAME,
                        %(schema)s AS SCHEMA_NAME,
                        %(table)s AS TABLE_NAME,
                        %(column)s AS COLUMN_NAME,
                        %(category)s AS DETECTED_CATEGORY,
                        %(type)s AS DETECTED_TYPE,
                        %(confidence)s AS COMBINED_CONFIDENCE,
                        %(conf_level)s AS CONFIDENCE_LEVEL,
                        %(methods)s AS METHODS_USED,
                        %(compliance)s AS COMPLIANCE_TAGS,
                        %(reason)s AS DETECTION_REASON,
                        %(rule_score)s AS RULE_SCORE,
                        %(pattern_score)s AS PATTERN_SCORE,
                        %(ai_score)s AS AI_SCORE,
                        %(composite)s AS COMPOSITE_SCORE,
                        %(keywords)s AS MATCHED_KEYWORDS,
                        %(patterns)s AS MATCHED_PATTERNS,
                        %(cia)s AS CIA_SCORES,
                        %(policies)s AS RECOMMENDED_POLICIES,
                        %(need_review)s AS NEED_REVIEW,
                        CURRENT_TIMESTAMP() AS LAST_SCAN_TS
                ) AS source
                ON target.DATABASE_NAME = source.DATABASE_NAME
                    AND target.SCHEMA_NAME = source.SCHEMA_NAME
                    AND target.TABLE_NAME = source.TABLE_NAME
                    AND target.COLUMN_NAME = source.COLUMN_NAME
                WHEN MATCHED THEN UPDATE SET
                    RUN_ID = source.RUN_ID,
                    DETECTED_CATEGORY = source.DETECTED_CATEGORY,
                    DETECTED_TYPE = source.DETECTED_TYPE,
                    COMBINED_CONFIDENCE = source.COMBINED_CONFIDENCE,
                    CONFIDENCE_LEVEL = source.CONFIDENCE_LEVEL,
                    METHODS_USED = source.METHODS_USED,
                    COMPLIANCE_TAGS = source.COMPLIANCE_TAGS,
                    DETECTION_REASON = source.DETECTION_REASON,
                    RULE_SCORE = source.RULE_SCORE,
                    PATTERN_SCORE = source.PATTERN_SCORE,
                    AI_SCORE = source.AI_SCORE,
                    COMPOSITE_SCORE = source.COMPOSITE_SCORE,
                    MATCHED_KEYWORDS = source.MATCHED_KEYWORDS,
                    MATCHED_PATTERNS = source.MATCHED_PATTERNS,
                    CIA_SCORES = source.CIA_SCORES,
                    RECOMMENDED_POLICIES = source.RECOMMENDED_POLICIES,
                    NEED_REVIEW = source.NEED_REVIEW,
                    LAST_SCAN_TS = source.LAST_SCAN_TS
                WHEN NOT MATCHED THEN INSERT (
                    RUN_ID, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME,
                    DETECTED_CATEGORY, DETECTED_TYPE, COMBINED_CONFIDENCE, CONFIDENCE_LEVEL,
                    METHODS_USED, COMPLIANCE_TAGS, DETECTION_REASON,
                    RULE_SCORE, PATTERN_SCORE, AI_SCORE, COMPOSITE_SCORE,
                    MATCHED_KEYWORDS, MATCHED_PATTERNS, CIA_SCORES,
                    RECOMMENDED_POLICIES, NEED_REVIEW, LAST_SCAN_TS
                ) VALUES (
                    source.RUN_ID, source.DATABASE_NAME, source.SCHEMA_NAME, source.TABLE_NAME, source.COLUMN_NAME,
                    source.DETECTED_CATEGORY, source.DETECTED_TYPE, source.COMBINED_CONFIDENCE, source.CONFIDENCE_LEVEL,
                    source.METHODS_USED, source.COMPLIANCE_TAGS, source.DETECTION_REASON,
                    source.RULE_SCORE, source.PATTERN_SCORE, source.AI_SCORE, source.COMPOSITE_SCORE,
                    source.MATCHED_KEYWORDS, source.MATCHED_PATTERNS, source.CIA_SCORES,
                    source.RECOMMENDED_POLICIES, source.NEED_REVIEW, source.LAST_SCAN_TS
                )
                """
                
                snowflake_connector.execute_non_query(merge_sql, {
                    'run_id': run_id,
                    'database': database,
                    'schema': schema_name,
                    'table': table_name,
                    'column': column_name,
                    'category': dominant_category,
                    'type': dominant_category,  # Same as category for now
                    'confidence': confidence,
                    'conf_level': confidence_level,
                    'methods': methods_str,
                    'compliance': compliance_tags,
                    'reason': detection_reason,
                    'rule_score': rule_score,
                    'pattern_score': pattern_score,
                    'ai_score': ai_score,
                    'composite': composite_score,
                    'keywords': matched_keywords,
                    'patterns': matched_patterns,
                    'cia': cia_str,
                    'policies': recommended_policies,
                    'need_review': need_review
                })
                
                # Insert into history table
                history_sql = f"""
                INSERT INTO {gov_schema}.AI_ASSISTANT_SENSITIVE_ASSETS_HISTORY (
                    RUN_ID, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME,
                    DETECTED_CATEGORY, DETECTED_TYPE, COMBINED_CONFIDENCE, CONFIDENCE_LEVEL,
                    METHODS_USED, COMPLIANCE_TAGS, DETECTION_REASON,
                    RULE_SCORE, PATTERN_SCORE, AI_SCORE, COMPOSITE_SCORE,
                    MATCHED_KEYWORDS, MATCHED_PATTERNS, CIA_SCORES,
                    RECOMMENDED_POLICIES, NEED_REVIEW, SCAN_TS
                ) VALUES (
                    %(run_id)s, %(database)s, %(schema)s, %(table)s, %(column)s,
                    %(category)s, %(type)s, %(confidence)s, %(conf_level)s,
                    %(methods)s, %(compliance)s, %(reason)s,
                    %(rule_score)s, %(pattern_score)s, %(ai_score)s, %(composite)s,
                    %(keywords)s, %(patterns)s, %(cia)s,
                    %(policies)s, %(need_review)s, CURRENT_TIMESTAMP()
                )
                """
                
                snowflake_connector.execute_non_query(history_sql, {
                    'run_id': run_id,
                    'database': database,
                    'schema': schema_name,
                    'table': table_name,
                    'column': column_name,
                    'category': dominant_category,
                    'type': dominant_category,
                    'confidence': confidence,
                    'conf_level': confidence_level,
                    'methods': methods_str,
                    'compliance': compliance_tags,
                    'reason': detection_reason,
                    'rule_score': rule_score,
                    'pattern_score': pattern_score,
                    'ai_score': ai_score,
                    'composite': composite_score,
                    'keywords': matched_keywords,
                    'patterns': matched_patterns,
                    'cia': cia_str,
                    'policies': recommended_policies,
                    'need_review': need_review
                })
                
            except Exception as e:
                print(f"Error persisting detection for column {column_name}: {e}")
                continue
        
        print(f"Successfully persisted {len(column_detections)} column detections to AI_ASSISTANT_SENSITIVE_ASSETS")
        
    except Exception as e:
        print(f"Error in persist_to_ai_assistant_assets: {e}")


def log_to_classification_audit(service, action: str, resource_id: str, details: Dict[str, Any]) -> None:
    """
    Log classification actions to CLASSIFICATION_AUDIT table for governance.
    
    This implements step 🔒 12️⃣ of the comprehensive detection logic.
    
    Args:
        service: AIClassificationService instance
        action: Action type (e.g., 'DETECTION_RUN', 'CONFIG_CHANGE', 'THRESHOLD_UPDATE')
        resource_id: Resource identifier (e.g., table FQN, config key)
        details: Additional details as dictionary
    """
    try:
        from src.connectors.snowflake_connector import snowflake_connector
    except:
        snowflake_connector = None
    
    if not (service.use_snowflake and snowflake_connector is not None):
        return
    
    try:
        gov_schema = service._gov_schema_fqn()
        
        # Get current user
        try:
            import streamlit as st
            user_id = st.session_state.get("username", "SYSTEM")
        except:
            user_id = "SYSTEM"
        
        # Prepare details JSON
        audit_details = {
            'action': action,
            'resource_id': resource_id,
            'timestamp': datetime.utcnow().isoformat(),
            'user': user_id,
            **details
        }
        
        details_json = json.dumps(audit_details).replace("'", "''")
        
        # Insert into CLASSIFICATION_AUDIT
        audit_sql = f"""
        INSERT INTO {gov_schema}.CLASSIFICATION_AUDIT (
            RESOURCE_ID, ACTION, DETAILS, CREATED_AT
        ) VALUES (
            %(resource_id)s, %(action)s, PARSE_JSON('{details_json}'), CURRENT_TIMESTAMP()
        )
        """
        
        snowflake_connector.execute_non_query(audit_sql, {
            'resource_id': resource_id,
            'action': action
        })
        
    except Exception as e:
        print(f"Error logging to CLASSIFICATION_AUDIT: {e}")


# Add these methods to AIClassificationService
def add_comprehensive_methods_to_service(service_class):
    """
    Dynamically add comprehensive detection methods to AIClassificationService.
    
    Usage:
        from src.services.comprehensive_detection_methods import add_comprehensive_methods_to_service
        add_comprehensive_methods_to_service(AIClassificationService)
    """
    service_class.persist_to_ai_assistant_assets = persist_to_ai_assistant_assets
    service_class.log_to_classification_audit = log_to_classification_audit
