"""
Tag Manager Service - Tag-Native Architecture

This service provides a logical, application-managed tagging system that is
decoupled from Snowflake's native tagging. It supports:
- Multiple tags per asset
- Multiple tag types
- System-generated + human overrides
- Tag history and versioning
- Optional sync to Snowflake native tags
"""

from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import logging
import json

from src.connectors.snowflake_connector import snowflake_connector

logger = logging.getLogger(__name__)


class TagManager:
    """
    Application-managed tag system with logical abstraction.
    
    Tags are stored in application tables, not directly as Snowflake tags.
    This provides flexibility for:
    - Multi-value tags
    - Tag history
    - Custom tag types
    - Override management
    """
    
    def __init__(self, governance_db: str = "DATA_CLASSIFICATION_DB"):
        self.governance_db = governance_db
        self.governance_schema = "DATA_CLASSIFICATION_GOVERNANCE"
        self._ensure_tag_tables()
    
    def _ensure_tag_tables(self):
        """Ensure tag metadata tables exist."""
        try:
            # Tag Definitions Table
            snowflake_connector.execute_non_query(f"""
                CREATE TABLE IF NOT EXISTS {self.governance_db}.{self.governance_schema}.TAG_DEFINITIONS (
                    TAG_TYPE VARCHAR(100) NOT NULL,
                    TAG_NAME VARCHAR(200) NOT NULL,
                    DESCRIPTION VARCHAR(1000),
                    ALLOWED_VALUES ARRAY,
                    IS_MULTI_VALUE BOOLEAN DEFAULT FALSE,
                    IS_SYSTEM BOOLEAN DEFAULT FALSE,
                    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                    CREATED_BY VARCHAR(200),
                    PRIMARY KEY (TAG_TYPE, TAG_NAME)
                )
            """)
            
            # Asset Tags Table (the main tag storage)
            snowflake_connector.execute_non_query(f"""
                CREATE TABLE IF NOT EXISTS {self.governance_db}.{self.governance_schema}.ASSET_TAGS (
                    ASSET_ID VARCHAR(500) NOT NULL,
                    ASSET_TYPE VARCHAR(50) NOT NULL,
                    TAG_TYPE VARCHAR(100) NOT NULL,
                    TAG_NAME VARCHAR(200) NOT NULL,
                    TAG_VALUE VARIANT NOT NULL,
                    SOURCE VARCHAR(50) DEFAULT 'MANUAL',
                    IS_OVERRIDE BOOLEAN DEFAULT FALSE,
                    APPLIED_BY VARCHAR(200),
                    APPLIED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                    EXPIRES_AT TIMESTAMP_NTZ,
                    METADATA VARIANT,
                    PRIMARY KEY (ASSET_ID, ASSET_TYPE, TAG_TYPE, TAG_NAME)
                )
            """)
            
            # Tag History Table
            snowflake_connector.execute_non_query(f"""
                CREATE TABLE IF NOT EXISTS {self.governance_db}.{self.governance_schema}.TAG_HISTORY (
                    HISTORY_ID NUMBER AUTOINCREMENT,
                    ASSET_ID VARCHAR(500) NOT NULL,
                    ASSET_TYPE VARCHAR(50) NOT NULL,
                    TAG_TYPE VARCHAR(100) NOT NULL,
                    TAG_NAME VARCHAR(200) NOT NULL,
                    OLD_VALUE VARIANT,
                    NEW_VALUE VARIANT,
                    CHANGE_TYPE VARCHAR(20),
                    CHANGED_BY VARCHAR(200),
                    CHANGED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                    REASON VARCHAR(1000),
                    PRIMARY KEY (HISTORY_ID)
                )
            """)
            
            logger.info("Tag metadata tables ensured")
        except Exception as e:
            logger.error(f"Failed to create tag tables: {e}")
    
    def register_tag_type(
        self,
        tag_type: str,
        tag_name: str,
        description: str = None,
        allowed_values: List[str] = None,
        is_multi_value: bool = False,
        is_system: bool = False,
        created_by: str = "SYSTEM"
    ) -> bool:
        """Register a new tag type in the system."""
        try:
            query = f"""
                MERGE INTO {self.governance_db}.{self.governance_schema}.TAG_DEFINITIONS AS target
                USING (
                    SELECT 
                        %(tag_type)s AS TAG_TYPE,
                        %(tag_name)s AS TAG_NAME,
                        %(description)s AS DESCRIPTION,
                        PARSE_JSON(%(allowed_values)s) AS ALLOWED_VALUES,
                        %(is_multi_value)s AS IS_MULTI_VALUE,
                        %(is_system)s AS IS_SYSTEM,
                        %(created_by)s AS CREATED_BY
                ) AS source
                ON target.TAG_TYPE = source.TAG_TYPE AND target.TAG_NAME = source.TAG_NAME
                WHEN MATCHED THEN UPDATE SET
                    DESCRIPTION = source.DESCRIPTION,
                    ALLOWED_VALUES = source.ALLOWED_VALUES,
                    IS_MULTI_VALUE = source.IS_MULTI_VALUE
                WHEN NOT MATCHED THEN INSERT (
                    TAG_TYPE, TAG_NAME, DESCRIPTION, ALLOWED_VALUES, 
                    IS_MULTI_VALUE, IS_SYSTEM, CREATED_BY
                ) VALUES (
                    source.TAG_TYPE, source.TAG_NAME, source.DESCRIPTION, 
                    source.ALLOWED_VALUES, source.IS_MULTI_VALUE, 
                    source.IS_SYSTEM, source.CREATED_BY
                )
            """
            
            snowflake_connector.execute_non_query(query, {
                'tag_type': tag_type,
                'tag_name': tag_name,
                'description': description or '',
                'allowed_values': json.dumps(allowed_values or []),
                'is_multi_value': is_multi_value,
                'is_system': is_system,
                'created_by': created_by
            })
            
            return True
        except Exception as e:
            logger.error(f"Failed to register tag type: {e}")
            return False
    
    def apply_tag(
        self,
        asset_id: str,
        asset_type: str,
        tag_type: str,
        tag_name: str,
        tag_value: Any,
        source: str = "MANUAL",
        is_override: bool = False,
        applied_by: str = None,
        metadata: Dict[str, Any] = None
    ) -> bool:
        """
        Apply a tag to an asset.
        
        Args:
            asset_id: Full asset identifier (e.g., DB.SCHEMA.TABLE or DB.SCHEMA.TABLE.COLUMN)
            asset_type: TABLE, COLUMN, SCHEMA, DATABASE
            tag_type: Classification type (e.g., DATA_CLASSIFICATION, SENSITIVITY)
            tag_name: Specific tag name
            tag_value: Tag value (can be string, number, or complex object)
            source: MANUAL, AI, RULE, IMPORT
            is_override: Whether this overrides a system-generated tag
            applied_by: User who applied the tag
            metadata: Additional context (confidence, rationale, etc.)
        """
        try:
            # Record history before applying
            old_value = self.get_tag(asset_id, asset_type, tag_type, tag_name)
            
            query = f"""
                MERGE INTO {self.governance_db}.{self.governance_schema}.ASSET_TAGS AS target
                USING (
                    SELECT 
                        %(asset_id)s AS ASSET_ID,
                        %(asset_type)s AS ASSET_TYPE,
                        %(tag_type)s AS TAG_TYPE,
                        %(tag_name)s AS TAG_NAME,
                        PARSE_JSON(%(tag_value)s) AS TAG_VALUE,
                        %(source)s AS SOURCE,
                        %(is_override)s AS IS_OVERRIDE,
                        %(applied_by)s AS APPLIED_BY,
                        PARSE_JSON(%(metadata)s) AS METADATA
                ) AS source
                ON target.ASSET_ID = source.ASSET_ID 
                   AND target.ASSET_TYPE = source.ASSET_TYPE
                   AND target.TAG_TYPE = source.TAG_TYPE
                   AND target.TAG_NAME = source.TAG_NAME
                WHEN MATCHED THEN UPDATE SET
                    TAG_VALUE = source.TAG_VALUE,
                    SOURCE = source.SOURCE,
                    IS_OVERRIDE = source.IS_OVERRIDE,
                    APPLIED_BY = source.APPLIED_BY,
                    APPLIED_AT = CURRENT_TIMESTAMP(),
                    METADATA = source.METADATA
                WHEN NOT MATCHED THEN INSERT (
                    ASSET_ID, ASSET_TYPE, TAG_TYPE, TAG_NAME, TAG_VALUE,
                    SOURCE, IS_OVERRIDE, APPLIED_BY, METADATA
                ) VALUES (
                    source.ASSET_ID, source.ASSET_TYPE, source.TAG_TYPE, 
                    source.TAG_NAME, source.TAG_VALUE, source.SOURCE,
                    source.IS_OVERRIDE, source.APPLIED_BY, source.METADATA
                )
            """
            
            snowflake_connector.execute_non_query(query, {
                'asset_id': asset_id,
                'asset_type': asset_type.upper(),
                'tag_type': tag_type,
                'tag_name': tag_name,
                'tag_value': json.dumps(tag_value),
                'source': source,
                'is_override': is_override,
                'applied_by': applied_by or 'SYSTEM',
                'metadata': json.dumps(metadata or {})
            })
            
            # Record history
            self._record_tag_history(
                asset_id, asset_type, tag_type, tag_name,
                old_value, tag_value, 'UPDATE' if old_value else 'CREATE',
                applied_by or 'SYSTEM'
            )
            
            return True
        except Exception as e:
            logger.error(f"Failed to apply tag: {e}")
            return False
    
    def apply_tags_bulk(
        self,
        asset_id: str,
        asset_type: str,
        tags: Dict[str, Dict[str, Any]],
        source: str = "MANUAL",
        applied_by: str = None
    ) -> int:
        """
        Apply multiple tags to an asset at once.
        
        Args:
            asset_id: Full asset identifier
            asset_type: TABLE, COLUMN, etc.
            tags: Dict of {tag_type: {tag_name: tag_value}}
            source: MANUAL, AI, RULE
            applied_by: User who applied the tags
            
        Returns:
            Number of tags successfully applied
        """
        count = 0
        for tag_type, tag_data in tags.items():
            for tag_name, tag_value in tag_data.items():
                if self.apply_tag(
                    asset_id, asset_type, tag_type, tag_name, tag_value,
                    source=source, applied_by=applied_by
                ):
                    count += 1
        return count
    
    def get_tag(
        self,
        asset_id: str,
        asset_type: str,
        tag_type: str,
        tag_name: str
    ) -> Optional[Any]:
        """Get a specific tag value for an asset."""
        try:
            query = f"""
                SELECT TAG_VALUE
                FROM {self.governance_db}.{self.governance_schema}.ASSET_TAGS
                WHERE ASSET_ID = %(asset_id)s
                  AND ASSET_TYPE = %(asset_type)s
                  AND TAG_TYPE = %(tag_type)s
                  AND TAG_NAME = %(tag_name)s
                  AND (EXPIRES_AT IS NULL OR EXPIRES_AT > CURRENT_TIMESTAMP())
            """
            
            result = snowflake_connector.execute_query(query, {
                'asset_id': asset_id,
                'asset_type': asset_type.upper(),
                'tag_type': tag_type,
                'tag_name': tag_name
            })
            
            if result and len(result) > 0:
                return result[0].get('TAG_VALUE')
            return None
        except Exception as e:
            logger.error(f"Failed to get tag: {e}")
            return None
    
    def get_all_tags(
        self,
        asset_id: str,
        asset_type: str = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get all tags for an asset.
        
        Returns:
            Dict of {tag_type: {tag_name: {value, source, applied_by, applied_at, metadata}}}
        """
        try:
            where_clause = "WHERE ASSET_ID = %(asset_id)s"
            params = {'asset_id': asset_id}
            
            if asset_type:
                where_clause += " AND ASSET_TYPE = %(asset_type)s"
                params['asset_type'] = asset_type.upper()
            
            where_clause += " AND (EXPIRES_AT IS NULL OR EXPIRES_AT > CURRENT_TIMESTAMP())"
            
            query = f"""
                SELECT 
                    TAG_TYPE, TAG_NAME, TAG_VALUE, SOURCE, 
                    IS_OVERRIDE, APPLIED_BY, APPLIED_AT, METADATA
                FROM {self.governance_db}.{self.governance_schema}.ASSET_TAGS
                {where_clause}
                ORDER BY TAG_TYPE, TAG_NAME
            """
            
            results = snowflake_connector.execute_query(query, params) or []
            
            tags = {}
            for row in results:
                tag_type = row['TAG_TYPE']
                tag_name = row['TAG_NAME']
                
                if tag_type not in tags:
                    tags[tag_type] = {}
                
                tags[tag_type][tag_name] = {
                    'value': row['TAG_VALUE'],
                    'source': row['SOURCE'],
                    'is_override': row['IS_OVERRIDE'],
                    'applied_by': row['APPLIED_BY'],
                    'applied_at': row['APPLIED_AT'],
                    'metadata': row.get('METADATA', {})
                }
            
            return tags
        except Exception as e:
            logger.error(f"Failed to get all tags: {e}")
            return {}
    
    def remove_tag(
        self,
        asset_id: str,
        asset_type: str,
        tag_type: str,
        tag_name: str,
        removed_by: str = None
    ) -> bool:
        """Remove a tag from an asset."""
        try:
            # Get old value for history
            old_value = self.get_tag(asset_id, asset_type, tag_type, tag_name)
            
            query = f"""
                DELETE FROM {self.governance_db}.{self.governance_schema}.ASSET_TAGS
                WHERE ASSET_ID = %(asset_id)s
                  AND ASSET_TYPE = %(asset_type)s
                  AND TAG_TYPE = %(tag_type)s
                  AND TAG_NAME = %(tag_name)s
            """
            
            snowflake_connector.execute_non_query(query, {
                'asset_id': asset_id,
                'asset_type': asset_type.upper(),
                'tag_type': tag_type,
                'tag_name': tag_name
            })
            
            # Record history
            self._record_tag_history(
                asset_id, asset_type, tag_type, tag_name,
                old_value, None, 'DELETE',
                removed_by or 'SYSTEM'
            )
            
            return True
        except Exception as e:
            logger.error(f"Failed to remove tag: {e}")
            return False
    
    def _record_tag_history(
        self,
        asset_id: str,
        asset_type: str,
        tag_type: str,
        tag_name: str,
        old_value: Any,
        new_value: Any,
        change_type: str,
        changed_by: str,
        reason: str = None
    ):
        """Record tag change in history."""
        try:
            query = f"""
                INSERT INTO {self.governance_db}.{self.governance_schema}.TAG_HISTORY (
                    ASSET_ID, ASSET_TYPE, TAG_TYPE, TAG_NAME,
                    OLD_VALUE, NEW_VALUE, CHANGE_TYPE, CHANGED_BY, REASON
                ) VALUES (
                    %(asset_id)s, %(asset_type)s, %(tag_type)s, %(tag_name)s,
                    PARSE_JSON(%(old_value)s), PARSE_JSON(%(new_value)s),
                    %(change_type)s, %(changed_by)s, %(reason)s
                )
            """
            
            snowflake_connector.execute_non_query(query, {
                'asset_id': asset_id,
                'asset_type': asset_type.upper(),
                'tag_type': tag_type,
                'tag_name': tag_name,
                'old_value': json.dumps(old_value) if old_value is not None else 'null',
                'new_value': json.dumps(new_value) if new_value is not None else 'null',
                'change_type': change_type,
                'changed_by': changed_by,
                'reason': reason
            })
        except Exception as e:
            logger.debug(f"Failed to record tag history: {e}")
    
    def get_tag_history(
        self,
        asset_id: str,
        asset_type: str = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get tag change history for an asset."""
        try:
            where_clause = "WHERE ASSET_ID = %(asset_id)s"
            params = {'asset_id': asset_id, 'limit': limit}
            
            if asset_type:
                where_clause += " AND ASSET_TYPE = %(asset_type)s"
                params['asset_type'] = asset_type.upper()
            
            query = f"""
                SELECT *
                FROM {self.governance_db}.{self.governance_schema}.TAG_HISTORY
                {where_clause}
                ORDER BY CHANGED_AT DESC
                LIMIT %(limit)s
            """
            
            return snowflake_connector.execute_query(query, params) or []
        except Exception as e:
            logger.error(f"Failed to get tag history: {e}")
            return []
    
    def sync_to_snowflake_tags(
        self,
        asset_id: str,
        asset_type: str,
        tag_mapping: Dict[str, str] = None
    ) -> bool:
        """
        Optionally sync application tags to Snowflake native tags.
        
        Args:
            asset_id: Full asset identifier
            asset_type: TABLE, COLUMN, etc.
            tag_mapping: Map of {app_tag_type: snowflake_tag_name}
        """
        # This would call the existing tagging_service for backward compatibility
        # Implementation depends on whether you want bidirectional sync
        pass


# Singleton instance
tag_manager = TagManager()


# Seed standard tag types
def seed_standard_tags():
    """Initialize standard classification tag types."""
    standard_tags = [
        {
            'tag_type': 'DATA_CLASSIFICATION',
            'tag_name': 'CLASSIFICATION_LABEL',
            'description': 'Primary data classification label',
            'allowed_values': ['Public', 'Internal', 'Restricted', 'Confidential'],
            'is_system': True
        },
        {
            'tag_type': 'CIA',
            'tag_name': 'CONFIDENTIALITY_LEVEL',
            'description': 'Confidentiality protection level (0-3)',
            'allowed_values': ['0', '1', '2', '3'],
            'is_system': True
        },
        {
            'tag_type': 'CIA',
            'tag_name': 'INTEGRITY_LEVEL',
            'description': 'Integrity protection level (0-3)',
            'allowed_values': ['0', '1', '2', '3'],
            'is_system': True
        },
        {
            'tag_type': 'CIA',
            'tag_name': 'AVAILABILITY_LEVEL',
            'description': 'Availability protection level (0-3)',
            'allowed_values': ['0', '1', '2', '3'],
            'is_system': True
        },
        {
            'tag_type': 'COMPLIANCE',
            'tag_name': 'FRAMEWORKS',
            'description': 'Applicable compliance frameworks',
            'allowed_values': ['PII', 'SOX', 'SOC2', 'HIPAA', 'PCI', 'GDPR', 'CCPA'],
            'is_multi_value': True,
            'is_system': True
        },
        {
            'tag_type': 'SENSITIVITY',
            'tag_name': 'CATEGORIES',
            'description': 'Detected sensitivity categories',
            'is_multi_value': True,
            'is_system': False
        }
    ]
    
    for tag_def in standard_tags:
        tag_manager.register_tag_type(**tag_def)


# Auto-seed on import
try:
    seed_standard_tags()
except Exception as e:
    logger.warning(f"Could not seed standard tags: {e}")
