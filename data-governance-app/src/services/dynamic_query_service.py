"""
Dynamic Query Service

Generates Snowflake-compatible SQL to retrieve sensitive/critical objects
based on current tags and policies. Queries are dynamic and reflect latest
TAG_REFERENCES and POLICY_REFERENCES, avoiding manual query edits.

Usage:
- build_sensitive_objects_query(...)
- build_critical_assets_query(...)
- build_column_sensitivity_query(...)
- run_query(sql, params) helper
"""
from __future__ import annotations

from typing import Dict, Any, Optional, List

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings


class DynamicQueryService:
    def __init__(self) -> None:
        self.connector = snowflake_connector

    def run_query(self, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return self.connector.execute_query(sql, params or {})

    def build_sensitive_objects_query(self, database: Optional[str] = None, min_conf_level: int = 2) -> str:
        """Return SQL that lists objects tagged Restricted/Confidential or C>=min_conf_level.
        Includes masking/row access flags when present.
        """
        db = (database or settings.SNOWFLAKE_DATABASE).upper()
        return f"""
        WITH tags AS (
          SELECT 
            UPPER(OBJECT_DATABASE) AS DB,
            UPPER(OBJECT_SCHEMA) AS SCHEMA,
            UPPER(OBJECT_NAME) AS OBJECT,
            MAX(CASE WHEN TAG_NAME = 'DATA_CLASSIFICATION' THEN TAG_VALUE END) AS CLASSIFICATION,
            TRY_TO_NUMBER(MAX(CASE WHEN TAG_NAME = 'CONFIDENTIALITY_LEVEL' THEN TAG_VALUE END)) AS C
          FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
          WHERE OBJECT_DATABASE = '{db}'
          GROUP BY 1,2,3
        ), pol AS (
          SELECT 
            UPPER(OBJECT_DATABASE) AS DB,
            UPPER(OBJECT_SCHEMA) AS SCHEMA,
            UPPER(OBJECT_NAME) AS OBJECT,
            MAX(CASE WHEN POLICY_KIND='MASKING_POLICY' THEN 1 ELSE 0 END) AS HAS_MASKING,
            MAX(CASE WHEN POLICY_KIND='ROW_ACCESS_POLICY' THEN 1 ELSE 0 END) AS HAS_ROW_ACCESS
          FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
          WHERE OBJECT_DATABASE = '{db}'
          GROUP BY 1,2,3
        )
        SELECT 
          t.DB||'.'||t.SCHEMA||'.'||t.OBJECT AS FULL_NAME,
          NVL(t.CLASSIFICATION,'Unclassified') AS CLASSIFICATION,
          NVL(t.C, 0) AS C,
          NVL(p.HAS_MASKING,0) AS HAS_MASKING,
          NVL(p.HAS_ROW_ACCESS,0) AS HAS_ROW_ACCESS
        FROM tags t
        LEFT JOIN pol p USING(DB,SCHEMA,OBJECT)
        WHERE (UPPER(NVL(CLASSIFICATION,'Internal')) IN ('RESTRICTED','CONFIDENTIAL')) OR NVL(C,0) >= {int(min_conf_level)}
        ORDER BY C DESC, CLASSIFICATION DESC, FULL_NAME
        """

    def build_critical_assets_query(self, database: Optional[str] = None) -> str:
        """Return SQL for highest risk assets: combine CIA levels with lineage fanout.
        Uses ACCOUNT_USAGE.OBJECT_DEPENDENCIES for downstream count.
        """
        db = (database or settings.SNOWFLAKE_DATABASE).upper()
        return f"""
        WITH t AS (
          SELECT 
            UPPER(OBJECT_DATABASE) AS DB,
            UPPER(OBJECT_SCHEMA) AS SCHEMA,
            UPPER(OBJECT_NAME) AS OBJECT,
            MAX(CASE WHEN TAG_NAME='DATA_CLASSIFICATION' THEN TAG_VALUE END) AS CLASSIFICATION,
            TRY_TO_NUMBER(MAX(CASE WHEN TAG_NAME='CONFIDENTIALITY_LEVEL' THEN TAG_VALUE END)) AS C,
            TRY_TO_NUMBER(MAX(CASE WHEN TAG_NAME='INTEGRITY_LEVEL' THEN TAG_VALUE END)) AS I,
            TRY_TO_NUMBER(MAX(CASE WHEN TAG_NAME='AVAILABILITY_LEVEL' THEN TAG_VALUE END)) AS A
          FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
          WHERE OBJECT_DATABASE = '{db}'
          GROUP BY 1,2,3
        ), lin AS (
          SELECT 
            UPPER(REFERENCED_DATABASE) AS DB,
            UPPER(REFERENCED_SCHEMA) AS SCHEMA,
            UPPER(REFERENCED_OBJECT_NAME) AS OBJECT,
            COUNT(*) AS DOWNSTREAM
          FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
          WHERE REFERENCED_DATABASE = '{db}' AND REFERENCED_OBJECT_DOMAIN='TABLE'
          GROUP BY 1,2,3
        )
        SELECT 
          t.DB||'.'||t.SCHEMA||'.'||t.OBJECT AS FULL_NAME,
          NVL(t.CLASSIFICATION,'Unclassified') AS CLASSIFICATION,
          NVL(t.C,0) AS C, NVL(t.I,0) AS I, NVL(t.A,0) AS A,
          NVL(lin.DOWNSTREAM,0) AS DOWNSTREAM,
          /* risk scoring aligned with metadata_service */
          ROUND(LEAST(100, ((NVL(t.C,0)*0.5 + NVL(t.I,0)*0.3 + NVL(t.A,0)*0.2)/3)*70 + LEAST(1, NVL(lin.DOWNSTREAM,0)/10.0)*30), 1) AS RISK_SCORE
        FROM t
        LEFT JOIN lin USING(DB,SCHEMA,OBJECT)
        ORDER BY RISK_SCORE DESC, DOWNSTREAM DESC
        """

    def build_column_sensitivity_query(self, database: Optional[str] = None) -> str:
        """Return SQL to list columns tagged as sensitive with categories and applied policies."""
        db = (database or settings.SNOWFLAKE_DATABASE).upper()
        return f"""
        WITH coltags AS (
          SELECT 
            UPPER(OBJECT_DATABASE) AS DB,
            UPPER(OBJECT_SCHEMA) AS SCHEMA,
            UPPER(OBJECT_NAME) AS OBJECT,
            UPPER(COLUMN_NAME) AS COLUMN,
            MAX(CASE WHEN TAG_NAME='DATA_CLASSIFICATION' THEN TAG_VALUE END) AS CLASSIFICATION,
            TRY_TO_NUMBER(MAX(CASE WHEN TAG_NAME='CONFIDENTIALITY_LEVEL' THEN TAG_VALUE END)) AS C
          FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
          WHERE OBJECT_DATABASE = '{db}' AND COLUMN_NAME IS NOT NULL
          GROUP BY 1,2,3,4
        )
        SELECT 
          DB||'.'||SCHEMA||'.'||OBJECT AS TABLE_NAME,
          COLUMN,
          NVL(CLASSIFICATION,'Internal') AS CLASSIFICATION,
          NVL(C,0) AS C
        FROM coltags
        WHERE UPPER(NVL(CLASSIFICATION,'INTERNAL')) IN ('RESTRICTED','CONFIDENTIAL') OR NVL(C,0) >= 2
        ORDER BY TABLE_NAME, COLUMN
        """


dynamic_query_service = DynamicQueryService()
