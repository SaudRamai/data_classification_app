"""
Unified Metadata Service
- Provides integrated lineage-quality-classification view
- Computes basic compliance risk scoring combining CIA, lineage fanout and quality
"""
from typing import List, Dict, Any, Optional
import logging

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_GOVERNANCE"


class MetadataService:
    def __init__(self) -> None:
        self.connector = snowflake_connector

    def get_unified_records(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Returns unified records with:
        - FULL_NAME
        - CLASSIFICATION_LEVEL and CIA from tags
        - LINEAGE_DOWNSTREAM (count) from ACCOUNT_USAGE.OBJECT_DEPENDENCIES
        - QUALITY_SCORE if available (placeholder 0-100)
        - COMPLIANCE_RISK_SCORE derived from CIA and lineage
        """
        sql = f"""
        WITH inv AS (
          SELECT FULL_NAME, ROW_COUNT
          FROM {DB}.{SCHEMA}.ASSET_INVENTORY
        ),
        tags AS (
          SELECT 
            UPPER(OBJECT_DATABASE||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME) AS FULL,
            MAX(CASE WHEN TAG_NAME = 'DATA_CLASSIFICATION' THEN TAG_VALUE END) AS DATA_CLASSIFICATION,
            MAX(CASE WHEN TAG_NAME = 'CONFIDENTIALITY_LEVEL' THEN TAG_VALUE END) AS C,
            MAX(CASE WHEN TAG_NAME = 'INTEGRITY_LEVEL' THEN TAG_VALUE END) AS I,
            MAX(CASE WHEN TAG_NAME = 'AVAILABILITY_LEVEL' THEN TAG_VALUE END) AS A
          FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
          GROUP BY 1
        ),
        lin AS (
          SELECT 
            UPPER(REFERENCED_DATABASE||'.'||REFERENCED_SCHEMA||'.'||REFERENCED_OBJECT_NAME) AS FULL,
            COUNT(*) AS DOWNSTREAM
          FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
          WHERE REFERENCED_OBJECT_DOMAIN = 'TABLE'
          GROUP BY 1
        )
        SELECT 
          inv.FULL_NAME,
          inv.ROW_COUNT,
          COALESCE(tags.DATA_CLASSIFICATION, 'Unclassified') AS DATA_CLASSIFICATION,
          TRY_TO_NUMBER(tags.C) AS C,
          TRY_TO_NUMBER(tags.I) AS I,
          TRY_TO_NUMBER(tags.A) AS A,
          COALESCE(lin.DOWNSTREAM, 0) AS LINEAGE_DOWNSTREAM,
          /* Placeholder for quality; can be extended to join real metrics table */
          NULL AS QUALITY_SCORE
        FROM inv
        LEFT JOIN tags ON UPPER(inv.FULL_NAME) = tags.FULL
        LEFT JOIN lin ON UPPER(inv.FULL_NAME) = lin.FULL
        LIMIT %(lim)s
        """
        rows = self.connector.execute_query(sql, {"lim": limit})
        for r in rows:
            # Compute compliance risk score: higher CIA + more downstream => higher risk
            c = int(r.get("C") or 0)
            i = int(r.get("I") or 0)
            a = int(r.get("A") or 0)
            downstream = int(r.get("LINEAGE_DOWNSTREAM") or 0)
            base = c * 0.5 + i * 0.3 + a * 0.2
            # Normalize downstream to 0..1 using log scale
            fanout = (1.0 if downstream >= 10 else downstream / 10.0)
            risk = round(min(100.0, (base / 3.0) * 70.0 + fanout * 30.0), 1)
            r["COMPLIANCE_RISK_SCORE"] = risk
        return rows


metadata_service = MetadataService()
