"""
Migration utilities to evolve metadata structures.
Adds BUSINESS_UNIT and REGULATORY to ASSETS and backfills from tags/reference.
"""
from typing import Dict, Any
import logging

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
INV = f"{DB}.{SCHEMA}.ASSETS"


class MigrationService:
    def __init__(self) -> None:
        self.connector = snowflake_connector

    def _table_exists(self, db: str, schema: str, table: str) -> bool:
        try:
            rows = self.connector.execute_query(
                """
                SELECT 1
                FROM INFORMATION_SCHEMA.TABLES
                WHERE TABLE_CATALOG = %(db)s AND TABLE_SCHEMA = %(sch)s AND TABLE_NAME = %(tbl)s
                LIMIT 1
                """,
                {"db": db, "sch": schema, "tbl": table},
            )
            return bool(rows)
        except Exception:
            return False

    def ensure_and_backfill_inventory_bu_regulatory(self) -> Dict[str, Any]:
        # Ensure columns exist
        try:
            self.connector.execute_non_query(
                f"ALTER TABLE {INV} ADD COLUMN IF NOT EXISTS BUSINESS_UNIT STRING"
            )
        except Exception as e:
            logger.warning(f"BUSINESS_UNIT add column warning: {e}")
        try:
            self.connector.execute_non_query(
                f"ALTER TABLE {INV} ADD COLUMN IF NOT EXISTS REGULATORY STRING"
            )
        except Exception as e:
            logger.warning(f"REGULATORY add column warning: {e}")

        # Counts before
        before_bu = self.connector.execute_query(
            f"SELECT COUNT(*) AS C FROM {INV} WHERE COALESCE(BUSINESS_UNIT,'') = ''"
        )[0]["C"]
        before_reg = self.connector.execute_query(
            f"SELECT COUNT(*) AS C FROM {INV} WHERE COALESCE(REGULATORY,'') = ''"
        )[0]["C"]

        # Backfill BUSINESS_UNIT from tag references
        try:
            self.connector.execute_non_query(
                f"""
                UPDATE {INV} inv
                SET BUSINESS_UNIT = COALESCE(inv.BUSINESS_UNIT, src.BUSINESS_UNIT)
                FROM (
                  SELECT UPPER(OBJECT_DATABASE||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME) AS FULL_NAME,
                         ANY_VALUE(TAG_VALUE) AS BUSINESS_UNIT
                  FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                  WHERE UPPER(TAG_NAME) IN ('BUSINESS_UNIT','BUSINESSUNIT','DEPARTMENT','OWNER_BU')
                  GROUP BY 1
                ) src
                WHERE UPPER(inv.FULLY_QUALIFIED_NAME) = src.FULL_NAME
                  AND (inv.BUSINESS_UNIT IS NULL OR inv.BUSINESS_UNIT = '')
                """
            )
        except Exception as e:
            logger.warning(f"BUSINESS_UNIT backfill from tags failed: {e}")

        # Optional reference map
        try:
            if self._table_exists(DB, SCHEMA, "BUSINESS_UNIT_MAP"):
                self.connector.execute_non_query(
                    f"""
                    UPDATE {INV} inv
                    SET BUSINESS_UNIT = COALESCE(inv.BUSINESS_UNIT, map.BUSINESS_UNIT)
                    FROM {DB}.{SCHEMA}.BUSINESS_UNIT_MAP map
                    WHERE UPPER(inv.FULLY_QUALIFIED_NAME) = UPPER(map.FULL_NAME)
                      AND (inv.BUSINESS_UNIT IS NULL OR inv.BUSINESS_UNIT = '')
                    """
                )
        except Exception as e:
            logger.warning(f"BUSINESS_UNIT backfill from reference failed: {e}")

        # Naming convention heuristic from schema name
        try:
            self.connector.execute_non_query(
                f"""
                UPDATE {INV} inv
                SET BUSINESS_UNIT = COALESCE(inv.BUSINESS_UNIT,
                  CASE
                    WHEN UPPER(SPLIT_PART(inv.FULLY_QUALIFIED_NAME, '.', 2)) LIKE 'FIN_%' THEN 'Finance'
                    WHEN UPPER(SPLIT_PART(inv.FULLY_QUALIFIED_NAME, '.', 2)) LIKE 'HR_%' THEN 'HR'
                    WHEN UPPER(SPLIT_PART(inv.FULLY_QUALIFIED_NAME, '.', 2)) LIKE 'MKT_%' THEN 'Marketing'
                    WHEN UPPER(SPLIT_PART(inv.FULLY_QUALIFIED_NAME, '.', 2)) LIKE 'SALES_%' THEN 'Sales'
                    WHEN UPPER(SPLIT_PART(inv.FULLY_QUALIFIED_NAME, '.', 2)) LIKE 'ENG_%' THEN 'Engineering'
                    WHEN UPPER(SPLIT_PART(inv.FULLY_QUALIFIED_NAME, '.', 2)) LIKE 'IT_%' THEN 'IT'
                    WHEN UPPER(SPLIT_PART(inv.FULLY_QUALIFIED_NAME, '.', 2)) LIKE 'OPS_%' THEN 'Operations'
                    ELSE inv.BUSINESS_UNIT
                  END)
                WHERE (inv.BUSINESS_UNIT IS NULL OR inv.BUSINESS_UNIT = '')
                """
            )
        except Exception as e:
            logger.warning(f"BUSINESS_UNIT backfill from naming convention failed: {e}")

        # Backfill REGULATORY from tags patterns
        try:
            self.connector.execute_non_query(
                f"""
                UPDATE {INV} inv
                SET REGULATORY = COALESCE(inv.REGULATORY,
                  CASE
                    WHEN REGEXP_LIKE(src.TAGS, '(HIPAA)') THEN 'HIPAA'
                    WHEN REGEXP_LIKE(src.TAGS, '(GDPR)') THEN 'GDPR'
                    WHEN REGEXP_LIKE(src.TAGS, '(SOX|SOC)') THEN 'SOX/SOC'
                    ELSE inv.REGULATORY
                  END)
                FROM (
                  SELECT UPPER(OBJECT_DATABASE||'.'||OBJECT_SCHEMA||'.'||OBJECT_NAME) AS FULL,
                         LISTAGG(UPPER(COALESCE(TAG_NAME,'')||':'||COALESCE(TAG_VALUE,'')), ',') WITHIN GROUP (ORDER BY TAG_NAME) AS TAGS
                  FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                  GROUP BY 1
                ) src
                WHERE UPPER(inv.FULLY_QUALIFIED_NAME) = src.FULL
                  AND (inv.REGULATORY IS NULL OR inv.REGULATORY = '')
                """
            )
        except Exception as e:
            logger.warning(f"REGULATORY backfill failed: {e}")

        # Counts after
        after_bu = self.connector.execute_query(
            f"SELECT COUNT(*) AS C FROM {INV} WHERE COALESCE(BUSINESS_UNIT,'') = ''"
        )[0]["C"]
        after_reg = self.connector.execute_query(
            f"SELECT COUNT(*) AS C FROM {INV} WHERE COALESCE(REGULATORY,'') = ''"
        )[0]["C"]

        return {
            "business_unit_filled": int(before_bu) - int(after_bu),
            "regulatory_filled": int(before_reg) - int(after_reg),
            "remaining_null_business_unit": int(after_bu),
            "remaining_null_regulatory": int(after_reg),
        }


migration_service = MigrationService()
