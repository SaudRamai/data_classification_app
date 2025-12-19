"""
Data Discovery & Inventory Service
- Scans Snowflake INFORMATION_SCHEMA and ACCOUNT_USAGE to discover assets
- Maintains inventory and prioritized classification queue in <DB>.DATA_GOVERNANCE (DB from settings)
"""
from typing import List, Dict, Any
from datetime import datetime
import logging

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

# Resolve DB with fallback
_db_setting = settings.SNOWFLAKE_DATABASE
DB = _db_setting if _db_setting and str(_db_setting).upper() != "NONE" else "DATA_CLASSIFICATION_DB"
SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
INVENTORY = "ASSETS"


class DiscoveryService:
    def __init__(self):
        self.connector = snowflake_connector
        # Avoid import-time DB work; ensure on first use
        self._ensured = False

    def _ensure_tables_once(self) -> None:
        if self._ensured:
            return
        try:
            self.connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}")
            # ASSETS table should already exist from schema init scripts
            pass
            # Secondary view for prioritized queue
            self.connector.execute_non_query(
                f"""
                CREATE OR REPLACE VIEW {DB}.{SCHEMA}.CLASSIFICATION_QUEUE AS
                SELECT *
                FROM {DB}.{SCHEMA}.{INVENTORY}
                WHERE COALESCE(CLASSIFICATION_LABEL, '') = ''
                ORDER BY CREATED_TIMESTAMP DESC
                """
            )
            self._ensured = True
        except Exception as e:
            logger.error(f"Failed to ensure discovery tables: {e}")

    def scan(self, database: str = DB, include_views: bool = True, limit: int = 1000, offset: int = 0) -> int:
        """Scan INFORMATION_SCHEMA for assets and upsert into inventory. Returns upserted count."""
        self._ensure_tables_once()
        obj_types = ("'BASE TABLE'" + (", 'VIEW'" if include_views else ""))
        rows = self.connector.execute_query(
            f"""
            SELECT 
                TABLE_CATALOG || '.' || TABLE_SCHEMA || '.' || TABLE_NAME AS FULL_NAME,
                TABLE_TYPE AS OBJECT_DOMAIN,
                ROW_COUNT,
                LAST_ALTERED AS LAST_DDL_TIME
            FROM {database}.INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA')
            AND TABLE_TYPE IN ({obj_types})
            LIMIT {limit} OFFSET {offset}
            """
        )
        upserted = 0
        # Get current warehouse for tagging the discovery
        try:
            wh_row = self.connector.execute_query("SELECT CURRENT_WAREHOUSE() AS WH")
            active_wh = wh_row[0].get('WH') if wh_row else None
        except Exception:
            active_wh = None

        for r in rows:
            try:
                self.connector.execute_non_query(
                    f"""
                    MERGE INTO {DB}.{SCHEMA}.{INVENTORY} t
                    USING (
                        SELECT 
                            %(full)s AS FULL_NAME, 
                            %(dom)s AS OBJECT_DOMAIN, 
                            %(rc)s AS ROW_COUNT, 
                            %(ddl)s AS LAST_DDL_TIME,
                            %(wh)s AS WAREHOUSE
                    ) s
                    ON t.FULLY_QUALIFIED_NAME = s.FULL_NAME
                    WHEN MATCHED THEN UPDATE SET 
                        ASSET_TYPE = s.OBJECT_DOMAIN,
                        WAREHOUSE_NAME = COALESCE(s.WAREHOUSE, t.WAREHOUSE_NAME),
                        LAST_MODIFIED_TIMESTAMP = CURRENT_TIMESTAMP
                    WHEN NOT MATCHED THEN INSERT (
                        ASSET_ID, FULLY_QUALIFIED_NAME, ASSET_NAME, ASSET_TYPE, 
                        DATABASE_NAME, SCHEMA_NAME, OBJECT_NAME, DATA_OWNER, 
                        WAREHOUSE_NAME, CREATED_TIMESTAMP, LAST_MODIFIED_TIMESTAMP
                    )
                    VALUES (
                        UUID_STRING(), s.FULL_NAME, SPLIT_PART(s.FULL_NAME, '.', 3), s.OBJECT_DOMAIN, 
                        SPLIT_PART(s.FULL_NAME, '.', 1), SPLIT_PART(s.FULL_NAME, '.', 2), SPLIT_PART(s.FULL_NAME, '.', 3), 
                        'SYSTEM', s.WAREHOUSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                    )
                    """,
                    {
                        "full": r["FULL_NAME"],
                        "dom": r["OBJECT_DOMAIN"],
                        "rc": r.get("ROW_COUNT", 0),
                        "ddl": r.get("LAST_DDL_TIME"),
                        "wh": active_wh
                    },
                )
                upserted += 1
            except Exception as e:
                logger.error(f"Inventory upsert failed for {r.get('FULL_NAME')}: {e}")
        # Update queue priority heuristics: higher for larger tables and sensitive names
        try:
            self.connector.execute_non_query(
                f"""
                UPDATE {DB}.{SCHEMA}.{INVENTORY}
                SET CONTAINS_PII = (
                    CASE WHEN FULLY_QUALIFIED_NAME ILIKE '%CUSTOMER%' OR FULLY_QUALIFIED_NAME ILIKE '%USER%' OR FULLY_QUALIFIED_NAME ILIKE '%PII%' THEN TRUE ELSE FALSE END
                ),
                CONTAINS_FINANCIAL_DATA = (
                    CASE WHEN FULLY_QUALIFIED_NAME ILIKE '%FINANCE%' OR FULLY_QUALIFIED_NAME ILIKE '%PAYROLL%' OR FULLY_QUALIFIED_NAME ILIKE '%INVOICE%' THEN TRUE ELSE FALSE END
                )
                WHERE COALESCE(CLASSIFICATION_LABEL, '') = ''
                """
            )
        except Exception as e:
            logger.warning(f"Failed to update queue priorities: {e}")
        return upserted

    def get_queue(self, limit: int = 50) -> List[Dict[str, Any]]:
        self._ensure_tables_once()
        try:
            return self.connector.execute_query(
                f"SELECT * FROM {DB}.{SCHEMA}.CLASSIFICATION_QUEUE LIMIT %(limit)s",
                {"limit": limit},
            )
        except Exception as e:
            logger.error(f"Failed to fetch classification queue: {e}")
            return []

    def mark_classified(self, full_name: str, cls: str, c: int, i: int, a: int) -> None:
        self._ensure_tables_once()
        try:
            self.connector.execute_non_query(
                f"""
                UPDATE {DB}.{SCHEMA}.{INVENTORY}
                SET CLASSIFICATION_LABEL = %(cls)s,
                    CONFIDENTIALITY_LEVEL = %(c)s,
                    INTEGRITY_LEVEL = %(i)s,
                    AVAILABILITY_LEVEL = %(a)s,
                    CLASSIFICATION_DATE = CURRENT_TIMESTAMP,
                    LAST_MODIFIED_TIMESTAMP = CURRENT_TIMESTAMP
                WHERE FULLY_QUALIFIED_NAME = %(full)s
                """,
                {"full": full_name, "cls": cls, "c": c, "i": i, "a": a},
            )
        except Exception as e:
            logger.error(f"Failed to mark asset classified {full_name}: {e}")

    def full_scan(self, database: str = DB, include_views: bool = True, batch_size: int = 1000, max_batches: int = 1000) -> int:
        """
        Run a complete inventory scan in batches until all assets are processed or max_batches reached.
        Returns total upserted.
        """
        self._ensure_tables_once()
        total = 0
        offset = 0
        batches = 0
        while batches < max_batches:
            count = self.scan(database=database, include_views=include_views, limit=batch_size, offset=offset)
            total += count
            if count < batch_size:
                break
            offset += batch_size
            batches += 1
        return total


discovery_service = DiscoveryService()
