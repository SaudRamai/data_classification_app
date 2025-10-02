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

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_GOVERNANCE"
INVENTORY = "ASSET_INVENTORY"


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
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{INVENTORY} (
                    FULL_NAME STRING,
                    OBJECT_DOMAIN STRING,
                    ROW_COUNT NUMBER,
                    LAST_DDL_TIME TIMESTAMP_NTZ,
                    FIRST_DISCOVERED TIMESTAMP_NTZ,
                    LAST_SEEN TIMESTAMP_NTZ,
                    CLASSIFICATION_LEVEL STRING,
                    CIA_CONF NUMBER,
                    CIA_INT NUMBER,
                    CIA_AVAIL NUMBER,
                    QUEUE_PRIORITY NUMBER,
                    CLASSIFIED BOOLEAN,
                    PRIMARY KEY (FULL_NAME)
                )
                """
            )
            # Secondary view for prioritized queue
            self.connector.execute_non_query(
                f"""
                CREATE OR REPLACE VIEW {DB}.{SCHEMA}.CLASSIFICATION_QUEUE AS
                SELECT *
                FROM {DB}.{SCHEMA}.{INVENTORY}
                WHERE COALESCE(CLASSIFIED, FALSE) = FALSE
                ORDER BY QUEUE_PRIORITY DESC, ROW_COUNT DESC, LAST_SEEN DESC
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
        for r in rows:
            try:
                self.connector.execute_non_query(
                    f"""
                    MERGE INTO {DB}.{SCHEMA}.{INVENTORY} t
                    USING (
                        SELECT %(full)s AS FULL_NAME, %(dom)s AS OBJECT_DOMAIN, %(rc)s AS ROW_COUNT, %(ddl)s AS LAST_DDL_TIME
                    ) s
                    ON t.FULL_NAME = s.FULL_NAME
                    WHEN MATCHED THEN UPDATE SET 
                        OBJECT_DOMAIN = s.OBJECT_DOMAIN,
                        ROW_COUNT = s.ROW_COUNT,
                        LAST_DDL_TIME = s.LAST_DDL_TIME,
                        LAST_SEEN = CURRENT_TIMESTAMP
                    WHEN NOT MATCHED THEN INSERT (FULL_NAME, OBJECT_DOMAIN, ROW_COUNT, LAST_DDL_TIME, FIRST_DISCOVERED, LAST_SEEN, CLASSIFIED)
                    VALUES (s.FULL_NAME, s.OBJECT_DOMAIN, s.ROW_COUNT, s.LAST_DDL_TIME, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, FALSE)
                    """,
                    {
                        "full": r["FULL_NAME"],
                        "dom": r["OBJECT_DOMAIN"],
                        "rc": r.get("ROW_COUNT", 0),
                        "ddl": r.get("LAST_DDL_TIME"),
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
                SET QUEUE_PRIORITY = (
                    COALESCE(ROW_COUNT,0)/1000 + 
                    CASE WHEN FULL_NAME ILIKE '%CUSTOMER%' OR FULL_NAME ILIKE '%USER%' OR FULL_NAME ILIKE '%PII%' THEN 50 ELSE 0 END +
                    CASE WHEN FULL_NAME ILIKE '%FINANCE%' OR FULL_NAME ILIKE '%PAYROLL%' OR FULL_NAME ILIKE '%INVOICE%' THEN 40 ELSE 0 END
                )
                WHERE CLASSIFIED = FALSE
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
                SET CLASSIFIED = TRUE,
                    CLASSIFICATION_LEVEL = %(cls)s,
                    CIA_CONF = %(c)s,
                    CIA_INT = %(i)s,
                    CIA_AVAIL = %(a)s,
                    LAST_SEEN = CURRENT_TIMESTAMP
                WHERE FULL_NAME = %(full)s
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
