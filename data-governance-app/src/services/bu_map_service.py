"""
Business Unit Map Service
Manage <DB>.DATA_GOVERNANCE.BUSINESS_UNIT_MAP
Provides ensure, list, upsert, delete, and bulk import.
"""
from typing import List, Dict, Any, Optional
import logging
import csv
import io

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_GOVERNANCE"
TABLE = "BUSINESS_UNIT_MAP"


class BUMapService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        self.ensure_table()

    def ensure_table(self) -> None:
        try:
            self.connector.execute_non_query(
                f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}"
            )
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE} (
                    FULL_NAME STRING,
                    BUSINESS_UNIT STRING
                )
                """
            )
        except Exception as e:
            logger.error(f"Failed to ensure BUSINESS_UNIT_MAP: {e}")

    def list(self, limit: int = 1000) -> List[Dict[str, Any]]:
        try:
            return self.connector.execute_query(
                f"SELECT FULL_NAME, BUSINESS_UNIT FROM {DB}.{SCHEMA}.{TABLE} ORDER BY FULL_NAME LIMIT %(lim)s",
                {"lim": limit},
            )
        except Exception as e:
            logger.error(f"Failed to list BUSINESS_UNIT_MAP: {e}")
            return []

    def upsert(self, full_name: str, business_unit: str) -> None:
        try:
            # Delete then insert to simulate upsert
            self.connector.execute_non_query(
                f"DELETE FROM {DB}.{SCHEMA}.{TABLE} WHERE UPPER(FULL_NAME) = UPPER(%(full)s)",
                {"full": full_name},
            )
            self.connector.execute_non_query(
                f"INSERT INTO {DB}.{SCHEMA}.{TABLE} (FULL_NAME, BUSINESS_UNIT) SELECT %(full)s, %(bu)s",
                {"full": full_name, "bu": business_unit},
            )
        except Exception as e:
            logger.error(f"Failed to upsert BUSINESS_UNIT_MAP: {e}")
            raise

    def delete(self, full_name: str) -> None:
        try:
            self.connector.execute_non_query(
                f"DELETE FROM {DB}.{SCHEMA}.{TABLE} WHERE UPPER(FULL_NAME) = UPPER(%(full)s)",
                {"full": full_name},
            )
        except Exception as e:
            logger.error(f"Failed to delete from BUSINESS_UNIT_MAP: {e}")
            raise

    def import_csv(self, file_bytes: bytes) -> int:
        """Import CSV with columns FULL_NAME,BUSINESS_UNIT. Returns rows processed."""
        try:
            text = file_bytes.decode("utf-8")
            reader = csv.DictReader(io.StringIO(text))
            count = 0
            for row in reader:
                full = (row.get("FULL_NAME") or row.get("full_name") or "").strip()
                bu = (row.get("BUSINESS_UNIT") or row.get("business_unit") or "").strip()
                if not full or not bu:
                    continue
                self.upsert(full, bu)
                count += 1
            return count
        except Exception as e:
            logger.error(f"Failed to import CSV into BUSINESS_UNIT_MAP: {e}")
            raise


bu_map_service = BUMapService()
