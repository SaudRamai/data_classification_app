"""
AI Sensitive Tables Service

This service provides functionality for the Sensitive Tables Overview sub-tab in the AI Assistant section.
It handles discovery, display, and drill-down of sensitive tables and their columns.
"""

import logging
import streamlit as st
from typing import List, Dict, Any, Optional, Tuple
import pandas as pd

from src.connectors.snowflake_connector import snowflake_connector
from src.services.ai_sensitive_detection_service import AISensitiveDetectionService
from src.services.governance_db_resolver import resolve_governance_db
try:
    from src.config import settings
except Exception:
    settings = None  # type: ignore

logger = logging.getLogger(__name__)

class AISensitiveTablesService:
    """Service for managing sensitive tables overview and drill-down functionality."""

    def __init__(self):
        """Initialize the sensitive tables service."""
        self.detection_service = AISensitiveDetectionService()

    def render_sensitive_tables_overview(self) -> None:
        """Render the Sensitive Tables Overview sub-tab."""
        st.markdown("### Sensitive Tables Overview")
        st.caption("Discover and explore sensitive tables based on column-level analysis with AI-enhanced detection.")

        # Get active database from global filters
        db = self._get_active_database()
        if not db:
            st.info("Select a database from Global Filters to view sensitive tables.")
            return

        # Get schema filter from session/global filters
        schema_filter = self._get_schema_filter()
        table_filter = self._get_table_filter()

        # Display scope information
        st.caption(f"Scope: Database `{db}`" +
                  (f", Schema `{schema_filter}`" if schema_filter else "") +
                  (f", Table `{table_filter}`" if table_filter else "") +
                  " (controlled by sidebar global filters)")

        # Level 1: Sensitive Tables Overview
        self._render_sensitive_tables_list(db, schema_filter, table_filter)

    def _get_active_database(self) -> Optional[str]:
        """Get the active database from global filters."""
        try:
            from src.pages.page_helpers import _active_db_from_filter
            db = _active_db_from_filter()
        except Exception:
            db = None

        # Fallbacks if helper is unavailable or returned nothing
        if not db:
            try:
                if hasattr(st, "session_state"):
                    # Common keys used elsewhere in the app
                    db = (
                        st.session_state.get("sf_database")
                        or (st.session_state.get("global_filters", {}) or {}).get("database")
                        or st.session_state.get("rt_db")
                        or st.session_state.get("selected_database")
                    )
            except Exception:
                db = None

        # Settings fallback
        if not db and settings is not None:
            try:
                db = getattr(settings, "SNOWFLAKE_DATABASE", None)
            except Exception:
                db = None

        # Probe from Snowflake context as a last resort
        if not db:
            try:
                rows = snowflake_connector.execute_query("select current_database() as DB") or []
                if rows and rows[0].get("DB"):
                    db = rows[0].get("DB")
            except Exception:
                db = None

        try:
            dbu = str(db or "").strip().upper()
            if dbu in {"", "NONE", "(NONE)", "NULL", "UNKNOWN"}:
                return None
        except Exception:
            pass

        return db

    def _get_schema_filter(self) -> Optional[str]:
        """Get schema filter from session state."""
        try:
            gf = st.session_state.get("global_filters", {}) if hasattr(st, "session_state") else {}
            return (
                st.session_state.get("schema_filter")
                or (gf.get("schema") if isinstance(gf, dict) else None)
            )
        except Exception:
            return None

    def _get_table_filter(self) -> Optional[str]:
        """Get table filter from session state."""
        try:
            gf = st.session_state.get("global_filters", {}) if hasattr(st, "session_state") else {}
            return (gf.get("table") if isinstance(gf, dict) else None)
        except Exception:
            return None

    def _render_sensitive_tables_list(self, db: str, schema_filter: Optional[str],
                                    table_filter: Optional[str]) -> None:
        """Render the list of sensitive tables with drill-down capability."""
        st.markdown("#### Sensitive Tables")

        # Get sensitive tables data
        sensitive_tables = self._get_sensitive_tables_data(db, schema_filter, table_filter)

        if not sensitive_tables:
            st.info("No sensitive tables found for the selected scope.")

            # Offer scan functionality
            if st.button("🔍 Scan for Sensitive Tables", key="scan_sensitive_tables"):
                self._run_sensitive_scan(db, schema_filter, table_filter)
        else:
            # Normalize accessor to handle Snowflake's uppercase dict keys
            def _g(d: Dict[str, Any], *keys):
                for k in keys:
                    if k in d and d[k] is not None:
                        return d[k]
                return None

            # Display tables in a dataframe
            records = []
            for table in sensitive_tables:
                fqn = _g(table, "table_fqn", "TABLE_FQN")
                if not fqn:
                    dbn = _g(table, "DATABASE_NAME", "database_name")
                    scn = _g(table, "TABLE_SCHEMA", "table_schema")
                    tbn = _g(table, "TABLE_NAME", "table_name")
                    if dbn and scn and tbn:
                        fqn = f"{dbn}.{scn}.{tbn}"
                if not fqn:
                    continue
                records.append({
                    "Table Name": fqn,
                    "Primary Sensitivity": _g(table, "PRIMARY_SENSITIVITY", "primary_sensitivity"),
                    "Confidence Score": f"{round(float(_g(table, 'CONFIDENCE_SCORE', 'confidence_score') or 0.0), 2)}%",
                    "Table Sensitivity Level": _g(table, "TABLE_SENSITIVITY_LEVEL", "table_sensitivity_level"),
                    "CIA Classification": _g(table, "CIA_CLASSIFICATION", "cia_classification"),
                })

            display_df = pd.DataFrame(records)
            if not display_df.empty:
                st.dataframe(display_df[[
                    "Table Name", "Primary Sensitivity", "Table Sensitivity Level"
                ]], width='stretch', hide_index=True)
            else:
                st.info("No sensitive tables found for the selected scope.")
                return

            # Table selection for drill-down
            table_options = [""] + [str(r.get("Table Name")) for r in records if r.get("Table Name")]
            selected_table = st.selectbox(
                "Select a table to drill down into sensitive columns",
                options=table_options,
                key="selected_sensitive_table"
            )

            if selected_table:
                self._render_sensitive_columns_drilldown(selected_table, db)

    def _get_sensitive_tables_data(self, db: str, schema_filter: Optional[str],
                                 table_filter: Optional[str]) -> List[Dict[str, Any]]:
        """Get sensitive tables data using CTE queries."""
        try:
            gov_db = resolve_governance_db() or db
            gv_str = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"

            # Build schema filter for CTE
            schema_filter_clause = " AND UPPER(c.TABLE_SCHEMA) = UPPER(%(sc)s)" if schema_filter else ""

            # CTE query for sensitive table detection (provided)
            cte_sql = f"""
            WITH
            -- 1️⃣ Active sensitivity categories with CIA levels
            CATEGORIES AS (
              SELECT 
                  CATEGORY_ID,
                  CATEGORY_NAME,
                  COALESCE(DETECTION_THRESHOLD, 0.7) AS DETECTION_THRESHOLD,
                  CONFIDENTIALITY_LEVEL AS C_LEVEL,
                  INTEGRITY_LEVEL AS I_LEVEL,
                  AVAILABILITY_LEVEL AS A_LEVEL
              FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
              WHERE IS_ACTIVE = TRUE
            ),

            -- 2️⃣ Active sensitivity weights
            WEIGHTS AS (
              SELECT
                  COALESCE(MAX(CASE WHEN UPPER(SENSITIVITY_TYPE) = 'RULE_BASED' THEN WEIGHT END), 1.0) AS RULE_BASED_WEIGHT,
                  COALESCE(MAX(CASE WHEN UPPER(SENSITIVITY_TYPE) = 'PATTERN_BASED' THEN WEIGHT END), 1.0) AS PATTERN_BASED_WEIGHT
              FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_WEIGHTS
              WHERE IS_ACTIVE = TRUE
            ),

            -- 3️⃣ Rule-based detections (column-level)
            RULE_BASED AS (
              SELECT
                  c.TABLE_CATALOG AS DATABASE_NAME,
                  c.TABLE_SCHEMA,
                  c.TABLE_NAME,
                  k.CATEGORY_ID,
                  cat.CATEGORY_NAME,
                  'RULE_BASED' AS DETECTION_TYPE,
                  k.KEYWORD_STRING AS MATCHED_KEYWORD,
                  COALESCE(k.SENSITIVITY_WEIGHT, 1.0) AS MATCH_WEIGHT,
                  cat.C_LEVEL, cat.I_LEVEL, cat.A_LEVEL
              FROM DATA_CLASSIFICATION_DB.INFORMATION_SCHEMA.COLUMNS c
              JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS k
                ON k.IS_ACTIVE = TRUE
               AND (
                    (k.MATCH_TYPE = 'EXACT' AND LOWER(c.COLUMN_NAME) = LOWER(k.KEYWORD_STRING))
                    OR
                    (k.MATCH_TYPE IN ('CONTAINS', 'PARTIAL') AND LOWER(c.COLUMN_NAME) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%')
                   )
              JOIN CATEGORIES cat ON k.CATEGORY_ID = cat.CATEGORY_ID
            ),

            -- 4️⃣ Pattern-based detections (column-level)
            PATTERN_BASED AS (
              SELECT
                  c.TABLE_CATALOG AS DATABASE_NAME,
                  c.TABLE_SCHEMA,
                  c.TABLE_NAME,
                  p.CATEGORY_ID,
                  cat.CATEGORY_NAME,
                  'PATTERN_BASED' AS DETECTION_TYPE,
                  p.PATTERN_NAME AS MATCHED_PATTERN,
                  COALESCE(p.SENSITIVITY_WEIGHT, 1.0) AS MATCH_WEIGHT,
                  cat.C_LEVEL, cat.I_LEVEL, cat.A_LEVEL
              FROM DATA_CLASSIFICATION_DB.INFORMATION_SCHEMA.COLUMNS c
              JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS p
                ON p.IS_ACTIVE = TRUE
               AND REGEXP_LIKE(LOWER(c.COLUMN_NAME), p.PATTERN_STRING, 'i')
              JOIN CATEGORIES cat ON p.CATEGORY_ID = cat.CATEGORY_ID
            ),

            -- 5️⃣ Combine detections
            COMBINED AS (
              SELECT * FROM RULE_BASED
              UNION ALL
              SELECT * FROM PATTERN_BASED
            ),

            -- 6️⃣ Compute confidence
            SCORED AS (
              SELECT
                  DATABASE_NAME,
                  TABLE_SCHEMA,
                  TABLE_NAME,
                  CATEGORY_NAME,
                  CATEGORY_ID,
                  ROUND(
                    CASE 
                      WHEN DETECTION_TYPE = 'RULE_BASED' THEN MATCH_WEIGHT * (SELECT RULE_BASED_WEIGHT FROM WEIGHTS)
                      WHEN DETECTION_TYPE = 'PATTERN_BASED' THEN MATCH_WEIGHT * (SELECT PATTERN_BASED_WEIGHT FROM WEIGHTS)
                      ELSE MATCH_WEIGHT
                    END * 100, 2
                  ) AS CONFIDENCE,
                  C_LEVEL, I_LEVEL, A_LEVEL
              FROM COMBINED
            ),

            -- 7️⃣ CIA label per column
            COLUMN_LABELLED AS (
              SELECT
                  DATABASE_NAME,
                  TABLE_SCHEMA,
                  TABLE_NAME,
                  CATEGORY_ID,
                  CATEGORY_NAME,
                  CONFIDENCE,
                  CASE
                      WHEN C_LEVEL = 3 AND I_LEVEL = 3 AND A_LEVEL >= 2 THEN '🟥 Confidential'
                      WHEN C_LEVEL = 2 AND I_LEVEL = 2 AND A_LEVEL BETWEEN 1 AND 2 THEN '🟧 Restricted'
                      WHEN C_LEVEL = 1 AND I_LEVEL = 1 AND A_LEVEL = 1 THEN '🟨 Internal'
                      WHEN C_LEVEL = 0 AND I_LEVEL = 0 AND A_LEVEL = 0 THEN '🟩 Public'
                      ELSE 'Unknown'
                  END AS CIA_LABEL
              FROM SCORED
            ),

            -- 8️⃣ Aggregate to table level
            TABLE_AGGREGATES AS (
              SELECT
                  DATABASE_NAME,
                  TABLE_SCHEMA,
                  TABLE_NAME,
                  ANY_VALUE(CATEGORY_ID) AS DOMINANT_CATEGORY_ID,
                  ANY_VALUE(CATEGORY_NAME) AS DOMINANT_CATEGORY,
                  ANY_VALUE(CIA_LABEL) AS TABLE_CIA_LABEL,
                  ROUND(AVG(CONFIDENCE), 2) AS AVG_CONFIDENCE,
                  COUNT(*) AS SENSITIVE_COLUMN_COUNT
              FROM COLUMN_LABELLED
              GROUP BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME
            ),

            -- 9️⃣ Compliance mappings (clean requirement handling)
            COMPLIANCE AS (
              SELECT 
                  CATEGORY_ID,
                  LISTAGG(DISTINCT COMPLIANCE_STANDARD, ', ') AS ASSOCIATED_COMPLIANCES,
                  LISTAGG(
                    DISTINCT REPLACE(
                      REPLACE(REQUIREMENT_IDS::STRING, '[', ''),
                      ']', ''
                    ), ', '
                  ) AS ASSOCIATED_REQUIREMENTS,
                  LISTAGG(DISTINCT DESCRIPTION, '; ') AS COMPLIANCE_DESCRIPTION
              FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.COMPLIANCE_MAPPING
              WHERE IS_ACTIVE = TRUE
              GROUP BY CATEGORY_ID
            )
            """

            # Build WHERE clause
            where_parts = []
            params = {}
            if schema_filter:
                where_parts.append("TABLE_SCHEMA = %(sc)s")
                params["sc"] = schema_filter
            if table_filter:
                where_parts.append("TABLE_NAME = %(tb)s")
                params["tb"] = table_filter
            where_sql = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""

            # Final aggregation query using provided output, with optional filters
            where_parts = []
            params = {}
            if schema_filter:
                where_parts.append("t.TABLE_SCHEMA = %(sc)s")
                params["sc"] = schema_filter
            if table_filter:
                where_parts.append("t.TABLE_NAME = %(tb)s")
                params["tb"] = table_filter
            where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
            agg_sql = f"""
            {cte_sql}
            SELECT
                t.DATABASE_NAME,
                t.TABLE_SCHEMA,
                t.TABLE_NAME,
                t.DOMINANT_CATEGORY AS PRIMARY_SENSITIVITY,
                t.TABLE_CIA_LABEL AS CIA_CLASSIFICATION,
                t.AVG_CONFIDENCE AS CONFIDENCE_SCORE,
                t.SENSITIVE_COLUMN_COUNT,
                CASE
                    WHEN t.AVG_CONFIDENCE >= 80 THEN 'HIGH RISK'
                    WHEN t.AVG_CONFIDENCE >= 60 THEN 'MEDIUM RISK'
                    ELSE 'LOW RISK'
                END AS TABLE_SENSITIVITY_LEVEL,
                COALESCE(c.ASSOCIATED_COMPLIANCES, 'None') AS RELEVANT_COMPLIANCES,
                COALESCE(c.ASSOCIATED_REQUIREMENTS, 'None') AS KEY_REQUIREMENTS,
                COALESCE(c.COMPLIANCE_DESCRIPTION, 'No specific compliance mapping') AS COMPLIANCE_SUMMARY,
                CURRENT_TIMESTAMP() AS ANALYZED_AT
            FROM TABLE_AGGREGATES t
            LEFT JOIN COMPLIANCE c 
              ON t.DOMINANT_CATEGORY_ID = c.CATEGORY_ID
            {where_sql}
            ORDER BY CONFIDENCE_SCORE DESC
            """

            rows = snowflake_connector.execute_query(agg_sql, params) or []

            # Fallback: try persisted data if CTE returns no results
            if not rows:
                rows = self._get_persisted_sensitive_tables(db, schema_filter, table_filter)

            return rows

        except Exception as e:
            logger.error(f"Error getting sensitive tables data: {e}")
            return []

    def _get_persisted_sensitive_tables(self, db: str, schema_filter: Optional[str],
                                      table_filter: Optional[str]) -> List[Dict[str, Any]]:
        """Fallback to get sensitive tables from persisted AI assistant data."""
        try:
            gov_db = resolve_governance_db() or db
            fqn_candidates = [
                f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE.AI_ASSISTANT_SENSITIVE_ASSETS",
                "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.AI_ASSISTANT_SENSITIVE_ASSETS",
            ]

            for fqn in fqn_candidates:
                try:
                    where = []
                    params = {}
                    if db:
                        where.append("DATABASE_NAME = %(db)s")
                        params["db"] = db
                    if schema_filter:
                        where.append("SCHEMA_NAME = %(sc)s")
                        params["sc"] = schema_filter
                    if table_filter:
                        where.append("TABLE_NAME = %(tb)s")
                        params["tb"] = table_filter

                    sql = f"""
                        SELECT
                          DATABASE_NAME,
                          SCHEMA_NAME,
                          TABLE_NAME,
                          COALESCE(DETECTED_CATEGORY, DETECTED_TYPE) AS DETECTED_TYPE,
                          MAX_CONF,
                          LAST_SCAN_TS
                        FROM (
                          SELECT
                            DATABASE_NAME,
                            SCHEMA_NAME,
                            TABLE_NAME,
                            DETECTED_CATEGORY,
                            DETECTED_TYPE,
                            LAST_SCAN_TS,
                            COMBINED_CONFIDENCE AS CONF,
                            MAX(COMBINED_CONFIDENCE) OVER (PARTITION BY DATABASE_NAME, SCHEMA_NAME, TABLE_NAME) AS MAX_CONF,
                            ROW_NUMBER() OVER (
                              PARTITION BY DATABASE_NAME, SCHEMA_NAME, TABLE_NAME
                              ORDER BY LAST_SCAN_TS DESC, COMBINED_CONFIDENCE DESC
                            ) AS RN
                          FROM {fqn}
                          {('WHERE ' + ' AND '.join(where)) if where else ''}
                        ) t
                        WHERE RN = 1 AND COALESCE(DETECTED_CATEGORY, DETECTED_TYPE) IS NOT NULL
                        ORDER BY MAX_CONF DESC, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME
                        LIMIT 1000
                    """

                    rows = snowflake_connector.execute_query(sql, params) or []
                    if rows:
                        # Transform persisted data to match expected format
                        transformed_rows = []
                        for r in rows:
                            db_name = r.get("DATABASE_NAME")
                            schema_name = r.get("SCHEMA_NAME")
                            table_name = r.get("TABLE_NAME")
                            detected_type = str(r.get("DETECTED_TYPE") or "")
                            max_conf = float(r.get('MAX_CONF') or 0.0)

                            if not detected_type:
                                continue

                            # Determine policy and level based on confidence
                            threshold = 0.7
                            if max_conf >= threshold:
                                policy, level = 'POLICY_REQUIRED', 'HIGH'
                            elif max_conf >= (threshold * 0.6):
                                policy, level = 'NEEDS_REVIEW', 'MEDIUM'
                            else:
                                policy, level = 'OK', 'LOW'

                            transformed_rows.append({
                                "table_fqn": f"{db_name}.{schema_name}.{table_name}",
                                "detected_type": detected_type,
                                "confidence_display": f"{round(max_conf*100, 2)}%",
                                "recommended_policy": policy,
                                "sensitivity_level": level,
                                "confidence_score": max_conf,
                                "DATABASE_NAME": db_name,
                                "TABLE_SCHEMA": schema_name,
                                "TABLE_NAME": table_name
                            })

                        return transformed_rows

                except Exception as e:
                    logger.warning(f"Failed to query {fqn}: {e}")
                    continue

            return []

        except Exception as e:
            logger.error(f"Error getting persisted sensitive tables: {e}")
            return []

    def _run_sensitive_scan(self, db: str, schema_filter: Optional[str],
                          table_filter: Optional[str]) -> None:
        """Run a sensitive data scan for the selected scope."""
        with st.spinner("Scanning for sensitive data... This may take several minutes."):
            try:
                summary = self.detection_service.run_scan_and_persist(
                    db,
                    schema_name=schema_filter,
                    table_name=table_filter
                )

                if "error" not in summary:
                    st.success(f"Scan complete! Detected {summary.get('columns_detected', 0)} sensitive columns.")

                    # Clear any cached data and refresh
                    if hasattr(self.detection_service, '_metadata_cache'):
                        self.detection_service._metadata_cache.clear()

                    st.rerun()
                else:
                    st.error(f"Scan failed: {summary['error']}")

            except Exception as e:
                st.error(f"Scan failed: {e}")

    def _render_sensitive_columns_drilldown(self, table_fqn: str, db: str) -> None:
        """Render the drill-down view for sensitive columns in a selected table."""
        st.markdown("#### Sensitive Columns Drill-down")

        try:
            # Parse table FQN
            parts = table_fqn.split('.')
            if len(parts) != 3:
                st.error("Invalid table format. Expected: DATABASE.SCHEMA.TABLE")
                return

            db_name, schema_name, table_name = parts

            # Get sensitive columns for this table
            sensitive_columns = self._get_sensitive_columns_for_table(db_name, schema_name, table_name)

            if not sensitive_columns:
                st.info("No sensitive columns detected in this table.")
                return

            # Display columns in a dataframe (includes CIA/Policy/Compliance from CTE)
            columns_df = pd.DataFrame([
                {
                    "Column Name": col.get("column_name"),
                    "Data Type": col.get("data_type"),
                    "Sensitive Data Type": col.get("detected_category"),
                    "Confidence Score": f"{round(float(col.get('confidence', 0.0)) * 100, 1)}%",
                    "CIA Label": col.get("cia_label"),
                    "Policy": col.get("policy"),
                    "Compliance Standards": (col.get("compliance", {}) or {}).get("standard"),
                    "Key Requirements": (col.get("compliance", {}) or {}).get("requirements"),
                    "Compliance Summary": (col.get("compliance", {}) or {}).get("description"),
                }
                for col in sensitive_columns
            ])

            st.dataframe(columns_df, width='stretch', hide_index=True)

        except Exception as e:
            logger.error(f"Error in sensitive columns drill-down: {e}")
            st.error(f"Failed to load sensitive columns: {e}")

    def _get_sensitive_columns_for_table(self, db: str, schema: str, table: str) -> List[Dict[str, Any]]:
        """Get sensitive columns for a specific table."""
        try:
            gov_db = resolve_governance_db() or db
            gv_str = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"

            # CTE query for column-level sensitive data detection (exact per user), scoped to selected table
            cte_sql = f"""
            WITH
            -- 1️⃣ Active sensitivity categories
            CATEGORIES AS (
              SELECT 
                  CATEGORY_ID,
                  CATEGORY_NAME,
                  COALESCE(DETECTION_THRESHOLD, 0.7) AS DETECTION_THRESHOLD,
                  CONFIDENTIALITY_LEVEL AS C_LEVEL,
                  INTEGRITY_LEVEL AS I_LEVEL,
                  AVAILABILITY_LEVEL AS A_LEVEL
              FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
              WHERE IS_ACTIVE = TRUE
            ),

            -- 2️⃣ Detection weights
            WEIGHTS AS (
              SELECT
                  COALESCE(MAX(CASE WHEN UPPER(SENSITIVITY_TYPE) = 'RULE_BASED' THEN WEIGHT END), 1.0) AS RULE_BASED_WEIGHT,
                  COALESCE(MAX(CASE WHEN UPPER(SENSITIVITY_TYPE) = 'PATTERN_BASED' THEN WEIGHT END), 1.0) AS PATTERN_BASED_WEIGHT
              FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_WEIGHTS
              WHERE IS_ACTIVE = TRUE
            ),

            -- 3️⃣ Rule-based detections (keyword-based)
            RULE_BASED AS (
              SELECT
                  c.TABLE_CATALOG AS DATABASE_NAME,
                  c.TABLE_SCHEMA,
                  c.TABLE_NAME,
                  c.COLUMN_NAME,
                  c.DATA_TYPE,
                  k.CATEGORY_ID,
                  cat.CATEGORY_NAME,
                  'RULE_BASED' AS DETECTION_TYPE,
                  k.KEYWORD_STRING AS MATCHED_KEYWORD,
                  NULL AS MATCHED_PATTERN,
                  COALESCE(k.SENSITIVITY_WEIGHT, 1.0) AS MATCH_WEIGHT,
                  cat.DETECTION_THRESHOLD,
                  cat.C_LEVEL,
                  cat.I_LEVEL,
                  cat.A_LEVEL
              FROM DATA_CLASSIFICATION_DB.INFORMATION_SCHEMA.COLUMNS c
              JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS k
                ON k.IS_ACTIVE = TRUE
               AND (
                    (k.MATCH_TYPE = 'EXACT' AND LOWER(c.COLUMN_NAME) = LOWER(k.KEYWORD_STRING))
                    OR
                    (k.MATCH_TYPE IN ('CONTAINS', 'PARTIAL') AND LOWER(c.COLUMN_NAME) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%')
                   )
              JOIN CATEGORIES cat ON k.CATEGORY_ID = cat.CATEGORY_ID
              WHERE UPPER(c.TABLE_SCHEMA) = UPPER(%(schema)s) AND UPPER(c.TABLE_NAME) = UPPER(%(table)s)
            ),

            -- 4️⃣ Pattern-based detections (regex)
            PATTERN_BASED AS (
              SELECT
                  c.TABLE_CATALOG AS DATABASE_NAME,
                  c.TABLE_SCHEMA,
                  c.TABLE_NAME,
                  c.COLUMN_NAME,
                  c.DATA_TYPE,
                  p.CATEGORY_ID,
                  cat.CATEGORY_NAME,
                  'PATTERN_BASED' AS DETECTION_TYPE,
                  NULL AS MATCHED_KEYWORD,
                  p.PATTERN_NAME AS MATCHED_PATTERN,
                  COALESCE(p.SENSITIVITY_WEIGHT, 1.0) AS MATCH_WEIGHT,
                  cat.DETECTION_THRESHOLD,
                  cat.C_LEVEL,
                  cat.I_LEVEL,
                  cat.A_LEVEL
              FROM DATA_CLASSIFICATION_DB.INFORMATION_SCHEMA.COLUMNS c
              JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS p
                ON p.IS_ACTIVE = TRUE
               AND REGEXP_LIKE(LOWER(c.COLUMN_NAME), p.PATTERN_STRING, 'i')
              JOIN CATEGORIES cat ON p.CATEGORY_ID = cat.CATEGORY_ID
              WHERE UPPER(c.TABLE_SCHEMA) = UPPER(%(schema)s) AND UPPER(c.TABLE_NAME) = UPPER(%(table)s)
            ),

            -- 5️⃣ Combine detections
            COMBINED AS (
              SELECT * FROM RULE_BASED
              UNION ALL
              SELECT * FROM PATTERN_BASED
            ),

            -- 6️⃣ Keep only the strongest detection per column
            TOP_DETECTION AS (
              SELECT *, 
                     ROW_NUMBER() OVER (
                       PARTITION BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME 
                       ORDER BY MATCH_WEIGHT DESC
                     ) AS RN
              FROM COMBINED
            ),

            SELECTED AS (
              SELECT * 
              FROM TOP_DETECTION 
              WHERE RN = 1
            ),

            -- 7️⃣ Compute confidence and CIA label
            FINAL AS (
              SELECT
                  s.DATABASE_NAME,
                  s.TABLE_SCHEMA,
                  s.TABLE_NAME,
                  s.COLUMN_NAME,
                  s.DATA_TYPE,
                  s.CATEGORY_ID,
                  s.CATEGORY_NAME,
                  s.DETECTION_TYPE,
                  s.MATCHED_KEYWORD,
                  s.MATCHED_PATTERN,
                  s.DETECTION_THRESHOLD,
                  s.C_LEVEL,
                  s.I_LEVEL,
                  s.A_LEVEL,
                  LEAST(
                    CASE 
                      WHEN s.DETECTION_TYPE = 'RULE_BASED' THEN s.MATCH_WEIGHT * (SELECT RULE_BASED_WEIGHT FROM WEIGHTS)
                      WHEN s.DETECTION_TYPE = 'PATTERN_BASED' THEN s.MATCH_WEIGHT * (SELECT PATTERN_BASED_WEIGHT FROM WEIGHTS)
                      ELSE s.MATCH_WEIGHT
                    END * 100,
                    100
                  ) AS CONFIDENCE_SCORE,
                  CASE
                      WHEN s.C_LEVEL = 3 AND s.I_LEVEL = 3 AND s.A_LEVEL >= 2 THEN '🟥 Confidential'
                      WHEN s.C_LEVEL = 2 AND s.I_LEVEL = 2 AND s.A_LEVEL BETWEEN 1 AND 2 THEN '🟧 Restricted'
                      WHEN s.C_LEVEL = 1 AND s.I_LEVEL = 1 AND s.A_LEVEL = 1 THEN '🟨 Internal'
                      WHEN s.C_LEVEL = 0 AND s.I_LEVEL = 0 AND s.A_LEVEL = 0 THEN '🟩 Public'
                      ELSE 'Unknown'
                  END AS CIA_LABEL
              FROM SELECTED s
            ),

            -- 8️⃣ Add compliance mapping for detected categories
            FINAL_WITH_COMPLIANCE AS (
              SELECT
                  f.DATABASE_NAME,
                  f.TABLE_SCHEMA,
                  f.TABLE_NAME,
                  f.COLUMN_NAME,
                  f.CATEGORY_NAME AS SENSITIVITY_TYPE,
                  ROUND(f.CONFIDENCE_SCORE, 2) AS CONFIDENCE,
                  f.CIA_LABEL,
                  CASE 
                      WHEN f.CONFIDENCE_SCORE >= (f.DETECTION_THRESHOLD * 100) THEN 'POLICY_REQUIRED'
                      WHEN f.CONFIDENCE_SCORE >= (f.DETECTION_THRESHOLD * 100 * 0.6) THEN 'NEEDS_REVIEW'
                      ELSE 'OK'
                  END AS RECOMMENDED_POLICY,
                  cm.COMPLIANCE_STANDARD,
                  cm.REQUIREMENT_IDS,
                  cm.DESCRIPTION AS COMPLIANCE_DESCRIPTION,
                  CURRENT_TIMESTAMP() AS DETECTED_AT
              FROM FINAL f
              LEFT JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.COMPLIANCE_MAPPING cm
                     ON f.CATEGORY_ID = cm.CATEGORY_ID
                     AND cm.IS_ACTIVE = TRUE
            )

            -- ✅ Final output
            SELECT *
            FROM FINAL_WITH_COMPLIANCE
            ORDER BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
            """

            params = {"schema": schema, "table": table}
            rows = snowflake_connector.execute_query(cte_sql, params) or []

            # Transform to expected format
            sensitive_columns = []
            for row in rows:
                sensitive_columns.append({
                    "column_name": row.get("COLUMN_NAME"),
                    "data_type": row.get("DATA_TYPE"),
                    "detected_category": row.get("SENSITIVITY_TYPE"),
                    # CONFIDENCE is already a percentage per the CTE; normalize to 0-1 for internal use
                    "confidence": float(row.get("CONFIDENCE", 0.0)) / (100.0 if float(row.get("CONFIDENCE", 0.0)) > 1.0 else 1.0),
                    "detection_methods": [],
                    "cia_levels": {
                        "confidentiality": row.get("C_LEVEL", 1),
                        "integrity": row.get("I_LEVEL", 1),
                        "availability": row.get("A_LEVEL", 1)
                    },
                    "compliance": {
                        "standard": row.get("COMPLIANCE_STANDARD"),
                        "requirements": row.get("REQUIREMENT_IDS"),
                        "description": row.get("COMPLIANCE_DESCRIPTION")
                    },
                    "policy": row.get("RECOMMENDED_POLICY"),
                    "cia_label": row.get("CIA_LABEL")
                })

            return sensitive_columns

        except Exception as e:
            logger.error(f"Error getting sensitive columns for table {db}.{schema}.{table}: {e}")
            return []


# Singleton instance
ai_sensitive_tables_service = AISensitiveTablesService()
