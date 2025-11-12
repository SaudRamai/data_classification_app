"""
AI Classification Pipeline Service

This service provides functionality for the Automatic AI Classification Pipeline sub-tab in the AI Assistant section.
It handles automated classification of data assets with semantic detection, CIA recommendations, and governance tagging.
"""

import logging
import streamlit as st
from typing import List, Dict, Any, Optional
import pandas as pd
import numpy as np  # type: ignore

from src.connectors.snowflake_connector import snowflake_connector
from src.services.ai_assistant_service import ai_assistant_service
from src.services.ai_classification_service import ai_classification_service
from src.services.discovery_service import DiscoveryService
from src.services.ai_sensitive_detection_service import AISensitiveDetectionService
from src.services.governance_db_resolver import resolve_governance_db
try:
    from src.config import settings
except Exception:
    settings = None  # type: ignore

logger = logging.getLogger(__name__)

class AIClassificationPipelineService:
    """Service for managing the automatic AI classification pipeline functionality."""

    def __init__(self):
        """Initialize the classification pipeline service."""
        self.ai_service = ai_assistant_service
        self.discovery = DiscoveryService()
        try:
            self.sensitive_service = AISensitiveDetectionService(sample_size=200, min_confidence=0.3, use_ai=True)
        except Exception:
            self.sensitive_service = None
        # Disable governance glossary usage for semantic context (use only information_schema + config)
        try:
            setattr(self.ai_service, "use_governance_glossary", False)
        except Exception:
            pass

    def render_classification_pipeline(self) -> None:
        """Render the Automatic AI Classification Pipeline sub-tab."""
        st.markdown("### Automatic AI Classification Pipeline")
        st.caption("Automatically discovers existing data assets, derives business context, performs semantic category detection, recommends CIA levels per Avendra's Data Classification Policy, and applies governance tags with full validation, review routing, and audit logging.")

        show_steps = False

        # Get active database
        db = self._get_active_database()
        if not db:
            st.info("Select a database from Global Filters to run the pipeline.")
            # Quick-select fallback
            try:
                db_rows = snowflake_connector.execute_query("SHOW DATABASES") or []
                # Accept both list[str] and list[dict]
                if db_rows and isinstance(db_rows[0], dict):
                    db_opts = [r.get("name") or r.get("database_name") or r.get("DATABASE_NAME") for r in db_rows if r]
                else:
                    db_opts = [str(r) for r in db_rows]
                db_opts = [d for d in db_opts if d and str(d).strip() and str(d).upper() not in {"NONE","(NONE)","NULL","UNKNOWN"}]
            except Exception:
                db_opts = []
            if db_opts:
                sel_quick = st.selectbox("Quick select a database:", options=[""] + db_opts, key="ai_pipe_quick_db")
                if sel_quick:
                    st.session_state["sf_database"] = sel_quick
                    db = sel_quick
            if not db:
                return

        # Validate database name
        if not self._is_valid_database(db):
            st.info("Select a valid database (Global Filters). Current selection is invalid.")
            return

        # Get governance database
        gov_db = self._get_governance_database(db)

        # Show status and set Snowflake context
        try:
            schema_filter = self._get_schema_filter()
            table_filter = self._get_table_filter()
        except Exception:
            schema_filter = None; table_filter = None
        st.caption(
            f"Using Database: {db}"
            + (f" | Schema: {schema_filter}" if schema_filter else "")
            + (f" | Table filter: {table_filter}" if table_filter else "")
        )
        try:
            snowflake_connector.execute_non_query(f"USE DATABASE {db}")
        except Exception:
            pass

        # Automatic background pipeline execution (disabled by default; runs only when explicitly enabled)
        try:
            _bg = False
            if _bg:
                self._maybe_run_background_pipeline(db=db, gov_db=gov_db)
        except Exception:
            pass

        if show_steps:
            with st.expander("Step 2: Collect Metadata", expanded=False):
                colm1, colm2 = st.columns([1, 1])
                with colm1:
                    if st.button("Collect table & column metadata", key="btn_collect_meta"):
                        try:
                            tables_df, columns_df, glossary_df = self._collect_metadata(db, schema_filter, table_filter, gov_db)
                            st.session_state["pipe_meta_tables"] = tables_df
                            st.session_state["pipe_meta_columns"] = columns_df
                            st.session_state["pipe_meta_glossary"] = glossary_df
                        except Exception as me:
                            st.error(f"Metadata collection failed: {me}")
                with colm2:
                    st.caption("Collects information_schema tables/columns, plus governance glossary references.")

            try:
                tables_df = st.session_state.get("pipe_meta_tables") if hasattr(st, 'session_state') else None
                columns_df = st.session_state.get("pipe_meta_columns") if hasattr(st, 'session_state') else None
                glossary_df = st.session_state.get("pipe_meta_glossary") if hasattr(st, 'session_state') else None
            except Exception:
                tables_df = columns_df = glossary_df = None

            if isinstance(tables_df, pd.DataFrame) and not tables_df.empty:
                st.markdown("**Tables (preview)**")
                st.dataframe(tables_df.head(100), use_container_width=True, hide_index=True)

            if isinstance(columns_df, pd.DataFrame) and not columns_df.empty:
                st.markdown("**Columns (preview)**")
                st.dataframe(columns_df.head(200), use_container_width=True, hide_index=True)

                # Sampling UI
                try:
                    sample_cols = columns_df[["TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME"]].drop_duplicates()
                    sample_cols["FQN"] = sample_cols.apply(lambda r: f"{db}.{r['TABLE_SCHEMA']}.{r['TABLE_NAME']} :: {r['COLUMN_NAME']}", axis=1)
                    sel = st.selectbox("Sample column values", options=[""] + list(sample_cols["FQN"]), key="pipe_sample_pick")
                    if sel:
                        try:
                            parts = sel.split(" :: ")
                            tblfqn = parts[0]
                            colname = parts[1]
                            _, sch, tbl = tblfqn.split('.')
                            values = self._sample_column_values(db=db, schema=sch, table=tbl, column=colname, sample_rows=100)
                            if values:
                                st.markdown("**Sample Values**")
                                st.write(values[:50])
                            else:
                                st.caption("No non-null values sampled.")
                        except Exception as se:
                            st.warning(f"Sampling failed: {se}")
                except Exception:
                    pass

            if isinstance(glossary_df, pd.DataFrame) and not glossary_df.empty:
                st.markdown("**Glossary / Compliance Mapping**")
                st.dataframe(glossary_df.head(200), use_container_width=True, hide_index=True)

        if show_steps:
            with st.expander("Step 3: Semantic Embedding Generation", expanded=False):
                c1, c2 = st.columns([1, 1])
                with c1:
                    if st.button("Initialize embedding backend", key="btn_init_embed"):
                        try:
                            emb_info = self.ai_service.initialize_sensitive_detection()
                            if hasattr(st, 'session_state'):
                                st.session_state["pipe_embed_info"] = emb_info
                            st.success(f"Backend: {emb_info.get('backend')} | Categories: {', '.join(emb_info.get('categories', []))}")
                        except Exception as ee:
                            st.error(f"Embedding init failed: {ee}")
                with c2:
                    try:
                        emb_info = st.session_state.get("pipe_embed_info") if hasattr(st, 'session_state') else None
                        if emb_info:
                            st.caption(f"Backend: {emb_info.get('backend')} | Categories loaded: {len(emb_info.get('categories', []))}")
                    except Exception:
                        pass

                try:
                    cols_df = st.session_state.get("pipe_meta_columns") if hasattr(st, 'session_state') else None
                except Exception:
                    cols_df = None

                cc1, cc2 = st.columns([1, 1])
                with cc1:
                    if st.button("Embed column contexts (sample)", key="btn_embed_cols"):
                        try:
                            out_rows = []
                            if isinstance(cols_df, pd.DataFrame) and not cols_df.empty:
                                sample = cols_df.head(100).copy()
                                for _, r in sample.iterrows():
                                    ctx = f"{db}.{r.get('TABLE_SCHEMA')}.{r.get('TABLE_NAME')}.{r.get('COLUMN_NAME')}"
                                    com = r.get('COLUMN_COMMENT') or ''
                                    if com:
                                        ctx = f"{ctx} | {com}"
                                    vec = None
                                    try:
                                        if hasattr(self.ai_service, "_get_embedding"):
                                            vec = self.ai_service._get_embedding(ctx)
                                    except Exception:
                                        vec = None
                                    dim = int(getattr(vec, "shape", [0])[-1]) if vec is not None and hasattr(vec, 'shape') else (len(vec) if isinstance(vec, (list, tuple)) else 0)
                                    out_rows.append({
                                        "context": ctx,
                                        "dim": dim,
                                    })
                            dfv = pd.DataFrame(out_rows)
                            if hasattr(st, 'session_state'):
                                st.session_state["pipe_embed_columns"] = dfv
                        except Exception as ce:
                            st.error(f"Column embedding failed: {ce}")
                with cc2:
                    if st.button("Build category reference embeddings", key="btn_embed_cats"):
                        try:
                            info = self.ai_service.initialize_sensitive_detection()
                            cents = getattr(self.ai_service, "_category_centroids", {}) or {}
                            rows = []
                            for k, v in cents.items():
                                dim = int(getattr(v, "shape", [0])[-1]) if v is not None and hasattr(v, 'shape') else (len(v) if isinstance(v, (list, tuple)) else 0)
                                rows.append({"category": k, "dim": dim, "has_centroid": v is not None})
                            dfr = pd.DataFrame(rows)
                            if hasattr(st, 'session_state'):
                                st.session_state["pipe_embed_categories"] = dfr
                        except Exception as ce2:
                            st.error(f"Category embedding failed: {ce2}")

                try:
                    dfv = st.session_state.get("pipe_embed_columns") if hasattr(st, 'session_state') else None
                    if isinstance(dfv, pd.DataFrame) and not dfv.empty:
                        st.markdown("**Embedded Column Contexts (sample)**")
                        st.dataframe(dfv.head(50), use_container_width=True, hide_index=True)
                except Exception:
                    pass

                try:
                    dfr = st.session_state.get("pipe_embed_categories") if hasattr(st, 'session_state') else None
                    if isinstance(dfr, pd.DataFrame) and not dfr.empty:
                        st.markdown("**Category Reference Embeddings**")
                        st.dataframe(dfr, use_container_width=True, hide_index=True)
                except Exception:
                    pass

        if show_steps:
            with st.expander("Step 4: Similarity Matching", expanded=False):
                thr = st.slider("Confidence threshold (cosine)", min_value=0.3, max_value=0.95, value=0.6, step=0.05, key="pipe_sim_thr")
                run_btn = st.button("Compute best category per column (sample)", key="btn_compute_similarity")
                cols_df = None
                try:
                    cols_df = st.session_state.get("pipe_meta_columns") if hasattr(st, 'session_state') else None
                except Exception:
                    cols_df = None
                if run_btn:
                    try:
                        cents = getattr(self.ai_service, "_category_centroids", {}) or {}
                        if not cents:
                            _ = self.ai_service.initialize_sensitive_detection()
                            cents = getattr(self.ai_service, "_category_centroids", {}) or {}
                        out_rows: List[Dict[str, Any]] = []
                        if isinstance(cols_df, pd.DataFrame) and not cols_df.empty and cents:
                            sample = cols_df.head(100).copy()
                            for _, r in sample.iterrows():
                                ctx = f"{db}.{r.get('TABLE_SCHEMA')}.{r.get('TABLE_NAME')}.{r.get('COLUMN_NAME')}"
                                com = r.get('COLUMN_COMMENT') or ''
                                if com:
                                    ctx = f"{ctx} | {com}"
                                v = None
                                try:
                                    if hasattr(self.ai_service, "_get_embedding"):
                                        v = self.ai_service._get_embedding(ctx)
                                except Exception:
                                    v = None
                                best_cat = None
                                best_sim = 0.0
                                if v is not None and np is not None:
                                    try:
                                        vv = np.asarray(v, dtype=float)
                                        nv = float(np.linalg.norm(vv) or 0.0)
                                        if nv > 0:
                                            vv = vv / nv
                                        for cat, c in cents.items():
                                            if c is None:
                                                continue
                                            cc = np.asarray(c, dtype=float)
                                            nc = float(np.linalg.norm(cc) or 0.0)
                                            if nc > 0:
                                                cc = cc / nc
                                            sim = float(np.dot(vv, cc))
                                            if sim > best_sim:
                                                best_sim = sim
                                                best_cat = cat
                                    except Exception:
                                        pass
                                assigned = best_cat if (best_cat and best_sim >= thr) else None
                                out_rows.append({
                                    "Schema": r.get('TABLE_SCHEMA'),
                                    "Table": r.get('TABLE_NAME'),
                                    "Column": r.get('COLUMN_NAME'),
                                    "BestCategory": best_cat or "",
                                    "Similarity": round(best_sim, 4),
                                    "Assigned": assigned or "",
                                })
                        df_sim = pd.DataFrame(out_rows)
                        if hasattr(st, 'session_state'):
                            st.session_state["pipe_similarity_results"] = df_sim
                    except Exception as se:
                        st.error(f"Similarity matching failed: {se}")

                try:
                    df_sim = st.session_state.get("pipe_similarity_results") if hasattr(st, 'session_state') else None
                    if isinstance(df_sim, pd.DataFrame) and not df_sim.empty:
                        st.markdown("**Similarity Results (sample)**")
                        st.dataframe(df_sim, use_container_width=True, hide_index=True)
                except Exception:
                    pass

            try:
                df_sim = st.session_state.get("pipe_similarity_results") if hasattr(st, 'session_state') else None
                if isinstance(df_sim, pd.DataFrame) and not df_sim.empty:
                    st.markdown("**Similarity Results (sample)**")
                    st.dataframe(df_sim, use_container_width=True, hide_index=True)
            except Exception:
                pass

        if show_steps:
            with st.expander("Debug: Discovery preview", expanded=False):
                st.write({
                    "database": db,
                    "schema_filter": schema_filter,
                    "table_filter": table_filter,
                })
                try:
                    sample_assets = self._discover_assets(db)[:10]
                    if sample_assets:
                        st.dataframe(pd.DataFrame(sample_assets), use_container_width=True, hide_index=True)
                    else:
                        st.caption("No assets discovered with current filters.")
                except Exception as _de:
                    st.caption(f"Discovery preview error: {_de}")

        # Run pipeline button
        if st.button("Run AI Classification Pipeline", type="primary", key="run_ai_pipeline"):
            self._run_classification_pipeline(db, gov_db)

        # Show automatic results if available
        try:
            auto_res = st.session_state.get("pipe_auto_results") if hasattr(st, 'session_state') else None
            if isinstance(auto_res, list) and auto_res:
                with st.expander("Automatic Results", expanded=False):
                    self._display_classification_results(auto_res)
        except Exception:
            pass

    def _get_active_database(self) -> Optional[str]:
        """Get the active database from global filters."""
        try:
            from src.pages.page_helpers import _active_db_from_filter
            db = _active_db_from_filter()
        except Exception:
            db = None

        # Fallbacks from session state
        if not db:
            try:
                if hasattr(st, "session_state"):
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

        # Probe Snowflake context last
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

    def _is_valid_database(self, db: str) -> bool:
        """Check if database name is valid (not placeholder/invalid)."""
        try:
            db_upper = str(db or '').upper()
            invalid_names = {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}
            return db_upper not in invalid_names
        except Exception:
            return False

    def _get_governance_database(self, db: str) -> str:
        """Resolve governance database for CTE joins."""
        try:
            gov_db = resolve_governance_db() or db
            return gov_db
        except Exception:
            return db

    def _run_classification_pipeline(self, db: str, gov_db: str) -> None:
        """Execute the full AI classification pipeline."""
        with st.spinner("Running AI Classification Pipeline... This may take several minutes."):
            try:
                # Ensure Snowflake-backed discovery/metadata/samples are used where available
                try:
                    self.ai_service.use_snowflake = True  # prefer live metadata/samples
                except Exception:
                    pass

                # Ensure MiniLM embedder and governance embeddings are initialized for reliable semantic detection
                try:
                    ai_classification_service.initialize_sensitive_detection()
                except Exception:
                    pass
                try:
                    if hasattr(ai_classification_service, "_ensure_gov_category_embeddings"):
                        ai_classification_service._ensure_gov_category_embeddings()  # type: ignore
                except Exception:
                    pass

                # Step 1b: Local discovery list for this run (preview)
                assets = self._discover_assets(db)
                if not assets:
                    st.warning("No tables found in the selected database.")
                    return

                st.info(f"Discovered {len(assets)} tables for classification.")

                # Optional: indicate embedding backend for transparency
                try:
                    backend = ai_classification_service.get_embedding_backend()
                    st.caption(f"Embedding backend: {backend if backend else 'none'} (MiniLM loads lazily if available)")
                except Exception:
                    pass

                # Step 2-8: Run classification pipeline
                results = self.ai_service.run_automated_classification(
                    database=db,
                    schema=self._get_schema_filter(),
                    limit=50  # Limit for UI performance
                )

                if not results:
                    st.warning("No assets were successfully classified.")
                    return

                # Enrich each result with column-level detections (MiniLM-backed)
                enriched: List[Dict[str, Any]] = []
                for r in results:
                    try:
                        asset = r.get('asset') or {}
                        dbn = asset.get('database') or str(asset.get('full_name','')).split('.')[0]
                        scn = asset.get('schema')
                        tbn = asset.get('table')
                        col_rows: List[Dict[str, Any]] = []
                        if self.sensitive_service is not None and dbn and scn and tbn:
                            cols = self.sensitive_service.detect_sensitive_columns(
                                database=dbn, schema_name=scn, table_name=tbn,
                            ) or []
                            for c in cols:
                                col_rows.append({
                                    'Column': getattr(c, 'column_name', None),
                                    'Type': getattr(c, 'data_type', None),
                                    'Sensitivity': getattr(c, 'sensitivity_level', None),
                                    'Confidence': round(float(getattr(c, 'confidence', 0.0) or 0.0), 4),
                                    'Categories': ', '.join(sorted(list(getattr(c, 'detected_categories', set()) or [])))
                                })
                        r['column_results'] = col_rows
                    except Exception:
                        r['column_results'] = []
                    enriched.append(r)

                # Display results (with column-level details)
                self._display_classification_results(enriched)

                # Summary
                successful = len([r for r in results if 'error' not in r])
                failed = len([r for r in results if 'error' in r])

                st.success(f"Pipeline completed! Successfully classified {successful} assets. Failed: {failed}")

                if failed > 0:
                    with st.expander("View Errors", expanded=False):
                        for result in results:
                            if 'error' in result:
                                st.error(f"{result['asset']['full_name']}: {result['error']}")

            except Exception as e:
                logger.error(f"Pipeline execution failed: {e}")
                st.error(f"Pipeline failed: {e}")

    def _maybe_run_background_pipeline(self, db: str, gov_db: str) -> None:
        """Run the automatic pipeline in the background for the current database once per selection."""
        try:
            last_db = None
            ran = False
            if hasattr(st, 'session_state'):
                last_db = st.session_state.get("pipe_auto_last_db")
                ran = bool(st.session_state.get("pipe_auto_ran"))
            if last_db == db and ran and st.session_state.get("pipe_auto_results"):
                return
        except Exception:
            pass

        try:
            try:
                emb_info = self.ai_service.initialize_sensitive_detection()
                _ = emb_info
            except Exception:
                pass

            assets = self._discover_assets(db)
            if not assets:
                return

            results = self.ai_service.run_automated_classification(
                database=db,
                schema=self._get_schema_filter(),
                limit=50,
            ) or []

            enriched: List[Dict[str, Any]] = []
            for r in results:
                try:
                    asset = r.get('asset') or {}
                    dbn = asset.get('database') or str(asset.get('full_name','')).split('.')[0]
                    scn = asset.get('schema')
                    tbn = asset.get('table')
                    col_rows: List[Dict[str, Any]] = []
                    if self.sensitive_service is not None and dbn and scn and tbn:
                        cols = self.sensitive_service.detect_sensitive_columns(
                            database=dbn, schema_name=scn, table_name=tbn,
                        ) or []
                        for c in cols:
                            col_rows.append({
                                'Column': getattr(c, 'column_name', None),
                                'Type': getattr(c, 'data_type', None),
                                'Sensitivity': getattr(c, 'sensitivity_level', None),
                                'Confidence': round(float(getattr(c, 'confidence', 0.0) or 0.0), 4),
                                'Categories': ', '.join(sorted(list(getattr(c, 'detected_categories', set()) or [])))
                            })
                    r['column_results'] = col_rows
                except Exception:
                    r['column_results'] = []
                enriched.append(r)

            try:
                if hasattr(st, 'session_state'):
                    st.session_state["pipe_auto_results"] = enriched
                    st.session_state["pipe_auto_last_db"] = db
                    st.session_state["pipe_auto_ran"] = True
            except Exception:
                pass
        except Exception:
            pass

    def _discover_assets(self, db: str) -> List[Dict[str, Any]]:
        """Discover tables and extract metadata for classification."""
        try:
            # Get filters from global state
            schema_filter = self._get_schema_filter()
            table_filter = self._get_table_filter()

            # Build query with filters
            where_parts = ["TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA', 'DATA_CLASSIFICATION_GOVERNANCE')",
                          "TABLE_TYPE IN ('BASE TABLE', 'VIEW')"]
            params = {}

            if schema_filter:
                where_parts.append("UPPER(TABLE_SCHEMA) = UPPER(%(sc)s)")
                params["sc"] = schema_filter

            if table_filter:
                where_parts.append("TABLE_NAME ILIKE %(tb)s")
                params["tb"] = f"%{table_filter}%"

            where_sql = " AND ".join(where_parts)

            query = f"""
                SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ROW_COUNT, CREATED, LAST_ALTERED, COMMENT
                FROM {db}.INFORMATION_SCHEMA.TABLES
                WHERE {where_sql}
                ORDER BY TABLE_SCHEMA, TABLE_NAME
                LIMIT 100  -- Limit for performance
            """

            rows = snowflake_connector.execute_query(query, params) or []

            assets = []
            for row in rows:
                assets.append({
                    'database': row['TABLE_CATALOG'] if 'TABLE_CATALOG' in row else db,
                    'schema': row['TABLE_SCHEMA'],
                    'table': row['TABLE_NAME'],
                    'full_name': f"{db}.{row['TABLE_SCHEMA']}.{row['TABLE_NAME']}",
                    'comment': row.get('COMMENT'),
                    'created': row.get('CREATED'),
                    'last_altered': row.get('LAST_ALTERED'),
                    'table_type': row.get('TABLE_TYPE'),
                    'row_count': row.get('ROW_COUNT')
                })

            return assets

        except Exception as e:
            logger.error(f"Asset discovery failed: {e}")
            return []

    def _collect_metadata(self, db: str, schema_filter: Optional[str], table_filter: Optional[str], gov_db: str):
        """Collect tables, columns and governance glossary/compliance info."""
        # Tables
        try:
            where_parts = [
                "TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA', 'DATA_CLASSIFICATION_GOVERNANCE')",
                "TABLE_TYPE IN ('BASE TABLE', 'VIEW')",
            ]
            params: Dict[str, Any] = {}
            if schema_filter:
                where_parts.append("UPPER(TABLE_SCHEMA) = UPPER(%(sc)s)")
                params["sc"] = schema_filter
            if table_filter:
                where_parts.append("TABLE_NAME ILIKE %(tb)s")
                params["tb"] = f"%{table_filter}%"
            where_sql = " AND ".join(where_parts)
            q_tables = f"""
                SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ROW_COUNT, CREATED, LAST_ALTERED, COMMENT
                FROM {db}.INFORMATION_SCHEMA.TABLES
                WHERE {where_sql}
                ORDER BY TABLE_SCHEMA, TABLE_NAME
            """
            t_rows = snowflake_connector.execute_query(q_tables, params) or []
            tables_df = pd.DataFrame(t_rows)
        except Exception:
            tables_df = pd.DataFrame()

        # Columns
        try:
            q_cols = f"""
                SELECT 
                    TABLE_SCHEMA,
                    TABLE_NAME,
                    COLUMN_NAME,
                    DATA_TYPE,
                    COMMENT AS COLUMN_COMMENT
                FROM {db}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA', 'SNOWFLAKE', 'DATA_CLASSIFICATION_GOVERNANCE')
            """
            params2: Dict[str, Any] = {}
            if schema_filter:
                q_cols += " AND TABLE_SCHEMA = %(sc)s"
                params2["sc"] = schema_filter
            if table_filter:
                q_cols += " AND TABLE_NAME ILIKE %(tb)s"
                params2["tb"] = f"%{table_filter}%"
            q_cols += " ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION"
            c_rows = snowflake_connector.execute_query(q_cols, params2) or []
            columns_df = pd.DataFrame(c_rows)
        except Exception:
            columns_df = pd.DataFrame()

        # Glossary / compliance mapping
        try:
            comp_map = getattr(self.ai_service, "_COMPLIANCE_MAP", {}) or {}
            # simple high-risk heuristic aligned with Avendra policy categories
            high_risk = {"PERSONAL_DATA", "FINANCIAL_DATA", "REGULATORY_DATA"}
            g_rows: List[Dict[str, Any]] = []
            for cat, tags in comp_map.items():
                g_rows.append({
                    "CATEGORY_NAME": str(cat).upper(),
                    "IS_HIGH_RISK": str(cat).upper() in high_risk,
                    "COMPLIANCE_TAGS": ", ".join(tags or [])
                })
            glossary_df = pd.DataFrame(g_rows)
        except Exception:
            glossary_df = pd.DataFrame()

        return tables_df, columns_df, glossary_df

    def _sample_column_values(self, db: str, schema: str, table: str, column: str, sample_rows: int = 100) -> List[Any]:
        """Sample non-null values from a specific column for semantics preview."""
        try:
            q = f"""
            SELECT "{column}" AS SAMPLE_VALUE
            FROM "{db}"."{schema}"."{table}"
            SAMPLE ({sample_rows} ROWS)
            WHERE "{column}" IS NOT NULL
            """
            rows = snowflake_connector.execute_query(q) or []
            return [r.get('SAMPLE_VALUE') for r in rows if r and r.get('SAMPLE_VALUE') is not None]
        except Exception:
            return []

    def _get_schema_filter(self) -> Optional[str]:
        """Get schema filter from session state."""
        try:
            gf = st.session_state.get("global_filters", {}) if hasattr(st, "session_state") else {}
            val = (
                st.session_state.get("schema_filter")
                or (gf.get("schema") if isinstance(gf, dict) else None)
            )
            if val and str(val).strip().upper() in {"ALL", "(ALL)", "*"}:
                return None
            return val
        except Exception:
            return None

    def _get_table_filter(self) -> Optional[str]:
        """Get table filter from session state."""
        try:
            gf = st.session_state.get("global_filters", {}) if hasattr(st, "session_state") else {}
            val = (gf.get("table") if isinstance(gf, dict) else None)
            if val and str(val).strip().upper() in {"ALL", "(ALL)", "*"}:
                return None
            return val
        except Exception:
            return None

    def _display_classification_results(self, results: List[Dict[str, Any]]) -> None:
        """Display the classification results in a structured format."""
        st.markdown("#### Classification Results")

        # Filter out errors for display
        successful_results = [r for r in results if 'error' not in r]

        if not successful_results:
            st.warning("No successful classifications to display.")
            return

        # Create display dataframe
        display_data = []
        for result in successful_results:
            asset = result['asset']
            display_data.append({
                "Asset": asset['full_name'],
                "Business Context": result.get('business_context', '')[:100] + '...' if result.get('business_context') and len(result.get('business_context', '')) > 100 else result.get('business_context', ''),
                "Category": result.get('category', 'N/A'),
                "Confidence": f"{result.get('confidence', 0):.1%}",
                "CIA Levels": f"{result.get('c', 'N/A')}/{result.get('i', 'N/A')}/{result.get('a', 'N/A')}",
                "Compliance": ", ".join(result.get('compliance', [])) if result.get('compliance') else 'N/A',
                "Label": result.get('label_emoji', result.get('label', 'N/A')),
                "Route": result.get('route', 'N/A'),
                "Status": result.get('application_status', 'N/A')
            })

        results_df = pd.DataFrame(display_data)
        st.dataframe(results_df, width='stretch', hide_index=True)

        # Show detailed results in expandable sections
        with st.expander("Detailed Results", expanded=False):
            for result in successful_results[:10]:  # Limit for performance
                asset = result['asset']
                with st.container():
                    col1, col2 = st.columns([1, 2])

                    with col1:
                        st.markdown(f"**{asset['full_name']}**")
                        st.write(f"**Category:** {result.get('category', 'N/A')}")
                        st.write(f"**Confidence:** {result.get('confidence', 0):.1%}")
                        st.write(f"**CIA:** {result.get('c', 'N/A')}/{result.get('i', 'N/A')}/{result.get('a', 'N/A')}")
                        st.write(f"**Label:** {result.get('label', 'N/A')}")
                        st.write(f"**Route:** {result.get('route', 'N/A')}")
                        st.write(f"**Compliance:** {', '.join(result.get('compliance', [])) if result.get('compliance') else 'None'}")
                        try:
                            # Auto-display column-level results if present on result
                            col_rows = result.get('column_results') or []
                            cols_df = pd.DataFrame(col_rows) if col_rows else pd.DataFrame()
                            if cols_df.empty:
                                st.caption("No sensitive columns detected by the current thresholds.")
                            else:
                                st.caption("Column-level classification:")
                                st.dataframe(cols_df, use_container_width=True, hide_index=True)
                        except Exception:
                            pass

                    with col2:
                        business_context = result.get('business_context', '')
                        if business_context:
                            st.write("**Business Context:**")
                            st.text_area("", value=business_context, height=80, disabled=True, key=f"context_{asset['full_name']}")

                        validation_issues = result.get('issues', [])
                        if validation_issues:
                            st.write("**Validation Issues:**")
                            for issue in validation_issues:
                                st.error(f"• {issue}")

                        sql_preview = result.get('sql_preview')
                        if sql_preview:
                            st.write("**SQL Preview:**")
                            st.code(sql_preview, language='sql')

                    st.divider()

        # Summary statistics
        self._display_summary_statistics(successful_results)

    def _display_summary_statistics(self, results: List[Dict[str, Any]]) -> None:
        """Display summary statistics of the classification results."""
        st.markdown("#### Summary Statistics")

        if not results:
            return

        # Calculate statistics
        categories = {}
        routes = {}
        statuses = {}
        confidence_ranges = {'High (≥80%)': 0, 'Medium (60-79%)': 0, 'Low (<60%)': 0}

        for result in results:
            # Categories
            cat = result.get('category', 'Unknown')
            categories[cat] = categories.get(cat, 0) + 1

            # Routes
            route = result.get('route', 'Unknown')
            routes[route] = routes.get(route, 0) + 1

            # Statuses
            status = result.get('application_status', 'Unknown')
            statuses[status] = statuses.get(status, 0) + 1

            # Confidence ranges
            conf = result.get('confidence', 0)
            if conf >= 0.8:
                confidence_ranges['High (≥80%)'] += 1
            elif conf >= 0.6:
                confidence_ranges['Medium (60-79%)'] += 1
            else:
                confidence_ranges['Low (<60%)'] += 1

        # Display in columns
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown("**Categories**")
            for cat, count in sorted(categories.items()):
                st.write(f"{cat}: {count}")

        with col2:
            st.markdown("**Routes**")
            for route, count in sorted(routes.items()):
                st.write(f"{route}: {count}")

        with col3:
            st.markdown("**Statuses**")
            for status, count in sorted(statuses.items()):
                st.write(f"{status}: {count}")

        with col4:
            st.markdown("**Confidence**")
            for range_name, count in confidence_ranges.items():
                st.write(f"{range_name}: {count}")


# Singleton instance
ai_classification_pipeline_service = AIClassificationPipelineService()
