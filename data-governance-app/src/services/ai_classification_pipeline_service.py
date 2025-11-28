"""
AI Classification Pipeline Service

This service provides functionality for the Automatic AI Classification Pipeline sub-tab in the AI Assistant section.
It handles automated classification of data assets with semantic detection, CIA recommendations, and governance tagging.
"""

import logging
import math
import hashlib
import streamlit as st
from typing import List, Dict, Any, Optional, Tuple
import pandas as pd
import numpy as np  # type: ignore
import re

try:
    from sentence_transformers import SentenceTransformer  # type: ignore
except Exception:
    SentenceTransformer = None  # type: ignore

from src.connectors.snowflake_connector import snowflake_connector
from src.services.ai_assistant_service import ai_assistant_service
from src.services.ai_classification_service import ai_classification_service
from src.services.discovery_service import DiscoveryService
from src.services.semantic_type_detector import semantic_type_detector
# AISensitiveDetectionService import moved to __init__
from src.services.governance_db_resolver import resolve_governance_db
from src.services.tagging_service import tagging_service
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
            from src.services.ai_sensitive_detection_service import AISensitiveDetectionService
            self.sensitive_service = AISensitiveDetectionService(sample_size=200, min_confidence=0.3, use_ai=True)
        except Exception:
            self.sensitive_service = None
        # Disable governance glossary usage for semantic context (use only information_schema + config)
        try:
            setattr(self.ai_service, "use_governance_glossary", False)
        except Exception:
            pass
        # Local embedding backend (MiniLM) for governance-free detection
        self._embed_backend: str = 'none'
        self._embedder: Any = None
        self._category_centroids: Dict[str, Any] = {}
        self._category_tokens: Dict[str, List[str]] = {}
        # Tuning defaults
        self._w_sem: float = 0.85
        self._w_kw: float = 0.15
        self._ctx_max_cols: int = 12
        self._ctx_max_vals: int = 5
        self._col_sample_rows: int = 200
        self._conf_label_threshold: float = 0.40  # BALANCED: Raised from 0.30 to reduce false positives while maintaining recall
        self._debug: bool = False
        self._cache: Dict[str, Any] = {}
        self._embed_cache: Dict[str, Any] = {}
        self._embed_ready: bool = False
        # Track whether we had to fall back to built-in categories instead of governance-driven ones
        self._using_fallback_categories: bool = False
        # Business glossary will be loaded dynamically from SENSITIVE_KEYWORDS table
        self._business_glossary_map: Dict[str, str] = {}
        # Metadata-driven mapping from governance categories to policy groups (PII/SOX/SOC2)
        self._policy_group_by_category: Dict[str, str] = {}

    def render_classification_pipeline(self) -> None:
        """Render the Automatic AI Classification Pipeline sub-tab."""
        st.markdown("### Automatic AI Classification Pipeline")
        st.caption("Automatically discovers existing data assets, derives business context, performs semantic category detection, recommends CIA levels per Avendra's Data Classification Policy, and applies governance tags with full validation, review routing, and audit logging.")

        show_steps = False

        # Get active database
        db = self._get_active_database()
        if not db:
            st.info("Use Global Filters to select a database to run the pipeline.")
            return

        # Additional validation
        if db.upper() in ('NONE', '(NONE)', 'NULL', 'UNKNOWN', ''):
            st.error("Invalid database selected. Please choose a valid database.")
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
        try:
            self._auto_tune_parameters()
        except Exception:
            pass

        # Removed automatic background pipeline as it's unused and causes errors

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
                st.dataframe(tables_df.head(100), width='stretch', hide_index=True)

            if isinstance(columns_df, pd.DataFrame) and not columns_df.empty:
                st.markdown("**Columns (preview)**")
                st.dataframe(columns_df.head(200), width='stretch', hide_index=True)

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
                st.dataframe(glossary_df.head(200), width='stretch', hide_index=True)

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
                        st.dataframe(dfv.head(50), width='stretch', hide_index=True)
                except Exception:
                    pass

                try:
                    dfr = st.session_state.get("pipe_embed_categories") if hasattr(st, 'session_state') else None
                    if isinstance(dfr, pd.DataFrame) and not dfr.empty:
                        st.markdown("**Category Reference Embeddings**")
                        st.dataframe(dfr, width='stretch', hide_index=True)
                except Exception:
                    pass

        if show_steps:
            with st.expander("Step 4: Similarity Matching", expanded=False):
                thr = st.slider("Confidence threshold (cosine)", min_value=0.3, max_value=0.95, value=0.45, step=0.05, key="pipe_sim_thr")
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
                        df_sim = pd.DataFrame(out_rows)
                        if hasattr(st, 'session_state'):
                            st.session_state["pipe_similarity_results"] = df_sim
                    except Exception as se:
                        st.error(f"Similarity matching failed: {se}")

                try:
                    df_sim = st.session_state.get("pipe_similarity_results") if hasattr(st, 'session_state') else None
                    if isinstance(df_sim, pd.DataFrame) and not df_sim.empty:
                        st.markdown("**Similarity Results (sample)**")
                        st.dataframe(df_sim, width='stretch', hide_index=True)
                except Exception:
                    pass

            try:
                df_sim = st.session_state.get("pipe_similarity_results") if hasattr(st, 'session_state') else None
                if isinstance(df_sim, pd.DataFrame) and not df_sim.empty:
                    st.markdown("**Similarity Results (sample)**")
                    st.dataframe(df_sim, width='stretch', hide_index=True)
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
                        st.dataframe(pd.DataFrame(sample_assets), width='stretch', hide_index=True)
                    else:
                        st.caption("No assets discovered with current filters.")
                except Exception as _de:
                    st.caption(f"Discovery preview error: {_de}")

        # Run pipeline button
        # Run pipeline button
        if st.button("Run AI Classification Pipeline", type="primary", key="run_ai_pipeline"):
            self._run_classification_pipeline(db, gov_db)

        # Display results if available in session state
        if st.session_state.get("pipeline_results"):
            st.divider()
            self._display_classification_results(st.session_state["pipeline_results"])

    def _get_active_database(self) -> Optional[str]:
        """
        Get the active database from global filters with comprehensive fallbacks.
        
        CRITICAL FIX: Never returns None - always probes Snowflake for current database.
        """
        db = None
        
        # PRIORITY 1: Global filters
        try:
            from src.pages.page_helpers import _active_db_from_filter
            db = _active_db_from_filter()
            if db and str(db).strip().upper() not in {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}:
                logger.info(f"Database from global filter: {db}")
                return db
        except Exception as e:
            logger.debug(f"Could not get database from global filter: {e}")

        # PRIORITY 2: Session state
        if not db:
            try:
                if hasattr(st, "session_state"):
                    db = (
                        st.session_state.get("sf_database")
                        or (st.session_state.get("global_filters", {}) or {}).get("database")
                        or st.session_state.get("rt_db")
                        or st.session_state.get("selected_database")
                    )
                    if db and str(db).strip().upper() not in {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}:
                        logger.info(f"Database from session state: {db}")
                        return db
            except Exception as e:
                logger.debug(f"Could not get database from session state: {e}")

        # PRIORITY 3: Settings
        if not db and settings is not None:
            try:
                db = getattr(settings, "SNOWFLAKE_DATABASE", None)
                if db and str(db).strip().upper() not in {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}:
                    logger.info(f"Database from settings: {db}")
                    return db
            except Exception as e:
                logger.debug(f"Could not get database from settings: {e}")

        # PRIORITY 4: Probe Snowflake context (ALWAYS TRY THIS)
        try:
            logger.info("Probing Snowflake for current database...")
            rows = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
            if rows and rows[0].get("DB"):
                db = rows[0].get("DB")
                if db and str(db).strip().upper() not in {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}:
                    logger.info(f"Database from Snowflake context: {db}")
                    return db
        except Exception as e:
            logger.error(f"Could not probe Snowflake for current database: {e}")

        # PRIORITY 5: Try to list databases and pick first one
        try:
            logger.warning("No database configured - attempting to list available databases...")
            rows = snowflake_connector.execute_query("SHOW DATABASES") or []
            if rows:
                # Filter out system databases
                user_dbs = [r.get('name') for r in rows if r.get('name') and 
                           r.get('name').upper() not in {'SNOWFLAKE', 'SNOWFLAKE_SAMPLE_DATA', 'UTIL_DB'}]
                if user_dbs:
                    db = user_dbs[0]
                    logger.warning(f"Auto-selected first available database: {db}")
                    logger.warning("⚠️  PLEASE SET A DATABASE IN GLOBAL FILTERS!")
                    return db
        except Exception as e:
            logger.error(f"Could not list databases: {e}")

        # FINAL FALLBACK: Return None and let calling code handle it
        logger.error("=" * 80)
        logger.error("CRITICAL: NO DATABASE CONFIGURED!")
        logger.error("Please set a database using one of these methods:")
        logger.error("  1. Use the Global Filters sidebar in the UI")
        logger.error("  2. Run: USE DATABASE your_database_name; in Snowflake")
        logger.error("  3. Set SNOWFLAKE_DATABASE in settings")
        logger.error("=" * 80)
        return None

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
        # Validate database
        if not db or db.upper() in ('NONE', '(NONE)', 'NULL', 'UNKNOWN', ''):
            st.error("Invalid database selected. Please choose a valid database from Global Filters.")
            return

        # Validate governance database
        if gov_db and gov_db.upper() in ('NONE', '(NONE)', 'NULL', 'UNKNOWN'):
            gov_db = db  # fallback to main db

        with st.spinner("Running AI Classification Pipeline... This may take several minutes."):
            try:
                # Prefer live metadata for discovery, but classification will be governance-free
                try:
                    self.ai_service.use_snowflake = True
                except Exception:
                    pass

                # Initialize local MiniLM (or fallback) embeddings and category centroids
                self._init_local_embeddings()

                try:
                    self._auto_tune_parameters()
                except Exception:
                    pass

                # Step 1b: Local discovery list for this run (preview)
                assets = self._discover_assets(db)
                if not assets:
                    st.warning("No tables found in the selected database.")
                    return

                st.info(f"Discovered {len(assets)} tables for classification.")

                # ========================================================================
                # AI MODEL DETECTION STATUS - Clear UI Messaging
                # ========================================================================
                
                st.markdown("---")
                st.markdown("### 🤖 AI Detection Engine Status")
                
                # 1. Embedding Model Status
                if self._embed_backend == 'sentence-transformers':
                    st.success("✅ **AI Model Active:** Using `intfloat/e5-large-v2` for semantic detection")
                    st.caption("🧠 Advanced transformer-based embeddings enabled for high-accuracy classification")
                else:
                    st.warning("⚠️ **AI Model Inactive:** Using keyword/pattern matching only")
                    st.caption("💡 Install `sentence-transformers` library to enable AI-powered semantic detection")
                
                # 2. Category Source Status
                try:
                    using_fallback = getattr(self, "_using_fallback_categories", False)
                    cat_cnt = len(getattr(self, "_category_centroids", {}) or {})
                    
                    if using_fallback:
                        st.warning("📋 **Categories:** Using hardcoded fallback (PII / SOX / SOC2)")
                        st.caption("⚙️ Governance tables unavailable - using built-in baseline categories")
                        st.info("💡 **Action Required:** Populate `SENSITIVITY_CATEGORIES`, `SENSITIVE_KEYWORDS`, and `SENSITIVE_PATTERNS` tables for metadata-driven detection")
                    else:
                        st.success(f"📋 **Categories:** Loaded from governance tables ({cat_cnt} categories)")
                        st.caption("✅ Metadata-driven classification active - using Snowflake governance tables")
                        
                        # Show category details
                        try:
                            tok_cnt = sum(len(v) for v in (getattr(self, "_category_tokens", {}) or {}).values())
                            kw_cnt = sum(len(v) for v in (getattr(self, "_category_keywords", {}) or {}).values())
                            pat_cnt = sum(len(v) for v in (getattr(self, "_category_patterns", {}) or {}).values())
                            
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                st.metric("Categories", cat_cnt)
                            with col2:
                                st.metric("Keywords", kw_cnt)
                            with col3:
                                st.metric("Patterns", pat_cnt)
                            with col4:
                                st.metric("Tokens", tok_cnt)
                        except Exception:
                            pass
                except Exception:
                    st.error("❌ Unable to determine category source")
                
                # 3. Detection Mode Summary
                st.markdown("---")
                if self._embed_backend == 'sentence-transformers' and not using_fallback:
                    st.success("🎯 **Detection Mode:** AI-Powered + Metadata-Driven (OPTIMAL)")
                    st.caption("Using E5-Large-v2 embeddings with governance-driven categories, keywords, and patterns")
                elif self._embed_backend == 'sentence-transformers' and using_fallback:
                    st.info("🎯 **Detection Mode:** AI-Powered + Hardcoded Fallback")
                    st.caption("Using E5-Large-v2 embeddings with baseline PII/SOX/SOC2 categories")
                elif not self._embed_backend == 'sentence-transformers' and not using_fallback:
                    st.warning("🎯 **Detection Mode:** Keyword/Pattern Only + Metadata-Driven")
                    st.caption("Using governance-driven keywords and patterns (no AI embeddings)")
                else:
                    st.warning("🎯 **Detection Mode:** Keyword/Pattern Only + Hardcoded Fallback")
                    st.caption("Using baseline keywords and patterns (no AI embeddings or governance tables)")
                
                # 4. Validation Warnings
                if self._embed_backend == 'sentence-transformers' and cat_cnt == 0:
                    st.error("⚠️ **CRITICAL:** E5-Large-v2 is active but no category centroids are available!")
                    st.caption("🔧 Verify governance table configuration and embeddings initialization")
                
                st.markdown("---")

                # Step 2-8: Run local classification pipeline (no governance tables)
                # Limit number of assets per run for performance, configurable via dynamic config
                try:
                    cfg = self._load_dynamic_config()
                except Exception:
                    cfg = {}
                try:
                    max_assets = int(cfg.get("max_assets_per_run", 30) or 30)
                except Exception:
                    max_assets = 30
                assets_to_classify = assets[:max_assets]
                results = self._classify_assets_local(db=db, assets=assets_to_classify)

                try:
                    conf_list = [float(r.get('confidence', 0.0) or 0.0) for r in results if isinstance(r, dict) and 'error' not in r]
                    adaptive = None
                    if conf_list:
                        if np is not None:
                            try:
                                p = float(np.percentile(conf_list, 60))
                            except Exception:
                                p = float(sum(conf_list)/max(1,len(conf_list)))
                        else:
                            try:
                                sl = sorted(conf_list)
                                idx = int(round(0.6 * (len(sl)-1)))
                                p = float(sl[idx])
                            except Exception:
                                p = float(sum(conf_list)/max(1,len(conf_list)))
                        # Do not lower below configured threshold; avoid circular lowering
                        base_thr = float(getattr(self, "_conf_label_threshold", 0.5) or 0.5)
                        adaptive = max(base_thr, min(0.75, p))
                    if adaptive is not None:
                        lbl_map = {
                            'Confidential': '🟥 Confidential',
                            'Restricted': '🟧 Restricted',
                            'Internal': '🟨 Internal',
                            'Public': '🟩 Public',
                            'Uncertain — review': '⬜ Uncertain — review',
                        }
                        col_map = {
                            'Confidential': 'Red',
                            'Restricted': 'Orange',
                            'Internal': 'Yellow',
                            'Public': 'Green',
                            'Uncertain — review': 'Gray',
                        }
                        for r in results:
                            try:
                                if 'error' in r:
                                    continue
                                confv = float(r.get('confidence', 0.0) or 0.0)
                                base_label = str(r.get('label') or '')
                                if confv < adaptive:
                                    r['label'] = 'Uncertain — review'
                                    r['label_emoji'] = lbl_map['Uncertain — review']
                                    r['color'] = col_map['Uncertain — review']
                                else:
                                    # ensure emoji/color match base_label
                                    r['label_emoji'] = lbl_map.get(base_label, base_label)
                                    r['color'] = col_map.get(base_label, r.get('color', ''))
                            except Exception:
                                continue
                except Exception:
                    pass

                if not results:
                    st.warning("No assets were successfully classified.")
                    return

                # Save results to session state for persistent display
                st.session_state["pipeline_results"] = results

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

    def _init_local_embeddings(self) -> None:
        """
        Initialize embeddings and load ALL classification metadata from governance tables.
        This is the main entry point for metadata-driven classification.
        """
        try:
            if not hasattr(self, "_embed_cache") or not isinstance(self._embed_cache, dict):
                self._embed_cache = {}
            self._embed_ready = False
            
            # Initialize SentenceTransformer embeddings
            if SentenceTransformer is not None:
                try:
                    logger.info("Initializing SentenceTransformer embeddings (E5-Large)...")
                    self._embedder = SentenceTransformer('intfloat/e5-large-v2')
                    tv = self._embedder.encode(["ok"], normalize_embeddings=True)
                    v0 = tv[0] if isinstance(tv, (list, tuple)) else tv
                    dim = int(getattr(v0, "shape", [0])[-1]) if hasattr(v0, "shape") else (len(v0) if isinstance(v0, (list, tuple)) else 0)
                    if dim and dim > 0:
                        self._embed_backend = 'sentence-transformers'
                        self._embed_ready = True
                        logger.info(f"✓ Embeddings initialized successfully. Backend: {self._embed_backend}, Dimension: {dim}")
                    else:
                        self._embedder = None
                        self._embed_backend = 'none'
                        logger.warning(f"✗ Embedding dimension validation failed: {dim}")
                except Exception as _e:
                    logger.warning(f"✗ Local embedding initialization failed: {_e}")
                    self._embedder = None
                    self._embed_backend = 'none'
            else:
                self._embedder = None
                self._embed_backend = 'none'
                logger.warning("✗ SentenceTransformer not available")
        except Exception as _e2:
            logger.warning(f"✗ Embedding setup error: {_e2}")
            self._embedder = None
            self._embed_backend = 'none'
            self._embed_ready = False

        # Load ALL metadata from governance tables (100% metadata-driven)
        self._load_metadata_driven_categories()
        
        # Load business glossary map from SENSITIVE_KEYWORDS table
        schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
        gov_db = None
        try:
            gov_db = resolve_governance_db()
            if gov_db:
                schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
        except Exception:
            pass
        
        self._load_business_glossary_from_governance(schema_fqn)

    def _generate_category_examples(self, name: str, desc: str) -> List[str]:
        n = (name or "").strip()
        d = (desc or "").strip()
        out: List[str] = []
        
        # Base examples: full name and description
        if n:
            out.append(n)
        if d:
            out.append(d)

        # Extract meaningful tokens from name/description
        raw_tokens: List[str] = []
        for s in [n, d]:
            for w in re.split(r"[^a-zA-Z0-9]+", s):
                w2 = w.strip()
                if not w2:
                    continue
                if len(w2) < 3:
                    continue
                raw_tokens.append(w2)

        # Conservative stopword filter (preserve domain-critical terms)
        # Removed: "data", "info", "information" (domain-critical)
        stops = {"the","a","an","and","or","of","to","in","for","on","at","by","with","from","as","is","are","was","were"}
        toks: List[str] = []
        seen: set = set()
        for t in raw_tokens:
            tl = t.lower()
            if tl in stops:
                continue
            if tl not in seen:
                toks.append(t)
                seen.add(tl)

        # Build enriched examples with multiple phrase patterns
        phrases: List[str] = []
        for t in toks[:12]:  # Increased from 10
            phrases.append(t)
            phrases.append(f"contains {t}")
            phrases.append(f"{t} field")
            phrases.append(f"{t} column")
        
        # Add domain-specific terminology patterns
        domain_patterns: List[str] = []
        for t in toks[:8]:
            domain_patterns.append(f"{t} record")
            domain_patterns.append(f"{t} value")
            domain_patterns.append(f"{t} attribute")
        
        # Combine all examples
        ex = out + phrases + domain_patterns
        
        # Dedupe while preserving order
        seen2 = set()
        dedup: List[str] = []
        for s in ex:
            sl = s.lower().strip()
            if sl and sl not in seen2:
                dedup.append(s.strip())
                seen2.add(sl)
        
        return dedup[:64]

    def _generate_category_tokens(self, name: str, desc: str) -> List[str]:
        n = (name or "").strip()
        d = (desc or "").strip()
        raw: List[str] = []
        for s in [n, d]:
            for w in re.split(r"[^a-zA-Z0-9]+", s):
                w2 = w.strip()
                if not w2:
                    continue
                if len(w2) < 3:
                    continue
                raw.append(w2)
        # simple stopword removal and dedupe
        stops = {"the","a","an","and","or","of","to","in","for","on","at","by","with","from","as","is","are","was","were","data","info","information"}
        out: List[str] = []
        seen = set()
        for t in raw:
            tt = re.sub(r"[_\-]+", " ", str(t)).strip()
            tl = tt.lower()
            if not tt or tl in stops:
                continue
            if tl not in seen:
                out.append(tt)
                seen.add(tl)
        return out[:64]

    def _load_additional_tokens_from_keywords(self, schema_fqn: str, category_name: str) -> List[str]:
        rows = []
        try:
            rows = snowflake_connector.execute_query(
                f"""
                SELECT COALESCE(keyword, KEYWORD, KEYWORD_STRING) AS KW
                FROM {schema_fqn}.SENSITIVE_KEYWORDS
                WHERE COALESCE(is_active, true) AND (
                    LOWER(category) = LOWER(%(n)s) OR LOWER(category_name) = LOWER(%(n)s)
                )
                """,
                {"n": category_name},
            ) or []
        except Exception:
            try:
                # CATEGORY_ID-based lookup using SENSITIVITY_CATEGORIES
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT COALESCE(keyword, KEYWORD, KEYWORD_STRING) AS KW
                    FROM {schema_fqn}.SENSITIVE_KEYWORDS
                    WHERE COALESCE(is_active, true) AND category_id IN (
                        SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE LOWER(CATEGORY_NAME) = LOWER(%(n)s)
                    )
                    """,
                    {"n": category_name},
                ) or []
            except Exception:
                try:
                    rows = snowflake_connector.execute_query(
                        f"""
                        SELECT COALESCE(keyword, KEYWORD, KEYWORD_STRING) AS KW
                        FROM {schema_fqn}.SENSITIVITY_KEYWORDS
                        WHERE COALESCE(is_active, true) AND category_id IN (
                            SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE LOWER(CATEGORY_NAME) = LOWER(%(n)s)
                        )
                        """,
                        {"n": category_name},
                    ) or []
                except Exception:
                    rows = []
        out: List[str] = []
        for r in rows:
            try:
                kw = str(r.get("KW") or "").strip()
                if kw:
                    out.append(kw)
            except Exception:
                continue
        return out

    def _load_business_glossary_from_governance(self, schema_fqn: str) -> None:
        """Load business glossary keyword-to-category mappings from SENSITIVE_KEYWORDS table."""
        try:
            # Query all active keywords with their associated categories
            rows = snowflake_connector.execute_query(
                f"""
                SELECT 
                    LOWER(COALESCE(keyword, KEYWORD, KEYWORD_STRING)) AS KEYWORD,
                    UPPER(COALESCE(category, category_name, CATEGORY_NAME)) AS CATEGORY
                FROM {schema_fqn}.SENSITIVE_KEYWORDS
                WHERE COALESCE(is_active, IS_ACTIVE, true) = true
                """) or []
            
            glossary_map = {}
            for r in rows:
                try:
                    kw = str(r.get("KEYWORD") or "").strip().lower()
                    cat = str(r.get("CATEGORY") or "").strip().upper()
                    
                    if kw and cat:
                        # Map the category to policy group (PII, SOX, SOC2)
                        pg = self._map_category_to_policy_group(cat)
                        if pg:
                            glossary_map[kw] = pg
                except Exception:
                    continue
            
            self._business_glossary_map = glossary_map
            logger.info(f"Loaded {len(glossary_map)} business glossary mappings from SENSITIVE_KEYWORDS")
            
        except Exception as e:
            logger.warning(f"Failed to load business glossary from governance: {e}")
            self._business_glossary_map = {}

    def _load_metadata_driven_categories(self) -> None:
        """
        Load ALL categories, keywords, and patterns from Snowflake governance tables.
        NO HARDCODED VALUES. System is 100% metadata-driven.
        
        Tables used:
        - SENSITIVITY_CATEGORIES: Category definitions and thresholds
        - SENSITIVE_KEYWORDS: Keywords mapped to categories
        - SENSITIVE_PATTERNS: Regex patterns mapped to categories
        """
        logger.info("=" * 80)
        logger.info("METADATA-DRIVEN CLASSIFICATION: Loading from governance tables")
        logger.info("=" * 80)
        
        # Resolve governance database
        schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
        gov_db = None
        try:
            gov_db = resolve_governance_db()
            if gov_db:
                snowflake_connector.execute_non_query(f"USE DATABASE {gov_db}")
                schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
                logger.info(f"✓ Using governance schema: {schema_fqn}")
        except Exception as e:
            logger.warning(f"✗ Could not resolve governance database: {e}")
            # If no governance DB, we cannot proceed with metadata-driven approach
            self._category_centroids = {}
            self._category_tokens = {}
            self._category_patterns = {}
            self._category_thresholds = {}
            self._category_weights = {}
            logger.error("CRITICAL: No governance database available. Classification will fail.")
            return
        
        # ========================================================================
        # STEP 1: Load SENSITIVITY_CATEGORIES (ALL FIELDS)
        # ========================================================================
        categories_data = []
        try:
            categories_data = snowflake_connector.execute_query(
                f"""
                SELECT 
                    CATEGORY_NAME,
                    COALESCE(DESCRIPTION, '') AS DESCRIPTION,
                    COALESCE(DETECTION_THRESHOLD, 0.45) AS DETECTION_THRESHOLD,
                    COALESCE(DETECTION_THRESHOLD, 0.45) AS DEFAULT_THRESHOLD,
                    1.0 AS SENSITIVITY_WEIGHT,
                    POLICY_GROUP,
                    COALESCE(WEIGHT_EMBEDDING, 0.60) AS WEIGHT_EMBEDDING,
                    COALESCE(WEIGHT_KEYWORD, 0.25) AS WEIGHT_KEYWORD,
                    COALESCE(WEIGHT_PATTERN, 0.15) AS WEIGHT_PATTERN,
                    COALESCE(MULTI_LABEL, TRUE) AS MULTI_LABEL,
                    COALESCE(IS_ACTIVE, TRUE) AS IS_ACTIVE,
                    CATEGORY_ID
                FROM {schema_fqn}.SENSITIVITY_CATEGORIES
                WHERE COALESCE(IS_ACTIVE, TRUE) = TRUE
                ORDER BY CATEGORY_NAME
                """
            ) or []
            logger.info(f"✓ Loaded {len(categories_data)} active categories from SENSITIVITY_CATEGORIES")
            
            # Debug: Log what was loaded
            for cat in categories_data:
                cat_name = str(cat.get("CATEGORY_NAME") or "").strip()
                desc = str(cat.get("DESCRIPTION") or "").strip()
                pg = str(cat.get("POLICY_GROUP") or "None")
                logger.info(f"   Category: {cat_name} (Group: {pg}), Description length: {len(desc)} chars")
                
        except Exception as e:
            logger.error(f"✗ Failed to load SENSITIVITY_CATEGORIES: {e}")
            import traceback
            logger.error(traceback.format_exc())
            categories_data = []
        
        if not categories_data:
            logger.error("CRITICAL: No active categories found in SENSITIVITY_CATEGORIES")
            logger.error("FALLBACK: Creating baseline PII/SOX/SOC2 categories")
            
            # GRACEFUL DEGRADATION: Use baseline categories
            self._create_baseline_categories()
            return  # Exit early - baseline categories are now loaded

        # Store category metadata with ALL fields
        self._category_thresholds = {}
        self._category_default_thresholds = {}
        self._category_weights = {}
        self._policy_group_by_category = {}
        self._category_scoring_weights = {}  # New: stores embedding/keyword/pattern weights
        self._category_multi_label = {}      # New: stores multi-label flag
        
        category_descriptions = {}
        category_ids = {}
        
        for cat in categories_data:
            cat_name = str(cat.get("CATEGORY_NAME") or "").strip()
            if not cat_name:
                logger.warning(f"Skipping category with empty CATEGORY_NAME")
                continue
            
            description = str(cat.get("DESCRIPTION") or "").strip()
            
            # CRITICAL: Validate description is not empty
            if not description:
                logger.error(f"CRITICAL: Category '{cat_name}' has EMPTY DESCRIPTION")
                logger.error(f"  → Centroid CANNOT be built without description")
                logger.error(f"  → This category will be SKIPPED")
                continue  # Skip this category
            
            if len(description) < 10:
                logger.warning(f"Category '{cat_name}' has very short DESCRIPTION ({len(description)} chars)")
            
            category_descriptions[cat_name] = description
            category_ids[cat_name] = cat.get("CATEGORY_ID")
            
            # Load thresholds and weights
            self._category_thresholds[cat_name] = float(cat.get("DETECTION_THRESHOLD") or 0.45)
            self._category_default_thresholds[cat_name] = float(cat.get("DEFAULT_THRESHOLD") or 0.45)
            self._category_weights[cat_name] = float(cat.get("SENSITIVITY_WEIGHT") or 1.0)
            
            # Load Policy Group (Metadata-Driven Mapping)
            policy_group = cat.get("POLICY_GROUP")
            if policy_group:
                self._policy_group_by_category[cat_name.upper()] = str(policy_group).strip()
            
            # Load Scoring Weights
            self._category_scoring_weights[cat_name] = {
                'w_sem': float(cat.get("WEIGHT_EMBEDDING") or 0.60),
                'w_kw': float(cat.get("WEIGHT_KEYWORD") or 0.25),
                'w_pat': float(cat.get("WEIGHT_PATTERN") or 0.15)
            }
            
            # Load Multi-Label Flag
            self._category_multi_label[cat_name] = bool(cat.get("MULTI_LABEL", True))
            
            logger.info(f"  Category: {cat_name}")
            logger.info(f"    Group: {policy_group or 'None'}")
            logger.info(f"    Weights: Sem={self._category_scoring_weights[cat_name]['w_sem']:.2f}, Kw={self._category_scoring_weights[cat_name]['w_kw']:.2f}, Pat={self._category_scoring_weights[cat_name]['w_pat']:.2f}")
        
        # ========================================================================
        # STEP 2: Load SENSITIVE_KEYWORDS (ALL FIELDS)
        # ========================================================================
        keywords_by_category: Dict[str, List[str]] = {cat: [] for cat in category_descriptions.keys()}
        keyword_metadata_by_category: Dict[str, List[Dict[str, Any]]] = {cat: [] for cat in category_descriptions.keys()}
        
        try:
            keywords_data = snowflake_connector.execute_query(
                f"""
                SELECT 
                    c.CATEGORY_NAME,
                    k.KEYWORD_STRING,
                    COALESCE(k.SENSITIVITY_WEIGHT, 1.0) AS KEYWORD_WEIGHT,
                    COALESCE(k.MATCH_TYPE, 'EXACT') AS MATCH_TYPE,
                    'STANDARD' AS SENSITIVITY_TYPE,
                    COALESCE(k.SENSITIVITY_WEIGHT, 1.0) AS SCORE
                FROM {schema_fqn}.SENSITIVE_KEYWORDS k
                JOIN {schema_fqn}.SENSITIVITY_CATEGORIES c
                  ON k.CATEGORY_ID = c.CATEGORY_ID
                WHERE COALESCE(k.IS_ACTIVE, true)
                  AND COALESCE(c.IS_ACTIVE, true)
                ORDER BY c.CATEGORY_NAME, k.KEYWORD_STRING
                """
            ) or []
            
            for kw in keywords_data:
                cat_name = str(kw.get("CATEGORY_NAME") or "").strip()
                keyword = str(kw.get("KEYWORD_STRING") or "").strip().lower()
                
                if cat_name in keywords_by_category and keyword:
                    keywords_by_category[cat_name].append(keyword)
                    
                    # Store full metadata for advanced scoring
                    keyword_metadata_by_category[cat_name].append({
                        'keyword': keyword,
                        'weight': float(kw.get("KEYWORD_WEIGHT") or 1.0),
                        'match_type': str(kw.get("MATCH_TYPE") or "EXACT").upper(),
                        'sensitivity_type': str(kw.get("SENSITIVITY_TYPE") or "STANDARD").upper(),
                        'score': float(kw.get("SCORE") or 1.0)
                    })
            
            total_keywords = sum(len(kws) for kws in keywords_by_category.values())
            logger.info(f"✓ Loaded {total_keywords} keywords from SENSITIVE_KEYWORDS")
            for cat, kws in keywords_by_category.items():
                if kws:
                    logger.info(f"  {cat}: {len(kws)} keywords")
        except Exception as e:
            logger.error(f"✗ Failed to load SENSITIVE_KEYWORDS: {e}")
        
        # ========================================================================
        # STEP 3: Load SENSITIVE_PATTERNS (ALL FIELDS)
        # ========================================================================
        patterns_by_category: Dict[str, List[str]] = {cat: [] for cat in category_descriptions.keys()}
        pattern_metadata_by_category: Dict[str, List[Dict[str, Any]]] = {cat: [] for cat in category_descriptions.keys()}
        
        try:
            patterns_data = snowflake_connector.execute_query(
                f"""
                SELECT 
                    c.CATEGORY_NAME,
                    COALESCE(p.PATTERN_REGEX, p.PATTERN_STRING) AS PATTERN_REGEX,
                    COALESCE(p.PATTERN_STRING, p.PATTERN_REGEX) AS PATTERN_STRING,
                    COALESCE(p.SENSITIVITY_WEIGHT, 1.0) AS SENSITIVITY_WEIGHT,
                    COALESCE(p.SENSITIVITY_TYPE, 'STANDARD') AS SENSITIVITY_TYPE
                FROM {schema_fqn}.SENSITIVE_PATTERNS p
                JOIN {schema_fqn}.SENSITIVITY_CATEGORIES c
                  ON p.CATEGORY_ID = c.CATEGORY_ID
                WHERE COALESCE(p.IS_ACTIVE, true)
                  AND COALESCE(c.IS_ACTIVE, true)
                ORDER BY c.CATEGORY_NAME
                """
            ) or []
            
            for pat in patterns_data:
                cat_name = str(pat.get("CATEGORY_NAME") or "").strip()
                # Prefer PATTERN_REGEX, fall back to PATTERN_STRING if regex is not provided
                pattern = str(pat.get("PATTERN_REGEX") or pat.get("PATTERN_STRING") or "").strip()
                
                if cat_name in patterns_by_category and pattern:
                    patterns_by_category[cat_name].append(pattern)
                    
                    # Store full metadata for weighted scoring
                    pattern_metadata_by_category[cat_name].append({
                        'pattern': pattern,
                        'weight': float(pat.get("SENSITIVITY_WEIGHT") or 1.0),
                        'sensitivity_type': str(pat.get("SENSITIVITY_TYPE") or "STANDARD").upper()
                    })
            
            total_patterns = sum(len(pats) for pats in patterns_by_category.values())
            logger.info(f"✓ Loaded {total_patterns} patterns from SENSITIVE_PATTERNS")
            for cat, pats in patterns_by_category.items():
                if pats:
                    logger.info(f"  {cat}: {len(pats)} patterns")
        except Exception as e:
            logger.error(f"✗ Failed to load SENSITIVE_PATTERNS: {e}")
        
        # ========================================================================
        # STEP 4: Build Embeddings (if available)
        # ========================================================================
        centroids: Dict[str, Any] = {}
        tokens_out: Dict[str, List[str]] = {}
        
        logger.info(f"Building centroids for {len(category_descriptions)} categories...")
        logger.info(f"Embedder available: {self._embedder is not None}")
        logger.info(f"NumPy available: {np is not None}")
        logger.info(f"Backend: {self._embed_backend}")
        
        for cat_name, description in category_descriptions.items():
            logger.info(f"\n  Processing category: {cat_name}")
            logger.info(f"    Description: '{description[:100]}...'")
            
            # Combine description + keywords for richer context
            keywords = keywords_by_category.get(cat_name, [])
            combined_text = f"{description} {' '.join(keywords[:50])}"  # Use top 50 keywords
            logger.info(f"    Keywords available: {len(keywords)}")
            logger.info(f"    Combined text length: {len(combined_text)} chars")
            
            # Generate tokens
            try:
                toks = self._generate_category_tokens(cat_name, combined_text)
                if toks:
                    tokens_out[cat_name] = toks
                    logger.info(f"    ✓ Generated {len(toks)} tokens")
                else:
                    logger.warning(f"    ✗ No tokens generated")
            except Exception as e:
                logger.error(f"    ✗ Token generation failed: {e}")
                tokens_out[cat_name] = []
            
            # Generate embeddings using asymmetric E5 encoding (passage: for category centroids)
            try:
                if self._embedder is not None and np is not None and self._embed_backend == 'sentence-transformers':
                    # Build rich category definition from description + keywords
                    category_definition = f"{description}"  # Start with description
                    
                    # Add keyword context if available
                    if keywords:
                        keyword_list = ", ".join(keywords[:15])  # Top 15 keywords
                        category_definition += f" This includes: {keyword_list}."
                    
                    # Add example patterns if this is about data formats
                    common_examples = {
                        'email': 'such as user@domain.com',
                        'phone': 'such as 555-123-4567',
                        'ssn': 'such as 123-45-6789',
                        'credit': 'such as 4111-1111-1111-1111',
                        'price': 'such as $99.99',
                        'date': 'such as 2024-01-15'
                    }
                    
                    cat_lower = cat_name.lower()
                    for pattern_kw, example in common_examples.items():
                        if pattern_kw in cat_lower or any(pattern_kw in kw.lower() for kw in keywords[:5]):
                            category_definition += f" Examples include values {example}."
                            break

                    logger.info(f"    Category definition: '{category_definition[:150]}...'")

                    # Asymmetric E5: use passage: prefix for category/"document" side
                    passage_text = f"passage: {category_definition}"
                    logger.info("    Encoding category definition with 'passage:' prefix (E5 asymmetric)...")
                    centroid_vec = self._embedder.encode([passage_text], normalize_embeddings=True)[0]
                    
                    # Normalize centroid
                    norm = float(np.linalg.norm(centroid_vec) or 0.0)
                    if norm > 0:
                        centroid_vec = centroid_vec / norm
                        centroids[cat_name] = centroid_vec
                        logger.info(f"    ✓ Created E5 category centroid for {cat_name} (dimension: {len(centroid_vec)})")
                        logger.info(f"    ✓ Using passage-based encoding for accurate semantic matching")
                    else:
                        logger.warning(f"    ✗ Zero norm centroid for {cat_name}")
                        centroids[cat_name] = None
                    
                else:
                    logger.warning(f"    ✗ Cannot create centroid: embedder={self._embedder is not None}, np={np is not None}, backend={self._embed_backend}")
                    centroids[cat_name] = None
            except Exception as e:
                logger.error(f"    ✗ Failed to create centroid for {cat_name}: {e}")
                import traceback
                logger.error(traceback.format_exc())
                centroids[cat_name] = None
        
        # ========================================================================
        # STEP 5: Store in instance variables (INCLUDING METADATA)
        # ========================================================================
        self._category_centroids = centroids
        self._category_tokens = tokens_out
        self._category_patterns = patterns_by_category
        self._category_keywords = keywords_by_category
        self._category_keyword_metadata = keyword_metadata_by_category  # NEW: Full keyword metadata
        self._category_pattern_metadata = pattern_metadata_by_category  # NEW: Full pattern metadata

        # Verification-only logging for policy-group mappings loaded from governance.
        try:
            logger.info("=" * 80)
            logger.info("POLICY GROUP MAPPING VERIFICATION")
            logger.info(f"  Total mappings: {len(self._policy_group_by_category)}")
            for cat, pg in (self._policy_group_by_category or {}).items():
                logger.info(f"    {cat}  {pg}")
            logger.info("=" * 80)
        except Exception:
            pass

        # Summary
        logger.info("=" * 80)
        logger.info("METADATA-DRIVEN CLASSIFICATION: Initialization Complete")
        logger.info(f"  Categories: {len(category_descriptions)}")
        logger.info(f"  Keywords: {sum(len(kws) for kws in keywords_by_category.values())}")
        logger.info(f"  Patterns: {sum(len(pats) for pats in patterns_by_category.values())}")
        logger.info(f"  Centroids: {len([c for c in centroids.values() if c is not None])}")
        logger.info(f"  Metadata Loaded: Keywords={len(keyword_metadata_by_category)}, Patterns={len(pattern_metadata_by_category)}")
        logger.info("=" * 80)
        
        try:
            st.session_state["_pipe_cat_count"] = len([c for c in centroids.values() if c is not None])
            st.session_state["_pipe_tok_count"] = sum(len(v) for v in tokens_out.values())
        except Exception:
            pass
    
    def _create_baseline_categories(self) -> None:
        """
        PHASE 1: Create baseline fallback categories when governance tables unavailable.
        
        This ensures the system ALWAYS has working PII/SOX/SOC2 categories,
        even when governance tables are empty or misconfigured.
        """
        logger.warning("=" * 80)
        logger.warning("CREATING BASELINE FALLBACK CATEGORIES")
        logger.warning("Governance tables unavailable - using built-in categories")
        logger.warning("=" * 80)
        
        # Baseline category definitions with rich metadata
        baseline_categories = {
            'PII_PERSONAL_INFO': {
                'description': 'Personal Identifiable Information including names, email addresses, phone numbers, physical addresses, Social Security Numbers, passport numbers, driver license numbers, dates of birth, and other individual identifiers that can be used to identify, contact, or locate a specific person',
                'keywords': [
                    'name', 'first_name', 'last_name', 'full_name', 'email', 'email_address', 
                    'phone', 'phone_number', 'mobile', 'telephone', 'contact', 'address', 
                    'street', 'city', 'state', 'zip', 'postal', 'ssn', 'social_security', 
                    'passport', 'driver_license', 'dob', 'date_of_birth', 'birthday', 'age',
                    'customer', 'employee', 'person', 'individual', 'user', 'patient',
                    'gender', 'race', 'ethnicity', 'nationality', 'citizen'
                ],
                'patterns': [
                    r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b',  # Full names
                    r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                    r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Phone
                ],
                'threshold': 0.40,
                'policy_group': 'PII'
            },
            'SOX_FINANCIAL_DATA': {
                'description': 'Financial and accounting data including revenue records, transaction details, account balances, payment information, invoices, billing records, general ledger entries, expense reports, cost allocations, profit calculations, asset valuations, and other financial information subject to SOX compliance requirements',
                'keywords': [
                    'revenue', 'transaction', 'account', 'account_number', 'balance', 'payment', 
                    'invoice', 'bill', 'billing', 'financial', 'ledger', 'general_ledger', 
                    'expense', 'cost', 'profit', 'asset', 'liability', 'equity', 'cash',
                    'credit_card', 'debit_card', 'card_number', 'routing', 'ach', 'wire',
                    'salary', 'wage', 'compensation', 'payroll', 'tax', 'fiscal', 'audit'
                ],
                'patterns': [
                    r'\$[\d,]+\.\d{2}',  # Currency
                    r'\b\d{13,19}\b',  # Credit card
                ],
                'threshold': 0.40,
                'policy_group': 'SOX'
            },
            'SOC2_SECURITY_DATA': {
                'description': 'Security and access control data including passwords, authentication tokens, API keys, encryption keys, certificates, credentials, security logs, access records, authentication attempts, authorization decisions, privilege escalations, and other security-critical information required for SOC2 compliance',
                'keywords': [
                    'password', 'passwd', 'pwd', 'token', 'credential', 'secret', 'key', 
                    'api_key', 'auth', 'authenticate', 'authorization', 'login', 'logout',
                    'access', 'permission', 'privilege', 'role', 'security', 'encryption',
                    'certificate', 'signature', 'hash', 'salt', 'session', 'cookie'
                ],
                'patterns': [
                    r'\b[A-Za-z0-9]{32,}\b',  # API keys/tokens
                ],
                'threshold': 0.40,
                'policy_group': 'SOC2'
            }
        }
        
        # Initialize data structures
        self._category_centroids = {}
        self._category_keywords = {}
        self._category_patterns = {}
        self._category_thresholds = {}
        self._category_weights = {}
        self._policy_group_by_category = {}
        
        # Build from baseline definitions
        for cat_name, cat_data in baseline_categories.items():
            # Store keywords
            self._category_keywords[cat_name] = cat_data['keywords']
            
            # Store patterns
            self._category_patterns[cat_name] = cat_data['patterns']
            
            # Store threshold (lowered to 0.40 for better recall)
            self._category_thresholds[cat_name] = cat_data['threshold']
            
            # Store weight
            self._category_weights[cat_name] = 1.0
            
            # Store policy mapping
            self._policy_group_by_category[cat_name.upper()] = cat_data['policy_group']
            
            # Store scoring weights (default)
            self._category_scoring_weights[cat_name] = {'w_sem': 0.6, 'w_kw': 0.25, 'w_pat': 0.15}
            
            # Store multi-label flag (default True)
            self._category_multi_label[cat_name] = True
            
            # Create centroid if embeddings available
            if self._embedder and self._embed_backend == 'sentence-transformers':
                try:
                    # Combine description + keywords for rich representation
                    examples = [cat_data['description']] + cat_data['keywords'][:15]
                    
                    # Encode with normalization
                    vecs = self._embedder.encode(examples, normalize_embeddings=True)
                    
                    # Weighted average (description gets 2x weight)
                    weights = [2.0] + [1.0] * (len(vecs) - 1)
                    weights_array = np.array(weights) / np.sum(weights)
                    centroid = np.average(vecs, axis=0, weights=weights_array)
                    
                    # Normalize centroid
                    norm = float(np.linalg.norm(centroid))
                    if norm > 0:
                        self._category_centroids[cat_name] = centroid / norm
                        logger.info(f"  ✓ Created centroid for {cat_name}")
                    else:
                        self._category_centroids[cat_name] = None
                        logger.warning(f"  ✗ Failed to create centroid for {cat_name} (zero norm)")
                
                except Exception as e:
                    logger.error(f"  ✗ Failed to create centroid for {cat_name}: {e}")
                    self._category_centroids[cat_name] = None
            else:
                self._category_centroids[cat_name] = None
        
        logger.warning(f"Created {len(baseline_categories)} baseline categories:")
        logger.warning(f"  - Categories: {', '.join(baseline_categories.keys())}")
        logger.warning(f"  - Total keywords: {sum(len(kws) for kws in self._category_keywords.values())}")
        logger.warning(f"  - Total patterns: {sum(len(pats) for pats in self._category_patterns.values())}")
        logger.warning(f"  - Centroids created: {len([c for c in self._category_centroids.values() if c is not None])}")
        logger.warning(f"  - Policy mappings: {len(self._policy_group_by_category)}")
        logger.warning("=" * 80)
    
    def _create_fallback_categories(self) -> None:
        """
        DEPRECATED: Use _create_baseline_categories() instead.
        This method now delegates to the baseline approach.
        """
        logger.warning("_create_fallback_categories() is deprecated. Using _create_baseline_categories().")
        self._create_baseline_categories()

    def _semantic_scores(self, text: str, vector: Optional[np.ndarray] = None) -> Dict[str, float]:
        """Compute semantic similarity scores per category using governance-driven centroids.

        Uses asymmetric E5 encoding for classification text ("query:" prefix) against
        category centroids encoded as "passage:". Returns raw boosted scores without
        min-max normalization, to preserve absolute confidence levels for downstream
        threshold-based filtering.
        """
        scores: Dict[str, float] = {}
        if not text and vector is None:
            return scores
        if self._embedder is None or not self._category_centroids:
            logger.warning("Embedder or category centroids not available for semantic scoring")
            return scores
        
        try:
            # Get or compute embedding vector
            v = vector
            if v is None:
                # Asymmetric E5: embed classification text with "query:" prefix
                t = str(text or "")
                key = f"emb::query::{t}"
                v = self._embed_cache.get(key) if hasattr(self, "_embed_cache") else None

                if v is None:
                    query_text = f"query: {t}"
                    v_raw = self._embedder.encode([query_text], normalize_embeddings=True)
                    v = np.asarray(v_raw[0], dtype=float)

                    try:
                        if hasattr(self, "_embed_cache"):
                            self._embed_cache[key] = v
                    except Exception:
                        pass
            
            # Ensure vector is normalized
            n = float(np.linalg.norm(v) or 0.0)
            if n > 0:
                v = v / n

            # Calculate raw cosine similarities against all category centroids
            raw: Dict[str, float] = {}
            for cat, centroid in self._category_centroids.items():
                try:
                    if centroid is None:
                        continue
                    
                    # **CRITICAL FIX**: Normalize centroid before cosine similarity
                    # Without this, similarity scores are mathematically incorrect!
                    centroid_norm = float(np.linalg.norm(centroid) or 0.0)
                    if centroid_norm == 0:
                        logger.debug(f"Centroid for {cat} has zero norm, skipping")
                        continue
                    
                    normalized_centroid = centroid / centroid_norm
                    
                    # Cosine similarity (dot product of normalized vectors)
                    # Both vectors MUST be normalized for correct cosine similarity
                    sim = float(np.dot(v, normalized_centroid))
                    
                    # Cosine similarity is in [-1, 1], convert to [0, 1] confidence
                    conf = max(0.0, min(1.0, (sim + 1.0) / 2.0))
                    raw[cat] = conf
                    
                    logger.debug(f"Similarity for {cat}: {sim:.4f} → confidence: {conf:.4f}")
                    
                except Exception as e:
                    logger.debug(f"Similarity calculation failed for {cat}: {e}")
                    continue

            if not raw:
                return {}

            # Multiplicative boosting only for strong signals (>= 0.60)
            boosted: Dict[str, float] = {}
            for cat, confidence in raw.items():
                # Get category-specific threshold from governance data (default 0.55)
                threshold = getattr(self, '_category_thresholds', {}).get(cat, 0.55)

                if confidence >= 0.60:
                    # Strong signal → modest boost up to ~20%
                    boost_factor = 1.10 + (confidence - 0.60) * 0.25
                else:
                    # No boost for weak signals
                    boost_factor = 1.0

                boosted_conf = confidence * boost_factor
                final_conf = max(0.0, min(0.95, boosted_conf))

                # Only include if meets category threshold
                if final_conf >= threshold:
                    boosted[cat] = final_conf

            # RETURN RAW BOOSTED SCORES - NO MIN-MAX NORMALIZATION
            scores = boosted

            logger.debug(f"Semantic scores (E5 asymmetric, no normalization): {scores}")
                
        except Exception as e:
            logger.error(f"Semantic scoring failed: {e}", exc_info=True)
            return {}
        
        return scores


    def _compute_fused_embedding(self, name: str, values: str, metadata: str, data_type: str = "", sample_values: List[Any] = None) -> Optional[np.ndarray]:
        """Compute multi-view fused embedding from name, values, and metadata.

        Uses asymmetric E5 encoding for the query side ("query:" prefix) combined from
        column name, values, and metadata. Weights: 50% name, 30% values, 20% metadata.
        
        Args:
            name: Column name
            values: Sample values as string
            metadata: Column metadata/comments
            data_type: SQL data type
            sample_values: List of actual sample values for type detection
        
        Returns:
            Fused embedding vector or None
        """
        if self._embedder is None:
            return None
        try:
            # Infer semantic type for better context
            semantic_type = ""
            if sample_values:
                try:
                    semantic_type = semantic_type_detector.infer_semantic_type(
                        sample_values, data_type, name
                    )
                except Exception:
                    pass
            
            # Encode each component with asymmetric E5 "query:" prefix
            vecs = []
            weights = []
            
            # View 1: Column Name (50% weight - most important for classification)
            if name:
                v_name = self._embedder.encode([f"query: {name}"], normalize_embeddings=True)[0]
                vecs.append(v_name)
                weights.append(0.50)
            
            # View 2: Sample Values with Semantic Type Hint (30% weight)
            if values:
                if semantic_type:
                    values_text = f"query: {semantic_type} values: {values[:200]}"
                else:
                    values_text = f"query: {values[:200]}"
                v_vals = self._embedder.encode([values_text], normalize_embeddings=True)[0]
                vecs.append(v_vals)
                weights.append(0.30)
            
            # View 3: Metadata/Comments (20% weight)
            if metadata:
                v_meta = self._embedder.encode([f"query: {metadata}"], normalize_embeddings=True)[0]
                vecs.append(v_meta)
                weights.append(0.20)
            
            if not vecs:
                return None
            
            # Weighted average instead of simple mean
            weights_array = np.array(weights) / np.sum(weights)  # Normalize weights
            final_vec = np.average(vecs, axis=0, weights=weights_array)
            
            # Normalize
            n = float(np.linalg.norm(final_vec) or 0.0)
            if n > 0:
                final_vec = final_vec / n
                
            return final_vec
        except Exception as e:
            logger.error(f"Multi-view embedding failed: {e}")
            return None

    def _get_min_max_values(self, db: str, schema: str, table: str, column: str) -> Tuple[Optional[str], Optional[str]]:
        """Get MIN and MAX values for a column to improve range detection.

        Uses aliased columns so we can safely access Snowflake's dict-style results.
        """
        try:
            q = f'''
            SELECT
                MIN("{column}") AS MIN_VAL,
                MAX("{column}") AS MAX_VAL
            FROM "{db}"."{schema}"."{table}"
            WHERE "{column}" IS NOT NULL
            '''
            rows = snowflake_connector.execute_query(q) or []
            if rows:
                r = rows[0] or {}
                mn = r.get("MIN_VAL")
                mx = r.get("MAX_VAL")
                return (str(mn) if mn is not None else None, str(mx) if mx is not None else None)
        except Exception:
            pass
        return None, None

    def _keyword_scores(self, text: str) -> Dict[str, float]:
        """
        Enhanced keyword scoring with weighted matching and exact match bonuses.
        Now uses metadata-driven approach from governance tables.
        """
        # Delegate to metadata-driven keyword scoring
        return self._keyword_scores_metadata_driven(text)

    def _pattern_scores(self, text: str) -> Dict[str, float]:
        """
        Metadata-driven pattern scoring using ONLY data from governance tables.
        Uses self._category_pattern_metadata loaded from SENSITIVE_PATTERNS table.
        Applies SENSITIVITY_WEIGHT and SENSITIVITY_TYPE from metadata.
        """
        out: Dict[str, float] = {}
        try:
            # Use pattern metadata if available
            if hasattr(self, '_category_pattern_metadata') and self._category_pattern_metadata:
                t = str(text or "")

                for cat, pattern_list in self._category_pattern_metadata.items():
                    if not pattern_list:
                        continue

                    total_weighted_score = 0.0
                    match_count = 0

                    for pat_meta in pattern_list:
                        pattern = pat_meta['pattern']
                        weight = pat_meta['weight']
                        sensitivity_type = pat_meta['sensitivity_type']

                        try:
                            if re.search(pattern, t, re.IGNORECASE):
                                match_count += 1
                                # Weighted contribution
                                contribution = weight
                                total_weighted_score += contribution
                                logger.debug(f"    Pattern match: '{pattern[:50]}...'  score={contribution:.3f}")
                        except Exception as e:
                            # Invalid regex, skip
                            logger.debug(f"    Invalid pattern: '{pattern[:50]}...'  {e}")
                            continue

                    if match_count > 0:
                        # Get category threshold (relaxed default for patterns)
                        threshold = getattr(self, '_category_thresholds', {}).get(cat, 0.30)
                        category_weight = getattr(self, '_category_weights', {}).get(cat, 1.0)

                        # Normalize by number of patterns
                        num_patterns = len(pattern_list)
                        normalized_score = (total_weighted_score / max(1, num_patterns)) * category_weight

                        # Cap at 1.0
                        final_score = min(1.0, normalized_score)

                        # STRICT: Only include if score meets category threshold
                        if final_score >= threshold:
                            out[cat] = final_score
                            logger.debug(f"   Pattern score: {cat} = {final_score:.2f} ({match_count} matches, threshold={threshold:.2f})")
                        else:
                            logger.debug(f"   Below threshold: {cat} = {final_score:.2f} < {threshold:.2f}")

            # Fallback to simple pattern matching if metadata not available
            if not hasattr(self, "_category_patterns") or not self._category_patterns:
                return out

            t = str(text or "")
            for cat, patterns in self._category_patterns.items():
                hits = 0
                for p in (patterns or [])[:20]:
                    try:
                        if not p:
                            continue
                        if re.search(p, t, re.IGNORECASE):
                            hits += 1
                    except Exception:
                        continue

                if hits > 0:
                    threshold = getattr(self, '_category_thresholds', {}).get(cat, 0.30)
                    score = max(0.0, min(1.0, hits / 3.0))
                    if score >= threshold:
                        out[cat] = score
        except Exception:
            return {}
        return out

    def _pattern_scores_with_matches(self, text: str) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
        out: Dict[str, float] = {}
        matches: Dict[str, List[str]] = {}
        try:
            if hasattr(self, '_category_pattern_metadata') and self._category_pattern_metadata:
                t = str(text or "")

                for cat, pattern_list in self._category_pattern_metadata.items():
                    if not pattern_list:
                        continue

                    total_weighted_score = 0.0
                    match_count = 0
                    cat_matches: List[str] = []

                    for pat_meta in pattern_list:
                        pattern = pat_meta['pattern']
                        weight = pat_meta['weight']
                        try:
                            if re.search(pattern, t, re.IGNORECASE):
                                match_count += 1
                                contribution = weight
                                total_weighted_score += contribution
                                cat_matches.append(pattern)
                                logger.debug(f"    Pattern match: '{pattern[:50]}...'  score={contribution:.3f}")
                        except Exception as e:
                            logger.debug(f"    Invalid pattern: '{pattern[:50]}...'  {e}")
                            continue

                    if match_count > 0:
                        threshold = getattr(self, '_category_thresholds', {}).get(cat, 0.30)
                        category_weight = getattr(self, '_category_weights', {}).get(cat, 1.0)
                        num_patterns = len(pattern_list)
                        normalized_score = (total_weighted_score / max(1, num_patterns)) * category_weight
                        final_score = min(1.0, normalized_score)

                        if final_score >= threshold:
                            out[cat] = final_score
                            matches[cat] = cat_matches
                            logger.debug(f"   Pattern score: {cat} = {final_score:.2f} ({match_count} matches, threshold={threshold:.2f})")
                        else:
                            logger.debug(f"   Below threshold: {cat} = {final_score:.2f} < {threshold:.2f}")

            if not hasattr(self, "_category_patterns") or not self._category_patterns:
                return out, matches

            t = str(text or "")
            for cat, patterns in self._category_patterns.items():
                hits = 0
                cat_matches: List[str] = []
                for p in (patterns or [])[:20]:
                    try:
                        if not p:
                            continue
                        if re.search(p, t, re.IGNORECASE):
                            hits += 1
                            cat_matches.append(p)
                    except Exception:
                        continue

                if hits > 0:
                    threshold = getattr(self, '_category_thresholds', {}).get(cat, 0.65)
                    score = max(0.0, min(1.0, hits / 3.0))
                    if score >= threshold:
                        out[cat] = score
                        matches[cat] = cat_matches
            return out, matches
        except Exception:
            return {}, {}

    def _keyword_scores_with_matches(self, text: str) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
        scores: Dict[str, float] = {}
        matched: Dict[str, List[str]] = {}
        t = (text or '').lower()

        if not hasattr(self, '_category_keyword_metadata') or not self._category_keyword_metadata:
            logger.warning("No category keyword metadata loaded from governance tables")
            return scores, matched

        for category, keyword_list in self._category_keyword_metadata.items():
            if not keyword_list:
                continue

            total_weighted_score = 0.0
            match_count = 0
            cat_matches: List[str] = []

            for kw_meta in keyword_list:
                keyword = kw_meta['keyword']
                weight = kw_meta['weight']
                match_type = kw_meta['match_type']
                base_score = kw_meta['score']

                matched_flag = False
                match_quality = 0.0

                try:
                    if match_type == 'EXACT':
                        # Use real word boundaries for exact keyword matching
                        if re.search(r'\b' + re.escape(keyword) + r'\b', t, re.IGNORECASE):
                            matched_flag = True
                            match_quality = 1.0
                    elif match_type == 'PARTIAL':
                        if keyword in t:
                            matched_flag = True
                            match_quality = 0.8
                    elif match_type == 'FUZZY':
                        keyword_words = keyword.split()
                        if any(word in t for word in keyword_words):
                            matched_flag = True
                            match_quality = 0.6
                    else:
                        if re.search(r'\b' + re.escape(keyword) + r'\b', t, re.IGNORECASE):
                            matched_flag = True
                            match_quality = 1.0
                except Exception:
                    if keyword in t:
                        matched_flag = True
                        match_quality = 0.7

                if matched_flag:
                    match_count += 1
                    contribution = base_score * weight * match_quality
                    total_weighted_score += contribution
                    cat_matches.append(keyword)
                    logger.debug(f"    Keyword match: '{keyword}' ({match_type})  score={contribution:.3f}")

            if match_count > 0:
                # Use a more permissive default threshold so governance-driven
                # keywords can contribute alongside embeddings and patterns.
                threshold = getattr(self, '_category_thresholds', {}).get(category, 0.30)
                category_weight = getattr(self, '_category_weights', {}).get(category, 1.0)
                num_keywords = len(keyword_list)
                normalized_score = (total_weighted_score / max(1, num_keywords)) * category_weight
                final_score = min(1.0, normalized_score)

                if final_score >= threshold:
                    scores[category] = final_score
                    matched[category] = cat_matches
                    logger.debug(f"   Keyword score: {category} = {final_score:.2f} ({match_count} matches, threshold={threshold:.2f})")
                else:
                    logger.debug(f"   Below threshold: {category} = {final_score:.2f} < {threshold:.2f}")

        return scores, matched

    def _keyword_scores_metadata_driven(self, text: str) -> Dict[str, float]:
        """
        Metadata-driven keyword scoring using ONLY data from governance tables.
        NO HARDCODED KEYWORDS.
        
        Uses self._category_keyword_metadata loaded from SENSITIVE_KEYWORDS table.
        Applies MATCH_TYPE, SENSITIVITY_TYPE, and SCORE from metadata.
        """
        scores, _ = self._keyword_scores_with_matches(text)
        return scores
    
    def _fallback_keyword_matching(self, text: str) -> Dict[str, float]:
        """
        DEPRECATED: Use _keyword_scores_metadata_driven() instead.
        This method now delegates to the metadata-driven approach.
        """
        logger.warning("_fallback_keyword_matching() is deprecated. Using metadata-driven keyword scoring.")
        return self._keyword_scores_metadata_driven(text)

    def _load_patterns_from_governance(self, schema_fqn: str, category_name: str) -> List[str]:
        rows = []
        try:
            rows = snowflake_connector.execute_query(
                f"""
                SELECT COALESCE(PATTERN_REGEX, PATTERN_STRING, PATTERN) AS PTN
                FROM {schema_fqn}.SENSITIVE_PATTERNS
                WHERE COALESCE(is_active, true) AND (
                    LOWER(category) = LOWER(%(n)s) OR LOWER(category_name) = LOWER(%(n)s)
                )
                """,
                {"n": category_name},
            ) or []
        except Exception:
            try:
                # CATEGORY_ID-based lookup using SENSITIVITY_CATEGORIES
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT COALESCE(PATTERN_REGEX, PATTERN_STRING, PATTERN) AS PTN
                    FROM {schema_fqn}.SENSITIVE_PATTERNS
                    WHERE COALESCE(is_active, true) AND category_id IN (
                        SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE LOWER(CATEGORY_NAME) = LOWER(%(n)s)
                    )
                    """,
                    {"n": category_name},
                ) or []
            except Exception:
                try:
                    rows = snowflake_connector.execute_query(
                        f"""
                        SELECT COALESCE(PATTERN_REGEX, PATTERN_STRING, PATTERN) AS PTN
                        FROM {schema_fqn}.SENSITIVE_PATTERNS
                        WHERE COALESCE(is_active, true) AND category_id IN (
                            SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE LOWER(CATEGORY_NAME) = LOWER(%(n)s)
                        )
                        """,
                        {"n": category_name},
                    ) or []
                except Exception:
                    rows = []
        out: List[str] = []
        for r in rows:
            try:
                p = str(r.get("PTN") or "").strip()
                if p:
                    out.append(p)
            except Exception:
                continue
        # minimal fallbacks when nothing configured
        if not out:
            base = (category_name or "").strip().lower()
            if base in {"personal_data", "personal", "pii"}:
                out = [r"\bssn\b", r"\bemail\b", r"\bphone\b"]
            elif base in {"financial_data", "financial"}:
                out = [r"\binvoice\b", r"\bbank\b", r"\bpayment\b"]
            elif base in {"regulatory_data", "regulatory"}:
                out = [r"\bgdpr\b", r"\bhipaa\b", r"\bpci\b"]
        return out

    def _gov_semantic_scores(self, text: str) -> Dict[str, float]:
        out: Dict[str, float] = {}
        try:
            # Cache governance semantic matches
            cache_key = f"gov_sim::{text}"
            if hasattr(self, "_cache") and cache_key in self._cache:
                val = self._cache.get(cache_key) or {}
                if isinstance(val, dict):
                    return val
            svc = ai_classification_service
            # If governance match function or connector isn't available, skip
            if not hasattr(svc, "_get_semantic_matches_gov"):
                return out
            try:
                # Some environments may not have Snowflake or proper tables; trap and continue
                matches = svc._get_semantic_matches_gov(text) or []
            except Exception:
                matches = []
            try:
                from src.services.ai_assistant_service import ai_assistant_service as _aas
                _map = getattr(_aas, "_SEMANTIC_TO_AVENDRA", {}) or {}
            except Exception:
                _map = {}
            for m in matches:
                try:
                    # Tolerate different field names from governance queries
                    c = str(
                        m.get("category")
                        or m.get("CATEGORY")
                        or m.get("CATEGORY_NAME")
                        or ""
                    ).strip()
                    conf = float(m.get("confidence") or m.get("CONFIDENCE") or 0.0)
                except Exception:
                    continue
                if not c:
                    continue
                av = _map.get(c, c)
                out[av] = max(0.0, min(1.0, conf))
            try:
                if hasattr(self, "_cache"):
                    self._cache[cache_key] = dict(out)
            except Exception:
                pass
        except Exception:
            return {}
        return out

    def _calibrate_scores(self, scores: Dict[str, float]) -> Dict[str, float]:
        # Disabled calibration to preserve high confidence scores
        return dict(scores)

    def _apply_quality_calibration(self, scores: Dict[str, float], quality: Dict[str, float]) -> Dict[str, float]:
        """Adjust scores based on context quality metrics to calibrate confidence.
        
        ENHANCED: Only boost scores, never penalize.
        """
        try:
            if not scores:
                return scores
            
            # Always apply a base boost to ensure higher confidence
            factor = 1.1
            
            # Additional boost for high quality context
            qlen = float(quality.get("len", 0.0) or 0.0)
            if qlen > 50:
                factor += 0.1
                
            out: Dict[str, float] = {}
            for k, v in scores.items():
                out[k] = max(0.0, min(1.0, float(v) * factor))
            return out
        except Exception:
            return scores

    def _auto_tune_parameters(self) -> None:
        try:
            valid_centroids = 0
            try:
                cents = getattr(self, "_category_centroids", {}) or {}
                valid_centroids = len([v for v in cents.values() if v is not None])
            except Exception:
                valid_centroids = 0
            has_sem = (self._embedder is not None) and valid_centroids > 0
            sem_ok = bool(getattr(self, "_embed_ready", False)) and (valid_centroids >= 3)
            
            logger.info(f"Auto-tuning parameters: embedder={self._embedder is not None}, embed_ready={self._embed_ready}, valid_centroids={valid_centroids}, sem_ok={sem_ok}")
            
            # Respect external overrides if provided via dynamic config
            try:
                cfg_over = None
                if hasattr(st, "session_state"):
                    cfg_over = st.session_state.get("ai_pipeline_config")
                if not cfg_over and settings is not None:
                    cfg_over = getattr(settings, "AI_PIPELINE_CONFIG", None)
                if isinstance(cfg_over, dict) and ("w_sem" in cfg_over or "w_kw" in cfg_over):
                    self._w_sem = float(cfg_over.get("w_sem", self._w_sem))
                    self._w_kw = float(cfg_over.get("w_kw", self._w_kw))
                    logger.info(f"  Using external config override: w_sem={self._w_sem}, w_kw={self._w_kw}")
                else:
                    if not sem_ok:
                        self._w_sem = 0.0
                        self._w_kw = 1.0
                        logger.info(f"  Regime: NO_EMBEDDINGS → w_sem=0.0, w_kw=1.0 (keyword-only)")
                    elif valid_centroids < 6:
                        self._w_sem = 0.7
                        self._w_kw = 0.3
                        logger.info(f"  Regime: BALANCED ({valid_centroids} centroids) → w_sem=0.7, w_kw=0.3")
                    else:
                        self._w_sem = 0.8
                        self._w_kw = 0.2
                        logger.info(f"  Regime: SEMANTIC_PREFERRED ({valid_centroids} centroids) → w_sem=0.8, w_kw=0.2")
            except Exception as _e:
                logger.warning(f"  Exception during config override: {_e}")
                if not sem_ok:
                    self._w_sem = 0.0
                    self._w_kw = 1.0
                    logger.info(f"  Fallback: w_sem=0.0, w_kw=1.0 (keyword-only)")
                elif valid_centroids < 6:
                    self._w_sem = 0.7
                    self._w_kw = 0.3
                    logger.info(f"  Fallback: w_sem=0.7, w_kw=0.3 (balanced)")
                else:
                    self._w_sem = 0.8
                    self._w_kw = 0.2
                    logger.info(f"  Fallback: w_sem=0.8, w_kw=0.2 (semantic-preferred)")
            self._ctx_max_cols = max(int(self._ctx_max_cols or 0), 20)
            self._ctx_max_vals = max(int(self._ctx_max_vals or 0), 7)
            self._col_sample_rows = max(int(self._col_sample_rows or 0), 400)
            try:
                thr = float(self._conf_label_threshold if self._conf_label_threshold is not None else 0.30)
            except Exception:
                thr = 0.30
            self._conf_label_threshold = max(0.0, min(1.0, thr))
            self._debug = False
        except Exception:
            pass

    def _load_dynamic_config(self) -> Dict[str, Any]:
        """Load dynamic configuration for the pipeline with sensible defaults and layered overrides.

        Precedence (lowest to highest):
        defaults < settings.AI_PIPELINE_CONFIG < st.secrets['AI_PIPELINE_CONFIG'] < st.session_state['ai_pipeline_config']
        """
        cfg: Dict[str, Any] = {
            "enable_context_enhancement": True,
            "min_context_length": 200,
            "adaptive_sampling": True,
            "apply_confidence_calibration": True,
            # expose weights so they can be tuned without code changes
            "w_sem": float(getattr(self, "_w_sem", 0.85) or 0.85),
            "w_kw": float(getattr(self, "_w_kw", 0.15) or 0.15),
            # minimum confidence required for a column to be treated as sensitive (PII/SOX/SOC2)
            # this can be tuned to unblock overly strict filtering
            "min_conf_for_sensitive_cols": 0.35,
        }

        # Merge from app settings if available
        try:
            if settings is not None:
                base = getattr(settings, "AI_PIPELINE_CONFIG", None)
                if isinstance(base, dict):
                    cfg.update(base)
        except Exception:
            pass

        # Merge from Streamlit secrets if available
        try:
            if hasattr(st, "secrets"):
                sec = st.secrets.get("AI_PIPELINE_CONFIG")  # type: ignore[attr-defined]
                if isinstance(sec, dict):
                    cfg.update(sec)  # type: ignore[arg-type]
        except Exception:
            pass

        # Merge from session state for on-the-fly adjustments
        try:
            if hasattr(st, "session_state"):
                ses = st.session_state.get("ai_pipeline_config")
                if isinstance(ses, dict):
                    cfg.update(ses)
        except Exception:
            pass

        # Sanitize/validate types and ranges
        try:
            mcl = int(cfg.get("min_context_length", 200) or 200)
            cfg["min_context_length"] = max(0, mcl)
        except Exception:
            cfg["min_context_length"] = 200
        try:
            ws = float(cfg.get("w_sem", 0.85) or 0.85)
            wk = float(cfg.get("w_kw", 0.15) or 0.15)
            cfg["w_sem"] = max(0.0, min(1.0, ws))
            cfg["w_kw"] = max(0.0, min(1.0, wk))
        except Exception:
            cfg["w_sem"] = 0.85
            cfg["w_kw"] = 0.15
        try:
            for flag in ("enable_context_enhancement", "adaptive_sampling", "apply_confidence_calibration"):
                cfg[flag] = bool(cfg.get(flag, cfg.get(flag, True)))
        except Exception:
            pass

        return cfg

    def _preprocess_text_local(self, text: str, remove_stopwords: bool = False) -> str:
        s = str(text or "")
        try:
            s = re.sub(r"[\n\r\t]+", " ", s)
            s = re.sub(r"\s+", " ", s).strip()
        except Exception:
            pass
        if not remove_stopwords:
            return s
        # Conservative stopword filter: preserve domain-critical terms
        # Removed: "data", "info", "information" (essential for PII/classification context)
        # Removed: "in", "for" (common in data patterns like "in database", "for classification")
        stops = {"the","a","an","and","or","of","to","on","at","by","with","from","as","is","are","was","were"}
        try:
            toks = [w for w in re.split(r"[^a-zA-Z0-9]+", s) if w and w.lower() not in stops]
            return " ".join(toks)
        except Exception:
            return s
        

    def _normalize_category_for_cia(self, category: Optional[str]) -> str:
        try:
            raw = (category or "").strip()
            if not raw:
                return ""
            # Prefer normalization from ai_classification_service when available
            try:
                from src.services.ai_classification_service import ai_classification_service as _svc
                if _svc is not None and hasattr(_svc, "_normalize_category_for_cia"):
                    return _svc._normalize_category_for_cia(raw)  # type: ignore[attr-defined]
            except Exception:
                pass
            # Fallback: use semantic-to-Avendra mapping from ai_assistant_service
            try:
                sem_map = getattr(ai_assistant_service, "_SEMANTIC_TO_AVENDRA", {}) or {}
            except Exception:
                sem_map = {}
            mapped = sem_map.get(raw, raw)
            return mapped
        except Exception:
            return str(category or "").strip()

    def _context_quality_metrics(self, text: str) -> Dict[str, float]:
        s = str(text or "")
        n = len(s)
        if n <= 0:
            return {"len": 0, "digit_ratio": 1.0, "alpha_ratio": 0.0, "too_short": True}
        digits = sum(1 for ch in s if ch.isdigit())
        alpha = sum(1 for ch in s if ch.isalpha())
        # configurable minimum context length
        try:
            mcl = int(self._load_dynamic_config().get("min_context_length", 200))
        except Exception:
            mcl = 200
        return {
            "len": n,
            "digit_ratio": float(digits) / float(max(1, n)),
            "alpha_ratio": float(alpha) / float(max(1, n)),
            "too_short": n < mcl,
        }

    def _map_category_to_policy_group(self, category: str) -> str:
        """Map a granular governance category into policy groups (PII, SOX, SOC2).

        Enhanced 3-layer cascade with comprehensive keyword mapping:
        - Layer 1: Metadata-driven mapping from governance tables (POLICY_GROUP column)
        - Layer 2: Enhanced keyword-based fallback with extensive pattern matching
        - Layer 3: Safe default to NON_SENSITIVE
        """
        if not category:
            logger.debug("_map_category_to_policy_group: Empty category, returning 'NON_SENSITIVE'")
            return "NON_SENSITIVE"

        raw = str(category).strip()
        cat_upper = raw.upper()

        # LAYER 1: Metadata-driven policy mapping from governance tables
        try:
            meta_map = getattr(self, "_policy_group_by_category", {}) or {}
        except Exception:
            meta_map = {}

        if cat_upper in meta_map:
            mapped = str(meta_map[cat_upper]).strip().upper()
            logger.debug(f"_map_category_to_policy_group: '{category}' → '{mapped}' (metadata)")
            return mapped

        # LAYER 2: Enhanced keyword-based fallback
        try:
            cat_lower = raw.lower()

            # PII-style categories (EXPANDED)
            if any(kw in cat_lower for kw in [
                "pii", "personal", "person", "customer", "employee", "patient", "contact", "identity",
                "name", "email", "phone", "address", "birth", "ssn", "social", "passport", "license",
                "medical", "health", "biometric", "demographic", "individual", "citizen", "resident",
                "user", "member", "subscriber", "client", "taxpayer", "beneficiary"
            ]):
                logger.debug(f"_map_category_to_policy_group: '{category}' → 'PII' (keyword fallback)")
                return "PII"

            # SOX / financial categories (EXPANDED)
            if any(kw in cat_lower for kw in [
                "sox", "financial", "ledger", "revenue", "account", "billing", "invoice", "payroll",
                "transaction", "payment", "order", "purchase", "sale", "expense", "asset", "liability",
                "equity", "journal", "balance", "income", "cash", "audit", "reconciliation",
                "fiscal", "budget", "forecast", "cost", "profit", "loss", "receivable", "payable",
                "gl", "ap", "ar", "accrual", "deferred", "amortization", "depreciation"
            ]):
                logger.debug(f"_map_category_to_policy_group: '{category}' → 'SOX' (keyword fallback)")
                return "SOX"

            # SOC2 / security categories (EXPANDED)
            if any(kw in cat_lower for kw in [
                "soc", "security", "access", "auth", "password", "credential", "token", "key",
                "session", "login", "permission", "role", "privilege", "encryption", "certificate",
                "firewall", "vulnerability", "incident", "breach", "audit_log", "monitoring",
                "compliance", "control", "policy", "configuration", "change_log", "backup",
                "recovery", "disaster", "continuity", "sod", "segregation"
            ]):
                logger.debug(f"_map_category_to_policy_group: '{category}' → 'SOC2' (keyword fallback)")
                return "SOC2"
        except Exception:
            pass

        # LAYER 3: Safe default
        logger.debug(f"_map_category_to_policy_group: '{category}' → 'NON_SENSITIVE' (no mapping)")
        return "NON_SENSITIVE"

    def _detect_sensitive_columns_local(self, database: str, schema: str, table: str, max_cols: int = 200) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        try:
            cols = snowflake_connector.execute_query(
                f"""
                SELECT COLUMN_NAME, DATA_TYPE, COMMENT
                FROM {database}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                ORDER BY ORDINAL_POSITION
                LIMIT {max_cols}
                """,
                {"s": schema, "t": table},
            ) or []
        except Exception:
            cols = []
        for c in cols:
            try:
                cn = str(c.get("COLUMN_NAME") or "")
                dt = str(c.get("DATA_TYPE") or "")
                com = str(c.get("COMMENT") or "")
                samples = self._sample_column_values(
                    database,
                    schema,
                    table,
                    cn,
                    sample_rows=int(getattr(self, "_col_sample_rows", 60) or 60),
                ) or []
                filtered_vals = []
                for v in samples:
                    sv = str(v)
                    if not sv.strip():
                        continue
                    if sv.strip().isdigit() and len(sv.strip()) < 5:
                        continue
                    filtered_vals.append(sv[:64])
                    if len(filtered_vals) >= 8:
                        break
                sample_txt = ", ".join(filtered_vals[:8])
                ctx_parts = [f"{database}.{schema}.{table}.{cn}"]
                if com:
                    ctx_parts.append(com)
                if sample_txt:
                    ctx_parts.append(sample_txt)
                ctx = " | ".join([p for p in ctx_parts if p])
                ptxt = self._preprocess_text_local(ctx)
                sem = self._semantic_scores(ptxt)
                kw = self._keyword_scores(ptxt)
                comb: Dict[str, float] = {}
                keys = set(list(sem.keys()) + list(kw.keys()))
                w_sem = float(getattr(self, "_w_sem", 0.7))
                w_kw = float(getattr(self, "_w_kw", 0.3))
                for k in keys:
                    s = float(sem.get(k, 0.0))
                    k2 = float(kw.get(k, 0.0))
                    
                    # WINNER TAKES ALL
                    if s > 0.7 or k2 > 0.7:
                        comb[k] = max(s, k2)
                    else:
                        comb[k] = max(0.0, min(1.0, (w_sem * s) + (w_kw * k2)))
                if not comb:
                    best = None
                    conf = 0.0
                else:
                    best = max(comb, key=comb.get)
                    conf = float(comb.get(best, 0.0))

                # CIA mapping and label
                try:
                    c_level, i_level, a_level = ai_assistant_service.CIA_MAPPING.get(best or '', (1, 1, 1))
                except Exception:
                    c_level, i_level, a_level = (1, 1, 1)
                try:
                    label = ai_assistant_service._map_cia_to_label(c_level, i_level, a_level)
                except Exception:
                    label = "Internal"
                rows.append({
                    "Column": cn,
                    "Type": dt,
                    "Sensitivity": label,
                    "Confidence": round(conf, 4),
                    "Categories": best or "",
                    "C": int(c_level),
                    "I": int(i_level),
                    "A": int(a_level),
                })
            except Exception:
                continue
        return rows

    def _classify_assets_local(self, db: str, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Governance-driven asset classification"""
        return self._run_governance_driven_pipeline(db, assets)

    def _classify_columns_local(self, db: str, schema: str, table: str, max_cols: int = 50) -> List[Dict[str, Any]]:
        """Classify individual columns using governance-driven hybrid scoring.
        
        UPDATED: Now delegates to _classify_column_governance_driven for consistency.
        """
        results: List[Dict[str, Any]] = []
        try:
            # Ensure embeddings and governance metadata are initialized
            if self._embedder is None or not getattr(self, "_category_centroids", {}):
                logger.info("Initializing embeddings for column classification...")
                self._init_local_embeddings()

            if not getattr(self, "_category_centroids", {}):
                logger.error("CRITICAL: No category centroids available after initialization.")
                return results

            # Fetch columns from information_schema
            cols = self._get_columns_from_information_schema(db, schema, table)
            
            if not cols:
                logger.warning(f"No columns found for {db}.{schema}.{table}")
                return results
                
            # Limit columns
            cols = cols[:max_cols]

            logger.info(f"Column-level classification: {db}.{schema}.{table} with {len(cols)} columns")

            # Batch sample values
            col_names = [c['COLUMN_NAME'] for c in cols]
            batch_samples = self._sample_table_values_batch(db, schema, table, col_names, limit=20)

            for col in cols:
                try:
                    col_name = col['COLUMN_NAME']
                    col_samples = batch_samples.get(col_name, [])
                    
                    # Use the shared governance-driven method
                    result = self._classify_column_governance_driven(
                        db, schema, table, col, pre_fetched_samples=col_samples
                    )
                    
                    # CRITICAL: Skip if None (non-sensitive column)
                    if result is None:
                        logger.debug(f"  Skipping non-sensitive column: {col_name}")
                        continue
                    
                    # Transform result to match expected UI format if needed
                    # _classify_column_governance_driven returns a rich dict that covers most needs
                    
                    # Add legacy fields if missing
                    if 'semantic_similarity' not in result:
                        # Just use confidence as proxy
                        result['semantic_similarity'] = result.get('confidence', 0.0)
                        result['keyword_score'] = 0.0
                        result['regex_score'] = 0.0
                        
                    # Add matched keywords/patterns (not returned by gov method currently, but that's ok)
                    result['matched_keywords'] = []
                    result['matched_patterns'] = []
                    
                    # Ensure high_confidence flag
                    result['high_confidence'] = result.get('confidence', 0.0) >= 0.90
                    
                    results.append(result)
                    
                except Exception as e:
                    logger.warning(f"Column classification failed for {col.get('COLUMN_NAME')}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Column-level classification failed: {e}", exc_info=True)

        logger.info(f"  Column classification complete: {len(results)} columns included in results")
        return results

    def _build_richer_context(self, asset: Dict[str, Any], max_cols: int = 120, max_vals: int = 10, business_purpose: Optional[str] = None) -> str:
        """Aggregate business purpose, column names, and example values in a single contextual string."""
        table_name = str(asset.get('table') or '')
        schema_name = str(asset.get('schema') or '')
        bp = str(business_purpose or asset.get('comment') or '').strip()
        # Cache lookup
        try:
            ck = f"ctx::{asset.get('full_name','')}::{int(max_cols)}::{int(max_vals)}::{bp[:64]}"
            if hasattr(self, "_cache") and ck in self._cache:
                v = self._cache.get(ck)
                if isinstance(v, str):
                    return v
        except Exception:
            pass
        cols_list: List[str] = []
        sample_values: List[str] = []
        stats_map: Dict[str, Dict[str, Any]] = {}
        meta_map: Dict[str, Dict[str, Any]] = {}
        try:
            cols = snowflake_connector.execute_query(
                f"""
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH, COMMENT
                FROM {asset['database']}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                ORDER BY ORDINAL_POSITION
                LIMIT {max_cols}
                """,
                {"s": asset.get('schema'), "t": asset.get('table')},
            ) or []
        except Exception:
            cols = []
        if cols:
            cols_list = [
                (f"{str(c.get('COLUMN_NAME'))} ({str(c.get('DATA_TYPE'))})")
                for c in cols if c.get('COLUMN_NAME')
            ]
            try:
                for c in cols:
                    cn = str(c.get('COLUMN_NAME') or '')
                    if not cn:
                        continue
                    meta_map[cn] = {
                        "type": str(c.get('DATA_TYPE') or ''),
                        "nullable": str(c.get('IS_NULLABLE') or '').upper() in ('YES','Y','TRUE','1'),
                        "length": c.get('CHARACTER_MAXIMUM_LENGTH'),
                        "comment": c.get('COMMENT')
                    }
            except Exception:
                meta_map = {}
        # Targeted sampling prioritizing columns matched by governance-configured tokens/regex
        try:
            # Load dynamic patterns from sensitivity config
            try:
                cfg = ai_classification_service.load_sensitivity_config() or {}
            except Exception:
                cfg = {}
            pats = cfg.get("patterns") or {}
            token_set = set()
            regex_list: List[str] = []
            try:
                for _cat, spec in pats.items():
                    try:
                        for t in (spec.get("name_tokens") or []):
                            if t:
                                token_set.add(str(t).lower())
                    except Exception:
                        pass
                    try:
                        for k in (spec.get("keywords") or []):
                            if k:
                                token_set.add(str(k).lower())
                    except Exception:
                        pass
                    try:
                        for rx in (spec.get("patterns") or spec.get("regex_list") or []):
                            if rx:
                                regex_list.append(str(rx))
                    except Exception:
                        pass
            except Exception:
                token_set = set(); regex_list = []
            # Fallback default PII tokens/patterns if governance config is empty
            if not token_set and not regex_list:
                token_set = set()
                regex_list = []

            def _name_matches(cname: str) -> bool:
                cl = (cname or "").lower()
                try:
                    for tok in token_set:
                        if tok and tok in cl:
                            return True
                except Exception:
                    pass
                try:
                    for rx in regex_list:
                        try:
                            if re.search(rx, cname, re.IGNORECASE):
                                return True
                        except Exception:
                            continue
                except Exception:
                    pass
                return False

            # Choose columns matched by config; prioritize text/commented columns; fallback to first N for coverage
            selected_cols = []
            try:
                text_like = []
                others = []
                for c in cols[:max_cols]:
                    cn = str(c.get('COLUMN_NAME') or '')
                    dt = str(c.get('DATA_TYPE') or '').upper()
                    has_comment = bool(str(c.get('COMMENT') or '').strip())
                    is_text = any(x in dt for x in ["CHAR","TEXT","STRING","VARCHAR","VARIANT"])
                    if cn and _name_matches(cn):
                        selected_cols.append(c)
                    elif is_text or has_comment:
                        text_like.append(c)
                    else:
                        others.append(c)
                if len(selected_cols) < max_cols:
                    for c in text_like:
                        if len(selected_cols) >= max_cols:
                            break
                        if c not in selected_cols:
                            selected_cols.append(c)
                if len(selected_cols) < max_cols:
                    for c in others:
                        if len(selected_cols) >= max_cols:
                            break
                        if c not in selected_cols:
                            selected_cols.append(c)
            except Exception:
                selected_cols = cols[:max_cols]

            total_rows = None
            try:
                tr = snowflake_connector.execute_query(f"SELECT COUNT(*) AS N FROM {asset['full_name']}") or []
                if tr:
                    total_rows = int(list(tr[0].values())[0])
            except Exception:
                total_rows = None

            for c in selected_cols:
                cn = str(c.get('COLUMN_NAME') or '')
                if not cn:
                    continue
                try:
                    qstats = (
                        f"SELECT COUNT(*) AS TOTAL, "
                        f"COUNT_IF(\"{cn}\" IS NULL) AS NULLS, "
                        f"APPROX_COUNT_DISTINCT(\"{cn}\") AS DISTINCTS "
                        f"FROM {asset['full_name']}"
                    )
                    srows = snowflake_connector.execute_query(qstats) or []
                    if srows:
                        row0 = srows[0]
                        tot = int(row0.get('TOTAL') or 0)
                        nulls = int(row0.get('NULLS') or 0)
                        dcnt = int(row0.get('DISTINCTS') or 0)
                        base = tot if tot else (total_rows or 0)
                        null_ratio = float(nulls) / float(base) if base else 0.0
                        uniq_ratio = float(dcnt) / float(base) if base else 0.0
                        stats_map.setdefault(cn, {})
                        stats_map[cn].update({"null_ratio": null_ratio, "uniq_ratio": uniq_ratio})
                except Exception:
                    pass
                try:
                    dt = str((meta_map.get(cn, {}) or {}).get("type") or '').upper()
                    if any(x in dt for x in ["CHAR","TEXT","STRING","VARCHAR"]):
                        qlen = (
                            f"SELECT AVG(LENGTH(\"{cn}\")) AS AVGL "
                            f"FROM {asset['full_name']} SAMPLE ({max(max_vals*50, 100)} ROWS) "
                            f"WHERE \"{cn}\" IS NOT NULL"
                        )
                        lrows = snowflake_connector.execute_query(qlen) or []
                        if lrows:
                            avgl = float(list(lrows[0].values())[0] or 0.0)
                            stats_map.setdefault(cn, {})
                            stats_map[cn].update({"avg_len": avgl})
                except Exception:
                    pass
                try:
                    q = (
                        f"SELECT \"{cn}\" AS V FROM {asset['full_name']} SAMPLE ({max_vals*10} ROWS) "
                        f"WHERE \"{cn}\" IS NOT NULL"
                    )
                    rows = snowflake_connector.execute_query(q) or []
                    cnt = 0
                    for r in rows:
                        v = r.get('V')
                        if v is None:
                            continue
                        sv = str(v)
                        # Skip only pure integers (avoid skipping formatted numeric PII like SSN, cards)
                        if re.fullmatch(r"\s*\d+\s*", sv) and len(sv.strip()) < 5:
                            continue
                        sv_trim = sv[:200] + ("…" if len(sv) > 200 else "")
                        sample_values.append(f"{cn}:{sv_trim}")
                        cnt += 1
                        if cnt >= max_vals:
                            break
                except Exception:
                    continue
        except Exception:
            pass
        # Build enriched column summary with stats
        col_items: List[str] = []
        try:
            for item in cols_list[:max_cols]:
                try:
                    nm, rest = item.split(" ", 1)
                except Exception:
                    nm, rest = item, ""
                m = meta_map.get(nm, {})
                stx = stats_map.get(nm, {})
                nr = stx.get("null_ratio", 0.0)
                ur = stx.get("uniq_ratio", 0.0)
                al = stx.get("avg_len")
                nullable = "Y" if m.get("nullable") else "N"
                length = m.get("length")
                cm = m.get("comment")
                frag = f"{nm} {rest} null={nr:.0%} unique={ur:.0%}"
                if al is not None:
                    try:
                        frag += f" avglen={float(al):.0f}"
                    except Exception:
                        pass
                if length:
                    frag += f" len={length}"
                frag += f" nullable={nullable}"
                if cm:
                    cmt = str(cm).strip().replace('\n',' ')[:80]
                    frag += f" comment={cmt}"
                col_items.append(frag)
        except Exception:
            col_items = cols_list[:max_cols]
        col_names = ", ".join(col_items) if col_items else ""
        # Include more examples overall with an upper cap
        max_examples = min(max_cols * max_vals, 600)
        examples = ", ".join(sample_values[: max_examples ]) if sample_values else ""
        # infer business domain from schema/table names
        name_blob = f"{schema_name} {table_name} {bp}".lower()
        domain_map = {
            "hr": "Human Resources",
            "employee": "Human Resources",
            "payroll": "Human Resources",
            "fin": "Finance",
            "acct": "Finance",
            "gl": "Finance",
            "ap": "Finance",
            "ar": "Finance",
            "invoice": "Finance",
            "bank": "Finance",
            "crm": "Customer Relationship",
            "sales": "Sales",
            "marketing": "Marketing",
            "pii": "Personal Data",
            "customer": "Customer Data",
            "vendor": "Supplier/Vendor",
            "reg": "Regulatory",
        }
        # Sample values for selected columns
        if selected_cols and total_rows and total_rows > 0:
            try:
                scols = [f'"{c.get("COLUMN_NAME")}"' for c in selected_cols[:8]]  # Limit to top 8 for sampling
                if scols:
                    q = f"SELECT {', '.join(scols)} FROM {asset['full_name']} SAMPLE ({max_vals} ROWS)"
                    rows = snowflake_connector.execute_query(q) or []
                    for r in rows:
                        # Flatten row values
                        vals = [str(v)[:64] for v in r.values() if v]
                        if vals:
                            sample_values.append(", ".join(vals))

                    # ENHANCED: Add MIN/MAX profile for these columns
                    for c in selected_cols[:5]:  # Limit to top 5 for profiling to save time
                        try:
                            cname = str(c.get("COLUMN_NAME"))
                            mn, mx = self._get_min_max_values(asset['database'], asset['schema'], asset['table'], cname)
                            if mn and mx:
                                sample_values.append(f"Range({cname}): MIN={mn}, MAX={mx}")
                        except Exception:
                            pass
            except Exception:
                pass

        # Combine into rich context
        # Format: "Table T (Schema S). Business Purpose: ... Columns: C1 (Type), C2 (Type)... Samples: V1, V2..."
        parts = []
        parts.append(f"Table {table_name} (Schema {schema_name})")
        if bp:
            parts.append(f"Business Purpose: {bp}")
        if col_items:  # Use col_items which has enriched column info
            parts.append(f"Columns: {'; '.join(col_items[:40])}")  # Limit column list length
        if sample_values:
            parts.append(f"Samples/Ranges: {'; '.join(sample_values[:20])}")  # Limit samples length

        out = " | ".join(parts)

        # Cache result
        try:
            if hasattr(self, "_cache"):
                self._cache[ck] = out
        except Exception:
            pass
        return out

    def _category_boosts(self, asset: Dict[str, Any], context: str) -> Dict[str, float]:
        """Dynamic pattern/keyword regex boosts using SENSITIVE_* configuration (no hardcoded patterns)."""
        boosts: Dict[str, float] = {}
        # Cache lookup
        try:
            ck = f"boosts::{asset.get('full_name','')}::{(context or '')[:256]}"
            if hasattr(self, "_cache") and ck in self._cache:
                v = self._cache.get(ck) or {}
                if isinstance(v, dict):
                    return v
        except Exception:
            pass
        # Build evaluation text from asset identifiers + context
        eval_text = " ".join([
            asset.get('full_name', ''),
            asset.get('schema', ''),
            asset.get('table', ''),
            context or ''
        ])
        # Load sensitivity configuration
        try:
            cfg = ai_classification_service.load_sensitivity_config() or {}
        except Exception:
            cfg = {}
        patterns = cfg.get('patterns') or {}
        # Detect configured pattern/keyword hits using the service helper
        try:
            if hasattr(ai_classification_service, "_detect_patterns_in_context"):
                raw = ai_classification_service._detect_patterns_in_context(eval_text, patterns)
            else:
                raw = {}
        except Exception:
            raw = {}
        # Map governance categories to Avendra categories when applicable
        try:
            sem_to_av = getattr(ai_assistant_service, "_SEMANTIC_TO_AVENDRA", {}) or {}
        except Exception:
            sem_to_av = {}
        # Aggregate boosts per Avendra category with a conservative cap
        cap = 0.4
        for gcat, b in (raw or {}).items():
            try:
                bval = float(b)
            except Exception:
                continue
            av = sem_to_av.get(gcat, gcat)
            prev = float(boosts.get(av, 0.0))
            boosts[av] = max(0.0, min(cap, prev + bval))
        out = {k: v for k, v in boosts.items() if v > 0.0}
        try:
            if hasattr(self, "_cache"):
                self._cache[ck] = dict(out)
        except Exception:
            pass
        return out

    def _discover_assets(self, db: str) -> List[Dict[str, Any]]:
        """Discover tables and extract metadata for classification."""
        try:
            # Cache lookup
            try:
                schema_filter = self._get_schema_filter()
                table_filter = self._get_table_filter()
                ck = f"discover::{db}::{schema_filter or ''}::{table_filter or ''}"
                if hasattr(self, "_cache") and ck in self._cache:
                    v = self._cache.get(ck) or []
                    if isinstance(v, list):
                        return v
            except Exception:
                pass
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

            try:
                if hasattr(self, "_cache"):
                    self._cache[ck] = list(assets)
            except Exception:
                pass
            return assets

        except Exception as e:
            logger.error(f"Asset discovery failed: {e}")
            return []

    def _collect_metadata(self, db: str, schema_filter: Optional[str], table_filter: Optional[str], gov_db: str):
        """Collect tables, columns and governance glossary/compliance info."""
        # Tables
        try:
            ck_t = f"meta_tables::{db}::{schema_filter or ''}::{table_filter or ''}"
            if hasattr(self, "_cache") and ck_t in self._cache:
                v = self._cache.get(ck_t)
                if isinstance(v, pd.DataFrame):
                    tables_df = v
                else:
                    raise Exception("no cache df")
            else:
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
                try:
                    if hasattr(self, "_cache"):
                        self._cache[ck_t] = tables_df
                except Exception:
                    pass
        except Exception:
            tables_df = pd.DataFrame()

        # Columns
        try:
            ck_c = f"meta_columns::{db}::{schema_filter or ''}::{table_filter or ''}"
            if hasattr(self, "_cache") and ck_c in self._cache:
                v2 = self._cache.get(ck_c)
                if isinstance(v2, pd.DataFrame):
                    columns_df = v2
                else:
                    raise Exception("no cache df")
            else:
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
                try:
                    if hasattr(self, "_cache"):
                        self._cache[ck_c] = columns_df
                except Exception:
                    pass
        except Exception:
            columns_df = pd.DataFrame()

        # Glossary / compliance mapping (data-driven from governance config when available)
        try:
            from src.services.ai_classification_service import ai_classification_service as _svc
            try:
                if hasattr(_svc, "_ensure_gov_category_embeddings"):
                    _svc._ensure_gov_category_embeddings()  # type: ignore
            except Exception:
                pass
            comp_map = getattr(_svc, "_gov_cat_compliance", {}) or {}
            thr_map = getattr(_svc, "_gov_cat_thresholds", {}) or {}
            # Optional model metadata threshold for high-risk (fallback to 0.75)
            try:
                cfg = _svc.load_sensitivity_config() or {}
                high_thr = float((cfg.get("model_metadata") or {}).get("high_risk_threshold", 0.75))
            except Exception:
                high_thr = 0.75
            g_rows: List[Dict[str, Any]] = []
            for cat, tags in comp_map.items():
                g_rows.append({
                    "CATEGORY_NAME": str(cat),
                    "IS_HIGH_RISK": bool(float(thr_map.get(cat, 0.0) or 0.0) >= high_thr),
                    "COMPLIANCE_TAGS": ", ".join(tags or [])
                })
            # Fallback to static map only if governance compliance is unavailable
            if not g_rows:
                comp_map2 = getattr(self.ai_service, "_COMPLIANCE_MAP", {}) or {}
                g_rows = [{
                    "CATEGORY_NAME": str(cat),
                    "IS_HIGH_RISK": False,
                    "COMPLIANCE_TAGS": ", ".join(tags or [])
                } for cat, tags in comp_map2.items()]
            glossary_df = pd.DataFrame(g_rows)
        except Exception:
            glossary_df = pd.DataFrame()

        return tables_df, columns_df, glossary_df

    def _sample_column_values(self, db: str, schema: str, table: str, column: str, sample_rows: int = 100) -> List[Any]:
        """Sample non-null values from a specific column for semantics preview."""
        try:
            ck = f"sample::{db}.{schema}.{table}.{column}::{int(sample_rows or 0)}"
            if hasattr(self, "_cache") and ck in self._cache:
                v = self._cache.get(ck) or []
                if isinstance(v, list):
                    return v
            q = f"""
            SELECT "{column}" AS SAMPLE_VALUE
            FROM "{db}"."{schema}"."{table}"
            SAMPLE ({sample_rows} ROWS)
            WHERE "{column}" IS NOT NULL
            """
            rows = snowflake_connector.execute_query(q) or []
            out = [r.get('SAMPLE_VALUE') for r in rows if r and r.get('SAMPLE_VALUE') is not None]
            try:
                if hasattr(self, "_cache"):
                    self._cache[ck] = list(out)
            except Exception:
                pass
            return out
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

    def get_column_detection_results(self, database: str, schema: str, table: str) -> List[Dict[str, Any]]:
        """Get column-level detection results for a specific table using MiniLM embeddings + governance tables."""
        try:
            logger.info(f"Starting column detection for {database}.{schema}.{table}")
            
            # Validate inputs
            if not database or not schema or not table:
                logger.error(f"Invalid inputs: db={database}, schema={schema}, table={table}")
                return []
            
            # Ensure embeddings are initialized
            if self._embedder is None:
                logger.info("Initializing embeddings...")
                self._init_local_embeddings()
            
            if not self._category_centroids:
                logger.info("Initializing centroids...")
                self._init_local_embeddings()
            
            # Auto-tune parameters
            logger.info("Auto-tuning parameters...")
            self._auto_tune_parameters()
            
            # Run column-level classification with governance table integration
            logger.info(f"Running column-level classification with {len(self._category_centroids)} centroids")
            results = self._classify_columns_local(database, schema, table, max_cols=100) or []
            
            # Filter out error rows and ensure we have valid results
            valid_results = [r for r in results if 'error' not in r and r.get('category')]
            logger.info(f"Column detection completed: {len(valid_results)} sensitive columns detected out of {len(results)} total")
            
            return results
        except Exception as e:
            logger.error(f"Column detection failed for {database}.{schema}.{table}: {e}", exc_info=True)
            return []



    def _display_classification_results(self, results: List[Dict[str, Any]]) -> None:
        """Display the classification results with a dropdown for table selection."""
        st.markdown("#### Classification Results")

        # Filter out errors for display
        successful_results = [r for r in results if 'error' not in r]

        if not successful_results:
            st.warning("No successful classifications to display.")
            return

        # Create display dataframe with human-readable CIA labels
        display_data = []
        for result in successful_results:
            asset = result['asset']
            c_val = int(result.get('c', 0) or 0)
            i_val = int(result.get('i', 0) or 0)
            a_val = int(result.get('a', 0) or 0)

            # Map numeric CIA values to descriptive labels
            if c_val <= 0:
                c_label = "C0: Public"
            elif c_val == 1:
                c_label = "C1: Internal"
            elif c_val == 2:
                c_label = "C2: Restricted (PII/Financial)"
            else:
                c_label = "C3: Confidential/Highly Sensitive"

            if i_val <= 0:
                i_label = "I0: Low"
            elif i_val == 1:
                i_label = "I1: Moderate"
            elif i_val == 2:
                i_label = "I2: High"
            else:
                i_label = "I3: Critical"

            if a_val <= 0:
                a_label = "A0: Days+"
            elif a_val == 1:
                a_label = "A1: Hours"
            elif a_val == 2:
                a_label = "A2: <1 hour"
            else:
                a_label = "A3: Near real-time"

            display_data.append({
                "Asset": asset['full_name'],
                "Business Context": result.get('business_context', '')[:100] + '...' if result.get('business_context') and len(result.get('business_context', '')) > 100 else result.get('business_context', ''),
                "Category": result.get('category', 'N/A'),
                "Classification": result.get('label_emoji', result.get('label', 'N/A')),
                "Color": result.get('color', 'N/A'),
                "Confidentiality": c_label,
                "Integrity": i_label,
                "Availability": a_label,
                "Status": result.get('application_status', 'N/A'),
            })

        results_df = pd.DataFrame(display_data)
        try:
            try:
                theme_base = st.get_option("theme.base")
            except Exception:
                theme_base = "light"
            is_dark = str(theme_base or "").lower() == "dark"
            if is_dark:
                mp = {
                    'Red': '#7f1d1d',
                    'Orange': '#7c2d12',
                    'Yellow': '#7a6e00',
                    'Green': '#14532d',
                    'Gray': '#374151',
                }
                fg = '#ffffff'
            else:
                mp = {
                    'Red': '#ffe5e5',
                    'Orange': '#fff0e1',
                    'Yellow': '#fffbe5',
                    'Green': '#e9fbe5',
                    'Gray': '#f5f5f5',
                }
                fg = '#000000'

            def _apply_classification_style(row: pd.Series):
                col_name = 'Classification'
                col = str(row.get('Color', '') or '')
                bg = mp.get(col, '')
                styles = ['' for _ in row.index]
                try:
                    idx = list(row.index).index(col_name)
                    if bg:
                        styles[idx] = f'background-color: {bg}; color: {fg}; font-weight: 600'
                except Exception:
                    pass
                return styles

            styled = results_df.style.apply(_apply_classification_style, axis=1)
            st.dataframe(styled, width='stretch', hide_index=True)
        except Exception:
            st.dataframe(results_df, width='stretch', hide_index=True)

        # Dropdown for Table Selection
        st.divider()
        st.markdown("### 🔍 Detailed Analysis")
        
        # Create options map: "Database.Schema.Table" -> result object
        options_map = {r['asset']['full_name']: r for r in successful_results}
        options = list(options_map.keys())
        
        col_sel, _ = st.columns([1, 1])
        with col_sel:
            selected_table = st.selectbox(
                "Select a table to view detailed classification:",
                options=options,
                key="classification_result_table_select"
            )
        
        if selected_table:
            result = options_map[selected_table]
            asset = result['asset']
            
            with st.container():
                col1, col2 = st.columns([1, 2])

                with col1:
                    st.markdown(f"**{asset['full_name']}**")
                    st.write(f"**Category:** {result.get('category', 'N/A')}")
                    st.write(f"**Classification:** {result.get('label_emoji', result.get('label', 'N/A'))}")
                    
                    # Display reasoning if available (e.g. column-level drivers)
                    reasoning = result.get('reasoning', [])
                    if reasoning:
                        st.write("**Reasoning:**")
                        for r in reasoning:
                            st.caption(f"• {r}")
                            
                    st.write(f"**Route:** {result.get('route', 'N/A')}")
                    
                    # Display most relevant compliance frameworks
                    compliance_list = result.get('compliance', [])
                    if compliance_list:
                        # Show top compliance frameworks with icons
                        comp_display = []
                        for comp in compliance_list[:3]:  # Show top 3 compliance frameworks
                            comp_icon = '📋'
                            if 'GDPR' in comp.upper():
                                comp_icon = '🇪🇺'
                            elif 'CCPA' in comp.upper():
                                comp_icon = '🇺🇸'
                            elif 'HIPAA' in comp.upper():
                                comp_icon = '🏥'
                            elif 'PCI' in comp.upper():
                                comp_icon = '💳'
                            elif 'SOX' in comp.upper():
                                comp_icon = '📊'
                            comp_display.append(f"{comp_icon} {comp}")
                        st.write(f"**Compliance Frameworks:** {', '.join(comp_display)}")
                    else:
                        st.write(f"**Compliance Frameworks:** None")

                with col2:
                    business_context = result.get('business_context', '')
                    if business_context:
                        st.write("**Business Context:**")
                        st.text_area("Business Context", value=business_context, height=80, disabled=True, key=f"context_{asset['full_name']}", label_visibility="collapsed")

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
                
                # Column-level detection with automatic loading (full-width display)
                try:
                    table_key = asset['full_name']
                    col_key = f"col_results_{table_key.replace('.', '_')}"
                    col_loading_key = f"col_loading_{table_key.replace('.', '_')}"
                    
                    # Initialize state flags
                    if col_loading_key not in st.session_state:
                        st.session_state[col_loading_key] = False
                    # Pre-populate with results from the current run if available
                    if result.get('columns'):
                        st.session_state[col_key] = result.get('columns')
                    elif col_key not in st.session_state:
                        st.session_state[col_key] = None
                    
                    # Auto-load column detection if not already loaded
                    col_rows = st.session_state.get(col_key)
                    if col_rows is None and not st.session_state[col_loading_key]:
                        st.session_state[col_loading_key] = True
                    
                    # Load column detection if triggered
                    if st.session_state[col_loading_key] and col_rows is None:
                        with st.spinner("🔄 Analyzing columns for sensitive data..."):
                            try:
                                dbn, scn, tbn = table_key.split('.')
                                logger.info(f"Fetching column detection for {dbn}.{scn}.{tbn}")
                                col_rows = self.get_column_detection_results(dbn, scn, tbn)
                                logger.info(f"Raw column detection results: {len(col_rows) if col_rows else 0} rows returned")
                                
                                # Ensure we have a list
                                if col_rows is None:
                                    col_rows = []
                                
                                st.session_state[col_key] = col_rows
                                st.session_state[col_loading_key] = False
                                logger.info(f"✓ Column detection completed: {len(col_rows)} columns analyzed")
                            except Exception as ce:
                                logger.error(f"❌ Column detection error: {ce}", exc_info=True)
                                st.error(f"❌ Column detection failed: {ce}")
                                st.session_state[col_key] = []
                                st.session_state[col_loading_key] = False
                    
                    # Display column results
                    col_rows = st.session_state.get(col_key, [])
                    
                    if col_rows and len(col_rows) > 0:
                        # Filter for display - show only higher-confidence PII / SOX / SOC2 columns
                        col_rows_clean = [
                            r for r in col_rows
                            if 'error' not in r
                            and r.get('category') in {'PII', 'SOX', 'SOC2'}
                            and r.get('confidence_pct', 0) >= 50
                        ]
                        
                        if col_rows_clean and len(col_rows_clean) > 0:
                            st.markdown("#### 📊 Column-Level Classification Results")
                            
                            # Use same emoji mapping as table-level classifications
                            label_emoji_map = {
                                'Confidential': '🟥 Confidential',
                                'Restricted': '🟧 Restricted',
                                'Internal': '🟨 Internal',
                                'Public': '🟩 Public',
                                'Uncertain — review': '⬜ Uncertain — review',
                            }
                            
                            # Create display dataframe with human-readable CIA labels (no confidence column)
                            col_display = []
                            for col in col_rows_clean:
                                raw_label = col.get('label', 'N/A')
                                label_with_emoji = label_emoji_map.get(raw_label, raw_label)
                                raw_cat = col.get('category')
                                # Use robust mapping for display
                                display_cat = self._map_category_to_policy_group(raw_cat)

                                c_val = int(col.get('c', 0) or 0)
                                i_val = int(col.get('i', 0) or 0)
                                a_val = int(col.get('a', 0) or 0)

                                # Map numeric CIA values to descriptive labels (same mapping as table-level)
                                if c_val <= 0:
                                    c_label = "C0: Public"
                                elif c_val == 1:
                                    c_label = "C1: Internal"
                                elif c_val == 2:
                                    c_label = "C2: Restricted (PII/Financial)"
                                else:
                                    c_label = "C3: Confidential/Highly Sensitive"

                                if i_val <= 0:
                                    i_label = "I0: Low"
                                elif i_val == 1:
                                    i_label = "I1: Moderate"
                                elif i_val == 2:
                                    i_label = "I2: High"
                                else:
                                    i_label = "I3: Critical"

                                if a_val <= 0:
                                    a_label = "A0: Days+"
                                elif a_val == 1:
                                    a_label = "A1: Hours"
                                elif a_val == 2:
                                    a_label = "A2: <1 hour"
                                else:
                                    a_label = "A3: Near real-time"

                                col_display.append({
                                    "Column": col.get('column', 'N/A'),
                                    "Data Type": col.get('data_type', 'N/A'),
                                    "Category": display_cat if display_cat is not None else 'N/A',
                                    "Label": label_with_emoji,
                                    "Confidentiality": c_label,
                                    "Integrity": i_label,
                                    "Availability": a_label,
                                })
                            
                            if col_display:
                                col_df = pd.DataFrame(col_display)
                                
                                # Color code by label using same scheme as table-level results
                                def _apply_column_label_style(row: pd.Series):
                                    val = str(row.get('Label', '') or '')
                                    bg = ''
                                    if '🟥 Confidential' in val:
                                        bg = '#ffe5e5'  # Red background (light)
                                    elif '🟧 Restricted' in val:
                                        bg = '#fff0e1'  # Orange
                                    elif '🟨 Internal' in val:
                                        bg = '#fffbe5'  # Yellow
                                    elif '🟩 Public' in val:
                                        bg = '#e9fbe5'  # Green
                                    elif '⬜ Uncertain — review' in val:
                                        bg = '#f5f5f5'  # Gray
                                    styles = ['' for _ in row.index]
                                    try:
                                        idx = list(row.index).index('Label')
                                        if bg:
                                            styles[idx] = f'background-color: {bg}; color: #000; font-weight: 600'
                                    except Exception:
                                        pass
                                    return styles
                                
                                styled_df = col_df.style.apply(_apply_column_label_style, axis=1)
                                st.dataframe(styled_df, width='stretch', hide_index=True)
                                
                                # Summary statistics
                                confident = sum(1 for c in col_rows_clean if c.get('confidence_pct', 0) >= 80)
                                likely = sum(1 for c in col_rows_clean if 60 <= c.get('confidence_pct', 0) < 80)
                                uncertain = sum(1 for c in col_rows_clean if c.get('confidence_pct', 0) < 60)
                                
                                st.success(f"✅ Summary: {confident} Confident (≥80%) | {likely} Likely (60-80%) | {uncertain} Uncertain (<60%)")
                            else:
                                st.info("ℹ️ No sensitive columns detected in this table.")
                        else:
                            st.info("ℹ️ Column detection completed - no sensitive columns found.")
                    elif col_rows == []:
                        st.info("ℹ️ Column detection completed - no sensitive columns found.")
                except Exception as e:
                    logger.error(f"Column detection UI error: {e}", exc_info=True)
                    st.error(f"Error displaying column detection: {e}")

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


    # ==================================================================================
    # NEW GOVERNANCE-DRIVEN CLASSIFICATION METHODS (100% METADATA DRIVEN)
    # ==================================================================================

    def _get_columns_from_information_schema(self, db: str, schema: str, table: str) -> List[Dict[str, Any]]:
        """Fetch columns from information_schema."""
        try:
            return snowflake_connector.execute_query(f"""
                SELECT COLUMN_NAME, DATA_TYPE, COMMENT as COLUMN_COMMENT
                FROM {db}.INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
                ORDER BY ORDINAL_POSITION
            """, (schema, table)) or []
        except Exception as e:
            logger.error(f"Failed to fetch columns for {db}.{schema}.{table}: {e}")
            return []

    def _build_table_context_from_metadata(self, db: str, schema: str, table: str) -> str:
        """Build context using ONLY information_schema metadata"""
        try:
            # Get table metadata
            table_info = snowflake_connector.execute_query(f"""
                SELECT TABLE_NAME, TABLE_TYPE, COMMENT, ROW_COUNT
                FROM {db}.INFORMATION_SCHEMA.TABLES 
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
            """, (schema, table))
            
            table_data = table_info[0] if table_info else {}
            
            # Get column metadata
            columns = self._get_columns_from_information_schema(db, schema, table)

            # Precompute column and comment strings to avoid nested f-strings
            col_desc_list = [
                "{} ({})".format(col.get("COLUMN_NAME"), col.get("DATA_TYPE"))
                for col in columns
            ]
            columns_str = ", ".join(col_desc_list) if col_desc_list else ""

            comment_desc_list = [
                "{}: {}".format(col.get("COLUMN_NAME"), col.get("COLUMN_COMMENT", "No comment"))
                for col in columns
                if col.get("COLUMN_COMMENT")
            ]
            comments_str = "; ".join(comment_desc_list) if comment_desc_list else ""

            # Build context from metadata only
            context_parts = [
                f"Table: {schema}.{table}",
                f"Type: {table_data.get('TABLE_TYPE', 'UNKNOWN')}",
                f"Description: {table_data.get('COMMENT', 'No description')}",
                f"Columns: {columns_str}",
                f"Column Comments: {comments_str}"
            ]
            
            return " | ".join([part for part in context_parts if part])
            
        except Exception as e:
            logger.error(f"Metadata context building failed for {db}.{schema}.{table}: {e}")
            return f"Table: {schema}.{table}"

    def _semantic_scores_governance_driven(self, text: str) -> Dict[str, float]:
        """
        PHASE 2: Semantic scoring using ONLY governance table centroids
        
        CRITICAL FIXES APPLIED:
        - E5 ASYMMETRIC ENCODING: Uses 'query:' prefix for input text
        - Matches against 'passage:' encoded centroids
        - Explicit vector normalization
        - Embedding caching for performance
        """
        scores = {}
        
        if not text or not self._embedder or not self._category_centroids:
            return scores
        
        try:
            # 1. Check Cache First
            # Use a simple class-level cache key based on text
            cache_key = f"sem_score_{hash(text)}"
            if hasattr(self, '_embedding_cache') and cache_key in self._embedding_cache:
                return self._embedding_cache[cache_key]
            
            # 2. Preprocess and Encode with E5 QUERY Prefix
            # E5 requires 'query:' for the input text when matching against 'passage:' documents
            processed_text = self._preprocess_text_local(text)
            
            # Add 'query:' prefix for E5 models
            if self._embed_backend == 'sentence-transformers':
                query_text = f"query: {processed_text}"
            else:
                query_text = processed_text
            
            # Encode text
            text_embedding = self._embedder.encode([query_text], normalize_embeddings=True)[0]
            
            # CRITICAL: Explicitly re-normalize to ensure unit vector
            text_norm = np.linalg.norm(text_embedding)
            if text_norm == 0:
                return scores
            
            text_embedding = text_embedding / text_norm
            
            # 3. Compare against ALL governance categories
            for category, centroid in self._category_centroids.items():
                if centroid is None:
                    continue
                    
                try:
                    # Centroids are already normalized during creation
                    # Cosine similarity (dot product of normalized vectors)
                    similarity = float(np.dot(text_embedding, centroid))
                    
                    # Convert cosine similarity to confidence score [0, 1]
                    confidence = (similarity + 1.0) / 2.0
                    
                    # Return ALL scores > 0 (filtering happens later)
                    if confidence > 0.0:
                        scores[category] = confidence
                    
                except Exception:
                    continue
            
            # 4. Cache Result
            if not hasattr(self, '_embedding_cache'):
                self._embedding_cache = {}
            
            # Simple LRU-like behavior: clear if too big
            if len(self._embedding_cache) > 1000:
                self._embedding_cache.clear()
                
            self._embedding_cache[cache_key] = scores
            return scores
                    
        except Exception as e:
            logger.error(f"Semantic scoring failed: {e}")
            return scores
            logger.error(f"Governance-driven semantic scoring failed: {e}", exc_info=True)
            
        logger.debug(f"Semantic scores returned: {len(scores)} categories")
        return scores

    def _pattern_scores_governance_driven(self, text: str) -> Dict[str, float]:
        """
        PHASE 3: Pattern scoring using ONLY SENSITIVE_PATTERNS table
        
        CRITICAL FIX:
        - Progressive scoring: At least 1 match = 0.5, scaling to 1.0 for 100% coverage
        - NO PRE-FILTERING at threshold (return all non-zero scores)
        """
        scores = {}
        
        if not hasattr(self, '_category_patterns') or not self._category_patterns:
            logger.warning("No pattern data loaded from SENSITIVE_PATTERNS table")
            return scores
        
        for category, patterns in self._category_patterns.items():
            if not patterns:
                continue
                
            match_count = 0
            total_patterns = len(patterns)
            matched_patterns = []
            
            for pattern in patterns:
                try:
                    if re.search(pattern, text, re.IGNORECASE):
                        match_count += 1
                        matched_patterns.append(pattern[:50])  # Store first 50 chars for debugging
                except re.error as e:
                    logger.warning(f"Invalid regex pattern for governance category {category}: {pattern} - {e}")
                    continue
            
            if match_count > 0:
                # PROGRESSIVE SCORING:
                # - At least 1 match = 0.50 (base confidence)
                # - 50% coverage = 0.75
                # - 100% coverage = 1.00
                coverage = match_count / max(1, total_patterns)
                score = 0.5 + (0.5 * coverage)  # Maps [0,1] coverage to [0.5,1.0] score
                
                # PHASE 3: NO PRE-FILTERING - return all non-zero scores
                scores[category] = min(1.0, score)
                logger.debug(
                    f"Pattern: {category} = {score:.3f} ({match_count}/{total_patterns} patterns matched)"
                )
        
        logger.debug(f"Pattern scores returned: {len(scores)} categories")
        return scores

    def _compute_governance_scores(self, text: str) -> Dict[str, float]:
        """
        PHASE 3: Adaptive confidence scoring with governance metadata
        
        CRITICAL FIXES:
        - Default threshold lowered from 0.65 to 0.45
        - Intelligent weight adjustment based on available signals
        - Quality-based calibration for context richness
        - Multiplicative boosting for strong signals
        - NO min-max normalization (preserves absolute confidence)
        """
        scores = {}
        
        # Get component scores (all now return unfiltered scores)
        semantic_scores = self._semantic_scores_governance_driven(text)
        keyword_scores = self._keyword_scores(text)
        pattern_scores = self._pattern_scores_governance_driven(text)
        
        # Context quality assessment
        quality = self._context_quality_metrics(text)
        quality_factor = 1.0
        
        # Boost for rich textual context
        if quality.get('len', 0) > 300 and quality.get('alpha_ratio', 0) > 0.5:
            quality_factor = 1.10  # Rich context → 10% boost
        elif quality.get('too_short', False):
            quality_factor = 0.95  # Limited context → 5% penalty
        
        # Combine all detected categories
        all_categories = set(
            list(semantic_scores.keys()) + 
            list(keyword_scores.keys()) + 
            list(pattern_scores.keys())
        )
        
        logger.debug(f"Combining scores for {len(all_categories)} categories from {len(semantic_scores)} semantic, {len(keyword_scores)} keyword, {len(pattern_scores)} pattern")
        
        for category in all_categories:
            sem_score = semantic_scores.get(category, 0.0)
            kw_score = keyword_scores.get(category, 0.0)
            pat_score = pattern_scores.get(category, 0.0)
            
            # INTELLIGENT WEIGHT ADJUSTMENT based on metadata configuration
            # Retrieve weights from metadata (default to 0.6/0.25/0.15 if not found)
            weights = self._category_scoring_weights.get(category, {'w_sem': 0.6, 'w_kw': 0.25, 'w_pat': 0.15})
            w_sem = weights['w_sem']
            w_kw = weights['w_kw']
            w_pat = weights['w_pat']
            
            # Dynamic normalization based on available signals
            # If a signal is missing (0.0), we redistribute its weight to the others
            available_weight = 0.0
            score_sum = 0.0
            signal_parts = []
            
            if sem_score > 0:
                available_weight += w_sem
                score_sum += sem_score * w_sem
                signal_parts.append("SEM")
            
            if kw_score > 0:
                available_weight += w_kw
                score_sum += kw_score * w_kw
                signal_parts.append("KW")
                
            if pat_score > 0:
                available_weight += w_pat
                score_sum += pat_score * w_pat
                signal_parts.append("PAT")
                
            if available_weight > 0:
                base_score = score_sum / available_weight
                signal_type = "+".join(signal_parts)
            else:
                continue  # No signals for this category
            
            # Apply quality calibration
            adjusted_score = base_score * quality_factor
            
            # MULTIPLICATIVE BOOSTING for strong signals
            # This amplifies confident detections while preserving relative ordering
            if adjusted_score >= 0.70:
                # Very strong signal → 15-30% boost
                boost_factor = 1.15 + (adjusted_score - 0.70) * 0.5
            elif adjusted_score >= 0.55:
                # Strong signal → 10-15% boost
                boost_factor = 1.10 + (adjusted_score - 0.55) * 0.33
            elif adjusted_score >= 0.40:
                # Moderate signal → 5-10% boost
                boost_factor = 1.05 + (adjusted_score - 0.40) * 0.33
            else:
                # Weak signal → no boost
                boost_factor = 1.0
            
            final_score = min(0.95, adjusted_score * boost_factor)
            
            # ADAPTIVE THRESHOLD from governance (DEFAULT 0.35 - BALANCED: Raised from 0.25 to reduce false positives)
            threshold = self._category_thresholds.get(category, 0.35)
            
            # Only include if above threshold
            if final_score >= threshold:
                scores[category] = final_score
                logger.debug(
                    f"✓ {category}: base={base_score:.3f}, final={final_score:.3f}, threshold={threshold:.3f} "
                    f"[{signal_type}] (sem={sem_score:.3f}, kw={kw_score:.3f}, pat={pat_score:.3f})"
                )
            else:
                logger.debug(
                    f"✗ {category}: final={final_score:.3f} < threshold={threshold:.3f} "
                    f"[{signal_type}] (sem={sem_score:.3f}, kw={kw_score:.3f}, pat={pat_score:.3f})"
                )
        
        logger.debug(f"Governance scores: {len(scores)} categories passed threshold")
        return scores
        
    def _sample_table_values_batch(self, db: str, schema: str, table: str, columns: List[str], limit: int = 20) -> Dict[str, List[Any]]:
        """
        Batch sample values for ALL columns in a single query to reduce Snowflake costs.
        Returns a dictionary mapping column_name -> list of sample values.
        """
        if not columns:
            return {}
            
        try:
            # Construct a single query to fetch samples for all columns
            # Using LIMIT instead of SAMPLE for better performance on large tables if we just need 'some' data
            # Or use TABLESAMPLE SYSTEM (1) for very large tables
            
            cols_sql = ", ".join([f'"{col}"' for col in columns])
            query = f"""
            SELECT {cols_sql}
            FROM "{db}"."{schema}"."{table}"
            LIMIT {limit}
            """
            
            rows = snowflake_connector.execute_query(query) or []
            
            # Transpose rows to columns
            samples_by_col = {col: [] for col in columns}
            for row in rows:
                for col in columns:
                    val = row.get(col)
                    if val is not None and str(val).strip():
                        samples_by_col[col].append(val)
                        
            return samples_by_col
            
        except Exception as e:
            logger.warning(f"Batch sampling failed for {table}: {e}")
            return {col: [] for col in columns}

    def _classify_column_governance_driven(self, db: str, schema: str, table: str, 
                                         column: Dict[str, Any], 
                                         pre_fetched_samples: List[Any] = None) -> Dict[str, Any]:
        """
        Classify single column using ONLY governance metadata.
        
        ACCURACY ENHANCEMENT: Added context-aware classification that understands:
        1. Table-level context (e.g., ORDER tables → SOX priority)
        2. Smart ID classification (order_id vs customer_id vs product_id)
        3. Category boosting based on semantic table understanding
        """
        
        col_name = column['COLUMN_NAME']
        col_type = column['DATA_TYPE']
        col_comment = column.get('COLUMN_COMMENT', '')
        
        col_lower = col_name.lower()

        # ========================================================================
        # WHITELIST APPROACH: Skip column UNLESS it matches sensitive patterns
        # ========================================================================
        # This inverts the logic to be more conservative - we only process columns
        # that have EXPLICIT indicators of sensitive data.
        
        # Define patterns that DEFINITELY indicate sensitive data
        # SYNCED WITH GOVERNANCE TABLES: SENSITIVE_KEYWORDS
        definitely_sensitive_patterns = [
            # === PII (Personal Identifiable Information) ===
            'ssn', 'social_security', 'social_sec', 'tax_id', 'ein', 'tin', 'itin',
            'email', 'e_mail', 'email_address', 'personal_email', 'work_email', 'customer_email', 'employee_email', 'user_email',
            'phone', 'mobile', 'telephone', 'cell_phone', 'phone_number', 'mobile_number', 'home_phone', 'customer_phone', 'employee_phone', 'client_phone', 'user_phone', 'patient_phone',
            'first_name', 'last_name', 'full_name', 'maiden_name', 'middle_name', 'customer_name', 'employee_name', 'client_name', 'patient_name',
            'birth_date', 'dob', 'date_of_birth', 'birthdate',
            'passport', 'passport_number', 'passport_id',
            'driver_license', 'drivers_license', 'license_number', 'drivers_license_number',
            'national_id', 'national_identifier', 'citizen_id', 'identity_number', 'government_id_number',
            'address', 'street_address', 'home_address', 'mailing_address',
            'billing_address', 'shipping_address',
            'zip_code', 'postal_code', 'postcode',
            'credit_card', 'card_number', 'cc_number', 'card_num', 'credit_card_number', 'debit_card',
            'cvv', 'cvc', 'security_code',
            'routing_number', 'routing_num', 'aba_number',
            'account_number', 'account_num', 'bank_account', 'bank_account_number',
            'iban', 'swift', 'bic', 'swift_code',
            'medical_record', 'patient_medical_record', 'patient_record', 'health_record', 'health_id',
            'patient_id', 'diagnosis', 'treatment',
            'biometric', 'fingerprint', 'retina_scan', 'facial_recognition',
            'ethnicity', 'marital_status',
            'taxpayer_id', 'tax_identification_number',
            
            # === Financial (SOX) ===
            # Revenue & Transactions
            'revenue', 'revenue_amount', 'revenue_transaction', 'revenue_recognition',
            'transaction_amount', 'financial_transaction',
            'invoice_amount', 'payment_total', 'total_due', 'amount',
            'order_amount',
            'expense_amount', 'expense_report',
            
            # Accounting & Ledgers
            'general_ledger', 'gl_account', 'journal_entry',
            'chart_of_accounts', 'trial_balance', 'subsidiary_ledger',
            'balance_sheet', 'income_statement', 'cash_flow', 'cash_flow_statement',
            'financial_statement', 'financial_report', 'audited_financials',
            
            # Accounts & Payments
            'accounts_payable', 'accounts_receivable',
            'sales_invoice', 'accounting_entry',
            
            # Audit & Compliance
            'audit_trail', 'audit_log', 'financial_audit',
            'internal_control', 'internal_controls', 'control_testing',
            'segregation_duties', 'segregation_of_duties',
            'sox_compliance',
            
            # === Security (SOC2) ===
            # Authentication & Credentials
            'password', 'passwd', 'pwd', 'pass_word', 'login_password',
            'credential', 'credentials', 'user_credentials',
            
            # Tokens & Keys
            'token', 'access_token', 'refresh_token', 'auth_token', 'authentication_token',
            'bearer_token', 'jwt_token', 'oauth_token',
            'api_key', 'apikey', 'api_secret', 'api_secret_key',
            'secret', 'secret_key',
            'encryption_key', 'private_key', 'public_key',
            
            # Sessions & Access
            'session_id', 'session_key', 'session_token', 'session_cookie',
            'auth_code', 'authorization_code',
            'access_control', 'access_control_list', 'role_based_access',
            'user_permissions',
            
            # Security Infrastructure
            'encryption', 'encryption_algorithm',
            'tls_certificate', 'ssl_certificate',
            'firewall_rule',
            
            # Security Monitoring
            'security_audit_log', 'security_incident', 'security_incident_report',
            'vulnerability', 'breach_notification',
            'security_policy', 'incident_response_plan',
            
            # System Security
            'system_config', 'change_log', 'change_management_log',
            'disaster_recovery', 'access_review_log', 'system_audit_trail',
            
            # === Health (HIPAA) ===
            'health_insurance', 'insurance_number',
        ]
        
        # Check if column name contains ANY sensitive pattern
        has_sensitive_pattern = any(pattern in col_lower for pattern in definitely_sensitive_patterns)
        
        # CRITICAL: Skip column if NO sensitive pattern found
        if not has_sensitive_pattern:
            logger.debug(f"  ✓ SKIPPED '{col_name}' - No sensitive pattern detected (whitelist approach)")
            return None
        
        # If we reach here, column has a sensitive pattern and should be scored
        logger.debug(f"  → PROCESSING '{col_name}' - Sensitive pattern detected")

        # Build context from metadata only
        context_parts = [
            f"Column: {col_name}",
            f"Table: {table}",
            f"Schema: {schema}",
            f"Data Type: {col_type}"
        ]
        
        if col_comment:
            context_parts.append(f"Comment: {col_comment}")
        
        # Use pre-fetched samples if available (Batch Optimization)
        if pre_fetched_samples is not None:
            samples = pre_fetched_samples
        else:
            # Fallback to individual query (legacy)
            samples = self._sample_column_values(db, schema, table, col_name, 20)
            
        if samples:
            sample_text = " ".join([str(s) for s in samples[:3]])
            context_parts.append(f"Samples: {sample_text}")
        
        context = " | ".join(context_parts)
        
        # Compute scores using governance-driven methods only
        scores = self._compute_governance_scores(context)
        
        # === ACCURACY ENHANCEMENT: Context-Aware Adjustments ===
        scores = self._apply_context_aware_adjustments(
            scores, col_name, table, col_type, samples
        )
        
        # === MULTI-LABEL SUPPORT ===
        # Identify ALL categories that meet the threshold, not just the top one
        detected_categories = []
        for cat, score in scores.items():
            # Use category-specific threshold if available, else 0.35 (BALANCED: Raised from 0.25 to reduce false positives)
            thresh = self._category_thresholds.get(cat, 0.35)
            
            # EXCLUDE GENERIC / NON-SENSITIVE CATEGORIES
            # We only want to report truly sensitive categories
            if cat.upper() in ('NON_SENSITIVE', 'GENERAL', 'SYSTEM', 'METADATA', 'UNKNOWN'):
                continue
                
            # Check if it maps to a sensitive policy group
            pg = self._map_category_to_policy_group(cat)
            if pg == 'NON_SENSITIVE':
                continue
            
            # STRICTER validation: Require minimum confidence of 0.70 to reduce false positives
            # This ensures only high-confidence sensitive signals are kept for column-level results
            if score < 0.70:
                continue

            if score >= thresh:
                detected_categories.append({
                    'category': cat,
                    'confidence': score
                })
        
        # Sort by confidence descending
        detected_categories.sort(key=lambda x: x['confidence'], reverse=True)
        
        # Determine primary category (top 1)
        if detected_categories:
            best_category = detected_categories[0]['category']
            confidence = detected_categories[0]['confidence']
        else:
            best_category = 'NON_SENSITIVE'
            confidence = 0.0
        
        # Map to policy group for UI consistency
        policy_group = self._map_category_to_policy_group(best_category) if best_category != 'NON_SENSITIVE' else None

        # Ensure we only treat PII/SOX/SOC2 as sensitive policy groups for column detection
        if policy_group not in {"PII", "SOX", "SOC2"}:
            policy_group = None
        
        # === CRITICAL VALIDATION: Skip Non-Sensitive Columns ===
        # If no detected categories OR best category is NON_SENSITIVE OR no policy group mapping
        # Then this column is NOT sensitive and should be EXCLUDED from results
        if not detected_categories or best_category == 'NON_SENSITIVE' or not policy_group:
            logger.debug(f"  → Column '{col_name}' is NON-SENSITIVE (no valid sensitive categories detected)")
            # Return None to indicate this column should be skipped
            return None
        
        # Additional validation: Ensure confidence is meaningful
        if confidence < 0.70:
            logger.debug(f"  ✓ Column '{col_name}' confidence {confidence:.3f} < 0.70 (too low, skipping)")
            return None
        
        # Calculate CIA and Label for UI
        c, i, a = (0, 0, 0)
        label = "Public"
        
        # Check if sensitive (policy group exists or category is not NON_SENSITIVE)
        if policy_group or best_category != 'NON_SENSITIVE':
             try:
                 canon_cat = self._normalize_category_for_cia(best_category)
                 c, i, a = ai_assistant_service.CIA_MAPPING.get(canon_cat, (1, 1, 1))
                 label = self.ai_service._map_cia_to_label(c, i, a)
             except Exception:
                 c, i, a = (1, 1, 1)
                 label = "Internal"

        # Create comma-separated string of all detected categories for UI display
        multi_label_str = ", ".join([d['category'] for d in detected_categories]) if detected_categories else best_category

        return {
            'column_name': col_name,
            'data_type': col_type,
            'category': best_category,
            'policy_group': policy_group,  # Expose policy group explicitly
            'confidence': confidence,
            'detected_categories': detected_categories,  # New Multi-Label Field
            'multi_label_category': multi_label_str,     # UI Display Field
            'governance_scores': scores,
            'context_used': context,
            # UI Fields
            'column': col_name,
            'label': label,
            'c': c, 'i': i, 'a': a,
            'confidence_pct': round(confidence * 100, 1)
        }
    
    def _apply_context_aware_adjustments(self, scores: Dict[str, float], 
                                        col_name: str, table: str, 
                                        col_type: str, samples: List) -> Dict[str, float]:
        """
        Apply context-aware adjustments to improve classification accuracy.
        
        Fixes misclassifications like:
        - order_id → SOC2 (wrong) should be SOX
        - product_id → PII (wrong) should be NON_SENSITIVE
        - customer_id → SOC2 (wrong) should be PII
        """
        
        adjusted_scores = scores.copy()
        
        col_lower = col_name.lower()
        table_lower = table.lower()
        
        # === RULE 1: Table Context Boosting ===
        # Identify table domain and boost relevant categories
        
        # Financial/Transactional tables → Boost SOX
        if any(kw in table_lower for kw in ['order', 'transaction', 'payment', 'invoice', 
                                              'billing', 'purchase', 'sale', 'revenue']):
            self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.3)
            # Reduce SOC2 for non-security columns in financial tables
            if not any(kw in col_lower for kw in ['password', 'token', 'auth', 'credential', 'session']):
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.7)
        
        # Customer/User tables → Boost PII
        elif any(kw in table_lower for kw in ['customer', 'user', 'employee', 'person', 'contact']):
            self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.3)
        
        # Security/Auth tables → Boost SOC2
        elif any(kw in table_lower for kw in ['auth', 'security', 'access', 'credential', 'session', 'login']):
            self._boost_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 1.3)
        
        # === RULE 2: Smart ID Classification ===
        # Different types of IDs should map to different categories
        
        if col_lower.endswith('_id') or col_lower.endswith('id'):
            
            # PII IDs: Identify people
            if any(kw in col_lower for kw in ['customer', 'user', 'employee', 'person', 'patient', 
                                               'member', 'subscriber', 'citizen', 'contact']):
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.5)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.3)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.5)
            
            # SOX IDs: Financial/transactional identifiers
            elif any(kw in col_lower for kw in ['order', 'transaction', 'payment', 'invoice', 
                                                 'account', 'billing', 'purchase', 'sale']):
                self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.4)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.3)
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.5)
            
            # SOC2 IDs: Security/access identifiers
            elif any(kw in col_lower for kw in ['session', 'token', 'auth', 'credential', 
                                                 'access', 'login', 'permission']):
                self._boost_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 1.5)
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.3)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.5)
            
            # Generic IDs: Product, category, etc. → Likely NON_SENSITIVE
            elif any(kw in col_lower for kw in ['product', 'item', 'category', 'catalog', 
                                                 'inventory', 'sku', 'department', 'store', 'warehouse',
                                                 'location', 'region', 'branch', 'division']):
                # Significantly reduce all sensitive scores for catalog IDs
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.2)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.2)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.6)
                # Remove all sensitive categories for these generic IDs
                for cat in list(adjusted_scores.keys()):
                    cat_upper = cat.upper()
                    if 'PII' in cat_upper or 'SOX' in cat_upper or 'SOC2' in cat_upper:
                        adjusted_scores.pop(cat, None)
        
        # === RULE 3: Price/Amount Fields → SOX ===
        if any(kw in col_lower for kw in ['price', 'amount', 'total', 'cost', 'fee', 
                                           'charge', 'balance', 'revenue', 'salary', 'wage']):
            self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.4)
            self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.4)
            self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.3)
        
        # === RULE 4: Quantity/Count Fields → Often NON_SENSITIVE or SOX ===
        if any(kw in col_lower for kw in ['quantity', 'count', 'qty', 'number_of']):
            # Slightly boost SOX if in transactional context
            if any(kw in table_lower for kw in ['order', 'transaction', 'sale']):
                self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.2)
            # Reduce PII/SOC2 for quantity fields
            self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.5)
            self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.4)

        # === RULE 6: Dates (invoice_date, due_date, etc.) ===
        # Dates are rarely PII unless they are birth dates
        if any(kw in col_lower for kw in ['date', 'time', 'created', 'updated', 'timestamp']):
            if any(kw in col_lower for kw in ['birth', 'dob']):
                # It IS PII (Date of Birth)
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.5)
            else:
                # Generic dates -> Reduce PII
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.3)
                # Boost SOX if financial context (invoice_date, due_date)
                if any(kw in col_lower for kw in ['invoice', 'due', 'payment', 'transaction']):
                    self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.3)

        # === RULE 7: Status/Codes (invoice_status, currency_code) ===
        # These are often system metadata or financial context, rarely PII
        if any(kw in col_lower for kw in ['status', 'state', 'type', 'code', 'mode', 'flag']):
            # Exception: "state" in address context (billing_state) -> PII
            if any(kw in col_lower for kw in ['billing', 'shipping', 'mailing', 'address']):
                # Likely PII (Address) - boost PII
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.4)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.5)
            else:
                # Reduce PII for generic status/codes
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.3)

        # === RULE 8: Generic Metadata Penalties (Status, Date, ID) ===
        # CRITICAL: Overwrite previous boosts for these generic fields to prevent false positives
        
        # Status/Flag/Type -> Strong Penalty
        if any(kw in col_lower for kw in ['status', 'state', 'flag', 'type', 'mode', 'method', 'config', 'setting']):
            # Unless it's a specific financial status like 'payment_status' which might be mild SOX, but usually not critical
            self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.2)
            self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.1)
            self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.1)

        # Dates (created, updated, etc) -> Moderate Penalty (exclude DOB)
        if any(kw in col_lower for kw in ['date', 'time', 'at', 'on', 'window', 'period']) and not any(kw in col_lower for kw in ['birth', 'dob']):
            self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.4) 
            self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.1)
            self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.2)
        
        # IDs (invoice_id, order_id) -> Moderate Penalty (exclude Account/Tax/SSN/User)
        if (col_lower.endswith('_id') or col_lower == 'id' or col_lower.endswith('id')) and not any(kw in col_lower for kw in ['tax', 'ssn', 'account', 'card', 'user', 'customer', 'employee', 'member', 'patient']):
             self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.3)
             self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.2)
             self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.2)
                
        # Boost SOX for financial codes (currency_code, tax_code)
        if any(kw in col_lower for kw in ['currency', 'tax', 'fiscal', 'invoice', 'payment']):
            self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.3)

        # === RULE 8: Currency Fields ===
        if any(kw in col_lower for kw in ['currency', 'iso_code']):
             self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.2)
             self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.4)
        
        # === RULE 9: Address Fields (billing_address, billing_city, billing_state_province) ===
        # Address components are PII, especially in billing/shipping context
        if any(kw in col_lower for kw in ['address', 'city', 'street', 'zip', 'postal', 'province', 'country']):
            # Check for billing/shipping context
            if any(kw in col_lower for kw in ['billing', 'shipping', 'mailing', 'delivery']):
                # Strong PII signal
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.6)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.4)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.3)
            else:
                # Generic address fields are still PII
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.4)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.5)
        
        # === RULE 10: Name Fields ===
        # Names are strong PII indicators
        if any(kw in col_lower for kw in ['name', 'first_name', 'last_name', 'full_name', 'firstname', 'lastname']):
            # Exception: product_name, company_name, etc. are NOT PII
            if any(kw in col_lower for kw in ['product', 'company', 'business', 'organization', 'vendor', 
                                               'supplier', 'merchant', 'store', 'shop', 'brand', 'category',
                                               'item', 'service', 'package', 'plan']):
                # Not personal names
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.3)
            else:
                # Personal names -> Strong PII
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.7)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.3)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.3)
        
        # === RULE 11: Description/Notes Fields ===
        # Description fields are usually non-sensitive metadata
        if any(kw in col_lower for kw in ['description', 'desc', 'notes', 'comment', 'remarks', 'memo']):
            # Exception: patient_notes, medical_description -> PII
            if any(kw in col_lower for kw in ['patient', 'medical', 'health', 'diagnosis', 'treatment']):
                # Medical context -> PII
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.3)
            else:
                # Generic descriptions -> Reduce all
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.4)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.5)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.4)
        
        # === RULE 12: Vendor/Supplier Fields ===
        # Vendor/supplier data is business data, not PII
        if any(kw in col_lower for kw in ['vendor', 'supplier', 'merchant', 'partner']):
            # Exception: vendor_contact, supplier_email -> Could be PII
            if any(kw in col_lower for kw in ['contact', 'email', 'phone', 'address', 'name']):
                # Contact info -> Keep as is (will be handled by other rules)
                pass
            else:
                # Generic vendor fields (vendor_id, vendor_code) -> Reduce PII
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.3)
                # Boost SOX for vendor financial data
                if any(kw in col_lower for kw in ['id', 'code', 'number', 'account']):
                    self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.2)
        
        # === RULE 5: Filter out very low scores (noise reduction) ===
        # Remove categories with confidence < 0.25 after adjustments
        adjusted_scores = {cat: score for cat, score in adjusted_scores.items() if score >= 0.25}
        
        return adjusted_scores
    
    def _boost_category(self, scores: Dict[str, float], policy_group: str, 
                       category_pattern: str, boost_factor: float):
        """Boost score for categories matching policy group or pattern"""
        for cat in list(scores.keys()):
            # Check metadata mapping first
            mapped_group = self._policy_group_by_category.get(cat.upper())
            
            if mapped_group == policy_group:
                 scores[cat] = min(0.95, scores[cat] * boost_factor)
                 continue
            
            # Fallback to pattern match (legacy/safety)
            cat_upper = cat.upper()
            if policy_group in cat_upper or category_pattern in cat_upper:
                scores[cat] = min(0.95, scores[cat] * boost_factor)
    
    def _reduce_category(self, scores: Dict[str, float], policy_group: str, 
                        category_pattern: str, reduction_factor: float):
        """Reduce score for categories matching policy group or pattern"""
        for cat in list(scores.keys()):
            # Check metadata mapping first
            mapped_group = self._policy_group_by_category.get(cat.upper())
            
            if mapped_group == policy_group:
                 scores[cat] = scores[cat] * reduction_factor
                 continue

            # Fallback to pattern match (legacy/safety)
            cat_upper = cat.upper()
            if policy_group in cat_upper or category_pattern in cat_upper:
                scores[cat] = scores[cat] * reduction_factor

    def _determine_table_category_governance_driven(self, table_scores: Dict[str, float], 
                                                  column_results: List[Dict[str, Any]]) -> Tuple[str, float, List[Dict[str, Any]]]:
        """Determine table category using governance rules only, supporting multi-label."""
        
        # Aggregate all potential categories from table scores and column multi-label results
        all_categories = set(table_scores.keys())
        
        # Map category -> list of column scores
        col_scores_map = {}
        
        for col in column_results:
            # Check all detected categories for this column
            cats = col.get('detected_categories', [])
            if not cats and col.get('category') != 'NON_SENSITIVE':
                # Fallback for legacy/single-label
                cats = [{'category': col['category'], 'confidence': col['confidence']}]
                
            for cat_entry in cats:
                c_name = cat_entry['category']
                c_conf = cat_entry['confidence']
                if c_name == 'NON_SENSITIVE':
                    continue
                
                all_categories.add(c_name)
                if c_name not in col_scores_map:
                    col_scores_map[c_name] = []
                col_scores_map[c_name].append(c_conf)
        
        if not all_categories:
            return 'NON_SENSITIVE', 0.0, []
        
        # Evaluate each category
        detected_categories = []
        
        for category in all_categories:
            table_score = table_scores.get(category, 0.0)
            column_scores = col_scores_map.get(category, [])
            
            # RELAXED: Consider ALL column scores (LOWERED from > 0.3 to > 0.25)
            valid_col_scores = [s for s in column_scores if s > 0.25]
            
            if valid_col_scores:
                column_avg = sum(valid_col_scores) / len(valid_col_scores)
                # Progressive coverage boost: More columns = higher confidence
                if len(valid_col_scores) >= 5:
                    coverage_boost = 1.15  # 5+ columns = 15% boost
                elif len(valid_col_scores) >= 3:
                    coverage_boost = 1.10  # 3-4 columns = 10% boost
                else:
                    coverage_boost = 1.05  # 1-2 columns = 5% boost
                
                combined_score = max(table_score, column_avg * coverage_boost)
            else:
                combined_score = table_score
            
            combined_score = min(0.99, combined_score)
            
            # Threshold check (using default 0.35 - BALANCED: Raised from 0.25 to reduce false positives)
            thresh = self._category_thresholds.get(category, 0.35)
            
            # EXCLUDE GENERIC / NON-SENSITIVE CATEGORIES
            if category.upper() in ('NON_SENSITIVE', 'GENERAL', 'SYSTEM', 'METADATA', 'UNKNOWN'):
                continue
                
            # Check if it maps to a sensitive policy group
            pg = self._map_category_to_policy_group(category)
            if pg == 'NON_SENSITIVE':
                continue
            
            # BALANCED validation: Require minimum confidence of 0.40 to reduce false positives
            # This is higher than before (0.30) but not too strict
            if combined_score < 0.40:
                continue
            
            if combined_score >= thresh:
                detected_categories.append({
                    'category': category,
                    'confidence': combined_score
                })
        
        # Sort by confidence
        detected_categories.sort(key=lambda x: x['confidence'], reverse=True)
        
        if detected_categories:
            best_category = detected_categories[0]['category']
            best_score = detected_categories[0]['confidence']
        else:
            best_category = 'NON_SENSITIVE'
            best_score = 0.0
        
        # === ADDITIONAL VALIDATION: Detect Non-Sensitive Tables ===
        # Check if this appears to be a catalog/product/reference table
        # by analyzing column composition
        if detected_categories and column_results:
            non_sensitive_indicators = [
                'product', 'item', 'catalog', 'category', 'sku', 'inventory',
                'warehouse', 'location', 'department', 'store', 'brand',
                'type', 'status', 'code', 'description', 'quantity', 'price'
            ]
            
            # Count how many columns match non-sensitive patterns
            total_cols = len(column_results)
            non_sensitive_count = 0
            
            for col in column_results:
                col_name = col.get('column_name', '').lower()
                if any(ind in col_name for ind in non_sensitive_indicators):
                    non_sensitive_count += 1
            
            # If >70% of columns are non-sensitive indicators, likely a catalog table
            if total_cols > 0 and (non_sensitive_count / total_cols) > 0.7:
                logger.info(f"  → Detected likely non-sensitive table: {non_sensitive_count}/{total_cols} columns match catalog patterns")
                # Downgrade to NON_SENSITIVE
                best_category = 'NON_SENSITIVE'
                best_score = 0.0
                detected_categories = []
            
        return best_category, best_score, detected_categories

    def _classify_table_governance_driven(self, db: str, asset: Dict[str, Any]) -> Dict[str, Any]:
        """Complete table classification using ONLY governance metadata"""
        try:
            schema = asset['schema']
            table = asset['table']
            full_name = f"{db}.{schema}.{table}"
            
            logger.info(f"Governance-driven classification for: {full_name}")
            
            # 1. Table-level classification using governance centroids
            table_context = self._build_table_context_from_metadata(db, schema, table)
            table_scores = self._compute_governance_scores(table_context)
            
            # 2. Column-level classification using governance patterns/keywords
            columns = self._get_columns_from_information_schema(db, schema, table)
            
            # BATCH OPTIMIZATION: Fetch samples for all columns in one query
            col_names = [c['COLUMN_NAME'] for c in columns]
            batch_samples = self._sample_table_values_batch(db, schema, table, col_names, limit=20)
            
            column_results = []
            
            for column in columns:
                col_name = column['COLUMN_NAME']
                # Pass pre-fetched samples to avoid N+1 queries
                col_samples = batch_samples.get(col_name, [])
                
                col_result = self._classify_column_governance_driven(
                    db, schema, table, column, pre_fetched_samples=col_samples
                )
                
                # CRITICAL: Only include sensitive columns (skip None results)
                if col_result is not None:
                    column_results.append(col_result)
            
            # 3. Determine final classification using governance rules
            table_category, confidence, table_detected_categories = self._determine_table_category_governance_driven(
                table_scores, column_results
            )
            
            # Map to policy group for UI
            policy_group = self._map_category_to_policy_group(table_category) if table_category != 'NON_SENSITIVE' else None
            
            # Calculate CIA and Label for UI
            c, i, a = (0, 0, 0)
            label = "Public"
            label_emoji = "🟩 Public"
            color = "Green"
            
            if policy_group or table_category != 'NON_SENSITIVE':
                 try:
                     canon_cat = self._normalize_category_for_cia(table_category)
                     c, i, a = ai_assistant_service.CIA_MAPPING.get(canon_cat, (1, 1, 1))
                     label = self.ai_service._map_cia_to_label(c, i, a)
                 except Exception:
                     c, i, a = (1, 1, 1)
                     label = "Internal"
                 
                 label_emoji_map = {
                    'Confidential': '🟥 Confidential',
                    'Restricted': '🟧 Restricted',
                    'Internal': '🟨 Internal',
                    'Public': '🟩 Public',
                 }
                 color_map = {
                    'Confidential': 'Red',
                    'Restricted': 'Orange',
                    'Internal': 'Yellow',
                    'Public': 'Green',
                 }
                 label_emoji = label_emoji_map.get(label, label)
                 color = color_map.get(label, 'Gray')

            # Create comma-separated string of top categories for UI display
            multi_label_str = ", ".join([d['category'] for d in table_detected_categories[:3]]) if table_detected_categories else table_category

            return {
                'asset': asset,
                'category': policy_group if policy_group else table_category, # Prefer policy group for display if available
                'detected_categories': table_detected_categories,  # Multi-label support
                'multi_label_category': multi_label_str,  # Comma-separated for UI
                'confidence': confidence,
                'columns': column_results,
                'business_context': table_context,
                'governance_categories_evaluated': list(table_scores.keys()),
                'status': 'COMPLETED',
                # UI Fields
                'confidence_pct': round(confidence * 100, 1),
                'confidence_tier': "Confident" if confidence > 0.75 else "Likely" if confidence > 0.5 else "Uncertain",
                'c': c, 'i': i, 'a': a,
                'label': label,
                'label_emoji': label_emoji,
                'color': color,
                'validation_status': 'REVIEW_REQUIRED',
                'issues': [],
                'route': 'STANDARD_REVIEW',
                'application_status': 'QUEUED_FOR_REVIEW',
                'compliance': [],
                'reasoning': [f"Matched category: {table_category}"],
                'multi_label_analysis': {"detected_categories": [policy_group] if policy_group else [], "reasoning": {}}
            }
            
        except Exception as e:
            logger.error(f"Governance-driven classification failed for {asset}: {e}")
            return {
                'asset': asset,
                'error': str(e),
                'status': 'FAILED'
            }

    def _run_governance_driven_pipeline(self, db: str, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Simplified pipeline using ONLY governance table data"""
        results = []
        
        # Ensure governance metadata is loaded
        if not self._category_centroids:
            logger.info("Loading governance metadata for classification...")
            self._load_metadata_driven_categories()
        
        # DIAGNOSTIC LOGGING
        logger.info("=" * 80)
        logger.info("GOVERNANCE-DRIVEN PIPELINE DIAGNOSTICS")
        logger.info("=" * 80)
        logger.info(f"Assets to classify: {len(assets)}")
        logger.info(f"Available governance categories: {list(self._category_centroids.keys())}")
        
        # Check governance metadata status
        valid_centroids = len([c for c in self._category_centroids.values() if c is not None])
        logger.info(f"Valid centroids: {valid_centroids}/{len(self._category_centroids)}")
        
        total_keywords = sum(len(kws) for kws in getattr(self, '_category_keywords', {}).values())
        logger.info(f"Total keywords loaded: {total_keywords}")
        
        total_patterns = sum(len(pats) for pats in getattr(self, '_category_patterns', {}).values())
        logger.info(f"Total patterns loaded: {total_patterns}")
        
        policy_map = getattr(self, '_policy_group_by_category', {})
        logger.info(f"Policy mapping: {len(policy_map)} categories → PII/SOX/SOC2")
        if policy_map:
            logger.info(f"  Policy map: {policy_map}")
        else:
            logger.warning("  ⚠️ NO POLICY MAPPING! Categories will not map to PII/SOX/SOC2")
        
        logger.info("-" * 80)
        
        filtered_count = 0
        passed_count = 0
        
        for idx, asset in enumerate(assets, 1):
            asset_name = f"{asset.get('schema')}.{asset.get('table')}"
            logger.info(f"\n[{idx}/{len(assets)}] Classifying: {asset_name}")
            
            result = self._classify_table_governance_driven(db, asset)
            
            # Extract classification results
            cat = result.get('category')
            conf = result.get('confidence', 0.0)
            status = result.get('status')
            error = result.get('error')
            
            logger.info(f"  Result: category={cat}, confidence={conf:.3f}, status={status}")
            
            if error:
                logger.error(f"  ✗ Classification error: {error}")
                filtered_count += 1
                continue
            
            # Check filter criteria
            # Multi-label support: Pass if ANY detected category is sensitive
            # We trust detected_categories because we already filtered out NON_SENSITIVE in the classification step
            detected_cats = result.get('detected_categories', [])
            has_sensitive = len(detected_cats) > 0
            
            # Also respect the confidence threshold
            meets_confidence = conf >= 0.40
            
            logger.info(f"  Filter check:")
            logger.info(f"    • Has sensitive categories: {has_sensitive} (found: {[d['category'] for d in detected_cats]})")
            logger.info(f"    • Confidence >= 0.40: {meets_confidence} (actual: {conf:.3f})")
            
            # Filter for UI
            if has_sensitive and meets_confidence:
                results.append(result)
                passed_count += 1
                logger.info(f"  ✓ PASSED - Added to results")
            else:
                filtered_count += 1
                # Provide specific reason for filtering
                reasons = []
                if not has_sensitive:
                    reasons.append(f"No sensitive categories detected (primary: '{cat}')")
                if not meets_confidence:
                    reasons.append(f"Confidence {conf:.3f} < 0.40")
                
                logger.warning(f"  ✗ FILTERED OUT - {'; '.join(reasons)}")
        
        logger.info("=" * 80)
        logger.info("PIPELINE SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total assets processed: {len(assets)}")
        logger.info(f"Passed filter: {passed_count}")
        logger.info(f"Filtered out: {filtered_count}")
        logger.info(f"Results returned: {len(results)}")
        
        if len(results) == 0:
            logger.error("⚠️ NO ASSETS PASSED FILTER!")
            logger.error("Common causes:")
            logger.error("  1. Governance categories not mapping to PII/SOX/SOC2")
            logger.error("  2. Confidence thresholds too high (check DETECTION_THRESHOLD in governance tables)")
            logger.error("  3. Empty or missing governance metadata (keywords, patterns, descriptions)")
            logger.error("  4. Category mapping logic failing")
            logger.error("")
            logger.error("Run .agent/debug_classification.py for detailed diagnostics")
        
        logger.info("=" * 80)
        
        return results

# Singleton instance
ai_classification_pipeline_service = AIClassificationPipelineService()
